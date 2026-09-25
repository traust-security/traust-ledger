from __future__ import annotations

import base64
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from auth_helpers import TokenActorVerifier
from conftest import (
    AUTH_HEADER,
    CONTRACTS_VERSION,
    LAYER_ID,
    RATIONALE_OK,
    RATIONALE_SHORT,
    RECORDED_AT,
    auth_header,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger._internal.integrity import verify_merkle_integrity
from traust_ledger.config import ServiceConfig
from traust_ledger.constants import (
    ACTOR_KIND_HUMAN,
    ACTOR_KIND_MACHINE,
    STATUS_ACCEPTED,
    TIMESTAMP_FUTURE_LIMIT_HOURS,
)
from traust_ledger.paths import layer_file_path
from traust_ledger.service.app import create_app
from traust_ledger.service.errors import (
    DecisionVerdictConflictError,
    IdentityRequiredError,
    InvalidEpochError,
    MachineDispositionError,
    MissingAuthError,
    MissingSeverityError,
    RationaleTooShortError,
    SigningRequiredError,
    TimestampFutureError,
    TwoPersonViolatedError,
    UnknownDecisionError,
)
from traust_ledger.service.identity import ActorResolver
from traust_ledger.service.route_constants import (
    ROUTE_EVENTS,
    ROUTE_HEALTHZ,
    ROUTE_LAYERS,
    STATUS_HEALTHY,
)


class _FixedActorVerifier:
    """Test double returning a predetermined LayerActor for every request."""

    def __init__(self, actor: LayerActor) -> None:
        self._actor = actor

    def verify(self, request):
        from traust_ledger.service.identity.tokens import extract_bearer_token

        extract_bearer_token(request)
        return self._actor.model_copy()

    @classmethod
    def from_config(cls, config):
        raise NotImplementedError("use constructor directly in tests")


def _app_with_actor(tmp_path: Path, actor: LayerActor) -> FastAPI:
    config = ServiceConfig(
        backend_type="file",
        data_dir=str(tmp_path),
        signing_required=False,
    )
    from conftest import canonical_shell

    app = create_app(config, verifier=_FixedActorVerifier(actor))
    app.state.backend.initialize(tmp_path / f"{LAYER_ID}.json", canonical_shell())
    return app


def _countersign_body(**overrides: object) -> dict[str, object]:
    event: dict[str, object] = {
        "layer_id": LAYER_ID,
        "finding_ref": "FIND-001",
        "verdict": "true_positive",
        "justification": RATIONALE_OK,
        "recorded_at": RECORDED_AT,
    }
    event.update(overrides)
    return {"kind": "countersign", "contracts_version": CONTRACTS_VERSION, "event": event}


def test_healthz(client: TestClient) -> None:
    response = client.get(ROUTE_HEALTHZ)
    assert response.status_code == 200
    assert response.json()["status"] == STATUS_HEALTHY


def test_submit_countersign(client: TestClient) -> None:
    response = client.post(ROUTE_EVENTS, json=_countersign_body(), headers=AUTH_HEADER)
    assert response.status_code == 200
    assert response.json()["status"] == STATUS_ACCEPTED


def test_get_layer(client: TestClient, app_with_backend) -> None:
    client.post(ROUTE_EVENTS, json=_countersign_body(), headers=AUTH_HEADER)
    response = client.get(ROUTE_LAYERS.format(layer_id=LAYER_ID), headers=AUTH_HEADER)
    assert response.status_code == 200
    assert response.json()["events"]


def test_get_layer_not_found(client: TestClient) -> None:
    response = client.get(ROUTE_LAYERS.format(layer_id="missing-layer"), headers=AUTH_HEADER)
    assert response.status_code == 404


def test_swagger_docs(client: TestClient) -> None:
    docs = client.get("/docs")
    assert docs.status_code == 200
    openapi = client.get("/openapi.json")
    assert openapi.status_code == 200
    assert isinstance(openapi.json(), dict)


def test_missing_auth_401(client: TestClient) -> None:
    response = client.post(ROUTE_EVENTS, json=_countersign_body())
    assert response.status_code == 401
    assert response.json()["detail"] == MissingAuthError.message


def test_invalid_auth_401(client: TestClient) -> None:
    response = client.post(
        ROUTE_EVENTS,
        json={"kind": "countersign", "event": {}},
        # Built at runtime so no literal credential-shaped header sits in
        # the tree; the value is a throwaway that the gate must reject.
        headers={"Authorization": "Basic " + base64.b64encode(b"user:pass").decode()},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == MissingAuthError.message


def test_countersign_missing_identity_422(tmp_path: Path) -> None:
    actor = LayerActor(kind=ACTOR_KIND_HUMAN, identity_verified=False)
    client = TestClient(_app_with_actor(tmp_path, actor))
    response = client.post(
        ROUTE_EVENTS,
        json=_countersign_body(),
        headers=AUTH_HEADER,
    )
    assert response.status_code == 422
    assert response.json()["detail"] == IdentityRequiredError.message


def test_human_fp_unverified_identity_422(tmp_path: Path) -> None:
    """Gate rejects unverified human false_positive with 422."""
    actor = LayerActor(
        kind=ACTOR_KIND_HUMAN,
        identity="user:unverified",
        identity_verified=False,
        identity_provider="oidc",
    )
    client = TestClient(_app_with_actor(tmp_path, actor))
    response = client.post(
        ROUTE_EVENTS,
        json=_countersign_body(verdict="false_positive"),
        headers=AUTH_HEADER,
    )
    assert response.status_code == 422


def test_server_stamps_identity_from_authn(tmp_path: Path) -> None:
    """Server-side identity stamp overwrites client-supplied actor fields."""
    actor = LayerActor(
        kind=ACTOR_KIND_HUMAN,
        identity="user:unverified",
        identity_verified=False,
        identity_provider="oidc",
    )
    app = _app_with_actor(tmp_path, actor)
    client = TestClient(app)
    client.post(
        ROUTE_EVENTS,
        json=_countersign_body(
            actor={"kind": ACTOR_KIND_HUMAN, "identity": "alice", "identity_verified": True},
        ),
        headers=AUTH_HEADER,
    )
    layer = layer_file_path(app.state.config.data_dir, LAYER_ID)
    events = json.loads(layer.read_text())["events"]
    stamped = events[-1]["source"]["actor"]
    assert stamped.get("identity_verified") is False


def test_machine_disposition_rejected(client: TestClient) -> None:
    machine_event = _countersign_body(
        source={"actor": {"kind": ACTOR_KIND_MACHINE, "identity": "bot"}},
        disposition={"validity": "confirmed"},
    )
    events_response = client.post(
        ROUTE_EVENTS,
        json=machine_event,
        headers=AUTH_HEADER,
    )
    assert events_response.status_code == 422
    assert events_response.json()["detail"] == MachineDispositionError.message


def test_severity_override_machine_rejected(tmp_path: Path) -> None:
    actor = LayerActor(
        kind=ACTOR_KIND_MACHINE,
        identity="svc:machine",
        identity_verified=True,
        identity_provider="oidc",
    )
    client = TestClient(_app_with_actor(tmp_path, actor))
    response = client.post(
        ROUTE_EVENTS,
        json={
            "kind": "severity",
            "event": {
                "layer_id": LAYER_ID,
                "finding_ref": "FIND-001",
                "severity": "high",
                "rationale": RATIONALE_OK,
                "recorded_at": RECORDED_AT,
            },
        },
        headers=AUTH_HEADER,
    )
    assert response.status_code == 422
    assert response.json()["detail"] == MachineDispositionError.message


def test_severity_override_no_rationale_rejected(client: TestClient) -> None:
    response = client.post(
        ROUTE_EVENTS,
        json={
            "kind": "severity",
            "event": {
                "layer_id": LAYER_ID,
                "finding_ref": "FIND-001",
                "severity": "high",
                "rationale": RATIONALE_SHORT,
                "recorded_at": RECORDED_AT,
            },
        },
        headers=AUTH_HEADER,
    )
    assert response.status_code == 422
    assert RationaleTooShortError.format_message(min_length=10) in response.json()["detail"]


def test_severity_override_happy_path(client: TestClient) -> None:
    response = client.post(
        ROUTE_EVENTS,
        json={
            "kind": "severity",
            "event": {
                "layer_id": LAYER_ID,
                "finding_ref": "FIND-001",
                "severity": "high",
                "rationale": RATIONALE_OK,
                "recorded_at": RECORDED_AT,
            },
        },
        headers=AUTH_HEADER,
    )
    assert response.status_code == 200
    assert response.json()["status"] == STATUS_ACCEPTED


def test_severity_missing_level_422(client: TestClient) -> None:
    response = client.post(
        ROUTE_EVENTS,
        json={
            "kind": "severity",
            "event": {
                "layer_id": LAYER_ID,
                "finding_ref": "FIND-001",
                "rationale": RATIONALE_OK,
                "recorded_at": RECORDED_AT,
            },
        },
        headers=AUTH_HEADER,
    )
    assert response.status_code == 422
    assert response.json()["detail"] == MissingSeverityError.message


def test_countersign_accepts_justification_instead_of_rationale(client: TestClient) -> None:
    response = client.post(
        ROUTE_EVENTS,
        json={
            "kind": "countersign",
            "contracts_version": CONTRACTS_VERSION,
            "event": {
                "layer_id": LAYER_ID,
                "finding_ref": "FIND-JUST",
                "verdict": "true_positive",
                "justification": RATIONALE_OK,
                "recorded_at": RECORDED_AT,
            },
        },
        headers=AUTH_HEADER,
    )
    assert response.status_code == 200


def test_decision_verdict_conflict_422(client: TestClient) -> None:
    response = client.post(
        ROUTE_EVENTS,
        json=_countersign_body(verdict="true_positive", decision="false_positive"),
        headers=AUTH_HEADER,
    )
    assert response.status_code == 422
    assert response.json()["detail"] == DecisionVerdictConflictError.message


def test_unknown_decision_422(client: TestClient) -> None:
    response = client.post(
        ROUTE_EVENTS,
        json={
            "kind": "countersign",
            "contracts_version": CONTRACTS_VERSION,
            "event": {
                "layer_id": LAYER_ID,
                "finding_ref": "FIND-001",
                "decision": "wont_fix",
                "rationale": RATIONALE_OK,
                "recorded_at": RECORDED_AT,
            },
        },
        headers=AUTH_HEADER,
    )
    assert response.status_code == 422
    assert UnknownDecisionError.format_message(decision="wont_fix") in response.json()["detail"]


def test_verify_after_append(client: TestClient, app_with_backend) -> None:
    client.post(ROUTE_EVENTS, json=_countersign_body(), headers=AUTH_HEADER)
    layer_path = layer_file_path(app_with_backend.state.config.data_dir, LAYER_ID)
    layer = json.loads(layer_path.read_text())
    assert verify_merkle_integrity(layer) == []


def test_two_person_rule_fp_reassertion_rejected(tmp_path: Path) -> None:
    """Two-person gate fires when same human re-asserts FP after exec-confirmed."""
    from traust_ledger._internal.integrity import stamp_merkle_metadata

    class _AlwaysActive:
        def is_active(self, identity: str) -> str:
            return "active"

    config = ServiceConfig(
        backend_type="file",
        data_dir=str(tmp_path),
        signing_required=False,
    )
    app = create_app(config, verifier=TokenActorVerifier())
    app.state.resolver = ActorResolver(TokenActorVerifier(), _AlwaysActive())
    fp_client = TestClient(app)

    alice = {"Authorization": "Bearer alice-token"}
    bob = {"Authorization": "Bearer bob-token"}

    layer_path = layer_file_path(str(tmp_path), LAYER_ID)
    layer_path.parent.mkdir(parents=True, exist_ok=True)
    from conftest import canonical_shell

    exec_confirmed = {
        "events": [
            {
                "event_id": "a" * 64,
                "finding_ref": "FIND-001",
                "recorded_at": "2026-01-15T00:00:00+00:00",
                "source": {
                    "type": "validation_report",
                    "ref": "validations/repo-a/validation.json",
                    "actor": {"kind": "machine", "identity": "svc:validator"},
                },
                "disposition": {"validity": "confirmed"},
                "rationale": "Exploit reproduced.",
            }
        ],
        "metadata": {**canonical_shell()["metadata"], "merkle_epoch": 0},
        "needs_review": [],
    }
    stamp_merkle_metadata(exec_confirmed)
    layer_path.write_text(json.dumps(exec_confirmed))

    fp_body = _countersign_body(verdict="false_positive")
    first = fp_client.post(ROUTE_EVENTS, json=fp_body, headers=alice)
    assert first.status_code == 200

    fp_body2 = _countersign_body(verdict="false_positive", recorded_at="2026-01-16T00:01:00+00:00")
    second = fp_client.post(ROUTE_EVENTS, json=fp_body2, headers=alice)
    assert second.status_code == 422
    assert second.json()["detail"] == TwoPersonViolatedError.message

    fp_body3 = _countersign_body(verdict="false_positive", recorded_at="2026-01-16T00:02:00+00:00")
    third = fp_client.post(ROUTE_EVENTS, json=fp_body3, headers=bob)
    assert third.status_code == 200


def test_timestamp_future_rejected(client: TestClient) -> None:
    future = (datetime.now(UTC) + timedelta(hours=25)).isoformat()
    response = client.post(
        ROUTE_EVENTS,
        json=_countersign_body(recorded_at=future),
        headers=AUTH_HEADER,
    )
    assert response.status_code == 422
    assert response.json()["detail"] == TimestampFutureError.format_message(
        hours=TIMESTAMP_FUTURE_LIMIT_HOURS,
    )


def test_epoch_truncation_rejected(client: TestClient, app_with_backend) -> None:
    from conftest import canonical_shell

    layer_path = layer_file_path(app_with_backend.state.config.data_dir, LAYER_ID)
    layer_path.parent.mkdir(parents=True, exist_ok=True)
    layer_path.write_text(
        json.dumps(
            {
                "events": [{"event_id": "seed-event", "finding_ref": "FIND-SEED"}],
                "metadata": {**canonical_shell()["metadata"], "merkle_epoch": 99},
                "needs_review": [],
            },
        ),
    )
    response = client.post(ROUTE_EVENTS, json=_countersign_body(), headers=AUTH_HEADER)
    assert response.status_code == 422
    assert response.json()["detail"] == InvalidEpochError.message


def test_concurrent_submissions_no_lost_events(app_with_backend) -> None:
    def submit(index: int) -> int:
        client = TestClient(app_with_backend)
        headers = auth_header(identity=f"worker-{index:03d}@test.local")
        body = _countersign_body(finding_ref=f"FIND-{index:03d}")
        response = client.post(ROUTE_EVENTS, json=body, headers=headers)
        return response.status_code

    with ThreadPoolExecutor(max_workers=10) as pool:
        statuses = list(pool.map(submit, range(10)))

    assert all(status == 200 for status in statuses)
    layer_path = layer_file_path(app_with_backend.state.config.data_dir, LAYER_ID)
    events = json.loads(layer_path.read_text())["events"]
    assert len(events) == 10


def test_signing_required_rejects_unsigned(tmp_path: Path) -> None:
    config = ServiceConfig(
        data_dir=str(tmp_path),
        signing_required=True,
        signing_key_path=None,
    )
    app = create_app(
        config,
        verifier=_FixedActorVerifier(
            LayerActor(
                kind=ACTOR_KIND_HUMAN,
                identity="dev@test.local",
                identity_verified=True,
                identity_provider="oidc",
            ),
        ),
        validate_config=False,
    )
    client = TestClient(app)
    response = client.post(ROUTE_EVENTS, json=_countersign_body(), headers=AUTH_HEADER)
    assert response.status_code == 422
    assert response.json()["detail"] == SigningRequiredError.message


def test_actor_resolution_distinct_identities(tmp_path: Path) -> None:
    config = ServiceConfig(
        backend_type="file",
        data_dir=str(tmp_path),
        signing_required=False,
    )
    app = create_app(config, verifier=TokenActorVerifier())
    from conftest import canonical_shell

    app.state.backend.initialize(tmp_path / f"{LAYER_ID}.json", canonical_shell())
    app.state.resolver = ActorResolver(TokenActorVerifier(), None)
    client = TestClient(app)
    client.post(
        ROUTE_EVENTS,
        json=_countersign_body(finding_ref="FIND-A"),
        headers={"Authorization": "Bearer alice-token"},
    )
    client.post(
        ROUTE_EVENTS,
        json=_countersign_body(finding_ref="FIND-B"),
        headers={"Authorization": "Bearer bob-token"},
    )
    layer_path = layer_file_path(str(tmp_path), LAYER_ID)
    events = json.loads(layer_path.read_text())["events"]
    identities = [event["source"]["actor"]["identity"] for event in events]
    assert identities[0] != identities[1]
    assert identities[0] == "user:alice"
    assert identities[1] == "user:bob"
