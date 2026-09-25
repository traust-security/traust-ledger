"""Tests for POST /v1/ledger/layers/{layer_id}/submit and ledger submit CLI."""

from __future__ import annotations

import json
from pathlib import Path

from conftest import AUTH_HEADER, LAYER_ID, RECORDED_AT, none_alg_jwt
from fastapi import FastAPI
from fastapi.testclient import TestClient
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger.config import ServiceConfig
from traust_ledger.constants import ACTOR_KIND_HUMAN, STATUS_ACCEPTED
from traust_ledger.paths import layer_file_path
from traust_ledger.service.app import create_app


class _FixedActorVerifier:
    def __init__(self, actor: LayerActor) -> None:
        self._actor = actor

    def verify(self, request):
        from traust_ledger.service.identity.tokens import extract_bearer_token

        extract_bearer_token(request)
        return self._actor.model_copy()


def _verified_human() -> LayerActor:
    return LayerActor(
        kind=ACTOR_KIND_HUMAN,
        identity="user:test@example.com",
        identity_verified=True,
        identity_provider="oidc",
    )


def _app(tmp_path: Path, actor: LayerActor | None = None) -> FastAPI:
    config = ServiceConfig(
        backend_type="file",
        data_dir=str(tmp_path),
        signing_required=False,
    )
    from conftest import canonical_shell

    app = create_app(config, verifier=_FixedActorVerifier(actor or _verified_human()))
    app.state.backend.initialize(tmp_path / f"{LAYER_ID}.json", canonical_shell())
    return app


def _submit_url(layer_id: str = LAYER_ID) -> str:
    return f"/v1/ledger/layers/{layer_id}/submit"


def _make_event(finding_ref: str = "FIND-001", validity: str = "confirmed") -> dict:
    return {
        "finding_ref": finding_ref,
        "disposition": {"validity": validity},
        "source": {"type": "triage_report", "ref": "src-001", "actor": {}},
        "recorded_at": RECORDED_AT,
        "rationale": "Reviewed source evidence and confirmed this finding.",
    }


def _submit_body(events=None, needs_review=None) -> dict:
    return {
        "source_ref": "audit-2026-001",
        "recorded_at": RECORDED_AT,
        "events": events or [],
        "needs_review": needs_review or [],
    }


# ── REST: batch submit ──────────────────────────────────────────────────────


def test_submit_events_accepted(tmp_path: Path) -> None:
    client = TestClient(_app(tmp_path))
    body = _submit_body(events=[_make_event()])
    resp = client.post(_submit_url(), json=body, headers=AUTH_HEADER)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == STATUS_ACCEPTED
    assert data["event_count"] >= 1


def test_submit_stamps_actor(tmp_path: Path) -> None:
    client = TestClient(_app(tmp_path))
    body = _submit_body(events=[_make_event()])
    client.post(_submit_url(), json=body, headers=AUTH_HEADER)

    layer_path = layer_file_path(str(tmp_path), LAYER_ID)
    layer = json.loads(layer_path.read_text())
    event = layer["events"][0]
    assert event["source"]["actor"]["identity"] == "user:test@example.com"
    assert event["source"]["actor"]["identity_verified"] is True


def test_submit_stamps_fingerprint_algo(tmp_path: Path) -> None:
    """An event carrying a fingerprint is stamped with the current algo version."""
    from traust_ledger._internal.identity import ALGO_VERSION

    client = TestClient(_app(tmp_path))
    event = _make_event()
    event["fingerprint"] = "aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44"
    client.post(_submit_url(), json=_submit_body(events=[event]), headers=AUTH_HEADER)

    layer_path = layer_file_path(str(tmp_path), LAYER_ID)
    layer = json.loads(layer_path.read_text())
    assert layer["events"][0]["fingerprint_algo"] == ALGO_VERSION


def test_submit_no_fingerprint_no_algo(tmp_path: Path) -> None:
    """An event without a fingerprint is not given a fingerprint_algo."""
    client = TestClient(_app(tmp_path))
    client.post(_submit_url(), json=_submit_body(events=[_make_event()]), headers=AUTH_HEADER)

    layer_path = layer_file_path(str(tmp_path), LAYER_ID)
    layer = json.loads(layer_path.read_text())
    assert "fingerprint_algo" not in layer["events"][0]


def test_submit_idempotent(tmp_path: Path) -> None:
    """Submitting the same event twice results in one copy."""
    client = TestClient(_app(tmp_path))
    event = _make_event()
    body = _submit_body(events=[event])
    client.post(_submit_url(), json=body, headers=AUTH_HEADER)
    resp = client.post(_submit_url(), json=body, headers=AUTH_HEADER)
    assert resp.status_code == 200

    layer_path = layer_file_path(str(tmp_path), LAYER_ID)
    layer = json.loads(layer_path.read_text())
    assert len(layer["events"]) == 1


def test_submit_needs_review(tmp_path: Path) -> None:
    client = TestClient(_app(tmp_path))
    items = [
        {
            "source_ref": "scan-001",
            "suggested_finding_ref": "FIND-001",
            "queue_reason": "weak_confirmation",
            "quote": "suspect",
            "author": "reporter@example.test",
        }
    ]
    body = _submit_body(needs_review=items)
    resp = client.post(_submit_url(), json=body, headers=AUTH_HEADER)
    assert resp.status_code == 200
    assert resp.json()["event_count"] == 1

    layer_path = layer_file_path(str(tmp_path), LAYER_ID)
    layer = json.loads(layer_path.read_text())
    assert len(layer["needs_review"]) == 1
    assert layer["needs_review"][0]["status"] == "pending"


def test_submit_needs_review_dedup(tmp_path: Path) -> None:
    """Duplicate queue items are not appended twice."""
    client = TestClient(_app(tmp_path))
    item = {
        "source_ref": "scan-001",
        "suggested_finding_ref": "FIND-001",
        "queue_reason": "weak_confirmation",
        "quote": "suspect",
        "author": "reporter@example.test",
    }
    body = _submit_body(needs_review=[item])
    client.post(_submit_url(), json=body, headers=AUTH_HEADER)
    resp = client.post(_submit_url(), json=body, headers=AUTH_HEADER)
    assert resp.status_code == 200

    layer_path = layer_file_path(str(tmp_path), LAYER_ID)
    layer = json.loads(layer_path.read_text())
    assert len(layer["needs_review"]) == 1


def test_submit_identity_rule_fires(tmp_path: Path) -> None:
    """Defense-in-depth: unverified human false_positive raises in writer."""
    actor = LayerActor(
        kind=ACTOR_KIND_HUMAN,
        identity="user:unverified",
        identity_verified=False,
        identity_provider="oidc",
    )
    client = TestClient(_app(tmp_path, actor), raise_server_exceptions=False)
    event = _make_event(validity="false_positive")
    body = _submit_body(events=[event])
    resp = client.post(_submit_url(), json=body, headers=AUTH_HEADER)
    assert resp.status_code == 500


def test_submit_missing_auth(tmp_path: Path) -> None:
    client = TestClient(_app(tmp_path))
    body = _submit_body(events=[_make_event()])
    resp = client.post(_submit_url(), json=body)
    assert resp.status_code == 401


def test_submit_invalid_layer_id(tmp_path: Path) -> None:
    client = TestClient(_app(tmp_path))
    body = _submit_body(events=[_make_event()])
    resp = client.post("/v1/ledger/layers/../../etc/passwd/submit", json=body, headers=AUTH_HEADER)
    assert resp.status_code in (404, 422)


# ── CLI: ledger submit ───────────────────────────────────────────────────────


def test_cli_submit(tmp_path: Path, monkeypatch) -> None:
    """CLI submit reads a JSON file and writes events to the layer."""
    monkeypatch.setenv("LAAS_BACKEND_TYPE", "file")
    monkeypatch.setenv("LAAS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv(
        "LAAS_TOKEN",
        none_alg_jwt(sub="test", exp=9999999999),
    )
    monkeypatch.setenv("LEDGER_TOKEN", "fake-jwt-for-test")

    from conftest import canonical_shell

    from traust_ledger._internal.backends.file import FileBackend

    FileBackend().initialize(tmp_path / f"{LAYER_ID}.json", canonical_shell())
    events_file = tmp_path / "events.json"
    events_file.write_text(json.dumps([_make_event()]))

    from argparse import Namespace
    from unittest.mock import patch

    from traust_ledger.cli.commands.submit import cmd_submit

    args = Namespace(
        events_file=str(events_file),
        layer=LAYER_ID,
        queue_file=None,
        source_ref="test-run",
    )

    mock_actor = _verified_human()
    with patch("traust_ledger.cli.commands.submit.require_verified_actor", return_value=mock_actor):
        result = cmd_submit(args)

    assert result == 0
    layer_path = layer_file_path(str(tmp_path), LAYER_ID)
    layer = json.loads(layer_path.read_text())
    assert len(layer["events"]) == 1
    assert layer["events"][0]["source"]["actor"]["identity"] == "user:test@example.com"
