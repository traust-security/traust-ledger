"""Tests for the findings read API — resolved disposition per finding."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from conftest import AUTH_HEADER, LAYER_ID, TEST_ISSUER, canonical_shell
from fastapi.testclient import TestClient
from pytest_httpserver import HTTPServer

from traust_ledger._internal.integrity import stamp_merkle_metadata
from traust_ledger.config import ServiceConfig
from traust_ledger.paths import layer_file_path
from traust_ledger.service.app import create_app


def _make_event(
    event_id: str,
    finding_ref: str,
    validity: str,
    source_type: str = "interactive",
    actor_kind: str = "human",
    actor_identity: str = "alice",
    recorded_at: str = "2026-01-16T00:00:00+00:00",
    **extra: object,
) -> dict:
    event: dict = {
        "event_id": event_id,
        "finding_ref": finding_ref,
        "recorded_at": recorded_at,
        "source": {
            "type": source_type,
            "ref": f"{source_type}:sign",
            "actor": {
                "kind": actor_kind,
                "identity": actor_identity,
                "identity_verified": True,
            },
        },
        "disposition": {"validity": validity},
        "rationale": "test",
    }
    event.update(extra)
    return event


def _layer_with_events(events: list[dict]) -> dict:
    layer = {**canonical_shell(), "events": events}
    for event in events:
        event["event_id"] = hashlib.sha256(event["event_id"].encode()).hexdigest()
        event["rationale"] = "Reviewed supporting evidence and source."
    layer["metadata"]["merkle_epoch"] = 0
    stamp_merkle_metadata(layer)
    return layer


@pytest.fixture()
def findings_client(tmp_path: Path, httpserver: HTTPServer, jwks_json) -> TestClient:
    httpserver.expect_request("/.well-known/jwks.json").respond_with_json(jwks_json)
    jwks_url = httpserver.url_for("/.well-known/jwks.json")
    config = ServiceConfig(
        backend_type="file",
        data_dir=str(tmp_path),
        signing_required=False,
        identity_provider="oidc",
        oidc_issuer=TEST_ISSUER,
        oidc_jwks_url=jwks_url,
    )
    return TestClient(create_app(config))


def _seed_layer(tmp_path: Path, layer_id: str, events: list[dict]) -> None:
    layer = _layer_with_events(events)
    path = layer_file_path(str(tmp_path), layer_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(layer))


class TestFindingsAPI:
    def test_single_finding_confirmed(self, findings_client, tmp_path) -> None:
        _seed_layer(
            tmp_path,
            LAYER_ID,
            [
                _make_event(
                    "e1",
                    "FIND-001",
                    "confirmed",
                    source_type="validation_report",
                    actor_kind="machine",
                    actor_identity="svc:validator",
                ),
            ],
        )
        r = findings_client.get(f"/v1/ledger/layers/{LAYER_ID}/findings", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert body["ledger_only"] is True
        assert len(body["findings"]) == 1
        f = body["findings"][0]
        assert f["finding_ref"] == "FIND-001"
        assert f["disposition"]["validity"] == "confirmed"
        assert f["disposition"]["assurance"] == "execution_proven"

    def test_human_override_precedence(self, findings_client, tmp_path) -> None:
        _seed_layer(
            tmp_path,
            LAYER_ID,
            [
                _make_event(
                    "e1",
                    "FIND-002",
                    "confirmed",
                    source_type="triage_report",
                    actor_kind="machine",
                    actor_identity="svc:triage",
                    recorded_at="2026-01-15T00:00:00+00:00",
                ),
                _make_event(
                    "e2",
                    "FIND-002",
                    "false_positive",
                    actor_kind="human",
                    actor_identity="alice",
                    recorded_at="2026-01-16T00:00:00+00:00",
                ),
            ],
        )
        r = findings_client.get(f"/v1/ledger/layers/{LAYER_ID}/findings", headers=AUTH_HEADER)
        assert r.status_code == 200
        f = r.json()["findings"][0]
        assert f["disposition"]["validity"] == "false_positive"
        assert f["disposition"]["assurance"] == "human_reviewed"

    def test_conflict_flag(self, findings_client, tmp_path) -> None:
        _seed_layer(
            tmp_path,
            LAYER_ID,
            [
                _make_event(
                    "e1",
                    "FIND-003",
                    "confirmed",
                    actor_kind="human",
                    actor_identity="alice",
                    recorded_at="2026-01-15T00:00:00+00:00",
                ),
                _make_event(
                    "e2",
                    "FIND-003",
                    "false_positive",
                    actor_kind="human",
                    actor_identity="bob",
                    recorded_at="2026-01-16T00:00:00+00:00",
                ),
            ],
        )
        r = findings_client.get(f"/v1/ledger/layers/{LAYER_ID}/findings", headers=AUTH_HEADER)
        assert r.status_code == 200
        f = r.json()["findings"][0]
        assert f["disposition"].get("conflict") is True

    def test_multiple_findings(self, findings_client, tmp_path) -> None:
        _seed_layer(
            tmp_path,
            LAYER_ID,
            [
                _make_event("e1", "FIND-A", "confirmed", recorded_at="2026-01-15T00:00:00+00:00"),
                _make_event(
                    "e2", "FIND-B", "false_positive", recorded_at="2026-01-16T00:00:00+00:00"
                ),
            ],
        )
        r = findings_client.get(f"/v1/ledger/layers/{LAYER_ID}/findings", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert len(body["findings"]) == 2
        assert body["summary"]["by_validity"]["confirmed"] == 1
        assert body["summary"]["by_validity"]["false_positive"] == 1

    def test_empty_layer_404(self, findings_client) -> None:
        r = findings_client.get("/v1/ledger/layers/nonexistent/findings", headers=AUTH_HEADER)
        assert r.status_code == 404

    def test_severity_override(self, findings_client, tmp_path) -> None:
        _seed_layer(
            tmp_path,
            LAYER_ID,
            [
                _make_event("e1", "FIND-SEV", "confirmed", recorded_at="2026-01-15T00:00:00+00:00"),
                {
                    "event_id": "e2",
                    "finding_ref": "FIND-SEV",
                    "recorded_at": "2026-01-16T00:00:00+00:00",
                    "source": {
                        "type": "interactive",
                        "ref": "interactive:sign",
                        "actor": {
                            "kind": "human",
                            "identity": "alice",
                            "identity_verified": True,
                        },
                    },
                    "disposition": {"severity": "low"},
                    "rationale": "Lowered severity after review",
                },
            ],
        )
        r = findings_client.get(f"/v1/ledger/layers/{LAYER_ID}/findings", headers=AUTH_HEADER)
        assert r.status_code == 200
        f = r.json()["findings"][0]
        assert "severity_override" in f["disposition"]
        assert f["disposition"]["severity_override"]["severity"] == "low"


class TestBulkFindingsAPI:
    def test_bulk_empty(self, findings_client) -> None:
        r = findings_client.get("/v1/ledger/findings", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert body["total_findings"] == 0
        assert body["layers"] == []
        assert body["has_more"] is False
        assert body["next_cursor"] is None

    def test_bulk_multiple_layers(self, findings_client, tmp_path) -> None:
        _seed_layer(tmp_path, "layer-a", [_make_event("e1", "F-1", "confirmed")])
        _seed_layer(
            tmp_path,
            "layer-b",
            [
                _make_event("e2", "F-2", "false_positive"),
                _make_event("e3", "F-3", "confirmed"),
            ],
        )
        r = findings_client.get("/v1/ledger/findings", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert body["total_findings"] == 3
        assert len(body["layers"]) == 2

    def test_bulk_includes_summary_per_layer(self, findings_client, tmp_path) -> None:
        _seed_layer(tmp_path, "layer-x", [_make_event("e1", "F-1", "confirmed")])
        r = findings_client.get("/v1/ledger/findings", headers=AUTH_HEADER)
        body = r.json()
        layer = body["layers"][0]
        assert "summary" in layer
        assert layer["summary"]["by_validity"]["confirmed"] == 1

    def test_bulk_includes_merkle_metadata(self, findings_client, tmp_path) -> None:
        _seed_layer(tmp_path, "layer-m", [_make_event("e1", "F-1", "confirmed")])
        r = findings_client.get("/v1/ledger/findings", headers=AUTH_HEADER)
        body = r.json()
        layer = body["layers"][0]
        assert "merkle_root" in layer
        assert "merkle_epoch" in layer
        assert layer["ledger_only"] is True

    def test_cursor_pagination(self, findings_client, tmp_path) -> None:
        for i in range(5):
            _seed_layer(
                tmp_path,
                f"layer-{i:02d}",
                [_make_event(f"e{i}", f"F-{i}", "confirmed")],
            )
        r1 = findings_client.get("/v1/ledger/findings?limit=2", headers=AUTH_HEADER)
        b1 = r1.json()
        assert len(b1["layers"]) == 2
        assert b1["has_more"] is True
        assert b1["next_cursor"] is not None

        r2 = findings_client.get(
            f"/v1/ledger/findings?limit=2&cursor={b1['next_cursor']}",
            headers=AUTH_HEADER,
        )
        b2 = r2.json()
        assert len(b2["layers"]) == 2
        first_ids = {ly["layer_id"] for ly in b1["layers"]}
        second_ids = {ly["layer_id"] for ly in b2["layers"]}
        assert first_ids.isdisjoint(second_ids)

    def test_since_epoch_filters(self, findings_client, tmp_path) -> None:
        _seed_layer(tmp_path, "layer-old", [_make_event("e1", "F-1", "confirmed")])
        _seed_layer(
            tmp_path,
            "layer-new",
            [
                _make_event("e2", "F-2", "confirmed"),
                _make_event("e3", "F-3", "confirmed"),
            ],
        )
        r = findings_client.get("/v1/ledger/findings?since_epoch=2", headers=AUTH_HEADER)
        body = r.json()
        epochs = [ly["merkle_epoch"] for ly in body["layers"]]
        assert all(e >= 2 for e in epochs if e is not None)
