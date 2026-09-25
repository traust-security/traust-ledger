"""Tests for the layer events read API — raw event history."""

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


def _event_id(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


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
        "event_id": hashlib.sha256(event_id.encode()).hexdigest(),
        "finding_ref": finding_ref,
        "recorded_at": recorded_at,
        "source": {
            "type": {"triage": "triage_report", "validation": "validation_report"}.get(
                source_type, source_type
            ),
            "ref": f"{source_type}:sign",
            "actor": {
                "kind": actor_kind,
                "identity": actor_identity,
                "identity_verified": True,
            },
        },
        "disposition": {"validity": validity},
        "rationale": "Reviewed the finding against source evidence.",
    }
    event.update(extra)
    return event


def _layer_with_events(events: list[dict]) -> dict:
    layer = {**canonical_shell(), "events": events}
    layer["metadata"]["merkle_epoch"] = 0
    stamp_merkle_metadata(layer)
    return layer


@pytest.fixture()
def events_client(tmp_path: Path, httpserver: HTTPServer, jwks_json) -> TestClient:
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


def _seed_empty_layer(tmp_path: Path, layer_id: str) -> None:
    path = layer_file_path(str(tmp_path), layer_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(canonical_shell()))


class TestEventsAPI:
    def test_returns_all_events(self, events_client, tmp_path) -> None:
        events = [
            _make_event("e1", "FIND-001", "confirmed", recorded_at="2026-01-15T00:00:00+00:00"),
            _make_event(
                "e2",
                "FIND-002",
                "false_positive",
                source_type="triage",
                recorded_at="2026-01-16T00:00:00+00:00",
            ),
        ]
        _seed_layer(tmp_path, LAYER_ID, events)
        r = events_client.get(f"/v1/ledger/layers/{LAYER_ID}/events", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert body["layer_id"] == LAYER_ID
        assert body["total"] == 2
        assert len(body["events"]) == 2
        assert [e["event_id"] for e in body["events"]] == [_event_id("e1"), _event_id("e2")]

    def test_finding_ref_filter(self, events_client, tmp_path) -> None:
        _seed_layer(
            tmp_path,
            LAYER_ID,
            [
                _make_event("e1", "FIND-A", "confirmed"),
                _make_event("e2", "FIND-B", "confirmed"),
                _make_event("e3", "FIND-A", "false_positive"),
            ],
        )
        r = events_client.get(
            f"/v1/ledger/layers/{LAYER_ID}/events?finding_ref=FIND-A",
            headers=AUTH_HEADER,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 2
        assert len(body["events"]) == 2
        assert all(e["finding_ref"] == "FIND-A" for e in body["events"])
        assert [e["event_id"] for e in body["events"]] == [_event_id("e1"), _event_id("e3")]

    def test_source_type_filter(self, events_client, tmp_path) -> None:
        _seed_layer(
            tmp_path,
            LAYER_ID,
            [
                _make_event("e1", "FIND-A", "confirmed", source_type="interactive"),
                _make_event("e2", "FIND-B", "confirmed", source_type="triage"),
                _make_event("e3", "FIND-C", "confirmed", source_type="validation"),
            ],
        )
        r = events_client.get(
            f"/v1/ledger/layers/{LAYER_ID}/events?source_type=triage_report",
            headers=AUTH_HEADER,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        assert body["events"][0]["event_id"] == _event_id("e2")
        assert body["events"][0]["source"]["type"] == "triage_report"

    def test_combined_filters(self, events_client, tmp_path) -> None:
        _seed_layer(
            tmp_path,
            LAYER_ID,
            [
                _make_event("e1", "FIND-A", "confirmed", source_type="interactive"),
                _make_event("e2", "FIND-A", "confirmed", source_type="triage"),
                _make_event("e3", "FIND-B", "confirmed", source_type="triage"),
            ],
        )
        r = events_client.get(
            f"/v1/ledger/layers/{LAYER_ID}/events?finding_ref=FIND-A&source_type=triage_report",
            headers=AUTH_HEADER,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        assert body["events"][0]["event_id"] == _event_id("e2")

    def test_pagination(self, events_client, tmp_path) -> None:
        events = [_make_event(f"e{i}", f"FIND-{i}", "confirmed") for i in range(5)]
        _seed_layer(tmp_path, LAYER_ID, events)
        r1 = events_client.get(
            f"/v1/ledger/layers/{LAYER_ID}/events?limit=2&offset=0",
            headers=AUTH_HEADER,
        )
        assert r1.status_code == 200
        b1 = r1.json()
        assert b1["total"] == 5
        assert len(b1["events"]) == 2
        assert [e["event_id"] for e in b1["events"]] == [_event_id("e0"), _event_id("e1")]

        r2 = events_client.get(
            f"/v1/ledger/layers/{LAYER_ID}/events?limit=2&offset=2",
            headers=AUTH_HEADER,
        )
        b2 = r2.json()
        assert b2["total"] == 5
        assert len(b2["events"]) == 2
        assert [e["event_id"] for e in b2["events"]] == [_event_id("e2"), _event_id("e3")]

    def test_empty_layer(self, events_client, tmp_path) -> None:
        _seed_empty_layer(tmp_path, LAYER_ID)
        r = events_client.get(f"/v1/ledger/layers/{LAYER_ID}/events", headers=AUTH_HEADER)
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_total_reflects_filtered_count_not_page_size(self, events_client, tmp_path) -> None:
        events = [_make_event(f"e{i}", "FIND-A", "confirmed") for i in range(10)]
        _seed_layer(tmp_path, LAYER_ID, events)
        r = events_client.get(
            f"/v1/ledger/layers/{LAYER_ID}/events?limit=3&offset=0",
            headers=AUTH_HEADER,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 10
        assert len(body["events"]) == 3

    def test_missing_layer_404(self, events_client) -> None:
        r = events_client.get("/v1/ledger/layers/nonexistent/events", headers=AUTH_HEADER)
        assert r.status_code == 404
