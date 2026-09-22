"""Route tests for POST /v1/ledger/layers/{id}/stamp and GET /v1/ledger/whoami.

The REST counterparts to LedgerClient.stamp_event_identities() and whoami() —
the write-path verbs the Go SDK needs endpoints for.
"""

from __future__ import annotations

from conftest import (
    AUTH_HEADER,
    CONTRACTS_VERSION,
    LAYER_ID,
    RATIONALE_OK,
    RECORDED_AT,
)
from fastapi.testclient import TestClient

FP = "a" * 64


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


def _seed_layer(client: TestClient) -> None:
    resp = client.post("/v1/ledger/events", json=_countersign_body(), headers=AUTH_HEADER)
    assert resp.status_code == 200, resp.text


def test_stamp_backfills_fingerprint_and_returns_root(client: TestClient) -> None:
    _seed_layer(client)
    resp = client.post(
        f"/v1/ledger/layers/{LAYER_ID}/stamp",
        json={"fingerprints": {"FIND-001": FP}},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["stamped"] == 1
    assert body["layer_id"] == LAYER_ID
    assert body["merkle_root"]

    events = client.get(f"/v1/ledger/layers/{LAYER_ID}/events", headers=AUTH_HEADER).json()
    assert any(e.get("fingerprint") == FP for e in events["events"])


def test_stamp_never_overwrites_is_idempotent(client: TestClient) -> None:
    _seed_layer(client)
    first = client.post(
        f"/v1/ledger/layers/{LAYER_ID}/stamp",
        json={"fingerprints": {"FIND-001": FP}},
        headers=AUTH_HEADER,
    )
    assert first.json()["stamped"] == 1
    second = client.post(
        f"/v1/ledger/layers/{LAYER_ID}/stamp",
        json={"fingerprints": {"FIND-001": FP}},
        headers=AUTH_HEADER,
    )
    assert second.status_code == 200, second.text
    assert second.json()["stamped"] == 0


def test_stamp_ignores_unmapped_refs(client: TestClient) -> None:
    _seed_layer(client)
    resp = client.post(
        f"/v1/ledger/layers/{LAYER_ID}/stamp",
        json={"fingerprints": {"FIND-999": FP}},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["stamped"] == 0


def test_stamp_requires_auth(client: TestClient) -> None:
    _seed_layer(client)
    resp = client.post(
        f"/v1/ledger/layers/{LAYER_ID}/stamp",
        json={"fingerprints": {"FIND-001": FP}},
    )
    assert resp.status_code == 401


def test_whoami_returns_verified_actor(client: TestClient) -> None:
    resp = client.get("/v1/ledger/whoami", headers=AUTH_HEADER)
    assert resp.status_code == 200, resp.text
    actor = resp.json()
    assert actor["kind"]
    assert actor["identity_verified"] is True


def test_whoami_requires_auth(client: TestClient) -> None:
    resp = client.get("/v1/ledger/whoami")
    assert resp.status_code == 401
