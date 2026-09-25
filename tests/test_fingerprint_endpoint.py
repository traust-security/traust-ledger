"""Tests for POST /v1/ledger/fingerprint and GET /v1/ledger/layers."""

from __future__ import annotations

from pathlib import Path

from conftest import AUTH_HEADER, LAYER_ID
from fastapi import FastAPI
from fastapi.testclient import TestClient
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger.config import ServiceConfig
from traust_ledger.constants import ACTOR_KIND_HUMAN
from traust_ledger.paths import layer_file_path
from traust_ledger.service.app import create_app


class _FixedActorVerifier:
    def __init__(self, actor: LayerActor) -> None:
        self._actor = actor

    def verify(self, request):
        from traust_ledger.service.identity.tokens import extract_bearer_token

        extract_bearer_token(request)
        return self._actor.model_copy()


def _app(tmp_path: Path) -> FastAPI:
    actor = LayerActor(
        kind=ACTOR_KIND_HUMAN,
        identity="user:test@example.com",
        identity_verified=True,
        identity_provider="oidc",
    )
    config = ServiceConfig(
        backend_type="file",
        data_dir=str(tmp_path),
        signing_required=False,
    )
    return create_app(config, verifier=_FixedActorVerifier(actor))


# ── Fingerprint endpoint ─────────────────────────────────────────────────────


def test_fingerprint_stamps_eligible(tmp_path: Path) -> None:
    client = TestClient(_app(tmp_path))
    body = {
        "findings": [
            {
                "locations": [{"path": "src/main.go"}],
                "cwes": ["CWE-79"],
            },
            {
                "locations": [{"path": "src/util.go"}],
                "cwes": ["CWE-89"],
            },
        ],
        "repository": "https://github.com/org/repo",
    }
    resp = client.post("/v1/ledger/fingerprint", json=body, headers=AUTH_HEADER)
    assert resp.status_code == 200
    data = resp.json()
    assert data["stamped_count"] == 2
    for f in data["findings"]:
        assert "fingerprint" in f
        assert len(f["fingerprint"]) == 64


def test_fingerprint_skips_ineligible(tmp_path: Path) -> None:
    client = TestClient(_app(tmp_path))
    body = {
        "findings": [
            {"title": "no locations or cwes"},
            {"locations": [{"path": "src/a.go"}]},
        ],
    }
    resp = client.post("/v1/ledger/fingerprint", json=body, headers=AUTH_HEADER)
    assert resp.status_code == 200
    data = resp.json()
    assert data["stamped_count"] == 0


def test_fingerprint_no_auth_401(tmp_path: Path) -> None:
    client = TestClient(_app(tmp_path))
    body = {"findings": []}
    resp = client.post("/v1/ledger/fingerprint", json=body)
    assert resp.status_code == 401


# ── List layers endpoint ─────────────────────────────────────────────────────


def test_list_layers_empty(tmp_path: Path) -> None:
    client = TestClient(_app(tmp_path))
    resp = client.get("/v1/ledger/layers", headers=AUTH_HEADER)
    assert resp.status_code == 200
    assert resp.json()["layers"] == []


def test_list_layers_returns_ids(tmp_path: Path) -> None:
    import json

    layer_path = layer_file_path(str(tmp_path), LAYER_ID)
    from conftest import canonical_shell

    layer_path.write_text(json.dumps(canonical_shell()))

    client = TestClient(_app(tmp_path))
    resp = client.get("/v1/ledger/layers", headers=AUTH_HEADER)
    assert resp.status_code == 200
    assert LAYER_ID in resp.json()["layers"]


def test_list_layers_no_auth_401(tmp_path: Path) -> None:
    client = TestClient(_app(tmp_path))
    resp = client.get("/v1/ledger/layers")
    assert resp.status_code == 401
