"""Tests for verify_layer core, REST endpoint, and CLI."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from conftest import (
    AUTH_HEADER,
    LAYER_ID,
    TEST_ISSUER,
    none_alg_jwt,
)
from fastapi.testclient import TestClient
from pytest_httpserver import HTTPServer

from traust_ledger._internal.integrity import stamp_merkle_metadata
from traust_ledger.config import ServiceConfig
from traust_ledger.handlers.verify_handler import verify_layer
from traust_ledger.paths import layer_file_path
from traust_ledger.service.app import create_app


def _good_layer() -> dict:
    from conftest import canonical_shell

    layer = {
        **canonical_shell(),
        "events": [
            {
                "event_id": "a" * 64,
                "finding_ref": "FIND-001",
                "recorded_at": "2026-01-16T00:00:00+00:00",
                "source": {
                    "type": "triage_report",
                    "ref": "triage.json",
                    "actor": {"kind": "machine", "identity": "svc:triage"},
                },
                "disposition": {"validity": "confirmed"},
                "rationale": "SQL injection confirmed.",
            }
        ],
        "metadata": {**canonical_shell()["metadata"], "merkle_epoch": 0},
    }
    stamp_merkle_metadata(layer)
    return layer


def _tampered_layer() -> dict:
    layer = _good_layer()
    layer["events"][0]["rationale"] = "TAMPERED evidence content"
    return layer


# ── verify_layer core ─────────────────────────────────────────────


class TestVerifyLayerCore:
    def test_clean_layer_passes(self) -> None:
        result = verify_layer(_good_layer())
        assert result["passed"] is True
        assert result["findings"] == []

    def test_tampered_layer_fails(self) -> None:
        result = verify_layer(_tampered_layer())
        assert result["passed"] is False
        assert len(result["findings"]) > 0


# ── REST endpoint ─────────────────────────────────────────────────


@pytest.fixture()
def verify_app(tmp_path: Path, httpserver: HTTPServer, jwks_json):
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
    return create_app(config)


@pytest.fixture()
def verify_client(verify_app) -> TestClient:
    return TestClient(verify_app)


class TestVerifyEndpoint:
    def test_verify_clean_layer(self, verify_app, verify_client, tmp_path: Path) -> None:
        layer = _good_layer()
        path = layer_file_path(str(tmp_path), LAYER_ID)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(layer))

        r = verify_client.get(f"/v1/ledger/layers/{LAYER_ID}/verify", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert body["passed"] is True
        assert body["findings"] == []

    def test_verify_tampered_layer(self, verify_app, verify_client, tmp_path: Path) -> None:
        layer = _tampered_layer()
        path = layer_file_path(str(tmp_path), LAYER_ID)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(layer))

        r = verify_client.get(f"/v1/ledger/layers/{LAYER_ID}/verify", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert body["passed"] is False
        assert len(body["findings"]) > 0

    def test_verify_missing_layer_404(self, verify_client) -> None:
        r = verify_client.get("/v1/ledger/layers/nonexistent/verify", headers=AUTH_HEADER)
        assert r.status_code == 404


# ── CLI ───────────────────────────────────────────────────────────


class TestVerifyCLI:
    _TOKEN = none_alg_jwt(sub="test", exp=9999999999)

    def test_clean_exit_0(self, tmp_path: Path) -> None:
        layer = _good_layer()
        (tmp_path / f"{LAYER_ID}.json").write_text(json.dumps(layer))

        from traust_ledger.cli.main import main

        with patch.dict(
            "os.environ",
            {
                "LAAS_BACKEND_TYPE": "file",
                "LAAS_DATA_DIR": str(tmp_path),
                "LAAS_TOKEN": self._TOKEN,
            },
        ):
            exit_code = main(["verify", "--all"])
        assert exit_code == 0

    def test_tampered_exit_1(self, tmp_path: Path) -> None:
        layer = _tampered_layer()
        (tmp_path / f"{LAYER_ID}.json").write_text(json.dumps(layer))

        from traust_ledger.cli.main import main

        with patch.dict(
            "os.environ",
            {
                "LAAS_BACKEND_TYPE": "file",
                "LAAS_DATA_DIR": str(tmp_path),
                "LAAS_TOKEN": self._TOKEN,
            },
        ):
            exit_code = main(["verify", "--all"])
        assert exit_code == 1

    def test_empty_volume_exit_1(self, tmp_path: Path) -> None:
        from traust_ledger.cli.main import main

        with patch.dict(
            "os.environ",
            {
                "LAAS_BACKEND_TYPE": "file",
                "LAAS_DATA_DIR": str(tmp_path),
                "LAAS_TOKEN": self._TOKEN,
            },
        ):
            exit_code = main(["verify", "--all"])
        assert exit_code == 1
