"""End-to-end tests: signed layer integrity via cosign keypair signing."""

from __future__ import annotations

import copy
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from conftest import TEST_ISSUER, auth_header
from fastapi.testclient import TestClient
from pytest_httpserver import HTTPServer

from traust_ledger._internal.backends.constants import BACKEND_TYPE_DB
from traust_ledger._internal.integrity import (
    CosignBackend,
    Severity,
    verify_merkle_integrity,
    verify_merkle_signature,
)
from traust_ledger.config import ServiceConfig
from traust_ledger.service.app import create_app

CONTRACTS = "0.4.4"
LAYER = "signed-smoke"
RECORDED = "2026-08-18T15:00:00+00:00"
RATIONALE = "Confirmed via manual code review and dynamic analysis"


def _severity_event(layer_id: str = LAYER) -> dict:
    return {
        "kind": "severity",
        "contracts_version": CONTRACTS,
        "event": {
            "layer_id": layer_id,
            "finding_ref": "VULN-001",
            "severity": "high",
            "rationale": RATIONALE,
            "recorded_at": RECORDED,
        },
    }


def _countersign(layer_id: str = LAYER) -> dict:
    return {
        "kind": "countersign",
        "contracts_version": CONTRACTS,
        "event": {
            "layer_id": layer_id,
            "finding_ref": "VULN-001",
            "decision": "keep_open",
            "rationale": RATIONALE,
            "recorded_at": RECORDED,
        },
    }


@pytest.fixture()
def signed_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    httpserver: HTTPServer,
    rsa_keypair,
    jwks_json,
) -> Iterator[tuple[TestClient, Path, dict[str, str]]]:
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    subprocess.run(
        ["cosign", "generate-key-pair"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        env={**os.environ, "COSIGN_PASSWORD": ""},
    )
    httpserver.expect_request("/.well-known/jwks.json").respond_with_json(jwks_json)
    jwks_url = httpserver.url_for("/.well-known/jwks.json")
    config = ServiceConfig(
        backend_type=BACKEND_TYPE_DB,
        database_url=f"sqlite:///{tmp_path}/ledger.db",
        data_dir=str(tmp_path),
        signing_required=True,
        signing_key_path=str(tmp_path / "cosign.key"),
        signing_method="cosign",
        identity_provider="oidc",
        oidc_issuer=TEST_ISSUER,
        oidc_jwks_url=jwks_url,
    )
    app = create_app(config)
    from conftest import canonical_shell

    app.state.backend.initialize(tmp_path / f"{LAYER}.json", canonical_shell())
    headers = auth_header(rsa_keypair, identity="alice@e2e.test")
    yield TestClient(app), tmp_path, headers


@pytest.mark.skipif(not shutil.which("cosign"), reason="cosign not installed")
class TestSignedIntegrity:
    def test_event_accepted_with_signing(
        self, signed_client: tuple[TestClient, Path, dict]
    ) -> None:
        client, _, headers = signed_client
        response = client.post("/v1/ledger/events", json=_severity_event(), headers=headers)
        assert response.status_code == 200
        assert response.json()["status"] == "accepted"

    def test_layer_has_signature(self, signed_client: tuple[TestClient, Path, dict]) -> None:
        client, _, headers = signed_client
        client.post("/v1/ledger/events", json=_severity_event(), headers=headers)
        layer = client.get(f"/v1/ledger/layers/{LAYER}", headers=headers).json()
        signature = layer["metadata"].get("merkle_root_signature")
        assert signature
        assert len(signature) > 0

    def test_signature_verifies(self, signed_client: tuple[TestClient, Path, dict]) -> None:
        client, tmp_path, headers = signed_client
        client.post("/v1/ledger/events", json=_severity_event(), headers=headers)
        layer = client.get(f"/v1/ledger/layers/{LAYER}", headers=headers).json()
        pub_key_path = tmp_path / "cosign.pub"
        findings = verify_merkle_signature(
            layer,
            str(pub_key_path),
            backend=CosignBackend(),
        )
        assert findings == []

    def test_tampered_signature_fails_verify(
        self,
        signed_client: tuple[TestClient, Path, dict],
    ) -> None:
        client, tmp_path, headers = signed_client
        client.post("/v1/ledger/events", json=_severity_event(), headers=headers)
        layer = client.get(f"/v1/ledger/layers/{LAYER}", headers=headers).json()
        tampered = copy.deepcopy(layer)
        tampered["metadata"]["merkle_root_signature"] = "corrupted-signature"
        findings = verify_merkle_signature(
            tampered,
            str(tmp_path / "cosign.pub"),
            backend=CosignBackend(),
        )
        assert any(f.severity == Severity.ERROR for f in findings)

    def test_full_flow_event_then_countersign_signed(
        self,
        signed_client: tuple[TestClient, Path, dict],
    ) -> None:
        client, tmp_path, headers = signed_client
        client.post("/v1/ledger/events", json=_severity_event(), headers=headers)
        response = client.post(
            "/v1/ledger/events",
            json=_countersign(),
            headers=headers,
        )
        assert response.status_code == 200
        layer = client.get(f"/v1/ledger/layers/{LAYER}", headers=headers).json()
        assert verify_merkle_integrity(layer) == []
        assert (
            verify_merkle_signature(
                layer,
                str(tmp_path / "cosign.pub"),
                backend=CosignBackend(),
            )
            == []
        )
