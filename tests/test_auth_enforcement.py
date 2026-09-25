"""P0 security enforcement — route auth and fail-closed config."""

from __future__ import annotations

import pytest
from conftest import (
    AUTH_HEADER,
    CONTRACTS_VERSION,
    LAYER_ID,
    RATIONALE_OK,
    RECORDED_AT,
)
from fastapi.testclient import TestClient
from pytest_httpserver import HTTPServer

from traust_ledger.config import ServiceConfig
from traust_ledger.service.app import create_app
from traust_ledger.service.errors import MissingAuthError
from traust_ledger.service.route_constants import ROUTE_EVENTS, ROUTE_LAYERS


def _countersign_body() -> dict[str, object]:
    return {
        "kind": "countersign",
        "contracts_version": CONTRACTS_VERSION,
        "event": {
            "layer_id": LAYER_ID,
            "finding_ref": "FIND-001",
            "verdict": "true_positive",
            "justification": RATIONALE_OK,
            "recorded_at": RECORDED_AT,
        },
    }


@pytest.fixture()
def oidc_client(tmp_path, httpserver: HTTPServer, jwks_json) -> TestClient:
    httpserver.expect_request("/.well-known/jwks.json").respond_with_json(jwks_json)
    jwks_url = httpserver.url_for("/.well-known/jwks.json")
    config = ServiceConfig(
        backend_type="file",
        data_dir=str(tmp_path),
        signing_required=False,
        identity_provider="oidc",
        oidc_issuer="https://sso.example.com/realms/test",
        oidc_jwks_url=jwks_url,
    )
    from conftest import canonical_shell

    app = create_app(config)
    app.state.backend.initialize(tmp_path / f"{LAYER_ID}.json", canonical_shell())
    return TestClient(app)


class TestRouteAuthEnforcement:
    def test_post_event_without_auth_returns_401(self, oidc_client: TestClient) -> None:
        response = oidc_client.post(ROUTE_EVENTS, json=_countersign_body())
        assert response.status_code == 401
        assert response.json()["detail"] == MissingAuthError.message

    def test_get_layer_without_auth_returns_401(self, oidc_client: TestClient) -> None:
        oidc_client.post(ROUTE_EVENTS, json=_countersign_body(), headers=AUTH_HEADER)
        response = oidc_client.get(ROUTE_LAYERS.format(layer_id=LAYER_ID))
        assert response.status_code == 401
        assert response.json()["detail"] == MissingAuthError.message

    def test_post_event_with_auth_succeeds(self, oidc_client: TestClient) -> None:
        response = oidc_client.post(ROUTE_EVENTS, json=_countersign_body(), headers=AUTH_HEADER)
        assert response.status_code == 200

    def test_get_layer_with_auth_succeeds(self, oidc_client: TestClient) -> None:
        oidc_client.post(ROUTE_EVENTS, json=_countersign_body(), headers=AUTH_HEADER)
        response = oidc_client.get(
            ROUTE_LAYERS.format(layer_id=LAYER_ID),
            headers=AUTH_HEADER,
        )
        assert response.status_code == 200
        assert response.json()["events"]


class TestFailClosedConfig:
    def test_oidc_mode_without_jwks_raises_at_startup(self, tmp_path) -> None:
        config = ServiceConfig(
            data_dir=str(tmp_path),
            identity_provider="oidc",
            oidc_jwks_url=None,
        )
        with pytest.raises(
            RuntimeError, match="identity_provider=oidc requires LAAS_OIDC_JWKS_URL"
        ):
            create_app(config)
