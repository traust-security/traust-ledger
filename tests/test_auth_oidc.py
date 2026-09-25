"""TDD tests for the human verification plan.

Each test exercises the service with real requests and asserts what the
production auth path must deliver. Tests fail until the stub resolve_actor()
is replaced with real OIDC validation.
"""

from __future__ import annotations

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from pytest_httpserver import HTTPServer

from traust_ledger._internal.backends.constants import BACKEND_TYPE_DB
from traust_ledger.config import ServiceConfig
from traust_ledger.service.app import create_app

CONTRACTS = "0.4.4"
LAYER = "auth-test"
RECORDED = "2026-08-18T15:00:00+00:00"
RATIONALE = "Confirmed via manual code review and dynamic analysis"

TEST_ISSUER = "https://sso.example.com/realms/test"


@pytest.fixture(scope="module")
def rsa_keypair():
    """Generate an RSA keypair for signing test JWTs."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key


@pytest.fixture(scope="module")
def jwks_json(rsa_keypair):
    """JWKS document containing the test public key."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

    pub = rsa_keypair.public_key()
    pub_numbers: RSAPublicNumbers = pub.public_numbers()

    def _int_to_base64url(n: int, length: int) -> str:
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    n_bytes = (pub_numbers.n.bit_length() + 7) // 8
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-key-1",
                "use": "sig",
                "alg": "RS256",
                "n": _int_to_base64url(pub_numbers.n, n_bytes),
                "e": _int_to_base64url(pub_numbers.e, 3),
            }
        ]
    }


def _make_signed_jwt(
    private_key,
    claims: dict | None = None,
    *,
    expired: bool = False,
    issuer: str = TEST_ISSUER,
    headers: dict | None = None,
) -> str:
    """Mint a properly RS256-signed JWT."""
    now = int(time.time())
    payload = {
        "iss": issuer,
        "sub": "alice@example.com",
        "email": "alice@example.com",
        "preferred_username": "alice",
        "iat": now - 60,
        "exp": now - 300 if expired else now + 3600,
    }
    if claims:
        payload.update(claims)
    hdr = {"kid": "test-key-1"}
    if headers:
        hdr.update(headers)
    return jwt.encode(payload, private_key, algorithm="RS256", headers=hdr)


class _FakeDirectory:
    """Test double for EmployeeDirectory — always returns a fixed answer."""

    def __init__(self, active: bool = True) -> None:
        self._active = active

    def is_active(self, identity: str) -> str:
        return "active" if self._active else "not_found"


@pytest.fixture()
def auth_client(tmp_path, httpserver: HTTPServer, rsa_keypair, jwks_json):
    """Service client configured with real OIDC validation against mock JWKS."""
    httpserver.expect_request("/.well-known/jwks.json").respond_with_json(jwks_json)
    jwks_url = httpserver.url_for("/.well-known/jwks.json")
    db_url = f"sqlite:///{tmp_path}/ledger.db"
    config = ServiceConfig(
        backend_type=BACKEND_TYPE_DB,
        database_url=db_url,
        data_dir=str(tmp_path),
        signing_required=False,
        oidc_issuer=TEST_ISSUER,
        oidc_jwks_url=jwks_url,
    )
    from conftest import canonical_shell

    app = create_app(config)
    app.state.backend.initialize(tmp_path / f"{LAYER}.json", canonical_shell())
    return TestClient(app)


def _severity_event(layer_id=LAYER):
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


# ── Task 2: resolve_actor must validate JWTs ─────────────────────


def test_valid_jwt_resolves_human_actor(auth_client, rsa_keypair) -> None:
    """A valid OIDC JWT should yield an actor with identity from claims
    and identity_verification='oidc'."""
    token = _make_signed_jwt(
        rsa_keypair,
        {"sub": "alice@example.com", "email": "alice@example.com"},
    )
    r = auth_client.post(
        "/v1/ledger/events",
        json=_severity_event(),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    auth_headers = {"Authorization": f"Bearer {token}"}
    layer = auth_client.get(f"/v1/ledger/layers/{LAYER}", headers=auth_headers).json()
    events = layer["events"]
    human_events = [
        e for e in events if e.get("source", {}).get("actor", {}).get("kind") == "human"
    ]
    assert human_events, "expected a human-authored event"
    actor = human_events[-1]["source"]["actor"]
    assert actor["identity"] == "alice@example.com", (
        "identity should come from JWT claims, not token prefix"
    )
    assert actor.get("identity_provider") == "oidc", "actor must record HOW identity was verified"
    assert actor.get("identity_verified") is True


def test_expired_jwt_rejected(auth_client, rsa_keypair) -> None:
    """An expired JWT must be rejected with 401, not silently accepted."""
    token = _make_signed_jwt(rsa_keypair, expired=True)
    r = auth_client.post(
        "/v1/ledger/events",
        json=_severity_event(),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401, f"expired JWT should be rejected; got {r.status_code}: {r.json()}"


def test_wrong_issuer_rejected(auth_client, rsa_keypair) -> None:
    """A JWT from an untrusted issuer must be rejected."""
    token = _make_signed_jwt(
        rsa_keypair,
        issuer="https://evil.example.com/realms/fake",
    )
    r = auth_client.post(
        "/v1/ledger/events",
        json=_severity_event(),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401, (
        f"wrong-issuer JWT should be rejected; got {r.status_code}: {r.json()}"
    )


def test_machine_token_resolves_machine_actor(auth_client, rsa_keypair) -> None:
    """A service-account JWT (azp present, no email) should resolve to kind=machine."""
    token = _make_signed_jwt(
        rsa_keypair,
        {
            "sub": "svc-scanner@clients",
            "azp": "scanner-service",
            "typ": "Bearer",
            "email": None,
        },
    )
    r = auth_client.post(
        "/v1/ledger/events",
        json=_severity_event(),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 422, (
        "service-account JWT should resolve to machine actor and be gate-rejected"
    )
    assert "machine" in r.json()["detail"].lower()


# ── Task 4: identity_verification field on events ────────────────


def test_identity_verification_field_on_event(auth_client, rsa_keypair) -> None:
    """Countersign events must record how the actor's identity was verified."""
    token = _make_signed_jwt(
        rsa_keypair,
        {"sub": "bob@example.com", "email": "bob@example.com"},
    )
    r = auth_client.post(
        "/v1/ledger/events",
        json=_severity_event(),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    auth_headers = {"Authorization": f"Bearer {token}"}
    layer = auth_client.get(f"/v1/ledger/layers/{LAYER}", headers=auth_headers).json()
    events = layer["events"]
    human_events = [
        e for e in events if e.get("source", {}).get("actor", {}).get("kind") == "human"
    ]
    assert human_events
    actor = human_events[-1]["source"]["actor"]
    assert "identity_provider" in actor, "actor must include identity_provider field (e.g. 'oidc')"
    assert actor.get("identity_verified") is True


# ── Employee directory cross-check (DI-based) ───────────────────


def test_oidc_plus_ldap_cross_check(
    tmp_path,
    httpserver: HTTPServer,
    rsa_keypair,
    jwks_json,
) -> None:
    """When an EmployeeDirectory is wired and the employee is active,
    actor gets ldap_verified=True and identity_verification='oidc+ldap'."""
    httpserver.expect_request("/.well-known/jwks.json").respond_with_json(jwks_json)
    jwks_url = httpserver.url_for("/.well-known/jwks.json")
    config = ServiceConfig(
        backend_type=BACKEND_TYPE_DB,
        database_url=f"sqlite:///{tmp_path}/ledger.db",
        data_dir=str(tmp_path),
        signing_required=False,
        oidc_issuer=TEST_ISSUER,
        oidc_jwks_url=jwks_url,
    )
    app = create_app(config)
    from conftest import canonical_shell

    app.state.backend.initialize(tmp_path / f"{LAYER}.json", canonical_shell())
    app.state.resolver._directory = _FakeDirectory(active=True)
    client = TestClient(app)

    token = _make_signed_jwt(
        rsa_keypair,
        {"sub": "carol@example.com", "email": "carol@example.com"},
    )
    r = client.post(
        "/v1/ledger/events",
        json=_severity_event(),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    auth_headers = {"Authorization": f"Bearer {token}"}
    layer = client.get(f"/v1/ledger/layers/{LAYER}", headers=auth_headers).json()
    human_events = [
        e for e in layer["events"] if e.get("source", {}).get("actor", {}).get("kind") == "human"
    ]
    assert human_events
    actor = human_events[-1]["source"]["actor"]
    assert actor.get("identity_provider") == "oidc"
    assert actor.get("identity_verified") is True
    assert actor.get("employee_status") == "active"


def test_oidc_ldap_not_found_rejected(
    tmp_path,
    httpserver: HTTPServer,
    rsa_keypair,
    jwks_json,
) -> None:
    """When an EmployeeDirectory is wired but the employee is not active, reject."""
    httpserver.expect_request("/.well-known/jwks.json").respond_with_json(jwks_json)
    jwks_url = httpserver.url_for("/.well-known/jwks.json")
    config = ServiceConfig(
        backend_type=BACKEND_TYPE_DB,
        database_url=f"sqlite:///{tmp_path}/ledger.db",
        data_dir=str(tmp_path),
        signing_required=False,
        oidc_issuer=TEST_ISSUER,
        oidc_jwks_url=jwks_url,
    )
    app = create_app(config)
    from conftest import canonical_shell

    app.state.backend.initialize(tmp_path / f"{LAYER}.json", canonical_shell())
    app.state.resolver._directory = _FakeDirectory(active=False)
    client = TestClient(app)

    token = _make_signed_jwt(
        rsa_keypair,
        {"sub": "gone@example.com", "email": "gone@example.com"},
    )
    r = client.post(
        "/v1/ledger/events",
        json=_severity_event(),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401


def test_oidc_without_ldap_gives_unverified(auth_client, rsa_keypair) -> None:
    """Without an EmployeeDirectory, OIDC actors have no employee_status."""
    token = _make_signed_jwt(
        rsa_keypair,
        {"sub": "dave@example.com", "email": "dave@example.com"},
    )
    r = auth_client.post(
        "/v1/ledger/events",
        json=_severity_event(),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    auth_headers = {"Authorization": f"Bearer {token}"}
    layer = auth_client.get(f"/v1/ledger/layers/{LAYER}", headers=auth_headers).json()
    human_events = [
        e for e in layer["events"] if e.get("source", {}).get("actor", {}).get("kind") == "human"
    ]
    assert human_events
    actor = human_events[-1]["source"]["actor"]
    assert actor.get("identity_verified") is True
    assert actor.get("identity_provider") == "oidc"
    assert actor.get("employee_status") is None


# ── Task 5: signing config OIDC passthrough ─────────────────────


def test_signing_config_passes_oidc_fields(tmp_path) -> None:
    """When signing_method='identity', ServiceConfig must expose OIDC fields
    that get passed through to SigningConfig."""
    config = ServiceConfig(
        backend_type="file",
        data_dir=str(tmp_path),
        signing_required=False,
        signing_method="identity",
    )
    assert hasattr(config, "oidc_issuer_url"), (
        "ServiceConfig needs oidc_issuer_url for identity-based signing"
    )
    assert hasattr(config, "oidc_client_id"), (
        "ServiceConfig needs oidc_client_id for identity-based signing"
    )


# ── Edge case tests ─────────────────────────────────────────────


class TestEdgeCases:
    def test_malformed_jwt_body_returns_401(self, auth_client) -> None:
        """A bearer token that isn't even valid base64 must yield 401, not 500."""
        r = auth_client.post(
            "/v1/ledger/events",
            json=_severity_event(),
            headers={"Authorization": "Bearer not.even.base64!"},
        )
        assert r.status_code == 401

    def test_missing_identity_claims_rejected(self, auth_client, rsa_keypair) -> None:
        """A JWT with neither sub nor email should be rejected."""
        token = _make_signed_jwt(rsa_keypair, {"sub": "", "email": ""})
        r = auth_client.post(
            "/v1/ledger/events",
            json=_severity_event(),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code in (401, 422)

    def test_alg_none_attack_rejected(self, auth_client) -> None:
        """An unsigned JWT (alg:none) with valid claims must be rejected."""
        import base64 as b64

        raw_hdr = b64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=")
        raw_body = b64.urlsafe_b64encode(
            json.dumps(
                {
                    "iss": TEST_ISSUER,
                    "sub": "alice@example.com",
                    "email": "alice@example.com",
                    "iat": int(time.time()) - 60,
                    "exp": int(time.time()) + 3600,
                }
            ).encode()
        ).rstrip(b"=")
        forged = f"{raw_hdr.decode()}.{raw_body.decode()}."
        r = auth_client.post(
            "/v1/ledger/events",
            json=_severity_event(),
            headers={"Authorization": f"Bearer {forged}"},
        )
        assert r.status_code == 401, (
            f"unsigned JWT (alg:none) should be rejected; got {r.status_code}"
        )

    def test_nbf_future_rejected(self, auth_client, rsa_keypair) -> None:
        """A JWT with nbf (not-before) in the future should be rejected."""
        token = _make_signed_jwt(
            rsa_keypair,
            {
                "nbf": int(time.time()) + 3600,
            },
        )
        r = auth_client.post(
            "/v1/ledger/events",
            json=_severity_event(),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 401, f"nbf-future JWT should be rejected; got {r.status_code}"


# ── Identity domain unit tests ──────────────────────────────────


def _fake_request(token: str) -> object:
    from starlette.requests import Request as StarletteRequest

    scope = {
        "type": "http",
        "method": "POST",
        "headers": [(b"authorization", f"Bearer {token}".encode())],
    }
    return StarletteRequest(scope)


class TestActorResolver:
    def test_resolver_with_fake_verifier(self) -> None:
        from fastapi import Request
        from traust_contracts.v1.models.layer import LayerActor

        from traust_ledger.service.identity.resolver import ActorResolver

        class FakeVerifier:
            def verify(self, request: Request) -> LayerActor:
                return LayerActor(
                    kind="human",
                    identity="test@example.com",
                    identity_verified=True,
                    identity_provider="test",
                )

        resolver = ActorResolver(FakeVerifier())
        actor = resolver.resolve(_fake_request("any-token"))
        assert actor.kind == "human"
        assert actor.identity == "test@example.com"
        assert actor.identity_verified is True

    def test_resolver_with_directory(self) -> None:
        from fastapi import Request
        from traust_contracts.v1.models.layer import LayerActor

        from traust_ledger.service.identity.resolver import ActorResolver

        class FakeVerifier:
            def verify(self, request: Request) -> LayerActor:
                return LayerActor(
                    kind="human",
                    identity="test@example.com",
                    identity_verified=True,
                    identity_provider="oidc",
                )

        resolver = ActorResolver(FakeVerifier(), _FakeDirectory(active=True))
        actor = resolver.resolve(_fake_request("any-token"))
        assert actor.identity_verified is True
        assert actor.employee_status == "active"

    def test_resolver_directory_rejects(self) -> None:
        from fastapi import Request
        from traust_contracts.v1.models.layer import LayerActor

        from traust_ledger.service.errors import InvalidAuthError
        from traust_ledger.service.identity.resolver import ActorResolver

        class FakeVerifier:
            def verify(self, request: Request) -> LayerActor:
                return LayerActor(
                    kind="human",
                    identity="test@example.com",
                    identity_verified=True,
                    identity_provider="oidc",
                )

        resolver = ActorResolver(FakeVerifier(), _FakeDirectory(active=False))
        with pytest.raises(InvalidAuthError):
            resolver.resolve(_fake_request("any-token"))

    def test_resolver_skips_directory_for_machine(self) -> None:
        from fastapi import Request
        from traust_contracts.v1.models.layer import LayerActor

        from traust_ledger.service.identity.resolver import ActorResolver

        class FakeVerifier:
            def verify(self, request: Request) -> LayerActor:
                return LayerActor(
                    kind="machine",
                    identity="svc:bot",
                    identity_verified=True,
                    identity_provider="oidc",
                )

        resolver = ActorResolver(FakeVerifier(), _FakeDirectory(active=False))
        actor = resolver.resolve(_fake_request("any-token"))
        assert actor.employee_status is None


class TestMultiIssuerOIDC:
    """LAAS_OIDC_TRUST lets the ledger accept tokens from more than one issuer,
    e.g. a browser SSO provider for humans and the cluster ServiceAccount
    issuer for machine callers."""

    ISSUER_A = "https://sso.example.com/realms/humans"
    ISSUER_B = "https://oidc.cluster.example/abc123"

    def _client(self, tmp_path, httpserver, jwks_json):
        # Two JWKS endpoints (same key material is fine for the test), one per
        # issuer, wired through LAAS_OIDC_TRUST.
        httpserver.expect_request("/humans/jwks").respond_with_json(jwks_json)
        httpserver.expect_request("/cluster/jwks").respond_with_json(jwks_json)
        trust = json.dumps(
            [
                {
                    "issuer": self.ISSUER_A,
                    "jwks_url": httpserver.url_for("/humans/jwks"),
                    "audience": "laas-humans",
                },
                {
                    "issuer": self.ISSUER_B,
                    "jwks_url": httpserver.url_for("/cluster/jwks"),
                    "audience": "laas-api",
                },
            ]
        )
        config = ServiceConfig(
            backend_type=BACKEND_TYPE_DB,
            database_url=f"sqlite:///{tmp_path}/ledger.db",
            data_dir=str(tmp_path),
            signing_required=False,
            oidc_trust=trust,
        )
        return TestClient(create_app(config))

    def test_human_token_from_issuer_a_accepted(self, tmp_path, httpserver, rsa_keypair, jwks_json):
        client = self._client(tmp_path, httpserver, jwks_json)
        token = _make_signed_jwt(
            rsa_keypair,
            {"aud": "laas-humans", "email": "alice@example.com", "sub": "alice@example.com"},
            issuer=self.ISSUER_A,
        )
        r = client.post(
            "/v1/ledger/events",
            json=_severity_event(),
            headers={"Authorization": f"Bearer {token}"},
        )
        # Reaches the handler (not 401); gate/validation may reject with 422.
        assert r.status_code != 401, r.text

    def test_machine_token_from_issuer_b_accepted(
        self, tmp_path, httpserver, rsa_keypair, jwks_json
    ):
        client = self._client(tmp_path, httpserver, jwks_json)
        token = _make_signed_jwt(
            rsa_keypair,
            {"aud": "laas-api", "sub": "system:serviceaccount:sci:sci", "email": None},
            issuer=self.ISSUER_B,
        )
        # Machine token on the query (read) path — must authenticate (200), not 401.
        r = client.get(
            "/v1/ledger/findings",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200, r.text

    def test_untrusted_issuer_rejected(self, tmp_path, httpserver, rsa_keypair, jwks_json):
        client = self._client(tmp_path, httpserver, jwks_json)
        token = _make_signed_jwt(
            rsa_keypair,
            {"aud": "laas-api", "email": "eve@evil.example"},
            issuer="https://evil.example/realms/rogue",
        )
        r = client.post(
            "/v1/ledger/events",
            json=_severity_event(),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 401, r.text

    def test_wrong_audience_rejected(self, tmp_path, httpserver, rsa_keypair, jwks_json):
        client = self._client(tmp_path, httpserver, jwks_json)
        # Trusted issuer A but audience meant for issuer B — must be rejected.
        token = _make_signed_jwt(
            rsa_keypair,
            {"aud": "laas-api", "email": "alice@example.com"},
            issuer=self.ISSUER_A,
        )
        r = client.post(
            "/v1/ledger/events",
            json=_severity_event(),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 401, r.text
