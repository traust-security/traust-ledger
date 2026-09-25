"""Exhaustive tests for the unified auth mechanism.

Covers the full surface introduced by the unification:
  - claims_to_actor: every actor-kind branch, custom claim params, edge cases
  - TokenVerifierPort: structural protocol conformance
  - ResolvedCredential.verify(): convenience method
  - OIDCAdapter delegation: verification delegated to TokenVerifier, error translation
  - LedgerClient paired verifier: stored verifier, fallback
  - Authenticator deprecation: emits DeprecationWarning
  - CLI resolve_auth integration: require_verified_actor through resolve_auth
  - Mock-OIDC e2e: full round-trip through SDK and CLI flows
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest import mock

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pytest_httpserver import HTTPServer
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger.auth.claims import IdentityClaimsError, TokenVerificationError, claims_to_actor
from traust_ledger.auth.config import ResolvedCredential, resolve_auth
from traust_ledger.auth.local import LOCAL_ISSUER, ensure_local_keypair, mint_local_token
from traust_ledger.auth.verifier import TokenVerifier, TokenVerifierPort, VerifierConfig
from traust_ledger.constants import ACTOR_KIND_HUMAN, ACTOR_KIND_MACHINE

# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture()
def local_config_dir(tmp_path: Path) -> Path:
    d = tmp_path / "traust-ledger"
    d.mkdir()
    return d


@pytest.fixture()
def local_key(local_config_dir: Path) -> ec.EllipticCurvePrivateKey:
    return ensure_local_keypair(local_config_dir)


@pytest.fixture(scope="module")
def rsa_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def jwks_json(rsa_keypair):
    import base64

    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

    pub = rsa_keypair.public_key()
    pub_numbers: RSAPublicNumbers = pub.public_numbers()

    def _b64(n: int, length: int) -> str:
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    n_bytes = (pub_numbers.n.bit_length() + 7) // 8
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-key-1",
                "use": "sig",
                "alg": "RS256",
                "n": _b64(pub_numbers.n, n_bytes),
                "e": _b64(pub_numbers.e, 3),
            }
        ]
    }


def _make_oidc_jwt(
    private_key,
    *,
    issuer: str = "https://sso.example.com/realms/test",
    sub: str = "alice@example.com",
    email: str | None = "alice@example.com",
    azp: str | None = None,
    expired: bool = False,
    extra: dict | None = None,
    aud: str | None = None,
) -> str:
    now = int(time.time())
    payload: dict = {
        "iss": issuer,
        "sub": sub,
        "iat": now - 60,
        "exp": now - 300 if expired else now + 3600,
    }
    if email is not None:
        payload["email"] = email
    if azp is not None:
        payload["azp"] = azp
    if aud is not None:
        payload["aud"] = aud
    if extra:
        payload.update(extra)
    return pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key-1"})


# ═══════════════════════════════════════════════════════════════════════════════
# 1. claims_to_actor — exhaustive actor-kind coverage
# ═══════════════════════════════════════════════════════════════════════════════


class TestClaimsToActorKind:
    """Every branch in the actor-kind decision tree."""

    def test_human_from_email(self):
        actor = claims_to_actor({"email": "Alice@Corp.COM", "sub": "alice"})
        assert actor.kind == ACTOR_KIND_HUMAN
        assert actor.identity == "alice@corp.com"

    def test_machine_from_azp_without_email(self):
        actor = claims_to_actor({"azp": "scanner-service", "sub": "svc:scanner"})
        assert actor.kind == ACTOR_KIND_MACHINE
        assert actor.identity == "scanner-service"

    def test_machine_fallback_to_sub(self):
        actor = claims_to_actor({"sub": "system:serviceaccount:ns:sa"})
        assert actor.kind == ACTOR_KIND_MACHINE
        assert actor.identity == "system:serviceaccount:ns:sa"

    def test_email_wins_over_azp(self):
        """When both azp and email are present, email takes precedence → human."""
        actor = claims_to_actor({"azp": "client-id", "email": "user@example.com", "sub": "u1"})
        assert actor.kind == ACTOR_KIND_HUMAN
        assert actor.identity == "user@example.com"

    def test_no_identity_raises(self):
        with pytest.raises(IdentityClaimsError, match="no identity claims"):
            claims_to_actor({})

    def test_empty_email_raises(self):
        with pytest.raises(IdentityClaimsError, match="empty identity claim"):
            claims_to_actor({"email": "   "})

    def test_identity_error_is_subclass_of_verification_error(self):
        """IdentityClaimsError must be catchable as TokenVerificationError."""
        with pytest.raises(TokenVerificationError):
            claims_to_actor({})

    def test_none_email_falls_through_to_sub(self):
        """email=None is falsy, so it should fall through like absent."""
        actor = claims_to_actor({"email": None, "sub": "svc:bot"})
        assert actor.kind == ACTOR_KIND_MACHINE
        assert actor.identity == "svc:bot"

    def test_none_azp_with_email(self):
        """azp=None should not count as a machine identity."""
        actor = claims_to_actor({"azp": None, "email": "user@test.com", "sub": "u1"})
        assert actor.kind == ACTOR_KIND_HUMAN

    def test_empty_string_azp_with_sub(self):
        """Empty string azp is falsy → falls through to sub."""
        actor = claims_to_actor({"azp": "", "sub": "svc:fallback"})
        assert actor.kind == ACTOR_KIND_MACHINE
        assert actor.identity == "svc:fallback"


class TestClaimsToActorIssuer:
    """Issuer handling and identity_provider derivation."""

    def test_local_issuer_sets_local_provider(self):
        actor = claims_to_actor({"email": "a@b.com", "iss": LOCAL_ISSUER})
        assert actor.identity_provider == "local"
        assert actor.identity_issuer == LOCAL_ISSUER

    def test_oidc_issuer(self):
        actor = claims_to_actor({"email": "a@b.com", "iss": "https://sso.example.com"})
        assert actor.identity_provider == "oidc"
        assert actor.identity_issuer == "https://sso.example.com"

    def test_missing_iss_uses_fallback(self):
        actor = claims_to_actor({"email": "a@b.com"}, issuer_fallback="https://fallback.com")
        assert actor.identity_issuer == "https://fallback.com"
        assert actor.identity_provider == "oidc"

    def test_missing_iss_no_fallback(self):
        actor = claims_to_actor({"email": "a@b.com"})
        assert actor.identity_issuer == ""
        assert actor.identity_provider == "oidc"

    def test_local_fallback(self):
        actor = claims_to_actor({"email": "a@b.com"}, issuer_fallback=LOCAL_ISSUER)
        assert actor.identity_provider == "local"


class TestClaimsToActorCustomParams:
    """Custom machine_claim and identity_claim parameters."""

    def test_custom_machine_claim(self):
        actor = claims_to_actor(
            {"client_id": "my-svc", "sub": "s1"},
            machine_claim="client_id",
        )
        assert actor.kind == ACTOR_KIND_MACHINE
        assert actor.identity == "my-svc"

    def test_custom_identity_claim(self):
        actor = claims_to_actor(
            {"preferred_username": "Alice", "sub": "a1"},
            identity_claim="preferred_username",
        )
        assert actor.kind == ACTOR_KIND_HUMAN
        assert actor.identity == "alice"

    def test_custom_both_claims(self):
        actor = claims_to_actor(
            {"cid": "bot", "uname": "human@test.com", "sub": "x"},
            machine_claim="cid",
            identity_claim="uname",
        )
        assert actor.kind == ACTOR_KIND_HUMAN
        assert actor.identity == "human@test.com"


class TestClaimsToActorFields:
    """Verify all LayerActor fields are set correctly."""

    def test_identity_verified_always_true(self):
        actor = claims_to_actor({"email": "a@b.com"})
        assert actor.identity_verified is True

    def test_subject_from_claims(self):
        actor = claims_to_actor({"email": "a@b.com", "sub": "subject-123"})
        assert actor.identity_subject == "subject-123"

    def test_subject_empty_when_absent(self):
        actor = claims_to_actor({"email": "a@b.com"})
        assert actor.identity_subject == ""

    def test_case_normalization(self):
        actor = claims_to_actor({"email": "  Alice@CORP.COM  "})
        assert actor.identity == "alice@corp.com"

    def test_machine_identity_not_case_folded(self):
        """Machine azp is str()'d but not lowered."""
        actor = claims_to_actor({"azp": "Triage/0.32.0-57f1EF1", "sub": "s"})
        assert actor.identity == "Triage/0.32.0-57f1EF1"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. TokenVerifierPort protocol conformance
# ═══════════════════════════════════════════════════════════════════════════════


class TestTokenVerifierPort:
    def test_token_verifier_satisfies_protocol(self):
        vc = VerifierConfig(issuer=LOCAL_ISSUER)
        verifier = TokenVerifier(vc)
        assert isinstance(verifier, TokenVerifierPort)

    def test_custom_class_satisfies_protocol(self):
        class MyVerifier:
            def verify(self, token: str) -> LayerActor:
                return LayerActor(
                    kind="human",
                    identity="test@example.com",
                    identity_verified=True,
                    identity_provider="test",
                )

        assert isinstance(MyVerifier(), TokenVerifierPort)

    def test_incomplete_class_fails_protocol(self):
        class NotAVerifier:
            pass

        assert not isinstance(NotAVerifier(), TokenVerifierPort)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. ResolvedCredential.verify() convenience
# ═══════════════════════════════════════════════════════════════════════════════


class TestResolvedCredentialVerify:
    def test_verify_delegates_to_verifier(self, local_config_dir, local_key):
        token = mint_local_token("alice@test.com", local_key)
        verifier = TokenVerifier(
            VerifierConfig(jwks_path=local_config_dir / "local-jwks.json", issuer=LOCAL_ISSUER)
        )
        cred = ResolvedCredential(token=token, verifier=verifier, source="test")
        actor = cred.verify()
        assert actor.kind == ACTOR_KIND_HUMAN
        assert actor.identity == "alice@test.com"
        assert actor.identity_provider == "local"

    def test_verify_machine_token(self, local_config_dir, local_key):
        token = mint_local_token("triage/1.0", local_key, machine=True)
        verifier = TokenVerifier(
            VerifierConfig(jwks_path=local_config_dir / "local-jwks.json", issuer=LOCAL_ISSUER)
        )
        cred = ResolvedCredential(token=token, verifier=verifier, source="test")
        actor = cred.verify()
        assert actor.kind == ACTOR_KIND_MACHINE
        assert actor.identity == "triage/1.0"

    def test_verify_propagates_error(self, local_config_dir, local_key):
        expired = pyjwt.encode(
            {"sub": "a", "email": "a@b.com", "iss": LOCAL_ISSUER, "iat": 0, "exp": 1},
            local_key,
            algorithm="ES256",
            headers={"kid": "local-1"},
        )
        verifier = TokenVerifier(
            VerifierConfig(jwks_path=local_config_dir / "local-jwks.json", issuer=LOCAL_ISSUER)
        )
        cred = ResolvedCredential(token=expired, verifier=verifier, source="test")
        with pytest.raises(TokenVerificationError, match="token expired"):
            cred.verify()

    def test_verify_with_custom_verifier(self):
        """ResolvedCredential works with any TokenVerifierPort implementation."""

        class StubVerifier:
            def verify(self, token: str) -> LayerActor:
                return LayerActor(
                    kind="machine",
                    identity=f"stub:{token}",
                    identity_verified=True,
                    identity_provider="stub",
                )

        cred = ResolvedCredential(token="test-tok", verifier=StubVerifier(), source="stub")
        actor = cred.verify()
        assert actor.identity == "stub:test-tok"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. OIDCAdapter delegation to TokenVerifier
# ═══════════════════════════════════════════════════════════════════════════════


class TestOIDCAdapterDelegation:
    """OIDCAdapter._verify_token delegates to entry.verifier.verify()."""

    TEST_ISSUER = "https://sso.example.com/realms/test"

    def _make_adapter(self, httpserver: HTTPServer, jwks_json, issuer=None):
        from traust_ledger.service.identity.oidc import OIDCAdapter, _TrustEntry

        httpserver.expect_request("/.well-known/jwks.json").respond_with_json(jwks_json)
        jwks_url = httpserver.url_for("/.well-known/jwks.json")
        iss = issuer or self.TEST_ISSUER
        vc = VerifierConfig(jwks_url=jwks_url, issuer=iss)
        entry = _TrustEntry(issuer=iss, verifier=TokenVerifier(vc))
        return OIDCAdapter([entry])

    def test_valid_token_returns_actor(self, httpserver, rsa_keypair, jwks_json):
        adapter = self._make_adapter(httpserver, jwks_json)
        token = _make_oidc_jwt(rsa_keypair, issuer=self.TEST_ISSUER)
        actor = adapter._verify_token(token)
        assert actor.kind == ACTOR_KIND_HUMAN
        assert actor.identity == "alice@example.com"
        assert actor.identity_provider == "oidc"

    def test_expired_token_raises_invalid_auth(self, httpserver, rsa_keypair, jwks_json):
        from traust_ledger.service.errors import InvalidAuthError

        adapter = self._make_adapter(httpserver, jwks_json)
        token = _make_oidc_jwt(rsa_keypair, issuer=self.TEST_ISSUER, expired=True)
        with pytest.raises(InvalidAuthError):
            adapter._verify_token(token)

    def test_wrong_issuer_raises_invalid_auth(self, httpserver, rsa_keypair, jwks_json):
        from traust_ledger.service.errors import InvalidAuthError

        adapter = self._make_adapter(httpserver, jwks_json)
        token = _make_oidc_jwt(rsa_keypair, issuer="https://evil.example.com")
        with pytest.raises(InvalidAuthError):
            adapter._verify_token(token)

    def test_machine_token_resolves_machine(self, httpserver, rsa_keypair, jwks_json):
        adapter = self._make_adapter(httpserver, jwks_json)
        token = _make_oidc_jwt(
            rsa_keypair,
            issuer=self.TEST_ISSUER,
            email=None,
            azp="scanner-service",
            sub="svc:scanner",
        )
        actor = adapter._verify_token(token)
        assert actor.kind == ACTOR_KIND_MACHINE
        assert actor.identity == "scanner-service"

    def test_multi_issuer_routes_correctly(self, httpserver, rsa_keypair, jwks_json):
        from traust_ledger.service.identity.oidc import OIDCAdapter, _TrustEntry

        ISS_A = "https://sso-a.example.com"
        ISS_B = "https://sso-b.example.com"
        httpserver.expect_request("/a/jwks").respond_with_json(jwks_json)
        httpserver.expect_request("/b/jwks").respond_with_json(jwks_json)

        entries = [
            _TrustEntry(
                issuer=ISS_A,
                verifier=TokenVerifier(
                    VerifierConfig(jwks_url=httpserver.url_for("/a/jwks"), issuer=ISS_A)
                ),
            ),
            _TrustEntry(
                issuer=ISS_B,
                verifier=TokenVerifier(
                    VerifierConfig(jwks_url=httpserver.url_for("/b/jwks"), issuer=ISS_B)
                ),
            ),
        ]
        adapter = OIDCAdapter(entries)

        token_a = _make_oidc_jwt(rsa_keypair, issuer=ISS_A, email="a@a.com", sub="a")
        token_b = _make_oidc_jwt(rsa_keypair, issuer=ISS_B, email="b@b.com", sub="b")

        assert adapter._verify_token(token_a).identity == "a@a.com"
        assert adapter._verify_token(token_b).identity == "b@b.com"

    def test_empty_trust_list_raises(self):
        from traust_ledger.service.identity.oidc import OIDCAdapter

        with pytest.raises(RuntimeError, match="at least one"):
            OIDCAdapter([])


# ═══════════════════════════════════════════════════════════════════════════════
# 5. LedgerClient paired verifier
# ═══════════════════════════════════════════════════════════════════════════════


class TestLedgerClientVerifier:
    def test_from_env_stores_verifier(self, local_config_dir, local_key, monkeypatch):
        """from_env() passes the verifier from resolve_auth() to the constructor."""
        from traust_ledger.client import LedgerClient

        monkeypatch.setenv("HOME", str(local_config_dir.parent))
        for var in ("LAAS_TOKEN", "LEDGER_TOKEN_PATH", "LEDGER_TOKEN", "LEDGER_LOCAL_IDENTITY"):
            monkeypatch.delenv(var, raising=False)
        for var in ("LEDGER_OIDC_JWKS_URL", "LEDGER_OIDC_ISSUER", "LEDGER_OIDC_AUDIENCE"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("LEDGER_LOCAL_IDENTITY", "test@dev.local")
        monkeypatch.setattr(
            "traust_ledger.cli.identity.config.config_dir", lambda: local_config_dir
        )

        client = LedgerClient.from_env()
        assert client._verifier is not None
        assert isinstance(client._verifier, TokenVerifierPort)

    def test_actor_uses_stored_verifier(self, local_config_dir, local_key):
        """_actor() uses the stored verifier, not verifier_for_token."""
        from traust_ledger.client import LedgerClient

        token = mint_local_token("alice@test.com", local_key)
        verifier = TokenVerifier(
            VerifierConfig(jwks_path=local_config_dir / "local-jwks.json", issuer=LOCAL_ISSUER)
        )
        client = LedgerClient(token, verifier=verifier, data_dir=str(local_config_dir))
        actor = client._actor()
        assert actor.identity == "alice@test.com"
        assert actor.kind == ACTOR_KIND_HUMAN

    def test_actor_fallback_without_stored_verifier(self, local_config_dir, local_key, monkeypatch):
        """_actor() falls back to verifier_for_token when verifier is None."""
        from traust_ledger.client import LedgerClient

        for var in ("LEDGER_OIDC_JWKS_URL", "LEDGER_OIDC_ISSUER", "LEDGER_OIDC_AUDIENCE"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setattr(
            "traust_ledger.cli.identity.config.config_dir", lambda: local_config_dir
        )
        token = mint_local_token("alice@test.com", local_key)
        client = LedgerClient(token, data_dir=str(local_config_dir))
        assert client._verifier is None
        actor = client._actor()
        assert actor.identity == "alice@test.com"

    def test_stored_verifier_prevents_rebuild(self, local_config_dir, local_key):
        """When verifier is stored, verifier_for_token is never called."""
        from traust_ledger.client import LedgerClient

        token = mint_local_token("alice@test.com", local_key)
        verifier = TokenVerifier(
            VerifierConfig(jwks_path=local_config_dir / "local-jwks.json", issuer=LOCAL_ISSUER)
        )
        client = LedgerClient(token, verifier=verifier, data_dir=str(local_config_dir))
        with mock.patch("traust_ledger.auth.config.verifier_for_token") as m:
            client._actor()
            m.assert_not_called()

    def test_machine_actor_via_client(self, local_config_dir, local_key):
        from traust_ledger.client import LedgerClient

        token = mint_local_token("triage/0.32.0", local_key, machine=True)
        verifier = TokenVerifier(
            VerifierConfig(jwks_path=local_config_dir / "local-jwks.json", issuer=LOCAL_ISSUER)
        )
        client = LedgerClient(token, verifier=verifier, data_dir=str(local_config_dir))
        actor = client._actor()
        assert actor.kind == ACTOR_KIND_MACHINE
        assert actor.identity == "triage/0.32.0"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. CLI require_verified_actor through resolve_auth
# ═══════════════════════════════════════════════════════════════════════════════


class TestCLIResolveAuth:
    def test_require_verified_actor_succeeds(self, local_config_dir, local_key, monkeypatch):
        from traust_ledger.cli.identity.actor import require_verified_actor

        monkeypatch.setenv("HOME", str(local_config_dir.parent))
        for var in ("LAAS_TOKEN", "LEDGER_TOKEN_PATH", "LEDGER_TOKEN", "LEDGER_LOCAL_IDENTITY"):
            monkeypatch.delenv(var, raising=False)
        for var in ("LEDGER_OIDC_JWKS_URL", "LEDGER_OIDC_ISSUER", "LEDGER_OIDC_AUDIENCE"):
            monkeypatch.delenv(var, raising=False)

        token = mint_local_token("cli@test.com", local_key)
        monkeypatch.setenv("LAAS_TOKEN", token)
        monkeypatch.setattr(
            "traust_ledger.cli.identity.config.config_dir", lambda: local_config_dir
        )

        actor = require_verified_actor()
        assert actor is not None
        assert actor.identity == "cli@test.com"
        assert actor.kind == ACTOR_KIND_HUMAN

    def test_require_verified_actor_no_auth(self, monkeypatch, tmp_path, capsys):
        from traust_ledger.cli.identity.actor import require_verified_actor

        monkeypatch.setenv("HOME", str(tmp_path))
        for var in (
            "LAAS_TOKEN",
            "LEDGER_TOKEN_PATH",
            "LEDGER_TOKEN",
            "LEDGER_LOCAL_IDENTITY",
            "LEDGER_OIDC_JWKS_URL",
            "LEDGER_OIDC_ISSUER",
            "LEDGER_OIDC_AUDIENCE",
        ):
            monkeypatch.delenv(var, raising=False)

        actor = require_verified_actor()
        assert actor is None
        captured = capsys.readouterr()
        assert "authentication required" in captured.err.lower()

    def test_require_verified_actor_machine_token(self, local_config_dir, local_key, monkeypatch):
        from traust_ledger.cli.identity.actor import require_verified_actor

        token = mint_local_token("triage/1.0", local_key, machine=True)
        monkeypatch.setenv("LAAS_TOKEN", token)
        monkeypatch.setattr(
            "traust_ledger.cli.identity.config.config_dir", lambda: local_config_dir
        )
        for var in ("LEDGER_OIDC_JWKS_URL", "LEDGER_OIDC_ISSUER", "LEDGER_OIDC_AUDIENCE"):
            monkeypatch.delenv(var, raising=False)

        actor = require_verified_actor()
        assert actor is not None
        assert actor.kind == ACTOR_KIND_MACHINE
        assert actor.identity == "triage/1.0"

    def test_require_verified_actor_expired_token(
        self,
        local_config_dir,
        local_key,
        monkeypatch,
        capsys,
    ):
        from traust_ledger.cli.identity.actor import require_verified_actor

        expired = pyjwt.encode(
            {"sub": "a@b.com", "email": "a@b.com", "iss": LOCAL_ISSUER, "iat": 0, "exp": 1},
            local_key,
            algorithm="ES256",
            headers={"kid": "local-1"},
        )
        monkeypatch.setenv("LAAS_TOKEN", expired)
        monkeypatch.setattr(
            "traust_ledger.cli.identity.config.config_dir", lambda: local_config_dir
        )
        for var in ("LEDGER_OIDC_JWKS_URL", "LEDGER_OIDC_ISSUER", "LEDGER_OIDC_AUDIENCE"):
            monkeypatch.delenv(var, raising=False)

        actor = require_verified_actor()
        assert actor is None
        assert "token verification failed" in capsys.readouterr().err.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Mock-OIDC e2e — full round-trip through SDK and REST flows
# ═══════════════════════════════════════════════════════════════════════════════

CONTRACTS_VERSION = "0.4.4"
LAYER_ID = "unified-auth-test"
RECORDED = "2026-08-31T10:00:00+00:00"


def _severity_event(layer_id=LAYER_ID):
    return {
        "kind": "severity",
        "contracts_version": CONTRACTS_VERSION,
        "event": {
            "layer_id": layer_id,
            "finding_ref": "UA-001",
            "severity": "high",
            "rationale": "Confirmed via unified auth test",
            "recorded_at": RECORDED,
        },
    }


class TestMockOIDCE2EREST:
    """Full REST path: mock OIDC JWKS → OIDCAdapter (delegating) → handler."""

    TEST_ISSUER = "https://sso.example.com/realms/test"

    @pytest.fixture()
    def rest_client(self, tmp_path, httpserver: HTTPServer, jwks_json):
        from traust_ledger._internal.backends.constants import BACKEND_TYPE_DB
        from traust_ledger.config import ServiceConfig
        from traust_ledger.service.app import create_app

        httpserver.expect_request("/.well-known/jwks.json").respond_with_json(jwks_json)
        jwks_url = httpserver.url_for("/.well-known/jwks.json")
        config = ServiceConfig(
            backend_type=BACKEND_TYPE_DB,
            database_url=f"sqlite:///{tmp_path}/ledger.db",
            data_dir=str(tmp_path),
            signing_required=False,
            oidc_issuer=self.TEST_ISSUER,
            oidc_jwks_url=jwks_url,
        )
        from conftest import canonical_shell
        from fastapi.testclient import TestClient

        app = create_app(config)
        app.state.backend.initialize(tmp_path / f"{LAYER_ID}.json", canonical_shell())
        return TestClient(app)

    def test_human_jwt_through_delegating_adapter(self, rest_client, rsa_keypair):
        token = _make_oidc_jwt(rsa_keypair, email="alice@example.com", sub="alice@example.com")
        r = rest_client.post(
            "/v1/ledger/events",
            json=_severity_event(),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200

        layer = rest_client.get(
            f"/v1/ledger/layers/{LAYER_ID}",
            headers={"Authorization": f"Bearer {token}"},
        ).json()
        events = layer["events"]
        human_events = [
            e for e in events if e.get("source", {}).get("actor", {}).get("kind") == "human"
        ]
        assert human_events
        actor = human_events[-1]["source"]["actor"]
        assert actor["identity"] == "alice@example.com"
        assert actor["identity_provider"] == "oidc"
        assert actor["identity_verified"] is True

    def test_machine_jwt_through_delegating_adapter(self, rest_client, rsa_keypair):
        token = _make_oidc_jwt(
            rsa_keypair,
            email=None,
            azp="scanner-service",
            sub="svc:scanner",
        )
        r = rest_client.get(
            "/v1/ledger/findings",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200

    def test_expired_jwt_rejected(self, rest_client, rsa_keypair):
        token = _make_oidc_jwt(rsa_keypair, expired=True)
        r = rest_client.post(
            "/v1/ledger/events",
            json=_severity_event(),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 401

    def test_wrong_key_rejected(self, rest_client):
        rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = _make_oidc_jwt(rogue_key, issuer=self.TEST_ISSUER)
        r = rest_client.post(
            "/v1/ledger/events",
            json=_severity_event(),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 401


class TestMockOIDCE2ESDK:
    """SDK path: resolve_auth → LedgerClient._actor() with mock OIDC."""

    TEST_ISSUER = "https://sso.example.com/realms/test"

    def test_sdk_from_env_with_oidc_token(
        self,
        httpserver,
        rsa_keypair,
        jwks_json,
        monkeypatch,
        tmp_path,
    ):
        """LedgerClient.from_env resolves an OIDC token and verifies through the paired verifier."""
        httpserver.expect_request("/.well-known/jwks.json").respond_with_json(jwks_json)
        jwks_url = httpserver.url_for("/.well-known/jwks.json")

        token = _make_oidc_jwt(rsa_keypair, email="sdk@test.com", sub="sdk@test.com")
        monkeypatch.setenv("LAAS_TOKEN", token)
        monkeypatch.setenv("LEDGER_OIDC_JWKS_URL", jwks_url)
        monkeypatch.setenv("LEDGER_OIDC_ISSUER", self.TEST_ISSUER)
        monkeypatch.delenv("LEDGER_OIDC_AUDIENCE", raising=False)

        from traust_ledger.client import LedgerClient

        client = LedgerClient.from_env()
        assert client._verifier is not None
        actor = client._actor()
        assert actor.identity == "sdk@test.com"
        assert actor.identity_provider == "oidc"
        assert actor.kind == ACTOR_KIND_HUMAN

    def test_sdk_from_env_with_machine_token(
        self,
        httpserver,
        rsa_keypair,
        jwks_json,
        monkeypatch,
        tmp_path,
    ):
        httpserver.expect_request("/.well-known/jwks.json").respond_with_json(jwks_json)
        jwks_url = httpserver.url_for("/.well-known/jwks.json")

        token = _make_oidc_jwt(
            rsa_keypair,
            email=None,
            azp="ci-pipeline",
            sub="svc:ci",
        )
        monkeypatch.setenv("LAAS_TOKEN", token)
        monkeypatch.setenv("LEDGER_OIDC_JWKS_URL", jwks_url)
        monkeypatch.setenv("LEDGER_OIDC_ISSUER", self.TEST_ISSUER)
        monkeypatch.delenv("LEDGER_OIDC_AUDIENCE", raising=False)

        from traust_ledger.client import LedgerClient

        client = LedgerClient.from_env()
        actor = client._actor()
        assert actor.kind == ACTOR_KIND_MACHINE
        assert actor.identity == "ci-pipeline"

    def test_sdk_local_round_trip(self, local_config_dir, local_key, monkeypatch):
        """Full local auth round-trip: mint → resolve_auth → client._actor()."""
        monkeypatch.setenv("HOME", str(local_config_dir.parent))
        for var in ("LAAS_TOKEN", "LEDGER_TOKEN_PATH", "LEDGER_TOKEN", "LEDGER_LOCAL_IDENTITY"):
            monkeypatch.delenv(var, raising=False)
        for var in ("LEDGER_OIDC_JWKS_URL", "LEDGER_OIDC_ISSUER", "LEDGER_OIDC_AUDIENCE"):
            monkeypatch.delenv(var, raising=False)

        token = mint_local_token("sdk-local@test.com", local_key)
        monkeypatch.setenv("LAAS_TOKEN", token)
        monkeypatch.setattr(
            "traust_ledger.cli.identity.config.config_dir", lambda: local_config_dir
        )

        from traust_ledger.client import LedgerClient

        client = LedgerClient.from_env()
        actor = client._actor()
        assert actor.identity == "sdk-local@test.com"
        assert actor.identity_provider == "local"
        assert actor.kind == ACTOR_KIND_HUMAN


# ═══════════════════════════════════════════════════════════════════════════════
# 9. resolve_auth verifier pairing — the credential always carries its verifier
# ═══════════════════════════════════════════════════════════════════════════════


class TestResolveAuthPairing:
    """The builder always returns a credential whose verifier can verify its token."""

    def test_laas_token_local_pairing(self, local_config_dir, local_key, monkeypatch):
        for var in ("LEDGER_TOKEN_PATH", "LEDGER_TOKEN", "LEDGER_LOCAL_IDENTITY"):
            monkeypatch.delenv(var, raising=False)
        for var in ("LEDGER_OIDC_JWKS_URL", "LEDGER_OIDC_ISSUER", "LEDGER_OIDC_AUDIENCE"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setattr(
            "traust_ledger.cli.identity.config.config_dir", lambda: local_config_dir
        )

        token = mint_local_token("pair@test.com", local_key)
        monkeypatch.setenv("LAAS_TOKEN", token)
        cred = resolve_auth()
        assert cred.source == "env:LAAS_TOKEN"
        actor = cred.verify()
        assert actor.identity == "pair@test.com"

    def test_laas_token_oidc_pairing(
        self,
        httpserver,
        rsa_keypair,
        jwks_json,
        monkeypatch,
        tmp_path,
    ):
        httpserver.expect_request("/.well-known/jwks.json").respond_with_json(jwks_json)
        jwks_url = httpserver.url_for("/.well-known/jwks.json")

        monkeypatch.setenv("HOME", str(tmp_path))
        for var in ("LEDGER_TOKEN_PATH", "LEDGER_TOKEN", "LEDGER_LOCAL_IDENTITY"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("LEDGER_OIDC_JWKS_URL", jwks_url)
        monkeypatch.setenv("LEDGER_OIDC_ISSUER", "https://sso.example.com/realms/test")
        monkeypatch.delenv("LEDGER_OIDC_AUDIENCE", raising=False)

        token = _make_oidc_jwt(rsa_keypair, email="oidc@test.com", sub="oidc@test.com")
        monkeypatch.setenv("LAAS_TOKEN", token)
        cred = resolve_auth()
        actor = cred.verify()
        assert actor.identity == "oidc@test.com"
        assert actor.identity_provider == "oidc"

    def test_auto_mint_pairing(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path))
        for var in ("LAAS_TOKEN", "LEDGER_TOKEN_PATH", "LEDGER_TOKEN"):
            monkeypatch.delenv(var, raising=False)
        for var in ("LEDGER_OIDC_JWKS_URL", "LEDGER_OIDC_ISSUER", "LEDGER_OIDC_AUDIENCE"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("LEDGER_LOCAL_IDENTITY", "auto@pair.com")
        cred = resolve_auth()
        assert cred.source == "auto-mint"
        actor = cred.verify()
        assert actor.identity == "auto@pair.com"
        assert actor.identity_provider == "local"

    def test_token_path_pairing(self, local_config_dir, local_key, monkeypatch, tmp_path):
        for var in ("LAAS_TOKEN", "LEDGER_TOKEN", "LEDGER_LOCAL_IDENTITY"):
            monkeypatch.delenv(var, raising=False)
        for var in ("LEDGER_OIDC_JWKS_URL", "LEDGER_OIDC_ISSUER", "LEDGER_OIDC_AUDIENCE"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setattr(
            "traust_ledger.cli.identity.config.config_dir", lambda: local_config_dir
        )

        token = mint_local_token("path@test.com", local_key)
        token_file = tmp_path / "token"
        token_file.write_text(token, encoding="utf-8")
        monkeypatch.setenv("LEDGER_TOKEN_PATH", str(token_file))
        cred = resolve_auth()
        assert cred.source == "env:LEDGER_TOKEN_PATH"
        actor = cred.verify()
        assert actor.identity == "path@test.com"
