from __future__ import annotations

import base64
import sys
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pytest_httpserver import HTTPServer

from traust_ledger.config import ServiceConfig
from traust_ledger.service.app import create_app

LAYER_ID = "repo-a"
RECORDED_AT = "2026-01-16T00:00:00+00:00"
RATIONALE_OK = "Reviewed source and confirmed exploit path."
RATIONALE_SHORT = "too short"
CONTRACTS_VERSION = "0.4.4"

TEST_ISSUER = "https://sso.example.com/realms/test"


# ── Module-level keypair and JWKS (shared across all tests) ─────────────────


def _int_to_base64url(n: int, length: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


_RSA_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)

_PUB = _RSA_PRIVATE_KEY.public_key()
_PUB_NUMBERS: RSAPublicNumbers = _PUB.public_numbers()
_N_BYTES = (_PUB_NUMBERS.n.bit_length() + 7) // 8
_JWKS_JSON = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "test-key-1",
            "use": "sig",
            "alg": "RS256",
            "n": _int_to_base64url(_PUB_NUMBERS.n, _N_BYTES),
            "e": _int_to_base64url(_PUB_NUMBERS.e, 3),
        }
    ]
}


def make_signed_jwt(
    private_key=None,
    *,
    identity: str = "dev@test.local",
    issuer: str = TEST_ISSUER,
    expired: bool = False,
    extra_claims: dict | None = None,
) -> str:
    """Mint a properly RS256-signed JWT for test use."""
    key = private_key or _RSA_PRIVATE_KEY
    now = int(time.time())
    payload = {
        "iss": issuer,
        "sub": identity,
        "email": identity,
        "iat": now - 60,
        "exp": now - 300 if expired else now + 3600,
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, key, algorithm="RS256", headers={"kid": "test-key-1"})


def auth_header(private_key=None, **kwargs) -> dict[str, str]:
    """Return an Authorization header dict with a signed JWT."""
    token = make_signed_jwt(private_key, **kwargs)
    return {"Authorization": f"Bearer {token}"}


AUTH_HEADER: dict[str, str] = auth_header()


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def rsa_keypair():
    """RSA keypair used to sign all test JWTs."""
    return _RSA_PRIVATE_KEY


@pytest.fixture(scope="session")
def jwks_json():
    """JWKS document containing the session test public key."""
    return _JWKS_JSON


@pytest.fixture()
def app_with_backend(tmp_path: Path, httpserver: HTTPServer) -> FastAPI:
    httpserver.expect_request("/.well-known/jwks.json").respond_with_json(_JWKS_JSON)
    jwks_url = httpserver.url_for("/.well-known/jwks.json")
    config = ServiceConfig(
        backend_type="file",
        data_dir=str(tmp_path),
        signing_required=False,
        identity_provider="oidc",
        oidc_issuer=TEST_ISSUER,
        oidc_jwks_url=jwks_url,
    )
    app = create_app(config)
    from traust_ledger._internal.backends.file import FileBackend

    FileBackend().initialize(tmp_path / f"{LAYER_ID}.json", canonical_shell())
    return app


def canonical_shell() -> dict:
    """A synthetic, complete schema-v1 layer for explicit test initialization."""
    return {
        "metadata": {
            "audit_report": "audit.json",
            "repository": "https://example.test/repo",
            "created": "2026-09-22T12:00:00Z",
            "harness_version": "1.0.0",
        },
        "events": [],
        "needs_review": [],
    }


@pytest.fixture()
def client(app_with_backend: FastAPI) -> TestClient:
    return TestClient(app_with_backend)


# ─── Import-state tripwire ────────────────────────────────────────────────────
#
# Python binds a submodule as an *attribute* of its parent package when imported:
# importing `traust_ledger.auth.config` sets `.config` on `traust_ledger.auth`.
# Restoring `sys.modules` does NOT restore those attribute bindings, so a test
# that deletes and re-imports part of a package leaves the parent object missing
# its children — and a later, innocent test fails resolving a dotted monkeypatch
# target like "traust_ledger.auth.config.discover_oidc" with a bare AttributeError
# pointing at the wrong file.
#
# That happened twice here, in two different modules, and both times the
# production code was fine: the tell is a test that passes alone and fails in the
# suite. Tests needing a mutated import graph (simulating an absent optional
# dependency, say) belong in a subprocess, which cannot leak. This fails the test
# that actually caused the damage, at the moment it does it.


@pytest.fixture(autouse=True)
def _no_import_graph_mutation():
    """Fail the test that breaks parent/submodule attribute bindings.

    Checking `sys.modules` is not enough and was the first thing tried: a test
    that deletes entries, re-imports, then puts the *original* objects back
    leaves `sys.modules` pristine while the parent package object has lost the
    attribute the re-import rebound elsewhere. What breaks later is attribute
    resolution — `traust_ledger.auth` no longer having `.config` — so that is what
    this checks.
    """
    before = []
    for name, module in list(sys.modules.items()):
        if not name.startswith("traust_ledger.") or module is None:
            continue
        parent_name, _, child = name.rpartition(".")
        parent = sys.modules.get(parent_name)
        if parent is not None and getattr(parent, child, None) is module:
            before.append((parent_name, child, module))
    yield
    damaged = []
    for parent_name, child, module in before:
        parent = sys.modules.get(parent_name)
        if parent is None:
            damaged.append(f"{parent_name} (package gone)")
        elif getattr(parent, child, None) is not module:
            damaged.append(f"{parent_name}.{child}")
    assert not damaged, (
        "this test left the import graph damaged: "
        + ", ".join(sorted(damaged))
        + ". Re-importing a package does not rebind submodule attributes on its "
        "parent, so restoring sys.modules is not enough — unrelated later tests "
        "then fail to resolve dotted monkeypatch targets. Do import-graph "
        "manipulation in a subprocess instead."
    )


def none_alg_jwt(**claims: object) -> str:
    """An unsigned (alg=none) JWT-shaped token for tests, assembled at runtime so
    no token-shaped literal sits in the tree for forge secret scanners."""
    import base64
    import json

    def seg(obj: object) -> str:
        return (
            base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode())
            .decode()
            .rstrip("=")
        )

    return f"{seg({'alg': 'none'})}.{seg(claims)}."
