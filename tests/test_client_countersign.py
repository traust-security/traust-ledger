"""Tests for LedgerClient.countersign — the gated human-lane write verb.

Countersign must route through submit_event (gates) rather than submit_batch
(machine lane). The token-verified caller is always the actor stamped; these
tests stand in for verification by patching ``_actor``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import none_alg_jwt
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger._internal.backends.file import FileBackend
from traust_ledger._internal.integrity.signing import SigningConfig
from traust_ledger.client import LedgerClient, LedgerError
from traust_ledger.paths import layer_file_path

LAYER_ID = "test-layer"
FAKE_TOKEN = none_alg_jwt(
    sub="test@example.com", email="test@example.com", iat=1693000000, exp=9999999999
)
AT = "2026-07-01T12:00:00+00:00"
RATIONALE = "Reviewed the machine refutation and I concur; the guard is real."


def _client(tmp_path: Path, caller: LayerActor | None = None) -> LedgerClient:
    client = LedgerClient(
        token=FAKE_TOKEN,
        data_dir=str(tmp_path),
        signing_config=SigningConfig(method="none"),
    )
    if caller is not None:
        client._actor = lambda: caller  # type: ignore[method-assign]
    return client


def _seed(tmp_path: Path) -> None:
    path = layer_file_path(str(tmp_path), LAYER_ID)
    from conftest import canonical_shell

    FileBackend(data_dir=tmp_path).initialize(path, canonical_shell())


def _reload(tmp_path: Path) -> dict:
    return FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))


def _human(identity: str = "alice", *, verified: bool = True) -> LayerActor:
    return LayerActor(kind="human", identity=identity, identity_verified=verified)


def test_countersign_records_false_positive(tmp_path: Path) -> None:
    _seed(tmp_path)
    _client(tmp_path, _human()).countersign(
        LAYER_ID,
        "F-1",
        rationale=RATIONALE,
        recorded_at=AT,
        decision="false_positive",
        actor=_human(),
    )
    ev = _reload(tmp_path)["events"][-1]
    assert ev["disposition"]["validity"] == "false_positive"
    assert ev["source"]["actor"]["identity"] == "alice"


def test_countersign_records_severity(tmp_path: Path) -> None:
    _seed(tmp_path)
    _client(tmp_path, _human()).countersign(
        LAYER_ID,
        "F-1",
        rationale=RATIONALE,
        recorded_at=AT,
        severity="high",
        actor=_human(),
    )
    ev = _reload(tmp_path)["events"][-1]
    assert ev["disposition"] == {"severity": "high"}


def test_countersign_rejects_unverified_false_positive(tmp_path: Path) -> None:
    _seed(tmp_path)
    with pytest.raises(LedgerError):
        _client(tmp_path, _human(verified=False)).countersign(
            LAYER_ID,
            "F-1",
            rationale=RATIONALE,
            recorded_at=AT,
            decision="false_positive",
            actor=_human(verified=False),
        )
    assert _reload(tmp_path)["events"] == []


def test_countersign_refuses_actor_other_than_caller(tmp_path: Path) -> None:
    # Passing someone else's actor must not record the event as them.
    _seed(tmp_path)
    with pytest.raises(LedgerError, match="does not match the token-verified caller"):
        _client(tmp_path, _human("alice")).countersign(
            LAYER_ID,
            "F-1",
            rationale=RATIONALE,
            recorded_at=AT,
            decision="false_positive",
            actor=_human("mallory"),
        )
    assert _reload(tmp_path)["events"] == []


def test_countersign_refuses_without_verifiable_token(tmp_path: Path) -> None:
    # An explicit actor is not a substitute for a token that verifies.
    _seed(tmp_path)
    with pytest.raises(LedgerError):
        _client(tmp_path).countersign(
            LAYER_ID,
            "F-1",
            rationale=RATIONALE,
            recorded_at=AT,
            decision="false_positive",
            actor=_human(),
        )
    assert _reload(tmp_path)["events"] == []


def test_countersign_stamps_verified_caller_not_passed_flags(tmp_path: Path) -> None:
    # Same principal, but the passed actor claims verification the token
    # doesn't carry: the stamped actor is the verified one, so the FP gate holds.
    _seed(tmp_path)
    with pytest.raises(LedgerError):
        _client(tmp_path, _human(verified=False)).countersign(
            LAYER_ID,
            "F-1",
            rationale=RATIONALE,
            recorded_at=AT,
            decision="false_positive",
            actor=_human(verified=True),
        )
    assert _reload(tmp_path)["events"] == []


def test_restate_refuses_actor_other_than_caller(tmp_path: Path) -> None:
    _seed(tmp_path)
    with pytest.raises(LedgerError, match="does not match the token-verified caller"):
        _client(tmp_path, _human("alice")).restate(
            LAYER_ID,
            {"target": "audit_report_sha256", "before": None, "after": "0" * 64},
            rationale=RATIONALE,
            actor=_human("mallory"),
        )


def test_whoami_returns_token_derived_actor(tmp_path: Path, monkeypatch) -> None:
    # whoami is the public alias for the token-verified actor; the harness
    # countersign CLI attributes non-event writes (alias confirms) through it.
    client = _client(tmp_path)
    monkeypatch.setattr(client, "_actor", lambda: _human("carol"))
    assert client.whoami().identity == "carol"


def test_whoami_requires_verifiable_token(tmp_path: Path) -> None:
    # No OIDC provider configured for the fake token → refuse, don't guess.
    with pytest.raises(LedgerError):
        _client(tmp_path).whoami()


OPAQUE_LAYER_ID = "corpus:layer:org/repo__main/repo__main"


def test_countersign_and_sign_reach_opaque_database_layer(tmp_path: Path) -> None:
    # Migrated corpus layers keep slash/colon IDs; SCI's countersign must land on them.
    from conftest import canonical_shell
    from storage_db import prepare_storage

    database_url = f"sqlite:///{tmp_path / 'ledger.db'}"
    owner = prepare_storage(database_url)
    client = LedgerClient(
        token=FAKE_TOKEN,
        backend_type="db",
        database_url=database_url,
        signing_config=SigningConfig(method="none"),
        signing_required=False,
    )
    client._actor = lambda: _human()  # type: ignore[method-assign]
    client._backend.import_layer(OPAQUE_LAYER_ID, canonical_shell(), product_repo_id=owner)

    client.countersign(
        OPAQUE_LAYER_ID,
        "F-1",
        rationale=RATIONALE,
        recorded_at=AT,
        decision="false_positive",
        actor=_human(),
    )
    assert client.sign(OPAQUE_LAYER_ID)["layer_id"] == OPAQUE_LAYER_ID

    events = client._backend.load_layer_id(OPAQUE_LAYER_ID)["events"]
    assert [e["disposition"]["validity"] for e in events] == ["false_positive"]
    assert client.verify(OPAQUE_LAYER_ID)
