"""Tests for LedgerClient.countersign — the gated human-lane write verb.

Countersign must route through submit_event (gates) rather than submit_batch
(machine lane). An explicit actor bypasses token verification so these run
without a signer.
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


def _client(tmp_path: Path) -> LedgerClient:
    return LedgerClient(
        token=FAKE_TOKEN,
        data_dir=str(tmp_path),
        signing_config=SigningConfig(method="none"),
    )


def _seed(tmp_path: Path) -> None:
    path = layer_file_path(str(tmp_path), LAYER_ID)
    FileBackend(data_dir=tmp_path).store(path, {"events": [], "metadata": {}})


def _reload(tmp_path: Path) -> dict:
    return FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))


def _human(identity: str = "alice", *, verified: bool = True) -> LayerActor:
    return LayerActor(kind="human", identity=identity, identity_verified=verified)


def test_countersign_records_false_positive(tmp_path: Path) -> None:
    _seed(tmp_path)
    _client(tmp_path).countersign(
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
    _client(tmp_path).countersign(
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
        _client(tmp_path).countersign(
            LAYER_ID,
            "F-1",
            rationale=RATIONALE,
            recorded_at=AT,
            decision="false_positive",
            actor=_human(verified=False),
        )
    assert _reload(tmp_path)["events"] == []


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
