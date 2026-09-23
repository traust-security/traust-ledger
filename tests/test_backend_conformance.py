"""Parameterized conformance suite for Backend implementations.

NOTE: This suite tests correctness, not concurrency. SQLite silently ignores
FOR UPDATE (no row-level locking), so concurrency tests must run against
Postgres. Tag future concurrency tests with @pytest.mark.postgres.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import create_engine

from traust_ledger._internal.backends import Backend, create_backend
from traust_ledger._internal.backends.constants import (
    BACKEND_TYPE_DB,
    BACKEND_TYPE_FILE,
    EMPTY_LAYER,
    LAYER_EVENTS_KEY,
)
from traust_ledger._internal.backends.db import DbBackend
from traust_ledger._internal.backends.file import FileBackend
from traust_ledger._internal.integrity import (
    Severity,
    stamp_merkle_metadata,
    verify_merkle_integrity,
)
from traust_ledger._internal.writer import LedgerWriter

BACKEND_PARAM_FILE = BACKEND_TYPE_FILE
BACKEND_PARAM_DB = BACKEND_TYPE_DB
SAMPLE_EVENT_ID = "evt-conformance-001"
SAMPLE_FINDING_REF = "TEST-CONFORMANCE-001"
SAMPLE_SOURCE_REF = "conformance-test"
SAMPLE_VALIDITY = "confirmed"
SAMPLE_RESOLUTION = "open"
TAMPERED_DISPOSITION = "tampered"
SIMULATED_WRITE_FAILURE = "simulated write failure"
MERKLE_EVENT_ID = "E-001"
MERKLE_DISPOSITION = "confirmed"
MERKLE_ACTOR = "tester"
MERKLE_TIMESTAMP = "2026-08-14T00:00:00Z"
ROUND_TRIP_METADATA_KEY = "note"
ROUND_TRIP_METADATA_VALUE = "round-trip"
ROUND_TRIP_EXTRA = [1, 2, 3]
ORIGINAL_STORED_EVENT_ID = "stored-event"
REPLACEMENT_EVENT_ID = "replacement-event"


@pytest.fixture(params=[BACKEND_PARAM_FILE, BACKEND_PARAM_DB])
def backend(request: pytest.FixtureRequest) -> Backend:
    """Yield a Backend instance for each registered backend type."""
    if request.param == BACKEND_PARAM_DB:
        engine = create_engine("sqlite:///:memory:")
        DbBackend.create_tables(engine)
        return DbBackend(engine)
    return create_backend(str(request.param))


def _sample_append_event() -> dict:
    return {
        "source": {"ref": SAMPLE_SOURCE_REF, "actor": {"kind": "machine"}},
        "finding_ref": SAMPLE_FINDING_REF,
        "disposition": {"validity": SAMPLE_VALIDITY, "resolution": SAMPLE_RESOLUTION},
    }


def _merkle_event() -> dict:
    return {
        "event_id": MERKLE_EVENT_ID,
        "disposition": MERKLE_DISPOSITION,
        "actor": MERKLE_ACTOR,
        "timestamp": MERKLE_TIMESTAMP,
    }


def _layer_with_events(event: dict) -> dict:
    return {LAYER_EVENTS_KEY: [event]}


def test_atomic_append(backend: Backend, tmp_path: Path) -> None:
    """Stored layer content matches what was written."""
    layer_path = tmp_path / "layer.json"
    layer = _layer_with_events({**_sample_append_event(), "event_id": SAMPLE_EVENT_ID})
    backend.store(layer_path, layer)
    loaded = backend.load(layer_path)
    assert loaded == layer


def test_idempotent_reappend(backend: Backend, tmp_path: Path) -> None:
    """Duplicate event_id appends produce a single ledger entry."""
    layer_path = tmp_path / "layer.json"
    writer = LedgerWriter(backend=backend)
    event = _sample_append_event()
    first_id = writer.append_event(layer_path, event.copy())
    second_id = writer.append_event(layer_path, event.copy())
    assert first_id == second_id
    loaded = backend.load(layer_path)
    assert len(loaded[LAYER_EVENTS_KEY]) == 1


def test_mutated_events_fail_verify(backend: Backend, tmp_path: Path) -> None:
    """Tampered event content is detected by Merkle verification."""
    layer_path = tmp_path / "layer.json"
    layer: dict = {"metadata": {}, LAYER_EVENTS_KEY: [_merkle_event()]}
    stamp_merkle_metadata(layer)
    backend.store(layer_path, layer)
    tampered = backend.load(layer_path)
    tampered[LAYER_EVENTS_KEY][0]["disposition"] = TAMPERED_DISPOSITION
    findings = verify_merkle_integrity(tampered)
    assert any(finding.severity == Severity.ERROR for finding in findings)


def test_load_absent_file(backend: Backend, tmp_path: Path) -> None:
    """Missing layer path yields an empty events list."""
    missing_path = tmp_path / "missing.json"
    loaded = backend.load(missing_path)
    assert loaded == EMPTY_LAYER


def test_store_is_atomic(
    backend: Backend,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failed store leaves the original layer bytes untouched."""
    if not isinstance(backend, FileBackend):
        pytest.skip("write-failure simulation applies to file backend only")

    layer_path = tmp_path / "layer.json"
    original = _layer_with_events({"event_id": ORIGINAL_STORED_EVENT_ID})
    backend.store(layer_path, original)
    original_bytes = layer_path.read_bytes()

    def failing_dump(*_args: object, **_kwargs: object) -> None:
        raise OSError(SIMULATED_WRITE_FAILURE)

    monkeypatch.setattr("traust_ledger._internal.backends.file.json.dump", failing_dump)
    replacement = _layer_with_events({"event_id": REPLACEMENT_EVENT_ID})
    with pytest.raises(OSError, match=SIMULATED_WRITE_FAILURE):
        backend.store(layer_path, replacement)
    assert layer_path.read_bytes() == original_bytes


def test_round_trip_fidelity(backend: Backend, tmp_path: Path) -> None:
    """Reloaded data matches what was stored."""
    layer_path = tmp_path / "layer.json"
    payload = {
        LAYER_EVENTS_KEY: [_merkle_event()],
        "metadata": {ROUND_TRIP_METADATA_KEY: ROUND_TRIP_METADATA_VALUE},
        "extra": ROUND_TRIP_EXTRA,
    }
    backend.store(layer_path, payload)
    if isinstance(backend, FileBackend):
        first_bytes = layer_path.read_bytes()
        reloaded = backend.load(layer_path)
        backend.store(layer_path, reloaded)
        second_bytes = layer_path.read_bytes()
        assert second_bytes == first_bytes
        assert json.loads(first_bytes.decode()) == payload
        return

    first_load = backend.load(layer_path)
    backend.store(layer_path, first_load)
    second_load = backend.load(layer_path)
    assert second_load == first_load == payload


def test_iter_layers_supports_file_and_database_identity_spaces(tmp_path):
    """File IDs obey path rules; database IDs remain opaque domain identities."""
    from sqlalchemy import create_engine

    from traust_ledger._internal.backends.db import DbBackend
    from traust_ledger._internal.backends.file import FileBackend
    from traust_ledger.cli import iter_layers
    from traust_ledger.paths import layer_file_path

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    layer = {"events": [], "metadata": {}}

    engine = create_engine("sqlite://")
    DbBackend.create_tables(engine)
    for backend in (FileBackend(data_dir), DbBackend(engine)):
        backend.store(layer_file_path(str(data_dir), "repo-a"), layer)
        assert backend.list_layer_ids() == ["repo-a"], type(backend).__name__
        for layer_id, _ in iter_layers(backend, str(data_dir)):
            layer_file_path(str(data_dir), layer_id)  # file-compatible ID must not raise

    opaque_id = "corpus:layer:org/repo__main/repo__main"
    db_backend = DbBackend(engine)
    db_backend.import_layer(opaque_id, layer)
    assert list(iter_layers(db_backend, str(data_dir))) == [(opaque_id, layer), ("repo-a", layer)]


# ── Atomic mutate conformance ────────────────────────────────────────────


def test_mutate_applies_callback_and_stores(backend: Backend, tmp_path: Path) -> None:
    """mutate: callback's mutation is persisted."""
    layer_path = tmp_path / "layer.json"
    base = {LAYER_EVENTS_KEY: [], "metadata": {}}
    backend.store(layer_path, base)

    def _add_note(layer: dict) -> str:
        layer.setdefault("metadata", {})["note"] = "mutated"
        return "ok"

    result = backend.mutate(layer_path, _add_note)
    assert result == "ok"
    reloaded = backend.load(layer_path)
    assert reloaded["metadata"]["note"] == "mutated"


def test_mutate_with_stamp_and_sign(backend: Backend, tmp_path: Path) -> None:
    """mutate: finalization (stamp + sign) inside the callback persists."""
    layer_path = tmp_path / "layer.json"
    layer = {LAYER_EVENTS_KEY: [_merkle_event()], "metadata": {}}
    backend.store(layer_path, layer)

    def _stamp(data: dict) -> None:
        stamp_merkle_metadata(data)

    backend.mutate(layer_path, _stamp)
    reloaded = backend.load(layer_path)
    assert reloaded.get("metadata", {}).get("merkle_root"), "merkle_root should be stamped"
    findings = verify_merkle_integrity(reloaded)
    assert not any(f.severity == Severity.ERROR for f in findings)


def test_mutate_rollback_on_error(backend: Backend, tmp_path: Path) -> None:
    """mutate: if the callback raises, nothing is stored."""
    layer_path = tmp_path / "layer.json"
    original = {LAYER_EVENTS_KEY: [{"event_id": "original"}], "metadata": {}}
    backend.store(layer_path, original)

    def _boom(layer: dict) -> None:
        layer["metadata"]["poisoned"] = True
        raise ValueError("intentional failure")

    with pytest.raises(ValueError, match="intentional failure"):
        backend.mutate(layer_path, _boom)

    reloaded = backend.load(layer_path)
    assert "poisoned" not in reloaded.get("metadata", {}), (
        "mutator raised — mutation must not be persisted"
    )


def test_mutate_finalize_signing_required_raises(backend: Backend, tmp_path: Path) -> None:
    """I2 parity: signing_required + no signer raises identically on both backends."""
    from traust_ledger._internal.layer_finalize import finalize_layer
    from traust_ledger.config import ServiceConfig
    from traust_ledger.service.errors import SigningFailedError

    layer_path = tmp_path / "layer.json"
    layer = {LAYER_EVENTS_KEY: [_merkle_event()], "metadata": {}}
    backend.store(layer_path, layer)

    config = ServiceConfig(signing_required=True, signing_method="none")

    def _finalize(data: dict) -> str:
        return finalize_layer(data, config)

    with pytest.raises(SigningFailedError):
        backend.mutate(layer_path, _finalize)

    reloaded = backend.load(layer_path)
    assert not reloaded.get("metadata", {}).get("merkle_root_signature"), (
        "signing_required failure must not persist unsigned layer"
    )
