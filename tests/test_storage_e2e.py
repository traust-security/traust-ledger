"""End-to-end storage lifecycle checks across supported Ledger backends."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Callable
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select

from traust_ledger._internal.backends import Backend, create_backend
from traust_ledger._internal.backends.constants import BACKEND_TYPE_DB, BACKEND_TYPE_FILE
from traust_ledger._internal.integrity import (
    Severity,
    stamp_merkle_metadata,
    verify_merkle_integrity,
)
from traust_ledger._internal.migrations import ledger_tables
from traust_ledger._internal.writer import LedgerWriter
from traust_ledger.api.events import compute_event_id
from traust_ledger.cli.main import main

BackendFactory = Callable[[], Backend]


def _event(source_ref: str) -> dict[str, object]:
    return {
        "finding_ref": "FIND-E2E-1",
        "recorded_at": "2026-09-22T12:00:00Z",
        "source": {
            "type": "triage_report",
            "ref": source_ref,
            "actor": {"kind": "machine"},
        },
        "disposition": {"validity": "confirmed", "resolution": "open"},
        "rationale": f"storage lifecycle event from {source_ref}",
    }


def _exercise_backend(factory: BackendFactory, layer_path: Path) -> None:
    backend = factory()
    writer = LedgerWriter(backend=backend)
    first = _event("first.json")
    second = _event("second.json")

    first_id = writer.append_event(layer_path, first)
    assert writer.append_event(layer_path, dict(first)) == first_id
    second_id = writer.append_event(layer_path, second)
    backend.mutate(layer_path, stamp_merkle_metadata)

    restarted = factory()
    layer = restarted.load(layer_path)
    assert [event["event_id"] for event in layer["events"]] == [first_id, second_id]
    assert not any(finding.severity == Severity.ERROR for finding in verify_merkle_integrity(layer))


@pytest.mark.parametrize("backend_type", [BACKEND_TYPE_FILE, BACKEND_TYPE_DB])
def test_file_and_sqlite_storage_lifecycle(
    backend_type: str,
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "layers"
    database_url = f"sqlite:///{tmp_path / 'ledger.db'}"

    def factory() -> Backend:
        return create_backend(
            backend_type,
            data_dir=data_dir,
            database_url=database_url,
        )

    _exercise_backend(factory, data_dir / "layer-e2e.json")


@pytest.mark.integration
def test_postgresql_storage_lifecycle() -> None:
    url = os.environ.get("LEDGER_TEST_DATABASE_URL")
    if not url:
        pytest.skip("LEDGER_TEST_DATABASE_URL is not configured")
    layer_id = f"storage-e2e-{uuid.uuid4().hex}"

    def factory() -> Backend:
        return create_backend(BACKEND_TYPE_DB, database_url=url)

    _exercise_backend(factory, Path(layer_id))


def _complete_layer() -> dict[str, object]:
    event = _event("migration.json")
    event["event_id"] = compute_event_id(
        "migration.json",
        "FIND-E2E-1",
        "confirmed",
        "open",
    )
    layer: dict[str, object] = {
        "metadata": {
            "audit_report": "audit.json",
            "repository": "https://example.test/repo",
            "created": "2026-09-22T12:00:00Z",
            "harness_version": "1.0.0",
        },
        "events": [event],
        "needs_review": [],
    }
    stamp_merkle_metadata(layer)
    return layer


def test_file_to_sqlite_migration_and_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "layer-a.json").write_text(json.dumps(_complete_layer()), encoding="utf-8")
    target = f"sqlite:///{tmp_path / 'target.db'}"

    assert main(["migrate", "--source-dir", str(source), "--target-database-url", target]) == 0
    monkeypatch.setenv("LAAS_BACKEND_TYPE", BACKEND_TYPE_DB)
    monkeypatch.setenv("LAAS_DATABASE_URL", target)
    assert main(["materialize", "--to", target]) == 0

    engine = create_engine(target)
    tables = ledger_tables("sqlite")
    with engine.connect() as conn:
        assert conn.execute(select(func.count()).select_from(tables.layers)).scalar_one() == 1
        assert conn.execute(select(func.count()).select_from(tables.events)).scalar_one() == 1
        assert (
            conn.execute(
                select(func.count()).select_from(tables.materialized_findings)
            ).scalar_one()
            == 1
        )
