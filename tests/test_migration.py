"""Historical migration into normalized authoritative storage."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.exc import DatabaseError

from traust_ledger._internal.backends.db import DbBackend
from traust_ledger._internal.historical_migration import (
    SourceLayer,
    iter_artifact_layers,
    iter_directory_layers,
    iter_ledger_layers,
    migrate,
)
from traust_ledger._internal.integrity import stamp_merkle_metadata
from traust_ledger._internal.migrations import (
    LEDGER_SCHEMA,
    SCHEMA_REVISION,
    DatabaseRoles,
    ledger_tables,
    upgrade,
)


def _layer(rationale: str = "reviewed against implementation") -> dict:
    return {
        "metadata": {
            "audit_report": "audit.json",
            "repository": "https://example.test/repo",
            "created": "2026-08-01T12:00:00Z",
            "harness_version": "1.0.0",
        },
        "events": [
            {
                "event_id": "e" * 64,
                "finding_ref": "FIND-1",
                "recorded_at": "2026-08-02T12:00:00Z",
                "occurred_at": "2026-08-02T11:55:00Z",
                "source": {
                    "type": "triage_report",
                    "ref": "triage.json",
                    "actor": {"kind": "machine"},
                },
                "disposition": {"validity": "confirmed", "resolution": "open"},
                "rationale": rationale,
            }
        ],
        "needs_review": [],
    }


def test_migration_is_idempotent_and_preserves_null_character(tmp_path: Path) -> None:
    target = f"sqlite:///{tmp_path / 'ledger.db'}"
    source = SourceLayer("layer-a", _layer("contains \x00 byte"), "fixture")

    first = list(migrate(iter([source]), target))
    second = list(migrate(iter([source]), target))

    assert first[0].status == "inserted"
    assert second[0].status == "skipped"
    engine = create_engine(target)
    loaded = DbBackend(engine).load(Path("layer-a"))
    assert loaded == source.document
    assert loaded["events"][0]["rationale"] == "contains \x00 byte"


def test_migration_reports_unverified_signature_warning(tmp_path: Path) -> None:
    target = f"sqlite:///{tmp_path / 'ledger.db'}"
    document = _layer()
    stamp_merkle_metadata(document)
    document["metadata"]["merkle_root_signature"] = "unverified-signature"
    source = SourceLayer("layer-a", document, "fixture")

    result = next(migrate(iter([source]), target))

    assert result.status == "inserted"
    assert result.validation_warnings == 1


def test_layer_signature_state_is_queryable(tmp_path: Path) -> None:
    target = create_engine(f"sqlite:///{tmp_path / 'ledger.db'}")
    DbBackend.create_tables(target)
    backend = DbBackend(target)
    document = _layer()
    document["metadata"].update(
        {
            "merkle_root": "a" * 64,
            "merkle_epoch": 3,
            "merkle_size": 1,
            "merkle_root_signature": "signed-value",
            "merkle_signing_method": "keypair",
            "merkle_signature_format": 4,
        }
    )
    backend.import_layer("layer-a", document)

    with target.connect() as conn:
        row = conn.execute(
            select(
                backend._tables.layers.c.repository,
                backend._tables.layers.c.merkle_root,
                backend._tables.layers.c.merkle_root_signature,
                backend._tables.layers.c.merkle_signature_format,
            )
        ).one()

    assert tuple(row) == (
        "https://example.test/repo",
        "a" * 64,
        "signed-value",
        4,
    )


def test_migration_reports_conflict_without_overwrite(tmp_path: Path) -> None:
    target = f"sqlite:///{tmp_path / 'ledger.db'}"
    original = SourceLayer("layer-a", _layer(), "first")
    changed = SourceLayer("layer-a", _layer("different rationale content"), "second")

    assert next(migrate(iter([original]), target)).status == "inserted"
    result = next(migrate(iter([changed]), target))

    assert result.status == "conflict"
    assert DbBackend(create_engine(target)).load(Path("layer-a")) == original.document


def test_artifact_source_reads_exact_current_evidence(tmp_path: Path) -> None:
    source_url = f"sqlite:///{tmp_path / 'artifacts.db'}"
    engine = create_engine(source_url)
    payload = json.dumps(_layer()).encode()
    digest = hashlib.sha256(payload).hexdigest()
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE artifact_evidence ("
                "digest TEXT PRIMARY KEY, payload BLOB NOT NULL, first_ingested_at TEXT NOT NULL)"
            )
        )
        conn.execute(
            text(
                "CREATE TABLE artifact_binding ("
                "binding_id TEXT PRIMARY KEY, artifact_digest TEXT NOT NULL, "
                "artifact_name TEXT NOT NULL, scope_id TEXT NOT NULL, subject_id TEXT, "
                "run_id TEXT, layer_id TEXT, supersedes_binding_id TEXT, bound_at TEXT NOT NULL)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO artifact_evidence VALUES (:digest, :payload, '2026-01-01T00:00:00Z')"
            ),
            {"digest": digest, "payload": payload},
        )
        conn.execute(
            text(
                "INSERT INTO artifact_binding VALUES "
                "('binding-1', :digest, 'layer', 'scope', NULL, NULL, "
                "'layer-a', NULL, '2026-01-01T00:00:00Z')"
            ),
            {"digest": digest},
        )

    layers = list(iter_artifact_layers(engine))

    assert [(layer.layer_id, layer.document) for layer in layers] == [("layer-a", _layer())]


def test_directory_migration_quarantines_bad_json_and_continues(tmp_path: Path) -> None:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "bad.json").write_text("{not json", encoding="utf-8")
    (source_dir / "good.json").write_text(json.dumps(_layer()), encoding="utf-8")
    target_url = f"sqlite:///{tmp_path / 'target.db'}"

    results = list(migrate(iter_directory_layers(source_dir), target_url))

    assert [(result.layer_id, result.status) for result in results] == [
        ("bad", "quarantined"),
        ("good", "inserted"),
    ]


def test_normalized_database_can_migrate_to_another_database(tmp_path: Path) -> None:
    source_url = f"sqlite:///{tmp_path / 'source-ledger.db'}"
    target_url = f"sqlite:///{tmp_path / 'target-ledger.db'}"
    source_engine = create_engine(source_url)
    DbBackend.create_tables(source_engine)
    DbBackend(source_engine).import_layer("layer-a", _layer())

    result = next(migrate(iter_ledger_layers(source_engine), target_url))

    assert result.status == "inserted"
    assert DbBackend(create_engine(target_url)).load(Path("layer-a")) == _layer()


def test_sqlite_guards_reject_authoritative_mutation(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'guarded.db'}")
    DbBackend.create_tables(engine)
    DbBackend(engine).import_layer("layer-a", _layer())

    for statement in (
        "UPDATE events SET event_id = 'changed' WHERE layer_id = 'layer-a'",
        "DELETE FROM events WHERE layer_id = 'layer-a'",
        "DELETE FROM layers WHERE layer_id = 'layer-a'",
        "INSERT INTO events (layer_id, seq, event_id, event_payload) "
        "VALUES ('layer-a', 9, 'gap', x'7b7d')",
    ):
        with pytest.raises(DatabaseError), engine.begin() as conn:
            conn.execute(text(statement))

    assert DbBackend(engine).load_layer_id("layer-a") == _layer()


def test_revision_one_upgrades_and_reinstalls_guards() -> None:
    engine = create_engine("sqlite:///:memory:")
    DbBackend.create_tables(engine)
    with engine.begin() as conn:
        conn.execute(text("UPDATE schema_revision SET revision = 1"))

    upgrade(engine)

    with engine.connect() as conn:
        assert conn.execute(text("SELECT revision FROM schema_revision")).scalar_one() == 2
    assert SCHEMA_REVISION == 2


def test_database_roles_must_be_distinct() -> None:
    with pytest.raises(ValueError, match="must be distinct"):
        DatabaseRoles(writer="shared", reader="shared")


def test_normalized_schema_has_no_complete_layer_blob() -> None:
    engine = create_engine("sqlite:///:memory:")
    DbBackend.create_tables(engine)
    inspector = inspect(engine)

    assert {"layers", "events", "schema_revision", "materialized_findings"}.issubset(
        inspector.get_table_names()
    )
    assert "data" not in {column["name"] for column in inspector.get_columns("layers")}
    assert ledger_tables("postgresql").layers.schema == LEDGER_SCHEMA
    assert ledger_tables("postgresql").events.schema == LEDGER_SCHEMA
