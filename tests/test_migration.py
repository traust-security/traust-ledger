"""Historical migration into normalized authoritative storage."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest import mock

import pytest
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.exc import DatabaseError
from traust_contracts.v1.ledger import CONTRACT_VERSION, REVISION, TABLE_ORDER

from traust_ledger._internal.backends.db import DbBackend
from traust_ledger._internal.historical_migration import (
    SourceLayer,
    iter_artifact_layers,
    iter_directory_layers,
    iter_ledger_layers,
    iter_manifest_layers,
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
from traust_ledger._internal.migrations import schema as schema_migrations
from traust_ledger.cli.main import main as ledger_main


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


def test_manifest_migrates_nested_layers_with_distinct_ids(tmp_path: Path) -> None:
    root = tmp_path / "findings"
    records = []
    for team in ("a", "b"):
        path = root / team / "repo-findings-layer.json"
        path.parent.mkdir(parents=True)
        payload = json.dumps(_layer()).encode()
        path.write_bytes(payload)
        records.append(
            {
                "format_version": 1,
                "source_file": f"{team}/repo-findings-layer.json",
                "source_digest": hashlib.sha256(payload).hexdigest(),
                "artifact": "layer",
                "namespace": "traust_ledger",
                "decision": "selected",
                "layer_id": f"corpus:layer:{team}/repo",
            }
        )
    manifest = tmp_path / "decisions.jsonl"
    manifest.write_text("".join(json.dumps(row) + "\n" for row in records))
    target = f"sqlite:///{tmp_path / 'ledger.db'}"
    results = list(migrate(iter_manifest_layers(root, manifest), target))
    assert [(row.layer_id, row.status) for row in results] == [
        ("corpus:layer:a/repo", "inserted"),
        ("corpus:layer:b/repo", "inserted"),
    ]
    assert DbBackend(create_engine(target)).list_layer_ids() == [
        "corpus:layer:a/repo",
        "corpus:layer:b/repo",
    ]
    records[1]["layer_id"] = records[0]["layer_id"]
    manifest.write_text("".join(json.dumps(row) + "\n" for row in records))
    with pytest.raises(ValueError, match="Duplicate Ledger selection"):
        list(iter_manifest_layers(root, manifest))


def test_cli_manifest_source_uses_ledger_loader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LAAS_MIGRATION_SOURCE_URL", raising=False)
    monkeypatch.delenv("LAAS_MIGRATION_TARGET_URL", raising=False)
    root = tmp_path / "findings"
    root.mkdir()
    source = root / "repo-findings-layer.json"
    payload = json.dumps(_layer()).encode()
    source.write_bytes(payload)
    manifest = tmp_path / "selection.jsonl"
    manifest.write_text(
        json.dumps(
            {
                "format_version": 1,
                "source_file": source.name,
                "source_digest": hashlib.sha256(payload).hexdigest(),
                "namespace": "traust_ledger",
                "decision": "selected",
                "artifact": "layer",
                "layer_id": "corpus:layer:repo",
            }
        )
        + "\n"
    )
    target = f"sqlite:///{tmp_path / 'ledger.db'}"
    assert (
        ledger_main(
            [
                "migrate",
                "--source-dir",
                str(root),
                "--selection-manifest",
                str(manifest),
                "--target-database-url",
                target,
            ]
        )
        == 0
    )
    assert DbBackend(create_engine(target)).list_layer_ids() == ["corpus:layer:repo"]


def test_manifest_requires_explicit_ledger_selections(tmp_path: Path) -> None:
    manifest = tmp_path / "decisions.jsonl"
    manifest.write_text(
        json.dumps(
            {
                "format_version": 1,
                "source_file": "a-security-audit.json",
                "namespace": "traust_storage",
                "decision": "selected",
                "artifact": "report",
            }
        )
        + "\n"
    )
    with pytest.raises(ValueError, match="No selected Ledger layers"):
        list(iter_manifest_layers(tmp_path, manifest))


def test_manifest_quarantines_source_drift_and_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "findings"
    root.mkdir()
    path = root / "repo-findings-layer.json"
    payload = json.dumps(_layer()).encode()
    path.write_bytes(payload)
    manifest = tmp_path / "selection.jsonl"
    record = {
        "format_version": 1,
        "source_file": path.name,
        "source_digest": hashlib.sha256(payload).hexdigest(),
        "artifact": "layer",
        "namespace": "traust_ledger",
        "decision": "selected",
        "layer_id": "corpus:layer:repo",
    }
    manifest.write_text(json.dumps(record) + "\n")
    path.write_text(json.dumps(_layer("changed")))
    assert (
        next(iter_manifest_layers(root, manifest)).error == "source digest changed since selection"
    )
    path.unlink()
    path.symlink_to(tmp_path / "outside.json")
    assert next(iter_manifest_layers(root, manifest)).error == "symlink alias is not a source file"
    record["source_file"] = "../outside.json"
    manifest.write_text(json.dumps(record) + "\n")
    with pytest.raises(ValueError, match="Invalid Ledger selection"):
        list(iter_manifest_layers(root, manifest))


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


def test_fresh_database_loads_pinned_contract_sql() -> None:
    engine = create_engine("sqlite:///:memory:")

    with mock.patch.object(
        schema_migrations,
        "ledger_bootstrap_files",
        wraps=schema_migrations.ledger_bootstrap_files,
    ) as files:
        upgrade(engine)

    files.assert_called_once_with("sqlite")


def test_revision_one_is_singleton_and_existing_mismatches_are_rejected() -> None:
    engine = create_engine("sqlite:///:memory:")
    DbBackend.create_tables(engine)
    with engine.connect() as conn:
        assert conn.execute(
            text("SELECT id, contract_version, revision FROM schema_revision")
        ).one() == (1, CONTRACT_VERSION, REVISION)
    for statement in (
        "UPDATE schema_revision SET revision = 2",
        "UPDATE schema_revision SET contract_version = 'v2'",
        "DELETE FROM schema_revision",
    ):
        with engine.begin() as conn:
            conn.execute(text(statement))
        with pytest.raises(RuntimeError, match="unsupported ledger schema metadata"):
            upgrade(engine)
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM schema_revision"))
            conn.execute(
                text(
                    "INSERT INTO schema_revision (id, contract_version, revision, applied_at) "
                    "VALUES (1, 'v1', 1, CURRENT_TIMESTAMP)"
                )
            )
    assert SCHEMA_REVISION == REVISION == 1


def test_legacy_revision_table_shape_fails_without_auto_migration() -> None:
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE schema_revision (revision INTEGER NOT NULL)"))
        conn.execute(text("INSERT INTO schema_revision VALUES (2)"))
    with pytest.raises(RuntimeError, match="unsupported ledger schema metadata shape"):
        upgrade(engine)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT revision FROM schema_revision")).scalar_one() == 2


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


@pytest.mark.parametrize("dialect_name", ["sqlite", "postgresql"])
def test_explicit_bindings_have_contract_table_inventory(dialect_name: str) -> None:
    tables = ledger_tables(dialect_name)
    assert set(table.name for table in tables.metadata.tables.values()) == set(TABLE_ORDER)
    assert tables.revision.c.contract_version.name == "contract_version"
    assert tables.events.schema == (LEDGER_SCHEMA if dialect_name == "postgresql" else None)
