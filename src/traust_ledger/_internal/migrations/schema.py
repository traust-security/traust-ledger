"""Revisioned normalized ledger schema for PostgreSQL and SQLite."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    PrimaryKeyConstraint,
    String,
    Table,
    Text,
    UniqueConstraint,
    insert,
    inspect,
    select,
    text,
    update,
)
from sqlalchemy.engine import Engine
from sqlalchemy.schema import CreateSchema
from sqlalchemy.sql import func

LEDGER_SCHEMA = "traust_ledger"
SCHEMA_REVISION = 2


@dataclass(frozen=True)
class LedgerTables:
    metadata: MetaData
    revision: Table
    layers: Table
    events: Table
    materialized_findings: Table


def _qualified(schema: str | None, table: str) -> str:
    return f"{schema}.{table}" if schema else table


@cache
def ledger_tables(dialect_name: str) -> LedgerTables:
    """Return one logical schema with PostgreSQL-only namespace qualification."""
    schema = LEDGER_SCHEMA if dialect_name == "postgresql" else None
    metadata = MetaData(schema=schema)
    revision = Table(
        "schema_revision",
        metadata,
        Column("revision", Integer, primary_key=True),
    )
    layers = Table(
        "layers",
        metadata,
        Column("layer_id", String, primary_key=True),
        Column("metadata_payload", LargeBinary, nullable=False),
        Column("needs_review_payload", LargeBinary, nullable=False),
        Column("extensions_payload", LargeBinary, nullable=False),
        Column("root_keys_payload", LargeBinary, nullable=False),
        Column("repository", Text),
        Column("created_at", DateTime(timezone=True)),
        Column("merkle_root", String),
        Column("merkle_epoch", Integer),
        Column("merkle_size", Integer),
        Column("merkle_root_signature", Text),
        Column("merkle_signing_method", String),
        Column("merkle_signature_format", Integer),
        Column(
            "updated_at",
            DateTime(timezone=True),
            nullable=False,
            server_default=func.now(),
            onupdate=func.now(),
        ),
    )
    identity_type = BigInteger().with_variant(Integer, "sqlite")
    events = Table(
        "events",
        metadata,
        Column("id", identity_type, Identity(always=True), primary_key=True),
        Column(
            "layer_id",
            String,
            ForeignKey(f"{_qualified(schema, 'layers')}.layer_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        Column("seq", Integer, nullable=False),
        Column("event_id", String, nullable=False),
        Column("finding_ref", String),
        Column("fingerprint", String),
        Column("fingerprint_algo", String),
        Column("recorded_at", DateTime(timezone=True)),
        Column("occurred_at", DateTime(timezone=True)),
        Column("source_type", String),
        Column("source_ref", String),
        Column("actor_kind", String),
        Column("actor_identity", String),
        Column("validity", String),
        Column("resolution", String),
        Column("evidence_grade", String),
        Column("auto_accept_tier", Boolean),
        Column("event_payload", LargeBinary, nullable=False),
        CheckConstraint("seq >= 0", name="ck_ledger_events_seq_nonnegative"),
        CheckConstraint("event_id <> ''", name="ck_ledger_events_event_id_nonempty"),
        UniqueConstraint("layer_id", "seq", name="uq_ledger_events_layer_seq"),
        UniqueConstraint("layer_id", "event_id", name="uq_ledger_events_layer_event_id"),
    )
    Index("idx_ledger_events_finding_ref", events.c.layer_id, events.c.finding_ref)
    Index("idx_ledger_events_recorded_at", events.c.layer_id, events.c.recorded_at)
    Index("idx_ledger_events_clock", events.c.fingerprint, events.c.occurred_at)
    Index("idx_ledger_events_resolution", events.c.resolution, events.c.occurred_at)
    Index("idx_ledger_events_source", events.c.source_type, events.c.occurred_at)
    materialized_findings = Table(
        "materialized_findings",
        metadata,
        Column("layer_id", String, nullable=False),
        Column("finding_ref", String, nullable=False),
        Column("fingerprint", String),
        Column("orphan", Boolean, default=False),
        Column("validity", String, nullable=False),
        Column("resolution", String, nullable=False),
        Column("assurance", String),
        Column("event_count", Integer, nullable=False),
        Column("conflict", Boolean, default=False),
        Column("fp_overridden", Boolean, default=False),
        Column("fp_reassertion_blocked", Boolean, default=False),
        Column("severity_override", JSON),
        Column("last_updated", String),
        Column("merkle_root", String),
        Column("merkle_epoch", Integer),
        Column("materialized_at", DateTime(timezone=True), server_default=func.now()),
        PrimaryKeyConstraint("layer_id", "finding_ref"),
    )
    return LedgerTables(
        metadata=metadata,
        revision=revision,
        layers=layers,
        events=events,
        materialized_findings=materialized_findings,
    )


def _install_sqlite_guards(conn) -> None:
    statements = (
        """
        CREATE TRIGGER IF NOT EXISTS events_reject_update
        BEFORE UPDATE ON events BEGIN
          SELECT RAISE(ABORT, 'ledger events are append-only');
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS events_reject_delete
        BEFORE DELETE ON events BEGIN
          SELECT RAISE(ABORT, 'ledger events are append-only');
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS events_validate_append
        BEFORE INSERT ON events
        WHEN NEW.event_id IS NULL OR NEW.event_id = '' OR NEW.seq != COALESCE(
          (SELECT MAX(seq) + 1 FROM events WHERE layer_id = NEW.layer_id), 0
        )
        BEGIN
          SELECT RAISE(ABORT, 'ledger event must have an ID and append at the next sequence');
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS layers_reject_delete
        BEFORE DELETE ON layers BEGIN
          SELECT RAISE(ABORT, 'ledger layers cannot be deleted');
        END
        """,
    )
    for statement in statements:
        conn.exec_driver_sql(statement)


def _install_postgresql_guards(conn) -> None:
    conn.execute(
        text(
            """
            CREATE OR REPLACE FUNCTION traust_ledger.reject_authoritative_mutation()
            RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              RAISE EXCEPTION 'ledger authoritative history cannot be updated or deleted'
                USING ERRCODE = '55000';
            END
            $$
            """
        )
    )
    conn.execute(
        text(
            """
            CREATE OR REPLACE FUNCTION traust_ledger.validate_event_append()
            RETURNS trigger LANGUAGE plpgsql AS $$
            DECLARE expected_seq integer;
            BEGIN
              IF NEW.event_id IS NULL OR NEW.event_id = '' THEN
                RAISE EXCEPTION 'ledger event_id is required' USING ERRCODE = '23502';
              END IF;
              SELECT COALESCE(MAX(seq) + 1, 0) INTO expected_seq
                FROM traust_ledger.events WHERE layer_id = NEW.layer_id;
              IF NEW.seq <> expected_seq THEN
                RAISE EXCEPTION 'ledger event sequence %, expected % for layer %',
                  NEW.seq, expected_seq, NEW.layer_id USING ERRCODE = '23514';
              END IF;
              RETURN NEW;
            END
            $$
            """
        )
    )
    statements = (
        "DROP TRIGGER IF EXISTS events_reject_mutation ON traust_ledger.events",
        "DROP TRIGGER IF EXISTS events_reject_truncate ON traust_ledger.events",
        "DROP TRIGGER IF EXISTS events_validate_append ON traust_ledger.events",
        "DROP TRIGGER IF EXISTS layers_reject_delete ON traust_ledger.layers",
        "DROP TRIGGER IF EXISTS layers_reject_truncate ON traust_ledger.layers",
        """
        CREATE TRIGGER events_reject_mutation
        BEFORE UPDATE OR DELETE ON traust_ledger.events
        FOR EACH ROW EXECUTE FUNCTION traust_ledger.reject_authoritative_mutation()
        """,
        """
        CREATE TRIGGER events_reject_truncate
        BEFORE TRUNCATE ON traust_ledger.events
        FOR EACH STATEMENT EXECUTE FUNCTION traust_ledger.reject_authoritative_mutation()
        """,
        """
        CREATE TRIGGER events_validate_append
        BEFORE INSERT ON traust_ledger.events
        FOR EACH ROW EXECUTE FUNCTION traust_ledger.validate_event_append()
        """,
        """
        CREATE TRIGGER layers_reject_delete
        BEFORE DELETE ON traust_ledger.layers
        FOR EACH ROW EXECUTE FUNCTION traust_ledger.reject_authoritative_mutation()
        """,
        """
        CREATE TRIGGER layers_reject_truncate
        BEFORE TRUNCATE ON traust_ledger.layers
        FOR EACH STATEMENT EXECUTE FUNCTION traust_ledger.reject_authoritative_mutation()
        """,
    )
    for statement in statements:
        conn.execute(text(statement))


def _upgrade_revision_one(conn, dialect_name: str, revision: Table) -> None:
    schema = LEDGER_SCHEMA if dialect_name == "postgresql" else None
    events_name = _qualified(schema, "events")
    null_ids = conn.execute(
        text(f"SELECT COUNT(*) FROM {events_name} WHERE event_id IS NULL OR event_id = ''")
    ).scalar_one()
    if null_ids:
        raise RuntimeError(f"cannot enforce append-only history: {null_ids} event(s) lack event_id")
    if dialect_name == "postgresql":
        conn.execute(text("ALTER TABLE traust_ledger.events ALTER COLUMN event_id SET NOT NULL"))
    conn.execute(update(revision).where(revision.c.revision == 1).values(revision=2))


def verify_current(engine: Engine) -> LedgerTables:
    """Verify runtime compatibility without requiring schema-owner privileges."""
    tables = ledger_tables(engine.dialect.name)
    with engine.connect() as conn:
        revisions = conn.execute(select(tables.revision.c.revision)).scalars().all()
    if revisions != [SCHEMA_REVISION]:
        raise RuntimeError(f"unsupported ledger schema revisions: {revisions!r}")
    return tables


def ensure_current(engine: Engine) -> LedgerTables:
    """Create a missing schema for local use, otherwise perform a read-only check."""
    schema = LEDGER_SCHEMA if engine.dialect.name == "postgresql" else None
    if inspect(engine).has_table("schema_revision", schema=schema):
        return verify_current(engine)
    return upgrade(engine)


def upgrade(engine: Engine) -> LedgerTables:
    """Create or upgrade the ledger-owned schema and integrity guards."""
    tables = ledger_tables(engine.dialect.name)
    with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            conn.execute(CreateSchema(LEDGER_SCHEMA, if_not_exists=True))
        tables.metadata.create_all(conn)
        revisions = conn.execute(select(tables.revision.c.revision)).scalars().all()
        if not revisions:
            conn.execute(insert(tables.revision).values(revision=SCHEMA_REVISION))
        elif revisions == [1]:
            _upgrade_revision_one(conn, engine.dialect.name, tables.revision)
        elif revisions != [SCHEMA_REVISION]:
            raise RuntimeError(f"unsupported ledger schema revisions: {revisions!r}")
        if engine.dialect.name == "postgresql":
            _install_postgresql_guards(conn)
        elif engine.dialect.name == "sqlite":
            _install_sqlite_guards(conn)
    return tables
