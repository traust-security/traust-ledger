"""Explicit SQLAlchemy bindings for the Contracts-owned Ledger SQL."""

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
    inspect,
    select,
    text,
)
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql import func
from traust_contracts.v1.ledger import (
    CONTRACT_VERSION,
    POSTGRES_SCHEMA,
    REVISION,
)
from traust_contracts.v1.ledger import (
    Dialect as ContractDialect,
)
from traust_contracts.v1.ledger import (
    bootstrap_files as ledger_bootstrap_files,
)
from traust_contracts.v1.ledger import (
    bootstrap_statements as ledger_bootstrap_statements,
)

LEDGER_SCHEMA = POSTGRES_SCHEMA
SCHEMA_REVISION = REVISION


@dataclass(frozen=True)
class LedgerTables:
    metadata: MetaData
    revision: Table
    layers: Table
    events: Table
    materialized_findings: Table


@cache
def ledger_tables(dialect_name: str) -> LedgerTables:
    """Local query bindings; physical DDL always comes from Contracts SQL."""
    if dialect_name not in ("postgresql", "sqlite"):
        raise ValueError(f"unsupported Ledger database dialect: {dialect_name}")
    schema = LEDGER_SCHEMA if dialect_name == "postgresql" else None
    metadata = MetaData(schema=schema)
    revision = Table(
        "schema_revision",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("contract_version", Text, nullable=False),
        Column("revision", Integer, nullable=False),
        Column("applied_at", DateTime(timezone=True), nullable=False),
        CheckConstraint("id = 1"),
    )
    layers = Table(
        "layers",
        metadata,
        Column("layer_id", String, primary_key=True),
        *(
            Column(name, LargeBinary, nullable=False)
            for name in (
                "metadata_payload",
                "needs_review_payload",
                "extensions_payload",
                "root_keys_payload",
            )
        ),
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
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        ),
    )
    events = Table(
        "events",
        metadata,
        Column(
            "id",
            BigInteger().with_variant(Integer, "sqlite"),
            Identity(always=True) if schema else None,
            primary_key=True,
        ),
        Column(
            "layer_id",
            String,
            ForeignKey(f"{schema + '.' if schema else ''}layers.layer_id", ondelete="RESTRICT"),
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
    for name, columns in (
        ("idx_ledger_events_clock", ("fingerprint", "occurred_at")),
        ("idx_ledger_events_finding_ref", ("layer_id", "finding_ref")),
        ("idx_ledger_events_recorded_at", ("layer_id", "recorded_at")),
        ("idx_ledger_events_resolution", ("resolution", "occurred_at")),
        ("idx_ledger_events_source", ("source_type", "occurred_at")),
    ):
        Index(name, *(events.c[column] for column in columns))
    findings = Table(
        "materialized_findings",
        metadata,
        Column("layer_id", String, nullable=False),
        Column("finding_ref", String, nullable=False),
        Column("fingerprint", String),
        Column("orphan", Boolean),
        Column("validity", String, nullable=False),
        Column("resolution", String, nullable=False),
        Column("assurance", String),
        Column("event_count", Integer, nullable=False),
        Column("conflict", Boolean),
        Column("fp_overridden", Boolean),
        Column("fp_reassertion_blocked", Boolean),
        Column("severity_override", JSON),
        Column("last_updated", String),
        Column("merkle_root", String),
        Column("merkle_epoch", Integer),
        Column("materialized_at", DateTime(timezone=True), server_default=func.now()),
        PrimaryKeyConstraint("layer_id", "finding_ref"),
    )
    return LedgerTables(metadata, revision, layers, events, findings)


def _contract_dialect(dialect_name: str) -> ContractDialect:
    if dialect_name == "postgresql":
        return "postgres"
    if dialect_name == "sqlite":
        return "sqlite"
    raise ValueError(f"unsupported Ledger database dialect: {dialect_name}")


def _install_contract_schema(conn, dialect_name: str) -> None:
    dialect = _contract_dialect(dialect_name)
    for path in ledger_bootstrap_files(dialect):
        for statement in ledger_bootstrap_statements(dialect, path):
            conn.exec_driver_sql(statement)


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


def _revision_rows(conn: Connection, table: Table) -> list[tuple[int, str, int]]:
    return [
        tuple(row)
        for row in conn.execute(
            select(table.c.id, table.c.contract_version, table.c.revision)
        ).all()
    ]


def _verify_revision(conn: Connection, table: Table) -> None:
    try:
        rows = _revision_rows(conn, table)
    except SQLAlchemyError as exc:
        raise RuntimeError(
            "unsupported ledger schema metadata shape; expected singleton v1/revision 1"
        ) from exc
    if rows != [(1, CONTRACT_VERSION, SCHEMA_REVISION)]:
        raise RuntimeError(
            f"unsupported ledger schema metadata: {rows!r}; "
            f"expected (1, {CONTRACT_VERSION!r}, {SCHEMA_REVISION})"
        )


def verify_current(engine: Engine) -> LedgerTables:
    """Verify compatibility without schema-owner privileges or implicit migration."""
    tables = ledger_tables(engine.dialect.name)
    with engine.connect() as conn:
        _verify_revision(conn, tables.revision)
    return tables


def ensure_current(engine: Engine) -> LedgerTables:
    """Create missing schema only; never migrate an existing database implicitly."""
    schema = LEDGER_SCHEMA if engine.dialect.name == "postgresql" else None
    if inspect(engine).has_table("schema_revision", schema=schema):
        return verify_current(engine)
    return upgrade(engine)


def upgrade(engine: Engine) -> LedgerTables:
    """Bootstrap fresh SQL; future upgrades must be explicit Ledger-owned steps."""
    tables = ledger_tables(engine.dialect.name)
    schema = LEDGER_SCHEMA if engine.dialect.name == "postgresql" else None
    exists = inspect(engine).has_table("schema_revision", schema=schema)
    with engine.begin() as conn:
        if not exists:
            _install_contract_schema(conn, engine.dialect.name)
            conn.execute(
                text(
                    f"INSERT INTO {schema + '.' if schema else ''}schema_revision "
                    "(id, contract_version, revision, applied_at) "
                    "VALUES (1, :version, :revision, CURRENT_TIMESTAMP)"
                ),
                {"version": CONTRACT_VERSION, "revision": SCHEMA_REVISION},
            )
        _verify_revision(conn, tables.revision)
        if engine.dialect.name == "postgresql":
            _install_postgresql_guards(conn)
        elif engine.dialect.name == "sqlite":
            _install_sqlite_guards(conn)
    return tables
