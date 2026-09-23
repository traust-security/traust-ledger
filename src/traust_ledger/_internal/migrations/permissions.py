"""Least-privilege PostgreSQL role grants for normalized Ledger storage."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from .schema import LEDGER_SCHEMA


@dataclass(frozen=True)
class DatabaseRoles:
    writer: str | None = None
    projector: str | None = None
    reader: str | None = None

    def __post_init__(self) -> None:
        configured = [role for role in (self.writer, self.projector, self.reader) if role]
        if len(configured) != len(set(configured)):
            raise ValueError("Ledger writer, projector, and reader roles must be distinct")


def _quote(engine: Engine, role: str) -> str:
    return engine.dialect.identifier_preparer.quote_identifier(role)


def _reset(conn: Connection, role: str) -> None:
    conn.execute(text(f"REVOKE ALL ON ALL TABLES IN SCHEMA {LEDGER_SCHEMA} FROM {role}"))
    conn.execute(text(f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA {LEDGER_SCHEMA} FROM {role}"))
    conn.execute(text(f"GRANT USAGE ON SCHEMA {LEDGER_SCHEMA} TO {role}"))


def configure_roles(engine: Engine, roles: DatabaseRoles) -> None:
    """Apply explicit PostgreSQL privileges; role creation remains deployment-owned."""
    if engine.dialect.name != "postgresql":
        if any((roles.writer, roles.projector, roles.reader)):
            raise ValueError("database roles are supported only by PostgreSQL")
        return
    with engine.begin() as conn:
        if roles.writer:
            writer = _quote(engine, roles.writer)
            _reset(conn, writer)
            conn.execute(
                text(f"GRANT SELECT, INSERT, UPDATE ON {LEDGER_SCHEMA}.layers TO {writer}")
            )
            conn.execute(text(f"GRANT SELECT, INSERT ON {LEDGER_SCHEMA}.events TO {writer}"))
            conn.execute(text(f"GRANT SELECT ON {LEDGER_SCHEMA}.schema_revision TO {writer}"))
            conn.execute(text(f"GRANT USAGE, SELECT ON {LEDGER_SCHEMA}.events_id_seq TO {writer}"))
        if roles.projector:
            projector = _quote(engine, roles.projector)
            _reset(conn, projector)
            conn.execute(
                text(
                    f"GRANT SELECT ON {LEDGER_SCHEMA}.layers, {LEDGER_SCHEMA}.events, "
                    f"{LEDGER_SCHEMA}.schema_revision TO {projector}"
                )
            )
            conn.execute(
                text(
                    f"GRANT SELECT, INSERT, UPDATE, DELETE ON "
                    f"{LEDGER_SCHEMA}.materialized_findings TO {projector}"
                )
            )
        if roles.reader:
            reader = _quote(engine, roles.reader)
            _reset(conn, reader)
            conn.execute(text(f"GRANT SELECT ON {LEDGER_SCHEMA}.materialized_findings TO {reader}"))
