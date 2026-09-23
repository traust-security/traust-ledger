"""Ledger-owned materialized findings projection."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import delete, insert, select, update
from sqlalchemy.engine import Connection, Engine

from traust_ledger._internal.migrations import ensure_current, ledger_tables
from traust_ledger.models import FindingDisposition

_sqlite_tables = ledger_tables("sqlite")
projection_metadata = _sqlite_tables.metadata
findings_table = _sqlite_tables.materialized_findings


def _table(dialect_name: str):
    return ledger_tables(dialect_name).materialized_findings


def ensure_schema(engine: Engine) -> None:
    """Create the ledger schema and projection at the current revision."""
    ensure_current(engine)


def build_row(
    layer_id: str,
    f: FindingDisposition,
    merkle_root: str | None,
    merkle_epoch: int | None,
    now: datetime,
) -> dict:
    d = f.disposition
    return {
        "layer_id": layer_id,
        "finding_ref": f.finding_ref,
        "fingerprint": f.fingerprint,
        "orphan": f.orphan,
        "validity": str(d.validity),
        "resolution": str(d.resolution),
        "assurance": str(d.assurance) if d.assurance else None,
        "event_count": f.event_count,
        "conflict": d.conflict or False,
        "fp_overridden": d.fp_overridden or False,
        "fp_reassertion_blocked": d.fp_reassertion_blocked or False,
        "severity_override": (d.severity_override.model_dump() if d.severity_override else None),
        "last_updated": d.last_updated,
        "merkle_root": merkle_root,
        "merkle_epoch": merkle_epoch,
        "materialized_at": now,
    }


def upsert_layer(
    conn: Connection, layer_id: str, rows: list[dict], *, prune_empty: bool = False
) -> None:
    """Replace one layer's rebuildable finding projection transactionally."""
    table = _table(conn.dialect.name)
    current_refs = {row["finding_ref"] for row in rows}
    if not current_refs and not prune_empty:
        return
    conn.execute(
        delete(table).where(
            table.c.layer_id == layer_id,
            ~table.c.finding_ref.in_(current_refs)
            if current_refs
            else table.c.finding_ref.isnot(None),
        )
    )
    for row in rows:
        existing = conn.execute(
            select(table.c.finding_ref).where(
                table.c.layer_id == row["layer_id"],
                table.c.finding_ref == row["finding_ref"],
            )
        ).first()
        if existing:
            conn.execute(
                update(table)
                .where(
                    table.c.layer_id == row["layer_id"],
                    table.c.finding_ref == row["finding_ref"],
                )
                .values(**row)
            )
        else:
            conn.execute(insert(table).values(**row))


def print_ddl() -> None:
    """Print portable SQLite DDL for the projection table."""
    from sqlalchemy.dialects import sqlite
    from sqlalchemy.schema import CreateTable

    print(str(CreateTable(findings_table).compile(dialect=sqlite.dialect())).strip() + ";")
