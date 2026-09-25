"""Normalized SQLAlchemy Ledger storage backend."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import TypeVar

from sqlalchemy import insert, select, text, update
from sqlalchemy.engine import Connection, Engine

from traust_ledger._internal.migrations import ledger_tables, upgrade

from .constants import EMPTY_LAYER
from .errors import LayerConflictError, LayerNotInitializedError
from .records import LayerRecord, StoredLayerRecord
from .validation import validate_layer

T = TypeVar("T")


def _layer_id(path: Path) -> str:
    return path.stem


class DbBackend:
    """Normalized layer storage with ordered events and atomic reconstruction."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._tables = ledger_tables(engine.dialect.name)

    @classmethod
    def create_tables(cls, engine: Engine) -> None:
        upgrade(engine)

    def list_layer_ids(self) -> list[str]:
        with self._engine.connect() as conn:
            rows = conn.execute(select(self._tables.layers.c.layer_id)).scalars().all()
        return sorted(rows)

    def has_layer(self, layer_id: str) -> bool:
        with self._engine.connect() as conn:
            return self._has_layer(conn, layer_id)

    def load(self, path: Path) -> dict:
        return self.load_layer_id(_layer_id(path))

    def load_layer_id(self, layer_id: str) -> dict:
        """Load by domain identity without applying filesystem path rules."""
        with self._engine.connect() as conn:
            layer = self._load(conn, layer_id)
        if layer is not None:
            validate_layer(layer)
        return deepcopy(layer) if layer is not None else deepcopy(EMPTY_LAYER)

    def store(self, path: Path, data: dict) -> None:
        validate_layer(data)
        layer_id = _layer_id(path)
        with self._engine.begin() as conn:
            self._lock_layer(conn, layer_id)
            self._persist(conn, layer_id, LayerRecord.from_document(data))

    def mutate(self, path: Path, mutator: Callable[[dict], T]) -> T:
        layer_id = _layer_id(path)
        with self._engine.begin() as conn:
            self._lock_layer(conn, layer_id)
            data = self._load(conn, layer_id, for_update=True)
            if data is None:
                raise LayerNotInitializedError(
                    f"layer {layer_id!r} is not initialized; provide a complete layer shell"
                )
            result = mutator(data)
            validate_layer(data)
            self._persist(conn, layer_id, LayerRecord.from_document(data))
            return result

    def import_layer(self, layer_id: str, data: dict, *, dry_run: bool = False) -> str:
        """Insert immutable history, accepting only exact idempotent migrations."""
        validate_layer(data)
        record = LayerRecord.from_document(data)
        with self._engine.begin() as conn:
            self._lock_layer(conn, layer_id)
            existing = self._load(conn, layer_id, for_update=True)
            if existing is not None:
                if existing != data:
                    raise LayerConflictError(f"layer {layer_id!r} already contains different data")
                return "skipped"
            if dry_run:
                return "would_insert"
            self._persist(conn, layer_id, record)
            reconstructed = self._load(conn, layer_id)
            if reconstructed != data:
                raise RuntimeError(f"layer {layer_id!r} failed reconstruction verification")
            validate_layer(reconstructed)
            return "inserted"

    def initialize(self, path: Path, data: dict) -> None:
        """Create one complete layer atomically; never replace an existing layer."""
        validate_layer(data)
        layer_id = _layer_id(path)
        with self._engine.begin() as conn:
            self._lock_layer(conn, layer_id)
            if self._has_layer(conn, layer_id):
                raise LayerConflictError(f"layer {layer_id!r} already exists")
            self._persist(conn, layer_id, LayerRecord.from_document(data))

    @staticmethod
    def _lock_layer(conn: Connection, layer_id: str) -> None:
        if conn.dialect.name == "postgresql":
            conn.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:layer_id, 0))"),
                {"layer_id": layer_id},
            )

    def _has_layer(self, conn: Connection, layer_id: str) -> bool:
        statement = select(self._tables.layers.c.layer_id).where(
            self._tables.layers.c.layer_id == layer_id
        )
        return conn.execute(statement).first() is not None

    def _load(
        self,
        conn: Connection,
        layer_id: str,
        *,
        for_update: bool = False,
    ) -> dict | None:
        statement = select(
            self._tables.layers.c.metadata_payload,
            self._tables.layers.c.needs_review_payload,
            self._tables.layers.c.extensions_payload,
            self._tables.layers.c.root_keys_payload,
        ).where(self._tables.layers.c.layer_id == layer_id)
        if for_update:
            statement = statement.with_for_update()
        row = conn.execute(statement).first()
        if row is None:
            return None
        stored = StoredLayerRecord.from_payloads(
            row.metadata_payload,
            row.needs_review_payload,
            row.extensions_payload,
            row.root_keys_payload,
        )
        return stored.reconstruct(self._event_payloads(conn, layer_id))

    def _event_payloads(self, conn: Connection, layer_id: str) -> list[bytes | memoryview]:
        statement = (
            select(self._tables.events.c.event_payload)
            .where(self._tables.events.c.layer_id == layer_id)
            .order_by(self._tables.events.c.seq)
        )
        return list(conn.execute(statement).scalars())

    def _persist(self, conn: Connection, layer_id: str, record: LayerRecord) -> None:
        stored_payloads = [bytes(payload) for payload in self._event_payloads(conn, layer_id)]
        append_offset = record.append_offset(layer_id, stored_payloads)
        values = record.layer_values()
        if self._has_layer(conn, layer_id):
            statement = (
                update(self._tables.layers)
                .where(self._tables.layers.c.layer_id == layer_id)
                .values(**values)
            )
        else:
            statement = insert(self._tables.layers).values(layer_id=layer_id, **values)
        conn.execute(statement)

        event_values = record.new_event_values(layer_id, append_offset)
        if event_values:
            conn.execute(insert(self._tables.events), event_values)


__all__ = ["DbBackend", "LayerConflictError"]
