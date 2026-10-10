"""Normalized SQLAlchemy Ledger storage backend."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import TypeVar

from sqlalchemy import insert, select, text, update
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError

from traust_ledger._internal.migrations import enable_sqlite_foreign_keys, ledger_tables, upgrade

from .constants import EMPTY_LAYER
from .errors import LayerConflictError, LayerNotInitializedError, LayerStorageError
from .keys import DbLayerKey, LayerKey
from .records import LayerRecord, StoredLayerRecord
from .validation import validate_layer

T = TypeVar("T")


def _layer_id(key: LayerKey) -> str:
    """Opaque database ID; a file path (local CLI) keeps its historical filename stem."""
    return key.layer_id if isinstance(key, DbLayerKey) else key.stem


class DbBackend:
    """Normalized layer storage with ordered events and atomic reconstruction."""

    #: Layer IDs are SQL values, not filenames; see ``traust_ledger.paths.layer_key``.
    opaque_layer_ids = True

    def __init__(self, engine: Engine) -> None:
        enable_sqlite_foreign_keys(engine)
        self._engine = engine
        self._tables = ledger_tables(engine.dialect.name)

    @classmethod
    def create_tables(cls, engine: Engine) -> None:
        upgrade(engine)

    def list_layer_ids(self) -> list[str]:
        with self._engine.connect() as conn:
            rows = conn.execute(select(self._tables.layers.c.layer_id)).scalars().all()
        return sorted(rows)

    def list_layer_refs(self, product_repo_id: str | None = None) -> list[tuple[str, str | None]]:
        layers = self._tables.layers
        statement = select(layers.c.layer_id, layers.c.product_repo_id).order_by(layers.c.layer_id)
        if product_repo_id is not None:
            statement = statement.where(layers.c.product_repo_id == product_repo_id)
        with self._engine.connect() as conn:
            return [(row.layer_id, row.product_repo_id) for row in conn.execute(statement)]

    def has_layer(self, layer_id: str) -> bool:
        with self._engine.connect() as conn:
            return self._has_layer(conn, layer_id)

    def load(self, path: LayerKey) -> dict:
        return self.load_layer_id(_layer_id(path))

    def load_layer_id(self, layer_id: str) -> dict:
        """Load by domain identity without applying filesystem path rules."""
        with self._engine.connect() as conn:
            layer = self._load(conn, layer_id)
        if layer is not None:
            validate_layer(layer)
        return deepcopy(layer) if layer is not None else deepcopy(EMPTY_LAYER)

    def store(self, path: LayerKey, data: dict) -> None:
        validate_layer(data)
        layer_id = _layer_id(path)
        with self._engine.begin() as conn:
            self._lock_layer(conn, layer_id)
            if not self._has_layer(conn, layer_id):
                raise LayerNotInitializedError(
                    f"layer {layer_id!r} is not initialized; create it with initialize "
                    "(and its product_repo_id) first"
                )
            self._persist(conn, layer_id, LayerRecord.from_document(data))

    def mutate(self, path: LayerKey, mutator: Callable[[dict], T]) -> T:
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

    def import_layer(
        self,
        layer_id: str,
        data: dict,
        *,
        product_repo_id: str | None = None,
        dry_run: bool = False,
    ) -> str:
        """Insert immutable history, accepting only exact idempotent migrations."""
        _require_product_repo(product_repo_id)
        validate_layer(data)
        record = LayerRecord.from_document(data)
        with self._engine.begin() as conn:
            self._lock_layer(conn, layer_id)
            existing = self._load(conn, layer_id, for_update=True)
            if existing is not None:
                if existing != data:
                    raise LayerConflictError(f"layer {layer_id!r} already contains different data")
                if self._product_repo(conn, layer_id) != product_repo_id:
                    raise LayerConflictError(
                        f"layer {layer_id!r} belongs to a different product_repo"
                    )
                return "skipped"
            self._require_unowned(conn, product_repo_id)
            if dry_run:
                return "would_insert"
            try:
                self._persist(conn, layer_id, record, product_repo_id=product_repo_id)
            except IntegrityError as exc:
                raise _ownership_conflict(layer_id) from exc
            reconstructed = self._load(conn, layer_id)
            if reconstructed != data:
                raise RuntimeError(f"layer {layer_id!r} failed reconstruction verification")
            validate_layer(reconstructed)
            return "inserted"

    def initialize(self, path: LayerKey, data: dict, product_repo_id: str | None = None) -> None:
        """Create one complete layer atomically; never replace an existing layer."""
        _require_product_repo(product_repo_id)
        validate_layer(data)
        layer_id = _layer_id(path)
        try:
            with self._engine.begin() as conn:
                self._lock_layer(conn, layer_id)
                if self._has_layer(conn, layer_id):
                    raise LayerConflictError(f"layer {layer_id!r} already exists")
                self._require_unowned(conn, product_repo_id)
                self._persist(
                    conn, layer_id, LayerRecord.from_document(data), product_repo_id=product_repo_id
                )
        except IntegrityError as exc:
            raise _ownership_conflict(layer_id) from exc

    def product_repo_id(self, layer_id: str) -> str | None:
        with self._engine.connect() as conn:
            return self._product_repo(conn, layer_id)

    def _product_repo(self, conn: Connection, layer_id: str) -> str | None:
        layers = self._tables.layers
        statement = select(layers.c.product_repo_id).where(layers.c.layer_id == layer_id)
        return conn.execute(statement).scalar_one_or_none()

    @staticmethod
    def _lock_layer(conn: Connection, layer_id: str) -> None:
        if conn.dialect.name == "postgresql":
            conn.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:layer_id, 0))"),
                {"layer_id": layer_id},
            )

    def _require_unowned(self, conn: Connection, product_repo_id: str | None) -> None:
        """One layer per product_repo: refuse a second owner claim as a conflict, not a 500."""
        layers = self._tables.layers
        statement = select(layers.c.layer_id).where(layers.c.product_repo_id == product_repo_id)
        existing = conn.execute(statement).scalar_one_or_none()
        if existing is not None:
            raise LayerConflictError(
                f"product_repo {product_repo_id!r} already has layer {existing!r}"
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

    def _persist(
        self,
        conn: Connection,
        layer_id: str,
        record: LayerRecord,
        *,
        product_repo_id: str | None = None,
    ) -> None:
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
            statement = insert(self._tables.layers).values(
                layer_id=layer_id, product_repo_id=product_repo_id, **values
            )
        conn.execute(statement)

        event_values = record.new_event_values(layer_id, append_offset)
        if event_values:
            conn.execute(insert(self._tables.events), event_values)


def _ownership_conflict(layer_id: str) -> LayerConflictError:
    """Map a racing or unregistered owner (unique/foreign-key violation) to a conflict."""
    return LayerConflictError(
        f"layer {layer_id!r} was not created: its product_repo already has a layer "
        "or is not registered in storage"
    )


def _require_product_repo(product_repo_id: str | None) -> None:
    if not isinstance(product_repo_id, str) or not product_repo_id.strip():
        raise LayerStorageError(
            "product_repo_id is required for database-backed layers "
            "(the storage product_repo the layer belongs to)"
        )


__all__ = ["DbBackend", "LayerConflictError"]
