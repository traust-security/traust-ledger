"""Ledger storage backends."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Protocol, TypeVar

from .constants import (
    BACKEND_TYPE_DB,
    BACKEND_TYPE_FILE,
    DATABASE_URL_REQUIRED_MSG,
    UNKNOWN_BACKEND_MSG,
)
from .file import FileBackend

T = TypeVar("T")


class Backend(Protocol):
    """Storage backend for disposition layer files."""

    def load(self, path: Path) -> dict:
        """Load a layer from storage."""
        ...

    def initialize(self, path: Path, data: dict) -> None:
        """Create a complete layer without replacing an existing one."""
        ...

    def store(self, path: Path, data: dict) -> None:
        """Persist a layer to storage."""
        ...

    def mutate(self, path: Path, mutator: Callable[[dict], T]) -> T:
        """Atomically load, mutate, and store a layer."""
        ...

    def list_layer_ids(self) -> list[str]:
        """Return all stored layer IDs."""
        ...


def create_backend(backend_type: str = BACKEND_TYPE_FILE, **kwargs: object) -> Backend:
    """Create a storage backend by type name."""
    if backend_type == BACKEND_TYPE_FILE:
        data_dir = kwargs.get("data_dir")
        return FileBackend(data_dir=data_dir)
    if backend_type == BACKEND_TYPE_DB:
        from sqlalchemy import create_engine, event

        from traust_ledger._internal.migrations import ensure_current

        from .db import DbBackend

        database_url = kwargs.get("database_url")
        if not database_url:
            raise ValueError(DATABASE_URL_REQUIRED_MSG)
        engine = create_engine(str(database_url))
        if engine.dialect.name == "sqlite":

            @event.listens_for(engine, "connect")
            def _set_sqlite_pragma(dbapi_conn, connection_record):  # type: ignore[no-untyped-def]
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA busy_timeout=5000")
                cursor.close()

        ensure_current(engine)
        return DbBackend(engine)
    raise ValueError(UNKNOWN_BACKEND_MSG.format(backend_type=backend_type))


__all__ = ["Backend", "FileBackend", "create_backend"]
