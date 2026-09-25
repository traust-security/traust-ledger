"""File-based layer storage backend."""

from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import os
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from .constants import (
    EMPTY_LAYER,
    JSON_ENCODING,
    JSON_ENSURE_ASCII,
    JSON_INDENT,
    LOCK_FILE_SUFFIX,
    NEWLINE,
    TEMP_FILE_SUFFIX,
)
from .errors import LayerConflictError, LayerNotInitializedError
from .validation import validate_layer

T = TypeVar("T")
logger = logging.getLogger(__name__)


class FileBackend:
    """File-based layer storage backend. Writes are atomic."""

    def __init__(self, data_dir: str | Path | None = None) -> None:
        self._data_dir = Path(data_dir) if data_dir else None

    def list_layer_ids(self) -> list[str]:
        """Return all stored layer IDs in the data directory.

        Only files that ARE layers count. The glob used to accept any `*.json`,
        so pointing the materializer at a real findings directory ingested the
        audit report and the triage report as empty layers — measured
        2026-08-20 against `console__release-5.0/`, which yielded four "layers"
        of which three were reports. An empty layer is not harmless: it flows
        into the projection as a layer with zero findings.

        Schema-valid complete layers, not filename shapes, are the test. A
        legacy event-only file is raw evidence, not a canonical layer. Paths
        can use service IDs or corpus findings-layer names.
        """
        if self._data_dir is None or not self._data_dir.exists():
            return []
        return sorted(
            p.stem
            for p in self._data_dir.glob("*.json")
            if not p.name.endswith(".lock") and self._is_layer(p)
        )

    @staticmethod
    def _is_layer(path: Path) -> bool:
        """Only complete schema-valid files are canonical layers for iteration."""
        try:
            with path.open(encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return False
        if not isinstance(doc, dict):
            return False
        try:
            validate_layer(doc)
        except ValueError as exc:
            if isinstance(doc.get("events"), list):
                logger.warning("skipping noncanonical layer %s: %s", path, exc)
            return False
        return True

    def load(self, path: Path) -> dict:
        """Load a layer from disk. Creates empty layer if file absent."""
        resolved = Path(path)
        with self._file_lock(resolved):
            return self._load_unlocked(resolved)

    def initialize(self, path: Path, data: dict) -> None:
        """Create a schema-valid shell without replacing an existing file."""
        validate_layer(data)
        resolved = Path(path)
        with self._file_lock(resolved):
            if resolved.exists():
                raise LayerConflictError(f"layer {resolved.stem!r} already exists")
            self._store_unlocked(resolved, data)

    def export_layer(self, path: Path) -> dict:
        """Export only complete portable layer documents (unlike legacy raw load)."""
        layer = self.load(path)
        validate_layer(layer)
        return layer

    def store(self, path: Path, data: dict) -> None:
        """Store a layer to disk atomically (tempfile + replace)."""
        resolved = Path(path)
        with self._file_lock(resolved):
            self._store_unlocked(resolved, data)

    def mutate(self, path: Path, mutator: Callable[[dict], T]) -> T:
        """Load, mutate, and store under a single file lock."""
        resolved = Path(path)
        with self._file_lock(resolved):
            if not resolved.exists():
                raise LayerNotInitializedError(
                    f"layer {resolved.stem!r} is not initialized; provide a complete layer shell"
                )
            data = self._load_unlocked(resolved)
            metadata = data.get("metadata") if isinstance(data, dict) else None
            if (
                not isinstance(metadata, dict)
                or not all(
                    isinstance(metadata.get(key), str) and metadata[key]
                    for key in ("audit_report", "repository", "created", "harness_version")
                )
                or not isinstance(data.get("needs_review"), list)
            ):
                raise LayerNotInitializedError(
                    f"layer {resolved.stem!r} has no complete initialized shell"
                )
            result = mutator(data)
            validate_layer(data)
            self._store_unlocked(resolved, data)
            return result

    def _lock_path(self, path: Path) -> Path:
        return path.with_suffix(path.suffix + LOCK_FILE_SUFFIX)

    @contextlib.contextmanager
    def _file_lock(self, path: Path):
        lock_path = self._lock_path(path)
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("w", encoding=JSON_ENCODING) as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _load_unlocked(self, path: Path) -> dict:
        if path.exists():
            with path.open(encoding=JSON_ENCODING) as handle:
                return json.load(handle)
        return dict(EMPTY_LAYER)

    def _store_unlocked(self, path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=TEMP_FILE_SUFFIX)
        tmp_path = Path(tmp)
        try:
            with os.fdopen(fd, "w", encoding=JSON_ENCODING) as handle:
                json.dump(data, handle, indent=JSON_INDENT, ensure_ascii=JSON_ENSURE_ASCII)
                handle.write(NEWLINE)
            tmp_path.replace(path)
        except BaseException:
            with contextlib.suppress(OSError):
                tmp_path.unlink()
            raise
