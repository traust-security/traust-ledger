"""LedgerWriter paths: schema validation and non-mutate backends."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from traust_ledger._internal.backends import Backend
from traust_ledger._internal.writer import LedgerWriter


class _LoadStoreBackend:
    """Backend without mutate — exercises load/store fallback in LedgerWriter."""

    def __init__(self) -> None:
        self._store: dict[str, dict] = {}

    def load(self, path: Path) -> dict:
        return self._store.setdefault(str(path), {"events": []})

    def store(self, path: Path, data: dict) -> None:
        self._store[str(path)] = data


class TestSchemaValidation:
    def test_invalid_schema_path_raises(self, tmp_path: Path) -> None:
        writer = LedgerWriter(schema_path=tmp_path / "missing.json")
        from conftest import canonical_shell

        writer.backend.initialize(tmp_path / "layer.json", canonical_shell())
        with pytest.raises(ValueError, match="Failed to load schema"):
            writer.append_event(tmp_path / "layer.json", _minimal_event())

    def test_schema_validation_failure_raises(self, tmp_path: Path) -> None:
        schema_path = tmp_path / "schema.json"
        schema_path.write_text(
            json.dumps(
                {
                    "type": "object",
                    "required": ["events", "layer_version"],
                    "properties": {
                        "events": {"type": "array"},
                        "layer_version": {"type": "integer"},
                    },
                }
            ),
            encoding="utf-8",
        )
        writer = LedgerWriter(schema_path=schema_path)
        layer_path = tmp_path / "layer.json"
        from conftest import canonical_shell

        layer_path.write_text(json.dumps(canonical_shell()), encoding="utf-8")
        with pytest.raises(ValueError, match="Layer validation failed"):
            writer.append_event(layer_path, _minimal_event())


class TestLoadStoreFallback:
    def test_backend_without_mutate_uses_load_store(self, tmp_path: Path) -> None:
        backend: Backend = _LoadStoreBackend()  # type: ignore[assignment]
        writer = LedgerWriter(backend=backend)
        layer_path = tmp_path / "layer.json"
        event_id = writer.append_event(layer_path, _minimal_event())
        assert event_id
        loaded = backend.load(layer_path)
        assert len(loaded["events"]) == 1


def _minimal_event() -> dict:
    return {
        "source": {"ref": "test", "actor": {"kind": "machine"}},
        "finding_ref": "FIND-001",
        "disposition": {"validity": "confirmed"},
    }
