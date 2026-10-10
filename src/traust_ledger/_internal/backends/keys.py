"""Backend storage keys: a filesystem path for file layers, an opaque ID for database layers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias


@dataclass(frozen=True)
class DbLayerKey:
    """A database layer's ID, used verbatim as the primary key; never a filesystem path."""

    layer_id: str


LayerKey: TypeAlias = Path | DbLayerKey


def as_layer_key(value: str | Path | DbLayerKey) -> LayerKey:
    """Keep a database key intact; treat anything else as a file path."""
    return value if isinstance(value, DbLayerKey) else Path(value)
