"""Storage-boundary errors for normalized Ledger backends."""

from __future__ import annotations


class LayerStorageError(ValueError):
    """Base error for invalid or conflicting normalized layer storage."""


class InvalidLayerDocumentError(LayerStorageError):
    """An incoming layer cannot be represented by the normalized backend."""


class CorruptStoredLayerError(LayerStorageError):
    """Stored payloads cannot reconstruct a valid layer document."""


class LayerNotInitializedError(LayerStorageError):
    """An operational write requires an explicitly initialized complete layer."""


class LayerConflictError(LayerStorageError):
    """A write attempted to replace authoritative history."""
