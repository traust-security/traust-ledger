"""Typed serialization records for normalized Ledger storage."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from .constants import LAYER_EVENTS_KEY
from .errors import CorruptStoredLayerError, InvalidLayerDocumentError, LayerConflictError

JsonObject = dict[str, object]
KNOWN_ROOT_KEYS = frozenset({"metadata", LAYER_EVENTS_KEY, "needs_review"})


def encode_json(value: object) -> bytes:
    """Encode JSON without passing decoded U+0000 through PostgreSQL text/JSONB."""
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _decode_json(payload: bytes | memoryview) -> object:
    return json.loads(bytes(payload).decode("utf-8"))


def _object(value: object, label: str, error_type: type[ValueError]) -> JsonObject:
    if not isinstance(value, Mapping):
        raise error_type(f"{label} must be an object")
    return {str(key): item for key, item in value.items()}


def _array(value: object, label: str, error_type: type[ValueError]) -> list[object]:
    if not isinstance(value, list):
        raise error_type(f"{label} must be an array")
    return value


def _optional_object(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _optional_string(value: object) -> str | None:
    """Project a string into PostgreSQL-compatible text; payload bytes remain authoritative.

    A literal NUL cannot be represented in PostgreSQL text. Escape it only in
    derived columns; queries against those columns must use the same projection.
    """
    if isinstance(value, str):
        return value.replace("\\", "\\\\").replace("\x00", "\\u0000")
    return None


def _optional_integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _optional_boolean(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _timestamp(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass(frozen=True)
class EventRecord:
    sequence: int
    document: JsonObject
    event_id: str

    @classmethod
    def from_document(cls, sequence: int, value: object) -> EventRecord:
        document = _object(value, f"event at sequence {sequence}", InvalidLayerDocumentError)
        event_id = document.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            raise InvalidLayerDocumentError(f"event at sequence {sequence} has no event_id")
        return cls(sequence=sequence, document=document, event_id=event_id)

    @property
    def payload(self) -> bytes:
        return encode_json(self.document)

    def database_values(self, layer_id: str) -> dict[str, object]:
        source = _optional_object(self.document.get("source"))
        actor = _optional_object(source.get("actor"))
        disposition = _optional_object(self.document.get("disposition"))
        return {
            "layer_id": layer_id,
            "seq": self.sequence,
            "event_id": self.event_id,
            "finding_ref": _optional_string(self.document.get("finding_ref")),
            "fingerprint": _optional_string(self.document.get("fingerprint")),
            "fingerprint_algo": _optional_string(self.document.get("fingerprint_algo")),
            "recorded_at": _timestamp(self.document.get("recorded_at")),
            "occurred_at": _timestamp(self.document.get("occurred_at")),
            "source_type": _optional_string(source.get("type")),
            "source_ref": _optional_string(source.get("ref")),
            "actor_kind": _optional_string(actor.get("kind")),
            "actor_identity": _optional_string(actor.get("identity")),
            "validity": _optional_string(disposition.get("validity")),
            "resolution": _optional_string(disposition.get("resolution")),
            "evidence_grade": _optional_string(self.document.get("evidence_grade")),
            "auto_accept_tier": _optional_boolean(self.document.get("auto_accept_tier")),
            "event_payload": self.payload,
        }


@dataclass(frozen=True)
class LayerRecord:
    metadata: JsonObject
    events: tuple[EventRecord, ...]
    needs_review: list[object]
    extensions: JsonObject
    root_keys: tuple[str, ...]

    @classmethod
    def from_document(cls, document: object) -> LayerRecord:
        layer = _object(document, "layer", InvalidLayerDocumentError)
        metadata = _object(
            layer.get("metadata") or {},
            "layer metadata",
            InvalidLayerDocumentError,
        )
        raw_events = _array(
            layer.get(LAYER_EVENTS_KEY) or [],
            "layer events",
            InvalidLayerDocumentError,
        )
        needs_review = _array(
            layer.get("needs_review") or [],
            "layer needs_review",
            InvalidLayerDocumentError,
        )
        events = tuple(
            EventRecord.from_document(seq, event) for seq, event in enumerate(raw_events)
        )
        extensions = {key: value for key, value in layer.items() if key not in KNOWN_ROOT_KEYS}
        root_keys = tuple(sorted(KNOWN_ROOT_KEYS.intersection(layer)))
        return cls(metadata, events, needs_review, extensions, root_keys)

    @property
    def event_payloads(self) -> tuple[bytes, ...]:
        return tuple(event.payload for event in self.events)

    def append_offset(self, layer_id: str, stored_payloads: list[bytes]) -> int:
        incoming = self.event_payloads
        if len(incoming) < len(stored_payloads):
            removed = len(stored_payloads) - len(incoming)
            raise LayerConflictError(
                f"layer {layer_id!r} cannot remove {removed} historical event(s)"
            )
        if incoming[: len(stored_payloads)] != tuple(stored_payloads):
            raise LayerConflictError(f"layer {layer_id!r} cannot rewrite historical events")
        return len(stored_payloads)

    def layer_values(self) -> dict[str, object]:
        return {
            "metadata_payload": encode_json(self.metadata),
            "needs_review_payload": encode_json(self.needs_review),
            "extensions_payload": encode_json(self.extensions),
            "root_keys_payload": encode_json(self.root_keys),
            "repository": _optional_string(self.metadata.get("repository")),
            "created_at": _timestamp(self.metadata.get("created")),
            "merkle_root": _optional_string(self.metadata.get("merkle_root")),
            "merkle_epoch": _optional_integer(self.metadata.get("merkle_epoch")),
            "merkle_size": _optional_integer(self.metadata.get("merkle_size")),
            "merkle_root_signature": _optional_string(self.metadata.get("merkle_root_signature")),
            "merkle_signing_method": _optional_string(self.metadata.get("merkle_signing_method")),
            "merkle_signature_format": _optional_integer(
                self.metadata.get("merkle_signature_format")
            ),
        }

    def new_event_values(self, layer_id: str, offset: int) -> list[dict[str, object]]:
        return [event.database_values(layer_id) for event in self.events[offset:]]


@dataclass(frozen=True)
class StoredLayerRecord:
    metadata: JsonObject
    needs_review: list[object]
    extensions: JsonObject
    root_keys: tuple[str, ...]

    @classmethod
    def from_payloads(
        cls,
        metadata: bytes | memoryview,
        needs_review: bytes | memoryview,
        extensions: bytes | memoryview,
        root_keys: bytes | memoryview,
    ) -> StoredLayerRecord:
        decoded_keys = _array(
            _decode_json(root_keys),
            "stored root keys",
            CorruptStoredLayerError,
        )
        if not all(isinstance(key, str) for key in decoded_keys):
            raise CorruptStoredLayerError("stored root keys must contain only strings")
        return cls(
            metadata=_object(
                _decode_json(metadata),
                "stored layer metadata",
                CorruptStoredLayerError,
            ),
            needs_review=_array(
                _decode_json(needs_review),
                "stored needs_review",
                CorruptStoredLayerError,
            ),
            extensions=_object(
                _decode_json(extensions),
                "stored layer extensions",
                CorruptStoredLayerError,
            ),
            root_keys=tuple(cast(list[str], decoded_keys)),
        )

    def reconstruct(self, event_payloads: list[bytes | memoryview]) -> JsonObject:
        events = [
            _object(_decode_json(payload), "stored event", CorruptStoredLayerError)
            for payload in event_payloads
        ]
        layer = dict(self.extensions)
        values: dict[str, object] = {
            "metadata": self.metadata,
            LAYER_EVENTS_KEY: events,
            "needs_review": self.needs_review,
        }
        for key in self.root_keys:
            if key in values:
                layer[key] = values[key]
        return layer
