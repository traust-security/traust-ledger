"""Single ledger write abstraction for disposition layers."""

from __future__ import annotations

import json
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import TypeVar

import jsonschema

from traust_ledger._internal import events
from traust_ledger._internal.backends import Backend, FileBackend
from traust_ledger._internal.backends.keys import DbLayerKey, LayerKey, as_layer_key
from traust_ledger._internal.disposition import is_actor_verified
from traust_ledger._internal.errors import EventIdMismatchError, IdentityUnverifiedError
from traust_ledger._internal.identity import ALGO_VERSION
from traust_ledger._internal.restatements import (
    SIGNED_METADATA_FIELDS,
    is_destructive_change,
    is_restatement,
    merge_delta,
)
from traust_ledger.errors import UnexplainedMetadataChangeError

T = TypeVar("T")


#: Terminal states a queued review item may be moved to (layer.schema.json).
_RESOLVED_STATUSES = frozenset({"confirmed", "rejected"})


def review_item_key(item: dict) -> tuple:
    """Addressable identity of a queued review item.

    A review item has no id in the schema, so it is addressed by the fields that
    make it distinct. Append and resolve MUST agree on this, or a queue can be
    written that nothing can close — which is exactly the state that made this
    function necessary.
    """
    return (
        item.get("source_ref"),
        item.get("suggested_finding_ref"),
        item.get("queue_reason"),
        item.get("quote"),
    )


def resolve_review_item(
    layer: dict,
    item_key: tuple,
    status: str,
    *,
    resolution_note: str | None = None,
    actor: dict | None = None,
) -> bool:
    """Close a queued review item IN THE GIVEN LAYER DICT. True if one changed.

    Pure: no I/O, no lock, no signing. `needs_review` is not an event, so it sits
    outside the Merkle tree and outside `merkle_signature_payload` — closing an
    item cannot move a root or invalidate a signature.

    Two rules from `layer.schema.json`, enforced here so that every caller gets
    them, not just the ones that go through `LedgerWriter`:

    * `confirmed` REQUIRES an event in the layer carrying the item's
      `suggested_finding_ref`. A confirmed item asserts a determination was
      recorded; without the event the assertion is false and the ledger and its
      queue disagree about what happened.
    * `rejected` REQUIRES a `resolution_note`. "We decided not to act" is only a
      decision if it says why.

    First PENDING match, not first match. The key is not unique — a review item
    has no id in the schema, so two statements about the same finding from the
    same source with the same quote collide, and the corpus has them. Matching
    the first item of any status made a pending item shadowed by a resolved twin
    permanently unreachable.

    Terminal: an already-resolved item is not re-resolved. Re-open by queueing a
    new item.
    """
    if status not in _RESOLVED_STATUSES:
        raise ValueError(f"status must be one of {sorted(_RESOLVED_STATUSES)}, got {status!r}")
    if status == "rejected" and not (resolution_note or "").strip():
        raise ValueError("a rejected review item must record a resolution_note")

    target = next(
        (
            item
            for item in (layer.get("needs_review") or [])
            if isinstance(item, dict)
            and item.get("status") == "pending"
            and review_item_key(item) == item_key
        ),
        None,
    )
    if target is None:
        return False

    if status == "confirmed":
        ref = target.get("suggested_finding_ref")
        refs = {e.get("finding_ref") for e in (layer.get("events") or []) if isinstance(e, dict)}
        if not ref or ref not in refs:
            raise ValueError(
                f"cannot confirm review item for {ref!r}: the layer holds no event "
                f"with that finding_ref. Append the event first — a confirmed item "
                f"asserts a determination the ledger does not have."
            )

    target["status"] = status
    if resolution_note:
        target["resolution_note"] = resolution_note
    if actor:
        target["resolved_by"] = actor
    return True


class LedgerWriter:
    """Write events to a disposition layer with ACID guarantees.

    Enforces append-only semantics: events are never mutated or removed,
    only added. Idempotent: appending the same event twice (same event_id)
    results in one copy in the ledger. Atomic: writes complete or fail
    atomically via tempfile + os.replace.
    """

    def __init__(
        self,
        schema_path: str | Path | None = None,
        backend: Backend | None = None,
    ):
        """Initialize writer with optional schema validation and backend.

        Args:
            schema_path: Path to JSON schema (layer.schema.json). If provided,
                         the layer is validated after append; None disables
                         schema validation (callers supply the contracts pin).
            backend: Storage backend (FileBackend by default). Can be replaced
                     with a custom backend that has load(path) and
                     store(path, data) methods.
        """
        self.schema_path = schema_path
        self.backend = backend or FileBackend()
        self._schema = None
        self._schema_loaded = False

    def _get_schema(self) -> dict | None:
        """Load and cache the JSON schema if configured."""
        if self._schema_loaded:
            return self._schema

        self._schema_loaded = True
        if self.schema_path is None:
            return None

        path = Path(self.schema_path)
        try:
            with path.open(encoding="utf-8") as f:
                self._schema = json.load(f)
            return self._schema
        except (OSError, json.JSONDecodeError) as e:
            raise ValueError(f"Failed to load schema from {path}: {e}") from e

    def _validate_layer(self, layer: dict) -> None:
        """Validate layer against schema if configured."""
        schema = self._get_schema()
        if schema is None:
            return
        try:
            jsonschema.validate(layer, schema)
        except jsonschema.ValidationError as e:
            raise ValueError(f"Layer validation failed: {e.message}") from e

    def _mutate_layer(
        self,
        layer_path: LayerKey,
        mutator: Callable[[dict], T],
    ) -> T:
        if hasattr(self.backend, "mutate"):
            return self.backend.mutate(layer_path, mutator)
        layer = self.backend.load(layer_path)
        result = mutator(layer)
        self.backend.store(layer_path, layer)
        return result

    def append_restatement(
        self,
        layer_path: str | Path | DbLayerKey,
        event: dict,
        metadata_updates: dict | Callable[[dict], dict],
        finalize: Callable[[dict], str] | None,
        before_append: Callable[[dict], None] | None = None,
    ) -> tuple[str, str]:
        """Append a restatement event and apply its metadata effect atomically.

        One lock, one write: split in two, there is a window where metadata has
        changed and nothing in the log explains it. The snapshot is taken inside
        the mutator so it compares against what storage holds, not a stale read.
        """
        layer_path = as_layer_key(layer_path)

        def _apply(layer: dict) -> tuple[str, str]:
            if before_append is not None:
                before_append(layer)
            meta = layer.setdefault("metadata", {})
            snapshot = {field: deepcopy(meta.get(field)) for field in SIGNED_METADATA_FIELDS}
            event_id = self._append_one(layer, event)
            # Callable form lets a caller compute the effect from what storage
            # actually holds -- a delta cannot be merged before the load.
            updates = metadata_updates(layer) if callable(metadata_updates) else metadata_updates
            for key, value in updates.items():
                if value is None:
                    meta.pop(key, None)
                else:
                    meta[key] = value
            self.require_restatements_cover_metadata(layer, snapshot, event)
            merkle_root = finalize(layer) if finalize is not None else ""
            return event_id, merkle_root

        return self._mutate_layer(layer_path, _apply)

    @staticmethod
    def require_restatements_cover_metadata(layer: dict, snapshot: dict, event: dict) -> None:
        """A changed signed-digest field must equal snapshot + the event's delta.

        Computed rather than trusted: the appended restatement says which
        entries it replaces, so the resulting metadata is derivable. Anything
        else in the same write -- an extra key, a second field, a value the
        delta does not mention -- is an unexplained change and fails.
        """
        meta = layer.get("metadata") or {}
        block = event.get("restatement") or {}
        covered = block.get("target") if is_restatement(event) else None
        for field in SIGNED_METADATA_FIELDS:
            if not is_destructive_change(snapshot.get(field), meta.get(field)):
                continue
            if field != covered:
                raise UnexplainedMetadataChangeError(field=field)
            expected = merge_delta(snapshot.get(field), block.get("after"))
            if meta.get(field) != expected:
                raise UnexplainedMetadataChangeError(field=field)

    def append_event(
        self,
        layer_path: str | Path | DbLayerKey,
        event: dict,
    ) -> str:
        """Append an event to a layer, idempotently."""
        event_id, _root = self.append_event_finalized(layer_path, event, None, None)
        return event_id

    def append_event_finalized(
        self,
        layer_path: str | Path | DbLayerKey,
        event: dict,
        finalize: Callable[[dict], str] | None,
        before_append: Callable[[dict], None] | None,
    ) -> tuple[str, str]:
        layer_path = as_layer_key(layer_path)

        def _append(layer: dict) -> tuple[str, str]:
            if before_append is not None:
                before_append(layer)
            event_id = self._append_one(layer, event)
            merkle_root = finalize(layer) if finalize is not None else ""
            return event_id, merkle_root

        result = self._mutate_layer(layer_path, _append)
        return result

    def resolve_needs_review(
        self,
        layer_path: str | Path | DbLayerKey,
        item_key: tuple,
        status: str,
        *,
        resolution_note: str | None = None,
        actor: dict | None = None,
    ) -> bool:
        """Close a queued review item under the layer lock. See `resolve_review_item`.

        Use this when you own the write. A caller that is already holding a layer
        dict and writing it itself — `countersign` is the one in-tree example —
        calls `resolve_review_item` directly instead, so the rules live in one
        place rather than being re-implemented beside every writer.
        """
        layer_path = as_layer_key(layer_path)

        def _resolve_locked(layer: dict) -> bool:
            changed = resolve_review_item(
                layer,
                item_key,
                status,
                resolution_note=resolution_note,
                actor=actor,
            )
            if changed:
                self._validate_layer(layer)
            return changed

        return self._mutate_layer(layer_path, _resolve_locked)

    def append_events_finalized(
        self,
        layer_path: str | Path | DbLayerKey,
        events: list[dict],
        finalize: Callable[[dict], str] | None,
        before_append: Callable[[dict], None] | None = None,
    ) -> tuple[list[str], str]:
        """Batch-append events to a layer under a single lock.

        Returns (event_ids, merkle_root). Idempotent per event_id.
        """
        layer_path = as_layer_key(layer_path)

        def _append_batch(layer: dict) -> tuple[list[str], str]:
            if before_append is not None:
                before_append(layer)
            ids = self._append_many(layer, events)
            merkle_root = finalize(layer) if finalize is not None else ""
            return ids, merkle_root

        return self._mutate_layer(layer_path, _append_batch)

    def append_events(
        self,
        layer_path: str | Path | DbLayerKey,
        events: list[dict],
    ) -> list[str]:
        """Batch-append without finalization."""
        ids, _ = self.append_events_finalized(layer_path, events, None)
        return ids

    def append_needs_review(
        self,
        layer_path: str | Path | DbLayerKey,
        items: list[dict],
    ) -> int:
        """Append needs_review queue items, deduplicating by review_item_key.

        Returns count of newly appended items. Mutates items in-place
        (stamps status=pending if absent).
        """
        layer_path = as_layer_key(layer_path)

        def _append_queue(layer: dict) -> int:
            queue = layer.get("needs_review") or []
            existing_keys = {review_item_key(i) for i in queue if isinstance(i, dict)}
            added = 0
            for item in items:
                if not isinstance(item, dict):
                    continue
                item.setdefault("status", "pending")
                key = review_item_key(item)
                if key in existing_keys:
                    continue
                queue.append(item)
                existing_keys.add(key)
                added += 1
            if added:
                layer["needs_review"] = queue
                self._validate_layer(layer)
            return added

        return self._mutate_layer(layer_path, _append_queue)

    def _append_many(self, layer: dict, events_list: list[dict]) -> list[str]:
        """Internal batch loop — calls _prepare_event per event (identity rule fires).

        Returns only the IDs of *newly appended* events (not pre-existing dupes).
        """
        ids: list[str] = []
        existing_events = layer.get("events") or []
        existing_ids = {e.get("event_id") for e in existing_events}
        for event in events_list:
            event_id = self._prepare_event(event)
            if event_id in existing_ids:
                continue
            existing_events.append(event)
            existing_ids.add(event_id)
            ids.append(event_id)
        layer["events"] = existing_events
        self._validate_layer(layer)
        return ids

    def _append_one(self, layer: dict, event: dict) -> str:
        event_id = self._prepare_event(event)
        existing_events = layer.get("events") or []
        existing_ids = {e.get("event_id") for e in existing_events}
        if event_id in existing_ids:
            return event_id
        layer["events"] = [*existing_events, event]
        self._validate_layer(layer)
        return event_id

    def _prepare_event(self, event: dict) -> str:
        if is_restatement(event) and (event.get("disposition") or {}):
            # Write-path copy of the schema rule, so a writer configured without
            # schema validation still cannot put a restatement into precedence.
            raise ValueError("a restatement event must carry an empty disposition")
        source_ref = (event.get("source") or {}).get("ref", "")
        finding_ref = event.get("finding_ref", "")
        validity = (event.get("disposition") or {}).get("validity")
        resolution = (event.get("disposition") or {}).get("resolution")
        canonical_id = events.compute_event_id(
            source_ref,
            finding_ref,
            validity,
            resolution,
        )
        supplied_id = event.get("event_id")
        if supplied_id and supplied_id != canonical_id:
            raise EventIdMismatchError(supplied=supplied_id, canonical=canonical_id)
        event["event_id"] = canonical_id
        self._stamp_fingerprint_algo(event)
        self._enforce_identity_rule(event)
        return canonical_id

    @staticmethod
    def _stamp_fingerprint_algo(event: dict) -> None:
        """Stamp fingerprint_algo on events that carry a fingerprint but no algo.

        Centralised here so every write path — REST batch, REST single-event,
        CLI submit — gets the stamp without each handler remembering to call it.
        """
        if event.get("fingerprint") and not event.get("fingerprint_algo"):
            event["fingerprint_algo"] = ALGO_VERSION

    def _enforce_identity_rule(self, event: dict) -> None:
        """Assert: human false_positive must have verified identity.

        With OIDC mandatory on all write paths, the stamped actor is always
        verified. This is defense-in-depth — if it fires, it's a programming
        error in the write path, not a user-facing condition.

        TODO: revisit removal once property tests have run in CI long enough
        to confirm no bypass exists. Keeping as a regression guard in case a
        future ingestion path (SDK, batch import, migration) skips authentication.
        """
        disp = event.get("disposition") or {}
        actor = (event.get("source") or {}).get("actor") or {}

        if disp.get("validity") != "false_positive":
            return
        if actor.get("kind") != "human":
            return
        if actor.get("identity") and is_actor_verified(actor):
            return

        raise IdentityUnverifiedError()
