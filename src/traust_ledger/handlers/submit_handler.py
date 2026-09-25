"""Batch submit handler — persist pre-formed events + queue items to a layer."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from traust_contracts.v1.models.layer import LayerActor

from traust_ledger._internal.backends.errors import LayerStorageError
from traust_ledger._internal.errors import EventIdMismatchError as _InternalEventIdMismatchError
from traust_ledger._internal.identity import ALGO_VERSION
from traust_ledger._internal.layer_finalize import finalize_layer, require_signing_configured
from traust_ledger._internal.writer import LedgerWriter, review_item_key
from traust_ledger.config import ServiceConfig
from traust_ledger.constants import LAYER_ID_PATTERN, STATUS_ACCEPTED
from traust_ledger.errors import ValidationError
from traust_ledger.models import BatchSubmitRequest, SubmitResponse
from traust_ledger.paths import layer_file_path
from traust_ledger.service.errors import (
    EventIdMismatchError,
    InvalidLayerIdError,
    MissingLayerIdError,
)

logger = logging.getLogger(__name__)


def _validate_layer_id(layer_id: str) -> str:
    if not layer_id:
        raise MissingLayerIdError()
    if not re.match(LAYER_ID_PATTERN, layer_id):
        raise InvalidLayerIdError()
    return layer_id


def _stamp_actor_on_event(event: dict, actor: LayerActor) -> dict:
    stamped = dict(event)
    source = stamped.get("source")
    if isinstance(source, dict):
        stamped["source"] = {**source, "actor": actor.to_dict()}
    else:
        stamped["source"] = {"actor": actor.to_dict()}
    return stamped


def _stamp_fingerprint_algo_on_event(event: dict) -> dict:
    """Stamp fingerprint_algo on events that carry a fingerprint but no algo.

    traust-ledger is the sole authority for the fingerprint recipe and its
    version: callers (SDK) copy fingerprint *values* onto events but never
    assert which algorithm produced them. Recording the algo here keeps a
    fingerprint's provenance verifiable and lets the recipe evolve without
    trusting client-supplied version strings.
    """
    if event.get("fingerprint") and not event.get("fingerprint_algo"):
        stamped = dict(event)
        stamped["fingerprint_algo"] = ALGO_VERSION
        return stamped
    return event


def _submit_atomic(
    writer: LedgerWriter,
    layer_path: Path,
    events: list[dict],
    queue_items: list[dict],
    config: ServiceConfig,
) -> tuple[list[str], str, int]:
    """Persist events + queue items in a single lock acquisition.

    TECH DEBT: reaches into writer._append_many, _mutate_layer, _validate_layer.
    Needs a public batch API on LedgerWriter (see AGENTS.md extraction candidates).
    """

    def _mutator(layer: dict) -> tuple[list[str], str, int]:
        ids = writer._append_many(layer, events)
        queue = layer.get("needs_review") or []
        existing_keys = {review_item_key(i) for i in queue if isinstance(i, dict)}
        added = 0
        for item in queue_items:
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
            writer._validate_layer(layer)
        merkle_root = finalize_layer(layer, config)
        return ids, merkle_root, added

    return writer._mutate_layer(layer_path, _mutator)


def submit_batch(
    layer_id: str,
    body: BatchSubmitRequest,
    actor: LayerActor,
    writer: LedgerWriter,
    config: ServiceConfig,
) -> SubmitResponse:
    """Persist pre-formed events and queue items to a layer.

    Stamps the caller's identity on every event. Idempotent per event_id.
    """
    require_signing_configured(config)
    layer_id = _validate_layer_id(layer_id)
    layer_path = layer_file_path(config.data_dir, layer_id)

    stamped_events = [
        _stamp_fingerprint_algo_on_event(_stamp_actor_on_event(e, actor)) for e in body.events
    ]

    queue_added = 0
    if body.needs_review:
        items = [dict(i) if isinstance(i, dict) else i for i in body.needs_review]
        for item in items:
            if isinstance(item, dict):
                item.setdefault("submitted_by", actor.to_dict())
                item.setdefault("source_ref", body.source_ref)
                item.setdefault("queued_at", body.recorded_at)
    else:
        items = []

    if stamped_events and items:
        try:
            event_ids, merkle_root, queue_added = _submit_atomic(
                writer, layer_path, stamped_events, items, config
            )
        except _InternalEventIdMismatchError as exc:
            raise EventIdMismatchError(supplied=exc.supplied, canonical=exc.canonical) from exc
        except LayerStorageError as exc:
            raise ValidationError(detail=str(exc)) from exc
    elif stamped_events:
        try:
            event_ids, merkle_root = writer.append_events_finalized(
                layer_path,
                stamped_events,
                lambda layer: finalize_layer(layer, config),
            )
        except _InternalEventIdMismatchError as exc:
            raise EventIdMismatchError(supplied=exc.supplied, canonical=exc.canonical) from exc
        except LayerStorageError as exc:
            raise ValidationError(detail=str(exc)) from exc
    elif items:
        try:
            queue_added = writer.append_needs_review(layer_path, items)
        except LayerStorageError as exc:
            raise ValidationError(detail=str(exc)) from exc
        event_ids = []
        merkle_root = ""
    else:
        event_ids = []
        merkle_root = ""

    total = len(event_ids) + queue_added
    logger.info(
        "batch submit layer=%s events=%d queue=%d actor=%s",
        layer_id,
        len(event_ids),
        queue_added,
        actor.identity,
    )
    return SubmitResponse(
        id=f"batch:{layer_id}:{body.source_ref}",
        status=STATUS_ACCEPTED,
        event_count=total,
        merkle_root=merkle_root or None,
        event_ids=event_ids,
        queue_added=queue_added,
    )
