"""Restatement handler — the single restatement path for CLI, REST, and LedgerClient.

All three converge here so no caller can pick a door with weaker checks.
Raises ``ServiceError`` subclasses; each entry point maps them its own way.

``apply_restatement_batch`` is the bulk form the CLI and ``LedgerClient`` share.
It is deliberately absent from REST: one HTTP request cannot be atomic across N
layers (there is one lock per layer), so a batch endpoint would imply a
guarantee the storage model does not give. Over HTTP, many restatements are
many requests.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from traust_contracts.v1.enums import RestatementTarget
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger._internal.events.builders import build_restatement_event
from traust_ledger._internal.gates import (
    require_fresh_restatement,
    require_monotonic_restatement,
    require_rationale_length,
    require_restatement_authority,
    require_something_to_restate,
    require_timestamp_bounds,
    require_valid_epoch,
    require_verified_human,
)
from traust_ledger._internal.layer_finalize import finalize_layer, require_signing_configured
from traust_ledger._internal.restatements import LAYER_SCOPE_REF, merge_delta
from traust_ledger._internal.writer import LedgerWriter
from traust_ledger.config import ServiceConfig
from traust_ledger.errors import ServiceError, ValidationError
from traust_ledger.models import RestatementResponse
from traust_ledger.paths import layer_key

logger = logging.getLogger(__name__)


def apply_restatement(
    layer_id: str,
    block: dict,
    rationale: str,
    actor: LayerActor,
    recorded_at: str,
    writer: LedgerWriter,
    config: ServiceConfig,
) -> RestatementResponse:
    """Append one restatement event and apply its effect, atomically.

    Integrity and attribution rules only (a verified human authors it; the
    change is ticketed, real, fresh and monotonic): every one holds whoever
    calls. *Who may* restate is
    authorization, enforced at the REST boundary
    (``service.auth.authorize_restatement``) where the operator, not the
    caller, owns the admin list. In-process callers (CLI, ``LedgerClient``)
    have no such boundary — they own their environment and their storage — so
    a check here would be self-granted. What they get instead is the record:
    prior value, actor, ticket and rationale, inside the signed tree.
    """
    require_signing_configured(config)
    require_verified_human(actor, "restatement_actor")
    require_rationale_length(rationale)
    require_timestamp_bounds(recorded_at)
    require_restatement_authority(block)

    target = block.get("target")
    if target not in set(RestatementTarget):
        raise ValidationError(detail=f"unknown restatement target: {target!r}")

    finding_ref = block.get("finding_ref") or LAYER_SCOPE_REF
    block = {k: v for k, v in block.items() if k != "finding_ref"}
    event = build_restatement_event(
        block, rationale, actor, recorded_at, finding_ref=finding_ref
    ).to_dict()

    def _before_append(layer: dict) -> None:
        require_valid_epoch(layer)
        # All three under the layer lock, not against the caller's earlier read.
        actual = (layer.get("metadata") or {}).get(target)
        require_something_to_restate(block, actual)
        require_fresh_restatement(block, actual)
        require_monotonic_restatement(block, layer.get("events") or [])

    def _updates(layer: dict) -> dict:
        """The delta merged over what storage holds, computed under the lock."""
        current = (layer.get("metadata") or {}).get(target)
        return {target: merge_delta(current, block.get("after"))}

    event_id, merkle_root = writer.append_restatement(
        layer_key(writer.backend, config.data_dir, layer_id),
        event,
        _updates,
        lambda layer: finalize_layer(layer, config, layer_id=layer_id),
        _before_append,
    )
    logger.info(
        "restatement accepted layer_id=%s target=%s reason=%s identity=%s ticket=%s event_id=%s",
        layer_id,
        target,
        block.get("reason"),
        actor.identity,
        (block.get("authority") or {}).get("ticket"),
        event_id,
    )
    return RestatementResponse(
        event_id=event_id,
        layer_id=layer_id,
        target=str(target),
        merkle_root=merkle_root or None,
    )


#: Keys of a batch item that are routing/metadata rather than block content.
_ITEM_KEYS = ("layer", "layer_id", "rationale", "recorded_at")


def _split_item(item: dict) -> tuple[str, str, dict, str | None]:
    layer_id = item.get("layer") or item.get("layer_id")
    if not layer_id:
        raise ValidationError(detail="each batch item needs a 'layer'")
    rationale = item.get("rationale")
    if not rationale:
        raise ValidationError(detail=f"{layer_id}: each batch item needs a 'rationale'")
    block = {k: v for k, v in item.items() if k not in _ITEM_KEYS}
    return str(layer_id), str(rationale), block, item.get("recorded_at")


def apply_restatement_batch(
    items: list[dict],
    actor: LayerActor,
    writer: LedgerWriter,
    config: ServiceConfig,
) -> dict[str, list[dict]]:
    """Apply many restatements in order, reporting per item.

    Each item is gated on its own and each write is atomic on its own layer, so
    a refusal is recorded and the run continues rather than stranding the items
    behind it. There is nothing to roll back: no partial layer was written.

    Returns ``{"applied": [...], "failed": [{index, layer, error}]}``.
    """
    if not items:
        raise ValidationError(detail="a restatement batch needs at least one item")
    applied: list[dict] = []
    failed: list[dict] = []
    for index, item in enumerate(items):
        try:
            layer_id, rationale, block, recorded_at = _split_item(item)
            result = apply_restatement(
                layer_id,
                block,
                rationale,
                actor,
                recorded_at or datetime.now(UTC).isoformat(),
                writer,
                config,
            )
            applied.append(result.model_dump())
        except ServiceError as exc:
            failed.append(
                {
                    "index": index,
                    "layer": item.get("layer") or item.get("layer_id"),
                    "error": exc.detail,
                }
            )
        except (OSError, ValueError) as exc:
            failed.append(
                {
                    "index": index,
                    "layer": item.get("layer") or item.get("layer_id"),
                    "error": str(exc),
                }
            )
    logger.info(
        "restatement batch applied=%d failed=%d identity=%s",
        len(applied),
        len(failed),
        actor.identity,
    )
    return {"applied": applied, "failed": failed}


__all__ = ["apply_restatement", "apply_restatement_batch"]
