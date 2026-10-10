from __future__ import annotations

import json
import logging

from traust_ledger._internal.layer_finalize import require_signing_configured
from traust_ledger._internal.writer import LedgerWriter
from traust_ledger.config import ServiceConfig
from traust_ledger.errors import NotFoundError, ValidationError
from traust_ledger.paths import layer_key
from traust_ledger.service.errors import LayerNotFoundError

logger = logging.getLogger(__name__)

_RESOLVED_DECISIONS = frozenset({"confirmed", "rejected"})


def _parse_item_key(key: str) -> tuple:
    """Deserialize a review-item key produced by `review_item_key`."""
    try:
        parsed = json.loads(key)
    except json.JSONDecodeError as exc:
        raise ValidationError(detail="key must be a JSON-encoded tuple") from exc
    if not isinstance(parsed, list) or len(parsed) != 4:
        raise ValidationError(detail="key must be a JSON array of four elements")
    return tuple(parsed)


parse_review_item_key = _parse_item_key


def resolve_review_item(
    layer_id: str,
    key: str,
    decision: str,
    note: str,
    writer: LedgerWriter,
    config: ServiceConfig,
) -> dict:
    """Close a needs_review item by key."""
    require_signing_configured(config)
    if decision not in _RESOLVED_DECISIONS:
        raise ValidationError(
            detail=f"decision must be one of {sorted(_RESOLVED_DECISIONS)}, got {decision!r}",
        )

    item_key = _parse_item_key(key)
    layer_path = layer_key(writer.backend, config.data_dir, layer_id)

    try:
        changed = writer.resolve_needs_review(
            layer_path,
            item_key,
            decision,
            resolution_note=note or None,
        )
    except FileNotFoundError as exc:
        raise LayerNotFoundError(layer_id=layer_id) from exc
    except ValueError as exc:
        raise ValidationError(detail=str(exc)) from exc

    if not changed:
        raise NotFoundError(detail="review item not found")

    logger.info(
        "review item resolved layer_id=%s decision=%s key=%s",
        layer_id,
        decision,
        key,
    )
    return {"resolved": True, "key": key}
