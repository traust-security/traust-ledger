"""Default disposition read model — resolved findings from ledger events.

Thin service-layer glue: loads layers via backend, delegates resolution
to traust_ledger.findings.resolve_layer_findings (the library function),
and wraps results in response models.
"""

from __future__ import annotations

from traust_ledger._internal.backends import Backend
from traust_ledger.api.findings import resolve_layer_findings as _resolve_layer_findings
from traust_ledger.config import ServiceConfig
from traust_ledger.handlers.layer_handler import load_layer
from traust_ledger.models import (
    BulkFindingsResponse,
    FindingsResponse,
    LayerFindings,
)


def _layer_merkle_meta(layer: dict) -> tuple[str | None, int | None]:
    meta = layer.get("metadata") or {}
    return meta.get("merkle_root"), meta.get("merkle_epoch")


def _layer_has_events_since(layer: dict, since_epoch: int) -> bool:
    """True if layer's merkle_epoch >= since_epoch (new events since that point)."""
    meta = layer.get("metadata") or {}
    epoch = meta.get("merkle_epoch")
    if epoch is None:
        return True
    return int(epoch) >= since_epoch


def resolve_findings(
    layer_id: str,
    backend: Backend,
    config: ServiceConfig,
) -> FindingsResponse:
    """Resolve current disposition per finding for a single layer."""
    layer = load_layer(layer_id, backend, config)
    findings, summary = _resolve_layer_findings(layer)
    return FindingsResponse(findings=findings, summary=summary)


def resolve_all_findings(
    backend: Backend,
    config: ServiceConfig,
    *,
    cursor: str | None = None,
    limit: int = 100,
    since_epoch: int | None = None,
) -> BulkFindingsResponse:
    """Resolve findings across layers with cursor-based pagination.

    Args:
        cursor: Resume after this layer_id (exclusive). None = start.
        limit: Max layers per page.
        since_epoch: Only include layers with merkle_epoch >= this value
                     (incremental delta — skip unchanged layers).
    """
    from traust_ledger.paths import layer_key

    all_ids = backend.list_layer_ids()

    if cursor:
        try:
            start = all_ids.index(cursor) + 1
        except ValueError:
            start = 0
        all_ids = all_ids[start:]

    layers: list[LayerFindings] = []
    total_findings = 0
    scanned = 0

    for layer_id in all_ids:
        if scanned >= limit:
            break

        layer = backend.load(layer_key(backend, config.data_dir, layer_id))

        if since_epoch is not None and not _layer_has_events_since(layer, since_epoch):
            continue

        findings, summary = _resolve_layer_findings(layer)
        merkle_root, merkle_epoch = _layer_merkle_meta(layer)
        total_findings += len(findings)
        layers.append(
            LayerFindings(
                layer_id=layer_id,
                merkle_root=merkle_root,
                merkle_epoch=merkle_epoch,
                findings=findings,
                summary=summary,
            )
        )
        scanned += 1

    has_more = scanned == limit and all_ids[scanned:] != []
    next_cursor = layers[-1].layer_id if has_more and layers else None

    return BulkFindingsResponse(
        layers=layers,
        total_findings=total_findings,
        next_cursor=next_cursor,
        has_more=has_more,
    )
