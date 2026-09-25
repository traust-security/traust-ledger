from __future__ import annotations

import logging

from traust_ledger._internal.backends import Backend
from traust_ledger._internal.backends.constants import EMPTY_LAYER, LAYER_EVENTS_KEY
from traust_ledger._internal.backends.errors import InvalidLayerDocumentError
from traust_ledger._internal.backends.validation import validate_layer
from traust_ledger.config import ServiceConfig
from traust_ledger.errors import ValidationError
from traust_ledger.paths import layer_file_path
from traust_ledger.service.errors import LayerNotFoundError

logger = logging.getLogger(__name__)


def load_layer(layer_id: str, backend: Backend, config: ServiceConfig) -> dict[str, object]:
    path = layer_file_path(config.data_dir, layer_id)
    layer = backend.load(path)
    events = layer.get(LAYER_EVENTS_KEY)
    # Only the raw absent sentinel is missing. A valid initialized shell can
    # legitimately have zero events and zero queued items.
    if layer == EMPTY_LAYER:
        logger.warning("layer not found layer_id=%s", layer_id)
        raise LayerNotFoundError(layer_id=layer_id)
    try:
        validate_layer(layer)
    except InvalidLayerDocumentError as exc:
        raise ValidationError(detail=str(exc)) from exc
    event_count = len(events) if isinstance(events, list) else 0
    logger.debug("layer loaded layer_id=%s event_count=%d", layer_id, event_count)
    return layer
