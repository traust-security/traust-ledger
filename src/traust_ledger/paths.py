from __future__ import annotations

import re
from pathlib import Path

from traust_ledger._internal.backends.keys import DbLayerKey, LayerKey
from traust_ledger.constants import (
    DB_LAYER_ID_MAX_LENGTH,
    DB_LAYER_ID_PATTERN,
    LAYER_FILE_SUFFIX,
    LAYER_ID_PATTERN,
)
from traust_ledger.service.errors import InvalidLayerIdError, MissingLayerIdError


def layer_file_path(data_dir: str, layer_id: str) -> Path:
    if not re.match(LAYER_ID_PATTERN, layer_id):
        raise ValueError(InvalidLayerIdError.message)
    return Path(data_dir) / f"{layer_id}{LAYER_FILE_SUFFIX}"


def layer_key(backend: object, data_dir: str, layer_id: str) -> LayerKey:
    """Resolve a domain layer ID to *backend*'s storage key, validated for that backend.

    Database backends (``opaque_layer_ids``) bind the ID verbatim; file backends map it to
    a confined filename under *data_dir*.
    """
    if not layer_id:
        raise MissingLayerIdError()
    if getattr(backend, "opaque_layer_ids", False):
        if len(layer_id) > DB_LAYER_ID_MAX_LENGTH or not re.match(DB_LAYER_ID_PATTERN, layer_id):
            raise InvalidLayerIdError()
        return DbLayerKey(layer_id)
    if not re.match(LAYER_ID_PATTERN, layer_id):
        raise InvalidLayerIdError()
    return layer_file_path(data_dir, layer_id)
