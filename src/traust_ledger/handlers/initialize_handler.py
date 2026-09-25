"""OIDC-gated creation of a caller-authored complete layer shell."""

from __future__ import annotations

from traust_contracts.v1.models.layer import LayerActor

from traust_ledger._internal.backends import Backend
from traust_ledger._internal.backends.errors import LayerStorageError
from traust_ledger._internal.backends.validation import validate_layer
from traust_ledger.config import ServiceConfig
from traust_ledger.errors import ValidationError
from traust_ledger.paths import layer_file_path


def initialize_layer(
    layer_id: str, shell: dict, actor: LayerActor, backend: Backend, config: ServiceConfig
) -> dict[str, str]:
    """Create once; actor is verified at each transport boundary, never embedded in metadata."""
    del actor  # Authentication is mandatory; do not invent metadata.
    try:
        validate_layer(shell)
        if shell["events"] or shell["needs_review"]:
            raise ValidationError(
                detail="initialization requires empty events and needs_review; "
                "use administrative migration for historical evidence"
            )
        backend.initialize(layer_file_path(config.data_dir, layer_id), shell)
    except (LayerStorageError, ValueError) as exc:
        raise ValidationError(detail=str(exc)) from exc
    return {"layer_id": layer_id}
