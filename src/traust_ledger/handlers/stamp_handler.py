"""Stamp handler — the single event-identity backfill path for REST and client.

Both entry points converge here. Callers load + write the layer themselves
(via backend or Backend.mutate); this function owns the in-tree fingerprint
backfill + finalize (Merkle stamp + sign) only. Never overwrites an existing
fingerprint — identity is a historical observation.
"""

from __future__ import annotations

from traust_ledger._internal.events import attach_identity
from traust_ledger._internal.layer_finalize import finalize_layer
from traust_ledger.config import ServiceConfig


def stamp_event_identities(
    layer: dict,
    fingerprints: dict[str, str],
    config: ServiceConfig,
    *,
    layer_id: str,
) -> dict:
    """Backfill event fingerprints from *fingerprints* and finalize in-place.

    *fingerprints* maps finding_ref -> fingerprint (the harness is the sole
    producer). Returns the new Merkle root, the layer id, and the count stamped.
    """
    stamped = sum(1 for event in layer.get("events") or [] if attach_identity(event, fingerprints))
    merkle_root = finalize_layer(layer, config, layer_id=layer_id)
    return {"merkle_root": merkle_root, "layer_id": layer_id, "stamped": stamped}
