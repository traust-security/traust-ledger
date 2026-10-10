from __future__ import annotations

ROUTE_EVENTS = "/v1/ledger/events"
ROUTE_LAYERS = "/v1/ledger/layers/{layer_id}"
# Query-addressed twin of ROUTE_LAYERS: `?layer_id=` carries any opaque database ID,
# including `:` and `/`, which a single path segment cannot. Singular, so it never
# collides with the `GET /v1/ledger/layers` owner listing.
ROUTE_LAYER = "/v1/ledger/layer"
ROUTE_HEALTHZ = "/healthz"

STATUS_HEALTHY = "healthy"

__all__ = [
    "ROUTE_EVENTS",
    "ROUTE_HEALTHZ",
    "ROUTE_LAYER",
    "ROUTE_LAYERS",
    "STATUS_HEALTHY",
]
