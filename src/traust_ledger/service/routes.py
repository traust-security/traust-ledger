from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Any, TypeVar

from fastapi import APIRouter, Depends, Query, Request
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger._internal.backends.errors import LayerNotInitializedError
from traust_ledger._internal.backends.validation import validate_layer
from traust_ledger._internal.writer import LedgerWriter
from traust_ledger.config import ServiceConfig
from traust_ledger.constants.domain import PRODUCT_REPO_ID_PATTERN
from traust_ledger.handlers.event_handler import submit_event
from traust_ledger.handlers.events_handler import query_layer_events
from traust_ledger.handlers.findings_handler import resolve_all_findings, resolve_findings
from traust_ledger.handlers.fingerprint_handler import compute_fingerprints
from traust_ledger.handlers.initialize_handler import initialize_layer
from traust_ledger.handlers.layer_handler import load_layer
from traust_ledger.handlers.resolve_handler import resolve_review_item
from traust_ledger.handlers.restatement_handler import apply_restatement
from traust_ledger.handlers.sign_handler import sign_layer
from traust_ledger.handlers.stamp_handler import stamp_event_identities
from traust_ledger.handlers.submit_handler import submit_batch
from traust_ledger.handlers.verify_handler import verify_layer
from traust_ledger.models import (
    BatchSubmitRequest,
    BulkFindingsResponse,
    EventEnvelope,
    EventsResponse,
    FindingsResponse,
    FingerprintRequest,
    FingerprintResponse,
    InitializeRequest,
    LayerListResponse,
    LayerRef,
    ResolveResponse,
    RestatementRequest,
    RestatementResponse,
    StampRequest,
    StampResponse,
    SubmitResponse,
    VerifyResponse,
)
from traust_ledger.paths import layer_key
from traust_ledger.service.auth import authorize_restatement, require_identity, resolve_actor
from traust_ledger.service.errors import LayerNotFoundError, ProductRepoLayerNotFoundError
from traust_ledger.service.models import ErrorDetail, HealthResponse, ResolveRequest
from traust_ledger.service.route_constants import (
    ROUTE_EVENTS,
    ROUTE_HEALTHZ,
    ROUTE_LAYER,
    ROUTE_LAYERS,
    STATUS_HEALTHY,
)

router = APIRouter()
F = TypeVar("F", bound=Callable[..., Any])


def _layer_route(method: str, suffix: str, **kwargs: Any) -> Callable[[F], F]:
    """Register one layer operation under both addressing styles.

    ``/v1/ledger/layers/{layer_id}<suffix>`` keeps existing clients working for IDs that
    fit one path segment; ``/v1/ledger/layer<suffix>?layer_id=`` carries any opaque
    database ID. The same handler serves both, so behaviour cannot drift.
    """

    def register(endpoint: F) -> F:
        for path in (ROUTE_LAYERS + suffix, ROUTE_LAYER + suffix):
            router.add_api_route(path, endpoint, methods=[method], **kwargs)
        return endpoint

    return register


def _config(request: Request) -> ServiceConfig:
    return request.app.state.config


def _writer(request: Request) -> LedgerWriter:
    return request.app.state.writer


@router.get(ROUTE_HEALTHZ)
async def healthz() -> HealthResponse:
    return HealthResponse(status=STATUS_HEALTHY)


@router.post(
    ROUTE_EVENTS,
    response_model=SubmitResponse,
    responses={
        401: {
            "model": ErrorDetail,
            "description": "Missing or invalid authentication credentials",
        },
        422: {
            "model": ErrorDetail,
            "description": (
                "Validation error: missing fields, short rationale, future timestamp, "
                "two-person violation, machine on human lane, or unverified identity"
            ),
        },
    },
)
async def post_event(
    envelope: EventEnvelope,
    request: Request,
    actor: Annotated[LayerActor, Depends(resolve_actor)],
) -> SubmitResponse:
    return submit_event(envelope, actor, _writer(request), _config(request))


@_layer_route(
    "POST",
    "/resolve",
    response_model=ResolveResponse,
    dependencies=[Depends(require_identity)],
    responses={
        401: {"model": ErrorDetail, "description": "Missing or invalid authentication credentials"},
        404: {"model": ErrorDetail, "description": "Layer or review item not found"},
        422: {"model": ErrorDetail, "description": "Invalid key, decision, or resolution rules"},
    },
)
async def resolve_review(
    layer_id: str,
    body: ResolveRequest,
    request: Request,
) -> ResolveResponse:
    result = resolve_review_item(
        layer_id,
        body.key,
        body.decision,
        body.note,
        _writer(request),
        _config(request),
    )
    return ResolveResponse(**result)


@_layer_route(
    "POST",
    "/restate",
    response_model=RestatementResponse,
    responses={
        401: {"model": ErrorDetail, "description": "Missing or invalid authentication credentials"},
        403: {"model": ErrorDetail, "description": "Caller is not a configured ledger admin"},
        422: {
            "model": ErrorDetail,
            "description": (
                "Invalid restatement: missing authority, no-op change, stale `before`, "
                "or a metadata change no restatement covers"
            ),
        },
    },
)
async def post_restatement(
    layer_id: str,
    body: RestatementRequest,
    request: Request,
    actor: Annotated[LayerActor, Depends(resolve_actor)],
) -> RestatementResponse:
    block = dict(body.restatement)
    authorize_restatement(actor, block, _config(request))
    if body.finding_ref:
        block["finding_ref"] = body.finding_ref
    return apply_restatement(
        layer_id,
        block,
        body.rationale,
        actor,
        body.recorded_at or datetime.now(UTC).isoformat(),
        _writer(request),
        _config(request),
    )


@router.post("/v1/ledger/layers/{layer_id}/initialize")
async def post_initialize_layer(
    layer_id: str,
    body: InitializeRequest,
    request: Request,
    actor: Annotated[LayerActor, Depends(resolve_actor)],
) -> dict[str, str]:
    return initialize_layer(
        layer_id,
        body.layer,
        actor,
        request.app.state.backend,
        _config(request),
        body.product_repo_id,
    )


@_layer_route(
    "GET",
    "",
    dependencies=[Depends(require_identity)],
    responses={
        401: {
            "model": ErrorDetail,
            "description": "Missing or invalid authentication credentials",
        },
        404: {
            "model": ErrorDetail,
            "description": "Layer not found",
        },
    },
)
async def get_layer(layer_id: str, request: Request) -> dict[str, object]:
    config = _config(request)
    return load_layer(layer_id, request.app.state.backend, config)


@_layer_route(
    "GET",
    "/verify",
    response_model=VerifyResponse,
    dependencies=[Depends(require_identity)],
    responses={
        401: {"model": ErrorDetail, "description": "Missing or invalid authentication credentials"},
        404: {"model": ErrorDetail, "description": "Layer not found"},
    },
)
async def verify_layer_endpoint(
    layer_id: str,
    request: Request,
    check_signatures: bool = False,
) -> VerifyResponse:
    config = _config(request)
    layer = load_layer(layer_id, request.app.state.backend, config)
    sig_check = check_signatures or config.signing_required
    result = verify_layer(layer, check_signatures=sig_check)
    return VerifyResponse(**result)


@_layer_route(
    "GET",
    "/findings",
    response_model=FindingsResponse,
    dependencies=[Depends(require_identity)],
    responses={
        401: {"model": ErrorDetail, "description": "Missing or invalid authentication credentials"},
        404: {"model": ErrorDetail, "description": "Layer not found"},
    },
)
async def get_findings(layer_id: str, request: Request) -> FindingsResponse:
    config = _config(request)
    return resolve_findings(layer_id, request.app.state.backend, config)


@_layer_route(
    "GET",
    "/cumulative",
    response_model=FindingsResponse,
    dependencies=[Depends(require_identity)],
    responses={
        401: {"model": ErrorDetail, "description": "Missing or invalid authentication credentials"},
        404: {"model": ErrorDetail, "description": "Layer not found"},
    },
    summary="Alias for /findings — baseline enrichment is a client concern",
)
async def get_cumulative(layer_id: str, request: Request) -> FindingsResponse:
    config = _config(request)
    return resolve_findings(layer_id, request.app.state.backend, config)


@_layer_route(
    "GET",
    "/events",
    response_model=EventsResponse,
    dependencies=[Depends(require_identity)],
    responses={
        401: {"model": ErrorDetail, "description": "Missing or invalid authentication credentials"},
        404: {"model": ErrorDetail, "description": "Layer not found"},
    },
)
async def get_layer_events(
    layer_id: str,
    request: Request,
    finding_ref: str | None = Query(None, description="Filter to a specific finding"),
    source_type: str | None = Query(None, description="Filter by source type"),
    limit: int = Query(100, ge=1, le=1000, description="Max events per page"),
    offset: int = Query(0, ge=0, description="Events to skip before returning results"),
) -> EventsResponse:
    config = _config(request)
    return query_layer_events(
        layer_id,
        request.app.state.backend,
        config,
        finding_ref=finding_ref,
        source_type=source_type,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/v1/ledger/findings",
    response_model=BulkFindingsResponse,
    dependencies=[Depends(require_identity)],
    responses={
        401: {
            "model": ErrorDetail,
            "description": "Missing or invalid authentication credentials",
        },
    },
)
async def get_all_findings(
    request: Request,
    cursor: str | None = Query(None, description="Resume after this layer_id"),
    limit: int = Query(100, ge=1, le=1000, description="Max layers per page"),
    since_epoch: int | None = Query(
        None, description="Only layers with merkle_epoch >= this value"
    ),
) -> BulkFindingsResponse:
    config = _config(request)
    return resolve_all_findings(
        request.app.state.backend,
        config,
        cursor=cursor,
        limit=limit,
        since_epoch=since_epoch,
    )


@_layer_route(
    "POST",
    "/submit",
    response_model=SubmitResponse,
    responses={
        401: {"model": ErrorDetail, "description": "Missing or invalid authentication credentials"},
        422: {"model": ErrorDetail, "description": "Validation error or identity rule violation"},
    },
)
async def post_submit(
    layer_id: str,
    body: BatchSubmitRequest,
    request: Request,
    actor: Annotated[LayerActor, Depends(resolve_actor)],
) -> SubmitResponse:
    return submit_batch(layer_id, body, actor, _writer(request), _config(request))


@router.post(
    "/v1/ledger/fingerprint",
    response_model=FingerprintResponse,
    dependencies=[Depends(require_identity)],
)
async def post_fingerprint(body: FingerprintRequest) -> FingerprintResponse:
    return compute_fingerprints(body)


@router.get(
    "/v1/ledger/layers",
    response_model=LayerListResponse,
    dependencies=[Depends(require_identity)],
    responses={
        401: {"model": ErrorDetail, "description": "Missing or invalid authentication credentials"},
        404: {"model": ErrorDetail, "description": "No layer belongs to the product_repo"},
    },
)
async def list_layers(
    request: Request,
    product_repo_id: str | None = Query(
        None, pattern=PRODUCT_REPO_ID_PATTERN, description="Only the layer of this product_repo"
    ),
) -> LayerListResponse:
    refs = request.app.state.backend.list_layer_refs(product_repo_id)
    if product_repo_id is not None and not refs:
        raise ProductRepoLayerNotFoundError(product_repo_id=product_repo_id)
    return LayerListResponse(
        layers=[LayerRef(layer_id=layer_id, product_repo_id=owner) for layer_id, owner in refs]
    )


@_layer_route(
    "POST",
    "/sign",
    dependencies=[Depends(require_identity)],
    responses={
        401: {"model": ErrorDetail, "description": "Missing or invalid authentication credentials"},
        404: {"model": ErrorDetail, "description": "Layer not found"},
        500: {"model": ErrorDetail, "description": "Signing failed"},
    },
)
async def sign_layer_endpoint(
    layer_id: str,
    request: Request,
    rekor: bool = Query(False, description="Upload signature to transparency log"),
) -> dict[str, object]:
    config = _config(request)
    backend = request.app.state.backend
    path = layer_key(backend, config.data_dir, layer_id)

    def sign(layer: dict) -> dict:
        validate_layer(layer)
        return sign_layer(layer, config, rekor=rekor)

    try:
        result = backend.mutate(path, sign)
    except LayerNotInitializedError as exc:
        raise LayerNotFoundError(layer_id=layer_id) from exc
    return {**result, "layer_id": layer_id}


@_layer_route(
    "POST",
    "/stamp",
    response_model=StampResponse,
    dependencies=[Depends(require_identity)],
    responses={
        401: {"model": ErrorDetail, "description": "Missing or invalid authentication credentials"},
        404: {"model": ErrorDetail, "description": "Layer not found"},
        500: {"model": ErrorDetail, "description": "Signing failed"},
    },
)
async def stamp_layer_endpoint(
    layer_id: str,
    body: StampRequest,
    request: Request,
) -> StampResponse:
    config = _config(request)
    backend = request.app.state.backend
    path = layer_key(backend, config.data_dir, layer_id)

    def stamp(layer: dict) -> dict:
        validate_layer(layer)
        return stamp_event_identities(layer, body.fingerprints, config, layer_id=layer_id)

    try:
        result = backend.mutate(path, stamp)
    except LayerNotInitializedError as exc:
        raise LayerNotFoundError(layer_id=layer_id) from exc
    return StampResponse(**result)


@router.get(
    "/v1/ledger/whoami",
    response_model=LayerActor,
    responses={
        401: {"model": ErrorDetail, "description": "Missing or invalid authentication credentials"},
    },
    summary="Return the token-verified actor for the caller",
)
async def whoami_endpoint(
    actor: Annotated[LayerActor, Depends(resolve_actor)],
) -> LayerActor:
    return actor
