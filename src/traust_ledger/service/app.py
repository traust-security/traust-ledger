from __future__ import annotations

import logging

from fastapi import FastAPI

from traust_ledger._internal.backends import create_backend
from traust_ledger._internal.backends.constants import BACKEND_TYPE_DB
from traust_ledger._internal.backends.errors import LayerStorageError
from traust_ledger._internal.writer import LedgerWriter
from traust_ledger.config import ServiceConfig
from traust_ledger.service.errors import SigningRequiredError
from traust_ledger.service.identity import ActorResolver
from traust_ledger.service.identity.ports import IdentityPort
from traust_ledger.service.identity.registry import build_provider
from traust_ledger.service.logging import configure_logging
from traust_ledger.service.routes import router
from traust_ledger.service.settings import ServiceSettings

logger = logging.getLogger(__name__)


def _validate_config(config: ServiceConfig) -> None:
    if (
        config.signing_required
        and not config.signing_key_path
        and config.signing_method not in ("sigstore-oidc", "identity")
    ):
        raise RuntimeError(SigningRequiredError.message)


def _build_resolver(
    config: ServiceConfig,
    verifier: IdentityPort | None = None,
    *,
    skip_provider: bool = False,
) -> ActorResolver:
    if verifier:
        provider = verifier
    elif skip_provider:
        provider = _NoopVerifier()
    else:
        provider = build_provider(config)
    from traust_ledger.auth.directory import load_directory

    return ActorResolver(provider, load_directory())


class _NoopVerifier:
    """Placeholder verifier for spec-generation mode (validate_config=False)."""

    def verify(self, request):
        from traust_ledger.service.errors import MissingAuthError

        raise MissingAuthError()

    @classmethod
    def from_config(cls, config):
        return cls()


def create_app(
    config: ServiceConfig | None = None,
    *,
    verifier: IdentityPort | None = None,
    validate_config: bool = True,
) -> FastAPI:
    resolved = config or ServiceSettings()
    configure_logging(resolved.log_level)
    if validate_config:
        _validate_config(resolved)
    backend_kwargs: dict[str, object] = {"data_dir": resolved.data_dir}
    if resolved.backend_type == BACKEND_TYPE_DB:
        backend_kwargs["database_url"] = resolved.database_url
    backend = create_backend(resolved.backend_type, **backend_kwargs)
    writer = LedgerWriter(backend=backend)
    resolver = _build_resolver(
        resolved, verifier, skip_provider=not validate_config and verifier is None
    )
    app = FastAPI(title="Ledger-as-a-Service", version="0.1.0")
    app.state.config = resolved
    app.state.writer = writer
    app.state.backend = backend
    app.state.resolver = resolver
    app.include_router(router)

    from fastapi.requests import Request
    from fastapi.responses import JSONResponse

    from traust_ledger.errors import AuthError, InternalError, NotFoundError, ServiceError

    @app.exception_handler(LayerStorageError)
    async def _storage_error(request: Request, exc: LayerStorageError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(ServiceError)
    async def _service_error_handler(request: Request, exc: ServiceError) -> JSONResponse:
        if isinstance(exc, AuthError):
            status_code = 401
            headers = {"WWW-Authenticate": "Bearer"}
        elif isinstance(exc, NotFoundError):
            status_code = 404
            headers = None
        elif isinstance(exc, InternalError):
            status_code = 500
            headers = None
        else:
            status_code = 422
            headers = None
        return JSONResponse(
            status_code=status_code,
            content={"detail": exc.detail},
            headers=headers,
        )

    logger.info(
        "app startup backend_type=%s signing_required=%s log_level=%s",
        resolved.backend_type,
        resolved.signing_required,
        resolved.log_level,
    )
    return app
