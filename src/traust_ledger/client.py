"""LedgerClient — in-process Python SDK for authenticated ledger operations.

Symmetric with CLI and REST API:
    CLI users    → `ledger sign`, `ledger query`, `ledger submit`
    HTTP users   → POST /layers/{id}/sign, GET /layers/{id}/findings
    Python users → LedgerClient(...).sign(), .query_findings(), .submit()

All three converge on the same handlers and backend abstraction.
Pure computation (fingerprint, verify_merkle) stays in traust_ledger.api — no client needed.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, TypeVar

from pydantic import BaseModel
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger._internal.backends import Backend, create_backend
from traust_ledger._internal.backends.constants import EMPTY_LAYER
from traust_ledger._internal.integrity.signing import SigningConfig
from traust_ledger._internal.layer_finalize import finalize_layer
from traust_ledger._internal.writer import LedgerWriter
from traust_ledger.auth.directory import (
    DirectoryRefusedError,
    EmployeeDirectory,
    apply_directory,
    load_directory,
)
from traust_ledger.auth.verifier import TokenVerifierPort
from traust_ledger.config import ServiceConfig
from traust_ledger.handlers.events_handler import query_layer_events
from traust_ledger.handlers.findings_handler import resolve_all_findings, resolve_findings
from traust_ledger.handlers.layer_handler import load_layer
from traust_ledger.handlers.resolve_handler import resolve_review_item
from traust_ledger.handlers.submit_handler import submit_batch
from traust_ledger.handlers.verify_handler import verify_layer
from traust_ledger.models import BatchSubmitRequest
from traust_ledger.paths import layer_file_path

T = TypeVar("T")

__all__ = ["LedgerClient", "LedgerError", "resolve_env_token"]


class LedgerError(Exception):
    """Raised when a ledger operation fails."""

    pass


def _decode_jwt_payload(token: str) -> dict[str, Any] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _service_config(
    *,
    backend_type: str,
    data_dir: str,
    database_url: str | None,
    signing_config: SigningConfig | None,
    signing_required: bool | None = None,
) -> ServiceConfig:
    kwargs: dict[str, object] = {
        "backend_type": backend_type,
        "data_dir": data_dir,
        "database_url": database_url,
    }
    if signing_required is not None:
        kwargs["signing_required"] = signing_required
    else:
        kwargs["signing_required"] = os.environ.get("LAAS_SIGNING_REQUIRED", "").lower() in (
            "true",
            "1",
            "yes",
        )
    if signing_config is not None:
        method = signing_config.method
        if method == "cosign":
            method = "keypair"
        elif method in ("sigstore-oidc", "identity"):
            method = "identity"
        kwargs["signing_method"] = method
        if signing_config.key_path:
            kwargs["signing_key_path"] = signing_config.key_path
        if signing_config.oidc_issuer:
            kwargs["oidc_issuer_url"] = signing_config.oidc_issuer
        if signing_config.oidc_client_id:
            kwargs["oidc_client_id"] = signing_config.oidc_client_id
    return ServiceConfig(**kwargs)


def resolve_env_token() -> str | None:
    """Resolve an identity token for SDK callers.

    `LAAS_TOKEN` first, then the same chain `ledger auth token` uses:
    ``LEDGER_TOKEN_PATH`` → ``LEDGER_TOKEN`` → stored credentials from
    ``ledger auth login`` → a locally-minted JWT when ``LEDGER_LOCAL_IDENTITY``
    is set.

    Before this existed the SDK read `LAAS_TOKEN` alone, so a developer who had
    run `ledger auth local` still could not append an event — the credential was
    on disk and the SDK refused to look. The chain lives in the CLI config
    module and is imported lazily so importing the SDK never drags the CLI in.
    """
    token = os.environ.get("LAAS_TOKEN")
    if token and token.strip():
        return token.strip()
    try:
        from traust_ledger.cli.identity.config import resolve_token
    except ImportError:  # pragma: no cover - CLI extra absent
        return None
    try:
        return resolve_token()
    except OSError:
        # The chain touches the filesystem: `config_dir()` mkdirs on every call and
        # the auto-mint writes a keypair. Where there is no writable HOME — a
        # container, a cron job, CI — that surfaced as
        # `OSError: Read-only file system: '/.config'` from what is merely a
        # *fallback*, naming neither the cause (no token) nor the fix. An
        # unreachable credential store is indistinguishable from an empty one, so
        # treat it as absent and let the caller raise the auth error it means.
        return None


def _resolve_identity(
    token: str | None,
    verifier: TokenVerifierPort | None,
) -> tuple[str, TokenVerifierPort | None]:
    """Resolve auth identity: explicit wins, then env chain.

    Verifier construction is best-effort — if ``resolve_auth()`` can pair
    a verifier it will; otherwise the token is accepted and verification
    is deferred to ``_actor()`` call time (same as passing an explicit
    token without a verifier).
    """
    if token is not None:
        if not token.strip():
            raise LedgerError("token is required")
        return token.strip(), verifier

    from traust_ledger.auth.config import AuthResolutionError, resolve_auth

    try:
        cred = resolve_auth()
        return cred.token, verifier or cred.verifier
    except AuthResolutionError:
        pass

    raw = os.environ.get("LAAS_TOKEN", "").strip()
    if raw:
        return raw, verifier

    raise LedgerError(
        "authentication required — set LAAS_TOKEN, or run "
        "`ledger auth login` / `ledger auth local --identity <you>`"
    )


def _resolve_backend(
    backend_type: str | None,
    data_dir: str | None,
    database_url: str | None,
    signing_config: SigningConfig | None,
    signing_required: bool | None = None,
) -> tuple[ServiceConfig, Backend]:
    """Resolve backend config: explicit wins, then env."""
    bt = backend_type or os.environ.get("LAAS_BACKEND_TYPE", "file")
    dd = data_dir or os.environ.get("LAAS_DATA_DIR", "/var/lib/laas/data")
    db = database_url or os.environ.get("LAAS_DATABASE_URL")

    config = _service_config(
        backend_type=bt,
        data_dir=dd,
        database_url=db,
        signing_config=signing_config,
        signing_required=signing_required,
    )
    backend_kwargs: dict[str, object] = {"data_dir": dd}
    if bt == "db":
        backend_kwargs["database_url"] = db or ""
    return config, create_backend(bt, **backend_kwargs)


class LedgerClient:
    """In-process Python SDK for authenticated ledger operations.

    Auth follows the standard SDK pattern: explicit wins, then env chain.

        # Explicit auth
        client = LedgerClient(token="ey...", verifier=my_verifier)

        # Env-resolved auth (LAAS_TOKEN → stored creds → auto-mint)
        client = LedgerClient()

        # Explicit backend, env-resolved auth
        client = LedgerClient(data_dir="/my/data")
    """

    def __init__(
        self,
        token: str | None = None,
        *,
        verifier: TokenVerifierPort | None = None,
        backend_type: str | None = None,
        data_dir: str | None = None,
        database_url: str | None = None,
        signing_config: SigningConfig | None = None,
        signing_required: bool | None = None,
        directory: EmployeeDirectory | bool | None = None,
    ) -> None:
        self._token, self._verifier = _resolve_identity(token, verifier)
        # Employee-directory cross-check (traust_ledger.auth.directory):
        # None → the deployment's LEDGER_DIRECTORY_COMMAND if set; False →
        # explicitly none; an object → that directory.
        if directory is None:
            self._directory = load_directory()
        elif directory is False:
            self._directory = None
        else:
            self._directory = directory
        resolved_signing = (
            signing_config if signing_config is not None else SigningConfig.from_env()
        )
        self._config, self._backend = _resolve_backend(
            backend_type,
            data_dir,
            database_url,
            resolved_signing,
            signing_required=signing_required,
        )
        self._writer = LedgerWriter(backend=self._backend)

    @classmethod
    def from_env(cls) -> LedgerClient:
        """Convenience alias — equivalent to ``LedgerClient()``."""
        return cls()

    def sign(self, layer_id: str, *, rekor: bool = False) -> dict[str, Any]:
        """Stamp Merkle metadata and sign a layer atomically.

        Uses ``Backend.mutate`` so the dict that hits storage is fully
        finalized (stamped + signed) or nothing changes.  Honors
        ``signing_required`` via ``finalize_layer`` — an unconfigured
        signer raises instead of silently writing unsigned.
        """
        from traust_ledger.errors import ServiceError

        path = layer_file_path(self._config.data_dir, layer_id)
        config = self._config

        def _finalize(layer: dict) -> str:
            return finalize_layer(layer, config, layer_id=layer_id)

        try:
            merkle_root = self._backend.mutate(path, _finalize)
        except ServiceError as exc:
            raise LedgerError(exc.detail) from exc
        return {"status": "signed", "merkle_root": merkle_root, "layer_id": layer_id}

    def patch_metadata(
        self,
        layer_id: str,
        updates: dict[str, Any],
    ) -> dict[str, Any]:
        """Merge *updates* into layer metadata and re-sign atomically.

        Uses ``Backend.mutate`` — one lock, one write.  The layer is
        stamped and signed inside the lock so no intermediate unsigned
        state reaches storage.
        """
        from traust_ledger.errors import ServiceError

        path = layer_file_path(self._config.data_dir, layer_id)
        config = self._config

        def _patch_and_finalize(layer: dict) -> str:
            meta = layer.setdefault("metadata", {})
            for key, value in updates.items():
                if isinstance(value, dict) and isinstance(meta.get(key), dict):
                    meta[key].update(value)
                else:
                    meta[key] = value
            meta["updated"] = datetime.now(UTC).isoformat(timespec="seconds")
            return finalize_layer(layer, config, layer_id=layer_id)

        try:
            merkle_root = self._backend.mutate(path, _patch_and_finalize)
        except ServiceError as exc:
            raise LedgerError(exc.detail) from exc
        return {"merkle_root": merkle_root, "layer_id": layer_id}

    def stamp_event_identities(
        self,
        layer_id: str,
        fingerprints: dict[str, str],
    ) -> dict[str, Any]:
        """Backfill event fingerprints from *fingerprints* and re-sign atomically.

        The counterpart to patch_metadata for the event layer: identity is
        stamped inside the Merkle tree, so the whole thing finalizes in one
        Backend.mutate — the caller never writes the layer itself. *fingerprints*
        maps finding_ref -> fingerprint (the harness is the sole producer). Never
        overwrites an existing fingerprint (identity is a historical
        observation). Returns the count stamped alongside the new root.
        """
        from traust_ledger.errors import ServiceError
        from traust_ledger.handlers.stamp_handler import (
            stamp_event_identities as _stamp,
        )

        path = layer_file_path(self._config.data_dir, layer_id)
        config = self._config

        def _stamp_and_finalize(layer: dict) -> dict[str, Any]:
            return _stamp(layer, fingerprints, config, layer_id=layer_id)

        try:
            return self._backend.mutate(path, _stamp_and_finalize)
        except ServiceError as exc:
            raise LedgerError(exc.detail) from exc

    def create(
        self,
        layer_id: str,
        *,
        shell: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Bootstrap an empty layer.  Unsigned — no events to root."""
        path = layer_file_path(self._config.data_dir, layer_id)
        base = shell if shell is not None else dict(EMPTY_LAYER)
        if "metadata" not in base:
            base["metadata"] = {}
        self._backend.store(path, base)
        return {"layer_id": layer_id}

    def store(self, layer_id: str, layer: dict[str, Any]) -> dict[str, Any]:
        """Persist a fully-materialized layer through the backend.

        For callers that build or mutate a whole layer in memory (e.g. the
        cumulative projection) and sign() separately. Unsigned on its own.
        """
        path = layer_file_path(self._config.data_dir, layer_id)
        self._backend.store(path, layer)
        return {"layer_id": layer_id}

    def verify(self, layer_id: str, *, check_signatures: bool = False) -> dict[str, Any]:
        layer = load_layer(layer_id, self._backend, self._config)
        sig_check = check_signatures or self._config.signing_required
        return self._invoke(verify_layer, layer, check_signatures=sig_check)

    def query_findings(self, layer_id: str) -> dict[str, Any]:
        return self._invoke(
            resolve_findings,
            layer_id,
            self._backend,
            self._config,
        )

    def query_all_findings(
        self,
        *,
        cursor: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        return self._invoke(
            resolve_all_findings,
            self._backend,
            self._config,
            cursor=cursor,
            limit=limit,
        )

    def query_events(
        self,
        layer_id: str,
        *,
        finding_ref: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        return self._invoke(
            query_layer_events,
            layer_id,
            self._backend,
            self._config,
            finding_ref=finding_ref,
            limit=limit,
            offset=offset,
        )

    def submit(
        self,
        layer_id: str,
        events: list[dict[str, Any]],
        *,
        needs_review: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        body = BatchSubmitRequest(
            source_ref=f"ledger-client:{layer_id}",
            recorded_at=datetime.now(UTC).isoformat(),
            events=events,
            needs_review=needs_review or [],
        )
        return self._invoke(
            submit_batch,
            layer_id,
            body,
            self._actor(),
            self._writer,
            self._config,
        )

    def resolve(self, layer_id: str, key: str, decision: str, note: str = "") -> dict[str, Any]:
        return self._invoke(
            resolve_review_item,
            layer_id,
            key,
            decision,
            note,
            self._writer,
            self._config,
        )

    def countersign(
        self,
        layer_id: str,
        finding_ref: str,
        *,
        rationale: str,
        recorded_at: str,
        decision: str | None = None,
        severity: str | None = None,
        actor: LayerActor | None = None,
    ) -> dict[str, Any]:
        """Record a human countersign/severity event through the gated handler.

        Runs the human-lane gates (two-person, verified-for-FP, rationale,
        timestamp) and finalizes atomically. Falls back to the token-verified
        caller when no actor is supplied.
        """
        from traust_ledger.handlers.event_handler import submit_event
        from traust_ledger.models import EventEnvelope

        event: dict[str, Any] = {
            "layer_id": layer_id,
            "finding_ref": finding_ref,
            "rationale": rationale,
            "recorded_at": recorded_at,
        }
        if severity is not None:
            event["severity"] = severity
            kind = "severity"
        else:
            event["decision"] = decision
            kind = "countersign"
        envelope = EventEnvelope(kind=kind, event=event)
        return self._invoke(
            submit_event, envelope, actor or self._actor(), self._writer, self._config
        )

    def list_layers(self) -> list[str]:
        return self._backend.list_layer_ids()

    def whoami(self) -> LayerActor:
        """Return the verified actor derived from the caller's token.

        The token is the authority for signer identity — callers that need
        to attribute a non-event write (e.g. an alias confirmation) resolve
        it here rather than asserting an identity of their own.
        """
        return self._actor()

    def actor(self) -> LayerActor:
        """The verified actor this client writes as: token verified, then the
        deployment's employee-directory cross-check applied (if configured).
        Raises LedgerError when either refuses."""
        return self._actor()

    def _actor(self) -> LayerActor:
        from traust_ledger.auth.config import AuthResolutionError, verifier_for_token
        from traust_ledger.auth.verifier import TokenVerificationError

        verifier = self._verifier
        if verifier is None:
            try:
                verifier = verifier_for_token(self._token)
            except AuthResolutionError as exc:
                raise LedgerError(str(exc)) from exc

        try:
            actor = verifier.verify(self._token)
        except TokenVerificationError as exc:
            raise LedgerError(f"token verification failed: {exc}") from exc
        try:
            return apply_directory(actor, self._directory)
        except DirectoryRefusedError as exc:
            raise LedgerError(exc.detail) from exc

    def _invoke(self, fn: Callable[..., T], *args: object, **kwargs: object) -> dict[str, Any]:
        from traust_ledger.errors import ServiceError

        try:
            result = fn(*args, **kwargs)
        except ServiceError as exc:
            raise LedgerError(exc.detail) from exc
        if isinstance(result, BaseModel):
            return result.model_dump()
        if isinstance(result, dict):
            return result
        raise TypeError(f"unexpected handler result type: {type(result)!r}")
