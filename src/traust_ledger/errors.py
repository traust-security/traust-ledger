"""Domain errors — plain exceptions categorized by kind.

No framework dependencies. The REST layer maps error categories to HTTP status
codes; the CLI maps them to exit codes; the LedgerClient maps them to LedgerError.

Categories:
    ServiceError        — base (validation failures, 422-equivalent)
    AuthError           — authentication/authorization failures
    NotFoundError       — resource not found
    InternalError       — unexpected failures (signing, etc.)
"""

from __future__ import annotations

from typing import ClassVar


class ServiceError(Exception):
    """Base domain error. Represents a validation/business-rule failure."""

    message: ClassVar[str] = ""

    def __init__(self, **kwargs: object) -> None:
        detail = type(self).format_message(**kwargs)
        super().__init__(detail)
        self.detail = detail

    @classmethod
    def format_message(cls, **kwargs: object) -> str:
        if kwargs:
            return cls.message.format(**kwargs)
        return cls.message


class AuthError(ServiceError):
    """Authentication or authorization failure."""

    message = "authentication required"


class NotFoundError(ServiceError):
    """Requested resource does not exist."""

    message = "{detail}"


class InternalError(ServiceError):
    """Unexpected internal failure."""

    message = "{detail}"


class ValidationError(ServiceError):
    """Generic validation error."""

    message = "{detail}"


# ─── Specific domain errors ──────────────────────────────────────────────


class MissingAuthError(AuthError):
    message = "authentication required"


class InvalidAuthError(AuthError):
    message = "invalid credentials"


class InvalidKindError(ServiceError):
    message = "unknown report kind: {kind}"


class IdentityRequiredError(ServiceError):
    message = "human identity required for this event kind"


class IdentityUnverifiedError(ServiceError):
    message = "verified identity required for human false_positive"


class TwoPersonViolatedError(ServiceError):
    message = "two-person rule: same human cannot satisfy both signatures"


class MachineDispositionError(ServiceError):
    message = "machine actors cannot submit disposition events"


class RationaleTooShortError(ServiceError):
    message = "rationale must be at least {min_length} characters"


class TimestampFutureError(ServiceError):
    message = "recorded_at cannot be more than {hours}h in the future"


class InvalidEpochError(ServiceError):
    message = "metadata.merkle_epoch is invalid for the current events array"


class LayerNotFoundError(NotFoundError):
    message = "layer not found: {layer_id}"


class SigningRequiredError(ServiceError):
    message = (
        "signing is required but no signer is configured — "
        "set LAAS_SIGNING_KEY_PATH (keypair) or configure sigstore-oidc; "
        "nothing was written"
    )


class SigningFailedError(InternalError):
    message = (
        "signing failed for {layer_id} — set LAAS_SIGNING_KEY_PATH and "
        "COSIGN_PASSWORD (keypair), or configure sigstore-oidc; "
        "nothing was written (atomic rollback)"
    )

    def __init__(self, *, layer_id: str = "unknown", **kwargs: object) -> None:
        super().__init__(layer_id=layer_id, **kwargs)


class MissingLayerIdError(ServiceError):
    message = "layer_id is required"


class MissingSeverityError(ServiceError):
    message = "severity level is required for severity events"


class MissingDecisionOrVerdictError(ServiceError):
    message = "decision or verdict is required for countersign events"


class DecisionVerdictConflictError(ServiceError):
    message = "decision and verdict both present but disagree; provide one, not both"


class UnknownDecisionError(ServiceError):
    message = "unknown decision value: {decision}"


class MissingFindingRefError(ServiceError):
    message = "finding_ref (or finding_fingerprint) is required"


class MissingRecordedAtEventError(ServiceError):
    message = "recorded_at is required in event payload"


class InvalidLayerIdError(ServiceError):
    message = "layer_id contains invalid characters"


class CorruptStoredEventError(InternalError):
    """A stored event violates a contract invariant it should not be able to.

    Raised on read, so the message must identify the event: without it the
    failure is an anonymous 500 over a corpus of thousands of layers.
    """

    message = "event {event_id} has {field}={value!r}, which is not RFC 3339"


class EventIdMismatchError(ServiceError):
    message = "event_id mismatch: supplied '{supplied}' != canonical '{canonical}'"


__all__ = [
    "AuthError",
    "CorruptStoredEventError",
    "DecisionVerdictConflictError",
    "EventIdMismatchError",
    "IdentityRequiredError",
    "IdentityUnverifiedError",
    "InternalError",
    "InvalidAuthError",
    "InvalidEpochError",
    "InvalidKindError",
    "InvalidLayerIdError",
    "LayerNotFoundError",
    "MachineDispositionError",
    "MissingAuthError",
    "MissingDecisionOrVerdictError",
    "MissingFindingRefError",
    "MissingLayerIdError",
    "MissingRecordedAtEventError",
    "MissingSeverityError",
    "NotFoundError",
    "RationaleTooShortError",
    "ServiceError",
    "SigningFailedError",
    "SigningRequiredError",
    "TimestampFutureError",
    "TwoPersonViolatedError",
    "UnknownDecisionError",
    "ValidationError",
]
