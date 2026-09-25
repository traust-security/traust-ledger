from __future__ import annotations

import logging
import re

from traust_contracts.v1.models.layer import LayerActor

from traust_ledger._internal.backends.errors import LayerStorageError
from traust_ledger._internal.errors import EventIdMismatchError as _InternalEventIdMismatchError
from traust_ledger._internal.event_fields import (
    client_actor,
    client_disposition,
    event_text,
)
from traust_ledger._internal.events import attach_identity
from traust_ledger._internal.events.builders import build_human_event, build_severity_event
from traust_ledger._internal.gates import (
    reject_machine_disposition,
    reject_machine_human_lane,
    require_human_identity,
    require_rationale_length,
    require_timestamp_bounds,
    require_two_person,
    require_valid_epoch,
    require_verified_for_false_positive,
)
from traust_ledger._internal.kinds import BIRTH_EVENT_KINDS, EventKind
from traust_ledger._internal.layer_finalize import finalize_layer, require_signing_configured
from traust_ledger._internal.submissions import submission_id_for_event
from traust_ledger._internal.writer import LedgerWriter
from traust_ledger.config import ServiceConfig
from traust_ledger.constants import (
    ALLOWED_DECISIONS,
    DECISION_FALSE_POSITIVE,
    DECISION_KEEP_OPEN,
    EVENT_KEY_ACTOR,
    EVENT_KEY_DECISION,
    EVENT_KEY_FINDING_FINGERPRINT,
    EVENT_KEY_FINDING_REF,
    EVENT_KEY_JUSTIFICATION,
    EVENT_KEY_LAYER_ID,
    EVENT_KEY_RATIONALE,
    EVENT_KEY_RECORDED_AT,
    EVENT_KEY_SEVERITY,
    EVENT_KEY_SOURCE,
    EVENT_KEY_VERDICT,
    LAYER_ID_PATTERN,
    STATUS_ACCEPTED,
    VERDICT_FALSE_POSITIVE,
    VERDICT_TRUE_POSITIVE,
)
from traust_ledger.models import EventEnvelope, SubmitResponse
from traust_ledger.paths import layer_file_path
from traust_ledger.service.errors import (
    DecisionVerdictConflictError,
    EventIdMismatchError,
    InvalidLayerIdError,
    MissingDecisionOrVerdictError,
    MissingFindingRefError,
    MissingLayerIdError,
    MissingRecordedAtEventError,
    MissingSeverityError,
    ServiceError,
    UnknownDecisionError,
    ValidationError,
)

logger = logging.getLogger(__name__)


def _finding_ref(event: dict[str, object]) -> str:
    ref = event_text(event, EVENT_KEY_FINDING_REF)
    if ref:
        return ref
    return event_text(event, EVENT_KEY_FINDING_FINGERPRINT)


def _decision_from_verdict(verdict: str) -> str:
    if verdict == VERDICT_FALSE_POSITIVE:
        return DECISION_FALSE_POSITIVE
    if verdict == VERDICT_TRUE_POSITIVE:
        return DECISION_KEEP_OPEN
    return verdict


def _resolve_decision(event: dict[str, object]) -> str:
    raw_decision = event_text(event, EVENT_KEY_DECISION)
    raw_verdict = event_text(event, EVENT_KEY_VERDICT)

    if raw_decision and raw_verdict:
        expected = _decision_from_verdict(raw_verdict)
        if raw_decision != expected:
            raise DecisionVerdictConflictError()

    if raw_decision:
        decision = raw_decision
    elif raw_verdict:
        decision = _decision_from_verdict(raw_verdict)
    else:
        raise MissingDecisionOrVerdictError()

    if decision not in ALLOWED_DECISIONS:
        raise UnknownDecisionError(decision=decision)

    return decision


def _rationale(event: dict[str, object]) -> str:
    text = event_text(event, EVENT_KEY_RATIONALE)
    if text:
        return text
    return event_text(event, EVENT_KEY_JUSTIFICATION)


def _require_recorded_at(event: dict[str, object]) -> str:
    value = event.get(EVENT_KEY_RECORDED_AT)
    if value is None or str(value).strip() == "":
        raise MissingRecordedAtEventError()
    return str(value)


def _require_layer_id(event: dict[str, object]) -> str:
    layer_id = event_text(event, EVENT_KEY_LAYER_ID)
    if not layer_id:
        raise MissingLayerIdError()
    if not re.match(LAYER_ID_PATTERN, layer_id):
        raise InvalidLayerIdError()
    return layer_id


def _require_finding_ref(event: dict[str, object]) -> str:
    ref = _finding_ref(event)
    if not ref:
        raise MissingFindingRefError()
    return ref


def _stamp_actor(actor: LayerActor) -> LayerActor:
    """Defensive copy of the resolved actor."""
    return actor.model_copy()


def _parse_event_kind(raw: str) -> EventKind:
    try:
        return EventKind(raw)
    except ValueError as exc:
        raise ValidationError(
            detail=f"unknown event kind: {raw}",
        ) from exc


def _stamp_actor_on_event(event: dict[str, object], actor: LayerActor) -> dict[str, object]:
    stamped = dict(event)
    source = stamped.get(EVENT_KEY_SOURCE)
    if isinstance(source, dict):
        stamped[EVENT_KEY_SOURCE] = {**source, EVENT_KEY_ACTOR: actor.to_dict()}
    return stamped


def _resolve_fingerprint_from_layer(event: dict, layer: dict[str, object]) -> None:
    """Resolve finding_ref → fingerprint from existing layer events.

    Human-lane events (countersign, severity) arrive with finding_ref only.
    If a prior event for the same finding already carries a fingerprint,
    copy it onto this event so provenance is recorded consistently.
    attach_identity is a no-op when the event already has a fingerprint.
    """
    existing = layer.get("events")
    if not isinstance(existing, list):
        return
    index = {
        e.get("finding_ref"): e.get("fingerprint")
        for e in existing
        if isinstance(e, dict) and e.get("finding_ref") and e.get("fingerprint")
    }
    if index:
        attach_identity(event, index)


def submit_event(
    envelope: EventEnvelope,
    actor: LayerActor,
    writer: LedgerWriter,
    config: ServiceConfig,
) -> SubmitResponse:
    require_signing_configured(config)
    event_kind = _parse_event_kind(envelope.kind)
    raw_event = envelope.event
    try:
        if event_kind not in BIRTH_EVENT_KINDS:
            reject_machine_disposition(client_actor(raw_event), client_disposition(raw_event))
        require_human_identity(actor, event_kind)
        reject_machine_human_lane(actor, event_kind)
        stamped = _stamp_actor(actor)
        logger.debug(
            "resolved actor kind=%s identity=%s verified=%s provider=%s",
            stamped.kind,
            stamped.identity,
            stamped.identity_verified,
            stamped.identity_provider,
        )
        if event_kind not in BIRTH_EVENT_KINDS:
            reject_machine_disposition(stamped.to_dict(), client_disposition(raw_event))

        layer_id = _require_layer_id(raw_event)
        finding_ref = _require_finding_ref(raw_event)
        rationale = _rationale(raw_event)
        recorded_at = _require_recorded_at(raw_event)
        require_rationale_length(rationale)
        require_timestamp_bounds(recorded_at)

        incoming_validity = ""
        if event_kind in BIRTH_EVENT_KINDS:
            event_payload = _stamp_actor_on_event(raw_event, stamped)
            event_payload.pop("layer_id", None)  # routing key is not part of layer.schema.json
        elif event_kind == EventKind.SEVERITY:
            level = event_text(raw_event, EVENT_KEY_SEVERITY)
            if not level:
                raise MissingSeverityError()
            built = build_severity_event(finding_ref, level, rationale, stamped, recorded_at)
            event_payload = built.to_dict()
            incoming_validity = built.disposition.validity or ""
        else:
            decision = _resolve_decision(raw_event)
            built = build_human_event(finding_ref, decision, rationale, stamped, recorded_at)
            if not built.disposition.validity:
                raise ValidationError(detail="event builder produced no validity")
            event_payload = built.to_dict()
            incoming_validity = built.disposition.validity or ""

        if incoming_validity:
            require_verified_for_false_positive(stamped, incoming_validity)

        layer_path = layer_file_path(config.data_dir, layer_id)

        def _before_append(layer: dict[str, object]) -> None:
            require_valid_epoch(layer)
            if event_kind == EventKind.COUNTERSIGN:
                require_two_person(layer, finding_ref, stamped.identity or "", incoming_validity)
            _resolve_fingerprint_from_layer(event_payload, layer)

        event_id, _merkle_root = writer.append_event_finalized(
            layer_path,
            event_payload,
            lambda layer: finalize_layer(layer, config),
            _before_append,
        )
    except _InternalEventIdMismatchError as exc:
        raise EventIdMismatchError(supplied=exc.supplied, canonical=exc.canonical) from exc
    except LayerStorageError as exc:
        raise ValidationError(detail=str(exc)) from exc
    except ServiceError as exc:
        gate = getattr(exc, "gate", None)
        if gate is None:
            raise
        actor_identity = getattr(exc, "actor_identity", None) or actor.identity or "<unknown>"
        logger.warning(
            "gate rejection gate=%s actor=%s reason=%s",
            gate,
            actor_identity,
            exc.detail,
        )
        raise
    submission_id = submission_id_for_event(envelope)
    resolved_id = event_id or submission_id
    logger.info(
        "event accepted kind=%s layer_id=%s identity=%s event_id=%s",
        event_kind.value,
        layer_id,
        stamped.identity,
        resolved_id,
    )
    return SubmitResponse(
        id=resolved_id,
        status=STATUS_ACCEPTED,
        event_count=1,
        merkle_root=_merkle_root or None,
    )
