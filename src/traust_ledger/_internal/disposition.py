"""Deterministic disposition merge engine.

Pure-function precedence engine over ledger events. No harness-specific
dependencies — only ``compute_claim_hash`` from traust-ledger's own events
module.

Merge rules:
  validity   — Evidence-class precedence: class 1 (execution-verified:
               validation_report, verification_report) > class 2 (human
               static) > class 3 (machine static). Latest wins within
               the deciding class.
  assurance  — Highest evidence class that has spoken on validity.
  resolution — verification_report > jira > everything else; latest
               wins within the highest populated tier.
  conflict   — Both 'confirmed' and 'false_positive' appear anywhere in
               the finding's events. Surfaced, never silently resolved.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from traust_contracts.v1.enums import (
    Assurance,
    DispositionResolution,
    SourceType,
    Validity,
)
from traust_contracts.v1.models.layer import LayerEvent

from traust_ledger.errors import CorruptStoredEventError

RESOLUTION_TIERS: dict[str, int] = {
    SourceType.VERIFICATION_REPORT: 0,
    "jira": 1,
}
DEFAULT_RESOLUTION_TIER = 2

EXEC_SOURCE_TYPES = frozenset({SourceType.VALIDATION_REPORT, SourceType.VERIFICATION_REPORT})


def _coerce(events: Sequence[LayerEvent | dict]) -> list[LayerEvent]:
    """Accept both typed models and raw dicts for backward compatibility."""
    return [e if isinstance(e, LayerEvent) else LayerEvent.model_validate(e) for e in events]


def is_actor_verified(actor: dict) -> bool:
    """True when an authn mechanism proved the actor's identity.

    Checks ``identity_verified`` first; falls back to ``ldap_verified``
    for events written before the identity model refactor.
    """
    iv = actor.get("identity_verified")
    if iv is not None:
        return bool(iv)
    return bool(actor.get("ldap_verified"))


def _actor_verified(event: LayerEvent) -> bool:
    a = event.source.actor
    if a.identity_verified is not None:
        return bool(a.identity_verified)
    return bool(a.ldap_verified)


def event_class(event: LayerEvent | dict) -> int:
    """1 = execution-verified, 2 = human static, 3 = machine static.

    E2/E3-graded events from execution sources are demoted to class 3.
    Ungraded events from execution sources keep class 1 (pre-0.179.0
    reports are grandfathered).
    """
    if isinstance(event, dict):
        event = LayerEvent.model_validate(event)
    if event.evidence_grade in ("E2", "E3"):
        return 3
    if event.source.actor.kind == "human":
        return 2
    if event.source.type in EXEC_SOURCE_TYPES:
        return 1
    return 3


def _event_dt(event: LayerEvent) -> datetime:
    """Sortable instant for an event.

    IsoTimestamp makes recorded_at RFC 3339, so this should never fail and no
    normalization is needed — aware datetimes compare by instant. It is still
    guarded because validation is reachable around: model_construct skips it,
    and _coerce passes already-typed events through unvalidated. Reaching the
    raise means an invariant broke, so it names the event rather than letting
    a bare ValueError surface as an anonymous 500.
    """
    try:
        return datetime.fromisoformat(event.recorded_at)
    except (TypeError, ValueError) as exc:
        raise CorruptStoredEventError(
            event_id=event.event_id, field="recorded_at", value=event.recorded_at
        ) from exc


def derive_disposition(
    finding: dict,
    events: Sequence[LayerEvent | dict],
    generated_at: str,
) -> dict:
    """Derive the current two-axis disposition for one finding.

    Returns a plain dict for backward compatibility with downstream callers.
    Use ``Disposition(**derive_disposition(...))`` for a typed result.
    """
    evts = sorted(_coerce(events), key=_event_dt)
    base_validity = finding.get("validation_status", "not_verified")

    validity_events = [e for e in evts if e.disposition.validity]
    exec_v = [e for e in validity_events if event_class(e) == 1]
    human_v = [e for e in validity_events if event_class(e) == 2]
    machine_v = [e for e in validity_events if event_class(e) == 3]

    fp_overridden = False
    fp_reassertion_blocked = False

    if human_v:
        class2_validity = human_v[-1].disposition.validity
    elif machine_v:
        last_e = machine_v[-1]
        last = last_e.disposition.validity
        if last == Validity.FALSE_POSITIVE and not last_e.auto_accept_tier:
            class2_validity = base_validity
        else:
            class2_validity = last
    else:
        class2_validity = base_validity

    exec_decisive = [e for e in exec_v if e.disposition.validity != Validity.FALSE_POSITIVE]
    if exec_decisive:
        proof = exec_decisive[-1]
        validity = proof.disposition.validity
        if validity == Validity.CONFIRMED:
            human_fp = [e for e in human_v if e.disposition.validity == Validity.FALSE_POSITIVE]
            if any(_event_dt(e) <= _event_dt(proof) for e in human_fp):
                fp_overridden = True
            post = [e for e in human_fp if _event_dt(e) > _event_dt(proof)]
            post_ids = {e.source.actor.identity for e in post if _actor_verified(e)}
            if len(post_ids) >= 2:
                validity = Validity.FALSE_POSITIVE
                fp_overridden = False
            elif post:
                fp_reassertion_blocked = True
    else:
        validity = class2_validity

    refuted_awaiting_signoff = (
        any(
            e.disposition.validity == Validity.FALSE_POSITIVE
            and e.source.actor.kind == "machine"
            and not e.auto_accept_tier
            for e in validity_events
        )
        and validity != Validity.FALSE_POSITIVE
        and not human_v
    )

    seen_validities = {e.disposition.validity for e in validity_events}
    if {Validity.CONFIRMED, Validity.FALSE_POSITIVE} <= seen_validities:
        refuted_awaiting_signoff = False

    if exec_v:
        assurance = Assurance.EXECUTION_PROVEN
    elif human_v:
        assurance = Assurance.HUMAN_REVIEWED
    elif machine_v:
        assurance = Assurance.MACHINE_VERIFIED
    else:
        assurance = Assurance.CLAIMED

    conflict = {Validity.CONFIRMED, Validity.FALSE_POSITIVE} <= seen_validities

    resolution_events = [e for e in evts if e.disposition.resolution]
    resolution: str = DispositionResolution.OPEN
    if resolution_events:
        best_tier = min(
            RESOLUTION_TIERS.get(e.source.type, DEFAULT_RESOLUTION_TIER) for e in resolution_events
        )
        tier_events = [
            e
            for e in resolution_events
            if RESOLUTION_TIERS.get(e.source.type, DEFAULT_RESOLUTION_TIER) == best_tier
        ]
        resolution = tier_events[-1].disposition.resolution

    severity_events = [e for e in evts if e.disposition.severity and event_class(e) == 2]

    result: dict = {
        "validity": validity,
        "resolution": resolution,
        "assurance": assurance,
        "last_updated": evts[-1].recorded_at if evts else generated_at,
        "events": [e.event_id for e in evts],
    }
    if severity_events:
        last_sev = severity_events[-1]
        result["severity_override"] = {
            "severity": last_sev.disposition.severity,
            "by": last_sev.source.actor.identity or "?",
            "at": last_sev.occurred_at or last_sev.recorded_at,
            **({"rationale": last_sev.rationale} if last_sev.rationale else {}),
        }
    if conflict:
        result["conflict"] = True
    if refuted_awaiting_signoff:
        result["refuted_awaiting_signoff"] = True
    if fp_overridden:
        result["fp_overridden"] = True
    if fp_reassertion_blocked:
        result["fp_reassertion_blocked"] = True
    return result
