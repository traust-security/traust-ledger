"""Events sort by instant, not by timestamp text."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from traust_contracts.v1.models.layer import LayerEvent

from traust_ledger._internal.disposition import derive_disposition
from traust_ledger.errors import CorruptStoredEventError

FINDING = "FIND-001"
GENERATED_AT = "2026-02-01T00:00:00+00:00"


def _event(event_id: str, recorded_at: str, validity: str) -> dict:
    return {
        "event_id": event_id,
        "finding_ref": FINDING,
        "recorded_at": recorded_at,
        "rationale": "probe rationale long enough to be realistic",
        "source": {
            "type": "verification_report",
            "ref": "reports/r.json",
            "actor": {"kind": "machine", "identity": "probe", "identity_verified": True},
        },
        "disposition": {"validity": validity},
    }


def test_offset_stamps_compare_by_instant_not_text() -> None:
    """'09:00-04:00' is 13:00Z, so it is LATER than '10:00+00:00'."""
    events = [
        _event("evt-utc", "2026-01-20T10:00:00+00:00", "false_positive"),
        _event("evt-edt", "2026-01-20T09:00:00-04:00", "confirmed"),
    ]
    result = derive_disposition({"id": FINDING}, events, GENERATED_AT)
    assert result["events"] == ["evt-utc", "evt-edt"]
    assert result["validity"] == "confirmed"


def test_corrupt_recorded_at_names_the_event() -> None:
    """IsoTimestamp should make this unreachable, but validation is bypassable.

    model_construct skips validation and _coerce passes typed events through,
    so the guard must identify the event instead of surfacing a bare
    ValueError as an anonymous 500.
    """
    event = LayerEvent.model_validate(_event("evt-corrupt", GENERATED_AT, "confirmed"))
    event.__dict__["recorded_at"] = "banana"  # what model_construct would leave

    with pytest.raises(CorruptStoredEventError) as excinfo:
        derive_disposition({"id": FINDING}, [event], GENERATED_AT)

    detail = excinfo.value.detail
    assert "evt-corrupt" in detail
    assert "recorded_at" in detail
    assert "banana" in detail


def test_assignment_stays_validated() -> None:
    """validate_assignment keeps the contract binding after construction."""
    event = LayerEvent.model_validate(_event("evt-1", GENERATED_AT, "confirmed"))
    with pytest.raises(ValidationError):
        event.recorded_at = "banana"
