"""Tamper and epoch edge cases for verify_merkle_integrity."""

from __future__ import annotations

import copy

import pytest

from traust_ledger.integrity import (
    Severity,
    stamp_merkle_metadata,
    verify_merkle_integrity,
)


def _event(n: int = 1, **extra: object) -> dict:
    base = {
        "event_id": f"E-{n:03d}",
        "finding_ref": f"FIND-{n:03d}",
        "disposition": {"validity": "confirmed"},
        "rationale": f"event {n} rationale content",
        "recorded_at": "2026-08-14T00:00:00Z",
        "source": {"ref": "test", "actor": {"kind": "machine", "identity": "harness/1.0"}},
    }
    base.update(extra)
    return base


def _stamped_layer(events: list[dict], *, epoch: int = 0) -> dict:
    layer = {"metadata": {"merkle_epoch": epoch}, "events": events}
    stamp_merkle_metadata(layer)
    return layer


def _error_messages(layer: dict) -> list[str]:
    return [f.message for f in verify_merkle_integrity(layer) if f.severity == Severity.ERROR]


class TestEpochBounds:
    def test_negative_epoch_is_error(self) -> None:
        layer = _stamped_layer([_event()])
        layer["metadata"]["merkle_epoch"] = -1
        assert any("negative" in msg for msg in _error_messages(layer))

    def test_epoch_exceeds_event_count_is_error(self) -> None:
        layer = _stamped_layer([_event(1), _event(2)])
        layer["metadata"]["merkle_epoch"] = 3
        assert any("exceeds event count" in msg for msg in _error_messages(layer))

    def test_epoch_equals_event_count_is_error(self) -> None:
        events = [_event(1), _event(2)]
        layer = _stamped_layer(events)
        layer["metadata"]["merkle_epoch"] = len(events)
        assert any("covers no events" in msg for msg in _error_messages(layer))


class TestRootAndSizeMismatch:
    def test_tampered_root_detected(self) -> None:
        layer = _stamped_layer([_event(1), _event(2)])
        layer["metadata"]["merkle_root"] = "0" * 64
        assert any("merkle_root mismatch" in msg for msg in _error_messages(layer))

    def test_wrong_merkle_size_detected(self) -> None:
        layer = _stamped_layer([_event(1), _event(2)])
        layer["metadata"]["merkle_size"] = 99
        assert any("merkle_size mismatch" in msg for msg in _error_messages(layer))

    def test_tampered_event_content_detected(self) -> None:
        layer = _stamped_layer([_event(1), _event(2)])
        layer["events"][0]["rationale"] = "tampered after stamp"
        assert any("merkle_root mismatch" in msg for msg in _error_messages(layer))


class TestPreEpochCheckpoint:
    def test_missing_checkpoint_at_positive_epoch(self) -> None:
        events = [_event(1), _event(2), _event(3)]
        layer = _stamped_layer(events, epoch=1)
        del layer["metadata"]["pre_merkle_checkpoint"]
        messages = _error_messages(layer)
        assert any("pre_merkle_checkpoint" in msg and "absent" in msg for msg in messages)

    def test_stale_checkpoint_detected(self) -> None:
        events = [_event(1), _event(2), _event(3)]
        layer = _stamped_layer(events, epoch=1)
        layer["metadata"]["pre_merkle_checkpoint"] = "0" * 64
        assert any("checkpoint mismatch" in msg for msg in _error_messages(layer))

    def test_checkpoint_at_epoch_zero_must_match_empty_pre_epoch(self) -> None:
        layer = _stamped_layer([_event()])
        layer["metadata"]["pre_merkle_checkpoint"] = "deadbeef" * 8
        msgs = _error_messages(layer)
        assert any("merkle_epoch 0" in msg for msg in msgs)

    def test_positive_epoch_still_verifies_when_intact(self) -> None:
        layer = _stamped_layer([_event(1), _event(2), _event(3)], epoch=1)
        assert verify_merkle_integrity(layer) == []


class TestEpochType:
    @pytest.mark.parametrize("bad_epoch", [None, "x"])
    def test_non_numeric_epoch_is_error(self, bad_epoch: object) -> None:
        layer = _stamped_layer([_event()])
        layer["metadata"]["merkle_epoch"] = bad_epoch
        assert any("merkle_epoch" in msg for msg in _error_messages(layer))


class TestLeafFormat:
    @pytest.mark.parametrize("bad_format", ["nope", 99, None])
    def test_unknown_leaf_format_is_error(self, bad_format: object) -> None:
        layer = _stamped_layer([_event()])
        layer["metadata"]["leaf_format"] = bad_format
        assert any("not a known Merkle leaf format" in msg for msg in _error_messages(layer))

    def test_restamped_copy_still_verifies(self) -> None:
        layer = _stamped_layer([_event(1), _event(2)])
        clone = copy.deepcopy(layer)
        assert verify_merkle_integrity(clone) == []
