#!/usr/bin/env python3
"""Enforcement severities in verify_merkle_integrity (plan P6).

Both cases below were WARNING until 2026-08-14 and had no test asserting
either severity, so the anti-pattern the plan describes — a check that
exists but does not enforce — could have been reintroduced silently. These
tests pin the severity, not just the message.
"""

from __future__ import annotations

from traust_ledger.integrity import (
    Severity,
    stamp_merkle_metadata,
    verify_merkle_integrity,
)


def _event(n: int = 1) -> dict:
    return {
        "event_id": f"E-{n:03d}",
        "disposition": "confirmed",
        "actor": "tester",
        "timestamp": "2026-08-14T00:00:00Z",
    }


class TestMissingRootIsAnError:
    """P6 flip 1 — a layer with no root has no tamper-evidence at all."""

    def test_absent_merkle_root_is_error(self) -> None:
        layer = {"metadata": {}, "events": [_event()]}
        findings = verify_merkle_integrity(layer)
        assert len(findings) == 1
        assert findings[0].severity == Severity.ERROR
        assert "merkle_root absent" in findings[0].message

    def test_absent_root_is_error_on_an_empty_layer_too(self) -> None:
        # 135 of the 143 layers the 2026-08-14 sweep stamped were zero-event.
        # An empty layer still gets an empty-tree root, so "no events" is not
        # an excuse for "no root".
        layer = {"metadata": {}, "events": []}
        findings = verify_merkle_integrity(layer)
        assert [f.severity for f in findings] == [Severity.ERROR]

    def test_stamping_clears_the_error(self) -> None:
        layer = {"metadata": {}, "events": [_event()]}
        stamp_merkle_metadata(layer)
        assert verify_merkle_integrity(layer) == []


class TestLegacyLeafFormatIsAnError:
    """P6 flip 2 — leaf_format 1 binds event_ids only, not event content."""

    def _legacy_layer(self) -> dict:
        layer = {"metadata": {}, "events": [_event(1), _event(2)]}
        stamp_merkle_metadata(layer)
        # Re-root under the legacy binding so the root stays self-consistent
        # and leaf_format is the only thing under test.
        from traust_ledger.integrity.merkle import compute_merkle_root

        root, size = compute_merkle_root(layer["events"], leaf_format=1)
        layer["metadata"]["merkle_root"] = root
        layer["metadata"]["merkle_size"] = size
        layer["metadata"]["leaf_format"] = 1
        return layer

    def test_leaf_format_1_is_error(self) -> None:
        findings = verify_merkle_integrity(self._legacy_layer())
        errs = [f for f in findings if f.severity == Severity.ERROR]
        assert errs, "leaf_format 1 must be an error, not a warning"
        assert any("LEGACY MERKLE LEAF FORMAT" in f.message for f in errs)

    def test_absent_leaf_format_is_treated_as_legacy(self) -> None:
        # 8 layers in the corpus had a valid root but no leaf_format key.
        # meta.get("leaf_format", 1) defaults them to the legacy binding,
        # so they must error rather than pass silently.
        layer = self._legacy_layer()
        del layer["metadata"]["leaf_format"]
        findings = verify_merkle_integrity(layer)
        assert any(
            f.severity == Severity.ERROR and "LEGACY MERKLE LEAF FORMAT" in f.message
            for f in findings
        )

    def test_restamping_upgrades_to_format_2_and_clears_it(self) -> None:
        layer = self._legacy_layer()
        stamp_merkle_metadata(layer)
        assert layer["metadata"]["leaf_format"] == 2
        assert verify_merkle_integrity(layer) == []
