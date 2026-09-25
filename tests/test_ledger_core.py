"""Tests for traust_ledger package."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from traust_ledger._internal import events
from traust_ledger._internal.writer import LedgerWriter

# The golden-vector replay that lived here read the suite from the installed
# traust-contracts package. Under plan decision D7 only the harness computes
# identity, so that cross-language oracle has no port left to hold; the 12 cases
# were ported into tests/fixtures/identity-recipe-vectors.json and are replayed by
# tests/test_identity_recipe_vectors.py, in this repo, versioned with the code they
# guard. Removed here on 2026-08-18 rather than left pointing at a file scheduled
# for deletion.


def _valid_event(event: dict) -> dict:
    source = event["source"]
    kind = source["actor"]["kind"]
    return {
        **event,
        "source": {"type": "interactive" if kind == "human" else "triage_report", **source},
        "recorded_at": "2026-09-22T12:00:00Z",
        "rationale": "Reviewed and confirmed this finding against source.",
    }


class TestLedgerWriterIdempotency:
    """Test LedgerWriter idempotency."""

    def test_append_same_event_twice(self):
        """Appending the same event twice results in one copy."""
        with tempfile.TemporaryDirectory() as tmpdir:
            layer_path = Path(tmpdir) / "layer.json"
            writer = LedgerWriter()
            from conftest import canonical_shell

            writer.backend.initialize(layer_path, canonical_shell())

            event = {
                "source": {"ref": "test", "actor": {"kind": "machine"}},
                "finding_ref": "TEST-123-001",
                "disposition": {"validity": "confirmed", "resolution": "open"},
            }

            id1 = writer.append_event(layer_path, _valid_event(event.copy()))
            id2 = writer.append_event(layer_path, _valid_event(event.copy()))

            assert id1 == id2

            layer = json.loads(layer_path.read_text())
            assert len(layer["events"]) == 1
            assert layer["events"][0]["event_id"] == id1

    def test_append_grows_events_only(self):
        """Append operations always grow the events array."""
        with tempfile.TemporaryDirectory() as tmpdir:
            layer_path = Path(tmpdir) / "layer.json"
            writer = LedgerWriter()
            from conftest import canonical_shell

            writer.backend.initialize(layer_path, canonical_shell())

            event1 = {
                "source": {"ref": "test1", "actor": {"kind": "machine"}},
                "finding_ref": "TEST-123-001",
                "disposition": {"validity": "confirmed", "resolution": "open"},
            }

            writer.append_event(layer_path, _valid_event(event1))
            layer = json.loads(layer_path.read_text())
            assert len(layer["events"]) == 1

            event2 = {
                "source": {"ref": "test2", "actor": {"kind": "machine"}},
                "finding_ref": "TEST-123-002",
                "disposition": {"validity": "confirmed", "resolution": "open"},
            }

            writer.append_event(layer_path, _valid_event(event2))
            layer_reloaded = json.loads(layer_path.read_text())
            assert len(layer_reloaded["events"]) == 2


class TestLedgerWriterLDAPRule:
    """Test human false_positive LDAP verification rule."""

    def test_human_false_positive_requires_verified_identity(self):
        """Human false_positive without verified identity raises."""
        with tempfile.TemporaryDirectory() as tmpdir:
            layer_path = Path(tmpdir) / "layer.json"
            writer = LedgerWriter()
            from conftest import canonical_shell

            writer.backend.initialize(layer_path, canonical_shell())

            event = {
                "source": {
                    "ref": "test",
                    "actor": {
                        "kind": "human",
                        "identity": "user@example.com",
                        "identity_verified": False,
                    },
                },
                "finding_ref": "TEST-123-001",
                "disposition": {"validity": "false_positive", "resolution": "open"},
            }

            with pytest.raises(Exception, match="verified identity"):
                writer.append_event(layer_path, _valid_event(event))

    def test_human_false_positive_with_verified_identity_succeeds(self):
        """Human false_positive with verified identity succeeds."""
        with tempfile.TemporaryDirectory() as tmpdir:
            layer_path = Path(tmpdir) / "layer.json"
            writer = LedgerWriter()
            from conftest import canonical_shell

            writer.backend.initialize(layer_path, canonical_shell())

            event = {
                "source": {
                    "ref": "test",
                    "actor": {
                        "kind": "human",
                        "identity": "user@example.com",
                        "identity_verified": True,
                    },
                },
                "finding_ref": "TEST-123-001",
                "disposition": {"validity": "false_positive", "resolution": "open"},
            }

            event_id = writer.append_event(layer_path, _valid_event(event))
            assert event_id

            layer = json.loads(layer_path.read_text())
            assert len(layer["events"]) == 1

    def test_human_false_positive_legacy_ldap_verified_succeeds(self):
        """Human false_positive with legacy ldap_verified=True succeeds (backward compat)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            layer_path = Path(tmpdir) / "layer.json"
            writer = LedgerWriter()
            from conftest import canonical_shell

            writer.backend.initialize(layer_path, canonical_shell())

            event = {
                "source": {
                    "ref": "test",
                    "actor": {
                        "kind": "human",
                        "identity": "user@example.com",
                        "ldap_verified": True,
                    },
                },
                "finding_ref": "TEST-123-001",
                "disposition": {"validity": "false_positive", "resolution": "open"},
            }

            event_id = writer.append_event(layer_path, _valid_event(event))
            assert event_id

    def test_machine_false_positive_no_ldap_required(self):
        """Machine-generated false_positive does not require LDAP."""
        with tempfile.TemporaryDirectory() as tmpdir:
            layer_path = Path(tmpdir) / "layer.json"
            writer = LedgerWriter()
            from conftest import canonical_shell

            writer.backend.initialize(layer_path, canonical_shell())

            event = {
                "source": {"ref": "test", "actor": {"kind": "machine"}},
                "finding_ref": "TEST-123-001",
                "disposition": {"validity": "false_positive", "resolution": "open"},
            }

            event_id = writer.append_event(layer_path, _valid_event(event))
            assert event_id

            layer = json.loads(layer_path.read_text())
            assert len(layer["events"]) == 1


class TestEventIdComputation:
    """Test canonical event_id computation."""

    def test_event_id_deterministic(self):
        """Same inputs produce same event_id."""
        id1 = events.compute_event_id("source1", "finding1", "confirmed", "open")
        id2 = events.compute_event_id("source1", "finding1", "confirmed", "open")
        assert id1 == id2

    def test_event_id_different_on_validity(self):
        """Different validity produces different event_id."""
        id1 = events.compute_event_id("source1", "finding1", "confirmed", "open")
        id2 = events.compute_event_id("source1", "finding1", "false_positive", "open")
        assert id1 != id2
