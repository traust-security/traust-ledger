"""Three fixes found by pointing the materializer at a real findings tree.

Measured 2026-08-20 against `console__release-5.0/`: it reported four "layers",
three of which were the audit report, the triage report and a companion. Nothing
downstream could tell those from real, empty layers.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traust_ledger._internal.backends.file import FileBackend
from traust_ledger._internal.projection import ensure_schema, findings_table, upsert_layer
from traust_ledger.cli.materialize import _redact


def _row(layer_id: str, ref: str) -> dict:
    return {
        "layer_id": layer_id,
        "finding_ref": ref,
        "fingerprint": None,
        "orphan": False,
        "validity": "confirmed",
        "resolution": "open",
        "assurance": None,
        "event_count": 1,
        "conflict": False,
        "fp_overridden": False,
        "fp_reassertion_blocked": False,
        "severity_override": None,
        "last_updated": None,
        "merkle_root": None,
        "merkle_epoch": None,
        "materialized_at": None,
    }


# --- 1. only layers are layers ----------------------------------------------


def test_reports_in_the_directory_are_not_listed_as_layers(tmp_path):
    (tmp_path / "repo-security-audit.json").write_text(
        json.dumps({"title": "t", "metadata": {"date": "2026-08-20"}, "findings": []})
    )
    (tmp_path / "repo-triage.json").write_text(json.dumps({"findings": []}))
    from conftest import canonical_shell

    shell = canonical_shell()
    shell["metadata"]["audit_report"] = "repo-security-audit.json"
    (tmp_path / "repo-findings-layer.json").write_text(json.dumps(shell))

    assert FileBackend(tmp_path).list_layer_ids() == ["repo-findings-layer"]


def test_only_explicitly_initialized_empty_layer_counts(tmp_path, caplog):
    """An event-only file is raw legacy evidence, not a canonical layer."""
    from conftest import canonical_shell

    (tmp_path / "legacy.json").write_text(json.dumps({"events": []}))
    (tmp_path / "fresh.json").write_text(json.dumps(canonical_shell()))
    assert FileBackend(tmp_path).list_layer_ids() == ["fresh"]
    assert "skipping noncanonical layer" in caplog.text


def test_unparseable_json_is_skipped_not_raised(tmp_path):
    (tmp_path / "broken.json").write_text("{not json")
    from conftest import canonical_shell

    (tmp_path / "ok.json").write_text(json.dumps(canonical_shell()))
    assert FileBackend(tmp_path).list_layer_ids() == ["ok"]


# --- 2. an empty result must not erase the projection ------------------------


def test_zero_findings_leaves_existing_rows_alone():
    """An unreadable or skipped layer must not look like a deleted one."""
    engine = create_engine("sqlite://")
    ensure_schema(engine)
    with engine.begin() as c:
        upsert_layer(c, "L1", [_row("L1", "FIND-001"), _row("L1", "FIND-002")])
    with engine.begin() as c:
        upsert_layer(c, "L1", [])  # e.g. the layer failed to parse
    with engine.begin() as c:
        rows = c.execute(select(findings_table.c.finding_ref)).fetchall()
    assert {r[0] for r in rows} == {"FIND-001", "FIND-002"}


def test_prune_empty_is_available_when_deletion_is_meant():
    engine = create_engine("sqlite://")
    ensure_schema(engine)
    with engine.begin() as c:
        upsert_layer(c, "L1", [_row("L1", "FIND-001")])
    with engine.begin() as c:
        upsert_layer(c, "L1", [], prune_empty=True)
    with engine.begin() as c:
        assert c.execute(select(findings_table.c.finding_ref)).fetchall() == []


def test_a_non_empty_run_still_prunes_stale_refs():
    """The case that keeps the projection honest after a re-baseline."""
    engine = create_engine("sqlite://")
    ensure_schema(engine)
    with engine.begin() as c:
        upsert_layer(c, "L1", [_row("L1", "OLD-1"), _row("L1", "KEEP-1")])
    with engine.begin() as c:
        upsert_layer(c, "L1", [_row("L1", "KEEP-1")])
    with engine.begin() as c:
        rows = c.execute(select(findings_table.c.finding_ref)).fetchall()
    assert {r[0] for r in rows} == {"KEEP-1"}


# --- 3. credentials never echoed --------------------------------------------


@pytest.mark.parametrize(
    "url,expected",
    [
        ("postgresql://user:sekret@host/db", "postgresql://***:***@host/db"),
        ("sqlite:///findings.db", "sqlite:///findings.db"),
    ],
)
def test_redact_strips_credentials(url, expected):
    assert _redact(url) == expected


# --------------------------------------------------------------------------
# 6e — the projection carries identity, and an unknown stays unknown
# --------------------------------------------------------------------------


def _layer(events, claim_hashes=None):
    layer = {"events": events}
    if claim_hashes is not None:
        layer["metadata"] = {"claim_hashes": claim_hashes}
    return layer


def _ev(ref, fp=None, **over):
    e = {
        "event_id": "e" * 64,
        "finding_ref": ref,
        "recorded_at": "2026-08-25T00:00:00Z",
        "rationale": "quoted verbatim",
        "source": {"type": "triage_report", "ref": "r", "actor": {"kind": "machine"}},
        "disposition": {"validity": "confirmed"},
    }
    if fp:
        e["fingerprint"] = fp
    e.update(over)
    return e


def test_projection_row_carries_the_event_fingerprint():
    from traust_ledger.handlers.findings_handler import _resolve_layer_findings

    findings, _ = _resolve_layer_findings(_layer([_ev("FIND-001", "a" * 64)]))
    assert findings[0].fingerprint == "a" * 64


def test_newest_stamp_wins():
    """Identity is a historical observation; the current answer is the latest."""
    from traust_ledger.handlers.findings_handler import _resolve_layer_findings

    findings, _ = _resolve_layer_findings(
        _layer([_ev("FIND-001", "a" * 64), _ev("FIND-001", "b" * 64)])
    )
    assert findings[0].fingerprint == "b" * 64


def test_unstamped_events_leave_the_column_null_not_empty():
    from traust_ledger.handlers.findings_handler import _resolve_layer_findings

    findings, _ = _resolve_layer_findings(_layer([_ev("FIND-001")]))
    assert findings[0].fingerprint is None


def test_orphan_is_true_when_no_baseline_holds_the_ref():
    from traust_ledger.handlers.findings_handler import _resolve_layer_findings

    findings, _ = _resolve_layer_findings(
        _layer([_ev("FIND-001"), _ev("FIND-404")], claim_hashes={"FIND-001": "h"})
    )
    by_ref = {f.finding_ref: f for f in findings}
    assert by_ref["FIND-001"].orphan is False
    assert by_ref["FIND-404"].orphan is True


def test_orphan_is_unknown_without_claim_hashes():
    """A layer that never pinned claims cannot answer; False would be an assertion."""
    from traust_ledger.handlers.findings_handler import _resolve_layer_findings

    findings, _ = _resolve_layer_findings(_layer([_ev("FIND-001")]))
    assert findings[0].orphan is None


def test_build_row_passes_both_through():
    from datetime import UTC, datetime

    from traust_ledger._internal.projection import build_row
    from traust_ledger.handlers.findings_handler import _resolve_layer_findings

    findings, _ = _resolve_layer_findings(
        _layer([_ev("FIND-001", "c" * 64)], claim_hashes={"FIND-001": "h"})
    )
    row = build_row("layer-1", findings[0], None, None, datetime.now(UTC))
    assert row["fingerprint"] == "c" * 64
    assert row["orphan"] is False
