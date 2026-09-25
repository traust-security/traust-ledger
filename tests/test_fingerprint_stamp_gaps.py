"""Tests for fingerprint/algo stamping gaps across all write paths.

These tests verify that fingerprint_algo is stamped uniformly, regardless
of whether an event enters via:
  - POST /submit (batch)        — already worked
  - POST /events (countersign)  — gap 1: human-built events had no stamp
  - POST /events (birth event)  — gap 2: passthrough events had no stamp
  - CLI ledger submit            — gap 3: CLI bypass skipped stamp entirely
"""

from __future__ import annotations

import json
from pathlib import Path

from conftest import AUTH_HEADER, LAYER_ID, RECORDED_AT, none_alg_jwt
from fastapi import FastAPI
from fastapi.testclient import TestClient
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger._internal.identity import ALGO_VERSION
from traust_ledger.config import ServiceConfig
from traust_ledger.paths import layer_file_path
from traust_ledger.service.app import create_app

# ── Helpers ──────────────────────────────────────────────────────────────────


class _FixedActorVerifier:
    def __init__(self, actor: LayerActor) -> None:
        self._actor = actor

    def verify(self, request):
        from traust_ledger.service.identity.tokens import extract_bearer_token

        extract_bearer_token(request)
        return self._actor.model_copy()


def _verified_human(identity: str = "user:test@example.com") -> LayerActor:
    return LayerActor(
        kind="human",
        identity=identity,
        identity_verified=True,
        identity_provider="oidc",
    )


def _app(tmp_path: Path, actor: LayerActor | None = None) -> FastAPI:
    config = ServiceConfig(
        backend_type="file",
        data_dir=str(tmp_path),
        signing_required=False,
    )
    from conftest import canonical_shell

    app = create_app(config, verifier=_FixedActorVerifier(actor or _verified_human()))
    if not (tmp_path / f"{LAYER_ID}.json").exists():
        app.state.backend.initialize(tmp_path / f"{LAYER_ID}.json", canonical_shell())
    return app


def _read_layer_events(tmp_path: Path, layer_id: str = LAYER_ID) -> list[dict]:
    layer_path = layer_file_path(str(tmp_path), layer_id)
    layer = json.loads(layer_path.read_text())
    return layer.get("events", [])


# ── Gap 1: countersign via POST /events ──────────────────────────────────────


def _seed_birth_event(tmp_path: Path, layer_id: str = LAYER_ID) -> None:
    """Seed a layer with a birth event carrying a fingerprint.

    The countersign path needs an existing layer with at least one event
    (for the two-person gate to have something to check against).
    """
    from conftest import canonical_shell

    from traust_ledger._internal.integrity import stamp_merkle_metadata

    fp = "aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44"
    layer = {
        "events": [
            {
                "event_id": "a" * 64,
                "finding_ref": "FIND-001",
                "recorded_at": "2026-01-15T00:00:00+00:00",
                "source": {
                    "type": "validation_report",
                    "ref": "scan:2026-01-15",
                    "actor": {"kind": "machine", "identity": "scanner-v1"},
                },
                "disposition": {"validity": "confirmed"},
                "fingerprint": fp,
                "fingerprint_algo": ALGO_VERSION,
                "rationale": "Reviewed execution evidence and reproduced this finding.",
            }
        ],
        "metadata": {**canonical_shell()["metadata"], "merkle_epoch": 0},
        "needs_review": [],
    }
    stamp_merkle_metadata(layer)
    path = layer_file_path(str(tmp_path), layer_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(layer))


def test_countersign_event_stamps_fingerprint_algo(tmp_path: Path) -> None:
    """A human countersign (POST /events) should carry fingerprint_algo.

    The countersign arrives with finding_ref only; the submit path should
    resolve the fingerprint from the existing birth event's index and stamp
    both fingerprint and fingerprint_algo on the persisted event.
    """
    _seed_birth_event(tmp_path)
    client = TestClient(_app(tmp_path))

    envelope = {
        "kind": "countersign",
        "event": {
            "layer_id": LAYER_ID,
            "finding_ref": "FIND-001",
            "decision": "keep_open",
            "rationale": "Confirmed via manual code audit, exploit path is real.",
            "recorded_at": RECORDED_AT,
        },
    }
    resp = client.post("/v1/ledger/events", json=envelope, headers=AUTH_HEADER)
    assert resp.status_code == 200, resp.json()

    events = _read_layer_events(tmp_path)
    countersign = [e for e in events if e.get("source", {}).get("type") == "interactive"]
    assert len(countersign) == 1, f"expected 1 countersign, got {len(countersign)}"

    cs = countersign[0]
    assert cs.get("fingerprint_algo") == ALGO_VERSION, (
        f"countersign event missing fingerprint_algo: got {cs.get('fingerprint_algo')!r}"
    )


# ── Gap 2: birth event via POST /events ──────────────────────────────────────


def test_birth_event_via_events_endpoint_stamps_algo(tmp_path: Path) -> None:
    """A birth event (vuln_scan) submitted via POST /events with a fingerprint
    but no fingerprint_algo should get the algo stamped."""
    client = TestClient(_app(tmp_path))

    fp = "bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55"
    envelope = {
        "kind": "vuln_scan",
        "event": {
            "layer_id": LAYER_ID,
            "finding_ref": "FIND-002",
            "recorded_at": RECORDED_AT,
            "fingerprint": fp,
            "rationale": "Automated scanner detected this vulnerability in dependencies.",
            "source": {
                "type": "validation_report",
                "ref": "scan:2026-01-16",
                "actor": {"kind": "machine", "identity": "scanner-v1"},
            },
            "disposition": {"validity": "confirmed"},
        },
    }
    resp = client.post("/v1/ledger/events", json=envelope, headers=AUTH_HEADER)
    assert resp.status_code == 200, resp.json()

    events = _read_layer_events(tmp_path)
    assert len(events) == 1
    assert events[0]["fingerprint"] == fp
    assert events[0].get("fingerprint_algo") == ALGO_VERSION, (
        f"birth event via /events missing fingerprint_algo: "
        f"got {events[0].get('fingerprint_algo')!r}"
    )


# ── Gap 3: CLI ledger submit ────────────────────────────────────────────────


def test_cli_submit_stamps_fingerprint_algo(tmp_path: Path, monkeypatch) -> None:
    """CLI `ledger submit` with a fingerprint-bearing event should stamp algo."""
    monkeypatch.setenv("LAAS_BACKEND_TYPE", "file")
    monkeypatch.setenv("LAAS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv(
        "LAAS_TOKEN",
        none_alg_jwt(sub="test", exp=9999999999),
    )
    monkeypatch.setenv("LEDGER_TOKEN", "fake-jwt-for-test")

    fp = "cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66"
    from conftest import canonical_shell

    from traust_ledger._internal.backends.file import FileBackend

    FileBackend().initialize(tmp_path / f"{LAYER_ID}.json", canonical_shell())
    events_file = tmp_path / "events.json"
    events_file.write_text(
        json.dumps(
            [
                {
                    "finding_ref": "FIND-003",
                    "disposition": {"validity": "confirmed"},
                    "source": {"type": "triage_report", "ref": "scan-001", "actor": {}},
                    "recorded_at": RECORDED_AT,
                    "fingerprint": fp,
                    "rationale": "Reviewed dependency scanner evidence for this finding.",
                }
            ]
        )
    )

    from argparse import Namespace
    from unittest.mock import patch

    from traust_ledger.cli.commands.submit import cmd_submit

    args = Namespace(
        events_file=str(events_file),
        layer=LAYER_ID,
        queue_file=None,
        source_ref="test-run",
    )
    with patch(
        "traust_ledger.cli.commands.submit.require_verified_actor", return_value=_verified_human()
    ):
        result = cmd_submit(args)

    assert result == 0
    events = _read_layer_events(tmp_path)
    assert len(events) == 1
    assert events[0]["fingerprint"] == fp
    assert events[0].get("fingerprint_algo") == ALGO_VERSION, (
        f"CLI submit event missing fingerprint_algo: got {events[0].get('fingerprint_algo')!r}"
    )
