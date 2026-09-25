"""Tests for LedgerClient atomic write methods (Phase A).

Validates:
  - sign() uses Backend.mutate (I1) and finalize_layer (I2)
  - patch_metadata() merges keys + finalizes inside one lock
  - create() bootstraps an empty layer
  - signing_required is resolved from env when not explicit
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from conftest import none_alg_jwt

from traust_ledger._internal.backends.file import FileBackend
from traust_ledger._internal.integrity import stamp_merkle_metadata, verify_merkle_integrity
from traust_ledger._internal.integrity.signing import SigningConfig
from traust_ledger.api.events import FINGERPRINT_ALGO_CURRENT
from traust_ledger.client import LedgerClient, LedgerError
from traust_ledger.paths import layer_file_path

LAYER_ID = "test-layer"
FAKE_TOKEN = none_alg_jwt(
    sub="test@example.com", email="test@example.com", iat=1693000000, exp=9999999999
)


class _TestVerifier:
    def verify(self, token: str):
        from traust_contracts.v1.models.layer import LayerActor

        return LayerActor(
            kind="human", identity="user:test", identity_verified=True, identity_provider="oidc"
        )


def _make_client(
    tmp_path: Path,
    *,
    signing_required: bool | None = None,
) -> LedgerClient:
    """Build a LedgerClient backed by a temp dir with no real signing."""
    return LedgerClient(
        token=FAKE_TOKEN,
        verifier=_TestVerifier(),
        data_dir=str(tmp_path),
        signing_config=SigningConfig(method="none"),
        signing_required=signing_required,
    )


def _canonical_shell() -> dict:
    return {
        "metadata": {
            "audit_report": "audit.json",
            "repository": "https://example.test/repo",
            "created": "2026-09-22T12:00:00Z",
            "harness_version": "1.0.0",
        },
        "events": [],
        "needs_review": [],
    }


def _seed_layer(tmp_path: Path, events: list[dict] | None = None) -> Path:
    """Write a minimal layer file and return its path."""
    normalized = []
    for index, event in enumerate(events or []):
        normalized.append(
            {
                "event_id": hashlib.sha256(event["event_id"].encode()).hexdigest(),
                "finding_ref": event.get("finding_ref", f"F-{index}"),
                "recorded_at": "2026-01-01T00:00:00Z",
                "source": {
                    "type": "triage_report",
                    "ref": f"report-{index}.json",
                    "actor": {"kind": "machine"},
                },
                "disposition": {"validity": "confirmed", "resolution": "open"},
                "rationale": "Reviewed and confirmed this finding against source.",
                **(
                    {"fingerprint": "c" * 64, "fingerprint_algo": "v2"}
                    if event.get("fingerprint")
                    else {}
                ),
            }
        )
    layer = {**_canonical_shell(), "events": normalized}
    if events:
        stamp_merkle_metadata(layer)
    path = layer_file_path(str(tmp_path), LAYER_ID)
    FileBackend(data_dir=tmp_path).store(path, layer)
    return path


# ── sign() ───────────────────────────────────────────────────────────────


class TestSign:
    def test_sign_is_atomic(self, tmp_path: Path) -> None:
        """sign() stamps and stores in one mutate call."""
        events = [
            {
                "event_id": "E-001",
                "finding_ref": "F-1",
                "disposition": "confirmed",
                "recorded_at": "2026-01-01T00:00:00Z",
            }
        ]
        _seed_layer(tmp_path, events=events)
        client = _make_client(tmp_path)
        result = client.sign(LAYER_ID)
        assert result["layer_id"] == LAYER_ID

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert reloaded["metadata"].get("merkle_root"), "should be stamped"

    def test_sign_empty_layer(self, tmp_path: Path) -> None:
        """sign() on an empty layer still stamps a root."""
        _seed_layer(tmp_path)
        client = _make_client(tmp_path)
        result = client.sign(LAYER_ID)
        assert "merkle_root" in result


# ── signing_required env resolution ──────────────────────────────────────


class TestSigningRequiredResolution:
    def test_explicit_kwarg_wins(self, tmp_path: Path) -> None:
        """signing_required=True kwarg takes precedence over env."""
        client = LedgerClient(
            token=FAKE_TOKEN,
            data_dir=str(tmp_path),
            signing_config=SigningConfig(method="none"),
            signing_required=True,
        )
        assert client._config.signing_required is True

    def test_env_var_resolved(self, tmp_path: Path) -> None:
        """LAAS_SIGNING_REQUIRED env var is read when kwarg is None."""
        env = {
            "LAAS_SIGNING_REQUIRED": "true",
            "LAAS_TOKEN": FAKE_TOKEN,
        }
        with patch.dict(os.environ, env, clear=False):
            client = LedgerClient(
                token=FAKE_TOKEN,
                data_dir=str(tmp_path),
                signing_config=SigningConfig(method="none"),
            )
        assert client._config.signing_required is True

    def test_default_is_false(self, tmp_path: Path) -> None:
        """Without env var or kwarg, signing_required defaults False."""
        env = {"LAAS_SIGNING_REQUIRED": ""}
        with patch.dict(os.environ, env, clear=False):
            client = _make_client(tmp_path)
        assert client._config.signing_required is False

    def test_signing_required_raises_without_signer(self, tmp_path: Path) -> None:
        """I2: signing_required=True + no signer → raises on sign()."""
        _seed_layer(tmp_path, events=[{"event_id": "E-1", "disposition": "c"}])
        client = _make_client(tmp_path, signing_required=True)
        with pytest.raises(LedgerError, match="signing"):
            client.sign(LAYER_ID)

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert not reloaded["metadata"].get("merkle_root_signature"), (
            "failed sign must not write unsigned layer"
        )


# ── patch_metadata() ─────────────────────────────────────────────────────


class TestPatchMetadata:
    def test_merges_keys(self, tmp_path: Path) -> None:
        """patch_metadata merges update keys into metadata."""
        _seed_layer(tmp_path, events=[{"event_id": "E-1", "disposition": "c"}])
        client = _make_client(tmp_path)
        result = client.patch_metadata(LAYER_ID, {"audit_report_ref": "object://value"})
        assert result["layer_id"] == LAYER_ID

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert reloaded["metadata"]["audit_report_ref"] == "object://value"

    def test_stamps_updated(self, tmp_path: Path) -> None:
        """patch_metadata sets metadata.updated timestamp."""
        _seed_layer(tmp_path, events=[{"event_id": "E-1", "disposition": "c"}])
        client = _make_client(tmp_path)
        client.patch_metadata(LAYER_ID, {"audit_report_ref": "test"})

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert "updated" in reloaded["metadata"]

    def test_deep_merges_dicts(self, tmp_path: Path) -> None:
        """patch_metadata deep-merges dict values."""
        _seed_layer(tmp_path, events=[{"event_id": "E-1", "disposition": "c"}])
        client = _make_client(tmp_path)
        client.patch_metadata(LAYER_ID, {"claim_hashes": {"a": "a" * 64}})
        client.patch_metadata(LAYER_ID, {"claim_hashes": {"b": "b" * 64}})

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        hashes = reloaded["metadata"]["claim_hashes"]
        assert hashes == {"a": "a" * 64, "b": "b" * 64}

    def test_finalizes_after_patch(self, tmp_path: Path) -> None:
        """patch_metadata re-stamps merkle root after metadata change."""
        _seed_layer(tmp_path, events=[{"event_id": "E-1", "disposition": "c"}])
        client = _make_client(tmp_path)

        client.patch_metadata(LAYER_ID, {"artifact_digests": {"r.json": "a" * 64}})

        after = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert after["metadata"].get("merkle_root"), "should be stamped"
        findings = verify_merkle_integrity(after)
        assert not any(f.severity.value >= 2 for f in findings)

    def test_signing_required_raises(self, tmp_path: Path) -> None:
        """I2: patch_metadata with signing_required + no signer raises."""
        _seed_layer(tmp_path, events=[{"event_id": "E-1", "disposition": "c"}])
        client = _make_client(tmp_path, signing_required=True)
        with pytest.raises(LedgerError, match="signing"):
            client.patch_metadata(LAYER_ID, {"audit_report_ref": "test"})


# ── create() ─────────────────────────────────────────────────────────────


class TestCreate:
    def test_creates_empty_layer(self, tmp_path: Path) -> None:
        """create() requires caller-authored canonical metadata."""
        client = _make_client(tmp_path)
        with pytest.raises(LedgerError, match="complete layer shell"):
            client.create(LAYER_ID)
        result = client.create(LAYER_ID, shell=_canonical_shell())
        assert result["layer_id"] == LAYER_ID

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert reloaded["events"] == []
        assert "metadata" in reloaded

    def test_creates_with_shell(self, tmp_path: Path) -> None:
        """create() uses the provided shell dict."""
        shell = _canonical_shell()
        client = _make_client(tmp_path)
        client.create(LAYER_ID, shell=shell)

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert reloaded == shell

    def test_create_is_unsigned(self, tmp_path: Path) -> None:
        """create() does not sign — no events to root."""
        client = _make_client(tmp_path)
        client.create(LAYER_ID, shell=_canonical_shell())

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert not reloaded["metadata"].get("merkle_root_signature")


class TestStampEventIdentities:
    def test_stamps_missing_identity(self, tmp_path: Path) -> None:
        """Backfills fingerprint + algo onto events by finding_ref."""
        events = [
            {"event_id": "E-1", "finding_ref": "F-1", "disposition": "c"},
            {"event_id": "E-2", "finding_ref": "F-2", "disposition": "c"},
        ]
        _seed_layer(tmp_path, events=events)
        client = _make_client(tmp_path)

        result = client.stamp_event_identities(LAYER_ID, {"F-1": "a" * 64, "F-2": "b" * 64})
        assert result["stamped"] == 2

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        by_ref = {e["finding_ref"]: e for e in reloaded["events"]}
        assert by_ref["F-1"]["fingerprint"] == "a" * 64
        assert by_ref["F-2"]["fingerprint"] == "b" * 64
        assert by_ref["F-1"]["fingerprint_algo"] == FINGERPRINT_ALGO_CURRENT

    def test_never_overwrites_existing(self, tmp_path: Path) -> None:
        """Identity is a historical observation — an existing fp is left alone."""
        events = [{"event_id": "E-1", "finding_ref": "F-1", "fingerprint": "old"}]
        _seed_layer(tmp_path, events=events)
        client = _make_client(tmp_path)

        result = client.stamp_event_identities(LAYER_ID, {"F-1": "a" * 64})
        assert result["stamped"] == 0

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert reloaded["events"][0]["fingerprint"] == "c" * 64

    def test_ignores_unmapped_refs(self, tmp_path: Path) -> None:
        """An event whose finding_ref is absent from the map is not stamped."""
        events = [{"event_id": "E-1", "finding_ref": "F-9", "disposition": "c"}]
        _seed_layer(tmp_path, events=events)
        client = _make_client(tmp_path)

        result = client.stamp_event_identities(LAYER_ID, {"F-1": "a" * 64})
        assert result["stamped"] == 0

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert "fingerprint" not in reloaded["events"][0]

    def test_finalizes_after_stamp(self, tmp_path: Path) -> None:
        """Re-stamps a valid Merkle root over the mutated events."""
        _seed_layer(tmp_path, events=[{"event_id": "E-1", "finding_ref": "F-1"}])
        client = _make_client(tmp_path)

        client.stamp_event_identities(LAYER_ID, {"F-1": "a" * 64})

        after = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert after["metadata"].get("merkle_root"), "should be stamped"
        findings = verify_merkle_integrity(after)
        assert not any(f.severity.value >= 2 for f in findings)

    def test_signing_required_raises(self, tmp_path: Path) -> None:
        """I2: signing_required + no signer raises and writes nothing unsigned."""
        _seed_layer(tmp_path, events=[{"event_id": "E-1", "finding_ref": "F-1"}])
        client = _make_client(tmp_path, signing_required=True)
        with pytest.raises(LedgerError, match="signing"):
            client.stamp_event_identities(LAYER_ID, {"F-1": "a" * 64})

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert not reloaded["metadata"].get("merkle_root_signature")


class TestStore:
    def test_store_cannot_replace_authoritative_layer(self, tmp_path: Path) -> None:
        client = _make_client(tmp_path)
        client.create(LAYER_ID, shell=_canonical_shell())
        with pytest.raises(LedgerError, match="cannot replace authoritative history"):
            client.store(LAYER_ID, _canonical_shell())
        assert FileBackend().load(layer_file_path(str(tmp_path), LAYER_ID)) == _canonical_shell()
