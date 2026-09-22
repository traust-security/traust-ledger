"""Tests for LedgerClient atomic write methods (Phase A).

Validates:
  - sign() uses Backend.mutate (I1) and finalize_layer (I2)
  - patch_metadata() merges keys + finalizes inside one lock
  - create() bootstraps an empty layer
  - signing_required is resolved from env when not explicit
"""

from __future__ import annotations

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


def _make_client(
    tmp_path: Path,
    *,
    signing_required: bool | None = None,
) -> LedgerClient:
    """Build a LedgerClient backed by a temp dir with no real signing."""
    return LedgerClient(
        token=FAKE_TOKEN,
        data_dir=str(tmp_path),
        signing_config=SigningConfig(method="none"),
        signing_required=signing_required,
    )


def _seed_layer(tmp_path: Path, events: list[dict] | None = None) -> Path:
    """Write a minimal layer file and return its path."""
    layer = {"events": events or [], "metadata": {}}
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
        result = client.patch_metadata(LAYER_ID, {"custom_key": "value"})
        assert result["layer_id"] == LAYER_ID

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert reloaded["metadata"]["custom_key"] == "value"

    def test_stamps_updated(self, tmp_path: Path) -> None:
        """patch_metadata sets metadata.updated timestamp."""
        _seed_layer(tmp_path, events=[{"event_id": "E-1", "disposition": "c"}])
        client = _make_client(tmp_path)
        client.patch_metadata(LAYER_ID, {"note": "test"})

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert "updated" in reloaded["metadata"]

    def test_deep_merges_dicts(self, tmp_path: Path) -> None:
        """patch_metadata deep-merges dict values."""
        _seed_layer(tmp_path, events=[{"event_id": "E-1", "disposition": "c"}])
        client = _make_client(tmp_path)
        client.patch_metadata(LAYER_ID, {"claim_hashes": {"a": "1"}})
        client.patch_metadata(LAYER_ID, {"claim_hashes": {"b": "2"}})

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        hashes = reloaded["metadata"]["claim_hashes"]
        assert hashes == {"a": "1", "b": "2"}

    def test_finalizes_after_patch(self, tmp_path: Path) -> None:
        """patch_metadata re-stamps merkle root after metadata change."""
        _seed_layer(tmp_path, events=[{"event_id": "E-1", "disposition": "c"}])
        client = _make_client(tmp_path)

        client.patch_metadata(LAYER_ID, {"artifact_digests": {"r.json": "abc"}})

        after = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert after["metadata"].get("merkle_root"), "should be stamped"
        findings = verify_merkle_integrity(after)
        assert not any(f.severity.value >= 2 for f in findings)

    def test_signing_required_raises(self, tmp_path: Path) -> None:
        """I2: patch_metadata with signing_required + no signer raises."""
        _seed_layer(tmp_path, events=[{"event_id": "E-1", "disposition": "c"}])
        client = _make_client(tmp_path, signing_required=True)
        with pytest.raises(LedgerError, match="signing"):
            client.patch_metadata(LAYER_ID, {"note": "test"})


# ── create() ─────────────────────────────────────────────────────────────


class TestCreate:
    def test_creates_empty_layer(self, tmp_path: Path) -> None:
        """create() writes a minimal layer file."""
        client = _make_client(tmp_path)
        result = client.create(LAYER_ID)
        assert result["layer_id"] == LAYER_ID

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert reloaded["events"] == []
        assert "metadata" in reloaded

    def test_creates_with_shell(self, tmp_path: Path) -> None:
        """create() uses the provided shell dict."""
        shell = {"events": [], "metadata": {"custom": True}}
        client = _make_client(tmp_path)
        client.create(LAYER_ID, shell=shell)

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert reloaded["metadata"]["custom"] is True

    def test_create_is_unsigned(self, tmp_path: Path) -> None:
        """create() does not sign — no events to root."""
        client = _make_client(tmp_path)
        client.create(LAYER_ID)

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

        result = client.stamp_event_identities(LAYER_ID, {"F-1": "fp1", "F-2": "fp2"})
        assert result["stamped"] == 2

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        by_ref = {e["finding_ref"]: e for e in reloaded["events"]}
        assert by_ref["F-1"]["fingerprint"] == "fp1"
        assert by_ref["F-2"]["fingerprint"] == "fp2"
        assert by_ref["F-1"]["fingerprint_algo"] == FINGERPRINT_ALGO_CURRENT

    def test_never_overwrites_existing(self, tmp_path: Path) -> None:
        """Identity is a historical observation — an existing fp is left alone."""
        events = [{"event_id": "E-1", "finding_ref": "F-1", "fingerprint": "old"}]
        _seed_layer(tmp_path, events=events)
        client = _make_client(tmp_path)

        result = client.stamp_event_identities(LAYER_ID, {"F-1": "new"})
        assert result["stamped"] == 0

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert reloaded["events"][0]["fingerprint"] == "old"

    def test_ignores_unmapped_refs(self, tmp_path: Path) -> None:
        """An event whose finding_ref is absent from the map is not stamped."""
        events = [{"event_id": "E-1", "finding_ref": "F-9", "disposition": "c"}]
        _seed_layer(tmp_path, events=events)
        client = _make_client(tmp_path)

        result = client.stamp_event_identities(LAYER_ID, {"F-1": "fp1"})
        assert result["stamped"] == 0

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert "fingerprint" not in reloaded["events"][0]

    def test_finalizes_after_stamp(self, tmp_path: Path) -> None:
        """Re-stamps a valid Merkle root over the mutated events."""
        _seed_layer(tmp_path, events=[{"event_id": "E-1", "finding_ref": "F-1"}])
        client = _make_client(tmp_path)

        client.stamp_event_identities(LAYER_ID, {"F-1": "fp1"})

        after = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert after["metadata"].get("merkle_root"), "should be stamped"
        findings = verify_merkle_integrity(after)
        assert not any(f.severity.value >= 2 for f in findings)

    def test_signing_required_raises(self, tmp_path: Path) -> None:
        """I2: signing_required + no signer raises and writes nothing unsigned."""
        _seed_layer(tmp_path, events=[{"event_id": "E-1", "finding_ref": "F-1"}])
        client = _make_client(tmp_path, signing_required=True)
        with pytest.raises(LedgerError, match="signing"):
            client.stamp_event_identities(LAYER_ID, {"F-1": "fp1"})

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert not reloaded["metadata"].get("merkle_root_signature")


class TestStore:
    def test_persists_whole_layer(self, tmp_path: Path) -> None:
        """store() writes a fully-materialized layer through the backend."""
        client = _make_client(tmp_path)
        layer = {"events": [{"finding_ref": "F-1"}], "metadata": {"built": True}}
        result = client.store(LAYER_ID, layer)
        assert result["layer_id"] == LAYER_ID

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert reloaded["events"] == [{"finding_ref": "F-1"}]
        assert reloaded["metadata"]["built"] is True

    def test_store_is_unsigned(self, tmp_path: Path) -> None:
        """store() persists as-is — signing is a separate step."""
        client = _make_client(tmp_path)
        client.store(LAYER_ID, {"events": [], "metadata": {}})

        reloaded = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))
        assert not reloaded["metadata"].get("merkle_root_signature")
