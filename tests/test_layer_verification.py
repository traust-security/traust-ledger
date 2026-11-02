"""A layer document end to end: stamp, sign with a real cosign keypair, verify; and the
restatement chain that pins signature-bound metadata."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

from traust_ledger.integrity import (
    Severity,
    SigningBackend,
    SigningConfig,
    VerifyResult,
    stamp_and_sign,
    stamp_merkle_metadata,
    verify_merkle_integrity,
    verify_merkle_signature,
    verify_restated_metadata,
)

needs_cosign = pytest.mark.skipif(shutil.which("cosign") is None, reason="cosign not installed")


@pytest.fixture
def keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Two throwaway keypairs: (private, public) each."""
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    pairs = []
    for name in ("ours", "theirs"):
        prefix = tmp_path / name
        subprocess.run(
            ["cosign", "generate-key-pair", "--output-key-prefix", str(prefix)],
            check=True,
            capture_output=True,
        )
        pairs.append((f"{prefix}.key", f"{prefix}.pub"))
    return pairs


def layer(*events: dict) -> dict:
    return {"metadata": {}, "events": list(events)}


def event(n: int, **extra: object) -> dict:
    return {"event_id": f"e{n}", "finding_ref": f"F-{n}", "disposition": {}, **extra}


def restatement(target: str, after: object, n: int = 9) -> dict:
    block = {"target": target, "after": after}
    return event(n, source={"type": "restatement"}, restatement=block)


def errors(findings: list) -> list[str]:
    return [f.message for f in findings if f.severity is Severity.ERROR]


def test_verify_merkle_signature_identity_without_policy_reports_unconfigured_not_failed() -> None:
    """An identity-signed layer with no verifier policy is unconfigured, not tampered.

    sign_if_configured/stamp_and_sign write merkle_signing_method='identity' layers;
    the standard entry point (no explicit backend=, exactly how traust-core calls it)
    dispatches them to a bare SigstoreOIDCBackend(), which structurally cannot
    verify. That must surface as an unconfigured-verifier WARNING — the keypair
    analogue of "no public key configured" — not as an ERROR claiming the
    signature failed verification, which is tamper-evidence language.
    """
    signed = layer()
    stamp_merkle_metadata(signed)
    signed["metadata"]["merkle_signing_method"] = "identity"
    signed["metadata"]["merkle_signature_format"] = 4
    signed["metadata"]["merkle_root_signature"] = "fake-bundle"

    with mock.patch.dict(
        sys.modules,
        {
            "sigstore": mock.MagicMock(),
            "sigstore.verify": mock.MagicMock(),
            "sigstore.models": mock.MagicMock(),
        },
    ):
        findings = verify_merkle_signature(signed, pubkey_path="/tmp/irrelevant.pub")

    assert not errors(findings), errors(findings)
    assert any(f.severity is Severity.WARNING and "identity" in f.message for f in findings), [
        f"{f.severity}: {f.message}" for f in findings
    ]


class _StubBackend(SigningBackend):
    """Backend that says yes to everything, so the test isolates the payload path."""

    @property
    def method_name(self) -> str:
        return "keypair"

    def available(self) -> bool:
        return True

    def sign(self, payload: bytes, key_path: str, *, rekor: bool = False):
        raise NotImplementedError

    def verify(self, payload: bytes, signature: str, key_path: str) -> VerifyResult:
        return VerifyResult(valid=True)


def test_verify_merkle_signature_non_hex_root_is_finding_not_crash() -> None:
    """A malformed merkle_root must be a finding, never an escaping exception.

    sig_format defaults to 1 when merkle_signature_format is absent, and the
    format-1 path feeds untrusted metadata.merkle_root straight into
    bytes.fromhex — a tampered layer with a non-hex root crashed the verifier
    (uncaught, straight through traust-core's LedgerService._issues) instead
    of returning an IntegrityFinding like every sibling malformed field.
    """
    layer = {
        "metadata": {
            "merkle_root": "definitely-not-hex",
            "merkle_root_signature": "c2ln",
        },
        "events": [],
    }
    findings = verify_merkle_signature(layer, pubkey_path="/tmp/pub.pub", backend=_StubBackend())
    assert any(f.severity is Severity.ERROR and "merkle_root" in f.message for f in findings), [
        f"{f.severity}: {f.message}" for f in findings
    ]


@needs_cosign
def test_a_signed_chain_verifies_and_a_tampered_event_does_not(keys) -> None:
    (private, public), _ = keys
    doc = layer(event(0), event(1), event(2))
    attempt = stamp_and_sign(doc, SigningConfig(method="keypair", key_path=private))
    assert attempt.status == "signed", attempt.error
    assert verify_merkle_integrity(doc) == []
    assert verify_merkle_signature(doc, public) == []

    doc["events"][1]["finding_ref"] = "F-edited"
    assert any("merkle_root mismatch" in e for e in errors(verify_merkle_integrity(doc)))


@needs_cosign
def test_a_signature_from_another_key_is_rejected(keys) -> None:
    (private, _), (_, their_public) = keys
    doc = layer(event(0))
    stamp_and_sign(doc, SigningConfig(method="keypair", key_path=private))
    assert verify_merkle_integrity(doc) == []
    assert errors(verify_merkle_signature(doc, their_public))


def test_an_empty_chain_stamps_and_verifies() -> None:
    doc = layer()
    stamp_merkle_metadata(doc)
    assert doc["metadata"]["merkle_size"] == 0
    assert verify_merkle_integrity(doc) == []


def test_an_unsigned_layer_fails_only_when_signing_is_required() -> None:
    doc = layer(event(0))
    stamp_merkle_metadata(doc)
    assert verify_merkle_signature(doc) == []
    assert any("absent" in e for e in errors(verify_merkle_signature(doc, required=True)))


def test_restated_metadata_must_hold_the_chains_last_value() -> None:
    doc = layer(
        event(0),
        restatement("audit_report_sha256", "a" * 64, n=1),
        restatement("audit_report_sha256", "b" * 64, n=2),
    )
    doc["metadata"]["audit_report_sha256"] = "b" * 64
    assert verify_restated_metadata(doc) == []

    doc["metadata"]["audit_report_sha256"] = "a" * 64
    assert errors(verify_restated_metadata(doc))


def test_map_restatements_pin_only_the_keys_they_name() -> None:
    doc = layer(
        restatement("claim_hashes", {"F-1": "h1", "F-2": "h2"}, n=1),
        restatement("claim_hashes", {"F-2": None}, n=2),  # null deletes the key
    )
    doc["metadata"]["claim_hashes"] = {"F-1": "h1", "F-3": "never restated"}
    assert verify_restated_metadata(doc) == []

    doc["metadata"]["claim_hashes"] = {"F-1": "changed"}
    assert any("F-1" in e for e in errors(verify_restated_metadata(doc)))


def test_a_restatement_block_on_an_ordinary_event_has_no_authority() -> None:
    forged = event(1, source={"type": "interactive"}, restatement={"target": "audit_report_sha256"})
    doc = layer(forged)
    doc["metadata"]["audit_report_sha256"] = "anything"
    assert verify_restated_metadata(doc) == []
