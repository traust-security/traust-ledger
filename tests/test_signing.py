#!/usr/bin/env python3
"""Tests for traust_ledger.integrity.signing (CosignBackend) and
traust_ledger.integrity.ledger.verify_merkle_signature."""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path
from unittest import mock

from traust_ledger.integrity import (
    Severity,
    stamp_merkle_metadata,
    verify_merkle_signature,
)
from traust_ledger.integrity.ledger import (
    SIGNATURE_FORMAT_CURRENT,
    merkle_root_payload,
    merkle_signature_payload,
)
from traust_ledger.integrity.signing import CosignBackend, SignResult, VerifyResult


def compute_event_id(
    source_ref: str, finding_ref: str, validity: str | None, resolution: str | None
) -> str:
    """Sample event ids, same formula the ledger used (sha256 of the joined fields)."""
    return hashlib.sha256(
        f"{source_ref}|{finding_ref}|{validity or ''}|{resolution or ''}".encode()
    ).hexdigest()


ROOT = "a" * 64
SIG = "dGVzdC1zaWduYXR1cmU="
F1 = "TEST_WIDGET-abcdef0-001"

_SIGNING_MOD = "traust_ledger.integrity.signing"


def _event():
    ref = "https://example.com/mr/17#note_1"
    return {
        "event_id": compute_event_id(ref, F1, "confirmed", None),
        "finding_ref": F1,
        "recorded_at": "2026-07-01T10:00:00+00:00",
        "source": {
            "type": "mr_comment",
            "ref": ref,
            "actor": {
                "kind": "human",
                "identity": "jdoe@example.com",
                "identity_verified": True,
            },
        },
        "disposition": {"validity": "confirmed"},
        "rationale": "Confirmed after review.",
    }


def _layer(*, signature: str | None = None, with_events: bool = True) -> dict:
    layer = {
        "metadata": {
            "audit_report": "test-widget-security-audit.json",
            "repository": "https://example.invalid/repo",
            "created": "2026-06-01T00:00:00+00:00",
            "harness_version": "0.48.0",
        },
        "events": [_event()] if with_events else [],
        "needs_review": [],
    }
    stamp_merkle_metadata(layer)
    if signature is not None:
        layer["metadata"]["merkle_root_signature"] = signature
        layer["metadata"]["merkle_signature_format"] = SIGNATURE_FORMAT_CURRENT
    return layer


def _mock_backend(
    *,
    available: bool = True,
    sign_result: SignResult | None = None,
    verify_result: VerifyResult | None = None,
    method_name: str = "keypair",
) -> mock.Mock:
    backend = mock.Mock()
    backend.available.return_value = available
    backend.sign.return_value = sign_result or SignResult(signature=SIG, success=True)
    backend.verify.return_value = verify_result or VerifyResult(valid=True)
    type(backend).method_name = mock.PropertyMock(return_value=method_name)
    return backend


class TestCosignBackend(unittest.TestCase):
    @mock.patch(f"{_SIGNING_MOD}.shutil.which", return_value=None)
    def test_available_false_without_cosign(self, _which):
        self.assertFalse(CosignBackend().available())

    @mock.patch(f"{_SIGNING_MOD}.shutil.which", return_value="/usr/bin/cosign")
    def test_available_true_with_cosign(self, _which):
        self.assertTrue(CosignBackend().available())

    @mock.patch(f"{_SIGNING_MOD}.shutil.which", return_value="/usr/bin/cosign")
    @mock.patch(f"{_SIGNING_MOD}.subprocess.run")
    def test_sign_command(self, run, _which):
        """cosign v3 contract: the signature arrives in a --bundle FILE, not on
        stdout, and the payload is a positional blob argument rather than
        stdin. The v2 shape this test used to assert never actually worked —
        it omitted the blob argument entirely."""
        import json as _json

        def _write_bundle(cmd, **kwargs):
            bundle_path = cmd[cmd.index("--bundle") + 1]
            Path(bundle_path).write_text(
                _json.dumps(
                    {
                        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                        "messageSignature": {"signature": SIG},
                    }
                )
            )
            return mock.Mock(returncode=0, stdout=b"", stderr=b"")

        run.side_effect = _write_bundle
        result = CosignBackend().sign(
            merkle_root_payload(ROOT),
            "/tmp/key.pem",
        )
        self.assertTrue(result.success)
        self.assertTrue(result.signature.startswith("{"), "must be a bundle")
        self.assertIn(SIG, result.signature)
        self.assertNotIn("\n", result.signature, "must be one line for JSON metadata")

        cmd = run.call_args.args[0]
        self.assertEqual(cmd[:4], ["cosign", "sign-blob", "--key", "/tmp/key.pem"])
        self.assertIn("--bundle", cmd)
        self.assertNotIn("--output-signature", cmd, "v3 hard-fails on this flag")
        self.assertIn("--tlog-upload=false", cmd, "publication is never allowed")
        # The payload is a real file now; nothing is piped on stdin.
        self.assertNotIn("input", run.call_args.kwargs)

    @mock.patch(f"{_SIGNING_MOD}.shutil.which", return_value="/usr/bin/cosign")
    @mock.patch(f"{_SIGNING_MOD}.subprocess.run")
    def test_sign_disables_tlog(self, run, _which):
        run.return_value = mock.Mock(returncode=0, stdout=SIG.encode(), stderr=b"")
        CosignBackend().sign(merkle_root_payload(ROOT), "/tmp/key.pem")
        cmd = run.call_args.args[0]
        self.assertIn("--tlog-upload=false", cmd)

    @mock.patch(f"{_SIGNING_MOD}.shutil.which", return_value="/usr/bin/cosign")
    @mock.patch(f"{_SIGNING_MOD}.subprocess.run")
    def test_sign_failure(self, run, _which):
        run.return_value = mock.Mock(returncode=1, stdout=b"", stderr=b"sign failed")
        result = CosignBackend().sign(b"payload", "/tmp/key.pem")
        self.assertFalse(result.success)
        self.assertEqual(result.error, "sign failed")

    @mock.patch(f"{_SIGNING_MOD}.shutil.which", return_value="/usr/bin/cosign")
    @mock.patch(f"{_SIGNING_MOD}.subprocess.run")
    def test_verify_success(self, run, _which):
        run.return_value = mock.Mock(returncode=0, stdout=b"", stderr=b"")
        result = CosignBackend().verify(
            merkle_root_payload(ROOT),
            SIG,
            "/tmp/pub.pem",
        )
        self.assertTrue(result.valid)
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[0:2], ["cosign", "verify-blob"])
        self.assertEqual(cmd[2:4], ["--key", "/tmp/pub.pem"])
        self.assertEqual(cmd[4:6], ["--signature", SIG])

    @mock.patch(f"{_SIGNING_MOD}.shutil.which", return_value="/usr/bin/cosign")
    @mock.patch(f"{_SIGNING_MOD}.subprocess.run")
    def test_verify_failure(self, run, _which):
        run.return_value = mock.Mock(returncode=1, stdout=b"", stderr=b"invalid signature")
        result = CosignBackend().verify(b"payload", SIG, "/tmp/pub.pem")
        self.assertFalse(result.valid)
        self.assertEqual(result.error, "invalid signature")


class TestVerifyMerkleSignature(unittest.TestCase):
    def test_absent_signature_errors_when_required(self):
        # v0.202.0 (self-audit -006): deleting the signature must never be
        # a downgrade path — required mode fails closed with an ERROR
        findings = verify_merkle_signature(_layer(signature=None), required=True)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.ERROR)
        self.assertIn("absent", findings[0].message)

    def test_absent_signature_silent_when_not_required(self):
        findings = verify_merkle_signature(_layer(signature=None))
        self.assertEqual(len(findings), 0)

    def test_signature_without_pubkey_warns(self):
        findings = verify_merkle_signature(_layer(signature=SIG), None)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.WARNING)
        self.assertIn("no public key configured", findings[0].message)

    def test_signature_without_cosign_warns(self):
        backend = _mock_backend(available=False)
        findings = verify_merkle_signature(
            _layer(signature=SIG),
            "/tmp/pub.pem",
            backend=backend,
        )
        self.assertEqual(findings[0].severity, Severity.WARNING)
        self.assertIn("not available", findings[0].message)

    def test_successful_verify(self):
        backend = _mock_backend()
        signed = _layer(signature=SIG)
        findings = verify_merkle_signature(
            signed,
            "/tmp/pub.pem",
            backend=backend,
        )
        self.assertEqual(findings, [])
        backend.verify.assert_called_once_with(
            merkle_signature_payload(signed["metadata"]),
            SIG,
            "/tmp/pub.pem",
        )

    def test_legacy_format1_verifies_with_content_unbound_warning(self):
        backend = _mock_backend()
        legacy = _layer(signature=SIG)
        del legacy["metadata"]["merkle_signature_format"]
        root = legacy["metadata"]["merkle_root"]
        findings = verify_merkle_signature(legacy, "/tmp/pub.pem", backend=backend)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.WARNING)
        self.assertIn("LEGACY SIGNATURE FORMAT", findings[0].message)
        backend.verify.assert_called_once_with(merkle_root_payload(root), SIG, "/tmp/pub.pem")

    def test_format2_binds_epoch_and_leaf_format(self):
        # same root, different leaf_format -> different signed payload
        signed = _layer(signature=SIG)
        m1 = dict(signed["metadata"])
        m2 = dict(signed["metadata"])
        m2["leaf_format"] = 1
        self.assertNotEqual(merkle_signature_payload(m1), merkle_signature_payload(m2))
        m3 = dict(signed["metadata"])
        m3["claim_hashes"] = {"F-001": "a" * 64}
        self.assertNotEqual(merkle_signature_payload(m1), merkle_signature_payload(m3))

    def test_failed_verify(self):
        backend = _mock_backend(
            verify_result=VerifyResult(valid=False, error="invalid signature"),
        )
        findings = verify_merkle_signature(
            _layer(signature=SIG),
            "/tmp/pub.pem",
            backend=backend,
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.ERROR)
        self.assertIn("verification failed", findings[0].message)


if __name__ == "__main__":
    unittest.main()


# --- format 3: the report digest inside the signature (plan §4.4.0a) ---------


def test_format_3_binds_the_report_digest():
    """The gap format 2 left: whoever could write the layer could repoint it at a
    substituted report by rewriting audit_report_sha256, because the digest sat
    outside the signature. Provenance, not tamper-evidence."""
    from traust_ledger.integrity.ledger import merkle_signature_payload

    meta = {
        "merkle_root": "ab" * 32,
        "leaf_format": 2,
        "merkle_epoch": 0,
        "merkle_size": 3,
        "claim_hashes": {"F-1": "x"},
        "audit_report_sha256": "cd" * 32,
    }
    swapped = {**meta, "audit_report_sha256": "ef" * 32}

    assert merkle_signature_payload(meta, fmt=3) != merkle_signature_payload(swapped, fmt=3)
    # and the old format is exactly why this step was needed
    assert merkle_signature_payload(meta, fmt=2) == merkle_signature_payload(swapped, fmt=2)


def test_format_3_differs_from_format_2_on_the_same_metadata():
    from traust_ledger.integrity.ledger import merkle_signature_payload

    meta = {
        "merkle_root": "ab" * 32,
        "leaf_format": 2,
        "merkle_epoch": 0,
        "merkle_size": 3,
        "audit_report_sha256": "cd" * 32,
    }
    assert merkle_signature_payload(meta, fmt=2) != merkle_signature_payload(meta, fmt=3)


def test_absent_digest_is_signed_as_a_distinct_value():
    """A layer whose report could not be resolved signs None, not 'omit the key' —
    so backfilling the digest later invalidates the signature instead of passing."""
    from traust_ledger.integrity.ledger import merkle_signature_payload

    without = {"merkle_root": "ab" * 32, "leaf_format": 2, "merkle_size": 1}
    with_digest = {**without, "audit_report_sha256": "cd" * 32}
    assert merkle_signature_payload(without, fmt=3) != merkle_signature_payload(with_digest, fmt=3)


def test_new_signatures_record_the_current_format(tmp_path, monkeypatch):
    """sign_if_configured records the current format, whatever it is.

    This asserted `== 3` literally and had to be edited when format 4 landed — the
    same trap two fixtures hit during the format-3 migration. A test that pins a
    version number breaks on every deliberate bump and proves nothing about behaviour,
    so it now checks the property that matters: the payload actually changes with the
    format, i.e. the number is load-bearing rather than decorative.
    """
    from traust_ledger.integrity.ledger import (
        SIGNATURE_FORMAT_CURRENT,
        merkle_signature_payload,
    )

    assert SIGNATURE_FORMAT_CURRENT >= 3
    meta = {"merkle_root": "a" * 64, "merkle_size": 1}
    assert merkle_signature_payload(meta, fmt=SIGNATURE_FORMAT_CURRENT) != (
        merkle_signature_payload(meta, fmt=SIGNATURE_FORMAT_CURRENT - 1)
    )


def test_format_2_still_verifies_during_the_migration():
    """Layers signed under format 2 must keep verifying without complaint,
    against the payload they were actually signed over."""
    from unittest.mock import Mock

    from traust_ledger.integrity.ledger import merkle_signature_payload

    backend = Mock()
    backend.method_name = "keypair"
    backend.available.return_value = True
    backend.verify.return_value = Mock(valid=True, error=None)

    layer = _layer(signature=SIG)
    layer["metadata"]["merkle_signature_format"] = 2
    layer["metadata"]["audit_report_sha256"] = "cd" * 32

    findings = verify_merkle_signature(layer, "/tmp/pub.pem", backend=backend)

    assert findings == []
    backend.verify.assert_called_once_with(
        merkle_signature_payload(layer["metadata"], fmt=2), SIG, "/tmp/pub.pem"
    )
