"""cosign v3 bundle-format signing.

cosign v3 changed the sign-blob contract: --output-signature hard-fails and the
signature arrives inside a Sigstore bundle. Critically, without
--use-signing-config=false the v3 default UPLOADS TO THE PUBLIC
rekor.sigstore.dev, which for an internal security ledger publishes the timing
of every ledger write to an irrevocable public log.

These tests need cosign on PATH and are skipped otherwise.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traust_ledger.integrity.signing import CosignBackend

pytestmark = pytest.mark.skipif(shutil.which("cosign") is None, reason="cosign not installed")


@pytest.fixture(scope="module")
def keypair(tmp_path_factory):
    d = tmp_path_factory.mktemp("cosign")
    subprocess.run(
        ["cosign", "generate-key-pair"],
        cwd=d,
        check=True,
        capture_output=True,
        env={"COSIGN_PASSWORD": "t", "PATH": __import__("os").environ["PATH"]},
    )
    return d / "cosign.key", d / "cosign.pub"


def _sign(backend, payload, key):
    import os

    os.environ["COSIGN_PASSWORD"] = "t"
    return backend.sign(payload, str(key))


def test_sign_produces_a_bundle_and_verifies(keypair):
    key, pub = keypair
    b = CosignBackend()
    r = _sign(b, b"payload-under-test", key)
    assert r.success, r.error
    assert r.signature.startswith("{"), "v3 signature must be a bundle"
    assert b.verify(b"payload-under-test", r.signature, str(pub)).valid


def test_bundle_carries_no_transparency_log_entry(keypair):
    """The offline path. A tlog entry here would mean the root's digest was
    published to rekor.sigstore.dev — irrevocably, and on every write."""
    key, _ = keypair
    r = _sign(CosignBackend(), b"payload-under-test", key)
    assert r.success, r.error
    vm = json.loads(r.signature).get("verificationMaterial") or {}
    assert not (vm.get("tlogEntries") or []), "must not publish to a public log"
    assert not ((vm.get("timestampVerificationData") or {}).get("rfc3161Timestamps") or [])


def test_tampered_payload_is_rejected(keypair):
    key, pub = keypair
    b = CosignBackend()
    r = _sign(b, b"original", key)
    assert r.success, r.error
    assert not b.verify(b"tampered", r.signature, str(pub)).valid


def test_signature_is_single_line_for_json_metadata(keypair):
    """The bundle is stored in layer metadata, which is JSON — an embedded
    newline would survive a round-trip but is needless breakage."""
    key, _ = keypair
    r = _sign(CosignBackend(), b"payload-under-test", key)
    assert r.success, r.error
    assert "\n" not in r.signature


def test_bundle_stays_small(keypair):
    """~390 bytes offline vs ~3.8 KB with a tlog entry. At 22k layers that is
    the difference between ~9 MB and ~84 MB of git-tracked metadata."""
    key, _ = keypair
    r = _sign(CosignBackend(), b"payload-under-test", key)
    assert r.success, r.error
    assert len(r.signature) < 1000, f"bundle unexpectedly large: {len(r.signature)}"


def test_sign_refuses_to_emit_a_published_signature(monkeypatch, tmp_path):
    """The durable guard: if cosign publishes despite our flags, the signature
    is DISCARDED rather than returned.

    Flags are not a durable defence — v2's --tlog-upload=false is rejected by
    v3's default signing config, and v3 publishes by default. A future version
    can change the contract again, so the post-condition verifies the artifact
    instead of trusting the request. Publication is irreversible; a failed
    signing run is not.
    """
    import json as _json
    import subprocess as _sp

    from traust_ledger.integrity import signing as _s

    def fake_run(cmd, **kwargs):
        bundle = cmd[cmd.index("--bundle") + 1]
        Path(bundle).write_text(
            _json.dumps(
                {
                    "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                    "messageSignature": {"signature": "aaa"},
                    # cosign ignored our flags and uploaded anyway:
                    "verificationMaterial": {
                        "tlogEntries": [{"logIndex": 1}],
                        "timestampVerificationData": {
                            "rfc3161Timestamps": [{"signedTimestamp": "x"}]
                        },
                    },
                }
            )
        )

        class R:
            returncode = 0
            stderr = b""
            stdout = b""

        return R()

    monkeypatch.setattr(_sp, "run", fake_run)
    monkeypatch.setattr(_s.subprocess, "run", fake_run)
    r = _s.CosignBackend().sign(b"payload", "/tmp/key.pem")
    assert not r.success, "a published signature must never be returned"
    assert r.signature == "", "the signature must be discarded"
    assert "REFUSING" in (r.error or "")
    assert "tlogEntries" in (r.error or "")
