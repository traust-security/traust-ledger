#!/usr/bin/env python3
"""End-to-end CI pipeline test for Merkle ledger integrity.

Simulates the disposition pipeline from fresh triage events through Merkle
stamping, validation, signing, append-only growth, cryptographic proofs,
and tamper detection — mirroring build_cumulative → validate → sign → countersign.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from pathlib import Path

from traust_ledger.integrity import (
    Severity,
    stamp_merkle_metadata,
    verify_merkle_integrity,
    verify_merkle_signature,
)
from traust_ledger.integrity.ledger import merkle_root_payload
from traust_ledger.integrity.merkle import (
    compute_merkle_root,
    consistency_proof,
    inclusion_proof,
    verify_consistency,
    verify_inclusion,
)
from traust_ledger.integrity.signing import (
    SigningBackend,
    SignResult,
    VerifyResult,
)


def compute_event_id(
    source_ref: str, finding_ref: str, validity: str | None, resolution: str | None
) -> str:
    """Sample event ids, same formula the ledger used (sha256 of the joined fields)."""
    return hashlib.sha256(
        f"{source_ref}|{finding_ref}|{validity or ''}|{resolution or ''}".encode()
    ).hexdigest()


F1 = "TEST_WIDGET-abcdef0-001"
F2 = "TEST_WIDGET-abcdef0-002"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class HmacTestBackend(SigningBackend):
    """Test-only backend using HMAC-SHA256 as a stand-in for cosign.

    Validates:
      - Payload binding: different payloads produce failed verification
      - Tamper detection: modified roots reject against original signature

    Does NOT validate (inherent to symmetric HMAC vs asymmetric signing):
      - Key-role separation: in production, only private-key holder can sign
      - Non-repudiation: HMAC holder can both sign and verify
      - Key path correctness: key_path parameter is ignored

    For asymmetric properties, rely on integration tests with real cosign binary.
    """

    def __init__(self, secret: bytes = b"test-key") -> None:
        self._secret = secret

    @property
    def method_name(self) -> str:
        return "hmac-test"

    def available(self) -> bool:
        return True

    def sign(self, payload: bytes, key_path: str) -> SignResult:
        sig = hmac.new(self._secret, payload, "sha256").digest()
        return SignResult(signature=base64.b64encode(sig).decode(), success=True)

    def verify(self, payload: bytes, signature: str, key_path: str) -> VerifyResult:
        expected = hmac.new(self._secret, payload, "sha256").digest()
        actual = base64.b64decode(signature)
        valid = hmac.compare_digest(expected, actual)
        return VerifyResult(valid=valid, error=None if valid else "signature mismatch")


def _event(
    finding_ref: str,
    validity: str = "confirmed",
    *,
    at: str = "2026-07-01T10:00:00+00:00",
    ref: str = "https://example.com/mr/17#note_1",
) -> dict:
    return {
        "event_id": compute_event_id(ref, finding_ref, validity, None),
        "finding_ref": finding_ref,
        "recorded_at": at,
        "source": {
            "type": "mr_comment",
            "ref": ref,
            "actor": {
                "kind": "human",
                "identity": "jdoe@example.com",
                "ldap_verified": True,
            },
        },
        "disposition": {"validity": validity},
        "rationale": "Because the input is validated upstream in the webhook.",
    }


def _layer(events: list[dict] | None = None) -> dict:
    return {
        "metadata": {
            "audit_report": "test-widget-security-audit.json",
            "audit_commit": "abcdef0123456789abcdef0123456789abcdef01",
            "repository": "https://github.com/example/test-widget",
            "created": "2026-06-01T00:00:00+00:00",
            "harness_version": "0.18.0-1234567",
        },
        "events": list(events or []),
        "needs_review": [],
    }


def _write_layer(path: Path, layer: dict) -> None:
    path.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")


def _read_layer(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _errors(findings: list) -> list:
    return [f for f in findings if f.severity == Severity.ERROR]


def _warnings(findings: list) -> list:
    return [f for f in findings if f.severity == Severity.WARNING]


def _event_entries(events: list[dict]) -> list[bytes]:
    # leaf_format 2 (v0.199.0): leaves are the canonical full-event bytes,
    # not event_ids — proofs must hash the same material the stamp did
    from traust_ledger.integrity.merkle import (
        canonical_event_bytes,
    )

    return [canonical_event_bytes(event) for event in events]


def test_e2e_ci_merkle_pipeline(tmp_path: Path) -> None:
    """Trace Merkle integrity through the full CI disposition pipeline."""
    layer_path = tmp_path / "test-widget-findings-layer.json"
    backend = HmacTestBackend()
    key_path = str(tmp_path / "test-key.pem")

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ Step 1: Create a fresh layer with triage events                     │
    # │                                                                     │
    # │ Tree state: NONE (no Merkle metadata exists yet)                    │
    # │                                                                     │
    # │   events = [E0, E1, E2]   metadata = { no merkle fields }           │
    # │                                                                     │
    # │ Expected: Layer has events but NO merkle_root                       │
    # └─────────────────────────────────────────────────────────────────────┘
    layer = _layer(
        [
            _event(F1, "confirmed", at="2026-07-01T10:00:00+00:00"),
            _event(
                F2,
                "confirmed",
                at="2026-07-01T11:00:00+00:00",
                ref="https://example.com/mr/18#note_1",
            ),
            _event(
                F1,
                "false_positive",
                at="2026-07-02T10:00:00+00:00",
                ref="https://example.com/mr/19#note_1",
            ),
        ]
    )
    _write_layer(layer_path, layer)
    layer = _read_layer(layer_path)
    assert len(layer["events"]) == 3, "Step 1: layer should have triage events"
    assert "merkle_root" not in layer["metadata"], (
        "Step 1: fresh layer must not have merkle_root yet"
    )

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ Step 2: Stamp Merkle metadata (build_cumulative path)               │
    # │                                                                     │
    # │ Tree state after stamp (3 leaves, epoch=0):                         │
    # │                                                                     │
    # │          root₃ = H(H(L₀,L₁), L₂)                                    │
    # │         /    \                                                      │
    # │    H(L₀,L₁)  L₂        where Lᵢ = SHA256(0x00 || event_id[i])       │
    # │    /    \                      H(a,b) = SHA256(0x01 || a || b)      │
    # │   L₀    L₁                                                          │
    # │                                                                     │
    # │ metadata += { merkle_root: root₃, merkle_size: 3,                   │
    # │              merkle_epoch: 0, merkle_algorithm: "sha256" }          │
    # │                                                                     │
    # │ Expected: All four Merkle fields present and correct                │
    # └─────────────────────────────────────────────────────────────────────┘
    stamp_merkle_metadata(layer)
    _write_layer(layer_path, layer)
    meta = layer["metadata"]
    assert meta.get("merkle_root"), "Step 2: merkle_root should be stamped"
    assert meta.get("merkle_size") == len(layer["events"]), (
        "Step 2: merkle_size should equal number of events"
    )
    assert meta.get("merkle_epoch") == 0, "Step 2: merkle_epoch should be 0"
    assert meta.get("merkle_algorithm") == "sha256", "Step 2: merkle_algorithm should be sha256"
    assert HEX64.match(meta["merkle_root"]), (
        "Step 2: merkle_root should be a 64-char hex SHA-256 digest"
    )

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ Step 3: Validate the layer (verify integrity)                       │
    # │                                                                     │
    # │ Tree state: UNCHANGED from Step 2                                   │
    # │ Verifier recomputes root₃ from events → must match declared root    │
    # │                                                                     │
    # │ Expected: No errors, no warnings, independent recomputation matches │
    # └─────────────────────────────────────────────────────────────────────┘
    findings = verify_merkle_integrity(layer)
    assert _errors(findings) == [], "Step 3: integrity check should pass with no errors"
    assert _warnings(findings) == [], "Step 3: integrity check should pass with no warnings"
    recomputed_root, recomputed_size = compute_merkle_root(layer["events"])
    assert meta["merkle_root"] == recomputed_root, (
        "Step 3: stamped merkle_root should match independent recomputation"
    )
    assert meta["merkle_size"] == recomputed_size, (
        "Step 3: stamped merkle_size should match independent recomputation"
    )

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ Step 4: Sign the merkle_root                                        │
    # │                                                                     │
    # │ Tree state: UNCHANGED — signing doesn't alter the tree              │
    # │                                                                     │
    # │   payload = bytes.fromhex(root₃)  →  32 raw bytes                   │
    # │   signature = HMAC-SHA256(secret, payload)  →  base64               │
    # │   metadata += { merkle_root_signature: "<base64>" }                 │
    # │                                                                     │
    # │ Expected: Signature covers exactly the 32-byte root hash            │
    # └─────────────────────────────────────────────────────────────────────┘
    payload = merkle_root_payload(meta["merkle_root"])
    assert len(payload) == 32, "Step 4: merkle_root payload should be 32 raw bytes"
    sign_result = backend.sign(payload, key_path)
    assert sign_result.success, "Step 4: mock signing should succeed"
    meta["merkle_root_signature"] = sign_result.signature
    meta["merkle_signing_method"] = backend.method_name
    _write_layer(layer_path, layer)
    assert meta.get("merkle_root_signature"), "Step 4: merkle_root_signature should be populated"
    assert meta.get("merkle_signing_method") == "hmac-test", (
        "Step 4: merkle_signing_method should record the backend's method_name"
    )
    assert base64.b64decode(meta["merkle_root_signature"]), (
        "Step 4: merkle_root_signature should be valid base64"
    )
    verify_payload = backend.verify(payload, meta["merkle_root_signature"], key_path)
    assert verify_payload.valid, (
        "Step 4: signature should cover exactly the raw 32-byte merkle_root hash"
    )

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ Step 5: Validate signed layer (integrity + signature)               │
    # │                                                                     │
    # │ Tree state: UNCHANGED — verification is read-only                   │
    # │ Checks: root recomputation ✓ AND signature over root ✓              │
    # │                                                                     │
    # │ Expected: Both integrity and signature checks pass                  │
    # └─────────────────────────────────────────────────────────────────────┘
    signed_root = meta["merkle_root"]
    findings = verify_merkle_integrity(layer)
    assert _errors(findings) == [], "Step 5: integrity check should still pass after signing"
    sig_findings = verify_merkle_signature(layer, key_path, backend=backend)
    assert _errors(sig_findings) == [], "Step 5: verify_merkle_signature should return no errors"
    assert backend.verify(
        merkle_root_payload(signed_root),
        meta["merkle_root_signature"],
        key_path,
    ).valid, "Step 5: mock backend should confirm signature valid=True"

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ Step 6: Append events (countersign adds human decisions)            │
    # │                                                                     │
    # │ Tree grows from 3 → 5 leaves:                                       │
    # │                                                                     │
    # │              root₅ = H(H(H(L₀,L₁),H(L₂,L₃)), L₄)                    │
    # │             /          \                                            │
    # │      H(H(L₀,L₁),       L₄                                           │
    # │        H(L₂,L₃))                                                    │
    # │       /       \                                                     │
    # │  H(L₀,L₁)  H(L₂,L₃)                                                 │
    # │  /    \     /    \                                                  │
    # │ L₀   L₁   L₂   L₃                                                   │
    # │                                                                     │
    # │ root₅ ≠ root₃ (append changes root), size: 3 → 5                    │
    # │ The signature over root₃ no longer describes the layer, so the      │
    # │ stamp DROPS it (traust-ledger 0.1.7) rather than leave a signature    │
    # │ that verifies against nothing. A writer with a key re-signs; this   │
    # │ test does so explicitly, standing in for that write path.           │
    # │                                                                     │
    # │ Expected: New root, increased size, signature dropped then renewed  │
    # └─────────────────────────────────────────────────────────────────────┘
    old_root = meta["merkle_root"]
    old_size = meta["merkle_size"]
    old_root_bytes = bytes.fromhex(old_root)
    new_events = [
        _event(
            F2,
            "confirmed",
            at="2026-07-03T10:00:00+00:00",
            ref="https://example.com/mr/20#note_1",
        ),
        _event(
            F1,
            "confirmed",
            at="2026-07-03T11:00:00+00:00",
            ref="https://example.com/mr/21#note_1",
        ),
    ]
    layer["events"].extend(new_events)
    dropped = stamp_merkle_metadata(layer)
    assert dropped is True, "Step 6: a root that moved must drop the signature it invalidated"
    assert "merkle_root_signature" not in meta, (
        "Step 6: the stale signature must not survive the re-stamp — a "
        "present-but-invalid signature is indistinguishable from tampering"
    )

    # Re-sign, as a write path with a key configured does. Everything below
    # depends on the layer being validly signed at its CURRENT root.
    resign = backend.sign(merkle_root_payload(meta["merkle_root"]), key_path)
    assert resign.success, "Step 6: re-signing the new root should succeed"
    meta["merkle_root_signature"] = resign.signature
    meta["merkle_signing_method"] = backend.method_name

    _write_layer(layer_path, layer)
    assert meta["merkle_root"] != old_root, (
        "Step 6: re-stamping after append should change merkle_root"
    )
    assert meta["merkle_size"] == old_size + len(new_events), (
        "Step 6: merkle_size should increase by number of appended events"
    )
    assert old_root != meta["merkle_root"], (
        "Step 6: append-only growth must produce a different root"
    )

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ Step 7: Consistency proof (old state → new state)                   │
    # │                                                                     │
    # │ Proves: tree₃ is a prefix of tree₅ — only appends, no edits         │
    # │                                                                     │
    # │   proof = SUBPROOF(3, leaves₅, true)                                │
    # │   verify_consistency(root₃, root₅, 3, 5, proof) → True              │
    # │                                                                     │
    # │ This is the append-only guarantee: anyone who recorded root₃        │
    # │ can verify that root₅ extends it without altering history.          │
    # │                                                                     │
    # │ Expected: Consistency proof verifies successfully                   │
    # └─────────────────────────────────────────────────────────────────────┘
    new_root_bytes = bytes.fromhex(meta["merkle_root"])
    new_size = meta["merkle_size"]
    entries = _event_entries(layer["events"])
    proof = consistency_proof(entries, old_size)
    assert verify_consistency(old_root_bytes, new_root_bytes, old_size, new_size, proof), (
        "Step 7: consistency proof should verify — events only appended, not altered"
    )

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ Step 8: Inclusion proof for each event                              │
    # │                                                                     │
    # │ Tree state: 5-leaf tree (same as Step 6/7)                          │
    # │                                                                     │
    # │ For each leaf index i ∈ [0..4]:                                     │
    # │   proof = sibling hashes along path from Lᵢ to root₅                │
    # │   verify_inclusion(root₅, Lᵢ, i, 5, proof) → True                   │
    # │                                                                     │
    # │ Expected: Every event has a valid inclusion proof                   │
    # └─────────────────────────────────────────────────────────────────────┘
    for index in range(new_size):
        entry = entries[index]
        proof = inclusion_proof(entries, index)
        assert verify_inclusion(new_root_bytes, entry, index, new_size, proof), (
            f"Step 8: inclusion proof should verify for event index {index}"
        )

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ Step 9: TAMPER — edit event content                                 │
    # │                                                                     │
    # │ Attacker changes events[1].finding_ref → new event_id               │
    # │ Declared root₅ remains unchanged but recomputation yields root₅'    │
    # │                                                                     │
    # │   root₅' ≠ root₅  →  merkle_root mismatch ERROR                     │
    # │                                                                     │
    # │ Expected: Integrity check catches content edit                      │
    # └─────────────────────────────────────────────────────────────────────┘
    tampered_edit = json.loads(json.dumps(layer))
    tampered_event = tampered_edit["events"][1]
    tampered_event["finding_ref"] = "TAMPERED-FINDING-REF"
    tampered_event["event_id"] = compute_event_id(
        tampered_event["source"]["ref"],
        tampered_event["finding_ref"],
        tampered_event["disposition"]["validity"],
        None,
    )
    findings = verify_merkle_integrity(tampered_edit)
    edit_errors = _errors(findings)
    assert edit_errors, "Step 9: tampered finding_ref should produce integrity errors"
    assert any("merkle_root mismatch" in f.message for f in edit_errors), (
        "Step 9: tampering should be detected via merkle_root mismatch"
    )
    declared = tampered_edit["metadata"]["merkle_root"]
    recomputed, _ = compute_merkle_root(tampered_edit["events"])
    assert declared != recomputed, "Step 9: declared root should no longer match recomputed root"

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ Step 10: TAMPER — delete event from middle                          │
    # │                                                                     │
    # │ Attacker removes events[2]; tree would be 4-leaf if recomputed      │
    # │ Declared: root₅, size=5  vs  actual: root₄', size=4                 │
    # │                                                                     │
    # │ Expected: Both root mismatch AND size mismatch errors               │
    # └─────────────────────────────────────────────────────────────────────┘
    tampered_delete = json.loads(json.dumps(layer))
    del tampered_delete["events"][2]
    findings = verify_merkle_integrity(tampered_delete)
    delete_errors = _errors(findings)
    assert delete_errors, "Step 10: deleted event should produce integrity errors"
    assert any("merkle_root mismatch" in f.message for f in delete_errors), (
        "Step 10: deletion should be detected via merkle_root mismatch"
    )
    assert any("merkle_size mismatch" in f.message for f in delete_errors), (
        "Step 10: deletion should be detected via merkle_size mismatch"
    )

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ Step 11: TAMPER — reorder events                                    │
    # │                                                                     │
    # │ Attacker swaps events[0] ↔ events[1]; all content preserved         │
    # │ Leaf order changes: H(L₁,L₀,...) ≠ H(L₀,L₁,...)                     │
    # │   → root differs even though set of events is identical             │
    # │                                                                     │
    # │ Expected: Root mismatch error (order is part of integrity)          │
    # └─────────────────────────────────────────────────────────────────────┘
    tampered_reorder = json.loads(json.dumps(layer))
    tampered_reorder["events"][0], tampered_reorder["events"][1] = (
        tampered_reorder["events"][1],
        tampered_reorder["events"][0],
    )
    findings = verify_merkle_integrity(tampered_reorder)
    reorder_errors = _errors(findings)
    assert reorder_errors, "Step 11: reordered events should produce integrity errors"
    assert any("merkle_root mismatch" in f.message for f in reorder_errors), (
        "Step 11: reordering should be detected via merkle_root mismatch"
    )

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ Step 12: TAMPER — attacker recomputes root after edit               │
    # │                                                                     │
    # │ Sophisticated attack: edit content AND update declared root         │
    # │                                                                     │
    # │   events[1] mutated → recompute root₅'' and set it in metadata      │
    # │   Integrity check passes (root matches tampered tree)               │
    # │   BUT signature was over original root₅ ≠ root₅''                   │
    # │   → signature verification FAILS                                    │
    # │                                                                     │
    # │ This proves why signing matters: without signature, a               │
    # │ colluding writer can tamper + re-sign to hide changes.              │
    # │                                                                     │
    # │ Expected: Integrity passes, signature fails                         │
    # └─────────────────────────────────────────────────────────────────────┘
    attacker_layer = json.loads(json.dumps(layer))
    attacker_event = attacker_layer["events"][1]
    attacker_event["finding_ref"] = "ATTACKER-EDITED-REF"
    attacker_event["event_id"] = compute_event_id(
        attacker_event["source"]["ref"],
        attacker_event["finding_ref"],
        attacker_event["disposition"]["validity"],
        None,
    )
    attacker_root, attacker_size = compute_merkle_root(attacker_layer["events"])
    attacker_layer["metadata"]["merkle_root"] = attacker_root
    attacker_layer["metadata"]["merkle_size"] = attacker_size
    findings = verify_merkle_integrity(attacker_layer)
    assert _errors(findings) == [], (
        "Step 12: attacker-recomputed root should pass integrity against tampered events"
    )
    sig_findings = verify_merkle_signature(attacker_layer, key_path, backend=backend)
    assert _errors(sig_findings), (
        "Step 12: signature check should fail when root was replaced after signing"
    )
    assert any("verification failed" in f.message for f in _errors(sig_findings)), (
        "Step 12: signature anchors root to identity — old signature invalid on new root"
    )
    assert (
        backend.verify(
            merkle_root_payload(attacker_root),
            attacker_layer["metadata"]["merkle_root_signature"],
            key_path,
        ).valid
        is False
    ), "Step 12: mock backend should reject signature over attacker-replaced root"

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ Step 13: TAMPER — truncate events from the end                      │
    # │                                                                     │
    # │ Attacker removes the last 2 events (5 → 3); tree shrinks            │
    # │ Declared: root₅, size=5  vs  actual: root₃', size=3                 │
    # │                                                                     │
    # │ Unlike middle-deletion (Step 10), end-truncation preserves the      │
    # │ relative order of remaining events. The tree still detects it       │
    # │ because both root and size change.                                  │
    # │                                                                     │
    # │ Expected: Both root mismatch AND size mismatch errors               │
    # └─────────────────────────────────────────────────────────────────────┘
    tampered_truncate = json.loads(json.dumps(layer))
    assert len(tampered_truncate["events"]) == 5, (
        "Step 13: precondition — layer should have 5 events before truncation"
    )
    tampered_truncate["events"] = tampered_truncate["events"][:3]
    findings = verify_merkle_integrity(tampered_truncate)
    truncate_errors = _errors(findings)
    assert truncate_errors, "Step 13: truncated events should produce integrity errors"
    assert any("merkle_root mismatch" in f.message for f in truncate_errors), (
        "Step 13: end-truncation should be detected via merkle_root mismatch"
    )
    assert any("merkle_size mismatch" in f.message for f in truncate_errors), (
        "Step 13: end-truncation should be detected via merkle_size mismatch"
    )

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ Step 14: TAMPER — epoch manipulation                                │
    # │                                                                     │
    # │ a) Set merkle_epoch=3 but keep root computed at epoch=0.            │
    # │    verify_merkle_integrity slices events[3:] (2 events), whose      │
    # │    root ≠ the declared root (computed over all 5 events).           │
    # │                                                                     │
    # │ b) Set merkle_epoch=-1 (invalid negative value).                    │
    # │    Verifier should return an ERROR for negative epoch.              │
    # │                                                                     │
    # │ Expected: (a) root mismatch + size mismatch, (b) negative epoch     │
    # └─────────────────────────────────────────────────────────────────────┘
    tampered_epoch = json.loads(json.dumps(layer))
    tampered_epoch["metadata"]["merkle_epoch"] = 3
    findings = verify_merkle_integrity(tampered_epoch)
    epoch_errors = _errors(findings)
    assert epoch_errors, (
        "Step 14a: shifting epoch without re-stamping should produce integrity errors"
    )
    assert any("merkle_root mismatch" in f.message for f in epoch_errors), (
        "Step 14a: epoch shift should be detected via merkle_root mismatch"
    )
    assert any("merkle_size mismatch" in f.message for f in epoch_errors), (
        "Step 14a: epoch shift should be detected via merkle_size mismatch"
    )

    tampered_neg_epoch = json.loads(json.dumps(layer))
    tampered_neg_epoch["metadata"]["merkle_epoch"] = -1
    findings = verify_merkle_integrity(tampered_neg_epoch)
    neg_epoch_errors = _errors(findings)
    assert neg_epoch_errors, "Step 14b: negative merkle_epoch should produce an error"
    assert any("negative" in f.message for f in neg_epoch_errors), (
        "Step 14b: error should mention negative epoch"
    )

    # ┌─────────────────────────────────────────────────────────────────────┐
    # │ Step 15: TAMPER — signature stripping (F-5)                         │
    # │                                                                     │
    # │ Attacker deletes merkle_root_signature from a signed layer.         │
    # │ Previously verify_merkle_signature returned [] (no findings),       │
    # │ allowing silent bypass. Now it must return a WARNING when           │
    # │ merkle_root is present but signature is absent.                     │
    # │                                                                     │
    # │ Expected: At least one WARNING about unsigned integrity             │
    # └─────────────────────────────────────────────────────────────────────┘
    stripped = json.loads(json.dumps(layer))
    assert stripped["metadata"].get("merkle_root"), (
        "Step 15: precondition — layer should have merkle_root"
    )
    stripped["metadata"].pop("merkle_root_signature", None)
    sig_findings = verify_merkle_signature(stripped, key_path, backend=backend, required=True)
    # v0.202.0 (self-audit -006): with signing required a
    # stripped signature is an ERROR, not a warning — deleting the
    # signature must never be a downgrade path
    stripped_errors = _errors(sig_findings)
    assert stripped_errors, "Step 15: signature-stripped layer should produce an ERROR"
    assert any("absent" in f.message for f in stripped_errors), (
        "Step 15: error should indicate the signature is absent"
    )


def test_signing_method_mismatch(tmp_path: Path) -> None:
    """Verify that method mismatch between signer and verifier fails gracefully."""
    backend_a = HmacTestBackend(secret=b"key-a")
    backend_b = HmacTestBackend(secret=b"key-b")

    layer = _layer([_event(F1, "confirmed", at="2026-07-01T10:00:00+00:00")])
    stamp_merkle_metadata(layer)
    meta = layer["metadata"]

    payload = merkle_root_payload(meta["merkle_root"])
    sign_result = backend_a.sign(payload, "unused")
    assert sign_result.success
    meta["merkle_root_signature"] = sign_result.signature
    meta["merkle_signing_method"] = backend_a.method_name

    sig_findings = verify_merkle_signature(layer, "unused", backend=backend_b)
    errors = _errors(sig_findings)
    assert errors, "Method mismatch: verification with a different backend should produce errors"
    assert any("verification failed" in f.message for f in errors), (
        "Method mismatch: error should indicate signature verification failure"
    )
    assert not any(isinstance(f, Exception) for f in errors), (
        "Method mismatch: should fail gracefully with findings, not exceptions"
    )


def test_signing_method_stored_in_metadata(tmp_path: Path) -> None:
    """Verify merkle_signing_method is correctly written and read from metadata."""
    backend = HmacTestBackend()
    layer = _layer([_event(F1, "confirmed", at="2026-07-01T10:00:00+00:00")])
    stamp_merkle_metadata(layer)
    meta = layer["metadata"]

    payload = merkle_root_payload(meta["merkle_root"])
    sign_result = backend.sign(payload, "unused")
    meta["merkle_root_signature"] = sign_result.signature
    meta["merkle_signing_method"] = backend.method_name

    layer_path = tmp_path / "test-layer.json"
    _write_layer(layer_path, layer)
    loaded = _read_layer(layer_path)
    assert loaded["metadata"]["merkle_signing_method"] == "hmac-test"
    assert loaded["metadata"]["merkle_root_signature"] == sign_result.signature


def test_legacy_layer_without_signing_method(tmp_path: Path) -> None:
    """Legacy layers without merkle_signing_method should still verify (backward compat)."""
    backend = HmacTestBackend()
    layer = _layer([_event(F1, "confirmed", at="2026-07-01T10:00:00+00:00")])
    stamp_merkle_metadata(layer)
    meta = layer["metadata"]

    payload = merkle_root_payload(meta["merkle_root"])
    sign_result = backend.sign(payload, "unused")
    meta["merkle_root_signature"] = sign_result.signature
    # deliberately omit merkle_signing_method to simulate legacy layer

    sig_findings = verify_merkle_signature(layer, "unused", backend=backend)
    assert _errors(sig_findings) == [], (
        "Legacy layer without merkle_signing_method should still verify"
    )
