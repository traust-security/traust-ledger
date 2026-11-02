"""Ledger integrity service — stamps and verifies Merkle metadata on layer files."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum

from .merkle import (
    LEAF_FORMAT_CURRENT,
    compute_merkle_root,
    compute_pre_epoch_checkpoint,
)
from .restatements import SIGNED_METADATA_FIELDS, terminal_value
from .signing import (
    SigningBackend,
    SigningConfig,
    get_backend,
    get_backend_for_method,
    get_backend_from_config,
)

SIGNING_TOOL_NOT_FOUND = (
    "signing tool not found — install a compatible signing backend to sign Merkle roots"
)

__all__ = [
    "SIGNATURE_FORMAT_CURRENT",
    "SIGNING_TOOL_NOT_FOUND",
    "IntegrityFinding",
    "Severity",
    "SignAttempt",
    "merkle_root_payload",
    "merkle_signature_payload",
    "sign_if_configured",
    "stamp_merkle_metadata",
    "verify_merkle_integrity",
    "verify_merkle_signature",
    "verify_restated_metadata",
]


class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"


@dataclass
class IntegrityFinding:
    severity: Severity
    message: str


def stamp_merkle_metadata(layer: dict) -> bool:
    """Update Merkle fields in layer metadata after events change.

    Returns True when a now-stale `merkle_root_signature` was dropped because
    the recomputed root differs from the one the signature covered. Callers
    that report signing outcomes should surface that: a signature silently
    disappearing is how a corpus de-attests without anyone noticing.

    Sets merkle_root, merkle_size, merkle_algorithm, and leaf_format
    (always the current format — restamping upgrades a legacy layer's
    binding to full event content). On first Merkle-enabled write, sets
    merkle_epoch (default 0 — all events in the tree). When merkle_epoch
    > 0, pins pre-epoch events via pre_merkle_checkpoint.

    An out-of-range merkle_epoch is REFUSED (ValueError), never silently
    reset: a reset would let a truncated events array restamp cleanly and
    hide the truncation.
    """
    events = layer.get("events") or []
    meta = layer.setdefault("metadata", {})

    if "merkle_epoch" not in meta:
        meta["merkle_epoch"] = 0

    epoch = int(meta["merkle_epoch"])
    if epoch < 0:
        raise ValueError(
            f"metadata.merkle_epoch is negative ({epoch}) — refusing to "
            "stamp; fix the layer metadata explicitly"
        )
    if len(events) == 0:
        if epoch != 0:
            raise ValueError(
                f"metadata.merkle_epoch is {epoch} but the events array is "
                "empty — refusing to stamp over what looks like a truncated "
                "ledger; restore the events or reset merkle_epoch explicitly"
            )
    elif epoch >= len(events):
        raise ValueError(
            f"metadata.merkle_epoch ({epoch}) is out of range for "
            f"{len(events)} event(s) — refusing to stamp over what looks "
            "like a truncated ledger; restore the events or reset "
            "merkle_epoch explicitly"
        )

    pre_epoch = events[:epoch]
    post_epoch = events[epoch:]

    if epoch > 0:
        meta["pre_merkle_checkpoint"] = compute_pre_epoch_checkpoint(pre_epoch)
    else:
        meta.pop("pre_merkle_checkpoint", None)

    prior_root = meta.get("merkle_root")

    root, size = compute_merkle_root(post_epoch, leaf_format=LEAF_FORMAT_CURRENT)
    meta["merkle_root"] = root
    meta["merkle_size"] = size
    meta["merkle_algorithm"] = "sha256"
    meta["leaf_format"] = LEAF_FORMAT_CURRENT

    # A signature covers the root it was made over. Once the root moves, the
    # stored signature describes a layer that no longer exists, so keeping it is
    # worse than having none: an absent signature is a visible gap, while a
    # present-but-invalid one is indistinguishable from tampering to every
    # verifier. Drop it here rather than in sign_if_configured, so it happens
    # exactly when the root actually changed — a re-stamp that produces the same
    # root leaves a still-valid signature alone.
    #
    # Found 2026-08-17: a 5.0 embargo backfill appended events to 9
    # signed layers with no signing key configured, so sign_if_configured
    # no-oped as `unconfigured` and all 9 kept a signature over the old root.
    # Every one failed verification. Until the key reaches the write path
    # (plan P8), any corpus pass that rewrites signed layers reproduces that at
    # scale — which is precisely what plan items B7 and P2's 417 layers do.
    if prior_root is not None and prior_root != root:
        for key in (
            "merkle_root_signature",
            "merkle_signing_method",
            "merkle_signature_format",
        ):
            meta.pop(key, None)
        return True

    return False


@dataclass
class SignAttempt:
    """Outcome of `sign_if_configured`. `status` is one of:

    * `unconfigured` — no signing key configured; the layer was left untouched.
      This is the expected state until a key is provisioned, and is NOT an error.
    * `signed`       — `metadata.merkle_root_signature` was set.
    * `failed`       — a key WAS configured but signing did not succeed. Callers
      must surface this: a configured-but-broken signer that degrades to silence
      is how a ledger ends up unsigned while everyone believes it is signed.
    """

    status: str
    method: str | None = None
    error: str | None = None
    stale_signature_dropped: bool = False

    @property
    def configured(self) -> bool:
        return self.status != "unconfigured"

    def warning(self) -> str | None:
        """The one thing a writer must print, or None when nothing is wrong.

        Exists so callers do not hand-roll the same conditional and disagree
        about which outcomes are reportable.
        """
        if self.status == "failed":
            return f"Merkle root stamped but NOT signed ({self.error})"
        if self.stale_signature_dropped:
            return (
                "the events changed, so the previous merkle_root_signature no "
                "longer covered this layer and was dropped; the layer is now "
                "UNSIGNED. Configure a signing key to re-sign on write."
            )
        return None


def sign_if_configured(layer: dict, config: SigningConfig) -> SignAttempt:
    """Sign `metadata.merkle_root` in place when a signing key is configured.

    The write-path counterpart to `stamp_merkle_metadata`. Every writer stamps a
    Merkle root; until this existed, nothing signed one, because signing lived
    only in a separate CLI and no write path invoked it — so no stored layer
    carried a signature. An unsigned root detects an accident but not an
    adversary, who can simply restamp.

    Call AFTER `stamp_merkle_metadata`, since the signature covers the stamped
    metadata (root + leaf_format + epoch + size + pre-epoch checkpoint) via
    `merkle_signature_payload`. Signing before stamping would sign a stale root.

    With no key in `config` this is a no-op returning `unconfigured`, so
    wiring it into a writer is safe before any key exists. Whether signing is
    required is the caller's decision.
    """
    key_path = getattr(config, "key_path", None)
    if not key_path:
        return SignAttempt("unconfigured")

    meta = layer.get("metadata") or {}
    if not meta.get("merkle_root"):
        return SignAttempt(
            "failed",
            method="keypair",
            error="no metadata.merkle_root to sign — call stamp_merkle_metadata() first",
        )

    try:
        backend = get_backend_from_config(config)
        result = backend.sign(merkle_signature_payload(meta), key_path)
    except Exception as e:  # backend/tool unavailable
        return SignAttempt("failed", method="keypair", error=str(e))

    if not getattr(result, "success", False):
        return SignAttempt(
            "failed", method="keypair", error=getattr(result, "error", None) or "sign failed"
        )

    meta["merkle_root_signature"] = result.signature
    meta["merkle_signing_method"] = backend.method_name
    meta["merkle_signature_format"] = SIGNATURE_FORMAT_CURRENT
    layer["metadata"] = meta
    return SignAttempt("signed", method=backend.method_name)


def verify_restated_metadata(layer: dict) -> list[IntegrityFinding]:
    """Restated entries must still hold the value their chain last gave them.

    Per key, because the chain carries deltas: an entry nobody restated is
    genuinely unconstrained here, and one that was restated is pinned to the
    last value a signed, in-tree event assigned it. A field with no chain is
    not examined -- there is nothing to compare it to.
    """
    meta = layer.get("metadata") or {}
    events = layer.get("events") or []
    findings: list[IntegrityFinding] = []
    for field in SIGNED_METADATA_FIELDS:
        restated, expected = terminal_value(events, field)
        if not restated:
            continue
        actual = meta.get(field)
        if isinstance(expected, dict):
            drifted = sorted(
                key
                for key, value in expected.items()
                if not isinstance(actual, dict) or actual.get(key) != value
            )
            if not drifted:
                continue
            detail = f"entries {', '.join(drifted)}"
        elif actual == expected:
            continue
        else:
            detail = "the value"
        findings.append(
            IntegrityFinding(
                severity=Severity.ERROR,
                message=(
                    f"metadata.{field}: {detail} do not match the terminal state of "
                    f"the restatement chain \u2014 rewritten out-of-band after the last "
                    f"restatement, or a restatement event was removed while its "
                    f"effect on metadata remained"
                ),
            )
        )
    return findings


def verify_merkle_integrity(layer: dict) -> list[IntegrityFinding]:
    """Verify Merkle metadata matches the events array.

    Returns a list of findings (errors and warnings). Empty list = all good.

    Merkle checks read the STORED events, never the restated projection.
    """
    findings: list[IntegrityFinding] = []
    meta = layer.get("metadata") or {}
    events = layer.get("events") or []
    merkle_root = meta.get("merkle_root")

    if merkle_root is None:
        findings.append(
            IntegrityFinding(
                severity=Severity.ERROR,
                message=(
                    "metadata.merkle_root absent — the layer has no tamper-evidence "
                    "at all; run stamp_merkle_metadata (or your layer writer) to "
                    "stamp Merkle fields"
                ),
            )
        )
        return findings

    try:
        epoch = int(meta.get("merkle_epoch", 0))
    except (TypeError, ValueError):
        findings.append(
            IntegrityFinding(
                severity=Severity.ERROR,
                message=(
                    f"metadata.merkle_epoch {meta.get('merkle_epoch')!r} is "
                    f"not an integer — invalid"
                ),
            )
        )
        return findings
    if epoch < 0:
        findings.append(
            IntegrityFinding(
                severity=Severity.ERROR,
                message=f"metadata.merkle_epoch is negative ({epoch}) — invalid",
            )
        )
        return findings

    if len(events) > 0:
        if epoch > len(events):
            findings.append(
                IntegrityFinding(
                    severity=Severity.ERROR,
                    message="merkle_epoch exceeds event count",
                )
            )
            return findings
        if epoch == len(events):
            findings.append(
                IntegrityFinding(
                    severity=Severity.ERROR,
                    message=("merkle_epoch equals event count — Merkle tree covers no events"),
                )
            )
            return findings

    leaf_format = meta.get("leaf_format", 1)
    try:
        leaf_format = int(leaf_format)
    except (TypeError, ValueError):
        leaf_format = -1
    if leaf_format not in (1, LEAF_FORMAT_CURRENT):
        findings.append(
            IntegrityFinding(
                severity=Severity.ERROR,
                message=(
                    f"metadata.leaf_format {meta.get('leaf_format')!r} is "
                    f"not a known Merkle leaf format"
                ),
            )
        )
        return findings
    if leaf_format == 1:
        findings.append(
            IntegrityFinding(
                severity=Severity.ERROR,
                message=(
                    "LEGACY MERKLE LEAF FORMAT (v1): the Merkle root binds "
                    "only event_id values — event CONTENT (actor, rationale, "
                    "timestamps, evidence) is NOT bound and could be edited "
                    "under a still-verifying root/signature. Re-stamp the "
                    "layer (any recording tool run upgrades it) to bind full "
                    "event content (leaf_format 2)."
                ),
            )
        )

    post_epoch = events[epoch:]
    computed_root, computed_size = compute_merkle_root(post_epoch, leaf_format=leaf_format)

    if merkle_root != computed_root:
        findings.append(
            IntegrityFinding(
                severity=Severity.ERROR,
                message=(
                    f"metadata.merkle_root mismatch — declared {merkle_root}, "
                    f"recomputed {computed_root} from {len(post_epoch)} post-epoch "
                    f"event(s)"
                ),
            )
        )

    declared_size = meta.get("merkle_size")
    if declared_size is not None and declared_size != computed_size:
        findings.append(
            IntegrityFinding(
                severity=Severity.ERROR,
                message=(
                    f"metadata.merkle_size mismatch — declared {declared_size}, "
                    f"but {computed_size} post-epoch event(s) hash into the tree"
                ),
            )
        )

    if epoch > 0:
        checkpoint = meta.get("pre_merkle_checkpoint")
        if checkpoint is None:
            findings.append(
                IntegrityFinding(
                    severity=Severity.ERROR,
                    message=(
                        f"metadata.merkle_epoch is {epoch} but pre_merkle_checkpoint "
                        f"is absent — pre-epoch history is unpinned, so any "
                        f"number of earlier events could have been removed or "
                        f"rewritten without detection"
                    ),
                )
            )
        else:
            expected = compute_pre_epoch_checkpoint(events[:epoch])
            if checkpoint != expected:
                findings.append(
                    IntegrityFinding(
                        severity=Severity.ERROR,
                        message=(
                            "metadata.pre_merkle_checkpoint mismatch — pre-epoch "
                            "events were edited or the checkpoint is stale"
                        ),
                    )
                )
    elif meta.get("pre_merkle_checkpoint") is not None:
        expected = compute_pre_epoch_checkpoint([])
        if meta["pre_merkle_checkpoint"] != expected:
            findings.append(
                IntegrityFinding(
                    severity=Severity.ERROR,
                    message=(
                        "metadata.pre_merkle_checkpoint present at merkle_epoch 0 "
                        "but does not match an empty pre-epoch event set"
                    ),
                )
            )

    findings.extend(verify_restated_metadata(layer))

    return findings


def merkle_root_payload(merkle_root: str) -> bytes:
    """Raw 32-byte payload signed for a metadata.merkle_root hex string.

    LEGACY (signature format 1): binds nothing but the bare root — kept
    only to verify existing signatures. New signatures use
    merkle_signature_payload (format 2).
    """
    return bytes.fromhex(merkle_root)


SIGNATURE_FORMAT_CURRENT = 4


def merkle_signature_payload(meta: dict, fmt: int = SIGNATURE_FORMAT_CURRENT) -> bytes:
    """Signed payload: binds the root AND its interpretation.

    A bare-root signature (format 1) can be transplanted onto any layer
    that reproduces the same root, replayed after a rollback to a
    previously-signed state, or re-scoped by editing leaf_format/epoch
    under the same signature (self-audit -005b/-006). Format 2 signs a
    digest over the root plus leaf_format, epoch, size, the pre-epoch
    checkpoint, and a digest of metadata.claim_hashes — so a signed
    layer also pins its baseline claim hashes (self-audit -014).

    **Format 3 (2026-08-18, plan §4.4.0a) adds `audit_report_sha256`.**
    Without it the digest recording *which bytes this layer annotates* sat
    outside the signature, so anyone able to write the layer could point it at a
    substituted report by rewriting the digest to match — provenance, but not
    tamper-evidence. Binding it closes the last gap between what the ledger
    claims and what a verifier can check: events (via the root), claims (via the
    claim-hash digest), and now the annotated report itself.

    **No format 5 for restatements (2026-09-01).** A restatement is an appended
    event, so it is inside `merkle_root`, and the values it authorises are
    already bound by format 4. A new format would re-sign every existing
    layer to bind data that is bound already.

    `fmt` is explicit so the verifier can reconstruct a payload for a layer
    signed under an older format. Signing always uses the current one.
    """
    claim = meta.get("claim_hashes")
    claim_digest = (
        hashlib.sha256(
            json.dumps(claim, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if claim
        else None
    )
    doc = {
        "merkle_root": meta.get("merkle_root"),
        "leaf_format": meta.get("leaf_format", 1),
        "merkle_epoch": meta.get("merkle_epoch", 0),
        "merkle_size": meta.get("merkle_size"),
        "pre_merkle_checkpoint": meta.get("pre_merkle_checkpoint"),
        "claim_hashes_digest": claim_digest,
    }
    if fmt >= 3:
        # Absent on a layer whose report could not be resolved; None is a
        # distinct, signed value, so a later backfill of the digest correctly
        # invalidates the signature rather than passing silently.
        doc["audit_report_sha256"] = meta.get("audit_report_sha256")
    if fmt >= 4:
        # **Format 4 (2026-08-21, plan R1) adds a digest over
        # `metadata.artifact_digests`.** Format 3 binds the ONE report a layer
        # annotates; every other artifact beside it — triage, threat model,
        # findings-current, verification, privilege profile — had no digest
        # anywhere, so 85% of what is being copied to object storage could not be
        # verified after the move. That is acceptable while git still holds the
        # original and unacceptable as a basis for deleting it, which is the
        # entire point of the migration. Binding the map, not the files, keeps
        # this one field per layer instead of one per artifact.
        arts = meta.get("artifact_digests")
        doc["artifact_digests_digest"] = (
            hashlib.sha256(
                json.dumps(arts, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            if arts
            else None
        )
    return hashlib.sha256(
        json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).digest()


def verify_merkle_signature(
    layer: dict,
    pubkey_path: str | None = None,
    backend: SigningBackend | None = None,
    *,
    required: bool = False,
) -> list[IntegrityFinding]:
    """Verify merkle_root_signature if present and pubkey is configured.

    Dispatches to the correct backend based on merkle_signing_method when no
    explicit backend is provided. Defaults to keypair when
    merkle_signing_method is absent.
    """
    meta = layer.get("metadata") or {}
    signature = meta.get("merkle_root_signature")
    if not signature:
        if meta.get("merkle_root") and required:
            return [
                IntegrityFinding(
                    severity=Severity.ERROR,
                    message=(
                        "merkle_root_signature absent but signing is "
                        "required — an unsigned layer "
                        "must not pass (deleting the signature is not a "
                        "downgrade path; self-audit -006)"
                    ),
                )
            ]
        return []
    if pubkey_path is None:
        return [
            IntegrityFinding(
                severity=Severity.WARNING,
                message=(
                    "merkle_root_signature present but no public key configured for verification"
                ),
            )
        ]
    merkle_root = meta.get("merkle_root")
    if not merkle_root:
        return [
            IntegrityFinding(
                severity=Severity.ERROR,
                message=("merkle_root_signature present but metadata.merkle_root is absent"),
            )
        ]

    if backend is not None:
        signer = backend
    else:
        declared_method = meta.get("merkle_signing_method")
        if declared_method is not None:
            try:
                signer = get_backend_for_method(declared_method)
            except ValueError:
                return [
                    IntegrityFinding(
                        severity=Severity.ERROR,
                        message=(
                            f"merkle_signing_method {declared_method!r} is not "
                            f"a recognized signing method"
                        ),
                    )
                ]
        else:
            signer = get_backend()

    if not signer.available():
        return [
            IntegrityFinding(
                severity=Severity.WARNING,
                message=(
                    f"{signer.method_name} signing backend not available — cannot verify signature"
                ),
            )
        ]
    sig_format = meta.get("merkle_signature_format", 1)
    format_findings: list[IntegrityFinding] = []
    if sig_format == SIGNATURE_FORMAT_CURRENT:
        payload = merkle_signature_payload(meta)
    elif sig_format == 3:
        # Accepted during the format-4 migration, same reasoning as format 2 was
        # accepted during the format-3 one: format 3 binds the root, its
        # interpretation, the claim hashes and the annotated report — only the
        # sibling artifacts' digests are outside it.
        payload = merkle_signature_payload(meta, fmt=3)
    elif sig_format == 2:
        # Accepted without complaint during the format-3 migration: layers signed
        # before it carry format 2, and warning on each would drown the signal it
        # is meant to carry. Format 2 binds the root, its interpretation and the claim
        # hashes — only audit_report_sha256 is outside it.
        payload = merkle_signature_payload(meta, fmt=2)
    elif sig_format == 1:
        try:
            payload = merkle_root_payload(merkle_root)
        except ValueError:
            return [
                IntegrityFinding(
                    severity=Severity.ERROR,
                    message=(
                        f"metadata.merkle_root {merkle_root!r} is not a hex "
                        "string — cannot reconstruct the legacy format-1 "
                        "signed payload"
                    ),
                )
            ]
        format_findings.append(
            IntegrityFinding(
                severity=Severity.WARNING,
                message=(
                    "LEGACY SIGNATURE FORMAT (v1): the signature binds only "
                    "the bare 32-byte root — leaf_format, epoch, and claim "
                    "pins are unbound, so rollback to a previously-signed "
                    "state or re-scoping the tree verifies cleanly. Re-stamp "
                    "and re-sign the layer from its writer to upgrade."
                ),
            )
        )
    else:
        return [
            IntegrityFinding(
                severity=Severity.ERROR,
                message=(
                    f"metadata.merkle_signature_format {sig_format!r} is not "
                    f"a known signature format"
                ),
            )
        ]
    result = signer.verify(
        payload,
        signature,
        pubkey_path,
    )
    if result.valid:
        return format_findings
    detail = result.error or "signature verification failed"
    return [
        IntegrityFinding(
            severity=Severity.ERROR,
            message=f"merkle_root_signature verification failed — {detail}",
        )
    ]
