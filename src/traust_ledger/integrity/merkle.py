"""RFC 9162 §2.1 Merkle Tree Hash with SHA-256 domain separation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence

__all__ = [
    "LEAF_FORMAT_CURRENT",
    "canonical_event_bytes",
    "compute_merkle_root",
    "compute_pre_epoch_checkpoint",
    "compute_root",
    "consistency_proof",
    "inclusion_proof",
    "leaf_hash",
    "node_hash",
    "verify_consistency",
    "verify_inclusion",
]

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"

# Leaf format history (self-audit AI_SECURITY_HARNESS-d686348-001; design
# reconciled with the SCI worker security-hardening branch's H1 fix so the
# vendored and upstream trees share one format):
#   1 (legacy)  leaf = event_id (sha256 of source_ref|finding_ref|validity|
#               resolution). Binds only those four fields — actor,
#               rationale, and timestamps could be rewritten under a
#               still-valid root/signature.
#   2 (current) leaf = sha256 of the canonical JSON serialization (sorted
#               keys, compact separators) of the FULL event object,
#               excluding only merkle_* metadata fields. Any edit to any
#               event field breaks the root.
LEAF_FORMAT_CURRENT = 2


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _largest_power_of_two_less_than(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)


def _mth_from_leaf_hashes(leaf_hashes: list[bytes]) -> bytes:
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hashes[0]
    k = _largest_power_of_two_less_than(n)
    return node_hash(
        _mth_from_leaf_hashes(leaf_hashes[:k]),
        _mth_from_leaf_hashes(leaf_hashes[k:]),
    )


def extend_frontier(frontier: Sequence[bytes], size: int, entry: bytes) -> tuple[bytes, ...]:
    """The frontier after appending `entry` to a tree of `size` leaves.

    A frontier is the roots of the perfect subtrees covering the leaves, largest first: one per
    set bit of the size, so at most log2(size) hashes. Appending costs O(log n) and never reads
    the earlier leaves.
    """
    if len(frontier) != size.bit_count():
        raise ValueError(f"a frontier of {len(frontier)} hashes can't cover {size} leaves")
    out, node, n = list(frontier), leaf_hash(entry), size
    while n & 1:
        node = node_hash(out.pop(), node)
        n >>= 1
    out.append(node)
    return tuple(out)


def frontier_root(frontier: Sequence[bytes]) -> bytes:
    """The tree's root from its frontier: equal to compute_root over the same leaves."""
    if not frontier:
        return hashlib.sha256(b"").digest()
    root = frontier[-1]
    for subtree in reversed(frontier[:-1]):
        root = node_hash(subtree, root)
    return root


def compute_frontier(entries: Sequence[bytes]) -> tuple[bytes, ...]:
    """The frontier of a whole tree, e.g. to start appending to an existing layer."""
    frontier: tuple[bytes, ...] = ()
    for size, entry in enumerate(entries):
        frontier = extend_frontier(frontier, size, entry)
    return frontier


def compute_root(entries: list[bytes]) -> bytes:
    return _mth_from_leaf_hashes([leaf_hash(entry) for entry in entries])


def inclusion_proof(entries: list[bytes], index: int) -> list[bytes]:
    n = len(entries)
    if not 0 <= index < n:
        raise IndexError(f"index {index} out of range for {n} entries")
    leaves = [leaf_hash(entry) for entry in entries]

    def path(subtree: list[bytes], m: int) -> list[bytes]:
        if len(subtree) == 1:
            return []
        k = _largest_power_of_two_less_than(len(subtree))
        if m < k:
            return [*path(subtree[:k], m), _mth_from_leaf_hashes(subtree[k:])]
        return [*path(subtree[k:], m - k), _mth_from_leaf_hashes(subtree[:k])]

    return path(leaves, index)


def verify_inclusion(
    root: bytes,
    entry: bytes,
    index: int,
    tree_size: int,
    proof: list[bytes],
) -> bool:
    if not 0 <= index < tree_size:
        return False
    if tree_size == 1:
        return not proof and leaf_hash(entry) == root

    # Trace root-to-leaf path to determine left/right at each level.
    # is_left[i] = True means the target is in the left subtree at level i.
    is_left: list[bool] = []
    m, size = index, tree_size
    while size > 1:
        k = _largest_power_of_two_less_than(size)
        if m < k:
            is_left.append(True)
            size = k
        else:
            is_left.append(False)
            m -= k
            size -= k

    if len(is_left) != len(proof):
        return False

    # Proof is leaf-to-root; path is root-to-leaf. Walk bottom-up.
    computed = leaf_hash(entry)
    for went_left, sibling in zip(reversed(is_left), proof, strict=False):
        computed = node_hash(computed, sibling) if went_left else node_hash(sibling, computed)

    return computed == root


def _subproof(m: int, leaves: list[bytes], complete_subtree: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if complete_subtree else [_mth_from_leaf_hashes(leaves)]
    k = _largest_power_of_two_less_than(n)
    if m <= k:
        return [*_subproof(m, leaves[:k], complete_subtree), _mth_from_leaf_hashes(leaves[k:])]
    return [*_subproof(m - k, leaves[k:], False), _mth_from_leaf_hashes(leaves[:k])]


def consistency_proof(entries: list[bytes], old_size: int) -> list[bytes]:
    new_size = len(entries)
    if not 0 <= old_size <= new_size:
        raise ValueError(f"require 0 <= old_size <= len(entries); got {old_size}/{new_size}")
    if old_size == 0 or old_size == new_size:
        return []
    leaves = [leaf_hash(entry) for entry in entries]
    return _subproof(old_size, leaves, True)


def verify_consistency(
    old_root: bytes,
    new_root: bytes,
    old_size: int,
    new_size: int,
    proof: list[bytes],
) -> bool:
    # Port of transparency-dev/merkle VerifyConsistency (iterative bit-walk).
    m, n = old_size, new_size
    if m < 0 or n < 0 or m > n:
        return False
    if m == 0:
        return not proof
    if m == n:
        return not proof and old_root == new_root

    nodes = list(proof)
    if m & (m - 1) == 0:
        nodes = [old_root, *nodes]
    if not nodes:
        return False

    fn = m - 1
    sn = n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    first_root = nodes[0]
    second_root = nodes[0]
    for node in nodes[1:]:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            first_root = node_hash(node, first_root)
            second_root = node_hash(node, second_root)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            second_root = node_hash(second_root, node)
        fn >>= 1
        sn >>= 1

    return sn == 0 and first_root == old_root and second_root == new_root


def compute_pre_epoch_checkpoint(events: list[dict]) -> str:
    """SHA-256 hex digest of the canonical JSON serialization of pre-epoch events."""
    payload = json.dumps(events, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def canonical_event_bytes(event: dict) -> bytes:
    """Canonical serialization of one event for leaf_format 2 leaves.

    Sorted keys + compact separators so the bytes are reproducible from
    the stored JSON regardless of on-disk formatting. Fields named
    merkle_* are excluded so stamping can never invalidate itself.
    """
    scrubbed = {k: v for k, v in event.items() if not str(k).startswith("merkle_")}
    return json.dumps(scrubbed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def compute_merkle_root(
    events: list[dict],
    leaf_format: int = LEAF_FORMAT_CURRENT,
) -> tuple[str, int]:
    """Return (hex_root, leaf_count) for a layer's events array.

    leaf_format 2 (default) hashes the full canonical event content;
    leaf_format 1 is the legacy event_id-only binding, kept ONLY so
    existing layers still verify (with a warning from the ledger layer).
    """
    if leaf_format == 1:
        entries = [event["event_id"].encode() for event in events]
    elif leaf_format == 2:
        entries = [canonical_event_bytes(event) for event in events]
    else:
        raise ValueError(f"unknown merkle leaf_format: {leaf_format!r}")
    return compute_root(entries).hex(), len(entries)
