"""Restatement chain replay, for verifying a layer's signature-bound metadata.

A restatement is an appended event carrying a ``restatement`` block; it changes
signature-bound layer METADATA only. Verification replays the chain and checks
the stored metadata still holds the value the last restatement gave it.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

# The layer document format these layers were written in (contracts
# restatement-target / source-type values when the format froze).
SOURCE_TYPE_RESTATEMENT = "restatement"

#: Metadata fields whose digests signature format 4 binds.
SIGNED_METADATA_FIELDS: tuple[str, ...] = (
    "claim_hashes",
    "audit_report_sha256",
    "artifact_digests",
)


def merge_delta(current: object, after: object) -> object:
    """Apply a restatement's ``after``: maps merge per key (null deletes), scalars replace."""
    if not isinstance(after, dict) or not isinstance(current, dict):
        return after
    merged = dict(current)
    for key, value in after.items():
        if value is None:
            merged.pop(key, None)
        else:
            merged[key] = value
    return merged


def is_restatement(event: object) -> bool:
    """True for a restatement block on a restatement-typed event.

    Both halves: a hand-written layer could put a block on an ordinary
    determination, which must not grant it authority over metadata.
    """
    if not isinstance(event, dict):
        return False
    if not isinstance(event.get("restatement"), dict):
        return False
    return (event.get("source") or {}).get("type") == SOURCE_TYPE_RESTATEMENT


def restatements_for(events: Iterable[object], target: str) -> list[dict]:
    """Restatement blocks naming *target*, oldest first."""
    return [
        e["restatement"]
        for e in (events or [])
        if is_restatement(e) and e["restatement"].get("target") == target
    ]


def terminal_value(events: Iterable[object], target: str) -> tuple[bool, Any]:
    """``(restated, expected)`` for a metadata field after replaying its chain.

    Deltas make this per key: a verifier compares only the keys the chain
    restated. The flag separates "never restated" from "restated to None".
    """
    chain = restatements_for(events, target)
    if not chain:
        return False, None
    expected: Any = None
    for block in chain:
        expected = merge_delta(expected if isinstance(expected, dict) else None, block.get("after"))
    return True, expected


__all__ = [
    "SIGNED_METADATA_FIELDS",
    "is_restatement",
    "merge_delta",
    "restatements_for",
    "terminal_value",
]
