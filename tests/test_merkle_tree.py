#!/usr/bin/env python3
"""Unit tests for traust_ledger/integrity/merkle.py (RFC 9162 §2.1)."""

from __future__ import annotations

import hashlib
import json

import pytest

from traust_ledger.integrity.merkle import (
    compute_merkle_root,
    compute_pre_epoch_checkpoint,
    compute_root,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    node_hash,
    verify_consistency,
    verify_inclusion,
)

RFC6962_LEAVES: list[bytes] = [
    b"",
    b"\x00",
    b"\x10",
    b"\x20\x21",
    b"\x30\x31",
    b"\x40\x41\x42\x43",
    b"\x50\x51\x52\x53\x54\x55\x56\x57",
    b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f",
]

EMPTY_ROOT = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
ONE_LEAF_ROOT = bytes.fromhex("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
EIGHT_LEAF_ROOT = bytes.fromhex("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328")

INCLUSION_0_8 = [
    bytes.fromhex(h)
    for h in [
        "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
        "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
    ]
]

INCLUSION_5_8 = [
    bytes.fromhex(h)
    for h in [
        "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
        "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    ]
]

CONSISTENCY_1_8 = [
    bytes.fromhex(h)
    for h in [
        "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
        "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
    ]
]

CONSISTENCY_6_8 = [
    bytes.fromhex(h)
    for h in [
        "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
        "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    ]
]


class TestTier1RfcVectors:
    def test_empty_tree_root(self) -> None:
        assert compute_root([]) == EMPTY_ROOT

    def test_one_leaf_root(self) -> None:
        assert compute_root(RFC6962_LEAVES[:1]) == ONE_LEAF_ROOT

    def test_eight_leaf_canonical_root(self) -> None:
        assert compute_root(RFC6962_LEAVES) == EIGHT_LEAF_ROOT

    def test_leaf_hash_l123456(self) -> None:
        assert leaf_hash(b"L123456") == bytes.fromhex(
            "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56"
        )

    def test_node_hash_n123_n456(self) -> None:
        assert node_hash(b"N123", b"N456") == bytes.fromhex(
            "aa217fe888e47007fa15edab33c2b492a722cb106c64667fc2b044444de66bbb"
        )

    def test_inclusion_proof_index_0_size_8(self) -> None:
        assert inclusion_proof(RFC6962_LEAVES, 0) == INCLUSION_0_8

    def test_inclusion_proof_index_5_size_8(self) -> None:
        assert inclusion_proof(RFC6962_LEAVES, 5) == INCLUSION_5_8

    def test_verify_inclusion_index_0_size_8(self) -> None:
        assert verify_inclusion(EIGHT_LEAF_ROOT, RFC6962_LEAVES[0], 0, 8, INCLUSION_0_8)

    def test_verify_inclusion_index_5_size_8(self) -> None:
        assert verify_inclusion(EIGHT_LEAF_ROOT, RFC6962_LEAVES[5], 5, 8, INCLUSION_5_8)

    def test_consistency_proof_1_to_8(self) -> None:
        assert consistency_proof(RFC6962_LEAVES, 1) == CONSISTENCY_1_8

    def test_consistency_proof_6_to_8(self) -> None:
        assert consistency_proof(RFC6962_LEAVES, 6) == CONSISTENCY_6_8

    def test_verify_consistency_1_to_8(self) -> None:
        assert verify_consistency(
            compute_root(RFC6962_LEAVES[:1]),
            EIGHT_LEAF_ROOT,
            1,
            8,
            CONSISTENCY_1_8,
        )

    def test_verify_consistency_6_to_8(self) -> None:
        assert verify_consistency(
            compute_root(RFC6962_LEAVES[:6]),
            EIGHT_LEAF_ROOT,
            6,
            8,
            CONSISTENCY_6_8,
        )


class TestTier2Properties:
    def test_determinism(self) -> None:
        entries = [f"leaf-{i}".encode() for i in range(20)]
        assert compute_root(entries) == compute_root(entries)

    def test_append_changes_root(self) -> None:
        base = [b"a", b"b", b"c"]
        extended = [*base, b"d"]
        assert compute_root(base) != compute_root(extended)

    def test_remove_changes_root(self) -> None:
        entries = [b"a", b"b", b"c"]
        assert compute_root(entries) != compute_root(entries[:2])

    def test_reorder_changes_root(self) -> None:
        entries = [b"a", b"b", b"c"]
        reordered = [b"c", b"a", b"b"]
        assert compute_root(entries) != compute_root(reordered)

    @pytest.mark.parametrize("size", range(1, 101))
    def test_inclusion_round_trip(self, size: int) -> None:
        entries = [f"entry-{i}".encode() for i in range(size)]
        root = compute_root(entries)
        for index in range(size):
            proof = inclusion_proof(entries, index)
            assert verify_inclusion(root, entries[index], index, size, proof)

    @pytest.mark.parametrize("new_size", range(2, 51))
    def test_consistency_round_trip(self, new_size: int) -> None:
        entries = [f"entry-{i}".encode() for i in range(new_size)]
        new_root = compute_root(entries)
        for old_size in range(1, new_size):
            old_root = compute_root(entries[:old_size])
            proof = consistency_proof(entries, old_size)
            assert verify_consistency(old_root, new_root, old_size, new_size, proof)

    def test_tampered_event_fails_inclusion(self) -> None:
        entries = [b"a", b"b", b"c", b"d"]
        root = compute_root(entries)
        proof = inclusion_proof(entries, 1)
        assert not verify_inclusion(root, b"X", 1, len(entries), proof)

    def test_wrong_index_fails_inclusion(self) -> None:
        entries = [b"a", b"b", b"c", b"d"]
        root = compute_root(entries)
        proof = inclusion_proof(entries, 1)
        assert not verify_inclusion(root, entries[1], 0, len(entries), proof)

    def test_domain_separation_leaf_not_node(self) -> None:
        data = b"shared-input"
        assert leaf_hash(data) != node_hash(data, b"anything")
        assert leaf_hash(data) != node_hash(b"anything", data)

    def test_empty_tree_edge_case(self) -> None:
        assert compute_root([]) == hashlib.sha256(b"").digest()
        assert compute_merkle_root([]) == (EMPTY_ROOT.hex(), 0)

    def test_single_event_edge_case(self) -> None:
        entries = [b"only"]
        root = compute_root(entries)
        proof = inclusion_proof(entries, 0)
        assert verify_inclusion(root, entries[0], 0, 1, proof)
        assert proof == []

    def test_two_events_edge_case(self) -> None:
        entries = [b"first", b"second"]
        root = compute_root(entries)
        for index in range(2):
            proof = inclusion_proof(entries, index)
            assert verify_inclusion(root, entries[index], index, 2, proof)


class TestHarnessWrappers:
    def test_compute_merkle_root_legacy_v1_from_event_ids(self) -> None:
        events = [
            {"event_id": "a" * 64},
            {"event_id": "b" * 64},
            {"event_id": "c" * 64},
        ]
        expected_entries = [event["event_id"].encode() for event in events]
        expected_root = compute_root(expected_entries).hex()
        assert compute_merkle_root(events, leaf_format=1) == (expected_root, 3)

    def test_compute_merkle_root_v2_binds_full_content(self) -> None:
        from traust_ledger.integrity.merkle import canonical_event_bytes

        events = [
            {
                "event_id": "a" * 64,
                "rationale": "original",
                "source": {"actor": {"kind": "machine"}},
            },
            {"event_id": "b" * 64, "rationale": "second"},
        ]
        expected = compute_root([canonical_event_bytes(e) for e in events]).hex()
        root, size = compute_merkle_root(events)  # default = format 2
        assert (root, size) == (expected, 2)
        # editing a NON-event_id field must change the root (the v1 gap)
        events[0]["rationale"] = "rewritten"
        root2, _ = compute_merkle_root(events)
        assert root2 != root
        # v1 would NOT have noticed the same edit
        v1_a, _ = compute_merkle_root(events, leaf_format=1)
        events[0]["rationale"] = "original"
        v1_b, _ = compute_merkle_root(events, leaf_format=1)
        assert v1_a == v1_b

    def test_compute_merkle_root_v2_ignores_merkle_fields(self) -> None:
        events = [{"event_id": "a" * 64, "rationale": "x"}]
        root_a, _ = compute_merkle_root(events)
        root_b, _ = compute_merkle_root([{**events[0], "merkle_note": "stamp artifact"}])
        assert root_a == root_b

    def test_compute_merkle_root_unknown_format_raises(self) -> None:
        import pytest

        with pytest.raises(ValueError):
            compute_merkle_root([{"event_id": "a" * 64}], leaf_format=9)

    def test_compute_pre_epoch_checkpoint(self) -> None:
        events = [
            {"event_id": "abc", "recorded_at": "2026-01-01T00:00:00+00:00"},
            {"event_id": "def", "recorded_at": "2026-01-02T00:00:00+00:00"},
        ]
        payload = json.dumps(events, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256(payload.encode()).hexdigest()
        assert compute_pre_epoch_checkpoint(events) == expected

    def test_inclusion_proof_index_error(self) -> None:
        with pytest.raises(IndexError):
            inclusion_proof([b"a"], 1)

    def test_consistency_proof_size_error(self) -> None:
        with pytest.raises(ValueError):
            consistency_proof([b"a", b"b"], 3)


class TestVerifyInclusionNegative:
    def test_verify_inclusion_truncated_proof(self) -> None:
        proof = inclusion_proof(RFC6962_LEAVES, 0)
        assert not verify_inclusion(EIGHT_LEAF_ROOT, RFC6962_LEAVES[0], 0, 8, proof[:-1])

    def test_verify_inclusion_extra_proof_elements(self) -> None:
        proof = inclusion_proof(RFC6962_LEAVES, 0)
        assert not verify_inclusion(
            EIGHT_LEAF_ROOT,
            RFC6962_LEAVES[0],
            0,
            8,
            [*proof, b"extra"],
        )

    def test_verify_inclusion_wrong_tree_size(self) -> None:
        proof = inclusion_proof(RFC6962_LEAVES, 4)
        assert not verify_inclusion(EIGHT_LEAF_ROOT, RFC6962_LEAVES[4], 4, 5, proof)


class TestVerifyConsistencyNegative:
    def test_verify_consistency_swapped_roots(self) -> None:
        old_root = compute_root(RFC6962_LEAVES[:1])
        assert not verify_consistency(
            EIGHT_LEAF_ROOT,
            old_root,
            1,
            8,
            CONSISTENCY_1_8,
        )

    def test_verify_consistency_tampered_proof(self) -> None:
        proof = list(CONSISTENCY_1_8)
        tampered = bytearray(proof[0])
        tampered[0] ^= 0x01
        proof[0] = bytes(tampered)
        assert not verify_consistency(
            compute_root(RFC6962_LEAVES[:1]),
            EIGHT_LEAF_ROOT,
            1,
            8,
            proof,
        )

    def test_verify_consistency_wrong_sizes(self) -> None:
        assert not verify_consistency(
            compute_root(RFC6962_LEAVES[:1]),
            EIGHT_LEAF_ROOT,
            2,
            7,
            CONSISTENCY_1_8,
        )


class TestUpdateLayerMerkleMetadata:
    def test_empty_layer(self) -> None:
        from traust_ledger.integrity import stamp_merkle_metadata

        layer = {"metadata": {}, "events": []}
        stamp_merkle_metadata(layer)
        assert layer["metadata"]["merkle_epoch"] == 0
        assert layer["metadata"]["merkle_size"] == 0
        assert layer["metadata"]["merkle_algorithm"] == "sha256"

    def test_refuses_negative_epoch(self) -> None:
        import pytest

        from traust_ledger.integrity import stamp_merkle_metadata

        layer = {
            "metadata": {"merkle_epoch": -1},
            "events": [{"event_id": "a" * 64, "rationale": "x"}],
        }
        with pytest.raises(ValueError, match="negative"):
            stamp_merkle_metadata(layer)

    def test_refuses_epoch_on_empty_events(self) -> None:
        import pytest

        from traust_ledger.integrity import stamp_merkle_metadata

        layer = {"metadata": {"merkle_epoch": 1}, "events": []}
        with pytest.raises(ValueError, match="empty"):
            stamp_merkle_metadata(layer)
