"""Appending to a tree from its frontier gives the same root as rebuilding it from every leaf."""

from __future__ import annotations

import os

import pytest

from traust_ledger.integrity import (
    compute_frontier,
    compute_root,
    extend_frontier,
    frontier_root,
)


def entries(n: int) -> list[bytes]:
    return [os.urandom(1 + i % 40) for i in range(n)]


def test_every_size_up_to_1100_matches_compute_root() -> None:
    leaves = entries(1100)
    frontier: tuple[bytes, ...] = ()
    assert frontier_root(frontier) == compute_root([])
    for size, leaf in enumerate(leaves):
        frontier = extend_frontier(frontier, size, leaf)
        assert frontier_root(frontier) == compute_root(leaves[: size + 1]), size + 1
        assert len(frontier) == (size + 1).bit_count()


@pytest.mark.parametrize("n", [0, 1, 2, 3, 7, 8, 9, 1023, 1024, 1025])
def test_compute_frontier_is_the_incremental_frontier(n: int) -> None:
    leaves = entries(n)
    assert frontier_root(compute_frontier(leaves)) == compute_root(leaves)


def test_a_frontier_of_the_wrong_size_is_refused() -> None:
    frontier = compute_frontier(entries(5))  # 0b101: two subtrees
    with pytest.raises(ValueError, match="can't cover 7 leaves"):
        extend_frontier(frontier, 7, b"x")
    with pytest.raises(ValueError, match="can't cover 5 leaves"):
        extend_frontier(frontier[:-1], 5, b"x")


def test_appending_never_changes_the_earlier_subtrees() -> None:
    before = compute_frontier(entries(12))  # 0b1100: an 8-leaf and a 4-leaf subtree
    after = extend_frontier(before, 12, b"new")
    assert after[:2] == before and len(after) == 3
