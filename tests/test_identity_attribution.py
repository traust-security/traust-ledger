"""Attribution — which historical recipe minted an existing stamp.

Stamps written before 2026-09-18 carry no fingerprint_algo. Answering
"which recipe made this?" meant trying every candidate by hand, which
works only while the candidate set is small. The ladder makes the trying
explicit, and the set is closed: new stamps self-declare, so history is
all it ever has to cover.
"""

from __future__ import annotations

import hashlib

from traust_ledger.api.identity import (
    ALGO_LADDER,
    ALGO_VERSION,
    attribute,
    canon_path,
    canon_repo,
    fingerprint,
)

REPO = "https://example.test/org/repo"


def _finding(paths, cwes):
    return {"locations": [{"path": p} for p in paths], "cwes": list(cwes)}


def _hash(repo, paths, cwe):
    return hashlib.sha256(
        "|".join([canon_repo(repo), ";".join(paths), cwe]).encode("utf-8")
    ).hexdigest()


def test_the_ladder_starts_at_the_current_version() -> None:
    """Newest first, so a value two recipes both produce reads as the newer."""
    assert ALGO_LADDER[0][0] == ALGO_VERSION
    assert [v for v, _, _ in ALGO_LADDER] == ["v3", "v2", "v1"]


def test_a_current_stamp_attributes_to_the_current_version() -> None:
    finding = _finding(["a/b.go"], ["CWE-79"])
    assert attribute(finding, fingerprint(finding, REPO), [REPO]) == ALGO_VERSION


def test_v2_is_recognised_by_its_cwe_ordering() -> None:
    """v2 took cwes[0]; v3 takes the lowest by number. 250 < 276, and the
    list is written 276-first, so the two recipes disagree here."""
    finding = _finding(["a/b.go"], ["CWE-276", "CWE-250"])
    v2_stamp = _hash(REPO, ["a/b.go"], "CWE-276")
    assert v2_stamp != fingerprint(finding, REPO)
    assert attribute(finding, v2_stamp, [REPO]) == "v2"


def test_v1_is_recognised_by_its_empty_path_component() -> None:
    """v1 filtered raw paths for truthiness, so '.' survived and
    canonicalized to '', leaving an empty component in the join."""
    finding = _finding([".", "src/a.go"], ["CWE-79"])
    v1_stamp = _hash(REPO, sorted({canon_path("."), canon_path("src/a.go")}), "CWE-79")
    assert v1_stamp != fingerprint(finding, REPO)
    assert attribute(finding, v1_stamp, [REPO]) == "v1"


def test_an_unnormalized_repository_string_is_an_input_not_a_rung() -> None:
    """72 corpus stamps were minted from '<https://...>' before
    normalize_repository stripped the autolink. That is a property of the
    input, so it multiplies candidates rather than adding a ladder rung."""
    finding = _finding(["a/b.go"], ["CWE-79"])
    wrapped = f"<{REPO}>"
    stamp = _hash(wrapped, ["a/b.go"], "CWE-79")
    assert attribute(finding, stamp, [REPO]) is None, "the clean string must not match"
    assert attribute(finding, stamp, [REPO, wrapped]) == ALGO_VERSION


def test_an_unknown_stamp_attributes_to_nothing() -> None:
    """The residue must be reported, never guessed at."""
    finding = _finding(["a/b.go"], ["CWE-79"])
    assert attribute(finding, "f" * 64, [REPO]) is None
    assert attribute(finding, "", [REPO]) is None


def test_duplicate_and_none_candidates_are_tolerated() -> None:
    """Callers pass whatever spellings they have; some repeat, some are None."""
    finding = _finding(["a/b.go"], ["CWE-79"])
    stamp = fingerprint(finding, REPO)
    assert attribute(finding, stamp, [None, REPO, REPO, None]) == ALGO_VERSION


def test_attribution_never_mutates_the_finding() -> None:
    finding = _finding(["a/b.go"], ["CWE-79"])
    before = dict(finding)
    attribute(finding, "f" * 64, [REPO])
    assert finding == before
