"""Finding identity primitives — fingerprinting and canonical forms.

The single definition of the fingerprint recipe: only the harness computes
identity (plan decision D7), so this module is it, and there is no second-language
port to hold to a shared oracle. Prose contract in docs/finding-identity.md; regression
vectors in tests/fixtures/identity-recipe-vectors.json.
"""

from __future__ import annotations

import hashlib
import re

# The recipe's version. Bump whenever a change moves an already-stamped
# fingerprint; every stamp records the version that produced it, so v1 and v2
# values coexist until a re-stamp migrates them.
#
# v2 (2026-08-18, decision D8): a location path that canonicalizes to empty is
# dropped from the hashed set instead of contributing an empty component. `.`,
# `/`, `./` and `/./` all reduce to "" under canon_path, so a finding located at
# `['.', 'src/a.go']` hashed ";src/a.go" under v1. Measured: 364 findings across
# 259 repos change value; the 2,762 repo-root-only findings hash identically
# either way, because an all-empty set and a dropped-empty set are both "".
#: v3 (2026-09-02) — primary_cwe picks the lowest CWE by NUMBER rather than the
#: first listed, so identity no longer depends on the order of a model-authored
#: list. Stamps record the version that produced them and the corpus already runs
#: mixed versions, so this does not compel a re-stamp; see the plan's A4.
ALGO_VERSION = "v3"

# Case folding is ASCII-only, deliberately, and every port must match.
#
# Python's str.lower() applies FULL Unicode case mapping and Go's
# strings.ToLower() applies SIMPLE mapping, so they disagree on inputs like
# 'İ' (U+0130): Python yields two codepoints (i + combining dot above), Go
# yields one. Measured 2026-08-17, 3 of 10 adversarial inputs diverged between
# traust_ledger and the Go SDK on exactly this. It is reachable —
# `metadata.repository` is an unconstrained string, and the ACS-collector lane
# derives it from attacker-influenceable OCI labels.
#
# Restricting the mapping to A-Z makes the recipe identical in every language
# without depending on any runtime's Unicode tables or their version. Non-ASCII
# text is hashed as-is, which is deterministic and cross-language stable.
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_ASCII_UPPER = str.maketrans("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")


def ascii_lower(s: str) -> str:
    """Lowercase A-Z only. See the note above: NOT str.lower()."""
    return s.translate(_ASCII_LOWER)


def ascii_upper(s: str) -> str:
    """Uppercase a-z only. See the note above: NOT str.upper()."""
    return s.translate(_ASCII_UPPER)


def canon_repo(url: str | None) -> str:
    """Canonical repository URL: lowercase host/path, https, no .git, no
    trailing slash. Non-URLs pass through lowercased (deterministic even
    for reports with broken metadata)."""
    s = ascii_lower((url or "").strip())
    s = re.sub(r"^git@([^:]+):", r"https://\1/", s)
    s = re.sub(r"^(https?|ssh|git)://", "https://", s)
    s = re.sub(r"\.git$", "", s).rstrip("/")
    return s


def canon_path(p: str | None) -> str:
    """Normalized location path: forward slashes, no leading ./ or /,
    collapsed separators. Line numbers live in `lines`, never here."""
    s = (p or "").strip().replace("\\", "/")
    s = re.sub(r"/{2,}", "/", s)
    return s.lstrip("./").rstrip("/")


_CWE_NUMBER_RE = re.compile(r"(\d+)")
#: A CWE with no digits cannot be ordered numerically; sort it last so the result
#: stays total instead of raising on input the schema permits.
_CWE_NO_NUMBER = 10**9


def primary_cwe(finding: dict) -> str:
    r"""Lowest CWE **by number**, ASCII-uppercased and stripped; 'CWE-0' when absent.

    **v3 (2026-09-02): the lowest-numbered CWE, not the first one listed.** v2 took
    `cwes[0]`, so identity depended on the ORDER a model happened to write a
    model-authored list: 27,496 of 75,128 corpus findings carry more than one CWE
    and 11,085 of those would hash differently under a positional rule, meaning two
    audits of the same finding could fail to correlate purely on list order.

    **Numeric, deliberately — not lexicographic.** Python's `min()` over these
    strings sorts character by character, so `min(["CWE-937", "CWE-1104"])` returns
    `CWE-1104` because `'1'` precedes `'9'`. That reading disagrees with the
    numeric one on **8,893 corpus findings**, and "lowest CWE" plainly means 937
    before 1104. Both are deterministic and either would serve identity, so the
    choice is documentation: a reimplementer (the Go SDK) builds from this
    description, and a recipe that contradicts its own wording earns a v4 the day
    someone notices. Michele chose numeric, 2026-09-02.

    A malformed entry with no digits sorts last rather than raising — identity must
    not fail on input the schema already permits — and ties fall back to the
    lexicographic order of the equal values, so the result is total.

    The blank case was a real divergence, not a judgement call: the vector
    suite's own rules have always said "'CWE-0' when absent/empty", the Go SDK
    implemented that, and this returned '' for `cwes: ["  "]`. Unreachable via a
    schema-valid report (minItems 1, ^CWE-\d{1,5}$) and fully reachable for the
    non-harness producers the SDK exists to serve.
    """
    cwes = [c for c in (finding.get("cwes") or []) if str(c).strip()]
    if not cwes:
        return "CWE-0"

    def _rank(cwe: object) -> tuple[int, str]:
        text = ascii_upper(str(cwe).strip()).strip()
        digits = _CWE_NUMBER_RE.search(text)
        return (int(digits.group(1)) if digits else _CWE_NO_NUMBER, text)

    return ascii_upper(str(min(cwes, key=_rank)).strip()).strip() or "CWE-0"


class DegenerateIdentity(ValueError):
    """Refused: the finding carries no usable location, so it has no identity.

    Raised only in strict mode. See fingerprint()'s docstring for why the
    default is not yet strict.
    """


def fingerprint(finding: dict, repo_url: str | None, *, strict: bool = False) -> str:
    """Deterministic finding fingerprint for correlation across audits.

    Canonical hash of repo URL, sorted normalized paths, and primary CWE.
    Paths that canonicalize to empty are dropped from the set (v2, D8).

    Part of the external contract. Any change that moves an already-stamped
    value must bump ALGO_VERSION above, because stamps record the version that
    produced them and consumers match on it.

    strict=True REFUSES an empty path set instead of hashing (repo, "", cwe).
    Without it the recipe silently accepts input that cannot identify anything:
    measured 2026-08-18, 433 fingerprints were shared by 1,397 findings whose
    only location was a repo-root marker, so "no SECURITY.md" and "not onboarded
    to OpenSSF Scorecard" in one repo were the same finding as far as the ledger
    could tell — a disposition on one silently covered the other.

    Note what strict mode is NOT: it does not change the hash of any accepted
    input, so no stamped value moves and ALGO_VERSION is untouched. It narrows
    the recipe's DOMAIN, which is why it can ship without a re-stamp — and why a
    schema rule alone would not do: a declared pattern only bites where
    validation runs, while nothing enters the ledger without an identity.

    The default is False because flipping it before the corpus is migrated would
    refuse ~2,762 existing repo-root findings at stamp time. Backfill, then flip
    — the same order P0.4 and P6 followed. The flip is a tracked plan item.
    """
    paths = sorted(
        {
            canon
            for loc in (finding.get("locations") or [])
            # Filter AFTER canonicalizing, not before: v1 tested the raw value
            # for truthiness, so a path of "." survived the check and then
            # canonicalized to "", putting an empty component in the join.
            if (canon := canon_path(loc.get("path")))
        }
    )
    if strict and not paths:
        raise DegenerateIdentity(
            "refusing to fingerprint a finding with no usable location: every "
            f"path in {[loc.get('path') for loc in (finding.get('locations') or [])]!r} "
            "canonicalizes to empty. Name the artifact the finding concerns "
            "(an absent SECURITY.md is still 'SECURITY.md'), or use a controlled "
            "pseudo-path from traust-contracts enums/v1/repo-scope-path.json "
            "when it genuinely concerns no artifact."
        )
    payload = "|".join([canon_repo(repo_url), ";".join(paths), primary_cwe(finding)])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Attribution — which historical recipe minted an existing stamp
# ---------------------------------------------------------------------------
#
# Stamps written before 2026-09-18 carry no fingerprint_algo, so nothing on
# disk says which recipe produced them. That was answerable only by trying
# every recipe against every finding, which works while the set of
# candidates is small and stops working the moment it is not.
#
# This makes the trying explicit and bounded. The set is CLOSED: every stamp
# written from now on self-declares its version, so the ladder only ever has
# to cover history, and history does not grow.
#
# Measured across the corpus 2026-09-18 (25,515 report stamps):
#   v3  21,478 (84.2%)   v2  3,909 (15.3%)   v1  56 (0.2%)
#   + 72 minted from an un-normalized repository string, which is a property
#     of the INPUT rather than of the recipe -- see repo_candidates below.
#   unattributed: 0


def _paths_v1(finding: dict) -> list[str]:
    """v1 tested the RAW path for truthiness, so '.' survived and canonicalized
    to '', putting an empty component in the join."""
    return sorted({canon_path(loc.get("path")) for loc in (finding.get("locations") or [])})


def _paths_v2(finding: dict) -> list[str]:
    return sorted(
        {
            canon
            for loc in (finding.get("locations") or [])
            if (canon := canon_path(loc.get("path")))
        }
    )


def _cwe_first(finding: dict) -> str:
    """v1/v2 took cwes[0] -- identity depended on the order a model wrote."""
    values = [c for c in (finding.get("cwes") or []) if c]
    return ascii_upper(values[0].strip()) if values else "CWE-0"


#: Newest first, so attribution reports the most recent recipe that matches.
#: Keep this ordered: a stamp that two recipes both produce is attributed to
#: the newer one, which is the safer read when they collide.
ALGO_LADDER: tuple[tuple[str, object, object], ...] = (
    ("v3", _paths_v2, primary_cwe),
    ("v2", _paths_v2, _cwe_first),
    ("v1", _paths_v1, _cwe_first),
)


def _hash(repo_url: str | None, paths: list[str], cwe: str) -> str:
    import hashlib

    return hashlib.sha256(
        "|".join([canon_repo(repo_url), ";".join(paths), cwe]).encode("utf-8")
    ).hexdigest()


def attribute(
    finding: dict, stamp: str, repo_candidates: list[str | None] | tuple[str | None, ...]
) -> str | None:
    """Which recipe version produced `stamp`, or None if no known one did.

    `repo_candidates` exists because the repository string itself has a
    history: 72 corpus stamps were minted from a value like
    `<https://host/org/repo>` before normalize_repository stripped the
    autolink brackets. That is an INPUT state, not a recipe version, so it
    multiplies the candidates rather than adding a rung to the ladder.
    Pass every plausible spelling; the first that reproduces wins.

    Returns the ALGO version only. A caller that needs to know WHICH repo
    string matched should re-run the winning rung itself -- attribution
    answers "is this stamp accounted for", not "reconstruct the inputs".
    """
    # No early return for an empty stamp: no digest equals "", so the loop
    # already yields None. A guard here would be untestable by construction.
    seen: list[str | None] = []
    for candidate in repo_candidates:
        if candidate in seen:
            continue
        seen.append(candidate)
        for version, paths_of, cwe_of in ALGO_LADDER:
            if _hash(candidate, paths_of(finding), cwe_of(finding)) == stamp:
                return version
    return None
