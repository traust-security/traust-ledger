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


# --- cloud-config location shape ------------------------------------------


def _cc_finding(resources, cwe=None, file_paths=None):
    locs = []
    for i, r in enumerate(resources):
        loc = {"resource": r, "file_line_range": [1, 5]}
        if file_paths:
            loc["file_path"] = file_paths[i]
        locs.append(loc)
    finding = {"locations": locs}
    if cwe:
        finding["cwe"] = cwe
    return finding


def test_resource_anchors_identity_when_path_is_absent() -> None:
    """2,592 corpus findings carry resource/file_path, not path, so they were
    unfingerprintable and their dispositions could not survive a re-audit."""
    finding = _cc_finding(["RoleBinding.ns.name"], cwe="CWE-284")
    stamp = fingerprint(finding, REPO)
    assert len(stamp) == 64
    assert stamp == _hash(REPO, ["RoleBinding.ns.name"], "CWE-284")


def test_resource_is_preferred_over_file_path_because_files_move() -> None:
    """RoleBinding.ns.name survives the IaC file being moved or renamed."""
    moved = _cc_finding(["RoleBinding.ns.name"], cwe="CWE-284", file_paths=["/deploy/a.yaml"])
    renamed = _cc_finding(["RoleBinding.ns.name"], cwe="CWE-284", file_paths=["/deploy_pko/B.yaml"])
    assert fingerprint(moved, REPO) == fingerprint(renamed, REPO)


def test_path_still_wins_when_both_are_present() -> None:
    """The alias is a fallback. No corpus finding has both, but if one ever
    does, the code shape must keep its existing identity."""
    finding = {"locations": [{"path": "a/b.go", "resource": "Ignored.me"}], "cwes": ["CWE-79"]}
    assert fingerprint(finding, REPO) == _hash(REPO, ["a/b.go"], "CWE-79")


def test_singular_cwe_is_read_when_cwes_is_absent() -> None:
    finding = _cc_finding(["Deployment.ns.app"], cwe="CWE-732")
    assert fingerprint(finding, REPO) == _hash(REPO, ["Deployment.ns.app"], "CWE-732")


def test_widening_the_domain_moves_no_existing_hash() -> None:
    """The whole safety argument: every input the recipe already accepted
    keeps its exact value, so ALGO_VERSION does not move."""
    code = {"locations": [{"path": "a/b.go"}], "cwes": ["CWE-276", "CWE-250"]}
    assert fingerprint(code, REPO) == _hash(REPO, ["a/b.go"], "CWE-250")
    no_cwe = {"locations": [{"path": "a/b.go"}]}
    assert fingerprint(no_cwe, REPO) == _hash(REPO, ["a/b.go"], "CWE-0")


def test_the_attribution_ladder_does_NOT_see_the_alias() -> None:
    """A rung that reads an input the historical recipe could not see would
    attribute a stamp to a version that provably did not mint it."""
    finding = _cc_finding(["RoleBinding.ns.name"], cwe="CWE-284")
    current = fingerprint(finding, REPO)
    assert attribute(finding, current, [REPO]) == ALGO_VERSION
    # v2/v1 read `path` only, so for this finding they hash an empty set --
    # they must not accidentally reproduce the resource-anchored value.
    v2_like = _hash(REPO, [], "CWE-0")
    assert v2_like != current
    assert attribute(finding, v2_like, [REPO]) in {"v2", "v1"}


def test_the_newest_rung_tracks_the_live_recipe() -> None:
    """Regression: the v3 rung shared a path helper with v2, so narrowing v2
    back to history silently narrowed v3, and attribution returned None for
    stamps the live recipe had just minted. Any future widening must keep
    this true."""
    for finding in (
        {"locations": [{"path": "a/b.go"}], "cwes": ["CWE-79"]},
        _cc_finding(["RoleBinding.ns.name"], cwe="CWE-284"),
        _cc_finding(["A.b.c", "D.e.f"], cwe="CWE-732"),
        {"locations": [{"path": "x.go"}, {"resource": "R.s.t"}], "cwes": ["CWE-1", "CWE-2"]},
    ):
        stamp = fingerprint(finding, REPO)
        assert attribute(finding, stamp, [REPO]) == ALGO_VERSION, finding


def test_frozen_rungs_cannot_see_inputs_their_recipe_never_read() -> None:
    """Tested through the rung's own helper, not through attribute().

    attribute() is newest-first, so v3 matches a resource-anchored stamp
    before v2 is ever consulted -- which means a v2 rung that wrongly read
    `resource` is invisible from the outside. A rung that sees an input its
    historical recipe could not would attribute stamps to a version that
    provably did not mint them.
    """
    resource_only = _cc_finding(["RoleBinding.ns.name"], cwe="CWE-284")
    rungs = {version: (paths_of, cwe_of) for version, paths_of, cwe_of in ALGO_LADDER}

    for frozen in ("v2", "v1"):
        paths_of, cwe_of = rungs[frozen]
        assert paths_of(resource_only) in ([], [""]), (
            f"{frozen} must not read `resource`; it read {paths_of(resource_only)}"
        )
        assert cwe_of(resource_only) == "CWE-0", f"{frozen} must not read the singular `cwe`"

    paths_of, cwe_of = rungs["v3"]
    assert paths_of(resource_only) == ["RoleBinding.ns.name"]
    assert cwe_of(resource_only) == "CWE-284"


# --- policy check id ------------------------------------------------------


def test_the_check_separates_findings_on_one_resource() -> None:
    """20 distinct policy violations on one Pod collapsed to a single identity
    without this: a disposition on one silently covered the other nineteen."""
    base = _cc_finding(["Pod.default.app"], cwe="CWE-250")
    a = {**base, "check_id": "CKV_K8S_11"}
    b = {**base, "check_id": "CKV_K8S_12"}
    assert fingerprint(a, REPO) != fingerprint(b, REPO)
    assert fingerprint(a, REPO) == fingerprint({**base, "check_id": "ckv_k8s_11"}, REPO)


def test_the_check_is_appended_only_when_present() -> None:
    """This is what keeps ALGO_VERSION still: no code-audit finding carries a
    check_id, so every already-stamped input keeps its exact payload."""
    code = {"locations": [{"path": "a/b.go"}], "cwes": ["CWE-79"]}
    assert fingerprint(code, REPO) == _hash(REPO, ["a/b.go"], "CWE-79")
    assert fingerprint({**code, "check_id": ""}, REPO) == _hash(REPO, ["a/b.go"], "CWE-79")
    assert fingerprint({**code, "check_id": None}, REPO) == _hash(REPO, ["a/b.go"], "CWE-79")


def test_a_check_changes_the_payload_only_for_findings_that_have_one() -> None:
    with_check = {"locations": [{"path": "a/b.go"}], "cwes": ["CWE-79"], "check_id": "CKV_1"}
    assert fingerprint(with_check, REPO) == _hash(REPO, ["a/b.go"], "CWE-79|CKV_1")


def test_the_same_check_on_the_same_resource_stays_one_identity() -> None:
    """The scanner splits one violation across file sets; those are the same
    finding and must collapse. All 28 real collision groups are this shape."""
    a = _cc_finding(["Spec.api.types"], cwe="CWE-20", file_paths=["/api/v1/types.json"])
    b = _cc_finding(["Spec.api.types"], cwe="CWE-20", file_paths=["/tooling/openapi.yaml"])
    a["check_id"] = b["check_id"] = "CKV_OPENAPI_21"
    assert fingerprint(a, REPO) == fingerprint(b, REPO)


def test_frozen_rungs_never_see_the_check() -> None:
    """A v2 rung that read check_id would attribute stamps to a recipe that
    provably could not have minted them."""
    finding = {"locations": [{"path": "a/b.go"}], "cwes": ["CWE-79"], "check_id": "CKV_1"}
    rungs = {v: (p, c) for v, p, c in ALGO_LADDER}
    for frozen in ("v2", "v1"):
        _, cwe_of = rungs[frozen]
        assert cwe_of(finding) == "CWE-79", f"{frozen} leaked the check into its payload"
    _, cwe_of = rungs["v3"]
    assert cwe_of(finding) == "CWE-79|CKV_1"


def test_attribution_still_recognises_a_checked_stamp_as_current() -> None:
    finding = _cc_finding(["Pod.default.app"], cwe="CWE-250")
    finding["check_id"] = "CKV_K8S_11"
    assert attribute(finding, fingerprint(finding, REPO), [REPO]) == ALGO_VERSION
