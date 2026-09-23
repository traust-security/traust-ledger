# Finding identity — the fingerprint

**One recipe, defined once, in `traust_ledger/identity.py`.** This file is the prose
half of that module; where the two disagree, the code wins and this file is stale.

## What it is

A **fingerprint** is a content-derived name for a *finding* — the answer to
*"have we seen this exact thing before?"* across audits, across scans, across
years. It is a `sha256` hex digest over three canonicalized components:

```
fingerprint = sha256( canon_repo(repo_url) | ";".join(sorted set of canon_path(locations[].path)) | primary_cwe )
```

`|` joins the three fields; `;` joins the paths inside the middle field. Both
separators are part of the contract, not formatting.

| Component | Rule |
|---|---|
| `canon_repo(url)` | strip → ASCII-lowercase → `git@host:` → `https://host/` → any of `https?`/`ssh`/`git` scheme → `https://` → drop a trailing `.git` → drop trailing `/`. A non-URL passes through lowercased, so a report with broken `metadata.repository` still hashes deterministically. |
| `canon_path(p)` | strip → `\` → `/` → collapse runs of `/` → strip leading `.` and `/` characters → strip trailing `/`. Applied to every `locations[].path`, deduped into a set, sorted, `;`-joined. **A path that canonicalizes to empty is dropped from the set** (v2 — see Versioning). |
| `primary_cwe(finding)` | `cwes[0]`, ASCII-uppercased and stripped; `CWE-0` when absent or blank. **Only the first CWE enters identity** — a finding re-tagged with a second CWE keeps its name. |

Worked example, pinned as vector `single_path_with_cwe`:

```
payload      https://github.com/org/repo|src/app.go|CWE-79
fingerprint  1d72674005823cd435bf2978bd586585c5984d9b13b695cd5460f76d4ab0bb2d
```

## What is deliberately excluded

- **Line numbers are never hashed.** They live in `locations[].lines`. This is
  the property the whole correlation story rests on: a finding survives every
  edit above it, so a disposition recorded in March still attaches in August.
- **Title, description, severity, remediation.** Model-authored prose moves
  between runs; identity that moved with it would name nothing. Those fields are
  pinned separately by `compute_claim_hash` / `CLAIM_FIELDS`, which is
  tamper-evidence, not identity.
- **Secondary CWEs**, per the rule above.

## Case folding is ASCII-only, deliberately

`ascii_lower` / `ascii_upper` map A–Z only — **not** `str.lower()`. Python applies
full Unicode case mapping and Go applies simple mapping, so they disagree on
inputs like `İ` (U+0130): Python yields two codepoints, Go yields one. Measured
2026-08-17, **3 of 10 adversarial inputs diverged** between `traust_ledger` and the
Go SDK on exactly this. It is reachable — `metadata.repository` is an
unconstrained string and the ACS-collector lane derives it from
attacker-influenceable OCI labels. Restricting the mapping to A–Z makes the
recipe independent of any runtime's Unicode tables *and their version*. Non-ASCII
text hashes as-is: deterministic, and stable across languages.

## Versioning: `ALGO_VERSION`

`ALGO_VERSION` (`"v2"`) is bumped **only** when a change moves an already-stamped
value. Every stamp records the version that produced it, so versions coexist
rather than silently reinterpreting history.

**v2 (2026-08-18, plan decision D8):** a location path canonicalizing to empty is
dropped from the hashed set instead of contributing an empty component. `.`, `/`,
`./` and `/./` all reduce to `""`, so a finding located at `['.', 'src/a.go']`
hashed `";src/a.go"` under v1. Measured cost, accepted: **364 findings across 259
repos changed value**; the 2,762 repo-root-only findings hash identically either
way, because an all-empty set and a dropped-empty set are both `""`.

Coexistence is real, not theoretical. In the live corpus today (measured
2026-08-24) event stamps read **198 `v1` against 54,614 `v2`** — the v1 residue is
events stamped before the recipe moved, and they are correct as recorded. A
consumer matching fingerprints across an epoch boundary must compare
`fingerprint_algo` too.

## Strict mode: the domain, not the hash

`fingerprint(..., strict=True)` raises `DegenerateIdentity` on an empty path set
instead of hashing `(repo, "", cwe)`. Without it the recipe accepts input that
cannot identify anything: measured 2026-08-18, **433 fingerprints were shared by
1,397 findings** whose only location was a repo-root marker — *"no SECURITY.md"*
and *"not onboarded to OpenSSF Scorecard"* in one repo were the same finding as
far as the ledger could tell, so a disposition on one silently covered the other.

Note what strict mode is **not**: it does not change the hash of any accepted
input, so no stamped value moves and `ALGO_VERSION` is untouched. It narrows the
recipe's **domain**, which is why it ships without a re-stamp — and why a schema
rule alone would not do the job: a declared pattern bites only where validation
runs, while nothing enters the ledger without an identity.

The default is `False` because flipping it before the corpus is migrated would
refuse existing repo-root findings at stamp time. Backfill, then flip. A finding
that genuinely concerns no artifact uses a controlled pseudo-path from
`traust-contracts` `enums/v1/repo-scope-path.json`; one that concerns an
*absent* artifact names it anyway (an absent `SECURITY.md` is still
`SECURITY.md`).

## Where the value lives, and who may write it

Two fields, different provenance, constantly conflated. A consumer saying "the
fingerprint" must say which.

| | Field | Written by | Integrity |
|---|---|---|---|
| **wire** | `findings[].fingerprint` in `*-security-audit.json` | the audit skills, via `traust_ledger.api.identity.fingerprint` | **none in-band** — plain JSON in the artifact. The harness validator recomputes and compares, so a forged stamp is caught at validation, but the value itself sits in no tree |
| **record** | event `fingerprint` + `fingerprint_algo` | `traust_ledger.api.events.attach_identity` | **yes** — under `leaf_format 2` the leaf is the whole event, so the stamp is inside the Merkle root. Editing it breaks the root |

**Computed once by the producer, read forever after.** `fingerprint_index` reads
stamped values off the report; `attach_identity` copies one onto an event and
**never overwrites** — an event is a historical observation, so *"at time T this
finding's identity was X"* stays true even after a moved file changes the current
answer. A changed identity is a **new event**, never an edit.

Only the harness computes identity (plan decision **D7**) — not just consumers:
no non-harness producer computes one either. A producer that mints findings
(SARIF ingest, a collector) routes through the harness or submits unstamped.
This is why the Go SDK's `go/v1/identity` package and the cross-language
golden-vector suite were retired in 2026-08: with one implementation there is no
port for a shared oracle to hold.

## What the fingerprint is NOT

- **Not the event id.** `event_id = sha256("<source.ref>|<finding_ref>|<validity>|<resolution>")`
  is the idempotency key and is untouched by identity stamping.
- **Not a key for anything that records who said what** (plan decision **D9**).
  One finding audited under many parents has the same fingerprint *by design*, so
  keying dispositions on it merges records from distinct audit contexts —
  measured, keying the projection on fingerprint lost **7,325 rows (21.0%)**
  against **6,960 (19.4%)** for the defect it was meant to fix. The projection key
  stays `(layer_id, finding_ref)`; the fingerprint belongs there as a **column**,
  for cross-repo joins. A fingerprint answers *"is this the same finding"*; it does
  not answer *"whose disposition is this"*.
- **Not a security control.** It is an unkeyed digest of public inputs — anyone
  holding the report can recompute it. What makes a stamp trustworthy is the
  signature over the Merkle root that contains it, not the hash itself.
- **Not stable under a re-tagged primary CWE or a moved file.** Those produce a
  new identity, which is what rebaseline alias events exist to bridge.

## Regression fixtures

`tests/fixtures/identity-recipe-vectors.json` holds 12 cases pinning the recipe,
replayed by `tests/test_identity_recipe_vectors.py` on every run. Regenerate
deliberately:

```bash
python3 scripts/gen_identity_recipe_vectors.py
```

The generator **refuses** to rewrite hashes under an unchanged `ALGO_VERSION`, so
identity cannot be silently redefined by regenerating, and each case keeps its
`v1_expected_fingerprint` so a recipe move stays visible.

**Known limit:** all 12 are ASCII with well-formed CWEs and no empty paths.
Fixtures sample; they do not prove. Every one passed green through the three real
divergences found in 2026-08 — which is why they are a regression net, not a
correctness argument.

## Pointers

| Topic | Where |
|---|---|
| How identity travels inside an event, and the Merkle binding | [`ledger-model.md`](ledger-model.md) |
| Why the ledger remembers at all; the two disposition axes | `traust/docs/disposition-ledger.md` |
| Schema declarations (`finding.fingerprint`, event `fingerprint`/`fingerprint_algo`) | `traust-contracts` `schemas/v1/report.schema.json`, `schemas/v1/layer.schema.json` |
| Decisions D7 (one implementation), D8 (v2), D9 (never a sole key) | `progress-tracker/plans/ledger-plan.md` §3 |
