# Changelog

All notable changes to traust-ledger are documented here.

## [0.9.1]

### Changed

- Pin `traust-contracts` by tag `v0.48.0` (floor `>=0.48.0`). That release adds
  storage binding roles and `artifact_location`; nothing in the ledger reads
  storage bindings, so there is no behaviour change here.

## [0.9.0]

### Security

- **`LedgerClient` no longer stamps a caller-supplied actor.** `countersign`,
  `restate` and `restate_many` took an `actor=` that replaced the
  token-verified caller outright, so an in-process caller could record a
  countersign or restatement as anyone, with any `identity_verified` /
  `employee_status`. The token is now always verified and the verified actor
  is what gets stamped; a passed `actor` must match its principal (kind,
  identity, issuer, subject) or the write is refused. This matches the CLI and
  REST paths, which never accepted an override.
- **Local tokens are no longer identity-verified by default.** `ledger auth
  local` (and `LEDGER_LOCAL_IDENTITY` auto-mint) let anyone mint a token for
  any address, and every such actor was stamped `identity_verified=true`. That
  satisfied the verified-human gates, so one person holding two local
  identities could meet the two-person rule alone. Local actors are now stamped
  `identity_verified=false`: false-positive verdicts and restatements from them
  are refused, while `keep_open` / `confirmed` / severity countersigns and
  submits still work. Solo and offline deployments can opt back in with
  `LEDGER_TRUST_LOCAL_IDENTITY=1`.

### Changed (breaking for local-auth operators)

- A human using `ledger auth local` who records false-positive verdicts or
  restatements must either switch to `ledger auth login` (OIDC) or set
  `LEDGER_TRUST_LOCAL_IDENTITY=1`. Events already in a ledger keep whatever
  `identity_verified` they were stamped with; replay does not re-interpret
  them. Pre-0.9.0 local events stay counted as verified because that was the
  rule when they were written. After upgrading, a `local` +
  `identity_verified=true` event means either it predates 0.9.0 or it was
  written with the opt-in. To tell them apart, note each layer's last `seq`
  at upgrade. Don't use `recorded_at`, because callers supply it and it can
  be backdated.

## [0.8.5]

### Changed

- traust-contracts 0.47.0 (every threat-model section defined). The ledger
  doesn't read threat models; this keeps one contracts ref across the
  release train.

## [0.8.4]

### Changed

- traust-contracts v0.46.0 (OWASP risk ratings in the storage `threat`
  table). The ledger doesn't read threats; the bump keeps one contracts ref
  across the release train.

## [0.8.3]

### Changed

- traust-contracts v0.45.0, which adds the OWASP Risk Rating Methodology
  `risk_rating` to threats. The ledger doesn't read threat models; the bump
  keeps one contracts ref across the release train so traust-engine and
  traust can pin v0.45.0.

## [0.8.2]

### Security

- **SDK/CLI OIDC verification no longer trusts the token's own issuer.**
  `verifier_for_token` used to discover signing keys from whatever `iss` the
  unverified token named, so a token could choose who vouched for it. OIDC
  tokens are now verified only against the configured `LEDGER_OIDC_JWKS_URL` /
  `LEDGER_OIDC_ISSUER` (or a stored login's recorded issuer). A token from any
  other issuer fails verification, and with no provider configured a non-local
  token is refused. The message now says so, replacing the misleading "OIDC
  token resolved but no OIDC provider configured".
- **Restatement authorization moved to the REST boundary.** The admin list
  (`LAAS_ADMIN_IDENTITIES`) and approver threshold
  (`LAAS_RESTATEMENT_MIN_APPROVERS`) are enforced by
  `POST /v1/ledger/layers/{id}/restate` (still 403 for non-admins), where the
  operator owns them. The shared handler no longer checks them:
  - The CLI read them from the caller's own environment, so any caller could
    grant itself.
  - `LedgerClient` never loaded them at all, so `restate()` always refused.
  - `ledger restate` and `LedgerClient.restate()` now apply every integrity rule
    and record the actor, ticket and rationale in the signed history.
  - A restatement must still be authored by a verified human on every entry
    point; machine and service-account identities are refused.

### Removed

- `traust_ledger.cli.admin_identities_from_env`; the CLI no longer reads
  authorization settings.

## [0.8.1]

### Changed

- Upgraded to `traust-contracts` 0.44.0 (typed enum registry, `retired`
  stage). No ledger code, schema or OpenAPI change.

## [0.8.0]

### Added

- **Administrative restatement events** — `ledger restate`,
  `POST /v1/ledger/layers/{layer_id}/restate`, and `LedgerClient.restate()`.
  A restatement is an APPEND that records the prior value, the actor and an
  authorising ticket, then applies the restated value and re-signs. It covers
  the signature-bound metadata digests (`claim_hashes`, `audit_report_sha256`,
  `artifact_digests`) and `finding_aliases`.
  - Named restatement, not correction: `corrected` is already taken by
    `Validity.CORRECTED` (a finding-level claim revision), and
    classifier-disposition plan step 15 moves `corrected` into the same future
    `event_type` enum. `amend` was rejected because in git it means rewrite
    history — the exact operation this forbids.
- `LedgerWriter.append_restatement()` enforces the invariant the whole feature
  rests on: a signature-bound metadata field may only change in a write that
  also appends a restatement covering it (`UnexplainedMetadataChangeError`).
- `verify_merkle_integrity` now checks restated metadata against the terminal
  state of its restatement chain — an out-of-band rewrite after a restatement
  is an ERROR rather than an unexplained digest mismatch a human must
  adjudicate.
- SDK-tier `apply_restatements`, `restatements`, `terminal_value`
  (`traust_ledger.api.events`). Reading a restated projection needs no
  credentials; writing a restatement does.
- **Restatements are deltas.** `before`/`after` carry only the entries being
  changed; the writer merges them over stored metadata under the layer lock. A
  one-entry restatement costs the same on a 10-finding layer as on a 500-finding
  one — event size tracks the change, not the layer. Verification and the
  freshness guard are per key, so an entry nobody restated stays unconstrained.
- **Monotonic chain** (`RetiredValueRestatedError`): a restatement may not
  restore a value the chain already retired. Reversing an earlier restatement is
  its own decision and needs its own reason — and without this, `A → B → A → B`
  passed every gate, letting an actor with admin credentials append events
  without bound, re-hashing and re-signing on every write.
- `ServiceConfig.restatement_min_approvers` (`LAAS_RESTATEMENT_MIN_APPROVERS`):
  independent approvers a restatement must name in `authority.approved_by`,
  excluding the actor. 0 by default — the threshold is a deployment question.
- Bulk restatement via one shared handler (`apply_restatement_batch`):
  `ledger restate --from batch.json` and `LedgerClient.restate_many(items)`. No
  separate plan step. Deliberately not exposed over REST — one request cannot be
  atomic across N layers, so a batch endpoint would imply a guarantee the
  storage model does not give. Each item is gated individually and each write is atomic
  on its own layer, so a refused item is reported without stranding the rest;
  exit code is non-zero if any failed.
- Removed `finding_aliases` as a target: a `rebaseline` event already records a
  rename inside the Merkle-covered event stream, so the metadata table is a
  rebuildable projection rather than authority.
- Restating a field or entry that holds no value is refused (`NothingToRestateError`) —
  a first entry destroys no prior value, so it belongs on the ordinary write
  path rather than being filed as an administrative act.
- `ServiceConfig.admin_identities` / `LAAS_ADMIN_IDENTITIES` (comma- or
  JSON-separated). The admin gate fails CLOSED on an empty set.
- `ForbiddenError` → HTTP 403, so a valid token without admin rights is not
  told to re-authenticate.

### Changed

- **`LedgerClient.patch_metadata()` refuses to OVERWRITE signature-bound
  digests.** This was the hole: it would rewrite `claim_hashes` /
  `audit_report_sha256` / `artifact_digests` and re-sign with no record of the
  prior value, the actor, or a reason. First writes and per-key additions still
  pass — pinning a claim hash for a newly baselined finding destroys no
  evidence and is routine harness work. Overwrites go through `restate()`.
- **Event content is not restatable, by design.** Events are immutable and a
  wrong determination is superseded by appending a later one, which latest-wins
  precedence already resolves. A read-time overlay would be a second read-time
  transform competing with the v1→v2 normaliser, with no defined ordering
  between them (classifier-disposition plan R1, D13). `resolve_layer_findings`
  and `findings_from_events` drop restatement events from the projection so
  they never reach the precedence engine; nothing else about event reads
  changes.
- Upgraded to `traust-contracts` 0.40.0 for the delta-form `restatement` vocabulary.

### Notes

- **No new signature format.** A restatement is inside `merkle_root`, and the
  values it authorises are already bound by format 4. Appending one moves the
  root, drops the stale signature, and re-signs through the ordinary path.

## [0.7.1]

### Changed

- Upgraded to `traust-contracts` 0.37.0. Fixes missed upgraded noted in the changelog before.
- Fix pyproject project groupings.

## [0.7.0]

### Breaking (added retroactively in 0.8.2)

- `LedgerClient.sign()`, `patch_metadata()` and `stamp_event_identities()` now
  verify the caller's token before writing. A placeholder string such as
  `token="test-token"` is refused. Use a real local token
  (`LEDGER_LOCAL_IDENTITY` / `ledger auth local`) or a configured OIDC
  provider.
- `LedgerClient.create()` requires a verified actor and a complete layer shell
  (`audit_report`, `repository`, `created`, `harness_version`).
- `LedgerClient.store()` always raises. Replacing a whole layer is no longer
  possible through the SDK.

### Changed

- Upgraded to `traust-contracts` 0.37.0. Append-only triggers are now installed
  by the contracts SQL during bootstrap; the Ledger's `_install_sqlite_guards()`
  and `_install_postgresql_guards()` are idempotent re-applications.
- Fixed `LEDGER_TEST_DATABASE_URL` default to use `postgresql+psycopg://`
  (psycopg v3 driver) instead of bare `postgresql://` which requires psycopg2.
- Added `make db-up` / `make db-down` for local PostgreSQL container lifecycle,
  matching the contracts repo convention.

## [0.6.33]

### Changed

- Replaced the legacy complete-layer database blob with Ledger-owned,
  revisioned `layers`, ordered `events`, `materialized_findings`, and
  `schema_revision` tables. PostgreSQL objects live under `traust_ledger`;
  SQLite uses a dedicated configured Ledger database.
- Renamed the administrative `ledger replay` operation to `ledger migrate`.
  Environment variables are now `LAAS_MIGRATION_SOURCE_URL` and
  `LAAS_MIGRATION_TARGET_URL`.
- Refactored normalized persistence around typed `LayerRecord`, `EventRecord`,
  and `StoredLayerRecord` boundaries. Canonical binary JSON remains the exact
  reconstruction payload and preserves strings containing U+0000.

### Integrity

- Database event history is physically append-only. Persistence accepts only
  an exact existing prefix plus a new suffix; PostgreSQL and SQLite reject
  event updates, deletes, missing IDs, and sequence gaps. PostgreSQL also
  rejects truncation. Layer deletion is prohibited.
- Added schema revision 2 and an explicit revision 1 to 2 upgrade.
- Added distinct configurable PostgreSQL writer, projector, and reader grants.
  The application role no longer needs schema-owner privileges after setup.
- Historical migration validates contracts and Merkle roots, reconstructs
  every inserted layer before commit, skips exact reruns, and quarantines
  malformed or conflicting source evidence. Signature verification is
  available through `LAAS_MIGRATION_SIGNATURE_KEY`; absent trusted key
  material is reported as an explicit warning.

### Verification

- Added storage lifecycle E2E coverage for the file backend, SQLite, and
  PostgreSQL, plus file-to-SQLite migration and findings materialization.
- Rehearsed the PostgreSQL migration against 8,236 real layers containing
  81,433 events and 17,951 review items. A second run skipped every layer;
  materialization produced 57,241 findings.

### Upgrading

- Replace `ledger replay` with `ledger migrate` and rename any `LAAS_REPLAY_*`
  environment variables to `LAAS_MIGRATION_*`.
- Run migration/schema setup using an owner or migration role before starting
  a least-privilege writer or projector. Existing revision-1 databases upgrade
  to revision 2 through Ledger's authored migration.

## [0.3.0]

## Changes

- Pin traust-contracts v0.5.0 (evidence projection + postgres storage
  namespace).

- **Two write-path verbs are now reachable over REST**, so remote consumers
  (the Go SDK) can drive them the way in-process Python already could:
  - `POST /v1/ledger/layers/{layer_id}/stamp` — backfill event fingerprints
    from a `finding_ref -> fingerprint` map and re-sign the layer. Never
    overwrites an existing fingerprint. Returns the new Merkle root and the
    count stamped.
  - `GET /v1/ledger/whoami` — return the token-verified `LayerActor` for the
    caller, without recording anything.
- **`stamp` has a single implementation.** `LedgerClient.stamp_event_identities`
  and the new route both call `handlers.stamp_handler.stamp_event_identities`,
  matching the convergence pattern `sign_handler` already uses for CLI/REST/
  client. No behavior change for existing callers.
## [0.2.3]

- Point the traust-contracts pin at the new `traust-security` GitHub
  organisation. A release is required rather than an in-place URL edit: uv
  honours `[tool.uv.sources]` inside git dependencies, so a consumer pinning
  `v0.2.2` inherits that tag's old-org URL and conflicts with its own. The
  fix has to travel as a new tag, bottom-up.

## [0.2.2]

- Pin traust-contracts v0.4.0, which extends the typed patch-evidence block to
  the verification family. No ledger behaviour changes; the bump exists so
  stage-8 producers downstream can emit the block at all.

## [0.2.1]

- Pin traust-contracts v0.3.0, which adds the optional `evidence[]` block to
  remediation reports. No ledger behaviour changes; the bump is so producers
  downstream can emit the block at all (the remediation schema is
  `additionalProperties: false`, so an unpinned consumer rejects it).

## [0.2.0]

## Changes

- The counterpart to patch_metadata for the event layer: backfills event
  fingerprints (finding_ref -> fp) via attach_identity and re-signs in one
  atomic Backend.mutate. Never overwrites an existing fingerprint (identity
  is a historical observation); returns the count stamped. Lets the harness
  stamp cross-scan identity onto events without writing the layer itself.

## [0.1.1]

## Changes

- **Container image: builder and runtime now agree on the Python minor.** The
  builder stage was `python:3.11-builder` while the runtime was `python:3.12`,
  and the `.venv` built in the builder was copied wholesale into the runtime.
  Native-extension `.so` files are ABI-pinned per minor and the venv's console
  scripts hardcode the builder's interpreter path, so the image shipped with
  missing native modules and an unusable `uvicorn` entrypoint — invisible until
  it ran in a cluster. Both stages are now 3.12, and a deploy invariant asserts
  the minors match so the skew cannot return.

- **Contracts floor raised to 0.1.1.** `LayerEvent.recorded_at` and
  `.occurred_at` are `IsoTimestamp` there, so timestamps are guaranteed RFC
  3339 before they reach this package.

- **Read paths no longer re-implement timestamp parsing.** `_event_dt` dropped
  its timezone normalization (RFC 3339 always carries an offset, and aware
  datetimes compare by instant), and `severity_override.at` is back to a plain
  `occurred_at or recorded_at`. Both were compensating for values the contract
  now rejects.

- **`CorruptStoredEventError` for stored data that breaks a contract
  invariant.** Validation is reachable around — `model_construct` skips it and
  `derive_disposition` accepts already-typed events without re-validating — so
  `_event_dt` still guards, and now names the `event_id`, field, and value
  instead of surfacing a bare `ValueError` as an anonymous 500 over a corpus of
  thousands of layers.

### Upgrading

Contracts 0.1.1 validates timestamps on read as well as write, so a corpus
holding non-conforming values must be migrated **before** deploying this
release (`python3 -m traust.migrations.fix_event_timestamps <root> --apply`).
Otherwise an affected layer stops being readable through `/findings`.

## [0.1.0]

The disposition-ledger kernel: an append-only, Merkle-signed log of
human/machine dispositions against a security-audit report. State is
derived by replaying events — corrections are new events, never edits.
Fixes the domain model, write contract, and integrity scheme shared by
every deployment.
