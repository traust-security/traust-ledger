# Changelog

All notable changes to traust-ledger are documented here.

## [0.7.0]

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
