# Consumer integration guide

traust-ledger exposes a **two-tier** public surface:

## SDK tier (pure computation — import freely)

Deterministic algorithms consumers need for pre-validation, matching, and
preparing data before submission. No auth required; safe for library use.

| Import path | Key exports |
|---|---|
| `traust_ledger.api.identity` | `fingerprint`, `canon_path`, `canon_repo`, `primary_cwe` |
| `traust_ledger.api.events` | `compute_event_id`, `compute_claim_hash`, `attach_identity`, `findings_from_events` |
| `traust_ledger.api.disposition` | `derive_disposition`, `is_actor_verified`, `event_class` |
| `traust_ledger.api.reports` | `report_sha256`, `check_report_digest`, `check_artifact_digests` |

These paths are stable across versions. `_internal/` may change freely.

**Note:** `identity`, `events`, and `disposition` are SDK migration candidates.
Portable schemas remain in `traust-contracts`; runtime APIs may move to
`traust-sdk`. Import paths will be shimmed.

## Gated tier (state changes — OIDC required)

All mutations require verified identity. Three entry points:

| Entry point | When to use |
|-------------|-------------|
| `LedgerClient` | In-process Python (import `traust_ledger.client`) |
| CLI | Shell scripts, pipelines (`ledger submit`, `ledger sign`, …) |
| REST API | Remote / cross-language consumers |

Never import `LedgerWriter` or `_internal/` modules for writes.

### LedgerClient (Python SDK)

```python
from traust_ledger.client import LedgerClient

client = LedgerClient.from_env()  # reads LAAS_TOKEN, LAAS_DATA_DIR, etc.
client.submit("layer-id", events)
client.sign("layer-id")
client.verify("layer-id")
result = client.query_findings("layer-id")
```

Requires `LAAS_TOKEN` (OIDC JWT) or `LEDGER_LOCAL_IDENTITY` (for local
auth — a token is auto-minted). No optional extras needed — `LedgerClient`
is importable from bare `traust-ledger`.

### REST API

For services that talk to traust-ledger over the network:

| Endpoint | Purpose |
|---|---|
| `POST /v1/ledger/layers/{id}/submit` | Batch event + queue submission |
| `POST /v1/ledger/review-items/resolve` | Resolve a queued review item |
| `GET /v1/ledger/layers/{id}/findings` | Per-layer resolved dispositions |
| `GET /v1/ledger/layers/{id}/events` | Raw event log |
| `GET /v1/ledger/layers/{id}/verify` | Merkle integrity check |
| `GET /v1/ledger/layers` | List known layers |
| `POST /v1/ledger/layers/{id}/fingerprint` | Server-side fingerprint stamping |

## CLI

For services that run traust-ledger in the same environment:

| Command | Purpose |
|---|---|
| `ledger submit <events.json>` | Submit events (same as REST batch) |
| `ledger countersign <finding_ref>` | Two-person countersign |
| `ledger fingerprint <report.json>` | Stamp fingerprints on a report |
| `ledger migrate --source-dir <dir>` | Migrate flat historical layer files (filename stem is ID) |
| `ledger migrate --source-dir <dir> --selection-manifest <file>` | Migrate selected nested layer files with pinned identities |
| `ledger migrate --source-database-url <url>` | Migrate complete layer artifact evidence |
| `ledger migrate --source-ledger-database-url <url>` | Copy normalized SQLite/PostgreSQL Ledger state |
| `ledger materialize --to <url>` | Rebuild the queryable findings projection |
| `ledger query layers` | List layers |
| `ledger query findings <layer>` | Resolved findings for a layer |
| `ledger query events <layer>` | Event log for a layer |
| `ledger query verify <layer>` | Merkle integrity check |

### Historical migration

Migration is an explicit administrative copy operation, never a startup conversion or
normal event submission. It does not mutate or delete the source. Credentials belong in
environment variables:

```bash
# Complete layer files from a Ledger data directory
export LAAS_MIGRATION_TARGET_URL=postgresql://user:pass@host/database
ledger migrate --source-dir /path/to/ledger-data --dry-run
ledger migrate --source-dir /path/to/ledger-data

# Nested findings tree: preview the same root with traust corpus migrate-artifacts plan
ledger migrate --source-dir /path/to/analysis-results/findings \
  --selection-manifest /path/to/preview/decisions.jsonl --dry-run
ledger migrate --source-dir /path/to/analysis-results/findings \
  --selection-manifest /path/to/preview/decisions.jsonl

# Complete evidence already stored by artifact migration
export LAAS_MIGRATION_SOURCE_URL=postgresql://user:pass@host/database
ledger migrate --source-database-url from-env

# Copy a dedicated SQLite Ledger into PostgreSQL
export LAAS_MIGRATION_SOURCE_URL=sqlite:////path/to/ledger.db
ledger migrate --source-ledger-database-url from-env

# Resume or inspect one layer
ledger migrate --source-dir /path/to/ledger-data --layer layer-a --json
```

`--selection-manifest` accepts version 1 receipts from artifact preview; it uses
only `traust_ledger` layer decisions, verifies the original SHA-256 and rejects
unsafe paths, symlink aliases, or duplicate layer IDs before importing. Use the
same source root for preview and migration. Without the manifest, `--source-dir`
retains its flat-directory and filename-stem identity behavior.
`--source-database-url from-env` selects database evidence while the real URL
comes from `LAAS_MIGRATION_SOURCE_URL`; `LAAS_MIGRATION_TARGET_URL` always names
the normalized Ledger destination. Migration validates complete layer documents,
preserves event array order, reconstructs after insertion, skips exact reruns,
and reports differing existing history as a conflict. Set
`LAAS_MIGRATION_SIGNATURE_KEY` to verify stored signatures; without it, signed
layers migrate with an explicit validation warning rather than a false claim of
signature verification.

For PostgreSQL, deployment-owned roles can be configured during migration with
`--writer-role`, `--projector-role`, and `--reader-role` (or their
`LAAS_MIGRATION_*_ROLE` environment variables). The roles must already exist and
must be distinct. Migration resets their Ledger-table grants to this matrix:

| Role | Authoritative tables | Projection |
|---|---|---|
| writer | `SELECT/INSERT` events; `SELECT/INSERT/UPDATE` layers | none |
| projector | `SELECT` layers/events | full rebuild access |
| reader | none | `SELECT` only |

### Materialization

`ledger materialize` reads the service backend and writes resolved findings into
a SQL store (SQLite or Postgres):

```bash
export LAAS_BACKEND_TYPE=file
export LAAS_DATA_DIR=/path/to/layers

# Populate a local SQLite
ledger materialize --to sqlite:///findings.db

# Populate Postgres (credentials via env, not argv)
export LAAS_MATERIALIZE_URL=postgresql://user:pass@host/db
ledger materialize

# Only specific layers
ledger materialize --to sqlite:///findings.db --layer repo-a --layer repo-b

# Print the schema DDL
ledger materialize --ddl
```

The projection table is keyed on `(layer_id, finding_ref)`. PostgreSQL exposes
it as `traust_ledger.materialized_findings`; SQLite uses the unqualified table
name. Re-running is idempotent. Each layer commits independently. To migrate and
materialize into one PostgreSQL database, set `LAAS_DATABASE_URL` and
`LAAS_MATERIALIZE_URL` to that same URL after migration.

### Layer ID derivation

If your layers live in nested directories (not the flat service backend), raw
filenames will collide. Use the CLI or REST layer-id in all downstream keying.
The service assigns layer IDs at ingest time; the materialize CLI handles its
own ID derivation internally.

## Boundary

```
traust-ledger provides (via LedgerClient/CLI/REST):
  ✓ event submission (append-only, idempotent, signed)
  ✓ disposition resolution (per-layer findings)
  ✓ integrity verification (merkle tree, signatures)
  ✓ fingerprint stamping (deterministic identity recipe)
  ✓ historical migration from complete trusted evidence
  ✓ materialized projection (queryable SQL table)
  ✓ queue management (needs_review lifecycle)

traust-ledger does NOT provide:
  ✗ tree iteration / filesystem traversal
  ✗ cross-layer joins or aggregation
  ✗ dashboard queries or scoring
  ✗ deployment topology awareness
  ✗ contracts-owned cross-schema views or application dashboard schemas
```
