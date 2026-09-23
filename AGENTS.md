# traust-ledger

Python 3.11+ library (`traust_ledger`). Disposition-ledger kernel — small, reviewed line-by-line.

- **Before done:** `make lint-fix` then `make test` — CI enforces both; do not skip
- **Lint:** line length 100; ruff E/W/F/I/UP/B/SIM/PTH/RUF (`pyproject.toml`) — `Path` not `os.path`, no bare `except: pass`
- **Commits:** conventional `type(scope): subject` (`feat`, `fix`, `perf`, `chore`, `ci`, …)
- **Releases:** `feat`/`fix`/`perf`/breaking MRs need `make check-release`, `VERSION` + `CHANGELOG.md` bump
- **Scope:** smallest diff; identity/event math changes may need golden-vector updates in contracts
- **Setup:** `make setup` once per clone (hooks). More: [CONTRIBUTING.md](CONTRIBUTING.md), [README.md](README.md)

## Two-tier public surface

### SDK tier (import freely, no auth)

Pure computation — deterministic algorithms consumers need for pre-validation,
matching, and preparing data before submission.

| Module | Exports | SDK migration candidate |
|--------|---------|------------------------|
| `traust_ledger.api.identity` | `fingerprint`, `canon_path`, `canon_repo`, `primary_cwe`, `ALGO_VERSION` | Yes |
| `traust_ledger.api.events` | `compute_event_id`, `compute_claim_hash`, `aliases_from_events`, `findings_from_events`, `attach_identity`, `make_alias_event` | Yes |
| `traust_ledger.api.disposition` | `derive_disposition`, `is_actor_verified`, `event_class` | Yes |
| `traust_ledger.api.integrity` | `verify_merkle_integrity`, `verify_merkle_signature`, `stamp_merkle_metadata`, `IntegrityFinding`, `Severity` | No |
| `traust_ledger.api.reports` | `report_sha256`, `check_report_digest`, `check_artifact_digests` | No |

These are stable public paths. `_internal/` may refactor freely underneath.

### Gated tier (OIDC-enforced)

All state changes go through one of three entry points, each stamping OIDC
identity onto the actor. `LedgerWriter` is internal and NOT importable.

| Entry point | Usage |
|-------------|-------|
| `LedgerClient` | In-process Python SDK (`traust_ledger.client`) |
| CLI | `ledger sign`, `ledger submit`, etc. |
| REST API | `traust_ledger.service` (FastAPI) |

| Command | Purpose |
|---------|---------|
| `ledger submit` | Batch event + queue submission |
| `ledger countersign` | Two-person countersign |
| `ledger sign` | Sign a layer's Merkle root |
| `ledger verify-signature` | Verify a Merkle root signature |
| `ledger resolve` | Resolve a needs_review item |
| `ledger fingerprint` | Stamp identity on a report (in-place write) |
| `ledger verify` | Merkle integrity check |
| `ledger migrate` | Administratively copy validated historical layers into normalized storage |
| `ledger materialize` | Populate SQL projection |
| `ledger query` | findings / events / layers |

### Boundary rule

If it **changes the ledger** → CLI/REST (OIDC enforced). Historical migration is
a separate explicit administrative path; it never submits old events as new ones.
If it **computes or reads** → importable from SDK-tier modules.

### Database integrity rules

- `events` is append-only: existing payloads must be an exact prefix; only suffix inserts.
- Never add event `UPDATE`, `DELETE`, replacement, or truncation paths.
- `layers` is the mutable current envelope but cannot be deleted.
- `materialized_findings` is rebuildable and never integrity authority.
- PostgreSQL changes require `LEDGER_TEST_DATABASE_URL` integration coverage.
- File, SQLite, and PostgreSQL storage lifecycle changes require `tests/test_storage_e2e.py`.

## Three-entry-point symmetry

Every write operation MUST work identically through the REST API, the `ledger`
CLI, and `LedgerClient`. All three converge on the same handlers
(`traust_ledger.handlers.*`). The internal layer (`_internal/writer.py`) raises
plain exceptions (`ValueError` subclasses). The service layer converts them to
`ServiceError` (→ HTTP status); the CLI to exit codes; `LedgerClient` to
`LedgerError`.

If you add a new error path to the writer, handle it in the handler layer —
all three entry points pick it up.

### Config split

`ServiceConfig` (`traust_ledger.config`) is a plain `BaseModel` — importable
with no optional deps. `ServiceSettings` (`traust_ledger.service.settings`)
extends it with `pydantic_settings.BaseSettings` for env-auto-loading;
only the REST app uses it. The CLI uses `config_from_env()` in
`traust_ledger.cli`. `LedgerClient` constructs `ServiceConfig` with explicit
kwargs.

## Extraction candidates (mixed concerns)

These modules have documented seams. Do NOT add more cross-concern code to them.
If you feel the urge to put filesystem traversal next to signing logic, stop and ask
the module owner first. The answer is no.

| Module | Mixed concerns | Target extraction |
|--------|---------------|-------------------|
| `_internal/reports.py` | hashing, signing lifecycle, filesystem traversal, metadata mutation | See module docstring |
| `_internal/writer.py` | `resolve_review_item` (queue semantics) + `_enforce_identity_rule` (authn policy) + schema validation + backend I/O — all in one class | Queue ops → own module; identity rule → `_internal/identity` or gates; validation → caller or middleware |
| `_internal/disposition.py` | `is_actor_verified` is an identity concern imported by `writer.py` — it's the actor-auth check living in the merge engine | → `_internal/identity` (the fingerprint module is NOT the right place either) |

Modules that are clean (single concern, leave alone):
- `_internal/identity.py` — fingerprint recipe only
- `_internal/hashing.py` — sha256 utility
- `_internal/errors.py` — plain exception defs
- `_internal/backends/` — storage protocol + impls
- `_internal/projection.py` — materialized findings schema (used by materialize CLI only)

## Ownership boundary

traust-ledger does NOT own:
- Tree iteration (which directories exist, naming conventions, skip-lists)
- Cross-layer joins or aggregation
- Dashboard queries or compliance scoring
- Deployment topology awareness
