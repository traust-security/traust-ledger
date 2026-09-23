# Deploying the service

Ledger-as-a-Service (`traust_ledger.service`) is a FastAPI app, run via:

```bash
uvicorn traust_ledger.service.app:create_app --factory --host 0.0.0.0 --port 8000
```

Config is entirely `LAAS_*` environment variables (`ServiceSettings` in
`traust_ledger.service.settings`, which extends `ServiceConfig` with `pydantic-settings`).
See [`../.env.example`](../.env.example) for the full list with defaults; auth/signing
seams are documented in [`auth.md`](auth.md) and [`service-identity.md`](service-identity.md).

## Storage backend

The internal `Backend` protocol supports `FileBackend` (default, zero dependencies,
JSON on disk) and `DbBackend` (SQLite or PostgreSQL through SQLAlchemy). Select it
with `LAAS_BACKEND_TYPE=file|db` plus `LAAS_DATABASE_URL`. SQLite uses a dedicated
Ledger file; PostgreSQL uses schema `traust_ledger`. The implemented revisioned
schema and append-only guards are documented in [`data-model.md`](data-model.md).

## Container image

`Containerfile`: multi-stage `uv` build, runs as non-root (`laas`, uid 1001), ships
`cosign` for signing without a sidecar (the key itself is mounted separately, never
baked into the image). `/healthz` backs the `HEALTHCHECK`.

## Kubernetes manifests (`deploy/`)

| File | Notes |
|---|---|
| `deployment.yaml` | **`replicas: 1`** — single-writer design, exactly one replica holds the write lock. Pod runs as uid/gid **1001** with `fsGroup: 1001` so the data volume is writable. Read-only root filesystem, all capabilities dropped, `runAsNonRoot`. Signing key mounted from an *optional* secret (`laas-signing-key`) at `/var/run/secrets/laas/signing-key/cosign.key` — absent by default, required when `LAAS_SIGNING_REQUIRED=true`. Optional `laas-secrets` for DB URL and OIDC. |
| `configmap.yaml` | Default env: file backend, `LAAS_IDENTITY_PROVIDER=oidc`, signing off. Supply `LAAS_OIDC_JWKS_URL` via `laas-secrets` or the `overlays/oidc/` overlay. Sensitive values go in `laas-secrets` (see `secret.example.yaml`). |
| `secret.example.yaml` | Template for `laas-secrets` (DB URL, OIDC) and `laas-signing-key` (cosign key). Copy and customize — never commit real values. |
| `kustomization.yaml` | `kubectl apply -k deploy/` bundles the base manifests. |
| `serviceaccount.yaml` / `service.yaml` | Dedicated `laas` service account; `ClusterIP` service on port 8000. |

Forbidden service accounts (`sci-api`, `default`) and other deploy-time invariants are
enforced by `tests/test_deploy_invariants.py`, not by convention — a manifest that
regresses one of them fails CI.

## Periodic integrity verification

`deploy/cronjob.yaml` runs `python -m traust_ledger.cli verify --all` every 6 hours. The CLI
sweeps all layers, runs `verify_merkle_integrity` (+ optional signature check), and exits
non-zero if any layer fails or zero layers are found. Standard Kubernetes monitoring
(`kube_job_status_failed`) catches failures.

On-demand verification is also available via the REST endpoint:

```
GET /v1/ledger/layers/{layer_id}/verify
```

Returns `{passed, findings, checked_at}`. Pass `?check_signatures=true` to also verify
merkle signatures (defaults to the value of `LAAS_SIGNING_REQUIRED`).

**CronJob volume:** The base manifest uses `emptyDir` as a placeholder. Production
overlays **must** bind the real data volume (PVC/NFS). The CLI exits non-zero when zero
layers are found, so a misconfigured mount fails loudly rather than passing vacuously.

## Findings read model

```
GET /v1/ledger/layers/{layer_id}/findings
```

Returns resolved current disposition per finding with precedence applied (validation >
human > triage, two-person satisfied, assurance, conflict, severity override). The
response includes `ledger_only: true` to signal that `base_validity` defaults to
`not_verified` (no audit report available). Consumers with the audit report can enrich
further via `build_cumulative`.

The bulk endpoint resolves all layers with cursor-based pagination:

```
GET /v1/ledger/findings?limit=100&cursor=<layer_id>&since_epoch=<n>
```

- `cursor` — resume after this layer_id (stable across rebuilds; no skip/duplicate).
- `limit` — max layers per page (1–1000, default 100).
- `since_epoch` — only include layers with `merkle_epoch >= n` (incremental delta).
- Response includes `next_cursor` and `has_more` for iteration, plus `merkle_root`
  and `merkle_epoch` per layer for staleness detection.

### Materializing findings into a queryable store

For dashboard-backing tables, the materialize CLI writes resolved findings into any
SQLAlchemy-compatible database:

```bash
ledger materialize --to sqlite:///findings.db
LAAS_MATERIALIZE_URL=postgresql://user:pass@host/db ledger materialize
ledger materialize --ddl   # print schema DDL and exit
```

Rows are keyed on `(layer_id, finding_ref)` — re-running is idempotent (upsert).
Each layer commits independently, so partial failures don't corrupt prior work.
The table includes `merkle_root` and `merkle_epoch` so consumers can answer
"is my view stale?" without re-resolving.

Pass `--json` for per-layer JSON-line progress. Pass `--ddl` to emit the
`CREATE TABLE` DDL without connecting to a database — this is the portable
artifact downstream dashboards bind to.

The flow:

```
ledger (any backend)
  └─ materialize CLI resolves precedence (derive_disposition)
       └─ upserts rows into target store (SQLite / Postgres / …)
            └─ SQL views + indexes over THAT → dashboards
```

The precedence engine lives in `traust_ledger.api.disposition` — shared by the service,
the harness engine, and SCI.

**Not yet built:** A push/streaming materializer (change-feed driven). Pull-on-schedule
covers every current consumer. Push requires change notification the service doesn't
have yet — deferred until demand materializes.

## Production overrides

| Setting | Default | Production recommendation |
|---|---|---|
| `LAAS_SIGNING_REQUIRED` | `false` | **`true`** — enables tamper-evident merkle signatures. Set it together with `LAAS_SIGNING_KEY_PATH`: the key path alone lets a broken mount degrade silently to unsigned, while `REQUIRED` alone fails loudly. Full variable list, and the `HARNESS_SIGNING_*` fallback, in [`auth.md`](auth.md#every-signing-setting-in-one-place). |
| `LAAS_BACKEND_TYPE` | `file` | `db` for multi-node access (Postgres recommended) |
| `replicas` | `1` | **Keep at 1** — single-writer design. The file backend uses `flock(2)` which is advisory and may not work on NFS. The DB backend uses `SELECT ... FOR UPDATE` which provides row-level locking on Postgres but is a silent no-op on SQLite. |

### SQLite considerations

SQLite is a valid backend for small/single-writer deployments. Be aware:

- **`FOR UPDATE` is a no-op** — SQLite has no row-level locking. Concurrency
  correctness relies on database-level write serialization (WAL mode + `busy_timeout`,
  both configured automatically by `create_backend`).
- SQLite serializes database writes; the backend still enforces suffix-only event
  appends and installs update/delete/sequence-gap triggers.
- **Concurrency tests must run against PostgreSQL.** Set `LEDGER_TEST_DATABASE_URL`;
  `tests/test_storage_e2e.py` covers the file, SQLite, and PostgreSQL lifecycle.

### NFS `flock` caveat

When using the file backend on NFS, `flock(2)` is advisory and may not provide
mutual exclusion across hosts. Stick to `replicas: 1` or use the DB backend for
multi-node deployments.
