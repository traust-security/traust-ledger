# traust-ledger

The disposition-ledger kernel, extracted from `traust`. Small by design:
this is the *legible* layer — reviewed line-by-line, changed rarely, and consumed by
every component that touches the ledger.

A **disposition layer** is an append-only, Merkle-signed log of human/machine
dispositions against one security-audit report — never edited, only appended to;
corrections are new events, and state is derived by replaying the log.

## Boundaries

`traust_ledger` (the library) fixes the domain model, the write contract, and the
integrity scheme — those are the same for every deployment, so a layer written by one
can verify under another.

Three OIDC-gated entry points: `LedgerClient` (in-process SDK), CLI, REST API.
All three converge on shared handlers (`traust_ledger.handlers`).

`ServiceConfig` (plain `BaseModel`) is importable with no optional deps.
`ServiceSettings` (env-auto-loading via `pydantic_settings`) is behind the
`[service]` extra — only the REST app needs it.

## Docs

| Doc | Covers |
|---|---|
| [`docs/ledger-model.md`](docs/ledger-model.md) | Layers, events, Merkle integrity, the write contract |
| [`docs/finding-identity.md`](docs/finding-identity.md) | The fingerprint: the recipe, what it excludes, `ALGO_VERSION`, strict mode, what it is *not* |
| [`docs/service-identity.md`](docs/service-identity.md) | Pluggable authn providers (OIDC, API key), endpoint protection, testing with mock IdP |
| [`docs/auth.md`](docs/auth.md) | Identity vs integrity split, Merkle-root signing |
| [`docs/deploying.md`](docs/deploying.md) | Running the service, container image, Kubernetes manifests |
| [`docs/data-model.md`](docs/data-model.md) | Proposed normalized DB schema for `DbBackend` at scale |

## Install

Depends on `traust-contracts` as a versioned package (not a submodule).

```bash
make setup    # uv sync + enable .githooks
make test
```

## Development

### Running tests

```bash
make test               # unit tests only (no Docker needed)
make mock-idp           # start mock OIDC server (mockserver on :1080)
make test-integration   # integration tests (requires mock-idp)
make mock-idp-stop      # tear down mock server
make coverage-all       # full coverage: starts mock-idp, runs all tests, stops it
```

### OpenAPI spec

```bash
make openapi            # regenerate docs/openapi.{json,yaml}
```

### Identity providers

OIDC is the only identity provider. For local dev, use the mock IdP:

```bash
make mock-idp
export LAAS_OIDC_JWKS_URL=http://localhost:1080/.well-known/jwks.json
```

The CLI uses `ledger auth login` (OIDC device flow); the REST API validates bearer
JWTs. Machine callers use `ledger auth service-account` (OIDC client-credentials) or
Kubernetes projected SA tokens; `ledger auth local --machine` mints an offline machine
identity for operator-run work on a trusted host.

Identity is decided by claim shape, not by a flag: a token carrying the machine claim
(`azp`) and **no** identity claim (`email`) resolves to a machine actor, anything with
an identity claim to a human. A service-account token that arrives carrying an address
therefore records a *human* actor — `ledger auth service-account` warns at acquisition
rather than letting that surface later as misattribution.

See [`docs/service-identity.md`](docs/service-identity.md) for full provider docs.

Consumers pin both:

```toml
[project]
dependencies = ["traust-ledger>=0.2.1", "traust-contracts>=0.3.0"]

[tool.uv.sources]
traust-ledger = { git = "ssh://git@<your-forge>/<namespace>/traust-ledger.git", tag = "v0.2.1" }
traust-contracts = { git = "ssh://git@<your-forge>/<namespace>/traust-contracts.git", tag = "v0.3.0" }
```

The authoritative pins for this repo are in its own `pyproject.toml` — if the block above
disagrees with it, `pyproject.toml` wins and this README is stale.

Local mono-checkout: point `[tool.uv.sources]` at a sibling path.

## Module reference

| Module | Contents |
|---|---|
| `traust_ledger.client` | `LedgerClient` — in-process Python SDK (OIDC-gated; `actor()` returns the verified actor after the optional employee-directory cross-check, `directory=` overrides `LEDGER_DIRECTORY_COMMAND`); `LedgerError` (raised when a ledger operation fails); `resolve_env_token` (identity token for SDK callers). See [`docs/consumer-integration.md`](docs/consumer-integration.md). |
| `traust_ledger.config` | `ServiceConfig` — plain `BaseModel` config bag, importable with no optional deps. |
| `traust_ledger.api.identity` | Fingerprint primitives: `canon_repo`, `canon_path`, `primary_cwe`, `fingerprint`; `DegenerateIdentity` (refused — the finding carries no usable location). See `docs/finding-identity.md`. |
| `traust_ledger.api.events` | Event math: `compute_event_id`, `compute_claim_hash`, `attach_identity`, `make_alias_event` (rebaseline alias: old finding_ref → successor); projections `findings_from_events`, `aliases_from_events`, `fingerprint_index`; constants `CLAIM_FIELDS`, `FINGERPRINT_ALGO_CURRENT`. |
| `traust_ledger.api.disposition` | `derive_disposition`, `is_actor_verified`, `event_class` (1 = execution-verified, 2 = human static, 3 = machine static). |
| `traust_ledger.api.integrity` | Merkle verification, stamping: `verify_merkle_integrity`, `verify_merkle_signature`; results as `IntegrityFinding` with a `Severity`. See `docs/ledger-model.md`. |
| `traust_ledger.api.reports` | `report_sha256`, `check_report_digest`, `stamp_report_reference`; sibling artifacts: `stamp_artifact_digests`, `check_artifact_digests`. |
| `traust_ledger.handlers` | Shared handler layer — CLI, REST, and LedgerClient all converge here. Package surface: `submit_event`, `load_layer`, `sign_layer`. |
| `traust_ledger.service` | LaaS FastAPI app (`[service]` extra): `create_app`. See `docs/deploying.md`. |
| `traust_ledger.service.settings` | `ServiceSettings` — env-auto-loading config (`[service]` extra). |

## Versioning

Semver, pre-1.0 (`0.x`): the API is still settling during the harness bake period.
Identity semantics are versioned separately via `algo_version` in the contracts vectors
and never change silently. A recipe change computes forward only — stored fingerprints are
never rewritten.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
