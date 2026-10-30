# traust-ledger

Python 3.11+ library (`traust_ledger.integrity`): the ledger's integrity primitives. Small, reviewed line by line, changed rarely.

- **Before done:** `make lint-fix` then `make test`; CI enforces both
- **Lint:** line length 100; ruff E/W/F/I/UP/B/SIM/PTH/RUF (`pyproject.toml`)
- **Commits:** conventional `type(scope): subject`
- **Drift ratchet:** CI runs traust-core's ratchet over `src`; `.ratchet.json` only shrinks. Its one entry is cosign's `subprocess` in `signing.py`; env, clock, file writes, HTTP and DB stay at zero (see *What doesn't*)
- **No releases:** consumers pin by commit SHA. After a merge, traust-core bumps its `[tool.uv.sources]` pin and runs its ledger tests
- **Format changes** (leaf bytes, signature payload, verification rules) must keep historical layers verifying: add a format number, never change an old one

## What lives here

| Module | Does |
|---|---|
| `integrity/merkle.py` | canonical event bytes, RFC 6962-style tree, inclusion and consistency proofs, appends from a frontier |
| `integrity/signing.py` | `SigningConfig`; cosign (keypair) and Sigstore (identity) backends |
| `integrity/ledger.py` | stamp, sign and verify a layer document; signature payload formats |
| `integrity/restatements.py` | restatement chain replay for verifying signature-bound metadata |

## What doesn't

- **State:** no database, files or object storage; the caller stores layers and events (traust-core)
- **Domain:** what an event contains, finding identity, dispositions, gates, who may write: traust-core
- **Transport and auth:** the platform API (traust-core)
- **Configuration:** no environment variables; the caller passes a `SigningConfig`
- **Dependencies:** none required; `sigstore` only for keyless signing
