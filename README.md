# traust-ledger

The ledger's integrity primitives, as a library: canonical event bytes, Merkle trees with inclusion and consistency proofs and appends from a stored frontier, signing and verification of a layer document. Pure functions; no database, no HTTP, no configuration of its own.

A **layer** is an append-only, signed sequence of events: never edited, only appended to. traust-core's `LedgerService` stores layers and events (one event per recorded decision) and calls this library to grow, sign and verify them. Everyone else reaches the ledger through the platform API.

## Use

```python
from traust_ledger.integrity import (
    SigningConfig,
    sign_if_configured,
    stamp_merkle_metadata,
    verify_merkle_integrity,
)

layer = {"events": [{"id": "...", "validity": "false_positive"}], "metadata": {}}
stamp_merkle_metadata(layer)  # recompute root; a changed root drops a stale signature
attempt = sign_if_configured(layer, SigningConfig(method="keypair", key_path="cosign.key"))
assert verify_merkle_integrity(layer) == []
```

What each function guarantees, the leaf and signature formats, and how historical layers verify: [docs/ledger-integrity.md](docs/ledger-integrity.md).

## Install

Consumers pin by commit SHA; there are no releases or tags:

```toml
[tool.uv.sources]
traust-ledger = { git = "https://github.com/traust-security/traust-ledger.git", rev = "<sha>" }
```

Signing shells out to [cosign](https://github.com/sigstore/cosign) 3 with a private key; offline, no transparency-log upload.

## Development

```bash
make setup    # uv sync + git hooks
make lint
make test     # signing tests run when cosign is on PATH
```

## License

Apache-2.0
