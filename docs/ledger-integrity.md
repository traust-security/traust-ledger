# Ledger integrity

What makes a layer tamper-evident, and what `traust_ledger.integrity` checks. The library computes; the caller (traust-core's `LedgerService`) stores layers and events and decides what goes in an event.

## The layer document

Every function reads and stamps one shape:

```json
{
  "events": [{"...": "one decision, any JSON object"}],
  "metadata": {
    "merkle_root": "hex", "merkle_size": 3, "merkle_epoch": 0, "leaf_format": 2,
    "merkle_root_signature": "cosign bundle", "merkle_signing_method": "keypair",
    "merkle_signature_format": 4
  }
}
```

## Leaves and root

- **Leaf format 2** (current): each leaf is `canonical_event_bytes(event)`: the whole event, sorted keys, compact separators, `merkle_*` keys excluded so stamping can't invalidate itself. Editing any field, removing an event or reordering events changes the root.
- **Leaf format 1** (legacy): leaves bind `event_id` only. Still verifies, always with an error saying event content isn't bound.
- The tree is RFC 6962-style (`0x00` leaf / `0x01` node prefixes), with inclusion and consistency proofs.
- `merkle_epoch > 0` pins events before the epoch with `pre_merkle_checkpoint` (a digest of them).

### Appending without rereading

`extend_frontier(frontier, size, entry)` appends one leaf to a tree from its frontier: the roots of the perfect subtrees covering its leaves, largest first, one per set bit of the size (at most log2(size) hashes). `frontier_root(frontier)` is the same root `compute_root` gives over every leaf; `compute_frontier(entries)` builds the frontier of an existing tree once. A writer that keeps the frontier appends in O(log n) and never reads earlier leaves, so an edit to a stored event can't be folded into the next root: it stays a mismatch for verification to find.

## Stamping and signing

| Function | Does |
|---|---|
| `stamp_merkle_metadata(layer)` | recomputes root and size; a changed root drops a stale signature (returns `True`) |
| `sign_if_configured(layer, config)` | signs the stamped metadata when `config` has a key; else `unconfigured`. Never silent on failure |

A writer that appends from a frontier sets `merkle_root` and `merkle_size` itself (`frontier_root`) and calls `sign_if_configured` on a document with only the metadata: signing never reads events. The frontier is the writer's to store (traust-core keeps it on the layer row); it isn't part of the document.

The signature (format 4) covers a digest of the root, leaf format, epoch, size, pre-epoch checkpoint and, for legacy layers, the claim-hash, report and artifact digests, so a signature can't be moved to another layer or replayed after a rollback.

`SigningConfig` is built by the caller from its own configuration; the library reads no environment variables.

| `method` | Signs with |
|---|---|
| `keypair` | cosign 3 and a private key (`key_path`); offline, no transparency-log upload |

## Verification

`verify_merkle_integrity(layer)` returns findings (errors and warnings; empty means clean):

- root and size recomputed from the stored events match the metadata
- epoch in range; pre-epoch checkpoint matches
- known leaf format (format 1 is reported)
- restated metadata: for each signature-bound field (`claim_hashes`, `audit_report_sha256`, `artifact_digests`) that a restatement event changed, the stored value still equals what the last restatement gave it

`verify_merkle_signature(layer, pubkey_path, *, required=False)` checks the signature with the method the layer declares. An absent signature is an error when `required`; a signature with no public key to check it is a warning.

## Historical layers

Layers written before traust-core (file layers, the old ledger service's database including SCI's, leaf format 1 or 2, signature formats 1 to 4, restatement chains) verify with the same two functions. They're kept as signed artifacts, never loaded into traust-core's ledger tables, which have no place for their legacy metadata. Nothing in a signed layer is rewritten.
