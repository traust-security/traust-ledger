"""traust-ledger: the ledger's integrity primitives, as a library.

`traust_ledger.integrity` computes canonical event bytes, Merkle roots, signatures and
verification over a layer document. It holds no state and reaches no database or API;
traust-core's `LedgerService` stores layers and events and calls it.
"""
