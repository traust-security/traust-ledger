"""CLI: materialize resolved findings into a queryable store.

Usage:
    python -m traust_ledger.cli.materialize --to sqlite:///findings.db
    python -m traust_ledger.cli.materialize --to postgresql://user:pass@host/db
    python -m traust_ledger.cli.materialize --layer layer-a --layer layer-b
    python -m traust_ledger.cli.materialize --ddl

Re-running is idempotent — rows are keyed on (layer_id, finding_ref).
Each layer commits independently so partial failures don't corrupt.

Env (same LAAS_ prefix as the service):
    LAAS_BACKEND_TYPE       file | db (default: file)
    LAAS_DATA_DIR           path to layer data directory
    LAAS_DATABASE_URL       SQLAlchemy URL when backend_type=db
    LAAS_MATERIALIZE_URL    target URL — use this, not --to, for anything with
                            credentials: argv is world-readable via ps
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime

from sqlalchemy import create_engine

from traust_ledger._internal.projection import build_row, ensure_schema, print_ddl, upsert_layer
from traust_ledger.api.findings import resolve_layer_findings as _resolve_layer_findings
from traust_ledger.cli import backend_from_env, iter_layers
from traust_ledger.handlers.findings_handler import _layer_merkle_meta


def _redact(url: str) -> str:
    """Never echo a password back, not even into a success line someone pipes to a log."""
    return re.sub(r"://[^/@]*:[^/@]*@", "://***:***@", url)


def _configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--to",
        help="SQLAlchemy URL for the target store (e.g. sqlite:///findings.db). "
        "For any URL carrying credentials use LAAS_MATERIALIZE_URL instead: "
        "argv is world-readable via ps.",
    )
    parser.add_argument(
        "--prune-empty",
        action="store_true",
        help="delete a layer's projection rows when it resolves to zero findings "
        "(default: leave the last good state; an unreadable layer must not "
        "look like an empty one)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON-line output per layer to stdout",
    )
    parser.add_argument(
        "--ddl",
        action="store_true",
        help="Print the projection table DDL and exit",
    )
    parser.add_argument(
        "--layer",
        action="append",
        dest="layers",
        metavar="ID",
        help="Materialize only this layer ID (repeatable)",
    )


def register_materialize_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("materialize", help="Rebuild the queryable findings projection")
    _configure_parser(parser)
    parser.set_defaults(handler=cmd_materialize)


def cmd_materialize(args: argparse.Namespace) -> int:
    if args.ddl:
        print_ddl()
        return 0

    target_url = os.environ.get("LAAS_MATERIALIZE_URL") or args.to
    if not target_url:
        raise SystemExit(
            "a target is required unless --ddl is specified: pass --to for a local "
            "sqlite path, or set LAAS_MATERIALIZE_URL for anything with credentials"
        )
    if args.to and "@" in args.to:
        print(
            "WARNING: --to contains credentials, which are visible in ps to every "
            "local user — use LAAS_MATERIALIZE_URL instead",
            file=sys.stderr,
        )

    target_engine = create_engine(target_url)
    ensure_schema(target_engine)

    layer_filter = set(args.layers) if args.layers else None
    now = datetime.now(UTC)
    total_findings = 0
    total_layers = 0
    seen_layers: set[str] = set()

    backend, data_dir = backend_from_env()
    source = iter_layers(backend, data_dir)

    for layer_id, layer in source:
        if layer_filter is not None and layer_id not in layer_filter:
            continue
        seen_layers.add(layer_id)
        findings, summary = _resolve_layer_findings(layer)
        merkle_root, merkle_epoch = _layer_merkle_meta(layer)
        rows = [build_row(layer_id, f, merkle_root, merkle_epoch, now) for f in findings]

        with target_engine.begin() as conn:
            upsert_layer(conn, layer_id, rows, prune_empty=args.prune_empty)

        total_findings += len(findings)
        total_layers += 1

        if args.json:
            print(
                json.dumps(
                    {
                        "layer_id": layer_id,
                        "findings": len(findings),
                        "summary": summary.model_dump(),
                    }
                )
            )

    if layer_filter is not None:
        for layer_id in sorted(layer_filter - seen_layers):
            print(f"warning: layer {layer_id!r} not found", file=sys.stderr)

    if not total_layers:
        print(json.dumps({"error": "no layers found"}), file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "status": "ok",
                "layers": total_layers,
                "findings": total_findings,
                "target": _redact(target_url),
            }
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Materialize resolved findings into a queryable store",
    )
    _configure_parser(parser)
    return cmd_materialize(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
