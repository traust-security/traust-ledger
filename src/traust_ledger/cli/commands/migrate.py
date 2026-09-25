"""Administrative migration into normalized Ledger storage."""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path


def _redact(url: str) -> str:
    return re.sub(r"://[^/@]*:[^/@]*@", "://***:***@", url)


def register_migrate_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("migrate", help="Migrate complete historical layers")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--source-dir", type=Path, help="Ledger data directory")
    parser.add_argument(
        "--selection-manifest",
        type=Path,
        help="decisions.jsonl from artifact preview; requires --source-dir",
    )
    source.add_argument(
        "--source-database-url",
        help="artifact storage SQLAlchemy URL; prefer LAAS_MIGRATION_SOURCE_URL for credentials",
    )
    source.add_argument(
        "--source-ledger-database-url",
        help="normalized Ledger URL; prefer LAAS_MIGRATION_SOURCE_URL for credentials",
    )
    parser.add_argument(
        "--target-database-url",
        help="Ledger SQLAlchemy URL; prefer LAAS_MIGRATION_TARGET_URL for credentials",
    )
    parser.add_argument(
        "--writer-role",
        help="PostgreSQL runtime writer role; defaults to LAAS_MIGRATION_WRITER_ROLE",
    )
    parser.add_argument(
        "--projector-role",
        help="PostgreSQL projection writer role; defaults to LAAS_MIGRATION_PROJECTOR_ROLE",
    )
    parser.add_argument(
        "--reader-role",
        help="PostgreSQL projection reader role; defaults to LAAS_MIGRATION_READER_ROLE",
    )
    parser.add_argument(
        "--signature-key",
        help="public key used to verify signatures; defaults to LAAS_MIGRATION_SIGNATURE_KEY",
    )
    parser.add_argument("--layer", action="append", dest="layers", help="limit to a layer ID")
    parser.add_argument(
        "--dry-run", action="store_true", help="validate and compare without writing"
    )
    parser.add_argument("--json", action="store_true", help="emit one JSON object per layer")
    parser.set_defaults(handler=cmd_migrate)


def cmd_migrate(args: argparse.Namespace) -> int:
    from sqlalchemy import create_engine

    from traust_ledger._internal.historical_migration import (
        iter_artifact_layers,
        iter_directory_layers,
        iter_ledger_layers,
        iter_manifest_layers,
        migrate,
    )
    from traust_ledger._internal.migrations import DatabaseRoles

    source_url = (
        os.environ.get("LAAS_MIGRATION_SOURCE_URL")
        or args.source_database_url
        or args.source_ledger_database_url
    )
    target_url = os.environ.get("LAAS_MIGRATION_TARGET_URL") or args.target_database_url
    if not target_url:
        raise SystemExit("target database required: set LAAS_MIGRATION_TARGET_URL")
    if (args.source_database_url and "@" in args.source_database_url) or (
        args.source_ledger_database_url and "@" in args.source_ledger_database_url
    ):
        raise SystemExit("source URL contains credentials; use LAAS_MIGRATION_SOURCE_URL")
    if args.target_database_url and "@" in args.target_database_url:
        raise SystemExit("target URL contains credentials; use LAAS_MIGRATION_TARGET_URL")

    if args.selection_manifest is not None and args.source_dir is None:
        raise SystemExit("--selection-manifest requires --source-dir")
    if args.source_dir is not None:
        layers = (
            iter(list(iter_manifest_layers(args.source_dir, args.selection_manifest)))
            if args.selection_manifest is not None
            else iter_directory_layers(args.source_dir)
        )
        source_name = str(args.source_dir)
    else:
        if not source_url:
            raise SystemExit("source database required: set LAAS_MIGRATION_SOURCE_URL")
        source_engine = create_engine(source_url)
        layers = (
            iter_ledger_layers(source_engine)
            if args.source_ledger_database_url is not None
            else iter_artifact_layers(source_engine)
        )
        source_name = _redact(source_url)

    selected = set(args.layers) if args.layers else None
    roles = DatabaseRoles(
        writer=args.writer_role or os.environ.get("LAAS_MIGRATION_WRITER_ROLE"),
        projector=args.projector_role or os.environ.get("LAAS_MIGRATION_PROJECTOR_ROLE"),
        reader=args.reader_role or os.environ.get("LAAS_MIGRATION_READER_ROLE"),
    )
    counts = {"inserted": 0, "skipped": 0, "would_insert": 0, "conflict": 0, "quarantined": 0}
    seen: set[str] = set()
    events = 0
    review_items = 0
    validation_warnings = 0
    for result in migrate(
        layers,
        target_url,
        dry_run=args.dry_run,
        selected=selected,
        roles=roles,
        signature_key=args.signature_key or os.environ.get("LAAS_MIGRATION_SIGNATURE_KEY"),
    ):
        seen.add(result.layer_id)
        counts[result.status] += 1
        events += result.events
        review_items += result.review_items
        validation_warnings += result.validation_warnings
        if args.json or result.detail:
            print(json.dumps(result.__dict__, sort_keys=True))

    missing = sorted((selected or set()) - seen)
    summary = {
        "status": "error" if counts["conflict"] or counts["quarantined"] or missing else "ok",
        "source": source_name,
        "target": _redact(target_url),
        "dry_run": args.dry_run,
        "layers": sum(counts.values()),
        "events": events,
        "review_items": review_items,
        "validation_warnings": validation_warnings,
        "counts": counts,
        "missing": missing,
    }
    print(json.dumps(summary, sort_keys=True))
    return 1 if summary["status"] == "error" else 0
