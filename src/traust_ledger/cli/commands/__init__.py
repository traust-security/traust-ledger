from __future__ import annotations

import argparse

from traust_ledger.cli.commands.countersign import cmd_countersign
from traust_ledger.cli.commands.event import cmd_event
from traust_ledger.cli.commands.fingerprint import cmd_fingerprint
from traust_ledger.cli.commands.materialize import register_materialize_parser
from traust_ledger.cli.commands.migrate import register_migrate_parser
from traust_ledger.cli.commands.query import register_query_parser
from traust_ledger.cli.commands.resolve import register_resolve_parser
from traust_ledger.cli.commands.sign import register_sign_parser
from traust_ledger.cli.commands.status import cmd_status
from traust_ledger.cli.commands.submit import cmd_submit
from traust_ledger.cli.commands.verify import register_verify_parser


def register_write_parsers(subparsers: argparse._SubParsersAction) -> None:
    """Register fingerprint, countersign, event, submit subcommands."""
    fp_p = subparsers.add_parser("fingerprint", help="Stamp finding fingerprints on a report")
    fp_p.add_argument("report_path", help="Path to report JSON file")
    fp_p.set_defaults(handler=cmd_fingerprint)

    cs_p = subparsers.add_parser("countersign", help="Countersign a finding disposition")
    cs_p.add_argument("finding_ref", help="Finding reference to countersign")
    cs_p.add_argument(
        "--verdict",
        required=True,
        choices=["false_positive", "keep_open", "confirmed", "severity"],
    )
    cs_p.add_argument("--rationale", required=True, help="Rationale for the decision")
    cs_p.add_argument("--layer", help="Layer ID (auto-discovered if omitted)")
    cs_p.add_argument("--severity", help="New severity level (required for severity verdict)")
    cs_p.set_defaults(handler=cmd_countersign)

    ev_p = subparsers.add_parser("event", help="Submit a raw event")
    ev_p.add_argument("file_path", help="Path to event JSON file")
    ev_p.add_argument("--kind", required=True, help="Event kind")
    ev_p.set_defaults(handler=cmd_event)

    sub_p = subparsers.add_parser("submit", help="Batch-submit pre-formed events and queue items")
    sub_p.add_argument("events_file", help="JSON file: array or {events, needs_review}")
    sub_p.add_argument("--layer", required=True, help="Target layer ID")
    sub_p.add_argument("--queue", dest="queue_file", help="JSON array of needs_review items")
    sub_p.add_argument("--source-ref", dest="source_ref", default="", help="Source reference")
    sub_p.set_defaults(handler=cmd_submit)


def register_all_parsers(subparsers: argparse._SubParsersAction) -> None:
    """Register all command subparsers."""
    register_write_parsers(subparsers)
    register_query_parser(subparsers)
    register_migrate_parser(subparsers)
    register_materialize_parser(subparsers)
    register_verify_parser(subparsers)
    register_resolve_parser(subparsers)
    register_sign_parser(subparsers)
    status_p = subparsers.add_parser("status", help="Check ledger service/backend health")
    status_p.set_defaults(handler=cmd_status)
