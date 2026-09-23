"""Lazy registration for the SQLAlchemy-backed materialize command."""

from __future__ import annotations

import argparse


def register_materialize_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("materialize", help="Rebuild the queryable findings projection")
    parser.add_argument("--to", help="target SQLAlchemy URL")
    parser.add_argument("--prune-empty", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--ddl", action="store_true")
    parser.add_argument("--layer", action="append", dest="layers", metavar="ID")
    parser.set_defaults(handler=cmd_materialize)


def cmd_materialize(args: argparse.Namespace) -> int:
    from traust_ledger.cli.materialize import cmd_materialize as run

    return run(args)
