"""Unified ledger CLI entry point."""

from __future__ import annotations

import argparse
import sys

from traust_ledger._internal.backends.errors import LayerStorageError
from traust_ledger.cli.commands import register_all_parsers
from traust_ledger.cli.identity.commands import register_auth_parser


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ledger", description="Ledger disposition CLI")
    subparsers = parser.add_subparsers(dest="command")
    register_auth_parser(subparsers)
    register_all_parsers(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 1
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 1
    try:
        return handler(args)
    except LayerStorageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
