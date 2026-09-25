"""Initialize a complete, caller-authored layer via the shared handler."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from traust_ledger.cli import local_writer
from traust_ledger.cli.auth import require_cli_auth
from traust_ledger.cli.identity.actor import require_verified_actor
from traust_ledger.errors import ServiceError
from traust_ledger.handlers.initialize_handler import initialize_layer


def cmd_initialize(args: argparse.Namespace) -> int:
    if require_cli_auth():
        return 1
    actor = require_verified_actor()
    if actor is None:
        return 1
    try:
        shell = json.loads(Path(args.layer_file).read_text(encoding="utf-8"))
        if not isinstance(shell, dict):
            raise ValueError("layer shell must be a JSON object")
        writer, config = local_writer()
        result = initialize_layer(args.layer, shell, actor, writer.backend, config)
    except (OSError, ValueError, ServiceError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0
