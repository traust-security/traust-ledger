"""ledger submit — batch-submit pre-formed events and queue items."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from traust_ledger._internal.errors import EventIdMismatchError, IdentityUnverifiedError
from traust_ledger.cli import local_writer
from traust_ledger.cli.auth import require_cli_auth
from traust_ledger.cli.commands._fmt import print_submit_response
from traust_ledger.cli.identity.actor import require_verified_actor
from traust_ledger.paths import layer_key


def cmd_submit(args: argparse.Namespace) -> int:
    """Submit pre-formed events (and optional queue items) to a layer."""
    if require_cli_auth():
        return 1
    events_path = Path(args.events_file)
    try:
        payload = json.loads(events_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read events file: {exc}", file=sys.stderr)
        return 1

    if isinstance(payload, list):
        events = payload
        needs_review: list[dict] = []
    elif isinstance(payload, dict):
        events = payload.get("events", [])
        needs_review = payload.get("needs_review", [])
    else:
        print(
            "error: events file must be a JSON array or object with 'events' key",
            file=sys.stderr,
        )
        return 1

    queue_items: list[dict] = []
    if args.queue_file:
        queue_path = Path(args.queue_file)
        try:
            queue_data = json.loads(queue_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read queue file: {exc}", file=sys.stderr)
            return 1
        if isinstance(queue_data, list):
            queue_items = queue_data
        else:
            print("error: queue file must be a JSON array", file=sys.stderr)
            return 1

    all_queue = needs_review + queue_items

    actor = require_verified_actor()
    if actor is None:
        return 1
    writer, config = local_writer()
    layer_path = layer_key(writer.backend, config.data_dir, args.layer)

    stamped_events = []
    for event in events:
        if not isinstance(event, dict):
            continue
        source = event.get("source")
        if isinstance(source, dict):
            stamped = {**event, "source": {**source, "actor": actor.to_dict()}}
        else:
            stamped = {**event, "source": {"actor": actor.to_dict()}}
        stamped_events.append(stamped)

    event_ids: list[str] = []
    if stamped_events:
        try:
            event_ids = writer.append_events(layer_path, stamped_events)
        except EventIdMismatchError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        except IdentityUnverifiedError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    queue_added = 0
    if all_queue:
        for item in all_queue:
            if isinstance(item, dict):
                item.setdefault("submitted_by", actor.to_dict())
                item.setdefault("source_ref", args.source_ref or "")
        queue_added = writer.append_needs_review(layer_path, all_queue)

    total = len(event_ids) + queue_added
    print_submit_response(
        {
            "id": f"batch:{args.layer}",
            "status": "accepted",
            "event_count": total,
        }
    )
    return 0
