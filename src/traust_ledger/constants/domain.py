from __future__ import annotations

from traust_ledger._internal.events.builders import (
    DECISION_FALSE_POSITIVE,
    DECISION_OVERRIDE_FALSE_POSITIVE,
)

ACTOR_KIND_MACHINE = "machine"
VERDICT_FALSE_POSITIVE = "false_positive"
VERDICT_TRUE_POSITIVE = "true_positive"

RATIONALE_MIN_LENGTH = 10
TIMESTAMP_FUTURE_LIMIT_HOURS = 24

ACTOR_KIND_HUMAN = "human"
DECISION_KEEP_OPEN = "keep_open"
STATUS_ACCEPTED = "accepted"

ALLOWED_DECISIONS = frozenset(
    {
        DECISION_KEEP_OPEN,
        DECISION_FALSE_POSITIVE,
        DECISION_OVERRIDE_FALSE_POSITIVE,
    }
)

# `layer_id` is OPAQUE. Nothing may parse it, split it, or derive a repo, product or
# branch from it — a 2026-08-20 sweep of all 40 usages found none that do: it is a
# validated token, a filename stem, a primary key, a URL segment, a log field and a
# pagination cursor, and nothing else. Two consequences worth stating, because they
# are easy to break by accident: the pattern forbids `/` on purpose (the id becomes a
# filename via `layer_file_path`, so a separator here is a path separator), and the
# id is a cursor, so it must be stable and sortable.
# **A single leading dot is allowed; `..` is not.** Real repositories are named
# `.github`, `.fullsend`, `.project`, `.github-private` — GitHub's own convention — and
# six such layers already exist in the corpus. Rejecting them made those layers
# unwritable through the SDK: `LedgerClient.sign()` raised ValueError, which aborted
# any corpus-wide pass at the first one (found 2026-09-02 by an artifact-digest
# backfill). The security property is traversal, not hiddenness: `..` stays forbidden
# anywhere in the id, a bare `.` is rejected, and `/` was never permitted.
#
# **Caveat that the pattern cannot fix.** A dot-prefixed id is a hidden file, so
# `glob.glob` and shell wildcards silently skip it — measured on the corpus:
# `pathlib.rglob` finds all six, `glob.glob` finds none. Any sweep over layers must
# use `pathlib.rglob` or `os.walk`, or it will under-count without saying so.
LAYER_ID_PATTERN = r"^(?!\.\.)(?!.*\.\.)\.?[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$"

# Database layer IDs are never filenames, so `LAYER_ID_PATTERN` does not apply: they are
# bound as SQL values and may carry `:` and `/` (migrated corpus IDs such as
# `corpus:layer:<subject>`). Still opaque: printable, no surrounding whitespace, bounded.
DB_LAYER_ID_PATTERN = r"^[^\x00-\x20\x7f](?:[^\x00-\x1f\x7f]*[^\x00-\x20\x7f])?$"
DB_LAYER_ID_MAX_LENGTH = 512

# Storage assigns product_repo ids as str(uuid.uuid4()).
PRODUCT_REPO_ID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

__all__ = [
    "ACTOR_KIND_HUMAN",
    "ACTOR_KIND_MACHINE",
    "ALLOWED_DECISIONS",
    "DB_LAYER_ID_MAX_LENGTH",
    "DB_LAYER_ID_PATTERN",
    "DECISION_FALSE_POSITIVE",
    "DECISION_KEEP_OPEN",
    "DECISION_OVERRIDE_FALSE_POSITIVE",
    "LAYER_ID_PATTERN",
    "PRODUCT_REPO_ID_PATTERN",
    "RATIONALE_MIN_LENGTH",
    "STATUS_ACCEPTED",
    "TIMESTAMP_FUTURE_LIMIT_HOURS",
    "VERDICT_FALSE_POSITIVE",
    "VERDICT_TRUE_POSITIVE",
]
