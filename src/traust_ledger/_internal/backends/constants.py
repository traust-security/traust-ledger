"""Backend storage constants."""

from __future__ import annotations

BACKEND_TYPE_FILE = "file"
BACKEND_TYPE_DB = "db"

LAYERS_TABLE_NAME = "layers"
EVENTS_TABLE_NAME = "events"

DATABASE_URL_REQUIRED_MSG = "database_url is required for db backend"

LAYER_EVENTS_KEY = "events"
EMPTY_LAYER: dict[str, list[dict]] = {LAYER_EVENTS_KEY: []}

JSON_ENCODING = "utf-8"
JSON_INDENT = 2
JSON_ENSURE_ASCII = True
TEMP_FILE_SUFFIX = ".tmp"
LOCK_FILE_SUFFIX = ".lock"
NEWLINE = "\n"

UNKNOWN_BACKEND_MSG = "Unknown backend type: {backend_type}"
