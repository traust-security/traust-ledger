"""CLI shared infrastructure — backend bootstrap, layer iteration, local writer."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from traust_ledger._internal.backends import Backend, create_backend
from traust_ledger._internal.writer import LedgerWriter
from traust_ledger.config import ServiceConfig
from traust_ledger.paths import layer_file_path


def backend_from_env() -> tuple[Backend, str]:
    """Create a backend from LAAS_* env vars. Returns (backend, data_dir)."""
    backend_type = os.environ.get("LAAS_BACKEND_TYPE", "file")
    data_dir = os.environ.get("LAAS_DATA_DIR", "/var/lib/laas/data")
    kwargs: dict[str, object] = {"data_dir": data_dir}
    if backend_type == "db":
        kwargs["database_url"] = os.environ.get("LAAS_DATABASE_URL", "")
    return create_backend(backend_type, **kwargs), data_dir


def config_from_env(data_dir: str | None = None) -> ServiceConfig:
    """Build ServiceConfig from LAAS_* env vars (no pydantic_settings needed)."""
    return ServiceConfig(
        backend_type=os.environ.get("LAAS_BACKEND_TYPE", "file"),
        data_dir=data_dir or os.environ.get("LAAS_DATA_DIR", "/var/lib/laas/data"),
        database_url=os.environ.get("LAAS_DATABASE_URL"),
        signing_required=os.environ.get("LAAS_SIGNING_REQUIRED", "").lower()
        in ("true", "1", "yes"),
        signing_key_path=os.environ.get("LAAS_SIGNING_KEY_PATH"),
        signing_method=os.environ.get("LAAS_SIGNING_METHOD", "cosign"),
        log_level=os.environ.get("LAAS_LOG_LEVEL", "INFO"),
    )


def iter_layers(
    backend: Backend,
    data_dir: str,
) -> Iterator[tuple[str, dict]]:
    """Yield (layer_id, layer_dict) for every layer in the backend."""
    database_loader = getattr(backend, "load_layer_id", None)
    for layer_id in backend.list_layer_ids():
        if callable(database_loader):
            yield layer_id, database_loader(layer_id)
            continue
        path = layer_file_path(data_dir, layer_id)
        layer = backend.load(Path(path) if isinstance(path, str) else path)
        yield layer_id, layer


def local_writer() -> tuple[LedgerWriter, ServiceConfig]:
    """Create a LedgerWriter + ServiceConfig from env vars."""
    backend, data_dir = backend_from_env()
    config = config_from_env(data_dir)
    return LedgerWriter(backend=backend), config


def discover_layer_for_finding(finding_ref: str) -> str | None:
    """Scan all layers for one containing the given finding_ref."""
    backend, data_dir = backend_from_env()
    for layer_id, layer in iter_layers(backend, data_dir):
        for event in layer.get("events") or []:
            if isinstance(event, dict) and event.get("finding_ref") == finding_ref:
                return layer_id
    return None
