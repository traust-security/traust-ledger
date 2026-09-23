"""Trusted migration of complete historical layer evidence."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from traust_contracts.paths import schema_path

from traust_ledger._internal.backends.db import DbBackend
from traust_ledger._internal.backends.errors import LayerConflictError
from traust_ledger._internal.integrity import (
    Severity,
    verify_merkle_integrity,
    verify_merkle_signature,
)
from traust_ledger._internal.migrations import DatabaseRoles, configure_roles


@dataclass(frozen=True)
class SourceLayer:
    layer_id: str
    document: dict
    source: str
    error: str | None = None


@dataclass(frozen=True)
class MigrationResult:
    layer_id: str
    status: str
    source: str
    events: int
    review_items: int
    validation_warnings: int = 0
    detail: str | None = None


def _document(payload: bytes, source: str) -> dict:
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{source}: layer document must be an object")
    return value


@cache
def _layer_validator() -> Draft202012Validator:
    schema = json.loads(schema_path("layer").read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _validate(layer: SourceLayer, signature_key: str | None = None) -> int:
    errors = sorted(
        _layer_validator().iter_errors(layer.document), key=lambda item: list(item.path)
    )
    blocking: list[ValidationError] = []
    warnings = 0
    for error in errors:
        path = list(error.absolute_path)
        legacy_review_extension = (
            error.validator == "additionalProperties"
            and len(path) >= 2
            and path[0] == "needs_review"
            and isinstance(path[1], int)
        )
        if legacy_review_extension:
            warnings += 1
        else:
            blocking.append(error)
    if blocking:
        error = blocking[0]
        path = "/".join(str(token) for token in error.absolute_path)
        raise ValueError(
            f"{layer.source}: schema rule {error.validator} failed at /{path}"
        ) from None
    metadata = layer.document.get("metadata") or {}
    baseline_claims = layer.document.get("baseline_claims")
    metadata_claims = metadata.get("claim_hashes") if isinstance(metadata, dict) else None
    if baseline_claims is not None and baseline_claims != metadata_claims:
        warnings += 1
    if isinstance(metadata, dict) and metadata.get("merkle_root"):
        findings = verify_merkle_integrity(layer.document)
        findings.extend(verify_merkle_signature(layer.document, signature_key))
        failures = [finding.message for finding in findings if finding.severity == Severity.ERROR]
        warnings += sum(finding.severity == Severity.WARNING for finding in findings)
        if failures:
            raise ValueError(f"{layer.source}: integrity verification failed: {failures[0]}")
    return warnings


def iter_directory_layers(directory: Path) -> Iterator[SourceLayer]:
    """Read a ledger data directory whose filenames are canonical layer IDs."""
    for path in sorted(directory.glob("*.json")):
        try:
            document = _document(path.read_bytes(), str(path))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            yield SourceLayer(path.stem, {}, str(path), f"invalid layer document: {error}")
            continue
        if not isinstance(document.get("events"), list):
            continue
        yield SourceLayer(layer_id=path.stem, document=document, source=str(path))


def iter_ledger_layers(engine: Engine) -> Iterator[SourceLayer]:
    """Read reconstructed layers from an existing normalized ledger database."""
    backend = DbBackend(engine)
    for layer_id in backend.list_layer_ids():
        yield SourceLayer(
            layer_id=layer_id,
            document=backend.load_layer_id(layer_id),
            source=f"ledger:{layer_id}",
        )


def iter_artifact_layers(engine: Engine) -> Iterator[SourceLayer]:
    """Read current complete layer evidence without using lossy projections."""
    prefix = "traust_storage." if engine.dialect.name == "postgresql" else ""
    statement = text(
        f"""
        SELECT b.layer_id, b.binding_id, e.digest, e.payload
          FROM {prefix}artifact_binding b
          JOIN {prefix}artifact_evidence e ON e.digest = b.artifact_digest
         WHERE b.artifact_name = 'layer'
           AND b.layer_id IS NOT NULL
           AND NOT EXISTS (
               SELECT 1 FROM {prefix}artifact_binding successor
                WHERE successor.supersedes_binding_id = b.binding_id
           )
         ORDER BY b.layer_id, b.bound_at, b.binding_id
        """
    )
    with engine.connect() as conn:
        for row in conn.execute(statement).mappings():
            payload = bytes(row["payload"])
            digest = hashlib.sha256(payload).hexdigest()
            source = f"artifact_binding:{row['binding_id']}"
            if len(row["digest"]) == 64 and digest != row["digest"]:
                yield SourceLayer(row["layer_id"], {}, source, "evidence digest mismatch")
                continue
            try:
                document = _document(payload, source)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                yield SourceLayer(row["layer_id"], {}, source, f"invalid layer document: {error}")
                continue
            yield SourceLayer(layer_id=row["layer_id"], document=document, source=source)


def migrate(
    layers: Iterator[SourceLayer],
    target_url: str,
    *,
    dry_run: bool = False,
    selected: set[str] | None = None,
    roles: DatabaseRoles | None = None,
    signature_key: str | None = None,
) -> Iterator[MigrationResult]:
    """Validate and idempotently migrate layers into normalized Ledger storage."""
    target_engine = create_engine(target_url)
    DbBackend.create_tables(target_engine)
    if roles is not None:
        configure_roles(target_engine, roles)
    backend = DbBackend(target_engine)
    for layer in layers:
        if selected is not None and layer.layer_id not in selected:
            continue
        if layer.error:
            yield MigrationResult(
                layer_id=layer.layer_id,
                status="quarantined",
                source=layer.source,
                events=0,
                review_items=0,
                detail=layer.error,
            )
            continue
        try:
            validation_warnings = _validate(layer, signature_key)
            status = backend.import_layer(layer.layer_id, layer.document, dry_run=dry_run)
            yield MigrationResult(
                layer_id=layer.layer_id,
                status=status,
                source=layer.source,
                events=len(layer.document.get("events") or []),
                review_items=len(layer.document.get("needs_review") or []),
                validation_warnings=validation_warnings,
            )
        except (LayerConflictError, ValueError, TypeError) as error:
            yield MigrationResult(
                layer_id=layer.layer_id,
                status="conflict" if isinstance(error, LayerConflictError) else "quarantined",
                source=layer.source,
                events=len(layer.document.get("events") or []),
                review_items=len(layer.document.get("needs_review") or []),
                detail=str(error),
            )
