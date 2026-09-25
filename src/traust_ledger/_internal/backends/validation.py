"""Canonical layer document validation at import/export boundaries."""

from __future__ import annotations

import json
from functools import cache

from jsonschema import Draft202012Validator, FormatChecker
from traust_contracts.paths import schema_path

from .errors import InvalidLayerDocumentError


@cache
def _validator() -> Draft202012Validator:
    schema = json.loads(schema_path("layer").read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_layer(document: dict) -> None:
    """Require a complete portable layer; no metadata may be synthesized."""
    error = next(iter(_validator().iter_errors(document)), None)
    if error is not None:
        path = "/".join(str(part) for part in error.absolute_path)
        raise InvalidLayerDocumentError(
            f"invalid complete layer at /{path}: {error.message}"
        ) from error
