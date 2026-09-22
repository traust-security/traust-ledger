"""Tier 4a OpenAPI spec export and $ref assertion tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from traust_ledger.config import ServiceConfig
from traust_ledger.service.app import create_app
from traust_ledger.service.route_constants import (
    ROUTE_EVENTS,
    ROUTE_HEALTHZ,
    ROUTE_LAYERS,
)

SCHEMA_EVENT_ENVELOPE = "EventEnvelope"
SCHEMA_SUBMIT_RESPONSE = "SubmitResponse"
SCHEMA_HEALTH_RESPONSE = "HealthResponse"
SCHEMA_STAMP_REQUEST = "StampRequest"
SCHEMA_STAMP_RESPONSE = "StampResponse"

EXPECTED_COMPONENT_SCHEMAS = (
    SCHEMA_EVENT_ENVELOPE,
    SCHEMA_SUBMIT_RESPONSE,
    SCHEMA_HEALTH_RESPONSE,
    SCHEMA_STAMP_REQUEST,
    SCHEMA_STAMP_RESPONSE,
)

ROUTE_LAYER_STAMP = "/v1/ledger/layers/{layer_id}/stamp"
ROUTE_WHOAMI = "/v1/ledger/whoami"

POST_ROUTES = (ROUTE_EVENTS, ROUTE_LAYER_STAMP)

ROUTE_LAYER_VERIFY = "/v1/ledger/layers/{layer_id}/verify"
ROUTE_LAYER_FINDINGS = "/v1/ledger/layers/{layer_id}/findings"
ROUTE_LAYER_EVENTS = "/v1/ledger/layers/{layer_id}/events"
ROUTE_BULK_FINDINGS = "/v1/ledger/findings"

EXPECTED_GET_ROUTES = (
    ROUTE_HEALTHZ,
    ROUTE_LAYERS,
    ROUTE_LAYER_VERIFY,
    ROUTE_LAYER_FINDINGS,
    ROUTE_LAYER_EVENTS,
    ROUTE_BULK_FINDINGS,
    ROUTE_WHOAMI,
)

COMMITTED_SPEC_PATH = Path(__file__).resolve().parent.parent / "docs" / "openapi.json"

SPEC_ROOT_KEYS = ("openapi", "info", "paths", "components")
OPENAPI_JSON_PATH = "/openapi.json"
REF_PREFIX = "#/components/schemas/"
JSON_MEDIA_TYPE = "application/json"
HTTP_OK = "200"
HTTP_METHOD_GET = "get"
HTTP_METHOD_POST = "post"

EVENT_REQUIRED_FIELDS = ("kind", "event")
EVENT_KIND_TYPE = "string"
EVENT_EVENT_TYPE = "object"


@pytest.fixture
def openapi_spec(tmp_path: Path) -> dict[str, Any]:
    config = ServiceConfig(
        backend_type="file",
        data_dir=str(tmp_path),
        signing_required=False,
    )
    client = TestClient(create_app(config, validate_config=False))
    response = client.get(OPENAPI_JSON_PATH)
    assert response.status_code == 200
    return response.json()


def _schema_ref(schema: dict[str, Any]) -> str | None:
    ref = schema.get("$ref")
    return ref if isinstance(ref, str) else None


def _request_body_schema(path: str, spec: dict[str, Any]) -> dict[str, Any]:
    operation = spec["paths"][path][HTTP_METHOD_POST]
    content = operation["requestBody"]["content"][JSON_MEDIA_TYPE]
    return content["schema"]


def _response_schema(path: str, spec: dict[str, Any], status: str = HTTP_OK) -> dict[str, Any]:
    operation = spec["paths"][path][HTTP_METHOD_POST]
    content = operation["responses"][status]["content"][JSON_MEDIA_TYPE]
    return content["schema"]


def test_openapi_spec_valid(openapi_spec: dict[str, Any]) -> None:
    for key in SPEC_ROOT_KEYS:
        assert key in openapi_spec


def test_openapi_version_3(openapi_spec: dict[str, Any]) -> None:
    assert openapi_spec["openapi"].startswith("3.")


def test_all_routes_present(openapi_spec: dict[str, Any]) -> None:
    paths = openapi_spec["paths"]
    for route in EXPECTED_GET_ROUTES:
        assert HTTP_METHOD_GET in paths[route]
    for route in POST_ROUTES:
        assert HTTP_METHOD_POST in paths[route]


def test_committed_spec_matches_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if not COMMITTED_SPEC_PATH.is_file():
        pytest.skip("docs/openapi.json not committed")

    monkeypatch.setenv("LAAS_DATA_DIR", str(tmp_path))

    live_spec = create_app(validate_config=False).openapi()
    committed = json.loads(COMMITTED_SPEC_PATH.read_text())
    assert committed == live_spec


def test_request_bodies_use_refs(openapi_spec: dict[str, Any]) -> None:
    for route in POST_ROUTES:
        schema = _request_body_schema(route, openapi_spec)
        ref = _schema_ref(schema)
        assert ref is not None
        assert ref.startswith(REF_PREFIX)


def test_response_schemas_use_refs(openapi_spec: dict[str, Any]) -> None:
    for route in POST_ROUTES:
        schema = _response_schema(route, openapi_spec)
        ref = _schema_ref(schema)
        assert ref is not None
        assert ref.startswith(REF_PREFIX)


def test_component_schemas_present(openapi_spec: dict[str, Any]) -> None:
    schemas = openapi_spec["components"]["schemas"]
    for name in EXPECTED_COMPONENT_SCHEMAS:
        assert name in schemas


def test_event_envelope_shape(openapi_spec: dict[str, Any]) -> None:
    schema = openapi_spec["components"]["schemas"][SCHEMA_EVENT_ENVELOPE]
    properties = schema["properties"]
    required = set(schema["required"])

    assert EVENT_REQUIRED_FIELDS[0] in required
    assert EVENT_REQUIRED_FIELDS[1] in required
    assert properties["kind"]["type"] == EVENT_KIND_TYPE
    assert properties[EVENT_REQUIRED_FIELDS[1]]["type"] == EVENT_EVENT_TYPE


def test_spec_export_json(openapi_spec: dict[str, Any]) -> None:
    serialized = json.dumps(openapi_spec)
    assert isinstance(serialized, str)
    assert json.loads(serialized) == openapi_spec


def test_spec_export_yaml(openapi_spec: dict[str, Any]) -> None:
    try:
        import yaml
    except ImportError:
        pytest.skip("PyYAML not installed")

    serialized = yaml.dump(openapi_spec)
    assert isinstance(serialized, str)
    assert yaml.safe_load(serialized) == openapi_spec
