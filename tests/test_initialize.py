"""Explicit initialization is shared by REST, CLI and SDK."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from auth_helpers import TokenActorVerifier
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from storage_db import prepare_storage
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger._internal.backends.db import DbBackend
from traust_ledger._internal.backends.file import FileBackend
from traust_ledger._internal.writer import LedgerWriter
from traust_ledger.cli.commands import initialize as cli_initialize
from traust_ledger.client import LedgerClient, LedgerError
from traust_ledger.config import ServiceConfig
from traust_ledger.service.app import create_app

SHELL = {
    "metadata": {
        "audit_report": "audit.json",
        "repository": "https://example.test/repo",
        "created": "2026-09-22T12:00:00Z",
        "harness_version": "1.0.0",
    },
    "events": [],
    "needs_review": [],
}


def _create(layer: dict, product_repo_id: str | None = None) -> dict:
    return {"product_repo_id": product_repo_id, "layer": layer}


def test_initialize_rest_requires_identity_and_never_replaces(tmp_path: Path) -> None:
    config = ServiceConfig(data_dir=str(tmp_path), signing_required=False)
    client = TestClient(create_app(config, verifier=TokenActorVerifier()))
    url = "/v1/ledger/layers/new-layer/initialize"
    assert client.post(url, json=_create(SHELL)).status_code == 401
    assert (
        client.post(
            url, json=_create({"events": []}), headers={"Authorization": "Bearer alice"}
        ).status_code
        == 422
    )
    assert (
        client.post(
            url, json={"layer": SHELL}, headers={"Authorization": "Bearer alice"}
        ).status_code
        == 422
    )
    headers = {"Authorization": "Bearer alice"}
    shell_with_history = {
        **SHELL,
        "events": [
            {
                "event_id": "a" * 64,
                "finding_ref": "FIND-001",
                "recorded_at": "2026-09-22T12:00:00Z",
                "source": {
                    "type": "triage_report",
                    "ref": "report.json",
                    "actor": {"kind": "machine"},
                },
                "disposition": {"validity": "confirmed", "resolution": "open"},
                "rationale": "Reviewed the evidence and confirmed the finding.",
            }
        ],
    }
    response = client.post(url, json=_create(shell_with_history), headers=headers)
    assert response.status_code == 422
    assert "administrative migration" in response.json()["detail"]
    assert client.post(url, json=_create(SHELL), headers=headers).status_code == 200
    assert client.get("/v1/ledger/layers/new-layer", headers=headers).json() == SHELL
    invalid = {
        "source_ref": "report.json",
        "recorded_at": "2026-09-22T12:00:00Z",
        "events": [
            {
                "finding_ref": "FIND-001",
                "source": {"ref": "report.json"},
                "disposition": {"validity": "confirmed"},
            }
        ],
    }
    rejected = client.post("/v1/ledger/layers/new-layer/submit", json=invalid, headers=headers)
    assert rejected.status_code == 422
    assert "invalid complete layer" in rejected.json()["detail"]
    assert FileBackend().load(tmp_path / "new-layer.json") == SHELL
    assert client.post(url, json=_create(SHELL), headers=headers).status_code == 422
    assert FileBackend().load(tmp_path / "new-layer.json") == SHELL


@pytest.mark.parametrize("operation", ["sign", "stamp"])
@pytest.mark.parametrize("backend_type", ["file", "db"])
def test_rest_sign_stamp_require_canonical_initialized_layer(
    tmp_path: Path, operation: str, backend_type: str
) -> None:
    database_url = f"sqlite:///{tmp_path / 'rest.db'}" if backend_type == "db" else None
    owner = prepare_storage(database_url) if database_url else None
    config = ServiceConfig(
        data_dir=str(tmp_path),
        backend_type=backend_type,
        database_url=database_url,
        signing_required=False,
    )
    app = create_app(config, verifier=TokenActorVerifier())
    client = TestClient(app)
    headers = {"Authorization": "Bearer alice"}
    url = f"/v1/ledger/layers/rest-layer/{operation}"
    body = {"fingerprints": {}} if operation == "stamp" else None
    assert client.post(url, json=body, headers=headers).status_code == 404
    assert not app.state.backend.list_layer_ids()
    if backend_type == "file":
        path = tmp_path / "rest-layer.json"
        path.write_text('{"events": []}', encoding="utf-8")
        assert client.post(url, json=body, headers=headers).status_code == 404
        assert json.loads(path.read_text(encoding="utf-8")) == {"events": []}
        path.unlink()
    initialize = "/v1/ledger/layers/rest-layer/initialize"
    if backend_type == "db":
        missing = client.post(initialize, json=_create(SHELL), headers=headers)
        assert missing.status_code == 422
        assert "product_repo_id is required" in missing.json()["detail"]
    assert client.post(initialize, json=_create(SHELL, owner), headers=headers).status_code == 200
    if backend_type == "db":
        assert app.state.backend.product_repo_id("rest-layer") == owner
    assert client.post(url, json=body, headers=headers).status_code == 200
    layer = app.state.backend.load(tmp_path / "rest-layer.json")
    assert layer["metadata"]["audit_report"] == "audit.json"


def test_initialize_cli_uses_shared_handler(tmp_path: Path, monkeypatch, capsys) -> None:

    from traust_ledger.cli.main import main

    shell_path = tmp_path / "shell.json"
    shell_path.write_text(json.dumps(SHELL), encoding="utf-8")
    config = ServiceConfig(data_dir=str(tmp_path), signing_required=False)
    writer = LedgerWriter(backend=FileBackend())
    actor = LayerActor(
        kind="human", identity="user:alice", identity_verified=True, identity_provider="oidc"
    )
    monkeypatch.setattr(cli_initialize, "require_cli_auth", lambda: 0)
    monkeypatch.setattr(cli_initialize, "require_verified_actor", lambda: actor)
    monkeypatch.setattr(cli_initialize, "local_writer", lambda: (writer, config))
    assert main(["initialize", str(shell_path), "--layer", "cli-layer"]) == 0
    assert FileBackend().load(tmp_path / "cli-layer.json") == SHELL
    assert main(["initialize", str(shell_path), "--layer", "cli-layer"]) == 1
    assert "already exists" in capsys.readouterr().err


def test_initialize_sqlite_is_atomic_and_complete(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'initialized.db'}")
    owner = prepare_storage(engine)
    DbBackend.create_tables(engine)
    backend = DbBackend(engine)
    path = Path("initialized.json")
    with pytest.raises(ValueError, match="product_repo_id is required"):
        backend.initialize(path, SHELL)
    backend.initialize(path, SHELL, owner)
    assert backend.load(path) == SHELL
    assert backend.product_repo_id("initialized") == owner
    with pytest.raises(ValueError, match="already exists"):
        backend.initialize(path, SHELL, owner)
    with pytest.raises(ValueError, match="invalid complete layer"):
        backend.initialize(Path("incomplete.json"), {"events": []}, owner)
    assert backend.list_layer_ids() == ["initialized"]


def test_client_create_requires_auth_and_shell(tmp_path: Path) -> None:
    from conftest import none_alg_jwt

    token = none_alg_jwt(sub="test@example.com", email="test@example.com", exp=9999999999)
    client = LedgerClient(token=token, data_dir=str(tmp_path))
    with pytest.raises(LedgerError, match="complete layer shell"):
        client.create("sdk-layer")
    with pytest.raises(LedgerError):
        client.store("sdk-layer", SHELL)


def test_uninitialized_write_rejected_across_entry_points(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    from conftest import RATIONALE_OK, RECORDED_AT

    from traust_ledger.cli.commands import submit as cli_submit

    config = ServiceConfig(data_dir=str(tmp_path), signing_required=False)
    actor = LayerActor(
        kind="human", identity="user:alice", identity_verified=True, identity_provider="oidc"
    )
    rest = TestClient(create_app(config, verifier=TokenActorVerifier()))
    response = rest.post(
        "/v1/ledger/events",
        json={
            "kind": "countersign",
            "event": {
                "layer_id": "missing",
                "finding_ref": "FIND-001",
                "verdict": "true_positive",
                "justification": RATIONALE_OK,
                "recorded_at": RECORDED_AT,
            },
        },
        headers={"Authorization": "Bearer alice"},
    )
    assert response.status_code == 422
    assert "not initialized" in response.json()["detail"]

    from traust_ledger.cli.main import main

    payload_path = tmp_path / "events.json"
    payload_path.write_text(
        json.dumps(
            [
                {
                    "source": {"ref": "test", "type": "triage_report"},
                    "finding_ref": "FIND-001",
                    "disposition": {"validity": "confirmed"},
                }
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli_submit, "require_cli_auth", lambda: 0)
    monkeypatch.setattr(cli_submit, "require_verified_actor", lambda: actor)
    monkeypatch.setattr(
        cli_submit, "local_writer", lambda: (LedgerWriter(backend=FileBackend()), config)
    )
    assert main(["submit", str(payload_path), "--layer", "missing"]) == 1
    assert "not initialized" in capsys.readouterr().err

    from conftest import none_alg_jwt

    class Verifier:
        def verify(self, token: str) -> LayerActor:
            return actor

    sdk = LedgerClient(
        token=none_alg_jwt(sub="test", exp=9999999999), verifier=Verifier(), data_dir=str(tmp_path)
    )
    with pytest.raises(LedgerError, match="not initialized"):
        sdk.sign("missing")


def test_layer_reads_are_anchored_to_product_repo(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'anchor.db'}"
    owner = prepare_storage(database_url)
    unowned = prepare_storage(database_url, repo_url="https://example.test/unowned")
    config = ServiceConfig(
        data_dir=str(tmp_path),
        backend_type="db",
        database_url=database_url,
        signing_required=False,
    )
    client = TestClient(create_app(config, verifier=TokenActorVerifier()))
    headers = {"Authorization": "Bearer alice"}
    initialize = "/v1/ledger/layers/anchored/initialize"
    assert client.post(initialize, json=_create(SHELL, owner), headers=headers).status_code == 200

    listed = client.get("/v1/ledger/layers", headers=headers).json()["layers"]
    assert listed == [{"layer_id": "anchored", "product_repo_id": owner}]
    found = client.get("/v1/ledger/layers", params={"product_repo_id": owner}, headers=headers)
    assert found.json()["layers"] == listed
    missing = client.get("/v1/ledger/layers", params={"product_repo_id": unowned}, headers=headers)
    assert missing.status_code == 404


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not-a-uuid",
        "../etc/passwd",
        "' OR 1=1 --",
        "A" * 36,
        "ABCDEF12-0000-4000-8000-000000000000",
    ],
)
def test_product_repo_id_is_a_storage_uuid(tmp_path: Path, value: str) -> None:
    config = ServiceConfig(data_dir=str(tmp_path), signing_required=False)
    client = TestClient(create_app(config, verifier=TokenActorVerifier()))
    headers = {"Authorization": "Bearer alice"}
    listed = client.get("/v1/ledger/layers", params={"product_repo_id": value}, headers=headers)
    assert listed.status_code == 422
    created = client.post(
        "/v1/ledger/layers/new-layer/initialize", json=_create(SHELL, value), headers=headers
    )
    assert created.status_code == 422


def test_second_layer_for_one_product_repo_is_a_conflict_not_a_500(tmp_path: Path) -> None:
    """One layer per product_repo surfaces as a client error on REST, SDK and import."""
    database_url = f"sqlite:///{tmp_path / 'owner.db'}"
    owner = prepare_storage(database_url)
    config = ServiceConfig(
        data_dir=str(tmp_path),
        backend_type="db",
        database_url=database_url,
        signing_required=False,
    )
    client = TestClient(
        create_app(config, verifier=TokenActorVerifier()), raise_server_exceptions=False
    )
    headers = {"Authorization": "Bearer alice"}
    first = client.post(
        "/v1/ledger/layers/first/initialize", json=_create(SHELL, owner), headers=headers
    )
    assert first.status_code == 200
    second = client.post(
        "/v1/ledger/layers/second/initialize", json=_create(SHELL, owner), headers=headers
    )
    assert second.status_code == 422, second.text
    assert "already has layer 'first'" in second.json()["detail"]

    unregistered = client.post(
        "/v1/ledger/layers/orphan/initialize",
        json=_create(SHELL, "00000000-0000-4000-8000-000000000000"),
        headers=headers,
    )
    assert unregistered.status_code == 422, unregistered.text

    backend = DbBackend(create_engine(database_url))
    from traust_ledger._internal.backends.errors import LayerConflictError

    with pytest.raises(LayerConflictError, match="already has layer 'first'"):
        backend.import_layer("corpus:layer:other", SHELL, product_repo_id=owner)
    with pytest.raises(LayerConflictError, match="already has layer 'first'"):
        backend.import_layer("corpus:layer:other", SHELL, product_repo_id=owner, dry_run=True)
    assert backend.list_layer_ids() == ["first"]
