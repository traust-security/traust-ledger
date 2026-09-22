"""D6 deployment invariants — properties invisible to unit/integration tests."""

from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

import httpx2 as httpx
import pytest
import yaml
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError

from traust_ledger._internal.backends.constants import LAYER_EVENTS_KEY, LAYERS_TABLE_NAME
from traust_ledger._internal.backends.db import DbBackend
from traust_ledger.config import ServiceConfig

SERVICE_MODULE: Final = "traust_ledger.service"
STEP_12_PREFIX: Final = "ships with step 12:"
ENV_BACKEND_TYPE: Final = "LAAS_BACKEND_TYPE"
ENV_PORT: Final = "LAAS_PORT"
ENV_DATA_DIR: Final = "LAAS_DATA_DIR"
ENV_IDENTITY_PROVIDER: Final = "LAAS_IDENTITY_PROVIDER"
ENV_SIGNING_REQUIRED: Final = "LAAS_SIGNING_REQUIRED"
BACKEND_FILE: Final = "file"
UVICORN_HOST: Final = "127.0.0.1"
HEALTHZ_URL: Final = "http://127.0.0.1:{port}/healthz"
HTTP_OK: Final = 200
STARTUP_TIMEOUT_SECONDS: Final = 5.0
HEALTH_RETRY_INTERVAL: Final = 0.3
HEALTH_MAX_RETRIES: Final = 15
TERMINATE_TIMEOUT_SECONDS: Final = 3.0

DEPLOY_DIR_NAME: Final = "deploy"
DEPLOYMENT_MANIFEST: Final = "deployment.yaml"
CONFIGMAP_MANIFEST: Final = "configmap.yaml"
SERVICE_ACCOUNT_MANIFEST: Final = "serviceaccount.yaml"
CONTAINERFILE_NAME: Final = "Containerfile"
YAML_GLOB: Final = "*.yaml"

LAAS_ENV_PREFIX: Final = "LAAS_"
LAAS_CONTAINER_UID: Final = 1001
SIGNING_KEY_MOUNT_DIR: Final = "/var/run/secrets/laas/signing-key"
SIGNING_KEY_FILENAME: Final = "cosign.key"
SIGNING_KEY_MOUNT_PATH: Final = f"{SIGNING_KEY_MOUNT_DIR}/{SIGNING_KEY_FILENAME}"

FIELD_METADATA: Final = "metadata"
FIELD_NAME: Final = "name"
FIELD_SPEC: Final = "spec"
FIELD_TEMPLATE: Final = "template"
FIELD_CONTAINERS: Final = "containers"
FIELD_SERVICE_ACCOUNT_NAME: Final = "serviceAccountName"
FIELD_VOLUME_MOUNTS: Final = "volumeMounts"
FIELD_VOLUMES: Final = "volumes"
FIELD_ENV_FROM: Final = "envFrom"
FIELD_CONFIG_MAP_REF: Final = "configMapRef"
FIELD_SECRET_REF: Final = "secretRef"
FIELD_DATA: Final = "data"
FIELD_SECURITY_CONTEXT: Final = "securityContext"
FIELD_RUN_AS_USER: Final = "runAsUser"
FIELD_RUN_AS_GROUP: Final = "runAsGroup"
FIELD_FS_GROUP: Final = "fsGroup"
FIELD_SECRET: Final = "secret"
FIELD_SECRET_NAME: Final = "secretName"

FORBIDDEN_SERVICE_ACCOUNT_SCI_API: Final = "sci-api"
FORBIDDEN_SERVICE_ACCOUNT_DEFAULT: Final = "default"
FORBIDDEN_SERVICE_ACCOUNTS: Final = frozenset(
    {FORBIDDEN_SERVICE_ACCOUNT_SCI_API, FORBIDDEN_SERVICE_ACCOUNT_DEFAULT}
)

SIGNING_VOLUME_NAME: Final = "signing-key"
SIGNING_SECRET_NAME: Final = "laas-signing-key"
LAAS_DEPLOYMENT_NAME: Final = "laas"

CONTAINERFILE_KEY_EXTENSION_KEY: Final = ".key"
CONTAINERFILE_KEY_EXTENSION_PEM: Final = ".pem"
CONTAINERFILE_KEY_EXTENSIONS: Final = (
    CONTAINERFILE_KEY_EXTENSION_KEY,
    CONTAINERFILE_KEY_EXTENSION_PEM,
)
CONTAINERFILE_INSTRUCTION_COPY: Final = "COPY"
CONTAINERFILE_INSTRUCTION_RUN: Final = "RUN"
CONTAINERFILE_INSTRUCTION_ENV: Final = "ENV"
CONTAINERFILE_COSIGN_INSTRUCTIONS: Final = (
    CONTAINERFILE_INSTRUCTION_COPY,
    CONTAINERFILE_INSTRUCTION_RUN,
)
COSIGN_TOOL_NAME: Final = "cosign"
ENV_PEM_BEGIN_MARKER: Final = "BEGIN"
ENV_PEM_PRIVATE_KEY_MARKER: Final = "PRIVATE KEY"

SQLITE_MEMORY_URL: Final = "sqlite:///:memory:"
SQLITE_FILE_URI_TEMPLATE: Final = "sqlite:///{path}"
SQLITE_READ_ONLY_URI_TEMPLATE: Final = "sqlite:///{path}?mode=ro&uri=true"
DB_FILENAME: Final = "ledger.db"

TEST_LAYER_ID: Final = "deploy-invariant-layer"
TEST_LAYER_PATH: Final = Path(TEST_LAYER_ID)
EVENT_ID_ALPHA: Final = "evt-alpha"
EVENT_ID_BETA: Final = "evt-beta"
EVENT_ID_GAMMA: Final = "evt-gamma"

SQL_STATEMENT_DELETE: Final = "DELETE"
SQL_STATEMENT_INSERT: Final = "INSERT"
SQL_STATEMENT_UPDATE: Final = "UPDATE"

COPY_KEY_MATERIAL_PATTERN: Final = re.compile(
    r"^\s*COPY\b.*\S+(?:"
    + re.escape(CONTAINERFILE_KEY_EXTENSION_KEY)
    + r"|"
    + re.escape(CONTAINERFILE_KEY_EXTENSION_PEM)
    + r")\b",
    re.IGNORECASE,
)
ENV_EMBEDDED_KEY_PATTERN: Final = re.compile(
    rf"{ENV_PEM_BEGIN_MARKER}.*{ENV_PEM_PRIVATE_KEY_MARKER}",
    re.IGNORECASE,
)


def _step_12_skip(reason: str) -> str:
    return f"{STEP_12_PREFIX} {reason}"


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _deploy_dir() -> Path:
    return _project_root() / DEPLOY_DIR_NAME


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        document = yaml.safe_load(handle)
    if not isinstance(document, dict):
        msg = f"expected mapping document in {path}"
        raise TypeError(msg)
    return document


def _service_config_env_keys() -> set[str]:
    return {f"{LAAS_ENV_PREFIX}{name.upper()}" for name in ServiceConfig.model_fields}


def _configmap_env_keys(deploy_dir: Path) -> set[str]:
    configmap = _load_yaml(deploy_dir / CONFIGMAP_MANIFEST)
    data = configmap.get(FIELD_DATA, {})
    if not isinstance(data, Mapping):
        msg = "configmap data must be a mapping"
        raise TypeError(msg)
    return {key for key in data if isinstance(key, str)}


def _pod_security_context(manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    context = _pod_spec(manifest).get(FIELD_SECURITY_CONTEXT, {})
    if not isinstance(context, Mapping):
        msg = "pod securityContext must be a mapping"
        raise TypeError(msg)
    return context


def _env_from_entries(container: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    entries = container.get(FIELD_ENV_FROM, [])
    if not isinstance(entries, Sequence):
        msg = "envFrom must be a sequence"
        raise TypeError(msg)
    return [entry for entry in entries if isinstance(entry, Mapping)]


def _volume_mount_path(container: Mapping[str, Any], volume_name: str) -> str | None:
    mounts = container.get(FIELD_VOLUME_MOUNTS, [])
    if not isinstance(mounts, Sequence):
        return None
    for mount in mounts:
        if not isinstance(mount, Mapping):
            continue
        if mount.get(FIELD_NAME) == volume_name:
            mount_path = mount.get("mountPath")
            if isinstance(mount_path, str):
                return mount_path
    return None


def _require_containerfile() -> Path:
    path = _project_root() / CONTAINERFILE_NAME
    if not path.is_file():
        pytest.skip(f"no {CONTAINERFILE_NAME} at {path}")
    return path


def _pod_spec(manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    spec = manifest[FIELD_SPEC][FIELD_TEMPLATE][FIELD_SPEC]
    if not isinstance(spec, Mapping):
        msg = "deployment pod spec must be a mapping"
        raise TypeError(msg)
    return spec


def _deployment_service_account_name(manifest: Mapping[str, Any]) -> str:
    account_name = _pod_spec(manifest)[FIELD_SERVICE_ACCOUNT_NAME]
    if not isinstance(account_name, str):
        msg = "serviceAccountName must be a string"
        raise TypeError(msg)
    return account_name


def _service_account_name(manifest: Mapping[str, Any]) -> str:
    name = manifest[FIELD_METADATA][FIELD_NAME]
    if not isinstance(name, str):
        msg = "service account name must be a string"
        raise TypeError(msg)
    return name


def _first_container(manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    containers = _pod_spec(manifest)[FIELD_CONTAINERS]
    if not isinstance(containers, Sequence) or not containers:
        msg = "deployment must declare at least one container"
        raise TypeError(msg)
    container = containers[0]
    if not isinstance(container, Mapping):
        msg = "container entry must be a mapping"
        raise TypeError(msg)
    return container


def _volume_mount_names(container: Mapping[str, Any]) -> set[str]:
    mounts = container.get(FIELD_VOLUME_MOUNTS, [])
    if not isinstance(mounts, Sequence):
        msg = "volumeMounts must be a sequence"
        raise TypeError(msg)
    names: set[str] = set()
    for mount in mounts:
        if not isinstance(mount, Mapping):
            continue
        name = mount.get(FIELD_NAME)
        if isinstance(name, str):
            names.add(name)
    return names


def _secret_volume_names(pod_spec: Mapping[str, Any]) -> dict[str, str]:
    volumes = pod_spec.get(FIELD_VOLUMES, [])
    if not isinstance(volumes, Sequence):
        msg = "volumes must be a sequence"
        raise TypeError(msg)
    secret_volumes: dict[str, str] = {}
    for volume in volumes:
        if not isinstance(volume, Mapping):
            continue
        volume_name = volume.get(FIELD_NAME)
        secret = volume.get(FIELD_SECRET)
        if not isinstance(volume_name, str) or not isinstance(secret, Mapping):
            continue
        secret_name = secret.get(FIELD_SECRET_NAME)
        if isinstance(secret_name, str):
            secret_volumes[volume_name] = secret_name
    return secret_volumes


def _manifest_text_references_signing_secret(text: str) -> bool:
    return f"{FIELD_SECRET_NAME}: {SIGNING_SECRET_NAME}" in text


def _manifests_referencing_signing_secret(deploy_dir: Path) -> list[Path]:
    referenced: list[Path] = []
    for path in sorted(deploy_dir.glob(YAML_GLOB)):
        if path.name.endswith(".example.yaml"):
            continue
        if _manifest_text_references_signing_secret(path.read_text(encoding="utf-8")):
            referenced.append(path)
    return referenced


def _containerfile_instructions(text: str) -> list[str]:
    normalized = re.sub(r"\\\s*\n\s*", " ", text)
    instructions: list[str] = []
    for line in normalized.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        instructions.append(stripped)
    return instructions


def _instruction_starts_with(instruction: str, prefix: str) -> bool:
    return instruction.upper().startswith(prefix)


def _copies_signing_material(instruction: str) -> bool:
    return _instruction_starts_with(instruction, CONTAINERFILE_INSTRUCTION_COPY) and bool(
        COPY_KEY_MATERIAL_PATTERN.search(instruction)
    )


def _embeds_key_in_env(instruction: str) -> bool:
    return _instruction_starts_with(instruction, CONTAINERFILE_INSTRUCTION_ENV) and bool(
        ENV_EMBEDDED_KEY_PATTERN.search(instruction)
    )


def _installs_cosign(instruction: str) -> bool:
    if not any(
        _instruction_starts_with(instruction, prefix)
        for prefix in CONTAINERFILE_COSIGN_INSTRUCTIONS
    ):
        return False
    return COSIGN_TOOL_NAME in instruction


def _find_free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((UVICORN_HOST, 0))
        return sock.getsockname()[1]


def _start_service(
    env_overrides: Mapping[str, str],
    port: int,
) -> subprocess.Popen[str]:
    env = {**os.environ, **{k: str(v) for k, v in env_overrides.items()}, ENV_PORT: str(port)}
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            f"{SERVICE_MODULE}.app:create_app",
            "--factory",
            "--host",
            UVICORN_HOST,
            "--port",
            str(port),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _stop_service(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=TERMINATE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _sample_event(event_id: str) -> dict[str, str]:
    return {"event_id": event_id}


def _layer_with_event_ids(*event_ids: str) -> dict[str, list[dict[str, str]]]:
    return {LAYER_EVENTS_KEY: [_sample_event(event_id) for event_id in event_ids]}


def _memory_db_engine() -> Engine:
    engine = create_engine(SQLITE_MEMORY_URL)
    DbBackend.create_tables(engine)
    return engine


def _attach_sql_capture(engine: Engine) -> list[str]:
    statements: list[str] = []

    @event.listens_for(engine, "before_cursor_execute")
    def _capture_sql(
        _conn: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        statements.append(statement)

    return statements


def _delete_statements_on_layers(statements: Sequence[str]) -> list[str]:
    table_name = LAYERS_TABLE_NAME.lower()
    return [
        statement
        for statement in statements
        if SQL_STATEMENT_DELETE in statement.upper() and table_name in statement.lower()
    ]


def _wait_for_health(port: int, timeout: float = STARTUP_TIMEOUT_SECONDS) -> bool:
    url = HEALTHZ_URL.format(port=port)
    retries = min(HEALTH_MAX_RETRIES, int(timeout / HEALTH_RETRY_INTERVAL))
    for _ in range(retries):
        try:
            response = httpx.get(url, timeout=HEALTH_RETRY_INTERVAL)
            if response.status_code == HTTP_OK:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(HEALTH_RETRY_INTERVAL)
    return False


def test_filebackend_standalone_start(tmp_path: Path) -> None:
    pytest.importorskip(SERVICE_MODULE)
    port = _find_free_port()
    env = {
        ENV_BACKEND_TYPE: BACKEND_FILE,
        ENV_DATA_DIR: str(tmp_path),
        ENV_IDENTITY_PROVIDER: "oidc",
        "LAAS_OIDC_JWKS_URL": "http://localhost/.well-known/jwks.json",
    }
    proc = _start_service(env, port)
    try:
        assert _wait_for_health(port)
    finally:
        _stop_service(proc)


def test_misconfiguration_fails_loudly() -> None:
    pytest.importorskip(SERVICE_MODULE)
    port = _find_free_port()
    env = {ENV_SIGNING_REQUIRED: "1"}
    proc = _start_service(env, port)
    try:
        if proc.poll() is not None:
            assert proc.returncode != 0
            return
        if _wait_for_health(port):
            pytest.fail("service accepted misconfiguration silently")
    finally:
        _stop_service(proc)


def test_separate_service_account() -> None:
    """Service Deployment must use a ServiceAccount distinct from sci-api."""
    deploy_dir = _deploy_dir()
    deployment = _load_yaml(deploy_dir / DEPLOYMENT_MANIFEST)
    service_account = _load_yaml(deploy_dir / SERVICE_ACCOUNT_MANIFEST)

    expected_name = _service_account_name(service_account)
    actual_name = _deployment_service_account_name(deployment)

    assert actual_name == expected_name
    assert actual_name not in FORBIDDEN_SERVICE_ACCOUNTS


def test_signing_secret_isolation() -> None:
    """Signing secret volume mount must appear only in the service pod spec."""
    deploy_dir = _deploy_dir()
    deployment = _load_yaml(deploy_dir / DEPLOYMENT_MANIFEST)
    pod_spec = _pod_spec(deployment)
    container = _first_container(deployment)

    mount_names = _volume_mount_names(container)
    assert SIGNING_VOLUME_NAME in mount_names

    secret_volumes = _secret_volume_names(pod_spec)
    assert secret_volumes.get(SIGNING_VOLUME_NAME) == SIGNING_SECRET_NAME

    referenced_by = _manifests_referencing_signing_secret(deploy_dir)
    assert referenced_by == [deploy_dir / DEPLOYMENT_MANIFEST]
    assert deployment[FIELD_METADATA][FIELD_NAME] == LAAS_DEPLOYMENT_NAME


def test_configmap_env_keys_match_service_config() -> None:
    """ConfigMap keys must map to ServiceConfig fields (no typos or drift)."""
    deploy_dir = _deploy_dir()
    config_keys = _configmap_env_keys(deploy_dir)
    allowed = _service_config_env_keys()
    unknown = config_keys - allowed
    assert unknown == set(), f"unknown configmap env keys: {sorted(unknown)}"


def test_configmap_uses_oidc_provider() -> None:
    """Default manifest must use OIDC identity (machine auth via client-credentials/SA tokens)."""
    deploy_dir = _deploy_dir()
    configmap = _load_yaml(deploy_dir / CONFIGMAP_MANIFEST)
    data = configmap[FIELD_DATA]
    assert data.get(ENV_IDENTITY_PROVIDER) == "oidc"


def test_configmap_signing_key_path_matches_mount() -> None:
    """Signing key env path must align with the mounted secret directory."""
    deploy_dir = _deploy_dir()
    configmap = _load_yaml(deploy_dir / CONFIGMAP_MANIFEST)
    deployment = _load_yaml(deploy_dir / DEPLOYMENT_MANIFEST)
    container = _first_container(deployment)

    mount_path = _volume_mount_path(container, SIGNING_VOLUME_NAME)
    assert mount_path == SIGNING_KEY_MOUNT_DIR
    assert configmap[FIELD_DATA]["LAAS_SIGNING_KEY_PATH"] == SIGNING_KEY_MOUNT_PATH


def test_pod_runs_as_laas_uid() -> None:
    """Pod securityContext must match the Containerfile non-root user."""
    deployment = _load_yaml(_deploy_dir() / DEPLOYMENT_MANIFEST)
    context = _pod_security_context(deployment)
    assert context[FIELD_RUN_AS_USER] == LAAS_CONTAINER_UID
    assert context[FIELD_RUN_AS_GROUP] == LAAS_CONTAINER_UID
    assert context[FIELD_FS_GROUP] == LAAS_CONTAINER_UID


def test_deployment_loads_optional_secrets() -> None:
    """Sensitive env (DB URL, OIDC) comes from an optional secretRef."""
    deployment = _load_yaml(_deploy_dir() / DEPLOYMENT_MANIFEST)
    container = _first_container(deployment)
    secret_refs = [
        entry[FIELD_SECRET_REF]
        for entry in _env_from_entries(container)
        if FIELD_SECRET_REF in entry and isinstance(entry[FIELD_SECRET_REF], Mapping)
    ]
    assert any(ref.get(FIELD_NAME) == "laas-secrets" for ref in secret_refs)
    laas_secret = next(ref for ref in secret_refs if ref.get(FIELD_NAME) == "laas-secrets")
    assert laas_secret.get("optional") is True


def test_no_signing_key_in_image() -> None:
    """Container image must not embed signing key material."""
    containerfile = _require_containerfile()
    instructions = _containerfile_instructions(containerfile.read_text(encoding="utf-8"))

    copied_key_material = [line for line in instructions if _copies_signing_material(line)]
    embedded_env_keys = [line for line in instructions if _embeds_key_in_env(line)]

    assert copied_key_material == []
    assert embedded_env_keys == []


def test_builder_and_runtime_python_minors_match() -> None:
    """The builder's .venv is copied into the runtime stage verbatim.

    Native-extension .so files are ABI-pinned per Python minor and the venv's
    console-script shebangs hardcode the builder's interpreter path, so a
    minor skew yields missing native modules and an unusable entrypoint —
    invisible until the image actually runs in a cluster.
    """
    containerfile = _require_containerfile()
    instructions = _containerfile_instructions(containerfile.read_text(encoding="utf-8"))

    from_lines = [line for line in instructions if _instruction_starts_with(line, "FROM")]
    minors = {
        stage: match.group(1)
        for stage, line in ((line.split()[-1], line) for line in from_lines)
        if (match := re.search(r"/python:(\d+\.\d+)", line))
    }

    assert "builder" in minors, f"no python builder stage found in {from_lines}"
    assert "runtime" in minors, f"no python runtime stage found in {from_lines}"
    assert minors["builder"] == minors["runtime"], (
        f"builder python {minors['builder']} != runtime python {minors['runtime']}; "
        "the copied .venv would be ABI-mismatched"
    )


def test_cosign_present_in_image() -> None:
    """Container image must ship cosign for signature verification."""
    containerfile = _require_containerfile()
    instructions = _containerfile_instructions(containerfile.read_text(encoding="utf-8"))

    cosign_steps = [line for line in instructions if _installs_cosign(line)]
    assert cosign_steps


def test_insert_only_grants() -> None:
    """Writer DB role must reject UPDATE and DELETE on event tables."""
    engine = _memory_db_engine()
    statements = _attach_sql_capture(engine)
    backend = DbBackend(engine)

    backend.store(TEST_LAYER_PATH, _layer_with_event_ids(EVENT_ID_ALPHA, EVENT_ID_BETA))
    backend.store(TEST_LAYER_PATH, _layer_with_event_ids(EVENT_ID_ALPHA))

    def append_gamma(layer: dict[str, list[dict[str, str]]]) -> None:
        layer[LAYER_EVENTS_KEY].append(_sample_event(EVENT_ID_GAMMA))

    backend.mutate(TEST_LAYER_PATH, append_gamma)

    assert _delete_statements_on_layers(statements) == []
    assert any(
        SQL_STATEMENT_INSERT in statement.upper() and LAYERS_TABLE_NAME in statement.lower()
        for statement in statements
    )
    assert any(
        SQL_STATEMENT_UPDATE in statement.upper() and LAYERS_TABLE_NAME in statement.lower()
        for statement in statements
    )

    loaded = backend.load(TEST_LAYER_PATH)
    event_ids = [event["event_id"] for event in loaded[LAYER_EVENTS_KEY]]
    assert event_ids == [EVENT_ID_ALPHA, EVENT_ID_GAMMA]


def test_no_sci_api_write_path(tmp_path: Path) -> None:
    """sci-api DB role must be unable to INSERT into event tables."""
    db_path = tmp_path / DB_FILENAME
    writer_engine = create_engine(SQLITE_FILE_URI_TEMPLATE.format(path=db_path))
    DbBackend.create_tables(writer_engine)
    writer = DbBackend(writer_engine)
    writer.store(TEST_LAYER_PATH, _layer_with_event_ids(EVENT_ID_ALPHA))

    reader_engine = create_engine(SQLITE_READ_ONLY_URI_TEMPLATE.format(path=db_path))
    reader = DbBackend(reader_engine)

    with pytest.raises(OperationalError):
        reader.store(TEST_LAYER_PATH, _layer_with_event_ids(EVENT_ID_BETA))

    unchanged = writer.load(TEST_LAYER_PATH)
    assert [event["event_id"] for event in unchanged[LAYER_EVENTS_KEY]] == [EVENT_ID_ALPHA]


# --------------------------------------------------------------------------
# The oidc overlay is the deployment posture; base is the dev bootstrap.
# --------------------------------------------------------------------------


def _oidc_overlay_dir():
    return _deploy_dir() / "overlays" / "oidc"


def test_oidc_overlay_flips_auth_mode_and_requires_signing() -> None:
    patch = _load_yaml(_oidc_overlay_dir() / "oidc-configmap.yaml")
    data = patch[FIELD_DATA]
    assert data["LAAS_IDENTITY_PROVIDER"] == "oidc"
    assert data["LAAS_SIGNING_REQUIRED"] == "true", (
        "an overlay that authenticates properly but leaves writes unsigned is half a posture"
    )
    assert data["LAAS_OIDC_JWKS_URL"], "oidc without a JWKS URL will not start"


def test_oidc_overlay_patch_targets_the_base_configmap() -> None:
    kust = _load_yaml(_oidc_overlay_dir() / "kustomization.yaml")
    patch = _load_yaml(_oidc_overlay_dir() / "oidc-configmap.yaml")
    base = _load_yaml(_deploy_dir() / CONFIGMAP_MANIFEST)
    target = kust["patches"][0]["target"]
    assert target["name"] == patch["metadata"]["name"] == base["metadata"]["name"]


def test_oidc_overlay_resources_all_exist() -> None:
    d = _oidc_overlay_dir()
    for rel in _load_yaml(d / "kustomization.yaml")["resources"]:
        assert (d / rel).resolve().is_file(), rel


def test_ldap_cross_check_is_off_by_default_in_both() -> None:
    """Optional by design: no directory, no cross-check, token alone."""
    base = _load_yaml(_deploy_dir() / CONFIGMAP_MANIFEST)[FIELD_DATA]
    patch = _load_yaml(_oidc_overlay_dir() / "oidc-configmap.yaml")[FIELD_DATA]
    merged = {**base, **patch}
    assert not (merged.get("LAAS_LDAP_SERVER") and merged.get("LAAS_LDAP_BASE_DN"))
