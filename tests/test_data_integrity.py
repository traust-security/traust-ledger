"""P1 data-integrity fixes: atomic mutate, layer_id, ServiceError."""

from __future__ import annotations

import os
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from traust_ledger._internal.backends.db import DbBackend
from traust_ledger._internal.errors import EventIdMismatchError, IdentityUnverifiedError
from traust_ledger._internal.migrations import DatabaseRoles, configure_roles
from traust_ledger._internal.writer import LedgerWriter
from traust_ledger.constants import (
    LAYER_ID_PATTERN,
)
from traust_ledger.paths import layer_file_path
from traust_ledger.service.errors import InvalidLayerIdError


class TestP18AtomicMutate:
    """P1-8: DbBackend mutate path preserves FOR UPDATE locking."""

    def test_mutate_layer_delegates_to_backend_mutate(self, tmp_path: Path) -> None:
        engine = create_engine("sqlite:///:memory:")
        DbBackend.create_tables(engine)
        backend = DbBackend(engine)
        writer = LedgerWriter(backend=backend)
        layer_path = tmp_path / "layer.json"

        backend.mutate = MagicMock(wraps=backend.mutate)  # type: ignore[method-assign]
        backend.load = MagicMock(wraps=backend.load)  # type: ignore[method-assign]
        backend.store = MagicMock(wraps=backend.store)  # type: ignore[method-assign]

        event = {
            "source": {"ref": "test", "actor": {"kind": "machine"}},
            "finding_ref": "FIND-001",
            "disposition": {"validity": "confirmed", "resolution": "open"},
        }
        writer.append_event(layer_path, event)

        backend.mutate.assert_called_once()
        backend.load.assert_not_called()
        backend.store.assert_not_called()


@pytest.mark.integration
def test_postgres_concurrent_mutate_preserves_both_appends() -> None:
    url = os.environ.get("LEDGER_TEST_DATABASE_URL")
    if not url:
        pytest.skip("LEDGER_TEST_DATABASE_URL is not configured")
    engine = create_engine(url)
    DbBackend.create_tables(engine)
    backend = DbBackend(engine)
    layer_id = f"concurrency-{uuid.uuid4().hex}"
    layer_path = Path(layer_id)
    barrier = Barrier(2)

    def append(event_id: str) -> None:
        barrier.wait()

        def mutate(layer: dict) -> None:
            layer.setdefault("events", []).append({"event_id": event_id})

        backend.mutate(layer_path, mutate)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(append, ("event-a", "event-b")))
    assert {event["event_id"] for event in backend.load(layer_path)["events"]} == {
        "event-a",
        "event-b",
    }


@pytest.mark.integration
def test_postgres_guards_and_role_matrix() -> None:
    url = os.environ.get("LEDGER_TEST_DATABASE_URL")
    if not url:
        pytest.skip("LEDGER_TEST_DATABASE_URL is not configured")
    engine = create_engine(url)
    DbBackend.create_tables(engine)
    backend = DbBackend(engine)
    layer_id = f"guard-{uuid.uuid4().hex}"
    backend.import_layer(layer_id, {"metadata": {}, "events": [{"event_id": "event-a"}]})

    for statement in (
        "UPDATE traust_ledger.events SET event_id = 'changed' WHERE layer_id = :layer_id",
        "DELETE FROM traust_ledger.events WHERE layer_id = :layer_id",
        "DELETE FROM traust_ledger.layers WHERE layer_id = :layer_id",
        "TRUNCATE traust_ledger.events",
    ):
        with pytest.raises(DBAPIError), engine.begin() as conn:
            conn.execute(text(statement), {"layer_id": layer_id})

    suffix = uuid.uuid4().hex
    roles = DatabaseRoles(
        writer=f"ledger_writer_{suffix}",
        projector=f"ledger_projector_{suffix}",
        reader=f"ledger_reader_{suffix}",
    )
    try:
        with engine.begin() as conn:
            for role in (roles.writer, roles.projector, roles.reader):
                conn.execute(text(f'CREATE ROLE "{role}" NOLOGIN'))
        configure_roles(engine, roles)
        checks = {
            "writer_insert_event": (roles.writer, "traust_ledger.events", "INSERT", True),
            "writer_update_event": (roles.writer, "traust_ledger.events", "UPDATE", False),
            "writer_delete_event": (roles.writer, "traust_ledger.events", "DELETE", False),
            "projector_write_projection": (
                roles.projector,
                "traust_ledger.materialized_findings",
                "UPDATE",
                True,
            ),
            "projector_insert_event": (roles.projector, "traust_ledger.events", "INSERT", False),
            "reader_read_projection": (
                roles.reader,
                "traust_ledger.materialized_findings",
                "SELECT",
                True,
            ),
            "reader_read_event": (roles.reader, "traust_ledger.events", "SELECT", False),
        }
        with engine.connect() as conn:
            for name, (role, table, privilege, expected) in checks.items():
                actual = conn.execute(
                    text("SELECT has_table_privilege(:role, :table, :privilege)"),
                    {"role": role, "table": table, "privilege": privilege},
                ).scalar_one()
                assert actual is expected, name
    finally:
        with engine.begin() as conn:
            for role in (roles.writer, roles.projector, roles.reader):
                conn.execute(text(f'DROP OWNED BY "{role}"'))
                conn.execute(text(f'DROP ROLE "{role}"'))


class TestLayerIdPattern:
    """layer_id must not allow traversal-like values."""

    @pytest.mark.parametrize(
        "layer_id",
        ["..", "..hidden", "foo..bar", "-bad", "bad-", ".", "-", ".-x", "./x", ".a/b", "a/b"],
    )
    def test_rejects_invalid_layer_ids(self, layer_id: str) -> None:
        assert re.match(LAYER_ID_PATTERN, layer_id) is None

    @pytest.mark.parametrize(
        "layer_id",
        [
            "repo-a",
            "a.b.c",
            "layer_1",
            "a-b",
            "a1",
            # A SINGLE leading dot is legitimate: `.github`, `.fullsend`, `.project`
            # and `.github-private` are real repositories (GitHub's own convention)
            # and six such layers exist in the corpus. `.hidden` was previously
            # asserted invalid, which made those layers unwritable through the SDK
            # and aborted any corpus-wide pass at the first one.
            ".hidden",
            ".github-findings-layer",
            ".fullsend",
            ".project",
        ],
    )
    def test_accepts_valid_layer_ids(self, layer_id: str) -> None:
        assert re.match(LAYER_ID_PATTERN, layer_id)

    def test_a_leading_dot_does_not_open_traversal(self) -> None:
        """Hiddenness is permitted; escaping the data dir is not."""
        for evil in ("..", "../x", ".././x", "..hidden", "./x", ".a/b"):
            assert re.match(LAYER_ID_PATTERN, evil) is None, evil

    def test_layer_file_path_rejects_dotdot(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match=InvalidLayerIdError.message):
            layer_file_path(str(tmp_path), "..")


class TestWriterServiceErrors:
    """ValueError from writer becomes ServiceError for HTTP handlers."""

    def test_identity_rule_raises_identity_unverified(self, tmp_path: Path) -> None:
        writer = LedgerWriter()
        layer_path = tmp_path / "layer.json"
        event = {
            "source": {
                "ref": "test",
                "actor": {
                    "kind": "human",
                    "identity": "user@example.com",
                    "identity_verified": False,
                },
            },
            "finding_ref": "FIND-001",
            "disposition": {"validity": "false_positive", "resolution": "open"},
        }
        with pytest.raises(IdentityUnverifiedError):
            writer.append_event(layer_path, event)

    def test_event_id_mismatch_raises_service_error(self, tmp_path: Path) -> None:
        writer = LedgerWriter()
        layer_path = tmp_path / "layer.json"
        event = {
            "event_id": "not-the-canonical-id",
            "source": {"ref": "test", "actor": {"kind": "machine"}},
            "finding_ref": "FIND-001",
            "disposition": {"validity": "confirmed", "resolution": "open"},
        }
        with pytest.raises(EventIdMismatchError):
            writer.append_event(layer_path, event)


def test_the_current_signature_format_is_allowed_by_the_layer_schema():
    """The gap that made the whole corpus fail validation: SIGNATURE_FORMAT_CURRENT
    went to 3 and 8,508 layers were re-signed with it while layer.schema.json still
    enumerated [1, 2]. Bumping the constant without widening the enum is the exact
    mistake, so pin the two together — this test fails the moment they diverge again.
    """
    import json

    from traust_contracts.paths import schema_path

    from traust_ledger._internal.integrity.ledger import SIGNATURE_FORMAT_CURRENT

    schema = json.loads(schema_path("layer").read_text())
    allowed = schema["$defs"]["layer_metadata"]["properties"]["merkle_signature_format"]["enum"]
    assert SIGNATURE_FORMAT_CURRENT in allowed, (SIGNATURE_FORMAT_CURRENT, allowed)


def test_changing_the_report_digest_drops_a_format3_signature(tmp_path):
    """D4b, for the case that has no root change to trigger it.

    Format 3 signs audit_report_sha256, so re-pointing a layer at different report
    bytes invalidates the signature while the Merkle root stays put. Nothing else
    catches that: stamp_merkle_metadata keys off the root, and resign_layers_format3
    compares the format number rather than verifying. A signature that lies is worse
    than no signature, so the digest write drops it.
    """
    from traust_ledger._internal.reports import stamp_report_reference

    a = tmp_path / "a.json"
    a.write_text('{"findings": []}')
    b = tmp_path / "b.json"
    b.write_text('{"findings": [1]}')

    layer = {"events": [], "metadata": {}}
    stamp_report_reference(layer, a)
    layer["metadata"].update(
        {
            "merkle_root": "deadbeef",
            "merkle_root_signature": "SIG",
            "merkle_signing_method": "keypair",
            "merkle_signature_format": 3,
        }
    )

    assert stamp_report_reference(layer, a) is False  # idempotent, keeps the sig
    assert layer["metadata"]["merkle_root_signature"] == "SIG"

    assert stamp_report_reference(layer, b) is True  # digest moved
    assert "merkle_root_signature" not in layer["metadata"]
    assert "merkle_signature_format" not in layer["metadata"]
    assert layer["metadata"]["merkle_root"] == "deadbeef"  # the root did NOT move


def test_a_format2_signature_survives_a_digest_change(tmp_path):
    """Format 2's payload does not cover the digest, so dropping would be wrong —
    it would de-attest a layer that is still correctly signed."""
    from traust_ledger._internal.reports import stamp_report_reference

    a = tmp_path / "a.json"
    a.write_text("{}")
    b = tmp_path / "b.json"
    b.write_text('{"x": 1}')
    layer = {"events": [], "metadata": {}}
    stamp_report_reference(layer, a)
    layer["metadata"].update({"merkle_root_signature": "SIG", "merkle_signature_format": 2})
    stamp_report_reference(layer, b)
    assert layer["metadata"]["merkle_root_signature"] == "SIG"


def test_artifact_digests_cover_the_layers_siblings(tmp_path):
    """R1: without this, only the ONE report a layer names is verifiable — 15% of what
    a migration to object storage copies. The other 85% could be corrupted in transit
    with nothing to check them against once the git copy is deleted."""
    from traust_ledger._internal.reports import check_artifact_digests, stamp_artifact_digests

    d = tmp_path / "repo"
    d.mkdir()
    layer_path = d / "repo-findings-layer.json"
    layer_path.write_text("{}")
    (d / "repo-security-audit.json").write_text('{"findings": []}')
    (d / "repo-triage.md").write_text("# triage")
    (d / "other-repo-triage.md").write_text("not mine")  # different base

    layer: dict = {"events": [], "metadata": {}}
    assert stamp_artifact_digests(layer, layer_path) is True
    got = layer["metadata"]["artifact_digests"]
    assert set(got) == {"repo-security-audit.json", "repo-triage.md"}, got
    assert stamp_artifact_digests(layer, layer_path) is False  # idempotent
    assert check_artifact_digests(layer, layer_path) == []

    (d / "repo-triage.md").write_text("# triage EDITED")
    msgs = check_artifact_digests(layer, layer_path)
    assert len(msgs) == 1 and "repo-triage.md" in msgs[0], msgs


def test_artifact_digests_report_a_file_that_appeared_or_vanished(tmp_path):
    from traust_ledger._internal.reports import check_artifact_digests, stamp_artifact_digests

    d = tmp_path / "r"
    d.mkdir()
    lp = d / "r-findings-layer.json"
    lp.write_text("{}")
    (d / "r-triage.json").write_text("{}")
    layer: dict = {"events": [], "metadata": {}}
    stamp_artifact_digests(layer, lp)

    (d / "r-threat-model.md").write_text("new")
    assert any("absent from artifact_digests" in m for m in check_artifact_digests(layer, lp))

    (d / "r-triage.json").unlink()
    assert any("missing on disk" in m for m in check_artifact_digests(layer, lp))


def test_format_4_signature_binds_the_artifact_digests():
    """A digest recorded outside the signature is provenance, not tamper-evidence —
    the same gap format 3 closed for audit_report_sha256, one level out."""
    from traust_ledger._internal.integrity.ledger import merkle_signature_payload

    base = {"merkle_root": "a" * 64, "merkle_size": 1, "audit_report_sha256": "b" * 64}
    without = merkle_signature_payload(base, fmt=4)
    with_arts = merkle_signature_payload({**base, "artifact_digests": {"x.json": "c" * 64}}, fmt=4)
    assert without != with_arts
    # and format 3 must ignore it, or existing signatures would break
    assert merkle_signature_payload(base, fmt=3) == merkle_signature_payload(
        {**base, "artifact_digests": {"x.json": "c" * 64}}, fmt=3
    )
