"""Restatement hardening: deltas, the monotonic guard, approvers, and bulk.

Four properties, each of which came out of an attack or a cost that the
per-rule unit tests did not surface:

* **Delta, not snapshot.** A restatement used to carry the whole map on both
  sides, so one changed claim on a large layer wrote the entire table twice.
  Event size tracked the LAYER instead of the change.
* **Monotonic chain.** `A -> B -> A -> B` passed every gate: each step's
  `before` matched what was stored. An actor holding admin credentials could
  append events without bound, re-hashing and re-signing the layer each time.
* **Approvers.** Whether one admin may move signature-bound state alone is a
  deployment question, not a library one.
* **Bulk.** Nine layers should not need nine invocations, and one refused
  layer must not strand the other eight.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest
from traust_contracts.v1.enums import RestatementTarget
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger._internal.backends.file import FileBackend
from traust_ledger._internal.integrity import Severity, verify_merkle_integrity
from traust_ledger._internal.integrity.merkle import canonical_event_bytes
from traust_ledger._internal.restatements import (
    RESTATABLE_METADATA_FIELDS,
    merge_delta,
    restatements_for,
    retired_values,
    terminal_value,
)
from traust_ledger._internal.writer import LedgerWriter
from traust_ledger.config import ServiceConfig
from traust_ledger.errors import (
    InsufficientApproversError,
    NothingToRestateError,
    RetiredValueRestatedError,
    StaleRestatementError,
)
from traust_ledger.handlers.restatement_handler import apply_restatement
from traust_ledger.paths import layer_file_path
from traust_ledger.service.auth import authorize_restatement

ADMIN_ID = "admin@example.com"
ADMIN = LayerActor(kind="human", identity=ADMIN_ID, identity_verified=True)
LAYER_ID = "hardening"
NOW = "2026-09-28T12:00:00+00:00"
RATIONALE = "Claim re-baselined after the finding's severity was corrected upstream."


def _claims(n: int) -> dict[str, str]:
    return {f"FIND-{i:04d}": f"{i:064x}" for i in range(n)}


def _seed(tmp_path: Path, *, claims: dict | None = None, approvers: int = 0):
    backend = FileBackend(data_dir=tmp_path)
    metadata: dict = {
        "audit_report": "audit.json",
        "repository": "https://example.test/repo",
        "created": "2026-09-01T10:00:00+00:00",
        "harness_version": "1.0.0",
    }
    if claims is not None:
        metadata["claim_hashes"] = claims
    backend.initialize(
        layer_file_path(str(tmp_path), LAYER_ID),
        {"metadata": metadata, "events": [], "needs_review": []},
    )
    config = ServiceConfig(
        data_dir=str(tmp_path),
        admin_identities=[ADMIN_ID],
        restatement_min_approvers=approvers,
    )
    return LedgerWriter(backend=backend), config


def _load(tmp_path: Path) -> dict:
    return FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), LAYER_ID))


def _restate(writer, config, block: dict, *, actor: LayerActor = ADMIN, rationale=RATIONALE):
    return apply_restatement(LAYER_ID, block, rationale, actor, NOW, writer, config)


def _block(before: dict, after: dict, **over) -> dict:
    block = {
        "target": "claim_hashes",
        "reason": "data_error",
        "before": before,
        "after": after,
        "authority": {"ticket": "SEC-1"},
    }
    block.update(over)
    return block


# ── Delta semantics ──────────────────────────────────────────────────────────


class TestDelta:
    def test_only_the_changed_entry_is_recorded(self, tmp_path: Path) -> None:
        claims = _claims(50)
        writer, config = _seed(tmp_path, claims=claims)
        _restate(
            writer,
            config,
            _block({"FIND-0000": claims["FIND-0000"]}, {"FIND-0000": "f" * 64}),
        )
        layer = _load(tmp_path)
        block = layer["events"][-1]["restatement"]
        assert list(block["before"]) == ["FIND-0000"]
        assert list(block["after"]) == ["FIND-0000"]
        # the other 49 entries survive untouched, merged under the lock
        assert len(layer["metadata"]["claim_hashes"]) == 50
        assert layer["metadata"]["claim_hashes"]["FIND-0000"] == "f" * 64
        assert layer["metadata"]["claim_hashes"]["FIND-0001"] == claims["FIND-0001"]

    def test_event_size_tracks_the_change_not_the_layer(self, tmp_path: Path) -> None:
        """The whole point of the delta form: restating one claim on a large
        layer must not cost the size of the layer."""
        sizes = {}
        for n in (10, 500):
            dir_n = tmp_path / str(n)
            dir_n.mkdir()
            claims = _claims(n)
            writer, config = _seed(dir_n, claims=claims)
            _restate(
                writer,
                config,
                _block({"FIND-0000": claims["FIND-0000"]}, {"FIND-0000": "f" * 64}),
            )
            event = _load(dir_n)["events"][-1]
            sizes[n] = len(canonical_event_bytes(event))
        assert sizes[500] == sizes[10], (
            f"a one-entry restatement cost {sizes[10]} B on a 10-finding layer and "
            f"{sizes[500]} B on a 500-finding layer — the delta is not bounded"
        )

    def test_a_null_value_deletes_an_entry(self, tmp_path: Path) -> None:
        claims = _claims(3)
        writer, config = _seed(tmp_path, claims=claims)
        _restate(
            writer,
            config,
            _block({"FIND-0001": claims["FIND-0001"]}, {"FIND-0001": None}),
        )
        remaining = _load(tmp_path)["metadata"]["claim_hashes"]
        assert "FIND-0001" not in remaining
        assert len(remaining) == 2

    def test_merge_delta_is_pure_and_per_key(self) -> None:
        current = {"a": "1", "b": "2"}
        assert merge_delta(current, {"b": "9"}) == {"a": "1", "b": "9"}
        assert merge_delta(current, {"c": "3"}) == {"a": "1", "b": "2", "c": "3"}
        assert merge_delta(current, {"a": None}) == {"b": "2"}
        assert current == {"a": "1", "b": "2"}, "input must not be mutated"
        assert merge_delta("old-digest", "new-digest") == "new-digest"

    def test_chain_replay_is_per_key(self, tmp_path: Path) -> None:
        claims = _claims(3)
        writer, config = _seed(tmp_path, claims=claims)
        _restate(
            writer, config, _block({"FIND-0000": claims["FIND-0000"]}, {"FIND-0000": "a" * 64})
        )
        _restate(
            writer, config, _block({"FIND-0002": claims["FIND-0002"]}, {"FIND-0002": "b" * 64})
        )
        layer = _load(tmp_path)
        restated, expected = terminal_value(layer["events"], "claim_hashes")
        assert restated
        # only the two restated keys are pinned; FIND-0001 is unconstrained
        assert expected == {"FIND-0000": "a" * 64, "FIND-0002": "b" * 64}
        assert not [f for f in verify_merkle_integrity(layer) if f.severity == Severity.ERROR]

    def test_verify_flags_only_the_drifted_entry(self, tmp_path: Path) -> None:
        claims = _claims(3)
        writer, config = _seed(tmp_path, claims=claims)
        _restate(
            writer, config, _block({"FIND-0000": claims["FIND-0000"]}, {"FIND-0000": "a" * 64})
        )
        layer = _load(tmp_path)

        # an untouched entry may change without tripping the chain check —
        # nothing in the chain ever spoke about it
        layer["metadata"]["claim_hashes"]["FIND-0001"] = "e" * 64
        assert not [f for f in verify_merkle_integrity(layer) if f.severity == Severity.ERROR]

        # the restated entry may not
        layer["metadata"]["claim_hashes"]["FIND-0000"] = "9" * 64
        errors = [f for f in verify_merkle_integrity(layer) if f.severity == Severity.ERROR]
        assert errors and "FIND-0000" in errors[0].message


# ── Monotonic chain ──────────────────────────────────────────────────────────


class TestMonotonic:
    def test_restoring_a_retired_value_is_refused(self, tmp_path: Path) -> None:
        claims = _claims(1)
        original = claims["FIND-0000"]
        writer, config = _seed(tmp_path, claims=claims)
        _restate(writer, config, _block({"FIND-0000": original}, {"FIND-0000": "b" * 64}))

        with pytest.raises(RetiredValueRestatedError):
            _restate(writer, config, _block({"FIND-0000": "b" * 64}, {"FIND-0000": original}))
        assert len(_load(tmp_path)["events"]) == 1

    def test_the_cycle_that_used_to_run_forever(self, tmp_path: Path) -> None:
        """A -> B -> A -> B passed every other gate: each step's `before`
        matched what was stored, so an admin could append without bound."""
        claims = _claims(1)
        a, b = claims["FIND-0000"], "b" * 64
        writer, config = _seed(tmp_path, claims=claims)
        _restate(writer, config, _block({"FIND-0000": a}, {"FIND-0000": b}))
        for _ in range(3):
            with pytest.raises(RetiredValueRestatedError):
                _restate(writer, config, _block({"FIND-0000": b}, {"FIND-0000": a}))
        assert len(_load(tmp_path)["events"]) == 1, "the loop appends nothing"

    def test_fresh_values_still_chain_freely(self, tmp_path: Path) -> None:
        """The guard blocks going BACK, not going forward."""
        claims = _claims(1)
        writer, config = _seed(tmp_path, claims=claims)
        chain = [claims["FIND-0000"], "b" * 64, "c" * 64, "d" * 64]
        for prior, nxt in itertools.pairwise(chain):
            _restate(writer, config, _block({"FIND-0000": prior}, {"FIND-0000": nxt}))
        layer = _load(tmp_path)
        assert len(restatements_for(layer["events"], "claim_hashes")) == 3
        assert layer["metadata"]["claim_hashes"]["FIND-0000"] == "d" * 64
        assert not [f for f in verify_merkle_integrity(layer) if f.severity == Severity.ERROR]

    def test_retirement_is_tracked_per_key(self, tmp_path: Path) -> None:
        """A value retired for one finding says nothing about another, or the
        guard would block two findings that legitimately share a digest."""
        claims = {"FIND-0000": "a" * 64, "FIND-0001": "a" * 64}
        writer, config = _seed(tmp_path, claims=claims)
        _restate(writer, config, _block({"FIND-0000": "a" * 64}, {"FIND-0000": "b" * 64}))
        # same value, different key: allowed
        _restate(writer, config, _block({"FIND-0001": "a" * 64}, {"FIND-0001": "c" * 64}))
        layer = _load(tmp_path)
        assert retired_values(layer["events"], "claim_hashes", "FIND-0000") == [
            "a" * 64,
            "b" * 64,
        ]
        assert len(layer["events"]) == 2

    def test_scalar_target_cannot_cycle_either(self, tmp_path: Path) -> None:
        writer, config = _seed(tmp_path)

        def patch(layer: dict) -> None:
            layer["metadata"]["audit_report_sha256"] = "1" * 64

        writer.backend.mutate(layer_file_path(str(tmp_path), LAYER_ID), patch)
        digest_block = {
            "target": "audit_report_sha256",
            "reason": "baseline_rewrite",
            "authority": {"ticket": "SEC-1"},
        }
        _restate(writer, config, {**digest_block, "before": "1" * 64, "after": "2" * 64})
        with pytest.raises(RetiredValueRestatedError):
            _restate(writer, config, {**digest_block, "before": "2" * 64, "after": "1" * 64})


# ── Per-key freshness and first-write ────────────────────────────────────────


class TestPerKeyGuards:
    def test_restating_an_absent_key_is_refused(self, tmp_path: Path) -> None:
        """Adding a newly baselined finding is an addition, not a restatement,
        even when the map already holds other entries."""
        writer, config = _seed(tmp_path, claims=_claims(2))
        with pytest.raises(NothingToRestateError) as exc:
            _restate(writer, config, _block({"FIND-9999": "a" * 64}, {"FIND-9999": "b" * 64}))
        assert "FIND-9999" in str(exc.value)

    def test_stale_entry_is_named(self, tmp_path: Path) -> None:
        claims = _claims(3)
        writer, config = _seed(tmp_path, claims=claims)
        with pytest.raises(StaleRestatementError) as exc:
            _restate(writer, config, _block({"FIND-0001": "9" * 64}, {"FIND-0001": "b" * 64}))
        assert "FIND-0001" in str(exc.value)

    def test_target_vocabulary_is_signed_metadata_only(self) -> None:
        """finding_aliases is gone: a rebaseline event already records a rename
        inside the Merkle tree, so the metadata table is a projection."""
        assert set(RESTATABLE_METADATA_FIELDS) == {t.value for t in RestatementTarget}
        assert "finding_aliases" not in {t.value for t in RestatementTarget}


# ── Approver threshold ───────────────────────────────────────────────────────


def _authorized_restate(writer, config, block: dict, *, actor: LayerActor = ADMIN):
    """The REST path: the approver threshold is enforced at the boundary."""
    authorize_restatement(actor, block, config)
    return _restate(writer, config, block, actor=actor)


class TestApprovers:
    def test_default_needs_no_approver(self, tmp_path: Path) -> None:
        claims = _claims(1)
        writer, config = _seed(tmp_path, claims=claims, approvers=0)
        _restate(
            writer, config, _block({"FIND-0000": claims["FIND-0000"]}, {"FIND-0000": "b" * 64})
        )
        assert len(_load(tmp_path)["events"]) == 1

    def test_threshold_requires_a_named_approver(self, tmp_path: Path) -> None:
        claims = _claims(1)
        writer, config = _seed(tmp_path, claims=claims, approvers=1)
        block = _block({"FIND-0000": claims["FIND-0000"]}, {"FIND-0000": "b" * 64})
        with pytest.raises(InsufficientApproversError):
            _authorized_restate(writer, config, block)
        approved = _block(
            {"FIND-0000": claims["FIND-0000"]},
            {"FIND-0000": "b" * 64},
            authority={"ticket": "SEC-1", "approved_by": "lead@example.com"},
        )
        _authorized_restate(writer, config, approved)
        assert len(_load(tmp_path)["events"]) == 1

    def test_the_actor_cannot_approve_themselves(self, tmp_path: Path) -> None:
        claims = _claims(1)
        writer, config = _seed(tmp_path, claims=claims, approvers=1)
        block = _block(
            {"FIND-0000": claims["FIND-0000"]},
            {"FIND-0000": "b" * 64},
            authority={"ticket": "SEC-1", "approved_by": ADMIN_ID.upper()},
        )
        with pytest.raises(InsufficientApproversError):
            _authorized_restate(writer, config, block)

    def test_two_approvers_must_be_distinct(self, tmp_path: Path) -> None:
        claims = _claims(1)
        writer, config = _seed(tmp_path, claims=claims, approvers=2)
        same_twice = _block(
            {"FIND-0000": claims["FIND-0000"]},
            {"FIND-0000": "b" * 64},
            authority={"ticket": "SEC-1", "approved_by": "lead@example.com,lead@example.com"},
        )
        with pytest.raises(InsufficientApproversError):
            _authorized_restate(writer, config, same_twice)
        two = _block(
            {"FIND-0000": claims["FIND-0000"]},
            {"FIND-0000": "b" * 64},
            authority={"ticket": "SEC-1", "approved_by": "lead@example.com, sec@example.com"},
        )
        _authorized_restate(writer, config, two)
        assert len(_load(tmp_path)["events"]) == 1


# ── Bulk ─────────────────────────────────────────────────────────────────────


class TestBulk:
    def _bulk_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, layers: dict) -> None:
        backend = FileBackend(data_dir=tmp_path)
        for layer_id, claims in layers.items():
            backend.initialize(
                layer_file_path(str(tmp_path), layer_id),
                {
                    "metadata": {
                        "audit_report": "audit.json",
                        "repository": "https://example.test/repo",
                        "created": "2026-09-01T10:00:00+00:00",
                        "harness_version": "1.0.0",
                        "claim_hashes": claims,
                    },
                    "events": [],
                    "needs_review": [],
                },
            )
        monkeypatch.setenv("LAAS_BACKEND_TYPE", "file")
        monkeypatch.setenv("LAAS_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("LAAS_ADMIN_IDENTITIES", ADMIN_ID)
        monkeypatch.setattr("traust_ledger.cli.commands.restate.require_cli_auth", lambda: False)
        monkeypatch.setattr(
            "traust_ledger.cli.commands.restate.require_verified_actor", lambda: ADMIN
        )

    def test_one_file_applies_many_layers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        from traust_ledger.cli.main import main

        layers = {f"repo-{i}": {"FIND-0001": f"{i:064x}"} for i in range(3)}
        self._bulk_env(tmp_path, monkeypatch, layers)
        batch = tmp_path / "batch.json"
        batch.write_text(
            json.dumps(
                [
                    {
                        "layer": layer_id,
                        "rationale": RATIONALE,
                        "target": "claim_hashes",
                        "reason": "data_error",
                        "before": claims,
                        "after": {"FIND-0001": "f" * 64},
                        "authority": {"ticket": "SEC-BULK"},
                    }
                    for layer_id, claims in layers.items()
                ]
            )
        )
        assert main(["restate", "--from", str(batch)]) == 0
        report = json.loads(capsys.readouterr().out)
        assert len(report["applied"]) == 3
        assert report["failed"] == []
        for layer_id in layers:
            layer = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), layer_id))
            assert layer["metadata"]["claim_hashes"]["FIND-0001"] == "f" * 64
            assert len(layer["events"]) == 1

    def test_one_bad_item_does_not_strand_the_rest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        """A refused layer is reported and the run continues: every write is
        atomic on its own layer, so there is nothing to roll back."""
        from traust_ledger.cli.main import main

        layers = {"repo-good": {"FIND-0001": "a" * 64}, "repo-stale": {"FIND-0001": "a" * 64}}
        self._bulk_env(tmp_path, monkeypatch, layers)
        batch = tmp_path / "batch.json"
        batch.write_text(
            json.dumps(
                {
                    "restatements": [
                        {
                            "layer": "repo-good",
                            "rationale": RATIONALE,
                            "target": "claim_hashes",
                            "reason": "data_error",
                            "before": {"FIND-0001": "a" * 64},
                            "after": {"FIND-0001": "f" * 64},
                            "authority": {"ticket": "SEC-BULK"},
                        },
                        {
                            "layer": "repo-stale",
                            "rationale": RATIONALE,
                            "target": "claim_hashes",
                            "reason": "data_error",
                            "before": {"FIND-0001": "9" * 64},  # not what is stored
                            "after": {"FIND-0001": "f" * 64},
                            "authority": {"ticket": "SEC-BULK"},
                        },
                    ]
                }
            )
        )
        assert main(["restate", "--from", str(batch)]) == 1, (
            "a failure must be visible in exit code"
        )
        report = json.loads(capsys.readouterr().out)
        assert [a["layer_id"] for a in report["applied"]] == ["repo-good"]
        assert report["failed"][0]["layer"] == "repo-stale"

        good = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), "repo-good"))
        stale = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), "repo-stale"))
        assert len(good["events"]) == 1
        assert stale["events"] == []
        assert stale["metadata"]["claim_hashes"]["FIND-0001"] == "a" * 64


class TestBulkParity:
    """The bulk form is shared, not reimplemented per surface.

    It is absent from REST on purpose: one HTTP request cannot be atomic across
    N layers (one lock per layer), so a batch endpoint would imply a guarantee
    the storage model does not give.
    """

    def _client(self, tmp_path: Path, layers: dict):
        from traust_ledger._internal.integrity.signing import SigningConfig
        from traust_ledger.client import LedgerClient

        backend = FileBackend(data_dir=tmp_path)
        for layer_id, claims in layers.items():
            backend.initialize(
                layer_file_path(str(tmp_path), layer_id),
                {
                    "metadata": {
                        "audit_report": "audit.json",
                        "repository": "https://example.test/repo",
                        "created": "2026-09-01T10:00:00+00:00",
                        "harness_version": "1.0.0",
                        "claim_hashes": claims,
                    },
                    "events": [],
                    "needs_review": [],
                },
            )

        class _Verifier:
            def verify(self, token: str) -> LayerActor:
                return ADMIN

        return LedgerClient(
            token="stub",
            verifier=_Verifier(),
            data_dir=str(tmp_path),
            signing_config=SigningConfig(method="none"),
        )

    def _item(self, layer_id: str, before: dict, after: dict) -> dict:
        return {
            "layer": layer_id,
            "rationale": RATIONALE,
            "target": "claim_hashes",
            "reason": "data_error",
            "before": before,
            "after": after,
            "authority": {"ticket": "SEC-BULK"},
        }

    def test_client_bulk_matches_the_cli_contract(self, tmp_path: Path) -> None:
        layers = {f"repo-{i}": {"FIND-0001": f"{i:064x}"} for i in range(3)}
        client = self._client(tmp_path, layers)
        report = client.restate_many(
            [self._item(lid, claims, {"FIND-0001": "f" * 64}) for lid, claims in layers.items()]
        )
        assert len(report["applied"]) == 3
        assert report["failed"] == []
        for layer_id in layers:
            layer = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), layer_id))
            assert layer["metadata"]["claim_hashes"]["FIND-0001"] == "f" * 64

    def test_client_bulk_reports_a_refusal_without_stranding_the_rest(self, tmp_path: Path) -> None:
        layers = {"repo-good": {"FIND-0001": "a" * 64}, "repo-stale": {"FIND-0001": "a" * 64}}
        client = self._client(tmp_path, layers)
        report = client.restate_many(
            [
                self._item("repo-good", {"FIND-0001": "a" * 64}, {"FIND-0001": "f" * 64}),
                self._item("repo-stale", {"FIND-0001": "9" * 64}, {"FIND-0001": "f" * 64}),
            ]
        )
        assert [a["layer_id"] for a in report["applied"]] == ["repo-good"]
        assert report["failed"][0]["layer"] == "repo-stale"
        assert "does not match the stored value" in report["failed"][0]["error"]
        stale = FileBackend(data_dir=tmp_path).load(layer_file_path(str(tmp_path), "repo-stale"))
        assert stale["events"] == []

    def test_bulk_honours_the_same_gates_as_single(self, tmp_path: Path) -> None:
        """A surface that skipped a gate would be the whole reason the handler
        is shared."""
        layers = {"repo-a": {"FIND-0001": "a" * 64}}
        client = self._client(tmp_path, layers)
        unticketed = self._item("repo-a", {"FIND-0001": "a" * 64}, {"FIND-0001": "f" * 64})
        unticketed["authority"] = {}
        report = client.restate_many([unticketed])
        assert report["applied"] == []
        assert "ticket" in report["failed"][0]["error"]

    def test_rest_has_no_batch_route(self) -> None:
        from traust_ledger.service import routes

        paths = [r.path for r in routes.router.routes if "restate" in getattr(r, "path", "")]
        # One layer per request under either addressing style; no batch route.
        assert paths == ["/v1/ledger/layers/{layer_id}/restate", "/v1/ledger/layer/restate"]

    def test_empty_batch_is_refused(self, tmp_path: Path) -> None:
        from traust_ledger.client import LedgerError

        client = self._client(tmp_path, {"repo-a": {"FIND-0001": "a" * 64}})
        with pytest.raises(LedgerError):
            client.restate_many([])
