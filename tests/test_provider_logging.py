from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

from traust_ledger.integrity import signing
from traust_ledger.integrity.signing import CosignBackend, SigstoreOIDCBackend

LOGGER = "traust_ledger.integrity.signing"
SECRET = "synthetic-secret-never-log"


def test_library_configures_no_output_handler() -> None:
    logger = logging.getLogger(LOGGER)
    assert logger.propagate is True
    assert logger.handlers and all(
        isinstance(handler, logging.NullHandler) for handler in logger.handlers
    )


def event(caplog: pytest.LogCaptureFixture) -> logging.LogRecord:
    records = [record for record in caplog.records if record.name == LOGGER]
    assert len(records) == 1
    record = records[0]
    assert isinstance(record.duration_ms, float) and record.duration_ms >= 0
    assert f"operation={record.operation}" in record.getMessage()
    expected_level = logging.INFO if record.outcome in {"signed", "verified"} else logging.WARNING
    assert record.levelno == expected_level
    return record


def test_cosign_nonzero_logs_only_a_bounded_terminal_reason(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    result = mock.Mock(returncode=7, stdout=b"payload output", stderr=SECRET.encode())
    monkeypatch.setattr(subprocess, "run", mock.Mock(return_value=result))
    key = f"/private/{SECRET}.key"
    with caplog.at_level(logging.INFO, logger=LOGGER):
        outcome = CosignBackend().sign(b"private document body", key)
    record = event(caplog)
    assert not outcome.success and outcome.error == SECRET
    assert (record.operation, record.provider, record.method, record.outcome, record.reason) == (
        "ledger.sign",
        "cosign",
        "keypair",
        "failed",
        "nonzero_exit",
    )
    assert SECRET not in caplog.text
    assert key not in caplog.text and "private document body" not in caplog.text
    assert "payload output" not in caplog.text


def test_cosign_timeout_does_not_log_command_arguments(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    error = subprocess.TimeoutExpired(["cosign", "--key", SECRET], 60, stderr=SECRET.encode())
    monkeypatch.setattr(subprocess, "run", mock.Mock(side_effect=error))
    with caplog.at_level(logging.INFO, logger=LOGGER):
        outcome = CosignBackend().sign(b"payload", f"/{SECRET}.key")
    record = event(caplog)
    assert not outcome.success
    assert (record.outcome, record.reason) == ("failed", "process_error")
    assert SECRET not in caplog.text


def test_cosign_success_and_invalid_signature_each_emit_one_terminal_event(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def run(command: list[object], **_: object) -> mock.Mock:
        if "sign-blob" in command:
            bundle = Path(command[command.index("--bundle") + 1])
            bundle.write_text(json.dumps({"messageSignature": {"signature": "safe"}}))
            return mock.Mock(returncode=0, stdout=b"", stderr=b"")
        return mock.Mock(returncode=1, stdout=b"", stderr=SECRET.encode())

    monkeypatch.setattr(subprocess, "run", run)
    with caplog.at_level(logging.INFO, logger=LOGGER):
        signed = CosignBackend().sign(b"payload", "/private/key")
        verified = CosignBackend().verify(b"payload", signed.signature, "/private/public")
    records = [record for record in caplog.records if record.name == LOGGER]
    assert signed.success and not verified.valid
    assert [(record.operation, record.outcome, record.reason) for record in records] == [
        ("ledger.sign", "signed", "completed"),
        ("ledger.verify", "failed", "nonzero_exit"),
    ]
    assert [record.levelno for record in records] == [logging.INFO, logging.WARNING]
    assert all(
        isinstance(record.duration_ms, float) and record.duration_ms >= 0 for record in records
    )
    assert all(f"operation={record.operation}" in record.getMessage() for record in records)
    assert SECRET not in caplog.text


def test_identity_provider_failure_omits_token_and_exception(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    backend = SigstoreOIDCBackend(oidc_token=SECRET)
    monkeypatch.setattr(signing, "_sigstore_importable", lambda: True)
    monkeypatch.setattr(backend, "_resolve_identity_token", lambda: object())

    def fail() -> object:
        raise RuntimeError(SECRET)

    monkeypatch.setattr(backend, "_build_signing_context", fail)
    with caplog.at_level(logging.INFO, logger=LOGGER):
        outcome = backend.sign(b"private document", "")
    record = event(caplog)
    assert not outcome.success and SECRET in (outcome.error or "")
    assert (record.provider, record.method, record.outcome, record.reason) == (
        "sigstore",
        "identity",
        "failed",
        "provider_error",
    )
    assert SECRET not in caplog.text and "private document" not in caplog.text


def test_identity_missing_credential_and_invalid_bundle_have_bounded_reasons(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    backend = SigstoreOIDCBackend()
    monkeypatch.setattr(signing, "_sigstore_importable", lambda: True)
    monkeypatch.setattr(backend, "_resolve_identity_token", lambda: None)
    with caplog.at_level(logging.INFO, logger=LOGGER):
        missing = backend.sign(b"payload", "")
    assert not missing.success
    assert event(caplog).reason == "credential_unavailable"

    caplog.clear()
    models = mock.MagicMock()
    models.Bundle.from_json.side_effect = ValueError(SECRET)
    with (
        mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.models": models,
                "sigstore.verify": mock.MagicMock(),
            },
        ),
        caplog.at_level(logging.INFO, logger=LOGGER),
    ):
        invalid = backend.verify(b"private payload", f"bundle-{SECRET}", "")
    record = event(caplog)
    assert not invalid.valid and SECRET in (invalid.error or "")
    assert (record.outcome, record.reason) == ("invalid", "invalid_bundle")
    assert SECRET not in caplog.text and "private payload" not in caplog.text


@pytest.mark.parametrize(
    ("bundle_text", "outcome", "reason"),
    [
        (None, "failed", "bundle_missing"),
        ("", "failed", "bundle_empty"),
        (
            json.dumps({"verificationMaterial": {"tlogEntries": [{"private": SECRET}]}}),
            "refused",
            "transparency_evidence",
        ),
    ],
)
def test_cosign_bundle_failures_have_bounded_terminal_reasons(
    bundle_text: str | None,
    outcome: str,
    reason: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def run(command: list[object], **_: object) -> mock.Mock:
        if bundle_text is not None:
            Path(command[command.index("--bundle") + 1]).write_text(bundle_text)
        return mock.Mock(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", run)
    with caplog.at_level(logging.INFO, logger=LOGGER):
        result = CosignBackend().sign(b"private payload", f"/{SECRET}.key")
    record = event(caplog)
    assert not result.success
    assert (record.outcome, record.reason) == (outcome, reason)
    assert SECRET not in caplog.text and "private payload" not in caplog.text


def test_unexpected_cosign_file_error_emits_once_then_reraises(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def fail_open(*_: object, **__: object) -> object:
        raise PermissionError(SECRET)

    monkeypatch.setattr(Path, "open", fail_open)
    with (
        caplog.at_level(logging.INFO, logger=LOGGER),
        pytest.raises(PermissionError, match=SECRET),
    ):
        CosignBackend().sign(b"private payload", f"/{SECRET}.key")
    record = event(caplog)
    assert (record.outcome, record.reason) == ("failed", "unexpected_error")
    assert SECRET not in caplog.text and "private payload" not in caplog.text


def test_logging_failure_does_not_replace_provider_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = mock.Mock(returncode=7, stdout=b"", stderr=SECRET.encode())
    monkeypatch.setattr(subprocess, "run", mock.Mock(return_value=result))
    monkeypatch.setattr(signing.log, "log", mock.Mock(side_effect=KeyError("operation")))
    outcome = CosignBackend().sign(b"private document body", f"/{SECRET}.key")
    assert not outcome.success and outcome.error == SECRET


def test_logging_failure_does_not_replace_provider_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_import_check() -> bool:
        raise RuntimeError(SECRET)

    monkeypatch.setattr(signing, "_sigstore_importable", fail_import_check)
    monkeypatch.setattr(signing.log, "log", mock.Mock(side_effect=KeyError("operation")))
    with pytest.raises(RuntimeError, match=SECRET):
        SigstoreOIDCBackend().sign(b"private payload", "")


def test_unexpected_sigstore_setup_error_emits_once_then_reraises(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def fail_import_check() -> bool:
        raise RuntimeError(SECRET)

    monkeypatch.setattr(signing, "_sigstore_importable", fail_import_check)
    with (
        caplog.at_level(logging.INFO, logger=LOGGER),
        pytest.raises(RuntimeError, match=SECRET),
    ):
        SigstoreOIDCBackend().sign(b"private payload", "")
    record = event(caplog)
    assert (record.outcome, record.reason) == ("failed", "unexpected_error")
    assert SECRET not in caplog.text and "private payload" not in caplog.text


def test_identity_dependency_and_configuration_refusals_are_bounded(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    backend = SigstoreOIDCBackend()
    monkeypatch.setattr(signing, "_sigstore_importable", lambda: False)
    with caplog.at_level(logging.INFO, logger=LOGGER):
        unavailable = backend.sign(b"payload", "")
    assert not unavailable.success
    assert (event(caplog).outcome, event(caplog).reason) == (
        "refused",
        "dependency_unavailable",
    )

    caplog.clear()
    monkeypatch.setattr(signing, "_sigstore_importable", lambda: True)
    backend = SigstoreOIDCBackend(ca_url=f"https://{SECRET}.invalid")
    with caplog.at_level(logging.INFO, logger=LOGGER):
        invalid = backend.sign(b"payload", "")
    record = event(caplog)
    assert not invalid.success
    assert (record.outcome, record.reason) == ("refused", "invalid_configuration")
    assert SECRET not in caplog.text


def test_identity_verification_terminal_outcomes_are_distinct(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    models = mock.MagicMock()
    models.Bundle.from_json.return_value = object()
    verify = mock.MagicMock()
    modules = {
        "sigstore": mock.MagicMock(),
        "sigstore.models": models,
        "sigstore.verify": verify,
    }

    with mock.patch.dict(sys.modules, modules), caplog.at_level(logging.INFO, logger=LOGGER):
        missing_policy = SigstoreOIDCBackend().verify(b"payload", "bundle", "")
    assert not missing_policy.valid
    assert (event(caplog).outcome, event(caplog).reason) == (
        "refused",
        "identity_policy_unavailable",
    )

    caplog.clear()
    backend = SigstoreOIDCBackend(
        expected_identity="subject@example.test", oidc_issuer="https://issuer.example.test"
    )
    verifier = mock.MagicMock()
    monkeypatch.setattr(backend, "_build_verifier", lambda: verifier)
    with mock.patch.dict(sys.modules, modules), caplog.at_level(logging.INFO, logger=LOGGER):
        verified = backend.verify(b"payload", "bundle", "")
    assert verified.valid
    assert (event(caplog).outcome, event(caplog).reason) == ("verified", "completed")

    caplog.clear()
    verifier.verify_artifact.side_effect = RuntimeError(SECRET)
    with mock.patch.dict(sys.modules, modules), caplog.at_level(logging.INFO, logger=LOGGER):
        rejected = backend.verify(b"private payload", f"bundle-{SECRET}", "")
    record = event(caplog)
    assert not rejected.valid and SECRET in (rejected.error or "")
    assert (record.outcome, record.reason) == ("invalid", "verification_rejected")
    assert SECRET not in caplog.text and "private payload" not in caplog.text

    caplog.clear()

    def fail_verifier() -> object:
        raise RuntimeError(SECRET)

    monkeypatch.setattr(backend, "_build_verifier", fail_verifier)
    with mock.patch.dict(sys.modules, modules), caplog.at_level(logging.INFO, logger=LOGGER):
        failed = backend.verify(b"private payload", f"bundle-{SECRET}", "")
    record = event(caplog)
    assert not failed.valid and SECRET in (failed.error or "")
    assert (record.outcome, record.reason) == ("failed", "provider_error")
    assert SECRET not in caplog.text and "private payload" not in caplog.text
