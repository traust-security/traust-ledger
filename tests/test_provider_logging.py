from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from traust_ledger.integrity import signing
from traust_ledger.integrity.signing import CosignBackend

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
    def fail_run(*_: object, **__: object) -> object:
        raise RuntimeError(SECRET)

    monkeypatch.setattr(subprocess, "run", fail_run)
    monkeypatch.setattr(signing.log, "log", mock.Mock(side_effect=KeyError("operation")))
    with pytest.raises(RuntimeError, match=SECRET):
        CosignBackend().sign(b"private payload", f"/{SECRET}.key")
