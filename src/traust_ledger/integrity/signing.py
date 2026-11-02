"""Signing backend adapters for Merkle root signatures."""

from __future__ import annotations

import abc
import json
import logging
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from time import perf_counter
from typing import ParamSpec, TypeVar

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())
_Params = ParamSpec("_Params")
_Result = TypeVar("_Result")


def _emit_terminal(
    *,
    operation: str,
    provider: str,
    method: str,
    outcome: str,
    reason: str,
    started: float,
) -> None:
    duration_ms = (perf_counter() - started) * 1000
    level = logging.INFO if outcome in {"signed", "verified"} else logging.WARNING
    event_operation = f"ledger.{operation}"
    # Application logging configuration must not replace a provider result or exception.
    with suppress(Exception):
        log.log(
            level,
            "ledger provider operation=%s provider=%s method=%s outcome=%s "
            "reason=%s duration_ms=%.1f",
            event_operation,
            provider,
            method,
            outcome,
            reason,
            duration_ms,
            extra={
                "operation": event_operation,
                "provider": provider,
                "method": method,
                "outcome": outcome,
                "reason": reason,
                "duration_ms": duration_ms,
            },
        )


def _terminal_on_unexpected(
    *, operation: str, provider: str, method: str
) -> Callable[[Callable[_Params, _Result]], Callable[_Params, _Result]]:
    """Emit one bounded event when a provider boundary unexpectedly raises."""

    def decorate(function: Callable[_Params, _Result]) -> Callable[_Params, _Result]:
        @wraps(function)
        def guarded(*args: _Params.args, **kwargs: _Params.kwargs) -> _Result:
            started = perf_counter()
            try:
                return function(*args, **kwargs)
            except Exception:
                _emit_terminal(
                    operation=operation,
                    provider=provider,
                    method=method,
                    outcome="failed",
                    reason="unexpected_error",
                    started=started,
                )
                raise

        return guarded

    return decorate


def _terminal(
    result: _Result,
    *,
    operation: str,
    provider: str,
    method: str,
    outcome: str,
    reason: str,
    started: float,
) -> _Result:
    _emit_terminal(
        operation=operation,
        provider=provider,
        method=method,
        outcome=outcome,
        reason=reason,
        started=started,
    )
    return result


@dataclass
class SignResult:
    signature: str  # base64-encoded signature or JSON bundle (OIDC)
    success: bool
    error: str | None = None


@dataclass
class VerifyResult:
    valid: bool
    error: str | None = None


@dataclass
class SigningConfig:
    """Which signer to use and how to reach it; the caller builds it from its own config."""

    method: str = "keypair"
    key_path: str | None = None


class SigningBackend(abc.ABC):
    """Abstract signing backend. Implementations wrap specific tools."""

    @property
    @abc.abstractmethod
    def method_name(self) -> str:
        """Generic method identifier (e.g. 'keypair')."""
        ...

    @abc.abstractmethod
    def available(self) -> bool:
        """Check if this backend's tooling is available."""
        ...

    @abc.abstractmethod
    def sign(self, payload: bytes, key_path: str) -> SignResult:
        """Sign payload bytes, return base64 signature."""
        ...

    @abc.abstractmethod
    def verify(self, payload: bytes, signature: str, key_path: str) -> VerifyResult:
        """Verify a base64 signature against payload."""
        ...


def _transparency_evidence(bundle: dict) -> list[str]:
    """Names of any transparency-log/timestamp material found in a bundle.

    Empty list == the signature was not published anywhere. Used as a
    post-condition on signing; see CosignBackend.sign.
    """
    vm = bundle.get("verificationMaterial") or {}
    found = []
    if vm.get("tlogEntries"):
        found.append(f"{len(vm['tlogEntries'])} tlogEntries")
    stamps = (vm.get("timestampVerificationData") or {}).get("rfc3161Timestamps")
    if stamps:
        found.append(f"{len(stamps)} rfc3161Timestamps")
    return found


class CosignBackend(SigningBackend):
    """Cosign sign-blob / verify-blob adapter."""

    @property
    def method_name(self) -> str:
        return "keypair"

    def available(self) -> bool:
        return shutil.which("cosign") is not None

    # cosign v3 compatibility (2026-08-12).
    #
    # v3 changed the sign-blob contract this backend targeted under v2:
    #   * --output-signature is deprecated and now HARD-FAILS ("must specify
    #     --bundle with --new-bundle-format"); the signature is delivered
    #     inside a Sigstore bundle written to a file, not on stdout.
    #   * --tlog-upload=false is rejected while the default signing config is
    #     active, and WITHOUT it cosign uploads to the PUBLIC rekor.sigstore.dev
    #     by default. For an internal security ledger that is unacceptable: it
    #     publishes the timing of ledger writes to an irrevocable public log,
    #     makes signing depend on Sigstore's availability, and inflates the
    #     bundle from ~390 bytes to ~3.8 KB (about 84 MB across a 22k-layer
    #     corpus). --use-signing-config=false restores the offline path.
    #
    # Also fixed here: the v2 code piped the payload on stdin but never passed
    # the positional blob argument, so every invocation failed with "requires
    # at least 1 arg(s), only received 0" — keypair signing had never worked.
    @_terminal_on_unexpected(operation="sign", provider="cosign", method="keypair")
    def sign(self, payload: bytes, key_path: str) -> SignResult:
        started = perf_counter()

        def done(result: SignResult, outcome: str, reason: str) -> SignResult:
            return _terminal(
                result,
                operation="sign",
                provider="cosign",
                method=self.method_name,
                outcome=outcome,
                reason=reason,
                started=started,
            )

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            blob = td_path / "payload.bin"
            bundle = td_path / "out.bundle"
            with blob.open("wb") as fh:
                fh.write(payload)

            cmd = [
                "cosign",
                "sign-blob",
                "--key",
                key_path,
                "--yes",
                # Never publish: the transparency log is forbidden by policy
                # (config/external-tools.yaml, cosign signing_policy).
                "--use-signing-config=false",
                "--tlog-upload=false",
                "--bundle",
                bundle,
                blob,
            ]

            try:
                result = subprocess.run(cmd, capture_output=True, timeout=60)
            except (OSError, subprocess.SubprocessError) as e:
                return done(
                    SignResult(signature="", success=False, error=str(e)),
                    "failed",
                    "process_error",
                )

            if result.returncode != 0:
                return done(
                    SignResult(
                        signature="",
                        success=False,
                        error=result.stderr.decode(errors="replace").strip(),
                    ),
                    "failed",
                    "nonzero_exit",
                )
            try:
                raw = Path(bundle).read_text(encoding="utf-8").strip()
            except OSError as e:
                return done(
                    SignResult(
                        signature="",
                        success=False,
                        error=f"cosign reported success but wrote no bundle: {e}",
                    ),
                    "failed",
                    "bundle_missing",
                )

        if not raw:
            return done(
                SignResult(signature="", success=False, error="cosign wrote an empty bundle"),
                "failed",
                "bundle_empty",
            )

        try:
            bundle = json.loads(raw)
        except ValueError:
            bundle = None

        # POST-CONDITION: never return a signature that was published.
        #
        # The flags above ask cosign not to use a transparency log, but flags
        # are not a durable defence — v2's `--tlog-upload=false` is REJECTED by
        # v3's default signing config, and v3 publishes to the PUBLIC
        # rekor.sigstore.dev when not told otherwise. A future version can
        # change the contract again. So instead of trusting the request, verify
        # the artifact: if the bundle carries a transparency-log entry or an
        # RFC3161 timestamp DISCARD
        # the signature and fail loudly. Publication is irreversible; a failed
        # signing run is not.
        #
        # Policy of record: config/external-tools.yaml, cosign
        # signing_policy.transparency_log: forbidden.
        if bundle is not None:
            published = _transparency_evidence(bundle)
            if published:
                return done(
                    SignResult(
                        signature="",
                        success=False,
                        error=(
                            "REFUSING the signature: cosign published it to a "
                            f"transparency log ({', '.join(published)}) despite "
                            "being asked not to. The signature has been "
                            "discarded, but the upload is already public and "
                            "irreversible. cosign has almost certainly changed "
                            "its flag contract again — see the "
                            "transparency-log hazard note on the cosign entry "
                            "in config/external-tools.yaml."
                        ),
                    ),
                    "refused",
                    "transparency_evidence",
                )

        # Compact to one line so it round-trips through JSON layer metadata.
        if bundle is not None:
            raw = json.dumps(bundle, separators=(",", ":"))
        return done(SignResult(signature=raw, success=True), "signed", "completed")

    @_terminal_on_unexpected(operation="verify", provider="cosign", method="keypair")
    def verify(self, payload: bytes, signature: str, key_path: str) -> VerifyResult:
        """Verify a v3 bundle, falling back to a v2 bare signature.

        Anything signed before the v3 port carries a base64 signature rather
        than a bundle, so both are accepted on the read path — refusing them
        would invalidate history that was validly signed under the old
        contract.
        """
        started = perf_counter()

        def done(result: VerifyResult, outcome: str, reason: str) -> VerifyResult:
            return _terminal(
                result,
                operation="verify",
                provider="cosign",
                method=self.method_name,
                outcome=outcome,
                reason=reason,
                started=started,
            )

        is_bundle = signature.lstrip().startswith("{")
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            blob = td_path / "payload.bin"
            with blob.open("wb") as fh:
                fh.write(payload)

            if is_bundle:
                bundle = td_path / "in.bundle"
                bundle.write_text(signature, encoding="utf-8")
                # --insecure-ignore-tlog is correct here rather than a
                # weakening: the bundle deliberately carries no
                # transparency-log entry (see sign). Integrity comes from the
                # key, not from Rekor.
                cmd = [
                    "cosign",
                    "verify-blob",
                    "--key",
                    key_path,
                    "--bundle",
                    bundle,
                    "--insecure-ignore-tlog",
                    blob,
                ]
            else:
                cmd = ["cosign", "verify-blob", "--key", key_path, "--signature", signature, blob]

            try:
                result = subprocess.run(cmd, capture_output=True, timeout=60)
            except (OSError, subprocess.SubprocessError) as e:
                return done(VerifyResult(valid=False, error=str(e)), "failed", "process_error")

        if result.returncode != 0:
            return done(
                VerifyResult(valid=False, error=result.stderr.decode(errors="replace").strip()),
                "failed",
                "nonzero_exit",
            )
        return done(VerifyResult(valid=True), "verified", "completed")


_METHOD_BACKENDS: dict[str, type[SigningBackend]] = {
    "keypair": CosignBackend,
}


def get_backend(name: str = "cosign") -> SigningBackend:
    """Factory for signing backends by provider name."""
    providers: dict[str, type[SigningBackend]] = {"cosign": CosignBackend}
    cls = providers.get(name)
    if cls is None:
        raise ValueError(f"Unknown signing backend: {name!r}. Available: {list(providers)}")
    return cls()


def get_backend_for_method(method: str) -> SigningBackend:
    """Resolve a generic signing method name to the corresponding backend."""
    cls = _METHOD_BACKENDS.get(method)
    if cls is None:
        raise ValueError(
            f"Unknown signing method: {method!r}. Available methods: {list(_METHOD_BACKENDS)}"
        )
    return cls()


def get_backend_from_config(config: SigningConfig) -> SigningBackend:
    """Dispatch to the correct backend based on a SigningConfig."""
    cls = _METHOD_BACKENDS.get(config.method)
    if cls is None:
        raise ValueError(
            f"Unknown signing method: {config.method!r}. "
            f"Available methods: {list(_METHOD_BACKENDS)}"
        )
    return cls()
