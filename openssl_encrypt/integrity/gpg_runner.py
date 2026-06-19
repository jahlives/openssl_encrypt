#!/usr/bin/env python3
"""
Thin, audited wrapper around the system ``gpg`` binary.

All sign/verify operations shell out to ``gpg`` (decision D2) rather than using a
bundled OpenPGP library, so that verification trust rests on a binary the operator
chooses to trust. Every invocation uses an explicit argument list (never a shell
string) and never interpolates untrusted data into the command line; manifest and
signature bytes are passed through stdin or temporary files.

If ``gpg`` cannot be located the operations raise ``GpgUnavailableError`` so callers
can fail closed (decision Q8) instead of silently skipping verification.
"""

import os
import shutil
import subprocess  # nosec B404 - gpg is invoked with an argument list, never a shell
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


class GpgError(Exception):
    """Base error for gpg operations."""


class GpgUnavailableError(GpgError):
    """Raised when the gpg binary cannot be located (fail closed)."""


@dataclass(frozen=True)
class SignatureResult:
    """Outcome of verifying a detached signature."""

    good: bool
    fingerprint: Optional[str]
    summary: str


def _resolve_gpg(gpg_binary: Optional[str]) -> str:
    """Locate the gpg executable or raise GpgUnavailableError.

    Args:
        gpg_binary: Explicit path/name to use, or None to search PATH.

    Returns:
        str: A usable gpg executable path.

    Raises:
        GpgUnavailableError: If no usable gpg binary is found.
    """
    if gpg_binary:
        resolved = shutil.which(gpg_binary) or (
            gpg_binary if os.path.isfile(gpg_binary) and os.access(gpg_binary, os.X_OK) else None
        )
    else:
        resolved = shutil.which("gpg")
    if not resolved:
        raise GpgUnavailableError(
            "gpg binary not found; cannot sign or verify (install gnupg)."
        )
    return resolved


def _run(
    args: List[str], home: Optional[Path], stdin: Optional[bytes]
) -> subprocess.CompletedProcess:
    """Run gpg with an isolated, non-interactive environment.

    Args:
        args: Full argument list beginning with the gpg executable.
        home: GNUPGHOME to use, or None for the caller's default.
        stdin: Optional bytes to pass on standard input.

    Returns:
        subprocess.CompletedProcess: The completed process (not checked here).
    """
    env = {"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"}
    if home is not None:
        env["GNUPGHOME"] = str(home)
    return subprocess.run(  # nosec B603 - explicit arg list, no shell, trusted binary
        args, input=stdin, capture_output=True, env=env, check=False
    )


def detached_sign(
    data: bytes,
    key_fingerprint: str,
    *,
    home: Optional[Path] = None,
    passphrase: Optional[str] = None,
    gpg_binary: Optional[str] = None,
) -> bytes:
    """Produce an ASCII-armored detached signature over ``data``.

    Args:
        data: The bytes to sign (typically the canonical manifest).
        key_fingerprint: Fingerprint of the signing key (``--local-user``).
        home: GNUPGHOME holding the private key (None = default keyring).
        passphrase: Optional passphrase, supplied via loopback pinentry. If None,
            signing relies on gpg-agent / an unprotected key.
        gpg_binary: Override the gpg executable (mainly for tests).

    Returns:
        bytes: The armored detached signature (the ``.asc`` contents).

    Raises:
        GpgUnavailableError: If gpg is not available.
        GpgError: If signing fails.
    """
    gpg = _resolve_gpg(gpg_binary)

    with tempfile.TemporaryDirectory() as td:
        data_file = Path(td) / "data"
        data_file.write_bytes(data)
        args = [
            gpg, "--batch", "--yes", "--armor", "--detach-sign",
            "--local-user", key_fingerprint, "--output", "-",
        ]
        stdin: Optional[bytes] = None
        if passphrase is not None:
            # Data comes from a file, so stdin is free to carry the passphrase.
            args[1:1] = ["--pinentry-mode", "loopback", "--passphrase-fd", "0"]
            stdin = passphrase.encode("utf-8")
        args.append(str(data_file))
        result = _run(args, home, stdin)

    if result.returncode != 0:
        raise GpgError(f"gpg signing failed: {result.stderr.decode('utf-8', 'replace').strip()}")
    return result.stdout


def export_public_key(
    key_fingerprint: str,
    *,
    home: Optional[Path] = None,
    gpg_binary: Optional[str] = None,
) -> bytes:
    """Export the ASCII-armored public key for ``key_fingerprint`` from a keyring.

    Lets a signature-validity check verify an existing detached signature against
    the very key that will (re)sign the manifest, so the check works with any
    keyring -- the project key or an ephemeral test key -- without needing a
    separate public-key file on disk.

    Args:
        key_fingerprint: Fingerprint of the key to export.
        home: GNUPGHOME holding the key (None = caller's default keyring).
        gpg_binary: Override the gpg executable (mainly for tests).

    Returns:
        bytes: The armored public key.

    Raises:
        GpgUnavailableError: If gpg is not available (fail closed).
        GpgError: If the key cannot be exported.
    """
    gpg = _resolve_gpg(gpg_binary)
    result = _run([gpg, "--batch", "--armor", "--export", key_fingerprint], home, None)
    if result.returncode != 0 or not result.stdout:
        raise GpgError(
            f"could not export public key {key_fingerprint}: "
            f"{result.stderr.decode('utf-8', 'replace').strip()}"
        )
    return result.stdout


def verify_detached(
    data: bytes,
    signature: bytes,
    *,
    public_key: bytes,
    expected_fingerprint: Optional[str] = None,
    gpg_binary: Optional[str] = None,
) -> SignatureResult:
    """Verify a detached signature over ``data`` against a specific public key.

    Verification runs in a throwaway GNUPGHOME containing only ``public_key`` so it
    does not depend on (or pollute) the operator's keyring, and so the reported
    signing fingerprint is unambiguous.

    Args:
        data: The signed bytes (the manifest).
        signature: The detached signature bytes.
        public_key: ASCII-armored public key to verify against.
        expected_fingerprint: If given, the signing fingerprint must match this
            (case-insensitive, suffix match tolerant of 40/16-char forms) or the
            result is reported as not good.
        gpg_binary: Override the gpg executable (mainly for tests).

    Returns:
        SignatureResult: good flag, signing fingerprint (if any), and a summary.

    Raises:
        GpgUnavailableError: If gpg is not available (fail closed).
    """
    gpg = _resolve_gpg(gpg_binary)

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        home = tmp / "gnupg"
        home.mkdir(mode=0o700)
        data_file = tmp / "data"
        sig_file = tmp / "data.asc"
        data_file.write_bytes(data)
        sig_file.write_bytes(signature)

        imp = _run([gpg, "--batch", "--import"], home, public_key)
        if imp.returncode != 0:
            return SignatureResult(
                False, None, "could not import public key for verification"
            )

        result = _run(
            [gpg, "--batch", "--status-fd", "1", "--verify", str(sig_file), str(data_file)],
            home,
            None,
        )
        status = result.stdout.decode("utf-8", "replace")

        fingerprint = None
        good_sig = False
        for line in status.splitlines():
            if line.startswith("[GNUPG:] VALIDSIG"):
                parts = line.split()
                if len(parts) >= 3:
                    fingerprint = parts[2]
                good_sig = True
            elif line.startswith("[GNUPG:] GOODSIG"):
                good_sig = good_sig or True

        if not good_sig:
            return SignatureResult(False, fingerprint, "signature is not valid")

        if expected_fingerprint is not None:
            exp = expected_fingerprint.replace(" ", "").upper()
            got = (fingerprint or "").upper()
            if not (got == exp or got.endswith(exp) or exp.endswith(got)):
                return SignatureResult(
                    False, fingerprint, f"signing key {got} != expected {exp}"
                )

        return SignatureResult(True, fingerprint, "signature valid")
