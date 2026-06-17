#!/usr/bin/env python3
"""
Core logic for the ``openssl-encrypt verify-integrity`` command.

This module loads the signed manifest, verifies its PGP signature against the
bundled public key (via the system gpg binary), re-hashes the protected files, and
reports the result. It ALWAYS surfaces a trust warning, because a built-in verifier
cannot be its own root of trust (see the package docstring and §7 of the plan).

Exit codes (distinct per failure class):
    0  all good
    1  one or more protected files modified/missing
    2  manifest signature invalid / unexpected signing key
    3  gpg unavailable (fail closed -- never a silent pass)
    4  manifest, signature, or public key not found / malformed
"""

import json
import sys
from pathlib import Path
from typing import Optional

from . import gpg_runner
from .verify import MISSING, MODIFIED, VerifyError, verify_files

EXIT_OK = 0
EXIT_HASH_MISMATCH = 1
EXIT_BAD_SIGNATURE = 2
EXIT_GPG_UNAVAILABLE = 3
EXIT_NOT_FOUND = 4

TRUST_WARNING = (
    "WARNING: This built-in verification runs code that lives in the same package "
    "it is checking. If an attacker can modify the protected source files, they can "
    "also modify THIS verifier, the manifest, and substitute the public key -- and "
    "you would still see a PASS. A green result here is a convenience tripwire, NOT "
    "proof of integrity.\n"
    "The ONLY reliable verification is MANUAL, using a gpg binary you trust and a key "
    "fingerprint obtained OUT-OF-BAND (not from this repo):\n"
    "    gpg --verify openssl_encrypt/integrity/manifest.json.asc "
    "openssl_encrypt/integrity/manifest.json\n"
    "    sha512sum <each protected file>   # compare against the manifest yourself\n"
    "Confirm the signing-key fingerprint independently (also in SECURITY.md and "
    "docs/SOURCE_INTEGRITY.md)."
)

SHORT_WARNING = (
    "Built-in verification is a tripwire, not proof -- verify manually with gpg; "
    "see docs/SOURCE_INTEGRITY.md."
)


def _pkg_dir() -> Path:
    """Return the directory of this integrity package."""
    return Path(__file__).resolve().parent


def default_manifest_path() -> Path:
    """Path to the shipped manifest."""
    return _pkg_dir() / "manifest.json"


def default_signature_path() -> Path:
    """Path to the shipped detached signature."""
    return _pkg_dir() / "manifest.json.asc"


def default_pubkey_path() -> Path:
    """Path to the bundled public key."""
    return _pkg_dir() / "keys" / "source-integrity-pubkey.asc"


def default_fingerprint() -> Optional[str]:
    """Return the expected signing fingerprint from keys/FINGERPRINT, if present."""
    fpr_file = _pkg_dir() / "keys" / "FINGERPRINT"
    if fpr_file.is_file():
        text = fpr_file.read_text(encoding="utf-8").strip()
        return text or None
    return None


def default_repo_root() -> Path:
    """Repo root that manifest paths are relative to (parents[2] of this file)."""
    return _pkg_dir().parents[1]


def verify_integrity(
    repo_root: Optional[Path] = None,
    *,
    manifest_path: Optional[Path] = None,
    signature_path: Optional[Path] = None,
    pubkey_path: Optional[Path] = None,
    expected_fingerprint: Optional[str] = None,
    quiet: bool = False,
    as_json: bool = False,
    gpg_binary: Optional[str] = None,
) -> int:
    """Verify the signed manifest and the protected files; return an exit code.

    Output streams are fixed: the trust warning, the human-readable report and all
    error messages go to **stderr**; only the ``--json`` payload is written to
    **stdout** (so stdout stays empty/clean in the non-JSON case and parseable in the
    JSON case). Tests capture these with contextlib.redirect_stdout/redirect_stderr.

    Args:
        repo_root: Root the manifest paths are relative to (default: package root).
        manifest_path: Manifest location (default: shipped manifest).
        signature_path: Detached signature location (default: shipped signature).
        pubkey_path: Public key location (default: bundled public key).
        expected_fingerprint: Expected signing fingerprint (default: keys/FINGERPRINT).
        quiet: If True, shorten the human warning to one line.
        as_json: If True, emit a JSON report on stdout.
        gpg_binary: Override the gpg executable (mainly for tests).

    Returns:
        int: One of the EXIT_* codes.
    """
    repo_root = Path(repo_root) if repo_root is not None else default_repo_root()
    manifest_path = manifest_path or default_manifest_path()
    signature_path = signature_path or default_signature_path()
    pubkey_path = pubkey_path or default_pubkey_path()
    if expected_fingerprint is None:
        expected_fingerprint = default_fingerprint()

    # The trust warning is non-negotiable: human-readable to stderr always.
    print(SHORT_WARNING if quiet else TRUST_WARNING, file=sys.stderr)

    def _emit(payload: dict, code: int) -> int:
        payload["trust_warning"] = TRUST_WARNING
        payload["exit_code"] = code
        if as_json:
            print(json.dumps(payload, indent=2, sort_keys=True))  # JSON data -> stdout
        return code

    # Step 1: required inputs must exist and parse.
    for label, path in (
        ("manifest", manifest_path),
        ("signature", signature_path),
        ("public key", pubkey_path),
    ):
        if not Path(path).is_file():
            print(f"ERROR: {label} not found: {path}", file=sys.stderr)
            return _emit({"error": f"{label} not found"}, EXIT_NOT_FOUND)

    manifest_bytes = Path(manifest_path).read_bytes()
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"ERROR: manifest is not valid JSON: {exc}", file=sys.stderr)
        return _emit({"error": "manifest malformed"}, EXIT_NOT_FOUND)

    # Step 2: signature verification (fail closed if gpg is missing).
    sig_checked = True
    try:
        sig = gpg_runner.verify_detached(
            manifest_bytes,
            Path(signature_path).read_bytes(),
            public_key=Path(pubkey_path).read_bytes(),
            expected_fingerprint=expected_fingerprint,
            gpg_binary=gpg_binary,
        )
        sig_good, sig_fpr, sig_summary = sig.good, sig.fingerprint, sig.summary
    except gpg_runner.GpgUnavailableError as exc:
        sig_checked, sig_good, sig_fpr, sig_summary = False, False, None, str(exc)

    # Step 3: file hash comparison.
    try:
        file_result = verify_files(repo_root, manifest)
        modified = [s.path for s in file_result.statuses if s.status == MODIFIED]
        missing = [s.path for s in file_result.statuses if s.status == MISSING]
        files_ok = file_result.all_ok
    except VerifyError as exc:
        print(f"ERROR: cannot process manifest: {exc}", file=sys.stderr)
        return _emit({"error": str(exc)}, EXIT_NOT_FOUND)

    # Determine exit code: most severe failure wins.
    code = EXIT_OK
    if not files_ok:
        code = EXIT_HASH_MISMATCH
    if not sig_good:
        code = EXIT_BAD_SIGNATURE
    if not sig_checked:
        code = EXIT_GPG_UNAVAILABLE

    if not quiet and not as_json:
        # Human-readable report -> stderr (stdout stays clean for non-JSON callers).
        sig_state = "VALID" if sig_good else "NOT VALID"
        print(f"Signature: {sig_state} ({sig_summary})", file=sys.stderr)
        if sig_fpr:
            print(f"Signing key: {sig_fpr}", file=sys.stderr)
        n_files = len(manifest.get("files", {}))
        print(
            f"Files: {n_files} checked, {len(modified)} modified, {len(missing)} missing",
            file=sys.stderr,
        )
        for path in modified:
            print(f"  MODIFIED: {path}", file=sys.stderr)
        for path in missing:
            print(f"  MISSING:  {path}", file=sys.stderr)

    return _emit(
        {
            "signature": {
                "checked": sig_checked,
                "good": sig_good,
                "fingerprint": sig_fpr,
                "summary": sig_summary,
            },
            "files": {
                "checked": len(manifest.get("files", {})),
                "modified": modified,
                "missing": missing,
                "all_ok": files_ok,
            },
        },
        code,
    )
