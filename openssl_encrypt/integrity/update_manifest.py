#!/usr/bin/env python3
"""
Generate, sign and drift-check the source-integrity manifest.

This is the module the local pre-commit hook invokes
(``python -m openssl_encrypt.integrity.update_manifest --sign``). It rebuilds the
canonical manifest from the allowlist, optionally produces a detached PGP signature
with the project signing key, and can stage both artifacts for the commit.

Per decision D3 the private key lives only on the developer's machine; this module
never embeds or transmits it -- it merely calls the local gpg.
"""

import argparse
import json
import os
import subprocess  # nosec B404 - git is invoked with an argument list, never a shell
import sys
from pathlib import Path
from typing import List, Optional

from .allowlist import default_allowlist_path, load_allowlist
from .gpg_runner import GpgError, GpgUnavailableError, detached_sign
from .manifest_core import build_manifest, serialize_manifest
from .verify_cli import (
    default_fingerprint,
    default_manifest_path,
    default_repo_root,
    default_signature_path,
)


def generate_manifest(
    repo_root: Path,
    *,
    allowlist_path: Optional[Path] = None,
    key_fingerprint: str = "",
    manifest_path: Optional[Path] = None,
    signature_path: Optional[Path] = None,
    sign: bool = False,
    home: Optional[Path] = None,
    passphrase: Optional[str] = None,
    gpg_binary: Optional[str] = None,
    write: bool = True,
) -> bytes:
    """Build (and optionally sign) the manifest, returning its canonical bytes.

    Args:
        repo_root: Repository root the allowlist paths are relative to.
        allowlist_path: Allowlist file (default: shipped allowlist).
        key_fingerprint: Fingerprint recorded in the manifest and used to sign.
        manifest_path: Where to write the manifest (default: shipped manifest).
        signature_path: Where to write the signature (default: shipped signature).
        sign: If True, produce a detached signature alongside the manifest.
        home: GNUPGHOME holding the signing key (None = default keyring).
        passphrase: Optional signing-key passphrase (loopback pinentry).
        gpg_binary: Override the gpg executable (mainly for tests).
        write: If False, do not touch disk (return bytes only).

    Returns:
        bytes: The canonical serialized manifest.

    Raises:
        GpgUnavailableError / GpgError: If signing is requested but fails.
    """
    allowlist_path = allowlist_path or default_allowlist_path()
    manifest_path = manifest_path or default_manifest_path()
    signature_path = signature_path or default_signature_path()

    entries = load_allowlist(allowlist_path)
    manifest = build_manifest(repo_root, entries, key_fingerprint=key_fingerprint)
    blob = serialize_manifest(manifest)

    if write:
        Path(manifest_path).parent.mkdir(parents=True, exist_ok=True)
        Path(manifest_path).write_bytes(blob)

    if sign:
        signature = detached_sign(
            blob, key_fingerprint, home=home, passphrase=passphrase, gpg_binary=gpg_binary
        )
        if write:
            Path(signature_path).write_bytes(signature)

    return blob


def check_manifest(
    repo_root: Path,
    *,
    allowlist_path: Optional[Path] = None,
    manifest_path: Optional[Path] = None,
) -> bool:
    """Return True iff the on-disk manifest matches a freshly generated one.

    The on-disk manifest's recorded key fingerprint is reused so the comparison
    reflects only file-content / allowlist drift, not a fingerprint difference.

    Args:
        repo_root: Repository root the allowlist paths are relative to.
        allowlist_path: Allowlist file (default: shipped allowlist).
        manifest_path: Manifest to check (default: shipped manifest).

    Returns:
        bool: True if current, False if absent, unparseable, or drifted.
    """
    allowlist_path = allowlist_path or default_allowlist_path()
    manifest_path = manifest_path or default_manifest_path()

    on_disk = Path(manifest_path)
    if not on_disk.is_file():
        return False
    on_disk_bytes = on_disk.read_bytes()
    try:
        parsed = json.loads(on_disk_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False

    entries = load_allowlist(allowlist_path)
    fresh = serialize_manifest(
        build_manifest(repo_root, entries, key_fingerprint=parsed.get("key_fingerprint", ""))
    )
    return fresh == on_disk_bytes


def sync_manifest(
    repo_root: Path,
    *,
    key_fingerprint: str,
    sign: bool,
    allowlist_path: Optional[Path] = None,
    manifest_path: Optional[Path] = None,
    signature_path: Optional[Path] = None,
    home: Optional[Path] = None,
    passphrase: Optional[str] = None,
    gpg_binary: Optional[str] = None,
) -> bool:
    """Regenerate (and sign) the manifest only when it would actually change.

    Signatures are non-deterministic, so blindly re-signing on every commit would
    churn the ``.asc`` even when nothing changed. This compares freshly computed
    manifest bytes against the on-disk manifest and only rewrites/re-signs when the
    content differs or the signature is missing.

    Args:
        repo_root: Repository root the allowlist paths are relative to.
        key_fingerprint: Fingerprint recorded in the manifest and used to sign.
        sign: Whether a detached signature should be produced.
        allowlist_path: Allowlist file (default: shipped allowlist).
        manifest_path: Manifest path (default: shipped manifest).
        signature_path: Signature path (default: shipped signature).
        home: GNUPGHOME holding the signing key.
        passphrase: Optional signing-key passphrase.
        gpg_binary: Override the gpg executable (mainly for tests).

    Returns:
        bool: True if the manifest/signature were (re)written, False if unchanged.
    """
    manifest_path = manifest_path or default_manifest_path()
    signature_path = signature_path or default_signature_path()

    fresh = generate_manifest(
        repo_root,
        allowlist_path=allowlist_path,
        key_fingerprint=key_fingerprint,
        manifest_path=manifest_path,
        signature_path=signature_path,
        write=False,
    )
    unchanged = Path(manifest_path).is_file() and Path(manifest_path).read_bytes() == fresh
    signature_present = Path(signature_path).is_file()
    if unchanged and (signature_present or not sign):
        return False

    generate_manifest(
        repo_root,
        allowlist_path=allowlist_path,
        key_fingerprint=key_fingerprint,
        manifest_path=manifest_path,
        signature_path=signature_path,
        sign=sign,
        home=home,
        passphrase=passphrase,
        gpg_binary=gpg_binary,
        write=True,
    )
    return True


def _git_add(paths: List[Path], repo_root: Path) -> None:
    """Stage the given paths so the regenerated manifest is part of the commit.

    Failures are reported but do not raise: staging is a convenience for the hook.

    Args:
        paths: Files to stage.
        repo_root: Repository root to run git in.
    """
    existing = [str(p) for p in paths if Path(p).exists()]
    if not existing:
        return
    try:
        subprocess.run(  # nosec B603 B607 - fixed argv, no shell, trusted git
            ["git", "-C", str(repo_root), "add", *existing],
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        print(f"warning: could not stage manifest ({exc})", file=sys.stderr)


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry for the pre-commit hook and manual regeneration.

    Args:
        argv: Argument list (defaults to sys.argv[1:]).

    Returns:
        int: 0 on success; non-zero on signing failure or, in --check mode, drift.
    """
    parser = argparse.ArgumentParser(
        prog="openssl-encrypt-update-manifest",
        description="Generate/sign or check the source-integrity manifest.",
    )
    parser.add_argument("--sign", action="store_true", help="Produce a detached signature")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify the committed manifest matches the tree (no write); exit 1 on drift",
    )
    parser.add_argument("--key", help="Signing key fingerprint (default: keys/FINGERPRINT)")
    parser.add_argument("--repo-root", help="Repository root (default: package root)")
    parser.add_argument(
        "--git-add", action="store_true", help="Stage manifest + signature after writing"
    )
    parser.add_argument(
        "--passphrase-env",
        metavar="VAR",
        help="Read the signing passphrase from this environment variable",
    )
    parser.add_argument("--gpg-binary", help="Override the gpg executable")
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root) if args.repo_root else default_repo_root()

    if args.check:
        if check_manifest(repo_root):
            print("Integrity manifest is up to date.", file=sys.stderr)
            return 0
        print(
            "ERROR: integrity manifest is out of date or missing; "
            "regenerate with: python -m openssl_encrypt.integrity.update_manifest --sign",
            file=sys.stderr,
        )
        return 1

    fingerprint = args.key or default_fingerprint()
    if args.sign and not fingerprint:
        print(
            "ERROR: no signing key fingerprint (set --key or keys/FINGERPRINT).",
            file=sys.stderr,
        )
        return 1

    passphrase = os.environ.get(args.passphrase_env) if args.passphrase_env else None

    try:
        changed = sync_manifest(
            repo_root,
            key_fingerprint=fingerprint or "",
            sign=args.sign,
            passphrase=passphrase,
            gpg_binary=args.gpg_binary,
        )
    except (GpgUnavailableError, GpgError) as exc:
        print(f"ERROR: signing failed: {exc}", file=sys.stderr)
        return 1

    if not changed:
        print("Integrity manifest already up to date.", file=sys.stderr)
        return 0

    if args.git_add:
        _git_add([default_manifest_path(), default_signature_path()], repo_root)

    print(
        "Integrity manifest regenerated" + (" and signed." if args.sign else "."),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
