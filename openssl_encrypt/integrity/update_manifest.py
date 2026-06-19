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

from .allowlist import default_allowlist_path, filter_installable, load_allowlist
from .gpg_runner import (
    GpgError,
    GpgUnavailableError,
    detached_sign,
    export_public_key,
    verify_detached,
)
from .manifest_core import build_manifest, serialize_manifest
from .verify_cli import (
    default_fingerprint,
    default_installed_manifest_path,
    default_installed_signature_path,
    default_manifest_path,
    default_pubkey_path,
    default_repo_root,
    default_signature_path,
)


def generate_manifest(
    repo_root: Path,
    *,
    allowlist_path: Optional[Path] = None,
    entries: Optional[List[str]] = None,
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
        allowlist_path: Allowlist file (default: shipped allowlist). Ignored when
            ``entries`` is given.
        entries: Explicit list of protected paths to use instead of loading the
            allowlist (used to build the installed-scope subset manifest).
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
    manifest_path = manifest_path or default_manifest_path()
    signature_path = signature_path or default_signature_path()

    if entries is None:
        entries = load_allowlist(allowlist_path or default_allowlist_path())
    manifest = build_manifest(repo_root, entries, key_fingerprint=key_fingerprint)
    blob = serialize_manifest(manifest)

    # Sign BEFORE writing so a signing failure leaves the existing manifest and
    # signature untouched. Writing the manifest first (then signing) could leave a
    # rewritten manifest paired with a stale .asc -- the exact state that let a
    # content-current manifest ship with a signature that no longer verified.
    signature = None
    if sign:
        signature = detached_sign(
            blob, key_fingerprint, home=home, passphrase=passphrase, gpg_binary=gpg_binary
        )

    if write:
        Path(manifest_path).parent.mkdir(parents=True, exist_ok=True)
        Path(manifest_path).write_bytes(blob)
        if signature is not None:
            Path(signature_path).write_bytes(signature)

    return blob


def _signature_valid(
    manifest_bytes: bytes,
    signature_path: Path,
    *,
    key_fingerprint: str = "",
    public_key: Optional[bytes] = None,
    expected_fingerprint: Optional[str] = None,
    home: Optional[Path] = None,
    gpg_binary: Optional[str] = None,
) -> bool:
    """Return True iff ``signature_path`` is a valid signature over ``manifest_bytes``.

    Fails closed: a missing signature, unavailable gpg, unexportable key, or any
    verification error all return False, so callers re-sign / report drift rather
    than trusting an unverified signature. ``public_key`` may be supplied directly;
    otherwise it is exported from ``home`` for ``key_fingerprint`` so the signature
    is checked against the key that produced (or will reproduce) it.

    Args:
        manifest_bytes: Canonical manifest the signature must cover.
        signature_path: Path to the detached ``.asc`` signature.
        key_fingerprint: Fingerprint to export the public key for (when
            ``public_key`` is not given) and the default expected signer.
        public_key: Armored public key to verify against (optional).
        expected_fingerprint: Required signing fingerprint (default: key_fingerprint).
        home: GNUPGHOME holding the key when exporting the public key.
        gpg_binary: Override the gpg executable (mainly for tests).

    Returns:
        bool: True only if the signature verifies and matches the expected key.
    """
    sig = Path(signature_path)
    if not sig.is_file():
        return False
    try:
        if public_key is None:
            public_key = export_public_key(key_fingerprint, home=home, gpg_binary=gpg_binary)
        result = verify_detached(
            manifest_bytes,
            sig.read_bytes(),
            public_key=public_key,
            expected_fingerprint=expected_fingerprint or key_fingerprint or None,
            gpg_binary=gpg_binary,
        )
    except GpgError:
        return False
    return result.good


def check_manifest(
    repo_root: Path,
    *,
    allowlist_path: Optional[Path] = None,
    manifest_path: Optional[Path] = None,
    signature_path: Optional[Path] = None,
    pubkey_path: Optional[Path] = None,
    expected_fingerprint: Optional[str] = None,
    verify_signature: bool = True,
    gpg_binary: Optional[str] = None,
) -> bool:
    """Return True iff the on-disk manifest matches the tree AND is validly signed.

    The on-disk manifest's recorded key fingerprint is reused for the content
    comparison so it reflects only file-content / allowlist drift, not a fingerprint
    difference. When ``verify_signature`` is True (the default) the detached
    signature must also verify against the manifest; a missing or invalid signature
    is treated as drift. This closes the gap where a content-current manifest could
    pass ``--check`` while its ``.asc`` no longer matched the contents. Signature
    verification fails closed when gpg is unavailable (consistent with the runtime
    verifier); pass ``verify_signature=False`` to check content drift only.

    Args:
        repo_root: Repository root the allowlist paths are relative to.
        allowlist_path: Allowlist file (default: shipped allowlist).
        manifest_path: Manifest to check (default: shipped manifest).
        signature_path: Detached signature (default: shipped signature).
        pubkey_path: Public key to verify against (default: bundled public key).
        expected_fingerprint: Required signing fingerprint (default: keys/FINGERPRINT).
        verify_signature: Also require a valid detached signature (default: True).
        gpg_binary: Override the gpg executable (mainly for tests).

    Returns:
        bool: True if current and (when requested) validly signed; False otherwise.
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
    if fresh != on_disk_bytes:
        return False

    if not verify_signature:
        return True

    signature_path = signature_path or default_signature_path()
    pubkey_path = pubkey_path or default_pubkey_path()
    if expected_fingerprint is None:
        expected_fingerprint = default_fingerprint()
    pub = Path(pubkey_path)
    if not pub.is_file():
        return False
    return _signature_valid(
        on_disk_bytes,
        Path(signature_path),
        public_key=pub.read_bytes(),
        expected_fingerprint=expected_fingerprint,
        gpg_binary=gpg_binary,
    )


def sync_manifest(
    repo_root: Path,
    *,
    key_fingerprint: str,
    sign: bool,
    allowlist_path: Optional[Path] = None,
    entries: Optional[List[str]] = None,
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
        entries=entries,
        key_fingerprint=key_fingerprint,
        manifest_path=manifest_path,
        signature_path=signature_path,
        write=False,
    )
    unchanged = Path(manifest_path).is_file() and Path(manifest_path).read_bytes() == fresh
    if unchanged:
        if not sign:
            return False
        # Content matches; skip re-signing ONLY when the existing signature actually
        # verifies against it. A present-but-stale/invalid .asc (e.g. left behind by
        # an earlier failed signing run) must trigger a re-sign, not a false
        # "already up to date".
        if _signature_valid(
            fresh,
            Path(signature_path),
            key_fingerprint=key_fingerprint,
            home=home,
            gpg_binary=gpg_binary,
        ):
            return False

    generate_manifest(
        repo_root,
        allowlist_path=allowlist_path,
        entries=entries,
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


def sync_all_manifests(
    repo_root: Path,
    *,
    key_fingerprint: str,
    sign: bool,
    allowlist_path: Optional[Path] = None,
    manifest_path: Optional[Path] = None,
    signature_path: Optional[Path] = None,
    installed_manifest_path: Optional[Path] = None,
    installed_signature_path: Optional[Path] = None,
    home: Optional[Path] = None,
    passphrase: Optional[str] = None,
    gpg_binary: Optional[str] = None,
) -> bool:
    """Sync both the full source manifest and the installed-scope subset manifest.

    The source manifest covers every allowlisted file; the installed manifest covers
    only the subset that survives installation (``filter_installable``). Each is
    synced idempotently (re-signed only when its content changed).

    Args:
        repo_root: Repository root the allowlist paths are relative to.
        key_fingerprint: Fingerprint recorded in the manifests and used to sign.
        sign: Whether detached signatures should be produced.
        allowlist_path: Allowlist file (default: shipped allowlist).
        manifest_path / signature_path: Source manifest paths (default: shipped).
        installed_manifest_path / installed_signature_path: Installed manifest paths
            (default: shipped).
        home: GNUPGHOME holding the signing key.
        passphrase: Optional signing-key passphrase.
        gpg_binary: Override the gpg executable (mainly for tests).

    Returns:
        bool: True if either manifest was (re)written.
    """
    entries = load_allowlist(allowlist_path or default_allowlist_path())
    common = dict(
        repo_root=repo_root,
        key_fingerprint=key_fingerprint,
        sign=sign,
        home=home,
        passphrase=passphrase,
        gpg_binary=gpg_binary,
    )
    changed = sync_manifest(
        entries=entries,
        manifest_path=manifest_path or default_manifest_path(),
        signature_path=signature_path or default_signature_path(),
        **common,
    )
    changed_installed = sync_manifest(
        entries=filter_installable(entries),
        manifest_path=installed_manifest_path or default_installed_manifest_path(),
        signature_path=installed_signature_path or default_installed_signature_path(),
        **common,
    )
    return changed or changed_installed


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
        changed = sync_all_manifests(
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
        print("Integrity manifests already up to date.", file=sys.stderr)
        return 0

    if args.git_add:
        _git_add(
            [
                default_manifest_path(),
                default_signature_path(),
                default_installed_manifest_path(),
                default_installed_signature_path(),
            ],
            repo_root,
        )

    print(
        "Integrity manifests regenerated" + (" and signed." if args.sign else "."),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
