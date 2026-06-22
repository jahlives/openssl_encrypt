#!/usr/bin/env python3
"""
Construction and canonical serialization of the integrity manifest.

The manifest records a SHA-512 hash of every protected file. It is built to be
*reproducible*: given an identical working tree and allowlist, the serialized
bytes are always identical (sorted keys, fixed indentation, trailing newline, no
timestamps or commit identifiers). This lets a verifier independently regenerate
the manifest and byte-compare it against the signed copy.

Security properties enforced here:
- protected paths must resolve to a regular file inside the repo root,
- symlinked entries are rejected (links are never followed),
- a path that resolves outside the repo root is rejected,
- a missing protected file is a hard error (fail closed).
"""

import hashlib
import json
from pathlib import Path
from typing import Dict, Iterable

#: Hash algorithm used for per-file digests (decision Q2).
HASH_ALGORITHM = "sha512"

#: Manifest schema version. Bump on any incompatible structural change.
SCHEMA_VERSION = 1

#: Read files in 1 MiB chunks so large inputs do not load fully into memory.
_CHUNK_SIZE = 1024 * 1024


class ManifestError(Exception):
    """Raised when a manifest cannot be built from the working tree."""


def hash_file(path: Path) -> str:
    """Compute the SHA-512 hex digest of a file's bytes.

    Args:
        path: Path to the file to hash.

    Returns:
        str: Lower-case hex digest (128 characters for SHA-512).
    """
    digest = hashlib.new(HASH_ALGORITHM)
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_target(repo_root: Path, entry: str) -> Path:
    """Resolve a protected entry to an absolute path, enforcing safety.

    Args:
        repo_root: Absolute path to the repository root.
        entry: Repo-relative path from the allowlist.

    Returns:
        Path: The validated absolute path to hash.

    Raises:
        ManifestError: If the entry is a symlink, is missing, is not a regular
            file, or resolves outside the repo root.
    """
    target = repo_root / entry
    if target.is_symlink():
        raise ManifestError(f"Protected entry is a symlink (not allowed): {entry}")

    resolved = target.resolve()
    try:
        resolved.relative_to(repo_root)
    except ValueError:
        raise ManifestError(f"Protected entry resolves outside the repo root: {entry}")

    if not resolved.is_file():
        raise ManifestError(f"Protected file is missing or not a regular file: {entry}")
    return resolved


def build_manifest(
    repo_root: Path,
    entries: Iterable[str],
    key_fingerprint: str = "",
) -> Dict[str, object]:
    """Build the integrity manifest for the given allowlist entries.

    Args:
        repo_root: Path to the repository root that ``entries`` are relative to.
        entries: Iterable of repo-relative protected paths.
        key_fingerprint: Expected signing-key fingerprint to record in the
            manifest (informational; empty during early bootstrap).

    Returns:
        Dict[str, object]: The manifest mapping (not yet serialized).

    Raises:
        ManifestError: If any protected entry fails validation (see ``_safe_target``).
    """
    root = Path(repo_root).resolve()
    files: Dict[str, str] = {}
    for entry in entries:
        target = _safe_target(root, entry)
        files[entry] = f"{HASH_ALGORITHM}:{hash_file(target)}"

    return {
        "schema_version": SCHEMA_VERSION,
        "hash_algorithm": HASH_ALGORITHM,
        "key_fingerprint": key_fingerprint,
        "files": files,
    }


def serialize_manifest(manifest: Dict[str, object]) -> bytes:
    """Serialize a manifest to canonical, reproducible UTF-8 bytes.

    Keys are sorted, indentation is fixed at two spaces, and the output ends with
    exactly one newline. ``ensure_ascii`` is enabled so the byte representation is
    stable across environments.

    Args:
        manifest: The manifest mapping to serialize.

    Returns:
        bytes: Canonical UTF-8 encoding of the manifest.
    """
    text = json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=True)
    return (text + "\n").encode("utf-8")
