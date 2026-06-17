#!/usr/bin/env python3
"""
File-hash comparison of the working tree against an integrity manifest.

This module performs only the *content* check: it re-hashes each protected file
and compares it to the manifest. Signature verification of the manifest itself is
handled separately (see gpg_runner / the verify-integrity CLI command), and the
overarching trust caveat applies (see the package docstring).
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from .manifest_core import HASH_ALGORITHM, hash_file

#: Per-file verification states.
OK = "OK"
MODIFIED = "MODIFIED"
MISSING = "MISSING"


class VerifyError(Exception):
    """Raised when a manifest cannot be processed (e.g. unsupported algorithm)."""


@dataclass(frozen=True)
class FileStatus:
    """Result for a single protected file."""

    path: str
    status: str


@dataclass(frozen=True)
class VerifyResult:
    """Aggregate result of comparing a tree against a manifest."""

    statuses: List[FileStatus]

    @property
    def problems(self) -> List[FileStatus]:
        """Return the entries whose status is not OK."""
        return [s for s in self.statuses if s.status != OK]

    @property
    def all_ok(self) -> bool:
        """True only when every protected file verified as OK."""
        return not self.problems


def verify_files(repo_root: Path, manifest: Dict[str, object]) -> VerifyResult:
    """Compare every file listed in ``manifest`` against the working tree.

    Args:
        repo_root: Repository root the manifest paths are relative to.
        manifest: A parsed manifest mapping (see manifest_core.build_manifest).

    Returns:
        VerifyResult: Per-file statuses (OK / MODIFIED / MISSING).

    Raises:
        VerifyError: If the manifest declares a hash algorithm this build does
            not support (fail closed rather than skip the check).
    """
    algorithm = manifest.get("hash_algorithm")
    if algorithm != HASH_ALGORITHM:
        raise VerifyError(
            f"Unsupported manifest hash algorithm {algorithm!r}; "
            f"this build only supports {HASH_ALGORITHM!r}"
        )

    root = Path(repo_root).resolve()
    files: Dict[str, str] = dict(manifest.get("files", {}))  # type: ignore[arg-type]

    statuses: List[FileStatus] = []
    for path, expected in sorted(files.items()):
        target = root / path
        # A symlink or non-regular file is never trusted: treat as MISSING.
        if target.is_symlink() or not target.is_file():
            statuses.append(FileStatus(path, MISSING))
            continue

        resolved = target.resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            statuses.append(FileStatus(path, MISSING))
            continue

        actual = f"{algorithm}:{hash_file(target)}"
        statuses.append(FileStatus(path, OK if actual == expected else MODIFIED))

    return VerifyResult(statuses)
