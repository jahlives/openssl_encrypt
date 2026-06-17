#!/usr/bin/env python3
"""
Loading and validation of the protected-files allowlist.

The allowlist (``protected_files.txt``) is an explicit, version-controlled list of
the repo-relative source paths covered by the integrity manifest. An explicit list
is used rather than a glob so that adding or removing a protected file is always a
deliberate, reviewable change: a glob would silently include newly-added files or
silently drop renamed ones, either of which could mask tampering.

Security properties enforced here:
- entries must be repo-relative (absolute paths rejected),
- entries must not contain a ``..`` traversal component,
- entries must use forward-slash separators (backslashes rejected),
- an empty allowlist is an error (fail closed).
"""

from pathlib import Path
from typing import List


class AllowlistError(Exception):
    """Raised when the protected-files allowlist is missing or malformed."""


def default_allowlist_path() -> Path:
    """Return the path to the allowlist shipped inside this package.

    Returns:
        Path: Absolute path to ``protected_files.txt`` next to this module.
    """
    return Path(__file__).resolve().parent / "protected_files.txt"


def _validate_entry(entry: str, lineno: int) -> None:
    """Validate a single allowlist entry.

    Args:
        entry: The stripped path entry to validate.
        lineno: 1-based source line number, for error messages.

    Raises:
        AllowlistError: If the entry is absolute, uses backslashes, or contains
            a parent-directory (``..``) component.
    """
    if "\\" in entry:
        raise AllowlistError(
            f"Allowlist line {lineno}: backslash separators are not allowed: {entry!r}"
        )
    pure = Path(entry)
    if pure.is_absolute() or entry.startswith("/"):
        raise AllowlistError(f"Allowlist line {lineno}: absolute paths are not allowed: {entry!r}")
    if ".." in pure.parts:
        raise AllowlistError(
            f"Allowlist line {lineno}: parent-directory traversal is not allowed: {entry!r}"
        )


def load_allowlist(path: Path) -> List[str]:
    """Parse and validate the protected-files allowlist.

    Blank lines and lines beginning with ``#`` are ignored. Remaining lines are
    stripped, validated, de-duplicated and returned in sorted order so the result
    is deterministic regardless of source ordering.

    Args:
        path: Path to the allowlist file.

    Returns:
        List[str]: Sorted, de-duplicated, validated repo-relative paths.

    Raises:
        AllowlistError: If the file is missing/unreadable, contains an invalid
            entry, or yields no real entries.
    """
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AllowlistError(f"Cannot read allowlist {path}: {exc}") from exc

    entries = set()
    for lineno, line in enumerate(raw.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        _validate_entry(stripped, lineno)
        entries.add(stripped)

    if not entries:
        raise AllowlistError(f"Allowlist {path} contains no entries")

    return sorted(entries)
