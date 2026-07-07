"""Signed per-package plugin manifest (H2 [PLUGIN-1]).

Signing/verifying only a package's ``__init__.py`` is insufficient: importing
``__init__`` transitively imports sibling modules that are never
signature-checked, AST-scanned, or hash-pinned. A signed manifest closes that
gap by covering **every importable module** under the package — source
(``.py``), bytecode (``.pyc``) and native extensions (``.so``/``.pyd``/...),
recursively, including underscore-prefixed and nested subpackages — with one
signature. (Only source modules can be AST-scanned; native/bytecode are covered
by hash + signature.) Non-executable data resources are out of scope.

Artifacts (both live inside the package directory):
- ``PLUGIN.manifest``     — canonical text listing ``sha256  relpath`` for each
  importable module in the package, sorted by relpath.
- ``PLUGIN.manifest.asc`` — a detached signature over the manifest bytes,
  verified with the existing plugin trust anchors.

A package verifies iff the manifest signature is good AND the on-disk importable
-module set matches the manifest exactly (no unlisted/extra module, no missing
listed module, every hash matches). The manifest guarantees "only vouched-for
bytes are imported", NOT "vouched-for bytes are benign" — the AST denylist and
the runtime sandbox remain the backstop for what verified code may do.
"""

import hashlib
import importlib.machinery as _machinery
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from .plugin_signature import signature_path_for, verify_plugin_signature

# The manifest file and its detached signature live in the package directory.
MANIFEST_FILENAME = "PLUGIN.manifest"
# Canonical header pinning the format; changing it invalidates every signature.
MANIFEST_HEADER = "# oesc-plugin-manifest v1"

# Every file the import machinery can load as a module MUST be covered, not just
# ``.py`` source: an unsigned ``.so``/``.pyd`` extension or ``.pyc`` bytecode
# sibling is an execution vector too (crypto-reviewer H2 finding 1). Source
# suffixes are AST-scanned; native/bytecode are hash+signature covered only.
_SOURCE_SUFFIXES = tuple(_machinery.SOURCE_SUFFIXES)  # ('.py',)
_MODULE_SUFFIXES = tuple(
    _machinery.SOURCE_SUFFIXES + _machinery.BYTECODE_SUFFIXES + _machinery.EXTENSION_SUFFIXES
)


class ManifestError(Exception):
    """A package tree cannot be safely enumerated/manifested (fail closed)."""


def is_source_module(path: str) -> bool:
    """True if ``path`` is a Python source module (``.py``) — the only kind we
    can AST-scan. Native/bytecode modules are covered by hash only."""
    return path.endswith(_SOURCE_SUFFIXES)


@dataclass(frozen=True)
class ManifestVerdict:
    """Outcome of verifying a package against its signed manifest."""

    verified: bool
    reason: str
    # Realpaths of every importable module covered by a verified manifest
    # (used to scope the import hook so only these files may be imported).
    verified_paths: Set[str]


def manifest_path_for(package_dir: str) -> str:
    """Path to the ``PLUGIN.manifest`` inside ``package_dir``."""
    return os.path.join(package_dir, MANIFEST_FILENAME)


def _iter_module_files(package_dir: str) -> List[Tuple[str, str]]:
    """Return ``(relpath, real_path)`` for every importable module file under
    ``package_dir`` (recursive): source (``.py``), bytecode (``.pyc``) and native
    extensions (``.so``/``.pyd``/...).

    Fail closed (raise ``ManifestError``) rather than silently skipping, so a
    crafted tree can never verify with hidden/uncovered modules:
    - any symlinked module file (a symlink is not a vouched-for shipped byte
      sequence and can be repointed) — rejected;
    - a module whose realpath escapes the package root — rejected;
    - a filename containing a newline (would break the line-based manifest) —
      rejected;
    - two entries resolving to the same realpath — rejected.
    """
    root = os.path.realpath(package_dir)
    root_prefix = root + os.sep
    out: List[Tuple[str, str]] = []
    seen_real: Set[str] = set()
    # followlinks=False: symlinked SUBDIRECTORIES are not descended. Replacing
    # a listed subdir with a symlink surfaces its modules as "missing on disk";
    # a brand-new symlinked subdir yields only modules unreferenced by the
    # hash-pinned __init__.py, so it is not an execution vector.
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in sorted(filenames):
            if not name.endswith(_MODULE_SUFFIXES):
                continue
            on_disk = os.path.join(dirpath, name)
            if os.path.islink(on_disk):
                raise ManifestError(f"symlinked module file not allowed: {on_disk}")
            real = os.path.realpath(on_disk)
            if real != root and not real.startswith(root_prefix):
                raise ManifestError(f"module file escapes package root: {on_disk}")
            rel = _relpath(real, root)
            if "\n" in rel or "\r" in rel:
                raise ManifestError(f"newline in module path: {rel!r}")
            if real in seen_real:
                raise ManifestError(f"duplicate module realpath: {real}")
            seen_real.add(real)
            out.append((rel, real))
    return out


def _relpath(real: str, root: str) -> str:
    """POSIX-normalized relative path (canonical key)."""
    return os.path.relpath(real, root).replace(os.sep, "/")


def _sha256_file(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def build_manifest(package_dir: str) -> bytes:
    """Build the canonical manifest bytes for ``package_dir``.

    Deterministic and reproducible: header line, then ``sha256  relpath`` lines
    sorted by relpath, LF-separated, trailing LF. Signing and verifying both
    serialize identically, so the signature covers exact bytes.
    """
    root = os.path.realpath(package_dir)
    entries = [(rel, _sha256_file(real)) for rel, real in _iter_module_files(root)]
    entries.sort()  # by relpath (then digest); stable canonical order
    lines = [MANIFEST_HEADER]
    lines.extend(f"{digest}  {rel}" for rel, digest in entries)
    return ("\n".join(lines) + "\n").encode("utf-8")


def parse_manifest(manifest_bytes: bytes) -> Dict[str, str]:
    """Parse manifest bytes into ``{relpath: sha256hex}``.

    Raises ValueError on a malformed header, malformed line, duplicate path,
    or a non-hex/64-length digest.
    """
    try:
        text = manifest_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"manifest is not valid UTF-8: {e}")
    lines = text.split("\n")
    if not lines or lines[0] != MANIFEST_HEADER:
        raise ValueError("missing or wrong manifest header")
    result: Dict[str, str] = {}
    for lineno, line in enumerate(lines[1:], start=2):
        if line == "":
            continue
        # Exactly "<64-hex-digest><two spaces><relpath>".
        if "  " not in line:
            raise ValueError(f"malformed line {lineno}")
        digest, rel = line.split("  ", 1)
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError(f"bad digest on line {lineno}")
        if not rel or rel.startswith("/") or ".." in rel.split("/"):
            raise ValueError(f"bad relpath on line {lineno}")
        if rel in result:
            raise ValueError(f"duplicate path on line {lineno}: {rel}")
        result[rel] = digest
    return result


def check_manifest_matches_tree(package_dir: str, manifest_bytes: bytes):
    """Check that the on-disk importable-module set matches ``manifest_bytes``
    exactly (source + bytecode + native extensions).

    Does NOT verify the signature — that is the caller's job (see
    ``verify_package_manifest``). Returns ``(ok, reason, verified_paths)``.
    Fails closed on any enumeration error (escaping/symlinked module, etc.).
    """
    root = os.path.realpath(package_dir)
    try:
        listed = parse_manifest(manifest_bytes)
    except ValueError as e:
        return False, f"malformed manifest: {e}", set()

    actual: Dict[str, str] = {}
    verified_paths: Set[str] = set()
    try:
        module_files = _iter_module_files(root)
    except ManifestError as e:
        return False, f"unsafe package tree: {e}", set()
    for rel, real in module_files:
        actual[rel] = _sha256_file(real)
        verified_paths.add(real)

    extra = sorted(set(actual) - set(listed))
    if extra:
        return False, f"unlisted file(s) present: {extra}", set()
    missing = sorted(set(listed) - set(actual))
    if missing:
        return False, f"manifest file(s) missing on disk: {missing}", set()
    for rel, digest in actual.items():
        if listed[rel] != digest:
            return False, f"hash mismatch for {rel}", set()
    return True, "manifest matches tree", verified_paths


def verify_package_manifest(
    package_dir: str,
    anchors,
    *,
    gpg_binary: Optional[str] = None,
) -> ManifestVerdict:
    """Verify a package against its signed manifest.

    Verified iff (1) ``PLUGIN.manifest`` exists, (2) ``PLUGIN.manifest.asc`` is a
    good signature over the manifest bytes by an enrolled anchor, and (3) the
    on-disk ``*.py`` tree matches the manifest exactly.
    """
    root = os.path.realpath(package_dir)
    mpath = manifest_path_for(root)
    if not os.path.isfile(mpath):
        return ManifestVerdict(False, f"no {MANIFEST_FILENAME} in package", set())
    try:
        with open(mpath, "rb") as f:
            manifest_bytes = f.read()
    except OSError as e:
        return ManifestVerdict(False, f"could not read manifest: {e}", set())

    sig_verdict = verify_plugin_signature(
        manifest_bytes, signature_path_for(mpath), anchors, gpg_binary=gpg_binary
    )
    if not sig_verdict.verified:
        return ManifestVerdict(
            False, f"manifest signature not verified: {sig_verdict.reason}", set()
        )

    ok, reason, verified_paths = check_manifest_matches_tree(root, manifest_bytes)
    if not ok:
        return ManifestVerdict(False, reason, set())
    return ManifestVerdict(True, "package manifest verified", verified_paths)
