"""Signature-gated plugin loading (#66 / CLI-3).

Third-party (non-built-in) plugins may be required to carry a detached PGP
signature over their exact source bytes, verified against a set of trusted
public keys before ``exec_module`` ever runs. This turns the load-time trust
decision from a denylist ("does this code look dangerous?") into an allowlist
("did someone trusted vouch for these exact bytes?").

Trust anchors are pluggable (see docs/PLUGIN_SIGNING_PLAN.md):
  * the project source-integrity key (officially distributed plugins),
  * enrolled third-party author keys (TOFU-style),
  * the operator's own key (ideally hardware-backed).

This module provides only the verification primitives and the trust-anchor
store; policy enforcement and CLI wiring live in the loader and CLI layers.

Honesty note: a valid signature means trusted bytes were loaded. It does NOT
sandbox what those bytes then do, and an on-disk signing key gives no
protection against an attacker who already executes code as the operator (they
can sign anything). A hardware-backed key protects the signing capability, not
the running process.
"""

import logging
import os
import stat
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from ...integrity.gpg_runner import GpgUnavailableError, verify_detached

logger = logging.getLogger(__name__)


class PluginSignaturePolicy(str, Enum):
    """How the loader treats plugin signatures.

    * OFF: signatures are not checked (legacy behavior; AST denylist only).
    * WARN: unsigned/unverifiable plugins load, but a warning + security-log
      event is emitted.
    * ENFORCE: unsigned/unverifiable non-built-in plugins are refused.
    """

    OFF = "off"
    WARN = "warn"
    ENFORCE = "enforce"


class TrustAnchorError(Exception):
    """Raised when the trust-anchor store itself is unsafe to use."""


@dataclass(frozen=True)
class TrustAnchor:
    """A public key trusted to vouch for plugin source.

    Attributes:
        fingerprint: Signing-key fingerprint (may be a 40- or 16-char form;
            matched suffix-tolerantly by verify_detached).
        public_key: ASCII-armored public key bytes.
        label: Human-readable origin (file name or built-in label) for logs.
    """

    fingerprint: str
    public_key: bytes
    label: str


@dataclass(frozen=True)
class PluginSignatureVerdict:
    """Outcome of verifying a plugin's detached signature."""

    verified: bool
    fingerprint: Optional[str]
    anchor_label: Optional[str]
    reason: str


# Detached-signature sidecar suffix (see design doc D3): <plugin>.py.asc
SIGNATURE_SUFFIX = ".asc"

# Only owner may write the trust-anchor store or its key files. A group/world-
# writable key file is an injected-anchor vector and is skipped; a writable
# store directory is fatal (an attacker controls the whole anchor set).
_WRITABLE_BY_OTHERS = stat.S_IWGRP | stat.S_IWOTH


class TrustAnchorStore:
    """Loads trusted plugin-signing public keys from an owner-only directory.

    Enrolled keys are ASCII-armored ``*.asc`` files. The store applies the
    same tampering-window reasoning as the plugin loader's insecure-location
    check: a group/world-writable *store directory* is refused outright, and
    an individually writable *key file* is ignored (it could have been dropped
    or rewritten by another user).
    """

    def __init__(self, directory: str, *, gpg_binary: Optional[str] = None):
        self.directory = directory
        self._gpg_binary = gpg_binary

    def load_anchors(self) -> List[TrustAnchor]:
        """Return the trust anchors enrolled in the store directory.

        Returns an empty list if the directory does not exist (no anchors
        configured is a valid state). Raises TrustAnchorError if the directory
        exists but is writable by anyone other than its owner.
        """
        directory = self.directory
        if not os.path.isdir(directory):
            return []

        if os.name != "nt":
            reason = self._posix_writable_reason(directory)
            if reason:
                raise TrustAnchorError(
                    f"Trust-anchor store {directory} is {reason}; refusing to load "
                    f"anchors from a location others can modify."
                )

        anchors: List[TrustAnchor] = []
        for name in sorted(os.listdir(directory)):
            if not name.endswith(SIGNATURE_SUFFIX):
                continue
            path = os.path.join(directory, name)
            if not os.path.isfile(path):
                continue
            if os.name != "nt":
                file_reason = self._posix_writable_reason(path)
                if file_reason:
                    logger.warning(
                        "Ignoring trust-anchor key %s: %s (only owner may write it)",
                        path,
                        file_reason,
                    )
                    continue
            try:
                pub = open(path, "rb").read()
            except OSError as e:
                logger.warning("Could not read trust-anchor key %s: %s", path, e)
                continue
            fingerprint = _fingerprint_of_public_key(pub, gpg_binary=self._gpg_binary)
            if fingerprint is None:
                logger.warning("Trust-anchor file %s is not a usable public key", path)
                continue
            anchors.append(TrustAnchor(fingerprint=fingerprint, public_key=pub, label=name))
        return anchors

    @staticmethod
    def _posix_writable_reason(path: str) -> Optional[str]:
        """Return a reason string if ``path`` is group/world-writable, else None."""
        try:
            st = os.stat(path)
        except OSError as e:
            return f"unstatable ({e})"
        if st.st_mode & _WRITABLE_BY_OTHERS:
            return f"group/world-writable (mode {oct(st.st_mode & 0o777)})"
        return None


def _fingerprint_of_public_key(public_key: bytes, *, gpg_binary: Optional[str] = None):
    """Extract the primary-key fingerprint from an armored public key, or None."""
    import subprocess
    import tempfile

    from ...integrity.gpg_runner import _resolve_gpg

    try:
        gpg = _resolve_gpg(gpg_binary)
    except GpgUnavailableError:
        return None

    with tempfile.TemporaryDirectory() as td:
        home = os.path.join(td, "gnupg")
        os.mkdir(home, 0o700)
        env = {"GNUPGHOME": home, "PATH": os.environ.get("PATH", "")}
        imp = subprocess.run(
            [gpg, "--homedir", home, "--batch", "--import"],
            input=public_key,
            capture_output=True,
            env=env,
        )
        if imp.returncode != 0:
            return None
        listing = subprocess.run(
            [gpg, "--homedir", home, "--batch", "--with-colons", "--list-keys"],
            capture_output=True,
            env=env,
            text=True,
        ).stdout
        for line in listing.splitlines():
            if line.startswith("fpr:"):
                return line.split(":")[9]
    return None


def signature_path_for(plugin_path: str) -> str:
    """Return the sidecar signature path for a plugin file (``<path>.asc``)."""
    return plugin_path + SIGNATURE_SUFFIX


# Label under which the bundled project key appears in logs/anchor lists.
PROJECT_ANCHOR_LABEL = "project-source-integrity-key"


def project_trust_anchor(*, gpg_binary: Optional[str] = None) -> Optional[TrustAnchor]:
    """Return the bundled project source-integrity key as a trust anchor (D2).

    This is the same key that signs the source-integrity manifest; enabling it
    as a default plugin-signing anchor lets officially distributed (non-built-in)
    plugins verify out of the box. Returns None if the bundled key or its
    fingerprint cannot be resolved (e.g. a stripped install), so the caller
    simply has no project anchor rather than failing.
    """
    try:
        from ...integrity.verify_cli import default_fingerprint, default_pubkey_path

        pub_path = default_pubkey_path()
        if not pub_path.is_file():
            return None
        pub = pub_path.read_bytes()
        fingerprint = default_fingerprint() or _fingerprint_of_public_key(
            pub, gpg_binary=gpg_binary
        )
        if not fingerprint:
            return None
        return TrustAnchor(fingerprint=fingerprint, public_key=pub, label=PROJECT_ANCHOR_LABEL)
    except Exception:
        return None


def verify_plugin_signature(
    plugin_bytes: bytes,
    signature_path: str,
    anchors: List[TrustAnchor],
    *,
    gpg_binary: Optional[str] = None,
) -> PluginSignatureVerdict:
    """Verify a detached signature over ``plugin_bytes`` against trust anchors.

    A verdict is ``verified`` iff the sidecar signature is a good signature,
    over exactly ``plugin_bytes``, made by one of the enrolled ``anchors``.

    Args:
        plugin_bytes: The exact source bytes that will be executed. Passing the
            already-read bytes (rather than re-reading here) keeps the verified
            bytes identical to the scanned/executed bytes.
        signature_path: Path to the detached ``.asc`` signature sidecar.
        anchors: Enrolled trust anchors to check against (any one may match).
        gpg_binary: Override the gpg executable (mainly for tests).

    Returns:
        PluginSignatureVerdict describing the outcome.
    """
    if not anchors:
        return PluginSignatureVerdict(
            False, None, None, "no trust anchors are configured for plugin signatures"
        )

    if not os.path.isfile(signature_path):
        return PluginSignatureVerdict(
            False, None, None, f"no signature sidecar found at {signature_path}"
        )

    try:
        signature = open(signature_path, "rb").read()
    except OSError as e:
        return PluginSignatureVerdict(False, None, None, f"could not read signature: {e}")

    last_reason = "signature did not match any trust anchor"
    for anchor in anchors:
        try:
            result = verify_detached(
                plugin_bytes,
                signature,
                public_key=anchor.public_key,
                expected_fingerprint=anchor.fingerprint,
                gpg_binary=gpg_binary,
            )
        except GpgUnavailableError:
            # Fail closed: without gpg we cannot establish trust.
            return PluginSignatureVerdict(
                False, None, None, "gpg is unavailable; cannot verify plugin signature"
            )
        if result.good:
            return PluginSignatureVerdict(True, result.fingerprint, anchor.label, "signature valid")
        last_reason = result.summary

    return PluginSignatureVerdict(False, None, None, last_reason)
