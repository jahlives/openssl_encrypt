"""Operator-facing helpers for plugin signing and trust-key enrollment (#66).

Thin wrappers over integrity.gpg_runner used by the CLI:

* ``sign_plugin`` — produce a ``<plugin>.py.asc`` detached signature with the
  operator's own key (default keyring, so a hardware-backed key or gpg-agent
  works transparently).
* ``enroll_trust_key`` — copy a public key into the per-user trust-anchor
  store, refusing an unsafe store and requiring an out-of-band fingerprint
  confirmation (TOFU pinning of a third-party author key).
* ``list_trust_keys`` — enumerate enrolled anchors.

Kept free of argparse so it is unit-testable without a full CLI harness.
"""

import os
from pathlib import Path
from typing import List, Optional

from ...integrity.gpg_runner import detached_sign
from .plugin_signature import (
    SIGNATURE_SUFFIX,
    TrustAnchor,
    TrustAnchorError,
    TrustAnchorStore,
    _fingerprint_of_public_key,
    signature_path_for,
)


def default_trusted_keys_dir() -> str:
    """Resolve the per-user trust-anchor store directory."""
    base = os.environ.get("OPENSSL_ENCRYPT_HOME") or os.path.join(
        os.path.expanduser("~"), ".openssl_encrypt"
    )
    return os.path.join(base, "trusted_plugin_keys")


def sign_plugin(
    plugin_path: str,
    key_id: str,
    *,
    passphrase: Optional[str] = None,
    home: Optional[Path] = None,
    gpg_binary: Optional[str] = None,
) -> str:
    """Sign a plugin source file, writing a detached ``<plugin>.py.asc`` sidecar.

    Signs the exact on-disk bytes so the sidecar matches what the loader
    verifies. Uses the default keyring, so a hardware token (YubiKey/OnlyKey)
    or gpg-agent handles the private key and any required touch/PIN.

    Args:
        plugin_path: Path to the plugin ``.py`` file to sign.
        key_id: Signing key fingerprint or id (gpg ``--local-user``).
        passphrase: Optional passphrase (loopback); omit to use gpg-agent /
            hardware token.
        home: GNUPGHOME holding the signing key (None = default keyring;
            mainly overridden in tests).
        gpg_binary: Override the gpg executable (mainly for tests).

    Returns:
        The path to the written signature sidecar.

    Raises:
        FileNotFoundError: If the plugin file does not exist.
        GpgError / GpgUnavailableError: On signing failure.
    """
    if not os.path.isfile(plugin_path):
        raise FileNotFoundError(f"Plugin file not found: {plugin_path}")

    with open(plugin_path, "rb") as f:
        data = f.read()

    signature = detached_sign(data, key_id, home=home, passphrase=passphrase, gpg_binary=gpg_binary)
    sig_path = signature_path_for(plugin_path)
    # Sidecar signatures are not secret, but write them owner-only to match the
    # rest of the plugin tree's hygiene.
    fd = os.open(sig_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, signature)
    finally:
        os.close(fd)
    return sig_path


def sign_plugin_package(
    package_dir: str,
    key_id: str,
    *,
    passphrase: Optional[str] = None,
    home: Optional[Path] = None,
    gpg_binary: Optional[str] = None,
) -> str:
    """Build and sign a per-package manifest (H2 [PLUGIN-1]).

    Writes ``PLUGIN.manifest`` (covering every importable module — source,
    bytecode and native extensions — under the package) and a detached
    ``PLUGIN.manifest.asc`` into the package directory, so the loader can refuse
    a tampered/unlisted sibling under the enforce policy. Accepts either the
    package directory or its ``__init__.py``.

    Returns the path to the written signature. Raises FileNotFoundError /
    ValueError for a non-package target, ManifestError for an unsafe tree, and
    GpgError / GpgUnavailableError on signing failure.
    """
    from .plugin_manifest import MANIFEST_FILENAME, build_manifest

    if os.path.isfile(package_dir) and os.path.basename(package_dir) == "__init__.py":
        package_dir = os.path.dirname(package_dir)
    if not os.path.isdir(package_dir):
        raise FileNotFoundError(f"Plugin package directory not found: {package_dir}")
    if not os.path.isfile(os.path.join(package_dir, "__init__.py")):
        raise ValueError(f"Not a package plugin (no __init__.py): {package_dir}")

    # Build over the module set BEFORE writing PLUGIN.manifest (which is not a
    # module and is therefore not covered), so verification re-enumerates the
    # identical set.
    manifest = build_manifest(package_dir)
    manifest_path = os.path.join(package_dir, MANIFEST_FILENAME)
    fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, manifest)
    finally:
        os.close(fd)

    signature = detached_sign(
        manifest, key_id, home=home, passphrase=passphrase, gpg_binary=gpg_binary
    )
    sig_path = signature_path_for(manifest_path)
    fd = os.open(sig_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, signature)
    finally:
        os.close(fd)
    return sig_path


def enroll_trust_key(
    public_key_path: str,
    *,
    trusted_keys_dir: Optional[str] = None,
    confirm_fingerprint: Optional[str] = None,
    label: Optional[str] = None,
    gpg_binary: Optional[str] = None,
) -> TrustAnchor:
    """Enroll an armored public key as a plugin-signing trust anchor.

    The caller MUST confirm the key fingerprint out of band and pass it as
    ``confirm_fingerprint``; enrollment fails if it does not match the key,
    so a substituted key file cannot be silently trusted (TOFU pinning).

    Args:
        public_key_path: Path to an ASCII-armored public key file.
        trusted_keys_dir: Store directory (default: per-user store).
        confirm_fingerprint: Out-of-band fingerprint the operator vouches for.
            Required — omitting it raises ValueError.
        label: File name to store the key under (default: derived from
            fingerprint).
        gpg_binary: Override the gpg executable (mainly for tests).

    Returns:
        The enrolled TrustAnchor.

    Raises:
        ValueError: If confirm_fingerprint is missing or does not match.
        FileNotFoundError: If the public key file is missing.
        TrustAnchorError: If the store directory is unsafe.
    """
    if not confirm_fingerprint:
        raise ValueError(
            "confirm_fingerprint is required: verify the key fingerprint out of "
            "band before enrolling it as a plugin-signing anchor"
        )
    if not os.path.isfile(public_key_path):
        raise FileNotFoundError(f"Public key file not found: {public_key_path}")

    with open(public_key_path, "rb") as f:
        pub = f.read()

    actual = _fingerprint_of_public_key(pub, gpg_binary=gpg_binary)
    if actual is None:
        raise ValueError(f"{public_key_path} is not a usable armored public key")

    exp = confirm_fingerprint.replace(" ", "").upper()
    got = actual.upper()
    if not (got == exp or got.endswith(exp) or exp.endswith(got)):
        raise ValueError(
            f"Fingerprint mismatch: key is {got}, you confirmed {exp}. "
            f"Refusing to enroll — confirm the correct fingerprint out of band."
        )

    directory = trusted_keys_dir or default_trusted_keys_dir()
    _ensure_owner_only_dir(directory)

    # Fail closed if the store is unsafe (writable by others).
    TrustAnchorStore(directory, gpg_binary=gpg_binary).load_anchors()

    file_label = label or f"{actual}{SIGNATURE_SUFFIX}"
    if not file_label.endswith(SIGNATURE_SUFFIX):
        file_label += SIGNATURE_SUFFIX
    dest = os.path.join(directory, file_label)
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, pub)
    finally:
        os.close(fd)

    return TrustAnchor(fingerprint=actual, public_key=pub, label=file_label)


def list_trust_keys(
    *, trusted_keys_dir: Optional[str] = None, gpg_binary: Optional[str] = None
) -> List[TrustAnchor]:
    """Return the enrolled plugin-signing trust anchors."""
    directory = trusted_keys_dir or default_trusted_keys_dir()
    return TrustAnchorStore(directory, gpg_binary=gpg_binary).load_anchors()


def _ensure_owner_only_dir(directory: str) -> None:
    """Create ``directory`` (and parents) as 0700 if absent; tighten if present."""
    if not os.path.isdir(directory):
        os.makedirs(directory, mode=0o700, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
