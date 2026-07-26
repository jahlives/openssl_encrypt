#!/usr/bin/env python3
"""
Detached file signing (feature #1).

Produces and verifies a *detached* post-quantum signature over an arbitrary
file, closing the authenticity gap of symmetric AEAD (which gives
confidentiality + integrity but lets anyone who knows the password forge a
valid file).

v1 signs with the signer identity's existing ML-DSA-65 key. The signature
covers a DOMAIN-SEPARATED canonical payload that binds the file's SHA-512
digest to the algorithm, signer fingerprint and timestamp; the domain tag is
distinct from the encrypted-file *metadata* signature so a signature from one
context can never be replayed in the other.

The detached signature is a JSON sidecar (``.sig``) — optionally wrapped in the
ASCII-armor SIGNATURE envelope — carrying a ``signatures`` list so a classical
(e.g. Ed25519) component can be added later without a format break.

Security notes:
- Verification recomputes the file hash, requires it to equal the signed hash,
  and verifies every signature component; it reports which component(s) passed
  rather than a bare boolean.
- Trust is established by the caller: the signer's public key is resolved from
  the local identity store (own identities + contacts) by the fingerprint
  embedded in the ``.sig``. This module only performs the cryptographic check.
"""

import base64
import hashlib
import json
from typing import List, Optional, Union

from .armor import armor, dearmor, is_armored
from .credential_env import CredentialError, consume_env, resolve_credential
from .pqc_signing import PQCSigner

# Environment channel for the signer identity passphrase (gitlab#159).
# Read once and deleted; see modules/credential_env.py for the rationale.
SIGNER_PASSPHRASE_ENV = "OPENSSL_ENCRYPT_SIGNER_PASSPHRASE"

# On-disk signature format version (the integer stored under the
# "openssl_encrypt_signature" key).
SIGNATURE_FORMAT_VERSION = 1

# ASCII-armor PEM label used for detached signatures.
ARMOR_LABEL = "SIGNATURE"

# File digest algorithm.
HASH_ALGORITHM = "SHA-512"

# Default post-quantum signature algorithm (matches the identity default).
DEFAULT_SIG_ALGORITHM = "ML-DSA-65"

# Domain-separation tag for detached FILE signatures. MUST stay distinct from
# any other signing context (e.g. the encrypted-file metadata signature) so a
# signature produced here cannot be accepted elsewhere and vice versa.
_DOMAIN_TAG = b"openssl-encrypt/detached-file-signature/v1"

# Chunk size for streaming file hashing.
_HASH_CHUNK = 1024 * 1024


class FileSignatureError(Exception):
    """Raised on signing/verification *setup* problems (malformed sidecar,
    unknown signer, missing key) — not for a merely-invalid signature, which is
    reported via :class:`VerifyResult`."""


# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #


def hash_bytes(data: bytes) -> str:
    """Return the lowercase hex SHA-512 digest of ``data``."""
    return hashlib.sha512(data).hexdigest()


def hash_file(path: str) -> str:
    """Return the lowercase hex SHA-512 digest of the file at ``path``.

    Reads the file in chunks so arbitrarily large files hash in constant memory.
    """
    h = hashlib.sha512()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_HASH_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# Signed payload (canonical, domain-separated)
# --------------------------------------------------------------------------- #


def _signed_payload(
    file_hash: str, algorithm: str, signer_fingerprint: str, signed_at: str
) -> bytes:
    """Build the exact bytes that are signed/verified.

    A domain-separation tag is prepended to a deterministic canonical JSON of
    the bound fields. The ``signatures`` field of the sidecar is deliberately
    NOT part of this payload.
    """
    core = {
        "algorithm": algorithm,
        "file_hash": file_hash,
        "hash_algorithm": HASH_ALGORITHM,
        "signed_at": signed_at,
        "signer_fingerprint": signer_fingerprint,
        "version": SIGNATURE_FORMAT_VERSION,
    }
    canonical = json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _DOMAIN_TAG + b"\x00" + canonical


# --------------------------------------------------------------------------- #
# Signing
# --------------------------------------------------------------------------- #


def build_signature(
    file_hash: str, signer, signed_at: str, algorithm: Optional[str] = None
) -> dict:
    """Create a detached-signature dict for a file with the given SHA-512 hash.

    Args:
        file_hash: Hex SHA-512 digest of the file to sign.
        signer: An own :class:`Identity` loaded with its private signing key.
        signed_at: RFC3339/ISO-8601 timestamp string to bind into the signature.
        algorithm: Override signature algorithm; defaults to the identity's
            ``signing_algorithm`` (else ML-DSA-65).

    Returns:
        The signature sidecar as a plain ``dict`` (ready for serialization).

    Raises:
        FileSignatureError: If the signer has no usable private signing key.
    """
    algorithm = algorithm or getattr(signer, "signing_algorithm", None) or DEFAULT_SIG_ALGORITHM

    if getattr(signer, "signing_private_key", None) is None:
        raise FileSignatureError(
            f"identity '{getattr(signer, 'name', '?')}' has no private signing key loaded"
        )

    payload = _signed_payload(file_hash, algorithm, signer.fingerprint, signed_at)
    pqc_signer = PQCSigner(algorithm, quiet=True)
    with signer.signing_private_key as key:
        raw_sig = pqc_signer.sign(payload, key.get_bytes())

    return {
        "openssl_encrypt_signature": SIGNATURE_FORMAT_VERSION,
        "algorithm": algorithm,
        "hash_algorithm": HASH_ALGORITHM,
        "file_hash": file_hash,
        "signer_fingerprint": signer.fingerprint,
        "signed_at": signed_at,
        "signatures": [
            {"component": algorithm.lower(), "value": base64.b64encode(raw_sig).decode("ascii")}
        ],
    }


# --------------------------------------------------------------------------- #
# Serialization
# --------------------------------------------------------------------------- #


def serialize_signature(sig: dict, armored: bool = True) -> bytes:
    """Serialize a signature dict to bytes (ASCII-armored by default)."""
    raw = (json.dumps(sig, sort_keys=True, indent=2) + "\n").encode("utf-8")
    return armor(raw, label=ARMOR_LABEL) if armored else raw


def parse_signature(data: Union[bytes, bytearray, str]) -> dict:
    """Parse a signature sidecar (armored or raw JSON) into a dict.

    Raises:
        FileSignatureError: If the input is not a valid signature sidecar.
    """
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    if is_armored(raw):
        try:
            raw = dearmor(raw, expected_label=ARMOR_LABEL)
        except Exception as exc:
            raise FileSignatureError(f"invalid armored signature file: {exc}")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise FileSignatureError(f"invalid signature file (not JSON): {exc}")
    if not isinstance(obj, dict) or "signatures" not in obj:
        raise FileSignatureError("invalid signature file: missing required fields")
    return obj


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #


class VerifyResult:
    """Outcome of verifying a detached signature.

    Attributes:
        valid: Overall verdict (file matches AND at least one component verified
            AND all present components verified).
        file_match: Whether the actual file hash equals the signed hash.
        signature_valid: Whether every signature component verified.
        signer_fingerprint: Fingerprint recorded in the sidecar.
        signed_at: Timestamp recorded in the sidecar.
        components: List of ``{"component": str, "valid": bool}`` per component.
        reason: Human-readable explanation when not valid.
    """

    def __init__(
        self,
        valid: bool,
        file_match: bool,
        signature_valid: bool,
        signer_fingerprint: Optional[str],
        signed_at: Optional[str],
        components: List[dict],
        reason: Optional[str] = None,
    ):
        self.valid = valid
        self.file_match = file_match
        self.signature_valid = signature_valid
        self.signer_fingerprint = signer_fingerprint
        self.signed_at = signed_at
        self.components = components
        self.reason = reason


def verify_signature(actual_file_hash: str, sig: dict, signer_public_key: bytes) -> VerifyResult:
    """Verify a detached signature against the actual file hash and signer key.

    Args:
        actual_file_hash: Hex SHA-512 digest of the file being verified.
        sig: The parsed signature sidecar dict.
        signer_public_key: The signer's public signing key (raw bytes), resolved
            by the caller from the identity store via ``signer_fingerprint``.

    Returns:
        A :class:`VerifyResult`.

    Raises:
        FileSignatureError: If the sidecar is structurally invalid.
    """
    try:
        algorithm = sig["algorithm"]
        signed_hash = sig["file_hash"]
        signer_fingerprint = sig["signer_fingerprint"]
        signed_at = sig["signed_at"]
        components_in = sig["signatures"]
    except (KeyError, TypeError) as exc:
        raise FileSignatureError(f"malformed signature sidecar: missing {exc}")

    # 1) Bind the signature to THIS file.
    file_match = bool(actual_file_hash) and (actual_file_hash == signed_hash)

    # 2) Reconstruct the signed payload from the authenticated fields and verify
    #    every component. Any decode/verify failure counts as an invalid
    #    component (never raises on a bad signature).
    payload = _signed_payload(signed_hash, algorithm, signer_fingerprint, signed_at)
    pqc_verifier = PQCSigner(algorithm, quiet=True)

    components_out: List[dict] = []
    for comp in components_in:
        name = comp.get("component", algorithm.lower())
        ok = False
        try:
            raw_sig = base64.b64decode(comp["value"], validate=True)
            ok = pqc_verifier.verify(payload, raw_sig, signer_public_key)
        except Exception:
            ok = False
        components_out.append({"component": name, "valid": bool(ok)})

    signature_valid = len(components_out) > 0 and all(c["valid"] for c in components_out)
    valid = file_match and signature_valid

    reason = None
    if not valid:
        if not file_match:
            reason = "file does not match the signed hash"
        elif not signature_valid:
            reason = "signature verification failed"

    return VerifyResult(
        valid=valid,
        file_match=file_match,
        signature_valid=signature_valid,
        signer_fingerprint=signer_fingerprint,
        signed_at=signed_at,
        components=components_out,
        reason=reason,
    )


# --------------------------------------------------------------------------- #
# CLI handlers (wired from crypt_cli dispatch)
# --------------------------------------------------------------------------- #


def sign_file_cli(args) -> None:
    """CLI handler for the ``sign`` action."""
    import sys
    from datetime import datetime, timezone

    from .crypt_cli import resolve_identity_store_path
    from .crypt_utils import eprint
    from .identity_cli import get_identity_store
    from .identity_protection import ProtectionLevel
    from .secure_memory import secure_memzero

    # Consumed first, before any store lookup or early exit: a value left in
    # the environment is inherited by any child process, and the guarantee
    # must not depend on the identity-load path happening not to spawn one.
    env_passphrase = consume_env(SIGNER_PASSPHRASE_ENV)

    input_file = args.input
    output_file = getattr(args, "output", None) or (input_file + ".sig")
    armored = getattr(args, "armor", True)
    signer_name = args.sign_with

    store = get_identity_store(resolve_identity_store_path(args))

    # Load metadata first (no private keys) to validate and check protection.
    signer_meta = store.get_by_name(signer_name, load_private_keys=False)
    if signer_meta is None:
        eprint(f"ERROR: Signer identity '{signer_name}' not found ❌")
        sys.exit(1)
    if not getattr(signer_meta, "is_own_identity", False):
        eprint(f"ERROR: '{signer_name}' is a contact (public key only) and cannot sign ❌")
        sys.exit(1)

    # The passphrase reached only a getpass() prompt, which reads /dev/tty and
    # cannot be answered by the desktop GUI or a CI caller, so `sign` was not
    # driveable non-interactively at all (gitlab#159). The environment channel
    # supplies it instead; it is never accepted on the command line, where
    # /proc/PID/cmdline would publish it.
    #
    # `requested` is the HSM_ONLY check: an HSM-only identity needs no
    # passphrase, and a planted variable must not introduce one.
    needs_passphrase = (
        not signer_meta.protection
        or signer_meta.protection.level != ProtectionLevel.HSM_ONLY
    )
    try:
        passphrase = resolve_credential(
            requested=needs_passphrase,
            env_name=SIGNER_PASSPHRASE_ENV,
            prompt=f"Passphrase for signer identity '{signer_name}': ",
            explicit=env_passphrase,
            explicit_source=f"${SIGNER_PASSPHRASE_ENV}",
        )
    except CredentialError as e:
        eprint(f"ERROR: {e} ❌")
        sys.exit(1)
    except EOFError:
        # No stdin (a GUI or CI caller): fail with a usable instruction rather
        # than a traceback from getpass.
        eprint(
            f"ERROR: no passphrase supplied and no terminal to prompt on; "
            f"set ${SIGNER_PASSPHRASE_ENV} ❌"
        )
        sys.exit(1)
    except KeyboardInterrupt:
        # A deliberate abort, not a headless environment. Telling the user to
        # export a variable they chose not to would be wrong, and 130 lets a
        # wrapper distinguish user-abort from failure.
        eprint("Aborted.")
        sys.exit(130)

    try:
        signer = store.get_by_name(signer_name, passphrase=passphrase, load_private_keys=True)
        if signer is None:
            eprint(f"ERROR: Signer identity '{signer_name}' not found ❌")
            sys.exit(1)
        file_hash = hash_file(input_file)
        signed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        sig = build_signature(file_hash, signer, signed_at)
    finally:
        if passphrase:
            secure_memzero(passphrase)

    blob = serialize_signature(sig, armored=armored)
    with open(output_file, "wb") as f:
        f.write(blob)

    if not getattr(args, "quiet", False):
        eprint(f"✅ Signed '{input_file}' as '{signer.name}' ({sig['algorithm']})")
        eprint(f"   Signature:          {output_file}")
        eprint(f"   Signer fingerprint: {signer.fingerprint}")


def verify_signature_cli(args) -> None:
    """CLI handler for the ``verify-signature`` action."""
    import json as _json
    import sys

    from .crypt_cli import resolve_identity_store_path
    from .crypt_utils import eprint
    from .identity_cli import get_identity_store

    input_file = args.input
    sig_file = getattr(args, "signature", None) or (input_file + ".sig")
    json_out = getattr(args, "json", False)

    try:
        with open(sig_file, "rb") as f:
            sig = parse_signature(f.read())
    except FileNotFoundError:
        eprint(f"ERROR: Signature file '{sig_file}' not found ❌")
        sys.exit(1)
    except FileSignatureError as exc:
        eprint(f"ERROR: {exc} ❌")
        sys.exit(1)

    signer_fp = sig.get("signer_fingerprint")
    store = get_identity_store(resolve_identity_store_path(args))

    # Resolve the signer's public key. Trust comes from the local store: the
    # signer must be a known own-identity or contact (fail closed if unknown).
    pinned = getattr(args, "signer", None)
    signer_identity = None
    if pinned:
        signer_identity = store.get_by_name(pinned, load_private_keys=False)
        if signer_identity is None:
            eprint(f"ERROR: Pinned signer identity '{pinned}' not found ❌")
            sys.exit(1)
        if signer_identity.fingerprint != signer_fp:
            eprint(
                f"ERROR: Pinned signer '{pinned}' does not match the signature's "
                f"signer fingerprint ❌"
            )
            sys.exit(1)
    else:
        for ident in store.list_identities(include_contacts=True):
            if ident.fingerprint == signer_fp:
                signer_identity = ident
                break
        if signer_identity is None:
            eprint(
                f"ERROR: Unknown signer (fingerprint {signer_fp}); not found among "
                f"your identities or contacts ❌"
            )
            eprint("       Add the signer as a contact, or use --signer to pin a known identity.")
            sys.exit(1)

    result = verify_signature(hash_file(input_file), sig, signer_identity.signing_public_key)

    if json_out:
        result_json = _json.dumps(
            {
                "valid": result.valid,
                "file_match": result.file_match,
                "signature_valid": result.signature_valid,
                "signer": signer_identity.name,
                "signer_fingerprint": result.signer_fingerprint,
                "signed_at": result.signed_at,
                "components": result.components,
                "reason": result.reason,
            },
            indent=2,
        )
        print(result_json)
    elif result.valid:
        comp = ", ".join(
            f"{c['component']}={'ok' if c['valid'] else 'BAD'}" for c in result.components
        )
        eprint(f"✅ GOOD signature from '{signer_identity.name}'")
        eprint(f"   Signer fingerprint: {result.signer_fingerprint}")
        eprint(f"   Signed at:          {result.signed_at}")
        eprint(f"   Components:         {comp}")
    else:
        eprint(f"❌ BAD signature: {result.reason}")
        eprint(f"   Claimed signer: '{signer_identity.name}' ({result.signer_fingerprint})")

    sys.exit(0 if result.valid else 1)
