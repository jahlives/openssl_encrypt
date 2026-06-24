"""Password-based envelope (DEK/KEK) wrapping for symmetric encryption.

Bulk data is encrypted under a random **Data Encryption Key (DEK)**. The DEK is
wrapped with a **Key Encryption Key (KEK)** derived from the password (the same
key ``generate_key`` already produces). Storing the wrapped DEK in the metadata
means a password change (``rekey``) only has to rewrap the small DEK rather than
re-encrypt the entire payload.

The wrap key is derived from the KEK with HKDF-SHA256 and a dedicated domain
separation label, so the KEK is never used directly as an AEAD key (and an
envelope wrap key can never collide with a key used elsewhere). The construction
otherwise mirrors the audited ``PasswordWrapper.wrap_password`` (AES-256-GCM with
a random 96-bit nonce and a 128-bit tag), but without pulling in the post-quantum
KEM machinery that ``PasswordWrapper`` instantiates.

Wrapped format: ``[nonce:12][ciphertext:32][tag:16]`` = 60 bytes for a 32-byte DEK.
"""

import copy
import json
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypt_errors import DecryptionError, ValidationError
from .secure_memory import secure_memzero

# 256-bit DEK for the AEAD bulk ciphers.
DEK_SIZE = 32

# --- Envelope bulk-AEAD AAD (Option A: stable-subset binding) ---------------
# The envelope bulk ciphertext is AEAD-bound to a CANONICAL subset of the
# metadata that EXCLUDES only the KEK-gating fields a credential rekey changes:
# the whole ``derivation_config`` subtree (KDF salt + hash/kdf config) and
# ``encryption.wrapped_dek``. Everything else affects interpretation of the
# bulk ciphertext, is stable across rekey, and stays authenticated. This is
# what lets the rekey fast-path rewrap the DEK and retain the bulk ciphertext
# verbatim (``envelope_aad`` is invariant across rekey by construction).
#
# Deny-list (exclude a known-small set), NOT allow-list: any future metadata
# field is authenticated by default; a mistake fails LOUDLY (broken round-trip
# or rekey) instead of silently dropping authentication.
_AAD_EXCLUDED_TOP = ("derivation_config",)
_AAD_EXCLUDED_ENCRYPTION = ("wrapped_dek",)
# Minimum acceptable KEK length (generate_key produces >= 32 bytes).
_MIN_KEK_SIZE = 32
_WRAP_NONCE_SIZE = 12
_WRAP_TAG_SIZE = 16
# Domain separation so an envelope wrap key is distinct from any other use of the KEK.
_WRAP_INFO = b"openssl_encrypt.envelope.dek-wrap.v1"

# Cascade DEK-wrap parameters. When the bulk is a cascade chain, the DEK is
# wrapped under the SAME chain so the envelope is never the weak link (breaking
# the wrap requires breaking every layer, matching the bulk's guarantee). A
# FIXED wrap salt is safe: the wrap key (HKDF(KEK)) is unique per file and wraps
# the DEK exactly once, so per-layer (key, nonce) pairs never repeat; a rekey
# rolls the KEK and therefore the whole derivation. The format_version is pinned
# so wrap/unwrap agree and stay interoperable across the 1.4.x / 1.5.x lines.
_CASCADE_WRAP_SALT = b"oesc.envelope.cascade-wrap.salt1"  # exactly 32 bytes
_CASCADE_WRAP_FORMAT_VERSION = 12


def generate_dek() -> bytearray:
    """Generate a fresh random DEK.

    Returns:
        A ``bytearray`` of ``DEK_SIZE`` bytes (mutable so the caller can
        ``secure_memzero`` it after use).
    """
    return bytearray(secrets.token_bytes(DEK_SIZE))


def envelope_aad(metadata: dict) -> bytes:
    """Compute the envelope bulk-AEAD AAD from a metadata dict.

    Returns a deterministic, canonical serialization of ``metadata`` with the
    KEK-gating fields removed: the whole ``derivation_config`` subtree and
    ``encryption.wrapped_dek``. Those are exactly the fields a credential rekey
    changes, so excluding them keeps the AAD invariant across rekey while every
    remaining (bulk-interpretation) field stays authenticated.

    The serialization sorts keys and uses compact separators so that encrypt and
    decrypt -- which build the metadata dict independently -- produce identical
    bytes. Input is deep-copied; the caller's metadata is never mutated.

    Args:
        metadata: The full file metadata dict (as written to / read from the
            file header).

    Returns:
        Canonical UTF-8 bytes suitable as AEAD associated data.

    Raises:
        ValidationError: If ``metadata`` is not a dict.
    """
    if not isinstance(metadata, dict):
        raise ValidationError("metadata must be a dict")

    reduced = copy.deepcopy(metadata)
    for key in _AAD_EXCLUDED_TOP:
        reduced.pop(key, None)
    encryption = reduced.get("encryption")
    if isinstance(encryption, dict):
        for key in _AAD_EXCLUDED_ENCRYPTION:
            encryption.pop(key, None)

    return json.dumps(reduced, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _derive_wrap_key(kek: bytes) -> bytearray:
    """Derive the AES-256 wrap key from the KEK via HKDF-SHA256.

    Returns a mutable ``bytearray`` so the caller can zero it.
    """
    return bytearray(
        HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=_WRAP_INFO,
        ).derive(bytes(kek))
    )


def wrap_dek(dek: bytes, kek: bytes) -> bytes:
    """Wrap a DEK under a KEK with AES-256-GCM.

    Args:
        dek: The data encryption key to protect (typically ``DEK_SIZE`` bytes).
        kek: The password-derived key encryption key (>= 32 bytes).

    Returns:
        ``nonce || ciphertext || tag`` bytes.

    Raises:
        ValidationError: If inputs are the wrong type or too short.
    """
    if not isinstance(dek, (bytes, bytearray)):
        raise ValidationError("dek must be bytes")
    if not isinstance(kek, (bytes, bytearray)):
        raise ValidationError("kek must be bytes")
    if len(dek) == 0:
        raise ValidationError("dek must not be empty")
    if len(kek) < _MIN_KEK_SIZE:
        raise ValidationError(f"kek must be at least {_MIN_KEK_SIZE} bytes")

    wrap_key = _derive_wrap_key(kek)
    try:
        nonce = secrets.token_bytes(_WRAP_NONCE_SIZE)
        ciphertext_with_tag = AESGCM(bytes(wrap_key)).encrypt(nonce, bytes(dek), None)
        return nonce + ciphertext_with_tag
    finally:
        secure_memzero(wrap_key)


def unwrap_dek(wrapped: bytes, kek: bytes) -> bytearray:
    """Unwrap a DEK produced by :func:`wrap_dek`.

    Args:
        wrapped: The ``nonce || ciphertext || tag`` blob.
        kek: The password-derived key encryption key (>= 32 bytes).

    Returns:
        The recovered DEK as a mutable ``bytearray`` (caller should
        ``secure_memzero`` it after use).

    Raises:
        ValidationError: If inputs are the wrong type/size.
        DecryptionError: If authentication fails (wrong KEK or tampering).
    """
    if not isinstance(wrapped, (bytes, bytearray)):
        raise ValidationError("wrapped must be bytes")
    if not isinstance(kek, (bytes, bytearray)):
        raise ValidationError("kek must be bytes")
    if len(kek) < _MIN_KEK_SIZE:
        raise ValidationError(f"kek must be at least {_MIN_KEK_SIZE} bytes")
    if len(wrapped) < _WRAP_NONCE_SIZE + _WRAP_TAG_SIZE + 1:
        raise ValidationError("wrapped DEK is too short")

    wrap_key = _derive_wrap_key(kek)
    try:
        nonce = bytes(wrapped[:_WRAP_NONCE_SIZE])
        ciphertext_with_tag = bytes(wrapped[_WRAP_NONCE_SIZE:])
        try:
            plaintext = AESGCM(bytes(wrap_key)).decrypt(nonce, ciphertext_with_tag, None)
        except Exception as e:
            # Generic message: never leak key material or crypto internals.
            raise DecryptionError("Envelope DEK unwrap failed", original_exception=e)
        return bytearray(plaintext)
    finally:
        secure_memzero(wrap_key)


def wrap_dek_cascade(
    dek: bytes, kek: bytes, cipher_names: list, hkdf_hash: str = "sha256"
) -> bytes:
    """Wrap a DEK under the same cascade chain that protects the bulk data.

    Ensures the envelope is never weaker than the payload: an attacker must
    break every cascade layer to recover the DEK, matching the bulk's
    strongest-component guarantee (rather than reducing to a single AES-256-GCM).

    Args:
        dek: The data encryption key to protect.
        kek: The password-derived key encryption key (>= 32 bytes).
        cipher_names: The cascade cipher chain (same as the bulk's cipher_chain).
        hkdf_hash: HKDF hash for the cascade key derivation.

    Returns:
        The cascade-wrapped DEK bytes.

    Raises:
        ValidationError: If inputs are the wrong type or too short.
    """
    from .cascade import CascadeConfig, CascadeEncryption

    if not isinstance(dek, (bytes, bytearray)) or len(dek) == 0:
        raise ValidationError("dek must be non-empty bytes")
    if not isinstance(kek, (bytes, bytearray)) or len(kek) < _MIN_KEK_SIZE:
        raise ValidationError(f"kek must be at least {_MIN_KEK_SIZE} bytes")
    if not cipher_names:
        raise ValidationError("cipher_names must be a non-empty cascade chain")

    config = CascadeConfig(cipher_names=list(cipher_names), hkdf_hash=hkdf_hash)
    enc = CascadeEncryption(config, format_version=_CASCADE_WRAP_FORMAT_VERSION)
    wrap_key = _derive_wrap_key(kek)
    try:
        return enc.encrypt(bytes(dek), bytes(wrap_key), _CASCADE_WRAP_SALT, associated_data=None)
    finally:
        secure_memzero(wrap_key)


def unwrap_dek_cascade(
    wrapped: bytes, kek: bytes, cipher_names: list, hkdf_hash: str = "sha256"
) -> bytearray:
    """Unwrap a DEK produced by :func:`wrap_dek_cascade`.

    Args:
        wrapped: The cascade-wrapped DEK blob.
        kek: The password-derived key encryption key (>= 32 bytes).
        cipher_names: The cascade cipher chain used to wrap (the bulk chain).
        hkdf_hash: HKDF hash for the cascade key derivation.

    Returns:
        The recovered DEK as a mutable ``bytearray``.

    Raises:
        ValidationError: If inputs are the wrong type/size.
        DecryptionError: If authentication fails (wrong KEK or tampering).
    """
    from .cascade import CascadeConfig, CascadeEncryption

    if not isinstance(wrapped, (bytes, bytearray)) or len(wrapped) == 0:
        raise ValidationError("wrapped must be non-empty bytes")
    if not isinstance(kek, (bytes, bytearray)) or len(kek) < _MIN_KEK_SIZE:
        raise ValidationError(f"kek must be at least {_MIN_KEK_SIZE} bytes")
    if not cipher_names:
        raise ValidationError("cipher_names must be a non-empty cascade chain")

    config = CascadeConfig(cipher_names=list(cipher_names), hkdf_hash=hkdf_hash)
    dec = CascadeEncryption(config, format_version=_CASCADE_WRAP_FORMAT_VERSION)
    wrap_key = _derive_wrap_key(kek)
    try:
        plaintext = dec.decrypt(
            bytes(wrapped), bytes(wrap_key), _CASCADE_WRAP_SALT, associated_data=None
        )
        return bytearray(plaintext)
    except (DecryptionError, ValidationError):
        raise
    except Exception as e:
        raise DecryptionError("Envelope cascade DEK unwrap failed", original_exception=e)
    finally:
        secure_memzero(wrap_key)
