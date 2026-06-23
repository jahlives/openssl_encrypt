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

import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypt_errors import DecryptionError, ValidationError
from .secure_memory import secure_memzero

# 256-bit DEK for the AEAD bulk ciphers.
DEK_SIZE = 32
# Minimum acceptable KEK length (generate_key produces >= 32 bytes).
_MIN_KEK_SIZE = 32
_WRAP_NONCE_SIZE = 12
_WRAP_TAG_SIZE = 16
# Domain separation so an envelope wrap key is distinct from any other use of the KEK.
_WRAP_INFO = b"openssl_encrypt.envelope.dek-wrap.v1"


def generate_dek() -> bytearray:
    """Generate a fresh random DEK.

    Returns:
        A ``bytearray`` of ``DEK_SIZE`` bytes (mutable so the caller can
        ``secure_memzero`` it after use).
    """
    return bytearray(secrets.token_bytes(DEK_SIZE))


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
