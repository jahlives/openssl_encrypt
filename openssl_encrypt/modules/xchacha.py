#!/usr/bin/env python3
"""
Real XChaCha20-Poly1305 with full 192-bit nonces.

Implements the HChaCha20 subkey derivation and the XChaCha20-Poly1305 AEAD
construction from draft-irtf-cfrg-xchacha-03 on top of the ``cryptography``
library, which exposes ChaCha20 and ChaCha20-Poly1305 but not XChaCha.

HChaCha20 is recovered from the ChaCha20 block function via the feed-forward
identity: a ChaCha20 keystream block is ``rounds(state) + state`` (per-word,
mod 2**32). Every initial state word is known (the "expand 32-byte k"
constants, the key, and the 16-byte HChaCha input in the counter/nonce
positions), so the raw round output that HChaCha20 needs — words 0-3 and
12-15 *without* the feed-forward — is obtained by subtracting the known
initial words from one keystream block. The implementation is pinned against
the official test vectors in test_xchacha_primitives.py.
"""

import struct
from typing import Optional

import cryptography.exceptions
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .crypt_errors import (
    AuthenticationError,
    DecryptionError,
    EncryptionError,
    ValidationError,
)
from .secure_memory import secure_memzero

# Sizes per draft-irtf-cfrg-xchacha-03
XCHACHA_KEY_SIZE = 32
XCHACHA_NONCE_SIZE = 24
HCHACHA_INPUT_SIZE = 16
POLY1305_TAG_SIZE = 16

_CHACHA_CONSTANTS = struct.unpack("<4I", b"expand 32-byte k")


def _validate_key(key: bytes) -> None:
    """Validate an XChaCha20 key.

    Args:
        key: Candidate 32-byte key.

    Raises:
        ValidationError: If the key is missing, not bytes-like, or not
            exactly 32 bytes.
    """
    if key is None:
        raise ValidationError("Key cannot be None")
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise ValidationError(f"Key must be bytes-like object, got {type(key).__name__}")
    if len(key) != XCHACHA_KEY_SIZE:
        raise ValidationError(
            f"Invalid key length: {len(key)}. XChaCha20 requires a {XCHACHA_KEY_SIZE}-byte key"
        )


def hchacha20(key: bytes, input16: bytes) -> bytes:
    """Compute the HChaCha20 function (draft-irtf-cfrg-xchacha-03, section 2.2).

    Args:
        key: 32-byte ChaCha20 key.
        input16: 16-byte input (the first 16 bytes of an XChaCha20 nonce).

    Returns:
        The 32-byte derived subkey.

    Raises:
        ValidationError: If the key or input has an invalid type or length.
    """
    _validate_key(key)
    if input16 is None:
        raise ValidationError("HChaCha20 input cannot be None")
    if not isinstance(input16, (bytes, bytearray, memoryview)):
        raise ValidationError(
            f"HChaCha20 input must be bytes-like object, got {type(input16).__name__}"
        )
    if len(input16) != HCHACHA_INPUT_SIZE:
        raise ValidationError(
            f"HChaCha20 input must be {HCHACHA_INPUT_SIZE} bytes, got {len(input16)}"
        )

    key = bytes(key)
    input16 = bytes(input16)

    # One keystream block with the HChaCha input occupying the counter and
    # nonce words (state words 12-15). cryptography's ChaCha20 takes a
    # 16-byte nonce laid out as 4-byte little-endian counter || 12-byte nonce,
    # which is exactly words 12-15 of the initial state.
    cipher = Cipher(algorithms.ChaCha20(key, input16), mode=None)
    keystream = cipher.encryptor().update(b"\x00" * 64)

    ks_words = struct.unpack("<16I", keystream)
    in_words = struct.unpack("<4I", input16)

    # Undo the feed-forward on the words HChaCha20 outputs (0-3 and 12-15).
    out_words = [(ks_words[i] - _CHACHA_CONSTANTS[i]) & 0xFFFFFFFF for i in range(4)]
    out_words += [(ks_words[12 + i] - in_words[i]) & 0xFFFFFFFF for i in range(4)]
    return struct.pack("<8I", *out_words)


def _derive_subkey_and_nonce(key: bytes, nonce: bytes) -> tuple:
    """Derive the per-message ChaCha20-Poly1305 subkey and 12-byte nonce.

    Args:
        key: 32-byte XChaCha20 key.
        nonce: 24-byte XChaCha20 nonce.

    Returns:
        Tuple of (subkey bytearray, 12-byte nonce bytes). The caller must
        zeroize the subkey with secure_memzero after use.

    Raises:
        ValidationError: If the key or nonce has an invalid type or length.
    """
    if nonce is None:
        raise ValidationError("Nonce cannot be None")
    if not isinstance(nonce, (bytes, bytearray, memoryview)):
        raise ValidationError(f"Nonce must be bytes-like object, got {type(nonce).__name__}")
    if len(nonce) != XCHACHA_NONCE_SIZE:
        raise ValidationError(
            f"XChaCha20 nonce must be {XCHACHA_NONCE_SIZE} bytes, got {len(nonce)}"
        )
    nonce = bytes(nonce)
    subkey = bytearray(hchacha20(key, nonce[:HCHACHA_INPUT_SIZE]))
    chacha_nonce = b"\x00\x00\x00\x00" + nonce[HCHACHA_INPUT_SIZE:]
    return subkey, chacha_nonce


def xchacha20poly1305_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Encrypt with XChaCha20-Poly1305 using a full 192-bit nonce.

    Args:
        key: 32-byte key.
        nonce: 24-byte nonce; every byte affects the result.
        plaintext: Data to encrypt.
        associated_data: Optional additional authenticated data.

    Returns:
        Ciphertext with the 16-byte Poly1305 tag appended.

    Raises:
        ValidationError: For invalid key, nonce, or data types.
        EncryptionError: If the underlying cipher fails.
    """
    if plaintext is None:
        raise ValidationError("Data cannot be None")
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise ValidationError(f"Data must be bytes-like object, got {type(plaintext).__name__}")
    subkey, chacha_nonce = _derive_subkey_and_nonce(key, nonce)
    try:
        cipher = ChaCha20Poly1305(bytes(subkey))
        try:
            return cipher.encrypt(chacha_nonce, bytes(plaintext), associated_data)
        except Exception as e:
            raise EncryptionError(original_exception=e)
    finally:
        secure_memzero(subkey)


def xchacha20poly1305_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Decrypt XChaCha20-Poly1305 data encrypted with a full 192-bit nonce.

    Args:
        key: 32-byte key.
        nonce: 24-byte nonce used during encryption.
        ciphertext: Ciphertext with the 16-byte Poly1305 tag appended.
        associated_data: Optional additional authenticated data.

    Returns:
        The decrypted plaintext.

    Raises:
        ValidationError: For invalid key, nonce, or data types.
        AuthenticationError: If the Poly1305 tag does not verify.
        DecryptionError: If decryption fails for other reasons.
    """
    if ciphertext is None:
        raise ValidationError("Data cannot be None")
    if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
        raise ValidationError(f"Data must be bytes-like object, got {type(ciphertext).__name__}")
    if len(ciphertext) < POLY1305_TAG_SIZE:
        raise ValidationError("Ciphertext too short - missing authentication tag")
    subkey, chacha_nonce = _derive_subkey_and_nonce(key, nonce)
    try:
        cipher = ChaCha20Poly1305(bytes(subkey))
        try:
            return cipher.decrypt(chacha_nonce, bytes(ciphertext), associated_data)
        except cryptography.exceptions.InvalidTag:
            raise AuthenticationError("Integrity verification failed")
        except Exception as e:
            raise DecryptionError(original_exception=e)
    finally:
        secure_memzero(subkey)
