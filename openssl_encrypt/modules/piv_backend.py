#!/usr/bin/env python3
"""PIV / PKCS#11 hardware backend for ``openssl_encrypt``.

This module implements a hardware-bound *pepper* source backed by a PIV
application on a PKCS#11 token (YubiKey Bio MPE, Token2 PIN+ R3.3+, or any
compliant PIV smart card).  Unlike the HMAC-SHA1 challenge-response backends, a
PIV key *signs* a deterministic challenge and the signature is normalized into a
fixed-length pepper via HKDF-SHA256.

The fundamental guarantee is **multi-device redundancy**: the same private key
imported on multiple tokens produces byte-for-byte identical pepper output for
the same input.  That only holds for *deterministic* signature schemes, so this
backend supports Ed25519 (RFC 8032) and RSA PKCS#1 v1.5 and explicitly rejects
randomized schemes (ECDSA, RSA-PSS).

Architecture (each component is independently unit-testable with a mocked
PKCS#11 layer):

    PKCS11Library     -- loads/validates the .so/.dll module
    TokenSession      -- slot selection, login, PIN handling, session lifecycle
    PIVSigner         -- key detection, key-type validation, deterministic signing
    PepperDerivation  -- HKDF-SHA256 challenge + pepper, fixed output length
    PIVBackend        -- orchestrates the above; get_pepper() / verify_hardware()

``python-pkcs11`` is imported lazily (only when a hardware operation is actually
performed) so that this module is importable, and PepperDerivation is usable,
without the binding installed.
"""

import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Exception hierarchy -- every PKCS#11 failure is translated to one of these
# with a descriptive, PIN-free message (security requirement: no silent errors).
# --------------------------------------------------------------------------- #
class PIVError(Exception):
    """Base class for all PIV backend errors."""


class PIVDependencyError(PIVError):
    """The python-pkcs11 binding is missing or unusable."""


class PIVConfigurationError(PIVError):
    """Invalid caller-supplied configuration (slot, length, path argument)."""


class PIVLibraryError(PIVError):
    """The PKCS#11 library file is missing or cannot be loaded."""


class PIVTokenError(PIVError):
    """No token / slot problem (no slot list, bad index, token absent)."""


class PIVKeyError(PIVError):
    """The PIV slot has no usable signing key, or an unsupported key type."""


class PIVAuthenticationError(PIVError):
    """Login/PIN/biometric authentication failed (message is always generic)."""


class PIVSignatureError(PIVError):
    """The signing operation failed or produced an invalid signature."""


class PIVDeterminismError(PIVError):
    """The key/mechanism did not produce a deterministic signature."""


# --------------------------------------------------------------------------- #
# HKDF challenge / pepper derivation (verification-table item 13)
# --------------------------------------------------------------------------- #
# HKDF-SHA256 can emit at most 255 * hash_len bytes.
_HKDF_MAX_OUTPUT = 255 * 32


class PepperDerivation:
    """Derive the signing challenge and the final pepper via HKDF-SHA256.

    Both derivations use the same fixed salt and distinct ``info`` labels so the
    challenge and the pepper are domain-separated.  Output lengths are verified
    explicitly rather than assumed.
    """

    HKDF_SALT = b"openssl_encrypt-piv-v1"
    CHALLENGE_INFO = b"piv-challenge"
    PEPPER_INFO = b"piv-pepper"
    CHALLENGE_LENGTH = 64

    def __init__(self, pepper_length: int = 32):
        if not isinstance(pepper_length, int):
            raise PIVConfigurationError("pepper_length must be an integer")
        if pepper_length <= 0:
            raise ValueError("pepper_length must be a positive number of bytes")
        if pepper_length > _HKDF_MAX_OUTPUT:
            raise ValueError(
                f"pepper_length must not exceed {_HKDF_MAX_OUTPUT} bytes (HKDF-SHA256 limit)"
            )
        self.pepper_length = pepper_length

    @classmethod
    def _hkdf(cls, ikm: bytes, info: bytes, length: int) -> bytes:
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=cls.HKDF_SALT,
            info=info,
        ).derive(ikm)
        # Item 13: verify the output length, never assume it.
        if len(derived) != length:
            raise PIVSignatureError(f"HKDF produced {len(derived)} bytes, expected {length}")
        return derived

    def derive_challenge(self, input_data: bytes) -> bytes:
        """HKDF-SHA256 the input into the fixed 64-byte signing challenge."""
        if not input_data:
            raise ValueError("input_data must be non-empty")
        return self._hkdf(input_data, self.CHALLENGE_INFO, self.CHALLENGE_LENGTH)

    def derive_pepper(self, raw_signature: bytes) -> bytes:
        """HKDF-SHA256 the raw signature into a fixed-length pepper.

        Normalizes RSA-2048 (256-byte), RSA-4096 (512-byte) and Ed25519
        (64-byte) signatures to ``pepper_length`` bytes.
        """
        if not raw_signature:
            raise ValueError("raw_signature must be non-empty")
        return self._hkdf(raw_signature, self.PEPPER_INFO, self.pepper_length)
