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
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Lazy python-pkcs11 loader
# --------------------------------------------------------------------------- #
def _load_pkcs11_module():
    """Import and return the ``pkcs11`` module, or raise a friendly error.

    Imported lazily so this module is usable without the binding, and so unit
    tests can substitute a fake ``pkcs11`` in ``sys.modules``.
    """
    try:
        import pkcs11
    except ImportError as exc:  # binding missing or broken
        raise PIVDependencyError(
            "python-pkcs11 is not installed or could not be imported. "
            "Install it with 'pip install python-pkcs11' and ensure a PKCS#11 "
            "module (e.g. opensc-pkcs11.so or ykcs11.so) is available on this system."
        ) from exc
    return pkcs11


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


# --------------------------------------------------------------------------- #
# PKCS11Library -- load and verify the PKCS#11 module (items 1 and 2)
# --------------------------------------------------------------------------- #
class PKCS11Library:
    """Loads and validates a PKCS#11 shared library by path.

    The path is always supplied by the caller -- it is never hardcoded. Both the
    file's existence (item 1) and its loadability (item 2) are verified before
    the library object is returned.
    """

    def __init__(self, lib_path: str):
        if not isinstance(lib_path, str) or not lib_path:
            raise PIVConfigurationError(
                "PKCS#11 library path must be a non-empty string supplied by the caller"
            )
        self.lib_path = lib_path
        self._lib = None

    def load(self):
        """Return the loaded PKCS#11 library object, loading it once and caching.

        Raises:
            PIVLibraryError: file missing or not loadable.
            PIVDependencyError: python-pkcs11 not installed.
        """
        if self._lib is not None:
            return self._lib

        # Item 1: verify the file exists before attempting to load it.
        if not os.path.isfile(self.lib_path):
            raise PIVLibraryError(
                f"PKCS#11 library not found at '{self.lib_path}'. "
                "Provide the correct path to a PKCS#11 module "
                "(e.g. /usr/lib/opensc-pkcs11.so or the YubiKey ykcs11 module)."
            )

        pkcs11 = _load_pkcs11_module()

        # Item 2: verify the library is actually loadable.
        try:
            self._lib = pkcs11.lib(self.lib_path)
        except (OSError, pkcs11.exceptions.PKCS11Error) as exc:
            raise PIVLibraryError(
                f"Failed to load PKCS#11 library '{self.lib_path}': {exc}. "
                "Verify the file is a valid PKCS#11 module for this platform/architecture."
            ) from exc
        except Exception as exc:  # any other binding-level failure
            raise PIVLibraryError(
                f"Failed to load PKCS#11 library '{self.lib_path}': {exc}."
            ) from exc

        return self._lib


# --------------------------------------------------------------------------- #
# TokenSession -- slot selection, login, PIN handling, session lifecycle
# (items 3, 4, 5, 8, 9, 14)
# --------------------------------------------------------------------------- #
class TokenSession:
    """Selects a token in a PKCS#11 slot and manages its authenticated session."""

    def __init__(self, library: PKCS11Library, slot_index: int = 0):
        if not isinstance(slot_index, int) or isinstance(slot_index, bool):
            raise PIVConfigurationError("slot_index must be an integer")
        if slot_index < 0:
            raise PIVConfigurationError("slot_index must be non-negative")
        self.library = library
        self.slot_index = slot_index
        self._token = None
        self._session = None

    def select_token(self):
        """Locate and validate the token in the configured slot.

        Verifies a slot with a token is present (item 3), the slot index is in
        range (item 4), and the token reports TOKEN_PRESENT (item 5).
        """
        lib = self.library.load()
        pkcs11 = _load_pkcs11_module()

        # Item 3: at least one slot with a token present.
        try:
            slots = lib.get_slots(token_present=True)
        except pkcs11.exceptions.PKCS11Error as exc:
            raise PIVTokenError(f"Failed to enumerate PKCS#11 slots: {exc}") from exc
        if not slots:
            raise PIVTokenError(
                "No PKCS#11 slot with a token present. Insert/connect the PIV token and retry."
            )

        # Item 4: the requested slot index is within bounds.
        if self.slot_index >= len(slots):
            raise PIVTokenError(
                f"PKCS#11 slot index {self.slot_index} is out of range; "
                f"{len(slots)} slot(s) with a token were found (valid indices 0..{len(slots) - 1})."
            )

        slot = slots[self.slot_index]
        try:
            token = slot.get_token()
        except pkcs11.exceptions.PKCS11Error as exc:
            raise PIVTokenError(
                f"Failed to read token in slot index {self.slot_index}: {exc}"
            ) from exc

        # Item 5: confirm the token is actually present.
        if not (token.flags & pkcs11.TokenFlag.TOKEN_PRESENT):
            raise PIVTokenError(
                f"No token present in slot index {self.slot_index} "
                "(TOKEN_PRESENT flag is not set)."
            )

        self._token = token
        return token
