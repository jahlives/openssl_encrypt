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

import ctypes
import logging
import os
from typing import Callable, Optional, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)


def _zero_bytearray(buf: bytearray) -> None:
    """Overwrite a mutable byte buffer in place with zeros (best-effort wipe)."""
    if not buf:
        return
    backing = (ctypes.c_char * len(buf)).from_buffer(buf)
    ctypes.memset(backing, 0, len(buf))


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

    def __enter__(self) -> "TokenSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        # Close on every exit path, including exceptions; never suppress them.
        self.close()
        return False

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

    def login(
        self,
        pin: Optional[Union[bytes, bytearray]] = None,
        *,
        confirm_final_attempt: Optional[Callable[[], bool]] = None,
    ):
        """Open an authenticated session on the selected token.

        Args:
            pin: ``None`` means biometric / empty-PIN login -- ``C_Login`` is
                called with ``b""`` so a Bio key waits for a fingerprint touch.
                ``bytes``/``bytearray`` is sent as the PIN and zeroed from memory
                before this method returns, on success or failure.
            confirm_final_attempt: called (with no args) only when the token
                reports its PIN is on the final try before lockout and a
                non-empty PIN was supplied. Must return True to proceed.

        The PIN never appears in logs, exceptions, or tracebacks. On any
        authentication failure a generic error is raised (no fallback).
        """
        if self._token is None:
            self.select_token()
        token = self._token
        pkcs11 = _load_pkcs11_module()

        biometric = pin is None
        if biometric:
            working = bytearray(b"")
        else:
            if not isinstance(pin, (bytes, bytearray)):
                raise PIVConfigurationError("pin must be bytes, bytearray, or None")
            working = bytearray(pin)

        session = None
        try:
            # Item 8: retry-counter guard for the PIN flow only (skip biometric).
            if not biometric:
                self._enforce_retry_guard(token, pkcs11, confirm_final_attempt)

            try:
                # Empty bytes for biometric; PIN bytes otherwise. Never None.
                session = token.open(rw=False, user_pin=bytes(working))
            except pkcs11.exceptions.PinLocked:
                # `from None`: never chain -- keeps any PIN-bearing frame out of the traceback.
                raise PIVAuthenticationError(
                    "Authentication failed: the token PIN is locked."
                ) from None
            except pkcs11.exceptions.PinIncorrect:
                if biometric:
                    raise PIVAuthenticationError(
                        "Authentication failed: the token rejected the empty-PIN/biometric "
                        "login. If this is a fingerprint (Bio) key, ensure a fingerprint is "
                        "enrolled and touch the sensor; if it is a PIN-only key, supply a PIN."
                    ) from None
                raise PIVAuthenticationError("Authentication failed") from None
            except pkcs11.exceptions.PKCS11Error:
                raise PIVAuthenticationError("Authentication failed") from None
        finally:
            # Zero our working copy and, if the caller passed a mutable buffer, theirs too.
            _zero_bytearray(working)
            if isinstance(pin, bytearray):
                _zero_bytearray(pin)

        self._session = session

        # Item 9: do not assume a non-raising open means we are authenticated.
        if not self._session_is_user_authenticated(session, pkcs11):
            self.close()
            raise PIVAuthenticationError("Authentication failed")

        return session

    @staticmethod
    def _enforce_retry_guard(token, pkcs11, confirm_final_attempt) -> None:
        """Refuse a PIN attempt that could lock the token without confirmation."""
        flags = token.flags
        if flags & pkcs11.TokenFlag.USER_PIN_LOCKED:
            raise PIVAuthenticationError("Authentication failed: the token PIN is locked.")
        if flags & pkcs11.TokenFlag.USER_PIN_FINAL_TRY:
            confirmed = bool(confirm_final_attempt()) if confirm_final_attempt else False
            if not confirmed:
                raise PIVAuthenticationError(
                    "Refusing to attempt the PIN: only one try remains before the token "
                    "locks. Re-run with explicit confirmation to proceed."
                )

    @staticmethod
    def _session_is_user_authenticated(session, pkcs11) -> bool:
        """Confirm the session reached a USER_FUNCTIONS state after login.

        Uses ``get_session_info().state`` when the binding exposes it. Some
        python-pkcs11 versions do not; in that case we trust ``token.open()``,
        which itself raises on a failed ``C_Login`` (the signer additionally
        exercises a login-gated operation on real hardware).
        """
        get_info = getattr(session, "get_session_info", None)
        if get_info is None:
            return True
        try:
            info = get_info()
        except Exception:
            return False
        state = getattr(info, "state", None)
        return state in (
            pkcs11.SessionState.RO_USER_FUNCTIONS,
            pkcs11.SessionState.RW_USER_FUNCTIONS,
        )

    def close(self) -> None:
        """Close the PKCS#11 session if one is open (idempotent)."""
        if self._session is not None:
            try:
                self._session.close()
            except Exception as exc:  # never mask the original error path
                logger.debug("Error while closing PKCS#11 session: %s", exc)
            finally:
                self._session = None


# --------------------------------------------------------------------------- #
# PIVSigner -- key detection, type validation, deterministic signing
# (items 6, 7, 10, 11, 12)
# --------------------------------------------------------------------------- #
class _PIVSignerMeta(type):
    """Expose SUPPORTED_KEY_TYPES lazily so the class needs no binding at import.

    Computed on attribute access (by which point python-pkcs11 -- real or the
    test fake -- is importable), keeping module import order irrelevant.
    """

    def __getattr__(cls, name):
        if name == "SUPPORTED_KEY_TYPES":
            pkcs11 = _load_pkcs11_module()
            return frozenset({pkcs11.KeyType.RSA, pkcs11.KeyType.EC_EDWARDS})
        raise AttributeError(name)


class PIVSigner(metaclass=_PIVSignerMeta):
    """Finds the PIV private key, validates its type, and signs deterministically.

    Only deterministic signature schemes are supported so the same key on
    multiple devices yields identical output: Ed25519 (RFC 8032) and RSA with
    PKCS#1 v1.5. ECDSA and RSA-PSS are randomized and are rejected.
    """

    # CKA_ID values OpenSC/ykcs11 assign to the PIV key slots.
    PIV_SLOT_TO_ID = {
        0x9A: b"\x01",
        0x9C: b"\x02",
        0x9D: b"\x03",
        0x9E: b"\x04",
    }

    # Expected raw signature lengths per key type (item 11).
    RSA_SIG_LEN = {2048: 256, 3072: 384, 4096: 512}
    ED25519_SIG_LEN = 64

    def __init__(self, piv_slot: int = 0x9A):
        if not isinstance(piv_slot, int) or isinstance(piv_slot, bool):
            raise PIVConfigurationError("piv_slot must be an integer (e.g. 0x9A)")
        if piv_slot not in self.PIV_SLOT_TO_ID:
            valid = ", ".join(f"{s:#x}" for s in self.PIV_SLOT_TO_ID)
            raise PIVConfigurationError(
                f"Unsupported PIV slot {piv_slot:#x}. Supported slots: {valid}."
            )
        self.piv_slot = piv_slot
        self._key = None

    def find_key(self, session):
        """Locate the private key in the configured PIV slot and validate its type.

        Verifies a signing key exists (item 6) and that its type is supported
        (item 7). Raises PIVKeyError otherwise.
        """
        pkcs11 = _load_pkcs11_module()
        key_id = self.PIV_SLOT_TO_ID[self.piv_slot]
        try:
            key = session.get_key(
                object_class=pkcs11.ObjectClass.PRIVATE_KEY,
                id=key_id,
            )
        except pkcs11.exceptions.NoSuchKey:
            raise PIVKeyError(
                f"No private key found in PIV slot {self.piv_slot:#x}. "
                "Import a key into that slot (see the PIV backend setup guide)."
            ) from None
        except pkcs11.exceptions.MultipleObjectsReturned:
            raise PIVKeyError(
                f"More than one key matched PIV slot {self.piv_slot:#x}; cannot choose unambiguously."
            ) from None
        except pkcs11.exceptions.PKCS11Error as exc:
            raise PIVKeyError(
                f"Failed to look up the key in PIV slot {self.piv_slot:#x}: {exc}"
            ) from exc

        self._validate_key_type(key, pkcs11)
        self._key = key
        return key

    @staticmethod
    def _validate_key_type(key, pkcs11) -> None:
        """Item 7: accept only deterministic key types; reject the rest clearly."""
        key_type = getattr(key, "key_type", None)
        if key_type == pkcs11.KeyType.RSA or key_type == pkcs11.KeyType.EC_EDWARDS:
            return
        if key_type == pkcs11.KeyType.EC:
            raise PIVKeyError(
                "ECDSA keys produce non-deterministic signatures and are not supported "
                "(they would break multi-device determinism). Use an Ed25519 or "
                "RSA (PKCS#1 v1.5) key instead."
            )
        raise PIVKeyError(
            f"Unsupported PIV key type: {key_type}. Supported types are RSA and Ed25519."
        )
