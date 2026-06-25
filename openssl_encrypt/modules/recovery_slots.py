#!/usr/bin/env python3
"""
Recovery-slot set authentication for the symmetric envelope.

A recovery slot is an *additional* wrapping of the envelope DEK under an
independent key-encryption key (a generated recovery code, a second passphrase,
a Shamir-reconstructed secret, or a recovery recipient's public key). Slots are
stored in ``metadata["encryption"]["dek_slots"]`` and are purely additive: the
primary ``wrapped_dek`` remains canonical, so files without recovery slots are
unchanged and remain readable by older code.

This module provides the security-critical integrity layer for the slot SET:
a MAC keyed by the DEK that lets a decryptor detect stripping, injection, or
modification of recovery slots *after* it has recovered the DEK through any
single valid slot.

The MAC is keyed by the DEK (via HKDF) rather than by the bulk AEAD's AAD on
purpose: it keeps the bulk ciphertext's AAD stable across rekey and post-hoc
slot management (so the O(header) fast-path is preserved), while still binding
the slot set. An attacker who cannot unwrap any slot never learns the DEK and
therefore cannot forge the MAC; a legitimate holder (who necessarily has the
DEK to add/remove a slot) can re-authenticate the set.
"""

import base64
import hashlib
import hmac
import json
import secrets
from typing import List

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .secure_ops import constant_time_compare

# The recovery-credential types a slot may use to wrap the DEK.
SLOT_TYPES = {"recovery_code", "passphrase", "shamir", "pqc"}

# Domain separation for the slot-set MAC key derived from the DEK.
_SLOT_SET_MAC_INFO = b"openssl_encrypt.envelope.slot-set-mac.v1"
_SLOT_SET_MAC_LEN = 32

# Recovery code: 256 bits of entropy, shown to the user as grouped base32.
_RECOVERY_CODE_BYTES = 32
_RECOVERY_CODE_GROUP = 5
_RECOVERY_CODE_INFO = b"openssl_encrypt.envelope.recovery-code-kek.v1"
_RECOVERY_SLOT_SALT_BYTES = 16
_BASE32_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def canonical_slots(slots: List[dict]) -> bytes:
    """Deterministically serialize the recovery-slot list for MAC computation.

    The serialization is independent of dict key ordering but preserves slot
    list order (slot order is part of the authenticated set).

    Args:
        slots: The recovery-slot list as stored in metadata (list of dicts).

    Returns:
        A canonical UTF-8 byte serialization.
    """
    return json.dumps(
        slots, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _derive_slot_set_mac_key(dek: bytes) -> bytes:
    """Derive the slot-set MAC key from the DEK via HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_SLOT_SET_MAC_LEN,
        salt=None,
        info=_SLOT_SET_MAC_INFO,
    ).derive(bytes(dek))


def compute_slot_set_mac(dek: bytes, slots: List[dict]) -> bytes:
    """Compute the DEK-keyed HMAC-SHA256 over the canonical recovery-slot set.

    Args:
        dek: The envelope data encryption key (>= 16 bytes).
        slots: The recovery-slot list as stored in metadata.

    Returns:
        A 32-byte MAC binding the slot set to the DEK.
    """
    mac_key = _derive_slot_set_mac_key(dek)
    return hmac.new(mac_key, canonical_slots(slots), hashlib.sha256).digest()


def verify_slot_set_mac(dek: bytes, slots: List[dict], mac: bytes) -> bool:
    """Verify a recovery-slot set MAC in constant time.

    Args:
        dek: The recovered envelope DEK.
        slots: The recovery-slot list as read from metadata.
        mac: The stored slot-set MAC to check against.

    Returns:
        True iff ``mac`` is the valid slot-set MAC for ``(dek, slots)``.
    """
    if not isinstance(mac, (bytes, bytearray)) or len(mac) != _SLOT_SET_MAC_LEN:
        return False
    expected = compute_slot_set_mac(dek, slots)
    return constant_time_compare(expected, bytes(mac))


# --- Recovery-code slots -------------------------------------------------
#
# A recovery code is a freshly generated 256-bit secret shown to the user as
# grouped base32. Because it is high-entropy, its key-encryption key is derived
# with HKDF (no slow KDF needed) from the decoded code and a per-slot salt; the
# DEK is then wrapped under that KEK with the standard envelope AES-256-GCM.


def generate_recovery_code() -> str:
    """Generate a fresh 256-bit recovery code as grouped, uppercase base32.

    Returns:
        A human-transcribable string like ``ABCDE-FGHIJ-...`` (no padding).
    """
    raw = secrets.token_bytes(_RECOVERY_CODE_BYTES)
    encoded = base64.b32encode(raw).decode("ascii").rstrip("=")
    groups = [
        encoded[i : i + _RECOVERY_CODE_GROUP]
        for i in range(0, len(encoded), _RECOVERY_CODE_GROUP)
    ]
    return "-".join(groups)


def normalize_recovery_code(code: str) -> bytes:
    """Decode a (possibly noisy) recovery code back to its raw key material.

    Tolerant of case, whitespace, and grouping separators.

    Args:
        code: The recovery code string as typed by the user.

    Returns:
        The decoded raw bytes.

    Raises:
        ValidationError: If the code is empty or not valid base32.
    """
    from .crypt_errors import ValidationError

    if not isinstance(code, str):
        raise ValidationError("Recovery code must be a string")
    cleaned = "".join(ch for ch in code.upper() if ch in _BASE32_ALPHABET)
    if not cleaned:
        raise ValidationError("Recovery code is empty or malformed")
    padded = cleaned + "=" * ((-len(cleaned)) % 8)
    try:
        return base64.b32decode(padded)
    except Exception as exc:  # noqa: BLE001 - normalize to a domain error
        raise ValidationError("Recovery code is not valid base32") from exc


def _recovery_code_kek(code: str, salt: bytes) -> bytes:
    """Derive the 32-byte KEK for a recovery-code slot."""
    material = normalize_recovery_code(code)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(salt),
        info=_RECOVERY_CODE_INFO,
    ).derive(material)


def build_recovery_code_slot(dek: bytes, code: str, slot_id: str) -> dict:
    """Wrap the DEK under a recovery code, returning a stored-shape slot dict.

    Args:
        dek: The envelope DEK to protect.
        code: The recovery code (as generated/displayed).
        slot_id: A unique identifier for this slot within the file.

    Returns:
        A slot dict: ``{id, type, wrap, params:{salt}}`` (base64-encoded blobs).
    """
    from .envelope import wrap_dek

    salt = secrets.token_bytes(_RECOVERY_SLOT_SALT_BYTES)
    kek = _recovery_code_kek(code, salt)
    wrapped = wrap_dek(bytes(dek), kek)
    return {
        "id": slot_id,
        "type": "recovery_code",
        "wrap": base64.b64encode(wrapped).decode("ascii"),
        "params": {"salt": base64.b64encode(salt).decode("ascii")},
    }


def unlock_recovery_code_slot(slot: dict, code: str) -> bytearray:
    """Recover the DEK from a recovery-code slot.

    Args:
        slot: A recovery-code slot dict (as stored in metadata).
        code: The recovery code supplied by the user.

    Returns:
        The recovered DEK as a mutable bytearray (caller should zeroize).

    Raises:
        ValidationError: If the slot is malformed.
        DecryptionError: If the code is wrong or the slot was tampered with.
    """
    from .crypt_errors import ValidationError

    if slot.get("type") != "recovery_code":
        raise ValidationError("Not a recovery_code slot")
    from .envelope import unwrap_dek

    salt = base64.b64decode(slot["params"]["salt"])
    kek = _recovery_code_kek(code, salt)
    return unwrap_dek(base64.b64decode(slot["wrap"]), kek)
