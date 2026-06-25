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
SLOT_TYPES = {"recovery_code", "passphrase", "pqc"}

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


# --- Passphrase recovery slots -------------------------------------------
#
# A recovery passphrase is human-chosen (lower entropy than a recovery code),
# so its KEK is derived with a slow memory-hard KDF (Argon2id) rather than
# HKDF. The Argon2 parameters are stored in the slot so unlock can reproduce
# the KEK. Self-contained (uses argon2-cffi directly; no generate_key coupling).

_PASSPHRASE_ARGON2_TIME = 3
_PASSPHRASE_ARGON2_MEMORY = 65536  # KiB (64 MiB)
_PASSPHRASE_ARGON2_PARALLELISM = 4


def _passphrase_kek(passphrase: bytes, salt: bytes, time_cost, memory_cost, parallelism) -> bytes:
    """Derive a 32-byte KEK from a recovery passphrase via Argon2id."""
    import argon2

    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")
    return argon2.low_level.hash_secret_raw(
        secret=bytes(passphrase),
        salt=bytes(salt),
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=argon2.low_level.Type.ID,
    )


def build_passphrase_slot(
    dek: bytes,
    passphrase: bytes,
    slot_id: str,
    time_cost: int = _PASSPHRASE_ARGON2_TIME,
    memory_cost: int = _PASSPHRASE_ARGON2_MEMORY,
    parallelism: int = _PASSPHRASE_ARGON2_PARALLELISM,
) -> dict:
    """Wrap the DEK under a recovery passphrase (Argon2id-derived KEK).

    Args:
        dek: The envelope DEK to protect.
        passphrase: The recovery passphrase (str or bytes).
        slot_id: Unique identifier for this slot.
        time_cost / memory_cost / parallelism: Argon2id parameters (stored so
            unlock can reproduce the KEK).

    Returns:
        A slot dict with the Argon2 parameters in params.
    """
    from .envelope import wrap_dek

    salt = secrets.token_bytes(_RECOVERY_SLOT_SALT_BYTES)
    kek = _passphrase_kek(passphrase, salt, time_cost, memory_cost, parallelism)
    wrapped = wrap_dek(bytes(dek), kek)
    return {
        "id": slot_id,
        "type": "passphrase",
        "wrap": base64.b64encode(wrapped).decode("ascii"),
        "params": {
            "salt": base64.b64encode(salt).decode("ascii"),
            "argon2": {
                "time_cost": time_cost,
                "memory_cost": memory_cost,
                "parallelism": parallelism,
            },
        },
    }


def unlock_passphrase_slot(slot: dict, passphrase: bytes) -> bytearray:
    """Recover the DEK from a passphrase slot.

    Args:
        slot: A passphrase slot dict (as stored in metadata).
        passphrase: The recovery passphrase (str or bytes).

    Returns:
        The recovered DEK as a mutable bytearray (caller should zeroize).

    Raises:
        ValidationError: If the slot is malformed.
        DecryptionError: If the passphrase is wrong or the slot was tampered.
    """
    from .crypt_errors import ValidationError

    if slot.get("type") != "passphrase":
        raise ValidationError("Not a passphrase slot")
    from .envelope import unwrap_dek

    params = slot["params"]
    a = params["argon2"]
    kek = _passphrase_kek(
        passphrase,
        base64.b64decode(params["salt"]),
        a["time_cost"],
        a["memory_cost"],
        a["parallelism"],
    )
    return unwrap_dek(base64.b64decode(slot["wrap"]), kek)


# --- PQC recipient recovery slots ----------------------------------------
#
# Wrap the DEK under a recovery recipient's ML-KEM public key (e.g. an offline
# escrow identity). KEM-encapsulation yields a shared secret; the DEK is wrapped
# under an HKDF of that secret. Recovery requires the recipient's private key.

_PQC_INFO = b"openssl_encrypt.envelope.pqc-recipient-kek.v1"


def _pqc_kek(shared_secret: bytes, salt: bytes) -> bytes:
    """Derive the 32-byte KEK from a KEM shared secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(salt),
        info=_PQC_INFO,
    ).derive(bytes(shared_secret))


def build_pqc_slot(
    dek: bytes,
    recipient_public_key: bytes,
    kem_algorithm: str,
    slot_id: str,
    key_id: str = None,
) -> dict:
    """Wrap the DEK under a recovery recipient's ML-KEM public key.

    Args:
        dek: The envelope DEK to protect.
        recipient_public_key: The recovery recipient's KEM public key.
        kem_algorithm: The KEM algorithm (e.g. "ML-KEM-768").
        slot_id: Unique identifier for this slot.
        key_id: Optional recipient fingerprint, stored for display/selection.

    Returns:
        A slot dict with the encapsulated key in params.
    """
    from .asymmetric_core import PasswordWrapper
    from .envelope import wrap_dek

    wrapper = PasswordWrapper(kem_algorithm, quiet=True)
    encapsulated_key, shared_secret = wrapper.encapsulate(recipient_public_key)
    shared = bytearray(shared_secret)
    try:
        salt = secrets.token_bytes(_RECOVERY_SLOT_SALT_BYTES)
        kek = _pqc_kek(bytes(shared), salt)
        wrapped = wrap_dek(bytes(dek), kek)
    finally:
        from .secure_memory import secure_memzero

        secure_memzero(shared)
    params = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "kem_algorithm": kem_algorithm,
        "encapsulated_key": base64.b64encode(encapsulated_key).decode("ascii"),
    }
    if key_id is not None:
        params["key_id"] = key_id
    return {
        "id": slot_id,
        "type": "pqc",
        "wrap": base64.b64encode(wrapped).decode("ascii"),
        "params": params,
    }


def unlock_pqc_slot(slot: dict, recipient_private_key: bytes) -> bytearray:
    """Recover the DEK from a PQC slot using the recipient's private key.

    Args:
        slot: A pqc slot dict (as stored in metadata).
        recipient_private_key: The recovery recipient's KEM private key bytes.

    Returns:
        The recovered DEK as a mutable bytearray (caller should zeroize).

    Raises:
        ValidationError: If the slot is malformed.
        DecryptionError: If the key is wrong or the slot was tampered with.
    """
    from .crypt_errors import ValidationError

    if slot.get("type") != "pqc":
        raise ValidationError("Not a pqc slot")
    from .asymmetric_core import PasswordWrapper
    from .envelope import unwrap_dek
    from .secure_memory import secure_memzero

    params = slot["params"]
    wrapper = PasswordWrapper(params["kem_algorithm"], quiet=True)
    shared_secret = wrapper.decapsulate(
        base64.b64decode(params["encapsulated_key"]), recipient_private_key
    )
    shared = bytearray(shared_secret)
    try:
        kek = _pqc_kek(bytes(shared), base64.b64decode(params["salt"]))
        return unwrap_dek(base64.b64decode(slot["wrap"]), kek)
    finally:
        secure_memzero(shared)


# --- Slot-set construction dispatcher ------------------------------------


def build_recovery_slots(dek: bytes, credentials: List[dict]) -> List[dict]:
    """Build the recovery-slot list for a set of recovery credentials.

    Args:
        dek: The envelope DEK to wrap under each recovery credential.
        credentials: A list of credential specs. Each must have a ``type`` in
            SLOT_TYPES plus the type-specific material, e.g.
            ``{"type": "recovery_code", "code": "<code>"}``.

    Returns:
        A list of stored-shape slot dicts with unique ids.

    Raises:
        ValidationError: If a credential has an unsupported or missing type.
    """
    from .crypt_errors import ValidationError

    slots: List[dict] = []
    for index, cred in enumerate(credentials or []):
        ctype = cred.get("type")
        if ctype == "recovery_code":
            slots.append(
                build_recovery_code_slot(dek, cred["code"], slot_id=f"recovery_code-{index}")
            )
        elif ctype == "pqc":
            slots.append(
                build_pqc_slot(
                    dek,
                    cred["public_key"],
                    cred["kem_algorithm"],
                    slot_id=f"pqc-{index}",
                    key_id=cred.get("key_id"),
                )
            )
        elif ctype == "passphrase":
            kwargs = {
                k: cred[k]
                for k in ("time_cost", "memory_cost", "parallelism")
                if k in cred
            }
            slots.append(
                build_passphrase_slot(
                    dek, cred["passphrase"], slot_id=f"passphrase-{index}", **kwargs
                )
            )
        else:
            raise ValidationError(f"Unsupported recovery slot type: {ctype!r}")
    return slots


# --- CLI handlers --------------------------------------------------------
#
# These wrap the recovery-slot API (crypt_core add/remove/list_recovery_slots
# and decrypt_file) for the list-recovery / add-recovery / remove-recovery /
# recover subcommands. All human output goes to stderr via eprint (stdout is
# reserved for piped data), matching secret_sharing's CLI convention.


def _read_password(args, prompt="Password: "):
    """Resolve a password from --password, $CRYPT_PASSWORD, or a prompt."""
    import getpass
    import os

    pw = getattr(args, "password", None)
    if pw is None:
        pw = os.environ.get("CRYPT_PASSWORD")
    if pw is None:
        pw = getpass.getpass(prompt)
    return pw.encode("utf-8") if isinstance(pw, str) else pw


def _recover_kwargs_from_args(args):
    """Build decrypt/unlock recovery kwargs from CLI args (one credential)."""
    if getattr(args, "recovery_code", None):
        return {"recovery_code": args.recovery_code}
    if getattr(args, "recovery_passphrase", False):
        import getpass

        return {"recovery_passphrase": getpass.getpass("Recovery passphrase: ")}
    return {}


def list_recovery_cli(args) -> None:
    """`list-recovery`: print the recovery slots in a file (no credential)."""
    from .crypt_core import list_recovery_slots
    from .crypt_utils import eprint

    slots = list_recovery_slots(args.input)
    if not slots:
        eprint("No recovery slots on this file.")
        return
    eprint(f"{len(slots)} recovery slot(s):")
    for s in slots:
        line = f"  id={s['id']}  type={s['type']}"
        if s.get("key_id"):
            line += f"  key_id={s['key_id'][:16]}..."
        eprint(line)


def recover_cli(args) -> None:
    """`recover`: decrypt a file using a recovery credential (not the password)."""
    from .crypt_core import decrypt_file
    from .crypt_utils import eprint

    kwargs = _recover_kwargs_from_args(args)
    if not kwargs:
        raise ValueError(
            "Provide a recovery credential: --recovery-code, "
            "--recovery-passphrase, or --recovery-share"
        )
    decrypt_file(
        input_file=args.input,
        output_file=args.output,
        quiet=getattr(args, "quiet", False),
        **kwargs,
    )
    eprint(f"Recovered to: {args.output}")


def add_recovery_cli(args) -> None:
    """`add-recovery`: add a recovery slot to an existing envelope file.

    Unlock with --password (or an existing --recovery-code); add one of
    --add-code (generated and printed) or --add-passphrase (prompted).
    """
    import getpass

    from .crypt_core import add_recovery_slots
    from .crypt_utils import eprint

    # How to unlock the existing file (to recover the DEK).
    unlock = {}
    if getattr(args, "recovery_code", None):
        unlock["recovery_code"] = args.recovery_code
    else:
        unlock["password"] = _read_password(args)

    creds = []
    generated_code = None
    if getattr(args, "add_code", False):
        generated_code = generate_recovery_code()
        creds.append({"type": "recovery_code", "code": generated_code})
    elif getattr(args, "add_passphrase", False):
        p1 = getpass.getpass("New recovery passphrase: ")
        p2 = getpass.getpass("Confirm recovery passphrase: ")
        if p1 != p2:
            raise ValueError("Recovery passphrases do not match")
        creds.append({"type": "passphrase", "passphrase": p1})
    else:
        raise ValueError("Specify --add-code or --add-passphrase")

    add_recovery_slots(args.input, args.output, creds, **unlock)
    eprint(f"Recovery slot added; wrote: {args.output}")
    if generated_code is not None:
        eprint("\n=== RECOVERY CODE (store this securely; it is shown only once) ===")
        eprint(f"  {generated_code}")


def remove_recovery_cli(args) -> None:
    """`remove-recovery`: remove a recovery slot by id from an envelope file."""
    from .crypt_core import remove_recovery_slot
    from .crypt_utils import eprint

    unlock = {}
    if getattr(args, "recovery_code", None):
        unlock["recovery_code"] = args.recovery_code
    else:
        unlock["password"] = _read_password(args)
    remove_recovery_slot(args.input, args.output, args.slot_id, **unlock)
    eprint(f"Removed recovery slot {args.slot_id!r}; wrote: {args.output}")
