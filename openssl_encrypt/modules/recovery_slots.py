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

from .secure_memory import secure_memzero
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

# Shamir slots wrap the DEK under a high-entropy recovery secret that is split
# k-of-n via modules/secret_sharing.py. The slot stores only the wrap and the
# (informational) threshold parameters -- never the secret or any share.
_SHAMIR_INFO = b"openssl_encrypt.envelope.shamir-secret-kek.v1"


def canonical_slots(slots: List[dict]) -> bytes:
    """Deterministically serialize the recovery-slot list for MAC computation.

    The serialization is independent of dict key ordering but preserves slot
    list order (slot order is part of the authenticated set).

    Args:
        slots: The recovery-slot list as stored in metadata (list of dicts).

    Returns:
        A canonical UTF-8 byte serialization.
    """
    return json.dumps(slots, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


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
        encoded[i : i + _RECOVERY_CODE_GROUP] for i in range(0, len(encoded), _RECOVERY_CODE_GROUP)
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
    material = bytearray(normalize_recovery_code(code))
    try:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=bytes(salt),
            info=_RECOVERY_CODE_INFO,
        ).derive(bytes(material))
    finally:
        secure_memzero(material)


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
    kek = bytearray(_recovery_code_kek(code, salt))
    try:
        wrapped = wrap_dek(bytes(dek), kek)
    finally:
        secure_memzero(kek)
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
    kek = bytearray(_recovery_code_kek(code, salt))
    try:
        return unwrap_dek(base64.b64decode(slot["wrap"]), kek)
    finally:
        secure_memzero(kek)


# --- Shamir (k-of-n) recovery slots --------------------------------------
#
# The recovery secret is generated and split into shares by the caller (reusing
# modules/secret_sharing.py); this module only wraps the DEK under that secret
# and unwraps it once the secret has been reconstructed from >= threshold
# shares. The wrap mechanism mirrors recovery_code: HKDF(secret, salt) -> KEK.


def _shamir_kek(secret: bytes, salt: bytes) -> bytes:
    """Derive the 32-byte KEK for a Shamir slot from the recovery secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(salt),
        info=_SHAMIR_INFO,
    ).derive(bytes(secret))


def build_shamir_slot(
    dek: bytes,
    secret: bytes,
    slot_id: str,
    threshold: int,
    num_shares: int,
    key_id: str = None,
) -> dict:
    """Wrap the DEK under a Shamir-split recovery secret.

    The caller is responsible for splitting ``secret`` into shares (via
    secret_sharing.split_secret) and distributing them; the slot itself stores
    only the wrap and the threshold parameters.

    Args:
        dek: The envelope DEK to protect.
        secret: The high-entropy recovery secret (will be Shamir-split).
        slot_id: Unique identifier for this slot.
        threshold: k -- minimum shares needed (informational, stored).
        num_shares: n -- total shares created (informational, stored).
        key_id: Optional share-set id to bind shares to this slot.

    Returns:
        A slot dict: ``{id, type, wrap, params:{salt, shamir:{...}}}``.
    """
    from .envelope import wrap_dek

    salt = secrets.token_bytes(_RECOVERY_SLOT_SALT_BYTES)
    kek = bytearray(_shamir_kek(secret, salt))
    try:
        wrapped = wrap_dek(bytes(dek), kek)
    finally:
        secure_memzero(kek)
    shamir_params = {"threshold": threshold, "num_shares": num_shares}
    if key_id is not None:
        shamir_params["key_id"] = key_id
    return {
        "id": slot_id,
        "type": "shamir",
        "wrap": base64.b64encode(wrapped).decode("ascii"),
        "params": {"salt": base64.b64encode(salt).decode("ascii"), "shamir": shamir_params},
    }


def unlock_shamir_slot(slot: dict, secret: bytes) -> bytearray:
    """Recover the DEK from a Shamir slot using the reconstructed secret.

    Args:
        slot: A shamir slot dict (as stored in metadata).
        secret: The recovery secret reconstructed from >= threshold shares.

    Returns:
        The recovered DEK as a mutable bytearray (caller should zeroize).

    Raises:
        ValidationError: If the slot is malformed.
        DecryptionError: If the secret is wrong or the slot was tampered with.
    """
    from .crypt_errors import ValidationError

    if slot.get("type") != "shamir":
        raise ValidationError("Not a shamir slot")
    from .envelope import unwrap_dek

    salt = base64.b64decode(slot["params"]["salt"])
    kek = bytearray(_shamir_kek(secret, salt))
    try:
        return unwrap_dek(base64.b64decode(slot["wrap"]), kek)
    finally:
        secure_memzero(kek)


# --- Passphrase recovery slots -------------------------------------------
#
# A recovery passphrase is human-chosen (lower entropy than a recovery code),
# so its KEK is derived with a slow memory-hard KDF (Argon2id) rather than
# HKDF. The Argon2 parameters are stored in the slot so unlock can reproduce
# the KEK. Self-contained (uses argon2-cffi directly; no generate_key coupling).

_PASSPHRASE_ARGON2_TIME = 3
_PASSPHRASE_ARGON2_MEMORY = 65536  # KiB (64 MiB)
_PASSPHRASE_ARGON2_PARALLELISM = 4

# Upper bounds on Argon2 cost parameters read from a slot. These parameters come
# from the (untrusted) file and are consumed BEFORE the slot-set MAC can be
# verified (the MAC key is derived from the DEK, which requires this very KDF), so
# a tampered slot could otherwise set memory_cost to gigabytes and OOM/crash the
# host. Legitimate slots use the defaults above, far under these caps (#73).
_PASSPHRASE_ARGON2_MAX_TIME = 64
_PASSPHRASE_ARGON2_MAX_MEMORY = 2 * 1024 * 1024  # KiB (2 GiB)
_PASSPHRASE_ARGON2_MAX_PARALLELISM = 16

# The maximum number of recovery slots processed on any recovery-unlock path
# before the slot-set MAC is verified (gitlab#233, scan F16). dek_slots is
# attacker-controlled plaintext excluded from the bulk AAD, and each passphrase
# slot triggers a full Argon2id run; a crafted file with hundreds of slots would
# otherwise exhaust CPU before the tampered set is rejected. A legitimate
# recovery-enabled file has a handful of slots, so this cap is generous headroom.
MAX_DEK_SLOTS = 32


def _validate_argon2_params(time_cost, memory_cost, parallelism) -> None:
    """Reject out-of-range Argon2 cost params from an untrusted slot (#73)."""
    from .crypt_errors import ValidationError

    checks = (
        ("time_cost", time_cost, 1, _PASSPHRASE_ARGON2_MAX_TIME),
        ("memory_cost", memory_cost, 8, _PASSPHRASE_ARGON2_MAX_MEMORY),
        ("parallelism", parallelism, 1, _PASSPHRASE_ARGON2_MAX_PARALLELISM),
    )
    for name, value, lo, hi in checks:
        # bool is an int subclass; reject it and any non-int explicitly.
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValidationError(f"Invalid Argon2 {name} in recovery slot: {value!r}")
        if not (lo <= value <= hi):
            raise ValidationError(
                f"Argon2 {name} in recovery slot out of allowed range " f"[{lo}, {hi}]: {value}"
            )


def _passphrase_kek(passphrase: bytes, salt: bytes, time_cost, memory_cost, parallelism) -> bytes:
    """Derive a 32-byte KEK from a recovery passphrase via Argon2id."""
    import argon2

    _validate_argon2_params(time_cost, memory_cost, parallelism)
    if isinstance(passphrase, str):
        # surrogateescape, not strict: a strict encode raises UnicodeEncodeError
        # whose message embeds a byte of the passphrase and its offset, printed
        # verbatim by the generic CLI handler -- outside debug_secret(). Identical
        # bytes for any surrogate-free string, so no existing slot's KEK changes.
        # A lone HIGH surrogate is still outside surrogateescape's range; re-raise
        # carrying nothing value-derived rather than let it leak (gitlab#147).
        try:
            passphrase = passphrase.encode("utf-8", "surrogateescape")
        except UnicodeEncodeError:
            raise ValueError(
                "recovery passphrase could not be encoded (contains an unpaired surrogate)"
            ) from None
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
    kek = bytearray(_passphrase_kek(passphrase, salt, time_cost, memory_cost, parallelism))
    try:
        wrapped = wrap_dek(bytes(dek), kek)
    finally:
        secure_memzero(kek)
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
    kek = bytearray(
        _passphrase_kek(
            passphrase,
            base64.b64decode(params["salt"]),
            a["time_cost"],
            a["memory_cost"],
            a["parallelism"],
        )
    )
    try:
        return unwrap_dek(base64.b64decode(slot["wrap"]), kek)
    finally:
        secure_memzero(kek)


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
    kek = None
    try:
        salt = secrets.token_bytes(_RECOVERY_SLOT_SALT_BYTES)
        kek = bytearray(_pqc_kek(bytes(shared), salt))
        wrapped = wrap_dek(bytes(dek), kek)
    finally:
        secure_memzero(shared)
        if kek is not None:
            secure_memzero(kek)
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
    kek = None
    try:
        kek = bytearray(_pqc_kek(bytes(shared), base64.b64decode(params["salt"])))
        return unwrap_dek(base64.b64decode(slot["wrap"]), kek)
    finally:
        secure_memzero(shared)
        if kek is not None:
            secure_memzero(kek)


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
        elif ctype == "shamir":
            slots.append(
                build_shamir_slot(
                    dek,
                    cred["secret"],
                    slot_id=f"shamir-{index}",
                    threshold=cred["threshold"],
                    num_shares=cred["num_shares"],
                    key_id=cred.get("key_id"),
                )
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
            kwargs = {k: cred[k] for k in ("time_cost", "memory_cost", "parallelism") if k in cred}
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

    from .crypt_utils import eprint

    pw = getattr(args, "password", None)
    if pw is not None:
        # -p/--password is visible in the world-readable /proc/PID/cmdline;
        # prefer $CRYPT_PASSWORD. Not silenced by --quiet, matching the
        # --rekey-password warning (gitlab#147).
        eprint(
            "WARNING: --password is visible in process list. "
            "Use the CRYPT_PASSWORD env var instead."
        )
    if pw is None:
        pw = os.environ.get("CRYPT_PASSWORD")
    if pw is None:
        pw = getpass.getpass(prompt)
    if not isinstance(pw, str):
        return pw
    # surrogateescape round-trips bytes os.environ/argv decoded the same way; a
    # strict encode would raise UnicodeEncodeError whose message embeds a byte of
    # the password (gitlab#147). A lone HIGH surrogate is refused value-free.
    try:
        return pw.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        raise ValueError("password could not be encoded (contains an unpaired surrogate)") from None


def _recover_kwargs_from_args(args):
    """Build decrypt/unlock recovery kwargs from CLI args (one credential)."""
    if getattr(args, "recovery_code", None):
        return {"recovery_code": args.recovery_code}
    if getattr(args, "recovery_passphrase", False):
        import getpass

        return {"recovery_passphrase": getpass.getpass("Recovery passphrase: ")}
    if getattr(args, "recovery_share", None):
        from .secret_sharing import Share

        return {"recovery_shares": [Share.from_file(p) for p in args.recovery_share]}
    return {}


def _capped(value, limit=256):
    """Bound an untrusted header field before echoing it into JSON output.

    id/type/key_id are copied verbatim out of the plaintext file header, so a
    crafted file could otherwise drive an arbitrarily large stdout document at
    a consumer that buffers the whole thing. A non-string is not merely long,
    it is the wrong shape for the documented schema, so it is reported as null
    rather than passed through.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    if len(value) > limit:
        # Report as null rather than truncate: a truncated slot id would no
        # longer round-trip into remove-recovery --slot-id (exact match).
        return None
    return value


def _display_safe(value, limit=256):
    """Bound and de-fang an untrusted header field before printing it.

    json.dumps escapes control characters for the --json path; the human path
    writes straight to a terminal, so strip C0/C1 controls (ANSI escapes,
    carriage returns, newlines) that a crafted file could otherwise use to
    spoof or overwrite output.

    Args:
        value: The raw header field.
        limit: Maximum characters to keep.

    Returns:
        A printable string, or "" for a missing or non-string value.
    """
    capped = _capped(value, limit)
    if capped is None:
        return ""
    return "".join(ch for ch in capped if ch.isprintable())


def _write_recovery_code_file(path, code):
    """Write a generated recovery code to a file only its owner can read.

    A recovery code unwraps the DEK of every file it is added to, so it is
    password-equivalent and must not travel on a general-purpose stream:
    stdout is the conventional target of `> file` (created at the caller's
    umask, typically world-readable) and is collapsed into stderr by `2>&1`;
    stderr lands in terminal scrollback and in the desktop GUI's persistent
    debug log. Writing it ourselves is the only way the tool controls the
    permissions.

    Args:
        path: Destination path, created 0600 and refused if it already exists.
        code: The generated recovery code.

    Raises:
        FileExistsError: If the destination already exists.
        OSError: If the file cannot be created or written.
    """
    import os

    from .file_permissions import PermissionLevel, create_secure_file

    # The hardened primitive adds O_NOFOLLOW, rejects non-regular and
    # foreign-owned targets, pins the mode with an unconditional fchmod, and
    # applies a DACL on Windows; exclusive adds O_EXCL, so a pre-planted
    # symlink, FIFO or device is refused outright.
    # Value-free charset check first: a strict .encode("ascii") failure would
    # embed a character of the credential in the UnicodeEncodeError message,
    # the gitlab#147 leak class this module already fixed twice.
    if not set(code) <= (_BASE32_ALPHABET | {"-"}):
        raise ValueError("recovery code contains unexpected characters")
    fd = create_secure_file(path, PermissionLevel.OWNER_ONLY, exclusive=True)
    try:
        os.write(fd, (code + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)

    # fsync the directory too: the point of writing the credential before the
    # envelope is that it survives a crash the envelope also survives. Best
    # effort by design — failing here would abort a correct operation after
    # the O_EXCL file already exists, making a retry die on FileExistsError.
    try:
        dir_fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:  # pragma: no cover - platform/filesystem dependent
        pass
    finally:
        os.close(dir_fd)


def list_recovery_cli(args) -> None:
    """`list-recovery`: print the recovery slots in a file (no credential)."""
    from .crypt_core import list_recovery_slots
    from .crypt_utils import eprint

    slots = list_recovery_slots(args.input)
    if getattr(args, "json", False):
        from .json_output import emit_json

        # Full key_id, not the 16-char display truncation below: a machine
        # consumer needs the whole value (gitlab#277). emit_json wraps this
        # in the total-json envelope (gitlab#268) like every 1.5.x endpoint.
        # The list is capped at MAX_DEK_SLOTS (the unlock paths enforce the
        # same bound) so a crafted header cannot drive an unbounded stdout
        # document; the cap is reported rather than applied silently.
        payload = {
            "slots": [
                {
                    "id": _capped(s.get("id")),
                    "type": _capped(s.get("type")),
                    "key_id": _capped(s.get("key_id")),
                }
                for s in slots[:MAX_DEK_SLOTS]
            ]
        }
        if len(slots) > MAX_DEK_SLOTS:
            payload["truncated"] = True
        emit_json(payload)
        return
    if not slots:
        eprint("No recovery slots on this file.")
        return
    eprint(f"{len(slots)} recovery slot(s):")
    if len(slots) > MAX_DEK_SLOTS:
        # Same bound as the JSON path and the unlock paths: a crafted header
        # must not flood the terminal either.
        eprint(f"  (showing the first {MAX_DEK_SLOTS}; the file claims {len(slots)})")
        slots = slots[:MAX_DEK_SLOTS]
    for s in slots:
        # These come verbatim from the plaintext file header, i.e. from
        # whoever authored the file. Listing requires no credential, so raw
        # output would let a crafted file emit ANSI escapes into the
        # operator's terminal (same class as gitlab#172).
        slot_id = _display_safe(s.get("id"))
        slot_type = _display_safe(s.get("type"))
        key_id = _display_safe(s.get("key_id"))
        line = f"  id={slot_id}  type={slot_type}"
        if key_id:
            line += f"  key_id={key_id[:16]}..."
        eprint(line)


def recover_cli(args) -> None:
    """`recover`: decrypt a file using a recovery credential (not the password)."""
    from .crypt_core import decrypt_file
    from .crypt_utils import eprint, sanitize_for_display

    kwargs = _recover_kwargs_from_args(args)
    if not kwargs:
        raise ValueError(
            "Provide a recovery credential: --recovery-code, "
            "--recovery-passphrase, or --recovery-share"
        )
    json_mode = getattr(args, "json", False)
    decrypt_file(
        input_file=args.input,
        output_file=args.output,
        # Under --json all human output is redundant and some legacy decrypt
        # branches print to stdout when not quiet — force quiet so stdout
        # stays a single JSON document (gitlab#277 review).
        quiet=json_mode or getattr(args, "quiet", False),
        **kwargs,
    )
    if json_mode:
        from .json_output import emit_json

        emit_json({"output": args.output})
    else:
        eprint(f"Recovered to: {sanitize_for_display(args.output)}")


def _validated_passphrase(value, source):
    """Reject a blank/whitespace-only recovery passphrase, whatever its source.

    A recovery slot is an *additional* wrapping of the same DEK, so the file's
    confidentiality is that of its weakest slot: a blank-passphrase slot is
    equivalent to publishing the file, and nothing downstream rejects one
    (_passphrase_kek feeds the value straight to Argon2id).

    The value is validated but deliberately NOT modified. Stripping here while
    the interactive path stores the raw input would wrap a slot under one string
    and later look it up under another, leaving it permanently unopenable
    through the other channel — an availability failure with no fallback,
    precisely when the primary password is already gone.

    Args:
        value: The candidate passphrase.
        source: Human-readable origin, used in the error message.

    Returns:
        The passphrase, unmodified.

    Raises:
        ValueError: If it is empty or whitespace-only.
    """
    if not value or not value.strip():
        raise ValueError(f"Recovery passphrase ({source}) is empty or whitespace-only")
    return value


def _policy_checked_passphrase(value, source, args=None):
    """Blank check plus the password policy, for a passphrase being CREATED.

    A recovery slot is an additional wrapping of the same DEK, so a file's
    confidentiality is that of its weakest slot -- and the primary password
    was already policy-checked while this one was not, which put the weaker
    check on the weaker credential (gitlab#149).

    Deliberately NOT used when unlocking -- that is `recover` only, via
    `_recover_kwargs_from_args`; `add-recovery` and `remove-recovery` cannot
    unlock with a passphrase at all. Two reasons, and the second is the
    stronger one:

    * Enforcing a policy against a passphrase the user already holds would
      refuse an existing slot on a file whose primary password is typically
      already gone, turning a weak-choice warning into permanent data loss.
    * It would also run a credential-dependent, non-constant-time computation
      BEFORE the Argon2id unwrap, and split the failure into "wrong
      passphrase" versus "weak passphrase" -- a distinguisher on the
      verification path where none exists today.

    `--force-password` overrides, as it does for the primary password: a
    passphrase the user cannot change is better used than refused. It does
    NOT override the blank check -- a blank slot is equivalent to publishing
    the file.

    Args:
        value: The candidate passphrase.
        source: Human-readable origin, used in messages.
        args: Parsed CLI namespace, for `force_password` and
            `password_policy`. None means "no policy context available", in
            which case only the blank check applies.

    Returns:
        The passphrase, unmodified.

    Raises:
        ValueError: If it is empty or whitespace-only.
        ValidationError: If it fails the policy and --force-password is not set.
    """
    value = _validated_passphrase(value, source)

    if args is None or getattr(args, "force_password", False):
        return value

    # Local imports: this line imports eprint per-function rather than at
    # module level.
    from .crypt_utils import eprint
    from .password_policy import validate_password

    level = getattr(args, "password_policy", None) or "standard"
    # "none" is treated as "standard", not as an escape hatch. main_with_args
    # back-fills password_policy="none" for namespaces that lack the
    # attribute, so honouring it would make this check a silent no-op the day
    # --password-policy is renamed or dropped from the subparser -- a fix that
    # fails OPEN with nothing to notice (gitlab#149 review). --force-password
    # is the one documented override.
    if level == "none":
        level = "standard"

    # The NON-raising API: validate_password_or_raise hides the reasons behind
    # SecureError's generic message, and reconstructing a number with
    # get_password_strength printed "STRONG" next to a refusal, because that
    # figure is raw search space while the gate is character classes. Telling
    # someone their passphrase is strong and refusing it in the same breath
    # points them straight at --force-password.
    valid, messages = validate_password(value, policy_level=level, quiet=True)
    if valid:
        return value

    from .crypt_errors import ValidationError

    # Unconditional, including under --quiet: a refusal the user cannot see
    # the reason for is a refusal they will bypass. The messages are canned
    # policy strings and constants -- none embeds the passphrase. The entropy
    # figure is deliberately NOT printed: it inverts to the exact distinct
    # character count and class set of a credential that unwraps the file key,
    # on a stream that reaches scrollback and the GUI's debug log.
    eprint(f"Recovery passphrase ({source}) does not meet the {level} password policy:")
    for message in messages:
        eprint(f"  - {message}")
    eprint(
        "  A recovery slot is another wrapping of the same file key, so the "
        "file is only as strong as its weakest slot."
    )
    eprint("  Use --force-password to add it anyway (not recommended).")
    raise ValidationError(f"Recovery passphrase does not meet the {level} password policy")


def add_recovery_cli(args) -> None:
    """`add-recovery`: add a recovery slot to an existing envelope file.

    Unlock with the primary password (--password / $CRYPT_PASSWORD); add one of
    --add-code (generated and printed), --add-passphrase (prompted), or
    --add-shares K-of-N (a Shamir-split recovery secret; shares written to
    --shares-dir). A recovery code can no longer authorize a slot change
    (F17/F18, gitlab#234): the wrapped key is re-bound to the new slot count,
    which requires the password KEK.
    """
    import getpass
    import os

    from .crypt_core import add_recovery_slots
    from .crypt_utils import eprint, sanitize_for_display

    # F17/F18 (gitlab#234): adding a slot re-binds the wrapped key to the new
    # slot count, which needs the password KEK -- a recovery code recovers only
    # the DEK. Refuse a recovery-code unlock rather than prompt.
    if getattr(args, "recovery_code", None):
        raise ValueError(
            "add-recovery now requires the primary password: a recovery code can "
            "no longer authorize adding a slot. Re-run with --password / "
            "$CRYPT_PASSWORD."
        )

    add_code = getattr(args, "add_code", False)
    add_passphrase = getattr(args, "add_passphrase", False)
    add_shares = getattr(args, "add_shares", None)
    json_mode = getattr(args, "json", False)
    code_out = getattr(args, "recovery_code_out", None)

    # Validate EVERY usage error before acquiring the unlock credential:
    # otherwise a bare `add-recovery -i f -o g` blocks on a getpass() prompt
    # (indefinitely, for a GUI subprocess) only to fail with a usage error
    # afterwards (gitlab#277 port of the 1.4.x rules).
    selected = [bool(add_code), bool(add_passphrase), bool(add_shares)]
    if sum(selected) > 1:
        raise ValueError("Specify only one of --add-code, --add-passphrase, or --add-shares")
    if sum(selected) == 0:
        raise ValueError("Specify --add-code, --add-passphrase, or --add-shares K-of-N")
    if code_out and not add_code:
        # Silently ignoring it would let a wrapper that always passes the flag
        # read back a stale file from an earlier run and present it as the new
        # credential.
        raise ValueError("--recovery-code-out is only meaningful with --add-code")
    if json_mode and add_code and not code_out:
        # Fail closed rather than silently withhold the credential: under
        # --json there is no safe general-purpose stream to put it on (see
        # _write_recovery_code_file), so the caller must name a destination.
        raise ValueError(
            "--add-code with --json requires --recovery-code-out PATH: the "
            "generated code is never written to stdout or stderr in JSON mode"
        )
    if code_out:
        # A destination equal to the envelope would be truncated by the header
        # write moments later, destroying the credential and reporting success.
        code_real = os.path.realpath(code_out)
        for label, other in (("--input", args.input), ("--output", args.output)):
            if other and code_real == os.path.realpath(other):
                raise ValueError(f"--recovery-code-out must differ from {label}")

    threshold = num_shares = None
    out_dir = None
    shares = []
    if add_shares:
        threshold, num_shares = _parse_k_of_n(add_shares)
        out_dir = getattr(args, "shares_dir", ".") or "."
        if os.path.exists(out_dir) and not os.path.isdir(out_dir):
            # Refuse BEFORE create_secure_directory: its defense-in-depth
            # chmod would otherwise hit a regular file (gitlab#276 review).
            raise ValueError(f"--shares-dir is not a directory: {sanitize_for_display(out_dir)}")
        if os.path.isdir(out_dir):
            # Pre-flight all target names before any prompt or write: share
            # files are never overwritten (exclusive create in to_file), and
            # failing midway would leave a partial share set next to an old
            # one.
            existing = [
                f"recovery_share_{i}.json"
                for i in range(1, num_shares + 1)
                if os.path.lexists(os.path.join(out_dir, f"recovery_share_{i}.json"))
            ]
            if existing:
                raise ValueError(
                    f"Share file(s) already exist in {sanitize_for_display(out_dir)}: "
                    f"{', '.join(existing)} — choose a different --shares-dir or move them away"
                )

    unlock = {"password": _read_password(args)}

    creds = []
    generated_code = None
    written_shares = []
    slot_source = None
    if add_code:
        generated_code = generate_recovery_code()
        # Not caught by the log redactor's shape heuristic: a grouped base32
        # code has no 32-char contiguous run. Register it explicitly.
        from .security_logger import register_consumed_secret

        register_consumed_secret("generated_recovery_code", generated_code)
        creds.append({"type": "recovery_code", "code": generated_code})
        slot_source = "generated recovery code"
    elif add_passphrase:
        p1 = getpass.getpass("New recovery passphrase: ")
        p2 = getpass.getpass("Confirm recovery passphrase: ")
        if p1 != p2:
            raise ValueError("Recovery passphrases do not match")
        # This line had NO check at all -- not even for blank -- so two Enter
        # presses wrapped the file key under an empty passphrase, which anyone
        # can unwrap (gitlab#149).
        creds.append(
            {
                "type": "passphrase",
                "passphrase": _policy_checked_passphrase(p1, "interactive prompt", args),
            }
        )
        slot_source = "interactively entered passphrase"
    else:
        from .secret_sharing import split_secret

        secret = secrets.token_bytes(32)
        shares = split_secret(secret, threshold, num_shares)
        if not os.path.isdir(out_dir):
            # 0700: the directory holds a key-escrow set. A pre-existing
            # directory is deliberately left untouched (gitlab#276 review).
            from .file_permissions import create_secure_directory

            create_secure_directory(out_dir)
        for sh in shares:
            path = os.path.join(out_dir, f"recovery_share_{sh.metadata.share_index}.json")
            sh.to_file(path)
            written_shares.append(path)
        creds.append(
            {"type": "shamir", "secret": secret, "threshold": threshold, "num_shares": num_shares}
        )
        slot_source = f"generated Shamir shares ({threshold}-of-{num_shares})"

    # Deliver the credential BEFORE modifying the envelope. The reverse order
    # risks the worst outcome available here: the slot is durably written and
    # the only credential that opens it is then lost to a failed write.
    if generated_code is not None and code_out:
        _write_recovery_code_file(code_out, generated_code)

    try:
        add_recovery_slots(
            args.input,
            args.output,
            creds,
            allow_high_kdf_cost=getattr(args, "allow_high_kdf_cost", False),
            **unlock,
        )
    except Exception:
        # Deliberately do NOT delete the code/share files here: a raise does
        # not prove the slot was not written (add_recovery_slots writes the
        # envelope before setting its permissions), and deleting them would
        # destroy the one credential that opens it. Orphans open nothing.
        if generated_code is not None and code_out:
            eprint(
                f"NOTE: a recovery code was written to {sanitize_for_display(code_out)} "
                "before this failure. If the slot was not added, that file is "
                "unused and can be deleted; verify with list-recovery first. A "
                "retry with the same --recovery-code-out will fail until it is "
                "removed."
            )
        if written_shares:
            eprint(
                "NOTE: share files were written before this failure. If the "
                "slot was not added they are unused and can be deleted; verify "
                "with list-recovery first."
            )
        raise

    if json_mode:
        doc = {
            "output": args.output,
            "slot_type": creds[0]["type"],
            # Which credential produced the slot: an unintended env/planted
            # path must be distinguishable from a typed one.
            "credential_source": slot_source,
        }
        if generated_code is not None:
            doc["recovery_code_written_to"] = code_out
        if written_shares:
            doc["shares"] = written_shares
            doc["threshold"] = threshold
            doc["num_shares"] = num_shares
        from .json_output import emit_json

        emit_json(doc)
        return

    eprint(f"Recovery slot added ({slot_source}); wrote: {sanitize_for_display(args.output)}")
    if generated_code is not None:
        if code_out:
            # The caller named a private destination, which is the strongest
            # possible statement that the credential must not go on a stream —
            # stderr reaches terminal scrollback and the GUI's persistent
            # debug log. Honour that regardless of --json.
            eprint(f"Recovery code written to: {sanitize_for_display(code_out)}")
        else:
            eprint("\n=== RECOVERY CODE (store this securely; it is shown only once) ===")
            eprint(f"  {generated_code}")
    for p in written_shares:
        eprint(f"  wrote share: {sanitize_for_display(p)}")


def remove_recovery_cli(args) -> None:
    """`remove-recovery`: remove a recovery slot by id from an envelope file."""
    from .crypt_core import remove_recovery_slot
    from .crypt_utils import eprint, sanitize_for_display

    # F17/F18 (gitlab#234): removing a slot re-binds the wrapped key to the new
    # slot count, which needs the password KEK. A recovery code can no longer
    # authorize a slot change.
    if getattr(args, "recovery_code", None):
        raise ValueError(
            "remove-recovery now requires the primary password: a recovery code "
            "can no longer authorize removing a slot. Re-run with --password / "
            "$CRYPT_PASSWORD."
        )
    unlock = {"password": _read_password(args)}
    remove_recovery_slot(
        args.input,
        args.output,
        args.slot_id,
        allow_high_kdf_cost=getattr(args, "allow_high_kdf_cost", False),
        **unlock,
    )
    if getattr(args, "json", False):
        from .json_output import emit_json

        emit_json({"output": args.output, "removed_slot_id": args.slot_id})
    else:
        eprint(
            f"Removed recovery slot {sanitize_for_display(args.slot_id)!r}; "
            f"wrote: {sanitize_for_display(args.output)}"
        )


def _parse_k_of_n(spec: str):
    """Parse a 'K-of-N' threshold spec into (threshold, num_shares)."""
    from .crypt_errors import ValidationError

    try:
        k_str, n_str = spec.lower().replace(" ", "").split("-of-")
        k, n = int(k_str), int(n_str)
    except Exception as exc:  # noqa: BLE001
        raise ValidationError("--add-shares must look like 'K-of-N', e.g. 2-of-3") from exc
    if k < 2 or n < k:
        raise ValidationError("--add-shares requires 2 <= K <= N")
    return k, n
