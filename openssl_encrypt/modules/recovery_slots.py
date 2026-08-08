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
import os
import secrets
import sys
from typing import List

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .credential_env import consume_env as _shared_consume_env
from .crypt_utils import eprint
from .secure_memory import secure_memzero
from .secure_ops import constant_time_compare
from .security_logger import register_consumed_secret

# Environment variables carrying recovery credentials for non-interactive
# callers (the desktop GUI). Each is consumed on read, so the credential is not
# on the process list and is not inherited by a child process spawned later.
# (Spawns reachable from these paths do sanitize their env; unsanitized ones do
# exist in the tree — e.g. crypt_cli.py:1306 and :1516 pass no env= — so the
# guarantee rests on consumption here rather than on every caller behaving.)
#
# Scope of that protection: del os.environ[...] calls unsetenv(), which drops the
# pointer from environ[] but does NOT scrub the exec-time copy of the string that
# /proc/self/environ exposes. A value set by our parent therefore stays readable
# there for this process's lifetime. That file is 0400 and gated by
# PTRACE_MODE_READ_FSCREDS (same uid or root), whereas /proc/PID/cmdline is
# world-readable — so this converts a cross-user leak into a same-user residual.
# It protects the credential from other local users, not from a compromised
# session of the user's own.
#
# The values are also registered with security_logger.register_consumed_secret()
# on read: _value_looks_secret resolves _SECRET_ENV_VARS against the live
# environment, which cannot match once the variable has been consumed.
RECOVERY_CODE_ENV = "OPENSSL_ENCRYPT_RECOVERY_CODE"
RECOVERY_PASSPHRASE_ENV = "OPENSSL_ENCRYPT_RECOVERY_PASSPHRASE"
ADD_RECOVERY_PASSPHRASE_ENV = "OPENSSL_ENCRYPT_ADD_RECOVERY_PASSPHRASE"

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
        # surrogateescape, not strict: os.environ decodes with surrogateescape,
        # so an env-supplied passphrase containing non-UTF-8 bytes arrives with
        # lone surrogates. A strict encode would raise UnicodeEncodeError, whose
        # message embeds one byte of the passphrase and its offset and is printed
        # verbatim by the generic CLI handler — outside debug_secret(). Identical
        # bytes for any surrogate-free string, so no existing slot's KEK changes.
        passphrase = passphrase.encode("utf-8", "surrogateescape")
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
# recover subcommands. Human output goes to stderr via eprint; stdout carries
# only the --json document, and never a credential (see
# _write_recovery_code_file for why the generated code gets its own file).


def _consume_env(name):
    """Read a secret-bearing env var and remove it from the environment.

    Delegates to the shared implementation in credential_env (gitlab#154):
    this primitive must stay in lockstep with
    security_logger._value_looks_secret, and the gitlab#144 review already
    found one "inert by construction" bug in that interaction -- a second copy
    would let a future hardening be applied to one and not the other, failing
    silently and open.

    Args:
        name: Environment variable to read.

    Returns:
        The value -- possibly the empty string when the variable is present
        but empty -- or None only when the variable is absent.
    """
    return _shared_consume_env(name)


def _consume_recovery_env():
    """Consume every credential-bearing env var this module reads.

    Called first in each handler, before any validation that can raise:
    consumption must not depend on which branch runs or on validation
    succeeding, or an early error would strand the remaining credentials in the
    environment for a later child process to inherit.

    Returns:
        Dict of consumed values keyed 'code', 'passphrase', 'add_passphrase'
        and 'password'. Each is the value, "" if set-but-empty, or None if the
        variable was absent.
    """
    return {
        "code": _consume_env(RECOVERY_CODE_ENV),
        "passphrase": _consume_env(RECOVERY_PASSPHRASE_ENV),
        "add_passphrase": _consume_env(ADD_RECOVERY_PASSPHRASE_ENV),
        "password": _consume_env("CRYPT_PASSWORD"),
    }


def _read_password(args, env_pw, prompt="Password: "):
    """Resolve a password from --password, an already-consumed env value, or a prompt.

    Args:
        args: Parsed CLI namespace.
        env_pw: Value already consumed from $CRYPT_PASSWORD by
            _consume_recovery_env, or None if it was absent.
        prompt: Prompt text used when neither source supplied one.

    Returns:
        The password as bytes.
    """
    import getpass

    pw = getattr(args, "password", None)
    if pw is None and env_pw:
        # An empty CRYPT_PASSWORD keeps its long-standing meaning of "not
        # supplied" here; only the new recovery channels treat blank as an error.
        pw = env_pw
    if pw is None:
        pw = getpass.getpass(prompt)
    # surrogateescape round-trips bytes that os.environ decoded the same way, so
    # a non-UTF-8 password neither crashes nor echoes its bytes in the traceback.
    return pw.encode("utf-8", "surrogateescape") if isinstance(pw, str) else pw


def _read_recovery_code(args, env_code):
    """Resolve an existing recovery code from --recovery-code or the env value.

    Pure resolution over an already-consumed value: it may raise, so it must run
    after _consume_recovery_env has emptied every variable, never before.

    The flag takes precedence but warns: a recovery credential on argv is
    visible in the world-readable /proc/PID/cmdline. The warning is deliberately
    not silenced by --quiet, matching the --rekey-password warning.

    Args:
        args: Parsed CLI namespace.
        env_code: Value already consumed from the env var, "" if it was set but
            empty, or None if it was absent.

    Returns:
        The recovery code, or None if neither source supplied one.

    Raises:
        ValueError: If the env var was set but empty and no flag was given.
    """
    flag_code = getattr(args, "recovery_code", None)
    if flag_code:
        eprint(
            "WARNING: --recovery-code is visible in process list. "
            f"Use the {RECOVERY_CODE_ENV} env var instead."
        )
        return flag_code
    if env_code == "":
        # Set but empty: fail fast rather than fall through to a password
        # prompt no GUI subprocess can answer.
        raise ValueError(f"${RECOVERY_CODE_ENV} is set but empty")
    return env_code


def _read_recovery_passphrase(env_name, env_value, prompt):
    """Resolve a recovery passphrase from its env var, else prompt for it.

    Only called once the caller has explicitly selected the passphrase path via
    its flag; the env var supplies the value, it never selects the path.

    Args:
        env_name: Environment variable the value came from (for messages).
        env_value: Already-consumed value, or None if the variable was absent.
        prompt: Prompt text used when the env var was absent.

    Returns:
        The passphrase as a str.

    Raises:
        ValueError: If the passphrase is blank, from either source.
    """
    import getpass

    if env_value is not None:
        validated = _validated_passphrase(env_value, f"${env_name}")
        eprint(f"Using recovery passphrase from ${env_name}.")
        return validated
    return _validated_passphrase(getpass.getpass(prompt), "interactive prompt")


def _capped(value, limit=256):
    """Bound an untrusted header field before echoing it into JSON output.

    id/type/key_id are copied verbatim out of the plaintext file header, so a
    crafted file could otherwise drive an arbitrarily large stdout document at a
    consumer that buffers the whole thing. A non-string is not merely long, it is
    the wrong shape for the documented schema, so it is reported as null rather
    than passed through.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    if len(value) > limit:
        return value[:limit]
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
    password-equivalent and must not travel on a general-purpose stream. stdout
    is the conventional target of `> file` (created at the caller's umask,
    typically world-readable) and is collapsed into stderr by `2>&1`; stderr
    lands in terminal scrollback and in the desktop GUI's persistent debug log.
    Writing it ourselves is the only way the tool controls the permissions.

    Args:
        path: Destination path, created 0600 and refused if it already exists.
        code: The generated recovery code.

    Raises:
        ValueError: If the destination already exists.
        OSError: If the file cannot be created or written.
    """
    from .file_permissions import PermissionLevel, create_secure_file

    # Delegate to the hardened primitive rather than a local os.open: it adds
    # O_NOFOLLOW, rejects non-regular and foreign-owned targets, pins the mode
    # with an unconditional fchmod (open()'s mode is ignored for an existing
    # file, and a restrictive umask would otherwise subtract from it), and
    # applies a DACL on Windows, where mode bits alone do nothing. exclusive
    # adds O_EXCL, so a pre-planted symlink, FIFO or device is refused outright.
    fd = create_secure_file(path, PermissionLevel.OWNER_ONLY, exclusive=True)
    try:
        os.write(fd, (code + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)

    # fsync the directory too: the whole point of writing the credential before
    # the envelope is that it survives a crash the envelope also survives, and
    # an unsynced directory entry can vanish while the envelope's new slot stays.
    #
    # Best-effort by design. Windows cannot open a directory handle this way at
    # all, and a write-only destination directory refuses it on POSIX; failing
    # the command here would abort a correct operation *after* the O_EXCL file
    # already exists, so the obvious retry would then die with FileExistsError.
    # Losing the extra durability is much cheaper than that.
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
    `_read_recovery_passphrase`; `add-recovery` and `remove-recovery` cannot
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

    try:
        validate_password_or_raise(value, policy_level=level, quiet=getattr(args, "quiet", False))
    except Exception:
        # eprint before re-raising: ValidationError is a SecureError, which
        # replaces the message it is given with a generic string unless
        # DEBUG=1 is set, so the reason would otherwise reach nobody.
        entropy, strength = get_password_strength(value)
        eprint(f"\nRecovery passphrase strength: {strength} (entropy: {entropy:.1f} bits)")
        eprint(f"Recovery passphrase ({source}) does not meet the {level} password policy.")
        eprint(
            "  A recovery slot is another wrapping of the same file key, so the "
            "file is only as strong as its weakest slot."
        )
        eprint("  Use --force-password to add it anyway (not recommended).")
        raise
    return value


def _recover_kwargs_from_args(args):
    """Build decrypt/unlock recovery kwargs from CLI args (one credential).

    Every credential env var is consumed before anything that can raise, so no
    branch and no early error leaves one behind. `recover` itself uses neither
    the add-passphrase value nor the password, but both are consumed anyway.
    """
    env = _consume_recovery_env()
    code = _read_recovery_code(args, env["code"])
    env_phrase = env["passphrase"]
    if code:
        return {"recovery_code": code}
    # The flag selects the passphrase path; the env var only supplies the value.
    # Letting the environment alone select it would let a planted variable steer
    # the credential type behind the user's back.
    if getattr(args, "recovery_passphrase", False):
        return {
            "recovery_passphrase": _read_recovery_passphrase(
                RECOVERY_PASSPHRASE_ENV, env_phrase, "Recovery passphrase: "
            )
        }
    return {}


def list_recovery_cli(args) -> None:
    """`list-recovery`: print the recovery slots in a file (no credential)."""
    from .crypt_core import list_recovery_slots

    slots = list_recovery_slots(args.input)
    if getattr(args, "json", False):
        # Full key_id, not the 16-char display truncation below: a machine
        # consumer needs the whole value.
        print(
            json.dumps(
                {
                    "slots": [
                        {
                            "id": _capped(s.get("id")),
                            "type": _capped(s.get("type")),
                            "key_id": _capped(s.get("key_id")),
                        }
                        for s in slots
                    ]
                },
                indent=2,
            )
        )
        sys.stdout.flush()
        return
    if not slots:
        eprint("No recovery slots on this file.")
        return
    eprint(f"{len(slots)} recovery slot(s):")
    for s in slots:
        # These come verbatim from the plaintext file header, i.e. from whoever
        # authored the file. Listing a file requires no credential, so raw
        # output here would let a crafted file emit ANSI escapes and newlines
        # into the operator's terminal, and an over-long or non-string value
        # would garble or crash the listing.
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

    kwargs = _recover_kwargs_from_args(args)
    if not kwargs:
        raise ValueError(
            "Provide a recovery credential: --recovery-code (or "
            f"${RECOVERY_CODE_ENV}), or --recovery-passphrase (value optionally "
            f"via ${RECOVERY_PASSPHRASE_ENV})"
        )
    decrypt_file(
        input_file=args.input,
        output_file=args.output,
        quiet=getattr(args, "quiet", False),
        **kwargs,
    )
    if getattr(args, "json", False):
        print(json.dumps({"output": args.output}, indent=2))
        sys.stdout.flush()
    else:
        eprint(f"Recovered to: {args.output}")


def add_recovery_cli(args) -> None:
    """`add-recovery`: add a recovery slot to an existing envelope file.

    Unlock with --password (or an existing --recovery-code); add one of
    --add-code (generated and printed) or --add-passphrase (prompted).
    """
    import getpass

    from .crypt_core import add_recovery_slots

    add_code = getattr(args, "add_code", False)
    add_passphrase = getattr(args, "add_passphrase", False)

    # Consume every credential env var first, before any check that can raise,
    # so no branch and no early error leaves one behind for a later child.
    env = _consume_recovery_env()
    env_phrase = env["add_passphrase"]

    # Validate EVERY usage error before acquiring the unlock credential:
    # otherwise a bare `add-recovery -i f -o g` blocks on a getpass() prompt
    # (indefinitely, for a GUI subprocess) only to fail with a usage error
    # afterwards.
    code_out = getattr(args, "recovery_code_out", None)
    if add_code and add_passphrase:
        raise ValueError("Specify only one of --add-code or --add-passphrase")
    if not add_code and not add_passphrase:
        raise ValueError("Specify --add-code or --add-passphrase")
    if code_out and not add_code:
        # Silently ignoring it would let a wrapper that always passes the flag
        # read back a stale file from an earlier run and present it as the new
        # credential.
        raise ValueError("--recovery-code-out is only meaningful with --add-code")
    if getattr(args, "json", False) and add_code and not code_out:
        # Fail closed rather than silently withhold the credential: under --json
        # there is no safe general-purpose stream to put it on (see
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

    existing_code = _read_recovery_code(args, env["code"])

    # How to unlock the existing file (to recover the DEK).
    unlock = {}
    if existing_code:
        unlock["recovery_code"] = existing_code
    else:
        unlock["password"] = _read_password(args, env["password"])

    creds = []
    generated_code = None
    if add_code:
        generated_code = generate_recovery_code()
        # Not caught by the log redactor's shape heuristic: a grouped base32
        # code has no 32-char contiguous run. Register it explicitly.
        register_consumed_secret("generated_recovery_code", generated_code)
        creds.append({"type": "recovery_code", "code": generated_code})
        slot_source = "generated recovery code"
    else:
        # --add-passphrase selects the path; the env var only supplies the
        # value. If the environment alone could select it, anyone able to plant
        # a variable in the user's session once would get a durable extra
        # decryption path into every file later passed to add-recovery.
        if env_phrase is not None:
            # Supplied non-interactively; there is no second channel to confirm
            # against, so the caller owns the typo risk.
            phrase = _policy_checked_passphrase(env_phrase, f"${ADD_RECOVERY_PASSPHRASE_ENV}", args)
            slot_source = f"passphrase from ${ADD_RECOVERY_PASSPHRASE_ENV}"
        else:
            p1 = getpass.getpass("New recovery passphrase: ")
            p2 = getpass.getpass("Confirm recovery passphrase: ")
            if p1 != p2:
                raise ValueError("Recovery passphrases do not match")
            # Same validation as the env path: two Enter presses would otherwise
            # wrap the DEK under an empty passphrase, which anyone can unwrap.
            phrase = _policy_checked_passphrase(p1, "interactive prompt", args)
            slot_source = "interactively entered passphrase"
        creds.append({"type": "passphrase", "passphrase": phrase})

    # Deliver the credential BEFORE modifying the envelope. The reverse order
    # risks the worst outcome available here: the slot is durably written and
    # the only credential that opens it is then lost to a failed write, leaving
    # an extra decryption path nobody can use and nobody can remove without the
    # primary password.
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
        # Deliberately do NOT delete the code file here. A raise does not prove
        # the slot was not written: add_recovery_slots writes the envelope and
        # only then sets its permissions, so a failure in that later step leaves
        # the slot durably on disk. Deleting the file would then destroy the one
        # credential that opens it. An orphan code file, by contrast, is a random
        # string that opens nothing.
        if generated_code is not None and code_out:
            eprint(
                f"NOTE: a recovery code was written to {code_out} before this "
                "failure. If the slot was not added, that file is unused and "
                "can be deleted; verify with list-recovery before deleting. "
                "A retry with the same --recovery-code-out will fail with "
                "FileExistsError until this file is removed."
            )
        raise

    if getattr(args, "json", False):
        doc = {
            "output": args.output,
            "slot_type": creds[0]["type"],
            # Which credential produced the slot. Omitting this would make a
            # slot wrapped under a planted $OPENSSL_ENCRYPT_ADD_RECOVERY_PASSPHRASE
            # indistinguishable from one the user typed — the very disclosure
            # the human path exists to provide.
            "credential_source": slot_source,
        }
        if generated_code is not None:
            doc["recovery_code_written_to"] = code_out
        print(json.dumps(doc, indent=2))
        sys.stdout.flush()
        return

    # Name the credential source: an unintended env-driven path must be visible
    # rather than reported as a bare "slot added".
    eprint(f"Recovery slot added ({slot_source}); wrote: {args.output}")
    if generated_code is not None:
        if code_out:
            # The caller named a private destination, which is the strongest
            # possible statement that the credential must not go on a stream —
            # stderr reaches terminal scrollback and the GUI's persistent debug
            # log. Honour that regardless of --json.
            eprint(f"Recovery code written to: {code_out}")
        else:
            eprint("\n=== RECOVERY CODE (store this securely; it is shown only once) ===")
            eprint(f"  {generated_code}")


def remove_recovery_cli(args) -> None:
    """`remove-recovery`: remove a recovery slot by id from an envelope file."""
    from .crypt_core import remove_recovery_slot

    # Consume every credential env var first, before any check that can raise.
    # remove-recovery adds no slot, so the passphrase values are unused here —
    # consumed anyway so a stray value cannot survive the invocation.
    env = _consume_recovery_env()

    unlock = {}
    existing_code = _read_recovery_code(args, env["code"])
    if existing_code:
        unlock["recovery_code"] = existing_code
    else:
        unlock["password"] = _read_password(args, env["password"])
    remove_recovery_slot(
        args.input,
        args.output,
        args.slot_id,
        allow_high_kdf_cost=getattr(args, "allow_high_kdf_cost", False),
        **unlock,
    )
    if getattr(args, "json", False):
        print(json.dumps({"output": args.output, "removed_slot_id": args.slot_id}, indent=2))
        sys.stdout.flush()
    else:
        eprint(f"Removed recovery slot {args.slot_id!r}; wrote: {args.output}")
