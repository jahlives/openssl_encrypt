#!/usr/bin/env python3
"""
Outer key derivation for the hidden ("whitened") file format.

The hidden format wraps the normal encrypted output in an outer layer whose
job is to make the on-disk bytes indistinguishable from random, hiding the
identifiable metadata header. Two modes share one fixed, versioned profile:

* **Keyless** -- the outer key is derived from the *public* per-file salt
  alone. There is no secret, so the layer is whitening/anti-fingerprinting
  only. Because the key is public, memory-hard work would protect nothing and
  would merely slow the (default) path, so keyless uses a single cheap HKDF.

* **Keyed** -- the outer key is derived from a *second* password through a
  heavy, fixed chain (iterated SHA3-512 -> several Argon2id passes ->
  scrypt -> HKDF). This gives real metadata confidentiality even against an
  adversary who has the tool. The chain parameters cannot be stored in the
  file (they would be needed to open the very layer that contains them), so
  they are fixed and pinned to the profile version.

The two modes are domain-separated: the same salt never yields the same key
across modes, and the profile version is bound into the derivation so future
profiles cannot collide with this one.

Security notes:
* The second password is taken as ``bytes``; the caller is responsible for
  encoding and for zeroizing the source material. Intermediate chain values
  are Python ``bytes`` (immutable) and therefore cannot be wiped in place;
  callers should treat the returned key as sensitive and zeroize it.
"""

import hashlib
import secrets
from dataclasses import dataclass
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypt_errors import AuthenticationError, KeyDerivationError, ValidationError
from .secure_memory import secure_memzero
from .xchacha import (
    XCHACHA_NONCE_SIZE,
    hchacha20,
    xchacha20poly1305_decrypt,
    xchacha20poly1305_encrypt,
)

# Try to import argon2 (required for keyed mode). Keyless mode does not need it.
try:
    from argon2.low_level import Type, hash_secret_raw

    ARGON2_AVAILABLE = True
except ImportError:  # pragma: no cover - environment-dependent
    ARGON2_AVAILABLE = False

_BytesLike = (bytes, bytearray, memoryview)

# Profile version. Bound into the domain-separation labels so a future profile
# (different chain or parameters) can never derive the same key as this one.
PROFILE_VERSION = 1

DOMAIN_KEYLESS = b"oe-hidden-header/keyless/v%d" % PROFILE_VERSION
DOMAIN_KEYED = b"oe-hidden-header/keyed/v%d" % PROFILE_VERSION

# Minimum salt length. 16 is what the encryptor produces; Argon2id also
# requires at least 8 bytes of salt.
_MIN_SALT_LEN = 8


@dataclass(frozen=True)
class KeyedProfile:
    """Cost parameters for the keyed-mode derivation chain.

    Production callers use :data:`PRODUCTION_KEYED_PROFILE`. The parameters are
    fixed per :data:`PROFILE_VERSION`; a different set of parameters is a
    different profile and must bump the version. A reduced profile is accepted
    only to keep tests fast -- it exercises the same chain structure.

    Attributes:
        sha3_iters: Number of iterated SHA3-512 rounds (cheap cost stacking).
        argon2_passes: Number of chained Argon2id invocations.
        argon2_time_cost: Argon2id time cost per pass.
        argon2_memory_kib: Argon2id memory cost per pass, in KiB.
        argon2_parallelism: Argon2id parallelism (lanes) per pass.
        scrypt_n: scrypt CPU/memory cost (power of two).
        scrypt_r: scrypt block size parameter.
        scrypt_p: scrypt parallelization parameter.
    """

    sha3_iters: int
    argon2_passes: int
    argon2_time_cost: int
    argon2_memory_kib: int
    argon2_parallelism: int
    scrypt_n: int
    scrypt_r: int
    scrypt_p: int


# The fixed production profile for PROFILE_VERSION 1. Memory-hardness comes
# from the Argon2id passes; the SHA3-512 iterations add cheap serial cost and
# scrypt adds an independent memory-hard step (KDF diversity).
PRODUCTION_KEYED_PROFILE = KeyedProfile(
    sha3_iters=100_000,
    argon2_passes=5,
    argon2_time_cost=3,
    argon2_memory_kib=128 * 1024,  # 128 MiB per pass (sequential -> 128 MiB peak)
    argon2_parallelism=4,
    scrypt_n=2**15,
    scrypt_r=8,
    scrypt_p=1,
)


def _validate_salt(salt) -> bytes:
    """Validate and normalize the salt.

    Args:
        salt: Candidate salt, expected to be a bytes-like object.

    Returns:
        The salt as ``bytes``.

    Raises:
        ValidationError: If the salt is missing, not bytes-like, or too short.
    """
    if salt is None:
        raise ValidationError("Salt cannot be None")
    if not isinstance(salt, _BytesLike):
        raise ValidationError(f"Salt must be a bytes-like object, got {type(salt).__name__}")
    if len(salt) < _MIN_SALT_LEN:
        raise ValidationError(f"Salt must be at least {_MIN_SALT_LEN} bytes, got {len(salt)}")
    return bytes(salt)


def _validate_second_password(second_password) -> Optional[bytes]:
    """Validate the optional second password.

    ``None`` and the empty value both mean "no second password" (keyless).

    Args:
        second_password: ``None`` or a bytes-like second password.

    Returns:
        ``None`` for keyless mode, otherwise the password as ``bytes``.

    Raises:
        ValidationError: If a non-None password is not bytes-like.
    """
    if second_password is None:
        return None
    if not isinstance(second_password, _BytesLike):
        raise ValidationError(
            "Second password must be a bytes-like object (encode str first), "
            f"got {type(second_password).__name__}"
        )
    second_password = bytes(second_password)
    return second_password if len(second_password) > 0 else None


def _derive_keyless(salt: bytes, length: int) -> bytes:
    """Cheap keyless derivation from the public salt only.

    Args:
        salt: The public per-file salt.
        length: Desired key length in bytes.

    Returns:
        The derived outer key.
    """
    return HKDF(
        algorithm=SHA512(),
        length=length,
        salt=DOMAIN_KEYLESS,
        info=b"outer-key",
    ).derive(salt)


def _derive_keyed(salt: bytes, password: bytes, length: int, profile: KeyedProfile) -> bytes:
    """Heavy keyed derivation: iterated SHA3-512 -> Argon2id -> scrypt -> HKDF.

    Args:
        salt: The public per-file salt.
        password: The second password (non-empty bytes).
        length: Desired key length in bytes.
        profile: Cost parameters for the chain.

    Returns:
        The derived outer key.

    Raises:
        KeyDerivationError: If Argon2 is unavailable or a KDF step fails.
    """
    if not ARGON2_AVAILABLE:
        raise KeyDerivationError(
            "Argon2 is required for keyed hidden-header mode but is not installed"
        )

    try:
        # 1) Iterated SHA3-512 (cheap serial cost stacking), domain-separated.
        material = hashlib.sha3_512(DOMAIN_KEYED + salt + password).digest()
        for _ in range(profile.sha3_iters):
            material = hashlib.sha3_512(material + salt).digest()

        # 2) Chained Argon2id passes (memory-hard core).
        for _ in range(profile.argon2_passes):
            material = hash_secret_raw(
                secret=material,
                salt=salt,
                time_cost=profile.argon2_time_cost,
                memory_cost=profile.argon2_memory_kib,
                parallelism=profile.argon2_parallelism,
                hash_len=64,
                type=Type.ID,
            )

        # 3) scrypt as an independent memory-hard step (KDF diversity).
        scrypt_maxmem = 256 * 1024 * 1024  # generous ceiling above production cost
        material = hashlib.scrypt(
            material,
            salt=salt,
            n=profile.scrypt_n,
            r=profile.scrypt_r,
            p=profile.scrypt_p,
            dklen=64,
            maxmem=scrypt_maxmem,
        )

        # 4) HKDF to the requested length, domain-separated and salt-bound.
        return HKDF(
            algorithm=SHA512(),
            length=length,
            salt=salt,
            info=DOMAIN_KEYED + b"|final",
        ).derive(material)
    except (ValidationError, KeyDerivationError):
        raise
    except Exception as exc:  # pragma: no cover - defensive
        raise KeyDerivationError(original_exception=exc)


def derive_outer_key(
    salt: Union[bytes, bytearray, memoryview],
    second_password: Optional[Union[bytes, bytearray, memoryview]] = None,
    *,
    length: int = 32,
    profile: KeyedProfile = PRODUCTION_KEYED_PROFILE,
) -> bytes:
    """Derive the outer (header-whitening) key for the hidden file format.

    When ``second_password`` is ``None`` or empty, the cheap keyless
    derivation is used (whitening from the public salt only). Otherwise the
    heavy keyed chain is used. The two modes are domain-separated.

    Args:
        salt: The public per-file salt (bytes-like, at least 8 bytes).
        second_password: Optional second password (bytes-like). ``None`` or
            empty selects keyless mode. Encode ``str`` passwords before calling.
        length: Desired key length in bytes (default 32).
        profile: Keyed-mode cost parameters. Defaults to the fixed production
            profile; a reduced profile is intended only for fast tests.

    Returns:
        The derived outer key as ``bytes``. Treat it as sensitive and zeroize
        it after use.

    Raises:
        ValidationError: If ``salt``/``second_password`` are malformed or
            ``length`` is not a positive integer.
        KeyDerivationError: If keyed mode is requested but Argon2 is
            unavailable, or a KDF step fails.
    """
    salt = _validate_salt(salt)
    password = _validate_second_password(second_password)
    if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
        raise ValidationError(f"length must be a positive integer, got {length!r}")

    if password is None:
        return _derive_keyless(salt, length)
    return _derive_keyed(salt, password, length, profile)


# ---------------------------------------------------------------------------
# Hidden-format container: wrap / unwrap
#
# Layout (identical for keyless and keyed so the two are indistinguishable):
#
#   salt(16) | nonce(24) | whitened_len(4) | header_region(L) | auth(16) | body
#
# whitened_len  = big-endian uint32(L) XOR keystream(len_key, nonce)
# header_region = keyed : XChaCha20-Poly1305 ciphertext of the header
#                 keyless: header XOR keystream(stream_key, nonce)
# auth          = keyed : Poly1305 tag (AAD = salt | nonce | whitened_len)
#                 keyless: 16 random decoy bytes (no tag -> no format oracle)
# ---------------------------------------------------------------------------

SALT_LEN = 16
NONCE_LEN = XCHACHA_NONCE_SIZE  # 24
LEN_FIELD_LEN = 4
AUTH_LEN = 16  # Poly1305 tag size (keyed) / decoy size (keyless)
HEADER_OFFSET = SALT_LEN + NONCE_LEN + LEN_FIELD_LEN  # 44

# Hard upper bound on the declared header length, independent of the input
# size, to stop a corrupt/hostile blob from driving a huge allocation before
# the remaining-bytes check runs.
_MAX_HEADER_LEN = 64 * 1024 * 1024


def _xchacha_keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    """Return ``n`` bytes of raw (unauthenticated) XChaCha20 keystream.

    Used for keyless header whitening and for whitening the length field. The
    construction matches XChaCha20: an HChaCha20 subkey from the first 16 nonce
    bytes, then ChaCha20 with a 4-byte little-endian counter (starting at 0)
    and a 12-byte nonce of ``b"\\x00" * 4 || nonce[16:24]``.

    Args:
        key: 32-byte key.
        nonce: 24-byte nonce.
        n: Number of keystream bytes to produce.

    Returns:
        ``n`` bytes of keystream.
    """
    if n == 0:
        return b""
    subkey = bytearray(hchacha20(key, nonce[:16]))
    try:
        cc_nonce = b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + nonce[16:24]  # 16 bytes
        cipher = Cipher(algorithms.ChaCha20(bytes(subkey), cc_nonce), mode=None)
        return cipher.encryptor().update(b"\x00" * n)
    finally:
        secure_memzero(subkey)


def _subkeys(salt: bytes, second_password, profile: KeyedProfile) -> Tuple[bytes, bytes]:
    """Derive the two domain-separated subkeys for one file.

    The outer key is derived once (64 bytes) and split: the first half is the
    AEAD / header-whitening key, the second half is the length-whitening key.
    Splitting HKDF output gives two independent keys, so the length keystream
    never overlaps the AEAD's Poly1305 key stream.

    Args:
        salt: The public per-file salt.
        second_password: Optional second password (bytes-like) or ``None``.
        profile: Keyed-mode cost parameters.

    Returns:
        Tuple ``(stream_key, len_key)``, each 32 bytes.
    """
    okey = bytearray(derive_outer_key(salt, second_password, length=64, profile=profile))
    try:
        return bytes(okey[:32]), bytes(okey[32:])
    finally:
        secure_memzero(okey)


def _validate_format_salt(salt) -> bytes:
    """Validate that the salt is exactly the format's fixed salt length."""
    if not isinstance(salt, _BytesLike):
        raise ValidationError(f"Salt must be a bytes-like object, got {type(salt).__name__}")
    if len(salt) != SALT_LEN:
        raise ValidationError(f"Salt must be exactly {SALT_LEN} bytes, got {len(salt)}")
    return bytes(salt)


def wrap_hidden(
    header_bytes: Union[bytes, bytearray, memoryview],
    body_bytes: Union[bytes, bytearray, memoryview],
    salt: Union[bytes, bytearray, memoryview],
    second_password: Optional[Union[bytes, bytearray, memoryview]] = None,
    *,
    profile: KeyedProfile = PRODUCTION_KEYED_PROFILE,
) -> bytes:
    """Wrap a (header, body) pair into the hidden raw-binary container.

    Args:
        header_bytes: The raw metadata header to hide.
        body_bytes: The raw encrypted body (kept as-is, not re-encrypted).
        salt: The public per-file salt (exactly :data:`SALT_LEN` bytes).
        second_password: Optional second password selecting keyed mode.
        profile: Keyed-mode cost parameters (defaults to production).

    Returns:
        The hidden-format bytes.

    Raises:
        ValidationError: For malformed inputs.
    """
    if not isinstance(header_bytes, _BytesLike):
        raise ValidationError(f"header_bytes must be bytes-like, got {type(header_bytes).__name__}")
    if not isinstance(body_bytes, _BytesLike):
        raise ValidationError(f"body_bytes must be bytes-like, got {type(body_bytes).__name__}")
    salt = _validate_format_salt(salt)
    header_bytes = bytes(header_bytes)
    body_bytes = bytes(body_bytes)

    keyed = _validate_second_password(second_password) is not None
    nonce = secrets.token_bytes(NONCE_LEN)
    stream_key, len_key = _subkeys(salt, second_password, profile)
    try:
        # Whiten the length field (same in both modes).
        length_plain = len(header_bytes).to_bytes(LEN_FIELD_LEN, "big")
        len_ks = _xchacha_keystream(len_key, nonce, LEN_FIELD_LEN)
        whitened_len = bytes(a ^ b for a, b in zip(length_plain, len_ks))

        if keyed:
            aad = salt + nonce + whitened_len
            ct_and_tag = xchacha20poly1305_encrypt(stream_key, nonce, header_bytes, aad)
            header_region = ct_and_tag[:-AUTH_LEN]
            auth = ct_and_tag[-AUTH_LEN:]
        else:
            ks = _xchacha_keystream(stream_key, nonce, len(header_bytes))
            header_region = bytes(a ^ b for a, b in zip(header_bytes, ks))
            auth = secrets.token_bytes(AUTH_LEN)  # decoy, never verified

        return salt + nonce + whitened_len + header_region + auth + body_bytes
    finally:
        secure_memzero(bytearray(stream_key))
        secure_memzero(bytearray(len_key))


def unwrap_hidden(
    blob: Union[bytes, bytearray, memoryview],
    second_password: Optional[Union[bytes, bytearray, memoryview]] = None,
    *,
    profile: KeyedProfile = PRODUCTION_KEYED_PROFILE,
) -> Tuple[bytes, bytes]:
    """Reverse :func:`wrap_hidden`, returning ``(header_bytes, body_bytes)``.

    In keyed mode the Poly1305 tag is verified; a wrong second password or any
    tampering raises :class:`AuthenticationError`. In keyless mode there is no
    tag (by design), so a wrong-mode/garbage input simply yields a meaningless
    header that the inner pipeline will reject.

    Args:
        blob: The hidden-format bytes.
        second_password: Optional second password selecting keyed mode.
        profile: Keyed-mode cost parameters (defaults to production).

    Returns:
        Tuple ``(header_bytes, body_bytes)``.

    Raises:
        ValidationError: If the blob is truncated or declares an impossible
            header length.
        AuthenticationError: In keyed mode, if authentication fails.
    """
    if not isinstance(blob, _BytesLike):
        raise ValidationError(f"blob must be bytes-like, got {type(blob).__name__}")
    blob = bytes(blob)
    if len(blob) < HEADER_OFFSET + AUTH_LEN:
        raise ValidationError("Hidden blob too short to contain a header")

    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN : SALT_LEN + NONCE_LEN]
    whitened_len = blob[SALT_LEN + NONCE_LEN : HEADER_OFFSET]

    keyed = _validate_second_password(second_password) is not None
    stream_key, len_key = _subkeys(salt, second_password, profile)
    try:
        len_ks = _xchacha_keystream(len_key, nonce, LEN_FIELD_LEN)
        header_len = int.from_bytes(bytes(a ^ b for a, b in zip(whitened_len, len_ks)), "big")
        if header_len > _MAX_HEADER_LEN or HEADER_OFFSET + header_len + AUTH_LEN > len(blob):
            # In keyed mode the length field is whitened with a password-derived
            # key, so an inconsistent length means a wrong second password or
            # tampering -- surface it as an authentication failure, not a
            # generic "malformed" error (and indistinguishable from random for
            # anyone without the password). In keyless mode it is genuinely
            # malformed input.
            if keyed:
                raise AuthenticationError("Integrity verification failed")
            raise ValidationError("Hidden blob declares an inconsistent header length")

        header_region = blob[HEADER_OFFSET : HEADER_OFFSET + header_len]
        auth = blob[HEADER_OFFSET + header_len : HEADER_OFFSET + header_len + AUTH_LEN]
        body = blob[HEADER_OFFSET + header_len + AUTH_LEN :]

        if keyed:
            aad = salt + nonce + whitened_len
            header = xchacha20poly1305_decrypt(stream_key, nonce, header_region + auth, aad)
        else:
            ks = _xchacha_keystream(stream_key, nonce, header_len)
            header = bytes(a ^ b for a, b in zip(header_region, ks))

        return header, body
    finally:
        secure_memzero(bytearray(stream_key))
        secure_memzero(bytearray(len_key))
