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
from dataclasses import dataclass
from typing import Optional, Union

from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypt_errors import KeyDerivationError, ValidationError

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
