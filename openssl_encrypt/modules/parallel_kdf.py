"""
Parallel Key Derivation entry point for Independent XOR.

`generate_key_independent_xor_parallel` is a thin dispatcher: every format
version routes to `crypt_core.generate_key_independent_xor` with
``parallel=True``, which derives the mutually-independent XOR components
concurrently on a thread pool with a byte-identical result to its sequential
mode (gitlab#220).

This module previously carried its own multiprocessing implementation of every
component (`_hash_worker`/`_kdf_worker` + a progress-queue aggregator) for
format versions < 13. That duplication was retired (gitlab#224): it is where
every parallel-vs-sequential divergence lived — the M3 argon2 rounds bug, the
RandomX silent drop (#71), a silently omitted whirlpool component, and a
balloon branch that imported a module which never existed. The single
implementation in `crypt_core` (`compute_hash_independent` /
`compute_kdf_independent`) now serves both modes for all formats, so the two
paths cannot drift again.
"""

from typing import Tuple


def _normalize_bytes(data: bytes, target_length: int) -> bytes:
    """
    Normalize data to target length using HKDF (plain-bytes version).

    Retained for its pinned equivalence with
    `crypt_core.normalize_to_key_length_secure` (see
    test_format_v14_default_flip.py): both must keep using the same
    HKDF-SHA256 construction with info=b"v10_xor_normalize" so every
    component normalization stays byte-identical across call sites.

    Note: salt=None is intentional here. This is a deterministic normalization
    of XOR accumulator output to the target key length. Using a random salt
    would break reproducibility since both encrypt and decrypt must derive
    the same key from the same KDF outputs. Per RFC 5869, HKDF with salt=None
    uses a zero-filled salt of hash length, which is acceptable for this
    deterministic key-length normalization use case.
    """
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    if len(data) == target_length:
        return data

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=target_length,
        salt=None,
        info=b"v10_xor_normalize",
        backend=default_backend(),
    )

    return hkdf.derive(data)


def generate_key_independent_xor_parallel(
    password: bytes,
    salt: bytes,
    hash_config: dict,
    pbkdf2_iterations: int = 100000,
    quiet: bool = False,
    algorithm: str = "aes-256-gcm",
    progress: bool = False,
    debug: bool = False,
    pqc_keypair: tuple = None,
    hsm_pepper: bytes = None,
    format_version: int = 11,
    max_workers: int = None,
) -> Tuple[bytes, bytes, bytes]:
    """
    Generate encryption key using Independent XOR composition with parallel
    component derivation.

    Robust XOR-combiner for PRFs (Herzberg; Harnik-Kilian-Naor-Reingold-Rosen):
    K = H1(x) ⊕ H2(x) ⊕ ... ⊕ Hn(x)

    The components are mutually independent and combined with (commutative)
    XOR, so computing them concurrently is byte-identical to the sequential
    derivation — a file encrypted with `--parallel-kdf` decrypts without it
    and vice-versa, for every format version.

    Args:
        password: User password (bytes)
        salt: Random salt (bytes)
        hash_config: Configuration dict for enabled algorithms
        pbkdf2_iterations: PBKDF2 iterations (deprecated; forwarded verbatim —
            PBKDF2 is not an independent-XOR component, see gitlab#224 item 8)
        quiet: Suppress output messages
        algorithm: Encryption algorithm (determines key length)
        progress: Show progress indicators
        debug: Enable debug logging
        pqc_keypair: Post-quantum keypair (if applicable)
        hsm_pepper: HSM pepper (if applicable)
        format_version: Metadata format version
        max_workers: Maximum number of parallel workers (default: capped at
            the component count)

    Returns:
        Tuple of (key, salt, iv)

    Raises:
        ValueError: If no algorithms are enabled (encryption configs only)
    """
    from .crypt_core import generate_key_independent_xor

    return generate_key_independent_xor(
        password,
        salt,
        hash_config,
        pbkdf2_iterations=pbkdf2_iterations,
        quiet=quiet,
        algorithm=algorithm,
        progress=progress,
        debug=debug,
        pqc_keypair=pqc_keypair,
        hsm_pepper=hsm_pepper,
        format_version=format_version,
        parallel=True,
        max_workers=max_workers,
    )
