#!/usr/bin/env python3
"""
Algorithm Registry System.

Unified management of cryptographic algorithms with support for:
- Symmetric ciphers (AES, ChaCha20, etc.)
- Hash functions (SHA, BLAKE, etc.)
- Key derivation functions (Argon2, PBKDF2, etc.)
- Post-quantum KEMs (ML-KEM, HQC)
- Post-quantum signatures (ML-DSA, FN-DSA, etc.)
- Hybrid encryption modes

All code in English as per project requirements.

Usage:
    from openssl_encrypt.modules.registry import (
        CipherRegistry, HashRegistry, KDFRegistry,
        get_cipher, get_hash, get_kdf,
    )

    # Get a cipher instance
    cipher = get_cipher("aes-256-gcm")
    ciphertext = cipher.encrypt(key, nonce, plaintext)

    # Get a hash function
    hasher = get_hash("sha256")
    digest = hasher.hash(data)

    # Get a KDF
    kdf = get_kdf("argon2id")
    derived_key = kdf.derive(password, salt)
"""

# Base classes and types
from .base import (
    AlgorithmBase,
    AlgorithmCategory,
    AlgorithmError,
    AlgorithmInfo,
    AlgorithmNotAvailableError,
    AlgorithmNotFoundError,
    AuthenticationError,
    RegistryBase,
    SecurityLevel,
    ValidationError,
)

# Utilities
from .utils import constant_time_compare, generate_random_bytes, pad_pkcs7, unpad_pkcs7

__all__ = [
    # Base classes
    "AlgorithmBase",
    "AlgorithmInfo",
    "AlgorithmCategory",
    "SecurityLevel",
    "RegistryBase",
    # Exceptions
    "AlgorithmError",
    "AlgorithmNotAvailableError",
    "AlgorithmNotFoundError",
    "ValidationError",
    "AuthenticationError",
    # Utilities
    "generate_random_bytes",
    "constant_time_compare",
    "pad_pkcs7",
    "unpad_pkcs7",
]

# Cipher registry
from .cipher_registry import (
    AES256GCM,
    AESGCMSIV,
    AESOCB3,
    AESSIV,
    ChaCha20Poly1305,
    CipherBase,
    CipherParams,
    CipherRegistry,
    Threefish512,
    Threefish1024,
    XChaCha20Poly1305,
    get_cipher,
)

__all__.extend(
    [
        # Cipher registry
        "CipherBase",
        "CipherParams",
        "CipherRegistry",
        "get_cipher",
        "AES256GCM",
        "AESGCMSIV",
        "AESSIV",
        "AESOCB3",
        "ChaCha20Poly1305",
        "XChaCha20Poly1305",
        "Threefish512",
        "Threefish1024",
    ]
)

# Hash registry
from .hash_registry import (
    BLAKE3,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHA256,
    SHA384,
    SHA512,
    SHAKE128,
    SHAKE256,
    BLAKE2b,
    BLAKE2s,
    HashBase,
    HashRegistry,
    Whirlpool,
    get_hash,
)

__all__.extend(
    [
        # Hash registry
        "HashBase",
        "HashRegistry",
        "get_hash",
        "SHA256",
        "SHA384",
        "SHA512",
        "SHA3_256",
        "SHA3_384",
        "SHA3_512",
        "BLAKE2b",
        "BLAKE2s",
        "BLAKE3",
        "SHAKE128",
        "SHAKE256",
        "Whirlpool",
    ]
)

# KDF registry
from .kdf_registry import (
    HKDF,
    PBKDF2,
    Argon2d,
    Argon2i,
    Argon2id,
    Argon2Params,
    Argon2Type,
    Balloon,
    BalloonParams,
    HKDFParams,
    KDFBase,
    KDFParams,
    KDFRegistry,
    PBKDF2Params,
    RandomX,
    RandomXParams,
    Scrypt,
    ScryptParams,
    get_kdf,
)

__all__.extend(
    [
        # KDF registry
        "KDFBase",
        "KDFParams",
        "Argon2Params",
        "PBKDF2Params",
        "ScryptParams",
        "BalloonParams",
        "HKDFParams",
        "RandomXParams",
        "Argon2Type",
        "KDFRegistry",
        "get_kdf",
        "Argon2id",
        "Argon2i",
        "Argon2d",
        "PBKDF2",
        "Scrypt",
        "Balloon",
        "HKDF",
        "RandomX",
    ]
)

# KEM registry (Post-Quantum Key Encapsulation Mechanisms)
from .kem_registry import (
    HQC128,
    HQC192,
    HQC256,
    MLKEM512,
    MLKEM768,
    MLKEM1024,
    KEMBase,
    KEMRegistry,
    get_kem,
)

__all__.extend(
    [
        # KEM registry
        "KEMBase",
        "KEMRegistry",
        "get_kem",
        "MLKEM512",
        "MLKEM768",
        "MLKEM1024",
        "HQC128",
        "HQC192",
        "HQC256",
    ]
)

# Signature registry (Post-Quantum Digital Signatures)
from .signature_registry import (
    CROSS128,
    CROSS192,
    CROSS256,
    FNDSA512,
    FNDSA1024,
    MAYO1,
    MAYO3,
    MAYO5,
    MLDSA44,
    MLDSA65,
    MLDSA87,
    SLHDSASHA2128F,
    SLHDSASHA2192F,
    SLHDSASHA2256F,
    SignatureBase,
    SignatureRegistry,
    get_signature,
)

__all__.extend(
    [
        # Signature registry
        "SignatureBase",
        "SignatureRegistry",
        "get_signature",
        "MLDSA44",
        "MLDSA65",
        "MLDSA87",
        "SLHDSASHA2128F",
        "SLHDSASHA2192F",
        "SLHDSASHA2256F",
        "FNDSA512",
        "FNDSA1024",
        "MAYO1",
        "MAYO3",
        "MAYO5",
        "CROSS128",
        "CROSS192",
        "CROSS256",
    ]
)

# Note: HybridRegistry not needed - hybrid encryption can be composed by
# combining KEMs with ciphers at application level

# CLI helper functions
from .cli_helpers import (
    format_algorithm_help,
    get_available_ciphers,
    get_available_hashes,
    get_available_kdfs,
    get_available_kems,
    get_available_signatures,
    get_cipher_aliases,
    get_cipher_info_dict,
    get_kdf_info_dict,
    get_recommended_cipher,
    get_recommended_hash,
    get_recommended_kdf,
    get_recommended_kem,
    get_recommended_signature,
    validate_algorithm_name,
)

__all__.extend(
    [
        # CLI helpers
        "get_available_ciphers",
        "get_available_hashes",
        "get_available_kdfs",
        "get_available_kems",
        "get_available_signatures",
        "get_cipher_info_dict",
        "get_kdf_info_dict",
        "format_algorithm_help",
        "get_recommended_cipher",
        "get_recommended_hash",
        "get_recommended_kdf",
        "get_recommended_kem",
        "get_recommended_signature",
        "validate_algorithm_name",
        "get_cipher_aliases",
    ]
)
