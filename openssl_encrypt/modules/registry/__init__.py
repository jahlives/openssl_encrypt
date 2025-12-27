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
    AlgorithmInfo,
    AlgorithmCategory,
    SecurityLevel,
    RegistryBase,
    AlgorithmError,
    AlgorithmNotAvailableError,
    AlgorithmNotFoundError,
    ValidationError,
    AuthenticationError,
)

# Utilities
from .utils import (
    generate_random_bytes,
    constant_time_compare,
    pad_pkcs7,
    unpad_pkcs7,
)


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
    CipherBase,
    CipherParams,
    CipherRegistry,
    get_cipher,
    AES256GCM,
    AESGCMSIV,
    AESSIV,
    AESOCB3,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
)

__all__.extend([
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
])

# Hash registry
from .hash_registry import (
    HashBase,
    HashRegistry,
    get_hash,
    SHA256,
    SHA384,
    SHA512,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    BLAKE2b,
    BLAKE2s,
    BLAKE3,
    SHAKE128,
    SHAKE256,
    Whirlpool,
)

__all__.extend([
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
])

# KDF registry
from .kdf_registry import (
    KDFBase,
    KDFParams,
    Argon2Params,
    PBKDF2Params,
    ScryptParams,
    BalloonParams,
    HKDFParams,
    RandomXParams,
    Argon2Type,
    KDFRegistry,
    get_kdf,
    Argon2id,
    Argon2i,
    Argon2d,
    PBKDF2,
    Scrypt,
    Balloon,
    HKDF,
    RandomX,
)

__all__.extend([
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
])

# KEM registry (Post-Quantum Key Encapsulation Mechanisms)
from .kem_registry import (
    KEMBase,
    KEMRegistry,
    get_kem,
    MLKEM512,
    MLKEM768,
    MLKEM1024,
    HQC128,
    HQC192,
    HQC256,
)

__all__.extend([
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
])

# Signature registry (Post-Quantum Digital Signatures)
from .signature_registry import (
    SignatureBase,
    SignatureRegistry,
    get_signature,
    MLDSA44,
    MLDSA65,
    MLDSA87,
    SLHDSASHA2128F,
    SLHDSASHA2192F,
    SLHDSASHA2256F,
    FNDSA512,
    FNDSA1024,
    MAYO1,
    MAYO3,
    MAYO5,
    CROSS128,
    CROSS192,
    CROSS256,
)

__all__.extend([
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
])

# Note: HybridRegistry not needed - hybrid encryption can be composed by
# combining KEMs with ciphers at application level
