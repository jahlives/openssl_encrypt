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

# Registries to be added:
# "HashRegistry", "get_hash",
# "KDFRegistry", "get_kdf",
# "KEMRegistry", "get_kem",
# "SignatureRegistry", "get_signature",
# "HybridRegistry", "get_hybrid",
