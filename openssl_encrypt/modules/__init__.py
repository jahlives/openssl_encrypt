#!/usr/bin/env python3
"""
OpenSSL Encrypt Modules package initialization.
"""

# Make all keystore error classes available
from .crypt_errors import (
    KeyNotFoundError,
    KeystoreCorruptedError,
    KeystoreError,
    KeystorePasswordError,
    KeystoreVersionError,
)
from .crypto_secure_memory import (
    CryptoIV,
    CryptoKey,
    CryptoSecureBuffer,
    create_key_from_password,
    generate_secure_key,
    secure_crypto_buffer,
    secure_crypto_iv,
    secure_crypto_key,
    validate_crypto_memory_integrity,
)

# Import the keystore classes for easier access
from .keystore_cli import (
    KeystoreSecurityLevel,
    PQCKeystore,
    add_key_to_keystore,
    get_key_from_keystore,
)

# Import keystore utility functions
from .keystore_utils import (
    auto_generate_pqc_key,
    extract_key_id_from_metadata,
    get_keystore_password,
    get_pqc_key_for_decryption,
)

# Import keystore wrapper functions
from .keystore_wrapper import decrypt_file_with_keystore, encrypt_file_with_keystore

# Import secure memory allocator and cryptographic memory utilities
from .secure_allocator import (
    SecureBytes,
    SecureHeap,
    SecureHeapBlock,
    allocate_secure_crypto_buffer,
    allocate_secure_memory,
    check_all_crypto_buffer_integrity,
    cleanup_secure_heap,
    free_secure_crypto_buffer,
    get_crypto_heap_stats,
)
