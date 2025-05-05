#!/usr/bin/env python3
"""
OpenSSL Encrypt Modules package initialization.
"""

# Import the keystore classes for easier access
from .keystore_cli import (
    PQCKeystore, 
    KeystoreSecurityLevel, 
    get_key_from_keystore, 
    add_key_to_keystore
)

# Import keystore utility functions
from .keystore_utils import (
    extract_key_id_from_metadata,
    get_keystore_password,
    get_pqc_key_for_decryption,
    auto_generate_pqc_key
)

# Make all keystore error classes available
from .crypt_errors import (
    KeystoreError,
    KeystorePasswordError,
    KeyNotFoundError,
    KeystoreCorruptedError,
    KeystoreVersionError
)