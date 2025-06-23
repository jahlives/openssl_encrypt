#!/usr/bin/env python3
"""
Patch script for pqc_keystore.py to fix the encryption/decryption issue
"""

import base64
import getpass
import json
import os
import secrets
import sys
import tempfile
import time
from enum import Enum

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def patch_encrypt_with_derived_key():
    """
    Directly patch the _encrypt_with_derived_key method to use the same associated data format
    as the decryption in load_keystore.
    """
    file_path = os.path.join(os.getcwd(), "openssl_encrypt", "modules", "pqc_keystore.py")

    # Verify the file exists
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found")
        return False

    # Create a backup
    backup_path = f"{file_path}.patched.bak"
    with open(file_path, "r") as f:
        original_content = f.read()

    # Save backup
    with open(backup_path, "w") as f:
        f.write(original_content)

    print(f"Backup saved to {backup_path}")

    # Fix for _encrypt_with_derived_key method
    old_code = """        if protection_method == KeystoreProtectionMethod.SCRYPT_CHACHA20:
            # Encrypt with ChaCha20Poly1305
            cipher = ChaCha20Poly1305(derived_key)
            ciphertext = cipher.encrypt(nonce, data, associated_data=None)

            # Prepare result (without key derivation parameters)
            result = {
                "method": protection_method.value,
                "params": {
                    "nonce": base64.b64encode(nonce).decode('utf-8'),
                    "key_source": "master"
                },
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
            }

        else:
            # Use AES-GCM for all other methods
            cipher = AESGCM(derived_key)
            ciphertext = cipher.encrypt(nonce, data, associated_data=None)

            # Prepare result (without key derivation parameters)
            result = {
                "method": protection_method.value,
                "params": {
                    "nonce": base64.b64encode(nonce).decode('utf-8'),
                    "key_source": "master"
                },
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
            }"""

    new_code = """        # Prepare the header that will be used for associated_data
        header = {
            "method": protection_method.value,
            "params": {
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "key_source": "master"
            }
        }

        if protection_method == KeystoreProtectionMethod.SCRYPT_CHACHA20:
            # Encrypt with ChaCha20Poly1305
            cipher = ChaCha20Poly1305(derived_key)
            # BUGFIX: Use the associated_data consistent with load_keystore
            ciphertext = cipher.encrypt(nonce, data, associated_data=json.dumps(header).encode('utf-8'))

            # Prepare result (without key derivation parameters)
            result = {
                "method": protection_method.value,
                "params": {
                    "nonce": base64.b64encode(nonce).decode('utf-8'),
                    "key_source": "master"
                },
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
            }

        else:
            # Use AES-GCM for all other methods
            cipher = AESGCM(derived_key)
            # BUGFIX: Use the associated_data consistent with load_keystore
            ciphertext = cipher.encrypt(nonce, data, associated_data=json.dumps(header).encode('utf-8'))

            # Prepare result (without key derivation parameters)
            result = {
                "method": protection_method.value,
                "params": {
                    "nonce": base64.b64encode(nonce).decode('utf-8'),
                    "key_source": "master"
                },
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
            }"""

    # Also fix decrypt_with_derived_key
    old_decrypt = """        try:
            method = encrypted_data["method"]
            params = encrypted_data["params"]
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            nonce = base64.b64decode(params["nonce"])

            if method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
                # Decrypt with ChaCha20Poly1305
                cipher = ChaCha20Poly1305(derived_key)
                plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)

            elif method in [
                KeystoreProtectionMethod.ARGON2ID_AES_GCM.value,
                KeystoreProtectionMethod.PBKDF2_AES_GCM.value
            ]:
                # Decrypt with AES-GCM
                cipher = AESGCM(derived_key)
                plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)"""

    new_decrypt = """        try:
            method = encrypted_data["method"]
            params = encrypted_data["params"]
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            nonce = base64.b64decode(params["nonce"])

            # Recreate the same header used during encryption to use as associated_data
            header = {
                "method": method,
                "params": params
            }

            if method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
                # Decrypt with ChaCha20Poly1305
                cipher = ChaCha20Poly1305(derived_key)
                # BUGFIX: Try both methods for backward compatibility
                try:
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=json.dumps(header).encode('utf-8'))
                except Exception:
                    # Fallback to old method for compatibility with existing keystores
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)

            elif method in [
                KeystoreProtectionMethod.ARGON2ID_AES_GCM.value,
                KeystoreProtectionMethod.PBKDF2_AES_GCM.value
            ]:
                # Decrypt with AES-GCM
                cipher = AESGCM(derived_key)
                # BUGFIX: Try both methods for backward compatibility
                try:
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=json.dumps(header).encode('utf-8'))
                except Exception:
                    # Fallback to old method for compatibility with existing keystores
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)"""

    # Apply the patches
    new_content = original_content.replace(old_code, new_code)
    new_content = new_content.replace(old_decrypt, new_decrypt)

    # Also fix _encrypt_private_key to use associated_data
    old_encrypt_private = """            # Encrypt with AES-GCM
            cipher = AESGCM(derived_key)
            ciphertext = cipher.encrypt(nonce, private_key, associated_data=None)"""

    new_encrypt_private = """            # Encrypt with AES-GCM
            cipher = AESGCM(derived_key)
            # Create a consistent header for associated data
            header = {
                "method": protection_method.value,
                "params": {
                    "salt": salt_b64,
                    "nonce": base64.b64encode(nonce).decode('utf-8')
                }
            }
            ciphertext = cipher.encrypt(nonce, private_key, associated_data=json.dumps(header).encode('utf-8'))"""

    # Apply the private key encryption patch
    new_content = new_content.replace(old_encrypt_private, new_encrypt_private)

    # Fix for ChaCha20 in _encrypt_private_key too
    old_chacha_private = """            # Encrypt with ChaCha20Poly1305
            cipher = ChaCha20Poly1305(derived_key)
            ciphertext = cipher.encrypt(nonce, private_key, associated_data=None)"""

    new_chacha_private = """            # Encrypt with ChaCha20Poly1305
            cipher = ChaCha20Poly1305(derived_key)
            # Create a consistent header for associated data
            header = {
                "method": protection_method.value,
                "params": {
                    "salt": base64.b64encode(salt).decode('utf-8'),
                    "nonce": base64.b64encode(nonce).decode('utf-8')
                }
            }
            ciphertext = cipher.encrypt(nonce, private_key, associated_data=json.dumps(header).encode('utf-8'))"""

    # Apply the ChaCha20 private key encryption patch
    new_content = new_content.replace(old_chacha_private, new_chacha_private)

    # Also patch _decrypt_private_key
    old_decrypt_private = """                # Decrypt with AES-GCM
                cipher = AESGCM(derived_key)
                plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)"""

    new_decrypt_private = """                # Decrypt with AES-GCM
                cipher = AESGCM(derived_key)
                # Recreate the header to match encryption
                header = {
                    "method": method,
                    "params": {
                        "salt": salt_b64,
                        "nonce": base64.b64encode(nonce).decode('utf-8')
                    }
                }
                # Try both methods for backward compatibility
                try:
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=json.dumps(header).encode('utf-8'))
                except Exception:
                    # Fallback for old encrypted data
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)"""

    # Apply the decrypt private key patch for AES-GCM
    new_content = new_content.replace(old_decrypt_private, new_decrypt_private)

    # Similar patch for ChaCha20 in _decrypt_private_key
    old_chacha_decrypt = """                # Decrypt with ChaCha20Poly1305
                cipher = ChaCha20Poly1305(derived_key)
                plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)"""

    new_chacha_decrypt = """                # Decrypt with ChaCha20Poly1305
                cipher = ChaCha20Poly1305(derived_key)
                # Recreate the header to match encryption
                header = {
                    "method": method,
                    "params": {
                        "salt": base64.b64encode(salt).decode('utf-8'),
                        "nonce": base64.b64encode(nonce).decode('utf-8')
                    }
                }
                # Try both methods for backward compatibility
                try:
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=json.dumps(header).encode('utf-8'))
                except Exception:
                    # Fallback for old encrypted data
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)"""

    # Apply the ChaCha20 decrypt patch
    new_content = new_content.replace(old_chacha_decrypt, new_chacha_decrypt)

    # Write the modified file
    with open(file_path, "w") as f:
        f.write(new_content)

    print(f"Applied patch to {file_path}")
    print("Now run 'python verify_fix.py' to test the fix.")
    return True


if __name__ == "__main__":
    patch_encrypt_with_derived_key()
