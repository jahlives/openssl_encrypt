#!/usr/bin/env python3
"""
Fix script for the PQCKeystore loading issue
"""

import base64
import hashlib
import json
import os
import sys
import tempfile
import traceback
from typing import Dict, Optional, Tuple

# Add the project to path
sys.path.insert(0, os.path.abspath("."))
from openssl_encrypt.modules.pqc_keystore import (
    KeystoreProtectionMethod,
    KeystoreSecurityLevel,
    PQCKeystore,
)


def test_fix_implementation():
    """Test the proposed fix for the keystore loading issue"""
    # Create a temporary directory for test files
    temp_dir = tempfile.mkdtemp()
    keystore_path = os.path.join(temp_dir, "test_keystore.pqc")

    # Master password for tests
    master_password = "test_master_password"

    print("\n=== Testing fix for keystore loading issue ===")

    # Create a keystore object
    print("\nStep 1: Creating keystore")
    keystore = PQCKeystore(keystore_path)

    # Apply the fix - modify the save_keystore method to match load_keystore associated_data
    # This is done by monkey patching the method

    original_save_keystore = keystore.save_keystore

    def fixed_save_keystore(master_password=None):
        """Fixed version that uses the same associated_data for encryption as decryption"""
        if keystore.keystore_data is None:
            raise ValueError("No keystore data to save")

        try:
            # Prepare the data
            keystore.keystore_data[
                "last_modified"
            ] = "2025-05-02T12:00:00.000000"  # Fixed for reproducibility
            plaintext = json.dumps(keystore.keystore_data).encode("utf-8")

            # Get encryption parameters
            protection = keystore.keystore_data["protection"]
            method = protection["method"]
            params = protection["params"]

            # Check if we can use the cached master key
            derived_key = None
            if master_password is None:
                if keystore.master_key is not None:
                    derived_key = keystore.master_key
                else:
                    raise ValueError("Master password required (no cached key)")

            # If we don't have a cached key, derive it from the password
            if derived_key is None:
                from openssl_encrypt.modules.pqc_keystore import KeystoreProtectionMethod

                if method == KeystoreProtectionMethod.ARGON2ID_AES_GCM.value:
                    # Derive key with Argon2
                    argon2_params = params["argon2_params"]
                    from argon2 import PasswordHasher

                    ph = PasswordHasher(
                        time_cost=argon2_params["time_cost"],
                        memory_cost=argon2_params["memory_cost"],
                        parallelism=argon2_params["parallelism"],
                        hash_len=32,
                    )

                    # Encode salt as required by argon2-cffi
                    salt_b64 = params["salt"]

                    # Hash the password with Argon2id
                    hash_result = ph.hash(master_password + salt_b64)
                    derived_key = hashlib.sha256(hash_result.encode("utf-8")).digest()

                # ... other methods handled by original code

                # Cache the key
                keystore.master_key = bytes(derived_key)

            # Encrypt the keystore data
            if method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
                from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

                # ChaCha20Poly1305 implementation (not modified)
                cipher = ChaCha20Poly1305(derived_key)
                nonce = base64.b64decode(params["nonce"])
                # Update nonce for each save
                import secrets

                nonce = secrets.token_bytes(12)
                params["nonce"] = base64.b64encode(nonce).decode("utf-8")

                header = {"protection": protection}
                # This is correct - ChaCha20Poly1305 uses the header as associated data
                ciphertext = cipher.encrypt(
                    nonce, plaintext, associated_data=json.dumps(header).encode("utf-8")
                )
            else:
                # AES-GCM implementation - FIX: use the same associated data approach as in load_keystore
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                cipher = AESGCM(derived_key)
                nonce = base64.b64decode(params["nonce"])
                # Update nonce for each save
                import secrets

                nonce = secrets.token_bytes(12)
                params["nonce"] = base64.b64encode(nonce).decode("utf-8")

                header = {"protection": protection}

                # FIX: Use the same associated_data approach as in load_keystore
                # Original code used: ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)
                # Using None for associated_data on save but header at load causes InvalidTag
                ciphertext = cipher.encrypt(
                    nonce, plaintext, associated_data=json.dumps(header).encode("utf-8")
                )

            # Prepare the final file format
            header_json = json.dumps(header).encode("utf-8")
            header_size = len(header_json)

            with open(keystore_path, "wb") as f:
                f.write(header_size.to_bytes(4, byteorder="big"))
                f.write(header_json)
                f.write(ciphertext)

            return True

        except Exception as e:
            print(f"Error in fixed_save_keystore: {e}")
            traceback.print_exc()
            return False

    # Patch the method
    keystore.save_keystore = fixed_save_keystore

    # Create the keystore
    keystore.create_keystore(master_password, KeystoreSecurityLevel.STANDARD)

    # Try to load it in a new instance
    print("\nStep 2: Loading keystore with standard load_keystore method")
    keystore2 = PQCKeystore(keystore_path)
    try:
        result = keystore2.load_keystore(master_password)
        print(f"Keystore loaded successfully: {result}")
    except Exception as e:
        print(f"Error loading keystore: {str(e)}")
        traceback.print_exc()

    # Test the fixed patched load method to verify
    print("\nStep 3: Now trying with a fixed load_keystore method")
    keystore3 = PQCKeystore(keystore_path)

    # Apply a reciprocal fix to the load_keystore method
    original_load_keystore = keystore3.load_keystore

    def fixed_load_keystore(master_password):
        """Fixed version that uses the same associated_data for decryption as encryption"""
        if keystore3.keystore_path is None:
            raise ValueError("No keystore path specified")

        if not os.path.exists(keystore3.keystore_path):
            raise ValueError(f"Keystore not found at {keystore3.keystore_path}")

        try:
            with open(keystore3.keystore_path, "rb") as f:
                encrypted_data = f.read()

            # Parse the encrypted data
            header_size = int.from_bytes(encrypted_data[:4], byteorder="big")
            header_bytes = encrypted_data[4 : 4 + header_size]
            header = json.loads(header_bytes.decode("utf-8"))
            ciphertext = encrypted_data[4 + header_size :]

            # Extract parameters
            protection = header["protection"]
            method = protection["method"]
            params = protection["params"]

            # Derive key from master password (same as original)
            from openssl_encrypt.modules.pqc_keystore import KeystoreProtectionMethod

            if method == KeystoreProtectionMethod.ARGON2ID_AES_GCM.value:
                # Argon2 key derivation (same as original)
                from argon2 import PasswordHasher

                # Extract parameters
                salt_b64 = params["salt"]
                argon2_params = params["argon2_params"]

                # Derive key with Argon2
                ph = PasswordHasher(
                    time_cost=argon2_params["time_cost"],
                    memory_cost=argon2_params["memory_cost"],
                    parallelism=argon2_params["parallelism"],
                    hash_len=32,
                )

                # Hash the password with Argon2id
                hash_result = ph.hash(master_password + salt_b64)
                derived_key = hashlib.sha256(hash_result.encode("utf-8")).digest()

            # ... other key derivation methods would be here

            # Decrypt the keystore data
            if method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
                # ChaCha20Poly1305 (same as original)
                from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

                cipher = ChaCha20Poly1305(derived_key)
                nonce = base64.b64decode(params["nonce"])
                plaintext = cipher.decrypt(
                    nonce, ciphertext, associated_data=json.dumps(header).encode("utf-8")
                )
            else:
                # AES-GCM implementation - FIX: use the same associated data approach as in save_keystore
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                cipher = AESGCM(derived_key)
                nonce = base64.b64decode(params["nonce"])

                # FIX: First try with associated_data=json.dumps(header).encode('utf-8')
                # as used in the fixed save_keystore method
                try:
                    plaintext = cipher.decrypt(
                        nonce, ciphertext, associated_data=json.dumps(header).encode("utf-8")
                    )
                    print("Decrypted using header as associated data!")
                except Exception as e:
                    print(f"Failed with header as associated data, trying with None: {e}")
                    try:
                        # If that fails, try the original approach with None
                        plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
                        print("Decrypted using None as associated data!")
                    except Exception as e2:
                        print(f"Both decryption approaches failed: {e2}")
                        raise

            # Parse the decrypted data
            keystore3.keystore_data = json.loads(plaintext.decode("utf-8"))

            # Store the derived key for later use
            keystore3.master_key = bytes(derived_key)

            return True

        except Exception as e:
            traceback.print_exc()
            print(f"Error in fixed_load_keystore: {e}")
            return False

    # Apply the fixed load method
    keystore3.load_keystore = fixed_load_keystore

    try:
        result = keystore3.load_keystore(master_password)
        print(f"Keystore loaded successfully with fixed method: {result}")
        print("Keystore data:", keystore3.keystore_data)
    except Exception as e:
        print(f"Error loading keystore with fixed method: {str(e)}")


if __name__ == "__main__":
    test_fix_implementation()
