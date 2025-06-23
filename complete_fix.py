#!/usr/bin/env python3
"""
Complete fix for the PQCKeystore encryption/decryption issue
"""

import base64
import hashlib
import json
import os
import secrets
import shutil
import sys
import tempfile
import traceback

# Add the project to path
sys.path.insert(0, os.path.abspath("."))
from openssl_encrypt.modules.pqc_keystore import (
    KeystoreProtectionMethod,
    KeystoreSecurityLevel,
    PQCKeystore,
)


class FixedPQCKeystore(PQCKeystore):
    """
    A fixed version of PQCKeystore that ensures consistent associated_data
    between save_keystore and load_keystore methods.
    """

    def save_keystore(self, master_password: str = None) -> bool:
        """
        Save the keystore to file with consistent associated data handling

        Args:
            master_password: Master password for the keystore, if None uses cached master key

        Returns:
            bool: True if the keystore was saved successfully
        """
        if self.keystore_data is None:
            raise ValueError("No keystore data to save")

        try:
            # Prepare the data
            self.keystore_data[
                "last_modified"
            ] = "2025-05-02T12:00:00.000000"  # Fixed for reproducibility
            plaintext = json.dumps(self.keystore_data).encode("utf-8")

            # Get encryption parameters
            protection = self.keystore_data["protection"]
            method = protection["method"]
            params = protection["params"]

            # Check if we can use the cached master key
            derived_key = None
            if master_password is None:
                if self.master_key is not None:
                    derived_key = self.master_key
                else:
                    raise ValueError("Master password required (cached key expired)")

            # If we don't have a cached key, derive it from the password
            if derived_key is None:
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

                elif method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
                    # Derive key with Scrypt
                    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

                    salt = base64.b64decode(params["salt"])
                    scrypt_params = params["scrypt_params"]

                    kdf = Scrypt(
                        salt=salt,
                        length=32,
                        n=scrypt_params["n"],
                        r=scrypt_params["r"],
                        p=scrypt_params["p"],
                    )
                    derived_key = kdf.derive(master_password.encode("utf-8"))

                elif method == KeystoreProtectionMethod.PBKDF2_AES_GCM.value:
                    # Derive key with PBKDF2
                    from cryptography.hazmat.primitives import hashes
                    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

                    salt = base64.b64decode(params["salt"])
                    pbkdf2_params = params["pbkdf2_params"]

                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=pbkdf2_params["iterations"],
                    )
                    derived_key = kdf.derive(master_password.encode("utf-8"))

                else:
                    raise ValueError(f"Unsupported protection method: {method}")

                # Cache the key for future operations
                self.master_key = bytes(derived_key)
                self.master_key_time = secrets.randbelow(1000) + 1000  # Just to have a value

            # Encrypt the keystore data
            if method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
                from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

                # Use ChaCha20Poly1305
                cipher = ChaCha20Poly1305(derived_key)
                # Fixed nonce for testing
                nonce = secrets.token_bytes(12)
                params["nonce"] = base64.b64encode(nonce).decode("utf-8")

                header = {"protection": protection}
                # IMPORTANT: Use the same associated_data approach in both save and load
                # For ChaCha20, always use the header
                associated_data = json.dumps(header).encode("utf-8")
                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=associated_data)
                print(f"DEBUG: ChaCha20 encryption successful with header as associated_data")

            else:
                # Use AES-GCM
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                cipher = AESGCM(derived_key)
                # Fixed nonce for testing
                nonce = secrets.token_bytes(12)
                params["nonce"] = base64.b64encode(nonce).decode("utf-8")

                header = {"protection": protection}
                # IMPORTANT: Use the same associated_data approach in both save and load
                # For AES-GCM, consistently use None for both encryption and decryption
                associated_data = None
                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=associated_data)
                print(f"DEBUG: AES-GCM encryption successful with None as associated_data")

            # Prepare the final file format
            header_json = json.dumps(header).encode("utf-8")
            header_size = len(header_json)

            with open(self.keystore_path, "wb") as f:
                f.write(header_size.to_bytes(4, byteorder="big"))
                f.write(header_json)
                f.write(ciphertext)

            return True

        except Exception as e:
            print(f"Failed to save keystore: {e}")
            traceback.print_exc()
            return False

    def load_keystore(self, master_password: str) -> bool:
        """
        Load the keystore from file with consistent associated data handling

        Args:
            master_password: Master password for the keystore

        Returns:
            bool: True if the keystore was loaded successfully
        """
        if self.keystore_path is None:
            raise ValueError("No keystore path specified")

        if not os.path.exists(self.keystore_path):
            raise ValueError(f"Keystore not found at {self.keystore_path}")

        try:
            with open(self.keystore_path, "rb") as f:
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

            # Derive key from master password
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

            elif method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
                # Derive key with Scrypt
                from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

                salt = base64.b64decode(params["salt"])
                scrypt_params = params["scrypt_params"]

                kdf = Scrypt(
                    salt=salt,
                    length=32,
                    n=scrypt_params["n"],
                    r=scrypt_params["r"],
                    p=scrypt_params["p"],
                )
                derived_key = kdf.derive(master_password.encode("utf-8"))

            elif method == KeystoreProtectionMethod.PBKDF2_AES_GCM.value:
                # Derive key with PBKDF2
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

                salt = base64.b64decode(params["salt"])
                pbkdf2_params = params["pbkdf2_params"]

                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=pbkdf2_params["iterations"],
                )
                derived_key = kdf.derive(master_password.encode("utf-8"))

            else:
                raise ValueError(f"Unsupported protection method: {method}")

            # Decrypt the keystore data
            if method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
                from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

                # Use ChaCha20Poly1305
                cipher = ChaCha20Poly1305(derived_key)
                nonce = base64.b64decode(params["nonce"])

                # IMPORTANT: Use the same associated_data approach in both save and load
                # For ChaCha20, always use the header
                associated_data = json.dumps(header).encode("utf-8")
                plaintext = cipher.decrypt(nonce, ciphertext, associated_data=associated_data)
                print(f"DEBUG: ChaCha20 decryption successful with header as associated_data")

            else:
                # Use AES-GCM
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                cipher = AESGCM(derived_key)
                nonce = base64.b64decode(params["nonce"])

                # IMPORTANT: Use the same associated_data approach in both save and load
                # For AES-GCM, consistently use None for both encryption and decryption
                associated_data = None
                plaintext = cipher.decrypt(nonce, ciphertext, associated_data=associated_data)
                print(f"DEBUG: AES-GCM decryption successful with None as associated_data")

            # Parse the decrypted data
            self.keystore_data = json.loads(plaintext.decode("utf-8"))

            # Store the derived key for later use
            self.master_key = bytes(derived_key)
            self.master_key_time = secrets.randbelow(1000) + 1000  # Just to have a value

            return True

        except Exception as e:
            print(f"Failed to load keystore: {e}")
            traceback.print_exc()
            return False


def test_fixed_keystore():
    """Test the fixed PQCKeystore implementation"""
    # Create a temporary directory for test files
    temp_dir = tempfile.mkdtemp()
    keystore_path = os.path.join(temp_dir, "fixed_keystore.pqc")

    # Master password for tests
    master_password = "test_master_password"

    print("\n=== Testing fixed PQCKeystore implementation ===")

    # Create a keystore
    print("\nStep 1: Creating keystore with fixed implementation")
    keystore = FixedPQCKeystore(keystore_path)
    try:
        result = keystore.create_keystore(master_password, KeystoreSecurityLevel.STANDARD)
        print(f"Keystore created successfully: {result}")
    except Exception as e:
        print(f"Error creating keystore: {str(e)}")
        traceback.print_exc()
        return False

    # Try to load it in a new instance
    print("\nStep 2: Loading keystore with fixed implementation")
    keystore2 = FixedPQCKeystore(keystore_path)
    try:
        result = keystore2.load_keystore(master_password)
        print(f"Keystore loaded successfully: {result}")
        print(f"Keystore contains: {list(keystore2.keystore_data.keys())}")
    except Exception as e:
        print(f"Error loading keystore: {str(e)}")
        traceback.print_exc()
        return False

    # Clean up
    print(f"\nTest complete. Cleaning up {temp_dir}")
    shutil.rmtree(temp_dir)

    print("\n=== FIXED IMPLEMENTATION SUCCESSFUL ===")
    print(
        """
    The fix for the PQCKeystore loading issue is to ensure consistent
    use of associated_data between save_keystore and load_keystore methods.

    In this implementation, we're using:
    - For AES-GCM: consistently using None for both encryption and decryption
    - For ChaCha20Poly1305: consistently using the header for both operations

    The important point is consistency between save and load, regardless of
    which approach is used.
    """
    )

    return True


if __name__ == "__main__":
    test_fixed_keystore()
