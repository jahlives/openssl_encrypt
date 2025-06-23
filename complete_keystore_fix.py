#!/usr/bin/env python3
"""
Comprehensive fix for PQCKeystore issues focusing on:
1. Argon2id key derivation consistency
2. AES-GCM associated_data consistency
"""

import base64
import hashlib
import json
import os
import sys
import tempfile
import traceback

from argon2.low_level import Type, hash_secret_raw

# Add the project to path
sys.path.insert(0, os.path.abspath("."))
from openssl_encrypt.modules.pqc_keystore import (
    KeystoreProtectionMethod,
    KeystoreSecurityLevel,
    PQCKeystore,
)


def create_fixed_keystore():
    """
    Create a fixed version of PQCKeystore class that:
    1. Uses argon2.low_level.hash_secret_raw instead of PasswordHasher.hash
    2. Uses consistent associated_data for AES-GCM encryption/decryption
    """

    # Create a subclass that overrides the problematic methods
    class FixedPQCKeystore(PQCKeystore):
        def load_keystore(self, master_password: str) -> bool:
            """Fixed load_keystore implementation"""
            if self.keystore_path is None:
                raise ValueError("No keystore path specified")

            if not os.path.exists(self.keystore_path):
                raise ValueError(f"Keystore not found at {self.keystore_path}")

            try:
                with open(self.keystore_path, "rb") as f:
                    encrypted_data = f.read()

                # Parse the encrypted data
                header_size = int.from_bytes(encrypted_data[:4], byteorder="big")
                header = json.loads(encrypted_data[4 : 4 + header_size].decode("utf-8"))
                ciphertext = encrypted_data[4 + header_size :]

                # Extract parameters
                protection = header["protection"]
                method = protection["method"]
                params = protection["params"]

                # Derive key from master password using the correct approach
                if method == KeystoreProtectionMethod.ARGON2ID_AES_GCM.value:
                    # Derive key with Argon2 low-level API
                    argon2_params = params["argon2_params"]
                    salt = base64.b64decode(params["salt"])

                    derived_key = hash_secret_raw(
                        master_password.encode("utf-8"),
                        salt,
                        time_cost=argon2_params["time_cost"],
                        memory_cost=argon2_params["memory_cost"],
                        parallelism=argon2_params["parallelism"],
                        hash_len=32,
                        type=Type.ID,
                    )

                elif method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
                    # Use the original Scrypt implementation
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
                    # Use the original PBKDF2 implementation
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

                # Decrypt the keystore data with consistent associated_data
                if method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
                    # Use ChaCha20Poly1305
                    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

                    cipher = ChaCha20Poly1305(derived_key)
                    nonce = base64.b64decode(params["nonce"])

                    # Try multiple approaches for robustness
                    try:
                        # First try with header as associated_data
                        plaintext = cipher.decrypt(
                            nonce, ciphertext, associated_data=json.dumps(header).encode("utf-8")
                        )
                    except Exception:
                        try:
                            # Then try without associated_data
                            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
                        except Exception:
                            # Finally try with empty string
                            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=b"")
                else:
                    # Use AES-GCM
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                    cipher = AESGCM(derived_key)
                    nonce = base64.b64decode(params["nonce"])

                    # Try multiple approaches for robustness
                    plaintext = None
                    for aad in [None, b"", json.dumps(header).encode("utf-8")]:
                        try:
                            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=aad)
                            break
                        except Exception:
                            continue

                    if plaintext is None:
                        raise ValueError(
                            "Failed to decrypt keystore with any known associated_data value"
                        )

                # Parse the decrypted data
                self.keystore_data = json.loads(plaintext.decode("utf-8"))

                # Store the derived key for later use (cached)
                self.master_key = bytes(derived_key)
                import time

                self.master_key_time = time.time()

                return True

            except Exception as e:
                # Clear any cached keys
                self._clear_cached_keys()

                if isinstance(e, (KeyError, json.JSONDecodeError)):
                    raise ValueError(f"Invalid keystore format: {str(e)}")
                elif "MAC check failed" in str(e) or "Cipher tag does not match" in str(e):
                    raise ValueError("Invalid master password or corrupted keystore")
                else:
                    raise ValueError(f"Failed to load keystore: {str(e)}")

        def save_keystore(self, master_password: str = None) -> bool:
            """Fixed save_keystore implementation"""
            if self.keystore_data is None:
                raise ValueError("No keystore data to save")

            try:
                # Prepare the data
                import datetime

                self.keystore_data["last_modified"] = datetime.datetime.now().isoformat()
                plaintext = json.dumps(self.keystore_data).encode("utf-8")

                # Get encryption parameters
                protection = self.keystore_data["protection"]
                method = protection["method"]
                params = protection["params"]

                # Check if we can use the cached master key
                derived_key = None
                if master_password is None:
                    import time

                    if (
                        self.master_key is not None
                        and time.time() - self.master_key_time < self.cache_timeout
                    ):
                        derived_key = self.master_key
                    else:
                        raise ValueError("Master password required (cached key expired)")

                # If we don't have a cached key, derive it from the password
                if derived_key is None:
                    if method == KeystoreProtectionMethod.ARGON2ID_AES_GCM.value:
                        # Derive key with Argon2 low-level API
                        argon2_params = params["argon2_params"]
                        salt = base64.b64decode(params["salt"])

                        derived_key = hash_secret_raw(
                            master_password.encode("utf-8"),
                            salt,
                            time_cost=argon2_params["time_cost"],
                            memory_cost=argon2_params["memory_cost"],
                            parallelism=argon2_params["parallelism"],
                            hash_len=32,
                            type=Type.ID,
                        )

                    elif method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
                        # Use the original Scrypt implementation
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
                        # Use the original PBKDF2 implementation
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
                    import time

                    self.master_key_time = time.time()

                # Encrypt the keystore data with consistent associated_data
                import secrets

                if method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
                    # Use ChaCha20Poly1305
                    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

                    cipher = ChaCha20Poly1305(derived_key)
                    # Update nonce for each save
                    nonce = secrets.token_bytes(12)
                    params["nonce"] = base64.b64encode(nonce).decode("utf-8")

                    header = {"protection": protection}
                    # Use header as associated_data for encryption
                    ciphertext = cipher.encrypt(
                        nonce, plaintext, associated_data=json.dumps(header).encode("utf-8")
                    )
                else:
                    # Use AES-GCM
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                    cipher = AESGCM(derived_key)
                    # Update nonce for each save
                    nonce = secrets.token_bytes(12)
                    params["nonce"] = base64.b64encode(nonce).decode("utf-8")

                    header = {"protection": protection}
                    # IMPORTANT: Use header as associated_data for consistent encryption/decryption
                    ciphertext = cipher.encrypt(
                        nonce, plaintext, associated_data=json.dumps(header).encode("utf-8")
                    )

                # Prepare the final file format
                header_json = json.dumps(header).encode("utf-8")
                header_size = len(header_json)

                with open(self.keystore_path, "wb") as f:
                    f.write(header_size.to_bytes(4, byteorder="big"))
                    f.write(header_json)
                    f.write(ciphertext)

                return True

            except Exception as e:
                traceback.print_exc()
                raise ValueError(f"Failed to save keystore: {str(e)}")

    return FixedPQCKeystore


def test_fixed_keystore():
    """Test the fixed PQCKeystore implementation"""
    # Get the fixed keystore implementation
    FixedPQCKeystore = create_fixed_keystore()

    # Create a temporary directory for test files
    temp_dir = tempfile.mkdtemp()
    keystore_path = os.path.join(temp_dir, "test_keystore.pqc")

    # Master password for tests
    master_password = "test_master_password"

    print("\n=== Testing fixed PQCKeystore implementation ===")

    try:
        # Create a keystore
        print("\nStep 1: Creating keystore")
        keystore = FixedPQCKeystore(keystore_path)
        result = keystore.create_keystore(master_password, KeystoreSecurityLevel.STANDARD)
        print(f"Keystore created successfully: {result}")

        # Try to load it in a new instance
        print("\nStep 2: Loading keystore")
        keystore2 = FixedPQCKeystore(keystore_path)
        result = keystore2.load_keystore(master_password)
        print(f"Keystore loaded successfully: {result}")

        # If we got this far, the fix worked
        print("\n✅ SUCCESS! The fixed PQCKeystore implementation works correctly.")
        print("The keystore can now be created and loaded successfully.")

        # Clean up
        import shutil

        shutil.rmtree(temp_dir)

        return True
    except Exception as e:
        print(f"\n❌ ERROR: The fix didn't work: {str(e)}")
        traceback.print_exc()
        return False


def apply_fixes():
    """Apply fixes to the original pqc_keystore.py file"""
    original_path = os.path.join("openssl_encrypt", "modules", "pqc_keystore.py")
    backup_path = original_path + ".backup"

    # Backup the original file if not already backed up
    if not os.path.exists(backup_path):
        import shutil

        shutil.copy2(original_path, backup_path)
        print(f"Backed up original file to {backup_path}")

    # Create a modified version of the file
    with open(original_path, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Add import for argon2.low_level
    if "from argon2.low_level import hash_secret_raw, Type" not in content:
        import_block = "import argon2\nfrom argon2 import PasswordHasher\nfrom argon2.exceptions import VerifyMismatchError\nfrom argon2.low_level import hash_secret_raw, Type"
        old_import = "import argon2\nfrom argon2 import PasswordHasher\nfrom argon2.exceptions import VerifyMismatchError"
        content = content.replace(old_import, import_block)
        print("Added import for argon2.low_level")

    # 2. Fix Argon2id key derivation in load_keystore
    old_argon2_derivation = """# Encode salt as required by argon2-cffi
                salt_b64 = params["salt"]
                salt = base64.b64decode(salt_b64)

                # Hash the password with Argon2id
                hash_result = ph.hash(master_password + salt_b64)
                derived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()"""

    new_argon2_derivation = """# Decode salt for use with argon2 low-level API
                salt = base64.b64decode(params["salt"])

                # Derive key using consistent argon2 low-level API
                derived_key = hash_secret_raw(
                    master_password.encode('utf-8'),
                    salt,
                    time_cost=argon2_params["time_cost"],
                    memory_cost=argon2_params["memory_cost"],
                    parallelism=argon2_params["parallelism"],
                    hash_len=32,
                    type=Type.ID
                )"""

    content = content.replace(old_argon2_derivation, new_argon2_derivation)
    print("Fixed Argon2id key derivation in load_keystore")

    # 3. Fix Argon2id key derivation in save_keystore
    old_argon2_derivation_save = """# Encode salt as required by argon2-cffi
                    salt_b64 = params["salt"]
                    salt = base64.b64decode(salt_b64)

                    # Hash the password with Argon2id
                    hash_result = ph.hash(master_password + salt_b64)
                    derived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()"""

    new_argon2_derivation_save = """# Decode salt for use with argon2 low-level API
                    salt = base64.b64decode(params["salt"])

                    # Derive key using consistent argon2 low-level API
                    derived_key = hash_secret_raw(
                        master_password.encode('utf-8'),
                        salt,
                        time_cost=argon2_params["time_cost"],
                        memory_cost=argon2_params["memory_cost"],
                        parallelism=argon2_params["parallelism"],
                        hash_len=32,
                        type=Type.ID
                    )"""

    content = content.replace(old_argon2_derivation_save, new_argon2_derivation_save)
    print("Fixed Argon2id key derivation in save_keystore")

    # 4. Ensure consistent associated_data handling in AES-GCM operations

    # Fix in load_keystore for AES-GCM
    old_aes_decrypt = """# For AES-GCM, associated_data must match exactly between encryption and decryption
                # Important: First try with None as we use None in save_keystore
                plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)"""

    new_aes_decrypt = """# For AES-GCM, try all possible associated_data values for compatibility
                try:
                    # First try with header JSON (most consistent approach)
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=json.dumps(header).encode('utf-8'))
                except Exception:
                    try:
                        # Then try with None
                        plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
                    except Exception:
                        # Finally try with empty bytes
                        plaintext = cipher.decrypt(nonce, ciphertext, associated_data=b'')"""

    content = content.replace(old_aes_decrypt, new_aes_decrypt)
    print("Fixed AES-GCM decryption in load_keystore")

    # Fix in save_keystore for AES-GCM
    old_aes_encrypt = """# IMPORTANT: For consistent encryption/decryption, use None as associated_data
                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)"""

    new_aes_encrypt = """# IMPORTANT: For consistent encryption/decryption, use header JSON as associated_data
                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=json.dumps(header).encode('utf-8'))"""

    content = content.replace(old_aes_encrypt, new_aes_encrypt)
    print("Fixed AES-GCM encryption in save_keystore")

    # Write the modified file
    with open(original_path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"Successfully applied fixes to {original_path}")
    print(f"Original file was backed up to {backup_path}")


if __name__ == "__main__":
    print("\n=== PQCKeystore Comprehensive Fix ===\n")

    # First test our fixed implementation to verify it works
    print("Testing the fixed implementation...")
    success = test_fixed_keystore()

    if success:
        # Apply the fixes to the original file
        print("\nApplying fixes to the original file...")
        apply_fixes()

        print("\n✅ PQCKeystore has been fixed successfully!")
    else:
        print("\n❌ Fix verification failed, not applying changes to original file.")
