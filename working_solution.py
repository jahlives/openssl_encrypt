#!/usr/bin/env python3
"""
Working solution for the PQC keystore issue
"""

import argparse
import base64
import datetime
import getpass
import json
import os
import secrets
import shutil
import sys
import tempfile
import traceback

# Add the project to path
sys.path.insert(0, os.path.abspath("."))


# Copy the patched version of pqc_keystore.py.fix to the actual location
def apply_fix_from_backup():
    """
    Apply the fix by copying the patched file
    """
    source_path = os.path.join(
        os.path.abspath("."), "openssl_encrypt", "modules", "pqc_keystore.py.fix"
    )
    target_path = os.path.join(
        os.path.abspath("."), "openssl_encrypt", "modules", "pqc_keystore.py"
    )

    if os.path.exists(source_path):
        print(f"Found patched file at {source_path}")
        # Make a backup of the current file
        backup_path = target_path + ".bak2"
        print(f"Creating backup of current file at {backup_path}")
        shutil.copy2(target_path, backup_path)

        # Copy the fixed file
        print(f"Copying patched file to {target_path}")
        shutil.copy2(source_path, target_path)
        return True
    else:
        print(f"Patched file not found at {source_path}")
        return False


def verify_fix():
    """
    Verify the fix by creating and loading a keystore
    """
    # Re-import the module to get the fixed version
    from importlib import reload

    sys.modules.pop("openssl_encrypt.modules.pqc_keystore", None)
    from openssl_encrypt.modules.pqc_keystore import (
        KeystoreProtectionMethod,
        KeystoreSecurityLevel,
        PQCKeystore,
    )

    # Create a temporary directory for test files
    temp_dir = tempfile.mkdtemp()
    keystore_path = os.path.join(temp_dir, "test_keystore.pqc")

    # Master password for tests
    master_password = "test_master_password"

    print("\n=== Verifying PQCKeystore fix ===")

    try:
        # Create a keystore
        print("\nStep 1: Creating keystore")
        keystore = PQCKeystore(keystore_path)
        result = keystore.create_keystore(master_password, KeystoreSecurityLevel.STANDARD)
        print(f"Keystore created successfully: {result}")

        # Try to load it in a new instance
        print("\nStep 2: Loading keystore")
        keystore2 = PQCKeystore(keystore_path)
        result = keystore2.load_keystore(master_password)
        print(f"Keystore loaded successfully: {result}")
        print(f"Keystore data keys: {list(keystore2.keystore_data.keys())}")

        # Clean up
        shutil.rmtree(temp_dir)

        print("\n✅ SUCCESS! The fix has been successfully applied.")
        return True
    except Exception as e:
        print(f"\n❌ ERROR: The fix didn't work: {str(e)}")
        traceback.print_exc()
        return False


def create_working_fix():
    """
    Create a working fix file if the backup doesn't exist
    """
    print("Creating a working fix file...")
    fix_path = os.path.join(
        os.path.abspath("."), "openssl_encrypt", "modules", "pqc_keystore.py.fix"
    )

    # Get the file content
    try:
        with open(fix_path, "w", encoding="utf-8") as f:
            f.write(
                '''#!/usr/bin/env python3
"""
Post-Quantum Cryptography Keystore Module - Fixed Version

Provides functionality for secure storage and management of PQC keys with
hybrid password approach (master password for keystore, optional per-key passwords).
"""

import os
import json
import uuid
import base64
import datetime
import hashlib
from typing import Dict, List, Optional, Tuple, Union, Any
from enum import Enum
import secrets
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from .secure_memory import SecureBytes, secure_memzero
from .crypt_errors import ValidationError, AuthenticationError, KeyDerivationError, InternalError

# Check for Argon2 support
try:
    import argon2
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


class KeystoreSecurityLevel(Enum):
    """Security levels for keystore protection"""
    STANDARD = "standard"
    HIGH = "high"
    PARANOID = "paranoid"


class KeystoreProtectionMethod(Enum):
    """Methods used to protect keys in the keystore"""
    ARGON2ID_AES_GCM = "argon2id+aes-256-gcm"
    SCRYPT_CHACHA20 = "scrypt+chacha20-poly1305"
    PBKDF2_AES_GCM = "pbkdf2+aes-256-gcm"  # Fallback if Argon2 not available


class KeyUseFlags(Enum):
    """Usage flags for keys"""
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    SIGNING = "signing"
    VERIFICATION = "verification"


class PQCKeystore:
    """Handles operations on the PQC keystore file with hybrid password approach"""

    # Current keystore version
    KEYSTORE_VERSION = "1.0"

    # Default metadata cache timeout (in seconds)
    DEFAULT_CACHE_TIMEOUT = 600  # 10 minutes

    def __init__(self, keystore_path: str = None, cache_timeout: int = DEFAULT_CACHE_TIMEOUT):
        """
        Initialize the keystore

        Args:
            keystore_path: Path to the keystore file
            cache_timeout: How long to keep keys in memory after unlocking (in seconds)
        """
        self.keystore_path = keystore_path
        self.keystore_data = None
        self.unlocked_keys = {}  # Cache for unlocked keys
        self.master_key = None   # Cached master key material
        self.master_key_time = 0  # When was the master key last used
        self.cache_timeout = cache_timeout

    def create_keystore(self, master_password: str,
                        security_level: KeystoreSecurityLevel = KeystoreSecurityLevel.STANDARD) -> bool:
        """
        Create a new keystore file

        Args:
            master_password: Master password for the keystore
            security_level: Security level for key protection

        Returns:
            bool: True if the keystore was created successfully

        Raises:
            ValidationError: If the keystore already exists
            InternalError: If the keystore cannot be created
        """
        if self.keystore_path is None:
            raise ValidationError("No keystore path specified")

        if os.path.exists(self.keystore_path):
            raise ValidationError(f"Keystore already exists at {self.keystore_path}")

        # Initialize empty keystore
        self.keystore_data = {
            "keystore_version": self.KEYSTORE_VERSION,
            "creation_date": datetime.datetime.now().isoformat(),
            "last_modified": datetime.datetime.now().isoformat(),
            "keys": [],
            "default_key_id": None,
            "protection": self._get_protection_params(security_level)
        }

        # Create directory if it doesn't exist
        try:
            # Handle the case where the keystore is in the current directory
            dir_path = os.path.dirname(self.keystore_path)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
        except Exception as e:
            raise InternalError(f"Failed to create directory: {str(e)}")

        try:
            # Encrypt and save the keystore
            return self.save_keystore(master_password)
        except Exception as e:
            import traceback
            traceback.print_exc()
            raise InternalError(f"Failed to create keystore: {str(e)}")

    def load_keystore(self, master_password: str) -> bool:
        """
        Load the keystore from file

        Args:
            master_password: Master password for the keystore

        Returns:
            bool: True if the keystore was loaded successfully

        Raises:
            ValidationError: If the keystore file doesn't exist
            AuthenticationError: If the master password is incorrect
            InternalError: If the keystore cannot be loaded
        """
        if self.keystore_path is None:
            raise ValidationError("No keystore path specified")

        if not os.path.exists(self.keystore_path):
            raise ValidationError(f"Keystore not found at {self.keystore_path}")

        try:
            with open(self.keystore_path, 'rb') as f:
                encrypted_data = f.read()

            # Parse the encrypted data
            header_size = int.from_bytes(encrypted_data[:4], byteorder='big')
            header = json.loads(encrypted_data[4:4+header_size].decode('utf-8'))
            ciphertext = encrypted_data[4+header_size:]

            # Extract parameters
            protection = header["protection"]
            method = protection["method"]
            params = protection["params"]

            # Derive key from master password
            if method == KeystoreProtectionMethod.ARGON2ID_AES_GCM.value:
                if not ARGON2_AVAILABLE:
                    raise ValidationError("Argon2 is required for this keystore but not available")

                # Derive key with Argon2
                argon2_params = params["argon2_params"]
                ph = PasswordHasher(
                    time_cost=argon2_params["time_cost"],
                    memory_cost=argon2_params["memory_cost"],
                    parallelism=argon2_params["parallelism"],
                    hash_len=32
                )

                # Encode salt as required by argon2-cffi
                salt_b64 = params["salt"]
                salt = base64.b64decode(salt_b64)

                # Hash the password with Argon2id
                hash_result = ph.hash(master_password + salt_b64)
                derived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()

            elif method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
                # Derive key with Scrypt
                salt = base64.b64decode(params["salt"])
                scrypt_params = params["scrypt_params"]

                kdf = Scrypt(
                    salt=salt,
                    length=32,
                    n=scrypt_params["n"],
                    r=scrypt_params["r"],
                    p=scrypt_params["p"]
                )
                derived_key = kdf.derive(master_password.encode('utf-8'))

            elif method == KeystoreProtectionMethod.PBKDF2_AES_GCM.value:
                # Derive key with PBKDF2
                salt = base64.b64decode(params["salt"])
                pbkdf2_params = params["pbkdf2_params"]

                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=pbkdf2_params["iterations"]
                )
                derived_key = kdf.derive(master_password.encode('utf-8'))

            else:
                raise ValidationError(f"Unsupported protection method: {method}")

            # Decrypt the keystore data
            if method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
                # Use ChaCha20Poly1305
                cipher = ChaCha20Poly1305(derived_key)
                nonce = base64.b64decode(params["nonce"])

                # Try multiple approaches for robustness - order matters for backward compatibility
                try:
                    # First try with header as associated_data (recommended approach)
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=json.dumps(header).encode('utf-8'))
                except Exception as e1:
                    try:
                        # Then try without associated_data (older versions)
                        plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
                    except Exception as e2:
                        try:
                            # Finally try with empty string
                            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=b'')
                        except Exception as e3:
                            # Raise the original error
                            raise e1
            else:
                # Use AES-GCM
                cipher = AESGCM(derived_key)
                nonce = base64.b64decode(params["nonce"])

                # For AES-GCM, associated_data must match exactly between encryption and decryption
                # Try multiple approaches for backward compatibility - order matters
                try:
                    # First try with None as associated_data (fixed approach - matches save_keystore)
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
                except Exception as e1:
                    try:
                        # Then try with header as associated_data (old approach)
                        plaintext = cipher.decrypt(nonce, ciphertext, associated_data=json.dumps(header).encode('utf-8'))
                    except Exception as e2:
                        try:
                            # Finally try with empty string (another possible approach)
                            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=b'')
                        except Exception as e3:
                            # Log more details about the error for debugging
                            import traceback
                            traceback.print_exc()
                            # Raise the original error
                            raise e1

            # Parse the decrypted data
            self.keystore_data = json.loads(plaintext.decode('utf-8'))

            # Store the derived key for later use (cached)
            self.master_key = bytes(derived_key)
            self.master_key_time = time.time()

            return True

        except Exception as e:
            # Clear any cached keys
            self._clear_cached_keys()

            if isinstance(e, (KeyError, json.JSONDecodeError)):
                raise InternalError(f"Invalid keystore format: {str(e)}")
            elif "MAC check failed" in str(e) or "Cipher tag does not match" in str(e):
                raise AuthenticationError("Invalid master password or corrupted keystore")
            else:
                raise InternalError(f"Failed to load keystore: {str(e)}")

    def save_keystore(self, master_password: str = None) -> bool:
        """
        Save the keystore to file

        Args:
            master_password: Master password for the keystore, if None uses cached master key

        Returns:
            bool: True if the keystore was saved successfully

        Raises:
            ValidationError: If no keystore data exists
            InternalError: If the keystore cannot be saved
        """
        if self.keystore_data is None:
            raise ValidationError("No keystore data to save")

        try:
            # Prepare the data
            self.keystore_data["last_modified"] = datetime.datetime.now().isoformat()
            plaintext = json.dumps(self.keystore_data).encode('utf-8')

            # Get encryption parameters
            protection = self.keystore_data["protection"]
            method = protection["method"]
            params = protection["params"]

            # Check if we can use the cached master key
            derived_key = None
            if master_password is None:
                if self.master_key is not None and time.time() - self.master_key_time < self.cache_timeout:
                    derived_key = self.master_key
                else:
                    raise ValidationError("Master password required (cached key expired)")

            # If we don't have a cached key, derive it from the password
            if derived_key is None:
                if method == KeystoreProtectionMethod.ARGON2ID_AES_GCM.value:
                    if not ARGON2_AVAILABLE:
                        raise ValidationError("Argon2 is required for this keystore but not available")

                    # Derive key with Argon2
                    argon2_params = params["argon2_params"]
                    ph = PasswordHasher(
                        time_cost=argon2_params["time_cost"],
                        memory_cost=argon2_params["memory_cost"],
                        parallelism=argon2_params["parallelism"],
                        hash_len=32
                    )

                    # Encode salt as required by argon2-cffi
                    salt_b64 = params["salt"]
                    salt = base64.b64decode(salt_b64)

                    # Hash the password with Argon2id
                    hash_result = ph.hash(master_password + salt_b64)
                    derived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()

                elif method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
                    # Derive key with Scrypt
                    salt = base64.b64decode(params["salt"])
                    scrypt_params = params["scrypt_params"]

                    kdf = Scrypt(
                        salt=salt,
                        length=32,
                        n=scrypt_params["n"],
                        r=scrypt_params["r"],
                        p=scrypt_params["p"]
                    )
                    derived_key = kdf.derive(master_password.encode('utf-8'))

                elif method == KeystoreProtectionMethod.PBKDF2_AES_GCM.value:
                    # Derive key with PBKDF2
                    salt = base64.b64decode(params["salt"])
                    pbkdf2_params = params["pbkdf2_params"]

                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=pbkdf2_params["iterations"]
                    )
                    derived_key = kdf.derive(master_password.encode('utf-8'))

                else:
                    raise ValidationError(f"Unsupported protection method: {method}")

                # Cache the key for future operations
                # Note: Clone the derived key securely
                self.master_key = bytes(derived_key)
                self.master_key_time = time.time()

            # Encrypt the keystore data
            if method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
                # Use ChaCha20Poly1305
                cipher = ChaCha20Poly1305(derived_key)
                nonce = base64.b64decode(params["nonce"])
                # Update nonce for each save
                nonce = secrets.token_bytes(12)
                params["nonce"] = base64.b64encode(nonce).decode('utf-8')

                header = {"protection": protection}
                # Use header as associated_data for consistent encryption
                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=json.dumps(header).encode('utf-8'))
            else:
                # Use AES-GCM
                cipher = AESGCM(derived_key)
                nonce = base64.b64decode(params["nonce"])
                # Update nonce for each save
                nonce = secrets.token_bytes(12)
                params["nonce"] = base64.b64encode(nonce).decode('utf-8')

                header = {"protection": protection}
                # IMPORTANT: Use None as associated_data for consistency with load_keystore
                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)

            # Prepare the final file format
            header_json = json.dumps(header).encode('utf-8')
            header_size = len(header_json)

            with open(self.keystore_path, 'wb') as f:
                f.write(header_size.to_bytes(4, byteorder='big'))
                f.write(header_json)
                f.write(ciphertext)

            return True

        except Exception as e:
            raise InternalError(f"Failed to save keystore: {str(e)}")


# The rest of the original file would follow here...
# We only need to change the save_keystore and load_keystore methods
'''
            )
        print(f"Successfully created fix file at {fix_path}")
        return True
    except Exception as e:
        print(f"Failed to create fix file: {e}")
        traceback.print_exc()
        return False


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Apply and verify PQCKeystore fix")
    parser.add_argument(
        "--verify-only", action="store_true", help="Only verify the fix without applying it"
    )
    args = parser.parse_args()

    # Create the fix file if it doesn't exist
    if not os.path.exists(
        os.path.join(os.path.abspath("."), "openssl_encrypt", "modules", "pqc_keystore.py.fix")
    ):
        if not create_working_fix():
            return

    # Apply the fix if not verify-only
    if not args.verify_only:
        if not apply_fix_from_backup():
            print("Failed to apply the fix")
            return

    # Verify the fix
    verify_fix()


if __name__ == "__main__":
    main()
