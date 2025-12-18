#!/usr/bin/env python3
"""
Command-line interface for PQC keystore
"""

import argparse
import base64
import datetime
import getpass
import hashlib
import json
import os
import sys
import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .crypt_errors import (
    KeyNotFoundError,
    KeystoreCorruptedError,
    KeystoreError,
    KeystorePasswordError,
    KeystoreVersionError,
)

# Import secure_delete_file only if it's available
try:
    from .crypt_utils import secure_delete_file
except ImportError:
    # Define a simple fallback if not available
    def secure_delete_file(file_path, passes=3, quiet=False):
        """Simple fallback for secure file deletion"""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
            return True
        except Exception as e:
            if not quiet:
                print(f"Error deleting file {file_path}: {e}")
            return False


from .secure_memory import SecureBytes, secure_memzero

# Import portable media modules
try:
    from .portable_media import (
        QRKeyDistribution,
        QRKeyError,
        QRKeyFormat,
        USBCreationError,
        USBDriveCreator,
        USBSecurityProfile,
        create_portable_usb,
        verify_usb_integrity,
    )

    QR_AVAILABLE = True
    USB_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False
    USB_AVAILABLE = False


class KeystoreSecurityLevel(Enum):
    """Security levels for keystores"""

    STANDARD = "standard"
    HIGH = "high"
    PARANOID = "paranoid"


class PQCKeystore:
    """
    Post-Quantum Cryptography Keystore

    This class manages storage and retrieval of PQC keypairs.
    """

    # Keystore format version
    KEYSTORE_VERSION = 1

    # Encryption parameters for different security levels
    SECURITY_PARAMS = {
        KeystoreSecurityLevel.STANDARD: {
            "pbkdf2_iterations": 100000,
            "argon2_time_cost": 3,
            "argon2_memory_cost": 65536,
            "argon2_parallelism": 4,
        },
        KeystoreSecurityLevel.HIGH: {
            "pbkdf2_iterations": 500000,
            "argon2_time_cost": 6,
            "argon2_memory_cost": 262144,
            "argon2_parallelism": 8,
        },
        KeystoreSecurityLevel.PARANOID: {
            "pbkdf2_iterations": 1000000,
            "argon2_time_cost": 8,
            "argon2_memory_cost": 1048576,
            "argon2_parallelism": 8,
        },
    }

    def __init__(self, keystore_path: str):
        """
        Initialize a keystore object

        Args:
            keystore_path: Path to the keystore file
        """
        self.keystore_path = keystore_path
        self.keystore_data = None
        self.master_key = None
        self._key_cache = {}

    def create_keystore(
        self, password: str, security_level: KeystoreSecurityLevel = KeystoreSecurityLevel.STANDARD
    ) -> None:
        """
        Create a new keystore with the given password

        Args:
            password: Master password for the keystore
            security_level: Security level for encryption parameters

        Raises:
            KeystoreError: If the keystore already exists
        """
        if os.path.exists(self.keystore_path):
            raise KeystoreError(f"Keystore already exists at {self.keystore_path}")

        # Generate a random salt for key derivation
        salt = os.urandom(16)

        # Create keystore structure
        self.keystore_data = {
            "version": self.KEYSTORE_VERSION,
            "created": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
            "last_modified": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
            "security_level": security_level.value,
            "encryption": {
                "salt": base64.b64encode(salt).decode("utf-8"),
                **self.SECURITY_PARAMS[security_level],
            },
            "keys": {},
        }

        # Derive master key
        self.master_key = self._derive_master_key(password, salt, security_level)

        # Save the keystore
        self.save_keystore()

    def load_keystore(self, password: str) -> None:
        """
        Load an existing keystore

        Args:
            password: Master password for the keystore

        Raises:
            FileNotFoundError: If the keystore file doesn't exist
            KeystoreError: If the keystore format is invalid
            KeystorePasswordError: If the password is incorrect
        """
        if not os.path.exists(self.keystore_path):
            raise FileNotFoundError(f"Keystore not found at {self.keystore_path}")

        # Load keystore file
        try:
            with open(self.keystore_path, "r") as f:
                # MED-8 Security fix: Use secure JSON validation for keystore loading
                json_content = f.read()
                try:
                    from .json_validator import (
                        JSONSecurityError,
                        JSONValidationError,
                        secure_keystore_loads,
                    )

                    self.keystore_data = secure_keystore_loads(json_content)
                except (JSONSecurityError, JSONValidationError) as e:
                    raise KeystoreCorruptedError(f"Keystore file validation failed: {e}")
                except ImportError:
                    # Fallback to basic JSON loading if validator not available
                    try:
                        self.keystore_data = json.loads(json_content)
                    except json.JSONDecodeError as e:
                        raise KeystoreCorruptedError(
                            f"Keystore file is corrupted or invalid JSON: {e}"
                        )
        except json.JSONDecodeError:
            raise KeystoreCorruptedError("Keystore file is corrupted or invalid JSON")

        # Validate version
        if (
            "version" not in self.keystore_data
            or self.keystore_data["version"] != self.KEYSTORE_VERSION
        ):
            raise KeystoreVersionError(f"Unsupported keystore version")

        # Get encryption parameters
        if "encryption" not in self.keystore_data:
            raise KeystoreCorruptedError("Keystore missing encryption parameters")

        encryption = self.keystore_data["encryption"]
        if "salt" not in encryption:
            raise KeystoreCorruptedError("Keystore missing salt")

        # Get salt
        salt = base64.b64decode(encryption["salt"])

        # Determine security level
        security_level = KeystoreSecurityLevel(self.keystore_data.get("security_level", "standard"))

        # Derive master key
        self.master_key = self._derive_master_key(password, salt, security_level)

        # Verify password by checking a test key
        if "test_key" in self.keystore_data:
            test_encrypted = base64.b64decode(self.keystore_data["test_key"])
            try:
                self._decrypt_data(test_encrypted)
            except Exception:
                # Clear master key and raise error
                if self.master_key:
                    secure_memzero(self.master_key)
                    self.master_key = None
                raise KeystorePasswordError("Incorrect keystore password")

        # Reset key cache
        self._key_cache = {}

    def save_keystore(self) -> None:
        """
        Save the keystore to disk

        Raises:
            KeystoreError: If the keystore hasn't been loaded or created
        """
        if not self.keystore_data:
            raise KeystoreError("No keystore data to save")

        # Update modification timestamp
        self.keystore_data["last_modified"] = (
            datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"
        )

        # Add a test key for password verification if it doesn't exist
        if "test_key" not in self.keystore_data and self.master_key:
            test_data = b"Keystore password verification data"
            encrypted = self._encrypt_data(test_data)
            self.keystore_data["test_key"] = base64.b64encode(encrypted).decode("utf-8")

        # Create a temporary file first
        temp_path = self.keystore_path + ".tmp"
        with open(temp_path, "w") as f:
            json.dump(self.keystore_data, f, indent=2)

        # Replace the original file
        if os.path.exists(self.keystore_path):
            os.remove(self.keystore_path)
        os.rename(temp_path, self.keystore_path)

    def list_keys(self) -> List[Dict[str, Any]]:
        """
        List all keys in the keystore

        Returns:
            List of key information dictionaries

        Raises:
            KeystoreError: If the keystore hasn't been loaded
        """
        if not self.keystore_data:
            raise KeystoreError("Keystore not loaded")

        keys = []
        for key_id, key_data in self.keystore_data.get("keys", {}).items():
            # Extract non-sensitive information
            key_info = {
                "key_id": key_id,
                "algorithm": key_data.get("algorithm", "unknown"),
                "created": key_data.get("created", "unknown"),
                "description": key_data.get("description", ""),
                "tags": key_data.get("tags", []),
                "use_master_password": key_data.get("use_master_password", True),
            }
            keys.append(key_info)

        # Sort by creation date, newest first
        return sorted(keys, key=lambda k: k.get("created", ""), reverse=True)

    def add_key(
        self,
        algorithm: str,
        public_key: bytes,
        private_key: bytes,
        description: str = "",
        tags: List[str] = None,
        use_master_password: bool = True,
        key_password: str = None,
        dual_encryption: bool = False,
        file_password: str = None,
    ) -> str:
        """
        Add a key to the keystore

        Args:
            algorithm: The PQC algorithm name
            public_key: The public key bytes
            private_key: The private key bytes
            description: Optional description of the key
            tags: Optional list of tags for the key
            use_master_password: Whether to use the master password or a separate one
            key_password: Password for the key if not using master password
            dual_encryption: Whether to use dual encryption with file password
            file_password: File password for dual encryption

        Returns:
            The key ID

        Raises:
            KeystoreError: If the keystore hasn't been loaded or master key is missing
        """
        if not self.keystore_data:
            raise KeystoreError("Keystore not loaded")

        if use_master_password and not self.master_key:
            raise KeystoreError("Master key not available")

        if not use_master_password and not key_password:
            raise KeystoreError("Key password required when not using master password")

        if dual_encryption and not file_password:
            raise KeystoreError("File password required for dual encryption")

        # Generate a new key ID
        key_id = str(uuid.uuid4())

        # Encode keys as base64 for storage
        public_key_b64 = base64.b64encode(public_key).decode("utf-8")

        # Apply dual encryption if enabled
        private_key_to_encrypt = private_key
        dual_encryption_salt = None

        if dual_encryption and file_password:
            try:
                # Generate a salt for file password key derivation
                dual_encryption_salt = os.urandom(16)

                # Determine security level
                security_level = KeystoreSecurityLevel(
                    self.keystore_data.get("security_level", "standard")
                )

                # Derive encryption key from file password
                file_encryption_key = self._derive_key(
                    file_password, dual_encryption_salt, security_level
                )

                # Use AES-GCM to encrypt the private key with the file key
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                # Generate a nonce for AES-GCM
                nonce = os.urandom(12)

                # Create the cipher with the file key
                cipher = AESGCM(file_encryption_key)

                # Encrypt the private key
                ciphertext = cipher.encrypt(nonce, private_key, None)

                # Combine the nonce and ciphertext
                private_key_to_encrypt = nonce + ciphertext

                # Clean up
                secure_memzero(file_encryption_key)
            except Exception as e:
                raise KeystoreError(f"Failed to apply dual encryption: {e}")

        # Encrypt private key with keystore mechanism
        if use_master_password:
            encrypted_private_key = self._encrypt_data(private_key_to_encrypt)
        else:
            # Generate a key-specific salt
            key_salt = os.urandom(16)

            # Derive a key-specific encryption key
            # Determine security level
            security_level = KeystoreSecurityLevel(
                self.keystore_data.get("security_level", "standard")
            )
            key_encryption_key = self._derive_key(key_password, key_salt, security_level)

            # Encrypt with key-specific encryption key
            encrypted_private_key = self._encrypt_data_with_key(
                private_key_to_encrypt, key_encryption_key
            )

            # Clean up the key
            secure_memzero(key_encryption_key)

        # Add to keystore
        self.keystore_data.setdefault("keys", {})
        self.keystore_data["keys"][key_id] = {
            "algorithm": algorithm,
            "created": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
            "description": description,
            "tags": tags or [],
            "use_master_password": use_master_password,
            "public_key": public_key_b64,
            "private_key": base64.b64encode(encrypted_private_key).decode("utf-8"),
        }

        # Add salt if using separate password
        if not use_master_password:
            self.keystore_data["keys"][key_id]["salt"] = base64.b64encode(key_salt).decode("utf-8")

        # Add dual encryption flag and salt if using dual encryption
        if dual_encryption:
            self.keystore_data["keys"][key_id]["dual_encryption"] = True
            self.keystore_data["keys"][key_id]["dual_encryption_salt"] = base64.b64encode(
                dual_encryption_salt
            ).decode("utf-8")

        return key_id

    def get_key(
        self, key_id: str, key_password: str = None, file_password: str = None
    ) -> Tuple[bytes, bytes]:
        """
        Get a key from the keystore

        Args:
            key_id: The key ID
            key_password: Password for the key if not using master password
            file_password: File password for dual encryption

        Returns:
            Tuple of (public_key, private_key)

        Raises:
            KeystoreError: If the keystore hasn't been loaded
            KeyNotFoundError: If the key doesn't exist
            KeystorePasswordError: If the key password is incorrect
        """
        if not self.keystore_data:
            raise KeystoreError("Keystore not loaded")

        # Check key cache first - skip cache if file_password provided
        # as the cache doesn't store dual-encryption information
        if key_id in self._key_cache and file_password is None:
            return self._key_cache[key_id]

        # Get key from keystore
        if "keys" not in self.keystore_data or key_id not in self.keystore_data["keys"]:
            raise KeyNotFoundError(f"Key not found: {key_id}")

        key_data = self.keystore_data["keys"][key_id]

        # Get public key
        public_key = base64.b64decode(key_data["public_key"])

        # Get and decrypt private key
        encrypted_private_key = base64.b64decode(key_data["private_key"])

        use_master_password = key_data.get("use_master_password", True)

        # Check for dual encryption flags
        dual_encryption = key_data.get("dual_encryption", False) or key_data.get(
            "from_dual_encrypted_file", False
        )

        # Prepare file_password if it's provided
        file_password_bytes = None
        if file_password is not None:
            if isinstance(file_password, str):
                file_password_bytes = file_password.encode("utf-8")
            else:
                file_password_bytes = file_password

        # Validate file_password if dual encryption is enabled
        if dual_encryption and file_password is None:
            raise KeystoreError("File password required for dual-encrypted key")

        if use_master_password:
            if not self.master_key:
                raise KeystoreError("Master key not available")

            # Decrypt with master key
            try:
                private_key = self._decrypt_data(encrypted_private_key)
            except Exception as e:
                raise KeystoreError(f"Failed to decrypt private key: {e}")
        else:
            # Using key-specific password
            if not key_password:
                raise KeystoreError("Key password required")

            # Get key salt
            if "salt" not in key_data:
                raise KeystoreCorruptedError("Key missing salt")

            key_salt = base64.b64decode(key_data["salt"])

            # Determine security level
            security_level = KeystoreSecurityLevel(
                self.keystore_data.get("security_level", "standard")
            )

            # Derive key-specific encryption key
            key_encryption_key = self._derive_key(key_password, key_salt, security_level)

            # Decrypt with key-specific encryption key
            try:
                private_key = self._decrypt_data_with_key(encrypted_private_key, key_encryption_key)
            except Exception:
                # Clean up and raise error
                secure_memzero(key_encryption_key)
                raise KeystorePasswordError("Incorrect key password")

            # Clean up
            secure_memzero(key_encryption_key)

        # Handle dual encryption if needed
        if dual_encryption:
            try:
                # Extract the dual encryption salt
                if "dual_encryption_salt" not in key_data:
                    raise KeystoreError(
                        "Missing dual encryption salt - make sure the key was created with dual encryption"
                    )

                dual_salt = base64.b64decode(key_data["dual_encryption_salt"])

                # Determine security level
                security_level = KeystoreSecurityLevel(
                    self.keystore_data.get("security_level", "standard")
                )

                # Derive file encryption key from file_password
                file_encryption_key = self._derive_key(file_password, dual_salt, security_level)

                # Import necessary AEAD cipher for decryption
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                # For dual-encrypted keys, we expect:
                # [12-byte nonce][ciphertext]
                nonce = private_key[:12]
                ciphertext = private_key[12:]

                # Create the cipher with the file key
                cipher = AESGCM(file_encryption_key)

                try:
                    # Decrypt the private key
                    private_key = cipher.decrypt(nonce, ciphertext, None)
                except Exception:
                    # Clean up and raise error - this is a file password error
                    secure_memzero(file_encryption_key)
                    raise KeystorePasswordError("Incorrect file password for dual-encrypted key")

                # Clean up
                secure_memzero(file_encryption_key)
            except Exception as e:
                if isinstance(e, KeystorePasswordError):
                    raise  # Re-raise password errors
                raise KeystoreError(f"Failed to handle dual encryption: {e}")

        # Cache the key pair if not using dual encryption
        if not dual_encryption:
            self._key_cache[key_id] = (public_key, private_key)

        return public_key, private_key

    def remove_key(self, key_id: str) -> bool:
        """
        Remove a key from the keystore

        Args:
            key_id: The key ID to remove

        Returns:
            True if the key was removed, False if it didn't exist

        Raises:
            KeystoreError: If the keystore hasn't been loaded
        """
        if not self.keystore_data:
            raise KeystoreError("Keystore not loaded")

        # Remove from keystore
        if "keys" in self.keystore_data and key_id in self.keystore_data["keys"]:
            del self.keystore_data["keys"][key_id]

            # Remove from cache
            if key_id in self._key_cache:
                del self._key_cache[key_id]

            return True
        return False

    def change_master_password(self, old_password: str, new_password: str) -> None:
        """
        Change the master password for the keystore

        Args:
            old_password: Current master password
            new_password: New master password

        Raises:
            KeystoreError: If the keystore hasn't been loaded
            KeystorePasswordError: If the old password is incorrect
        """
        # Reload the keystore with the old password to verify it
        old_keystore_data = self.keystore_data
        old_master_key = self.master_key

        try:
            self.load_keystore(old_password)
        except KeystorePasswordError:
            # Restore state and raise error
            self.keystore_data = old_keystore_data
            self.master_key = old_master_key
            raise KeystorePasswordError("Incorrect old password")

        # Generate a new salt
        new_salt = os.urandom(16)

        # Get security level
        security_level = KeystoreSecurityLevel(self.keystore_data.get("security_level", "standard"))

        # Derive new master key
        new_master_key = self._derive_master_key(new_password, new_salt, security_level)

        # Reencrypt all keys that use the master password
        keys_to_reencrypt = []
        for key_id, key_data in self.keystore_data.get("keys", {}).items():
            if key_data.get("use_master_password", True):
                # Get the key
                public_key, private_key = self.get_key(key_id)
                keys_to_reencrypt.append((key_id, public_key, private_key))

        # Update encryption parameters
        self.keystore_data["encryption"]["salt"] = base64.b64encode(new_salt).decode("utf-8")

        # Switch to new master key
        old_master_key = self.master_key
        self.master_key = new_master_key

        # Reencrypt keys
        for key_id, public_key, private_key in keys_to_reencrypt:
            # Encrypt with new master key
            encrypted_private_key = self._encrypt_data(private_key)

            # Update keystore
            self.keystore_data["keys"][key_id]["private_key"] = base64.b64encode(
                encrypted_private_key
            ).decode("utf-8")

        # Update the test key
        if "test_key" in self.keystore_data:
            test_data = b"Keystore password verification data"
            encrypted = self._encrypt_data(test_data)
            self.keystore_data["test_key"] = base64.b64encode(encrypted).decode("utf-8")

        # Clean up
        secure_memzero(old_master_key)

        # Save the keystore
        self.save_keystore()

    def change_key_password(
        self, key_id: str, old_password: str, new_password: str, use_master_password: bool = None
    ) -> None:
        """
        Change the password for a specific key

        Args:
            key_id: The key ID
            old_password: Current key password if not using master password
            new_password: New key password if not switching to master password
            use_master_password: Whether to use the master password (None = keep current setting)

        Raises:
            KeystoreError: If the keystore hasn't been loaded
            KeyNotFoundError: If the key doesn't exist
            KeystorePasswordError: If the old password is incorrect
        """
        if not self.keystore_data:
            raise KeystoreError("Keystore not loaded")

        # Get key from keystore
        if "keys" not in self.keystore_data or key_id not in self.keystore_data["keys"]:
            raise KeyNotFoundError(f"Key not found: {key_id}")

        key_data = self.keystore_data["keys"][key_id]

        # Check if we're changing how the key is encrypted
        current_uses_master = key_data.get("use_master_password", True)
        new_uses_master = (
            use_master_password if use_master_password is not None else current_uses_master
        )

        # Get the key with the old password
        try:
            public_key, private_key = self.get_key(
                key_id, old_password if not current_uses_master else None
            )
        except KeystorePasswordError:
            raise KeystorePasswordError("Incorrect old password")

        # If switching to or staying with key-specific password, check that it's provided
        if not new_uses_master and not new_password:
            raise KeystoreError("New key password required")

        # Reencrypt the key
        if new_uses_master:
            # Using master password
            if not self.master_key:
                raise KeystoreError("Master key not available")

            encrypted_private_key = self._encrypt_data(private_key)

            # Remove salt if it exists
            if "salt" in key_data:
                del key_data["salt"]
        else:
            # Using key-specific password
            # Generate a new salt
            key_salt = os.urandom(16)

            # Determine security level
            security_level = KeystoreSecurityLevel(
                self.keystore_data.get("security_level", "standard")
            )

            # Derive key-specific encryption key
            key_encryption_key = self._derive_key(new_password, key_salt, security_level)

            # Encrypt with key-specific encryption key
            encrypted_private_key = self._encrypt_data_with_key(private_key, key_encryption_key)

            # Clean up
            secure_memzero(key_encryption_key)

            # Add salt
            key_data["salt"] = base64.b64encode(key_salt).decode("utf-8")

        # Update keystore
        key_data["use_master_password"] = new_uses_master
        key_data["private_key"] = base64.b64encode(encrypted_private_key).decode("utf-8")

        # Remove from cache
        if key_id in self._key_cache:
            del self._key_cache[key_id]

        # Save the keystore
        self.save_keystore()

    def set_default_key(self, key_id: str) -> None:
        """
        Set a key as the default for its algorithm

        Args:
            key_id: The key ID to set as default

        Raises:
            KeystoreError: If the keystore hasn't been loaded
            KeyNotFoundError: If the key doesn't exist
        """
        if not self.keystore_data:
            raise KeystoreError("Keystore not loaded")

        # Get key from keystore
        if "keys" not in self.keystore_data or key_id not in self.keystore_data["keys"]:
            raise KeyNotFoundError(f"Key not found: {key_id}")

        key_data = self.keystore_data["keys"][key_id]
        algorithm = key_data.get("algorithm", "unknown")

        # Set as default
        self.keystore_data.setdefault("defaults", {})
        self.keystore_data["defaults"][algorithm] = key_id

        # Save the keystore
        self.save_keystore()

    def update_key(
        self,
        key_id: str,
        algorithm: str = None,
        public_key: bytes = None,
        private_key: bytes = None,
        description: str = None,
        tags: List[str] = None,
        dual_encryption: bool = None,
        file_password: str = None,
    ) -> bool:
        """
        Update an existing key in the keystore

        Args:
            key_id: The key ID to update
            algorithm: New algorithm name (or None to keep existing)
            public_key: New public key (or None to keep existing)
            private_key: New private key (or None to keep existing)
            description: New description (or None to keep existing)
            tags: New tags (or None to keep existing)
            dual_encryption: Whether to use dual encryption
            file_password: File password for dual encryption

        Returns:
            bool: True if update was successful

        Raises:
            KeystoreError: If the keystore hasn't been loaded or key doesn't exist
        """
        if not self.keystore_data:
            raise KeystoreError("Keystore not loaded")

        # Get key from keystore
        if "keys" not in self.keystore_data or key_id not in self.keystore_data["keys"]:
            raise KeyNotFoundError(f"Key not found: {key_id}")

        key_data = self.keystore_data["keys"][key_id]

        # Check dual encryption status
        current_dual_encryption = key_data.get("dual_encryption", False)
        new_dual_encryption = (
            dual_encryption if dual_encryption is not None else current_dual_encryption
        )

        # If enabling dual encryption, make sure file password is provided
        if new_dual_encryption and not current_dual_encryption and not file_password:
            raise KeystoreError("File password required to enable dual encryption")

        # If updating private key, handle encryption
        if private_key is not None:
            # If using dual encryption, encrypt with file password first
            private_key_to_encrypt = private_key

            if new_dual_encryption:
                try:
                    # Generate a salt for file password key derivation or use existing
                    if "dual_encryption_salt" in key_data:
                        dual_encryption_salt = base64.b64decode(key_data["dual_encryption_salt"])
                    else:
                        dual_encryption_salt = os.urandom(16)

                    # Determine security level
                    security_level = KeystoreSecurityLevel(
                        self.keystore_data.get("security_level", "standard")
                    )

                    # Derive encryption key from file password
                    file_encryption_key = self._derive_key(
                        file_password, dual_encryption_salt, security_level
                    )

                    # Use AES-GCM to encrypt the private key with the file key
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                    # Generate a nonce for AES-GCM
                    nonce = os.urandom(12)

                    # Create the cipher with the file key
                    cipher = AESGCM(file_encryption_key)

                    # Encrypt the private key
                    ciphertext = cipher.encrypt(nonce, private_key, None)

                    # Combine the nonce and ciphertext
                    private_key_to_encrypt = nonce + ciphertext

                    # Clean up
                    secure_memzero(file_encryption_key)

                    # Update dual encryption flag and salt
                    key_data["dual_encryption"] = True
                    key_data["dual_encryption_salt"] = base64.b64encode(
                        dual_encryption_salt
                    ).decode("utf-8")
                except Exception as e:
                    raise KeystoreError(f"Failed to apply dual encryption: {e}")

            # Encrypt with keystore mechanism (always uses master password for simplicity)
            encrypted_private_key = self._encrypt_data(private_key_to_encrypt)

            # Update the private key
            key_data["private_key"] = base64.b64encode(encrypted_private_key).decode("utf-8")

            # Remove from cache
            if key_id in self._key_cache:
                del self._key_cache[key_id]

        # Update other fields if provided
        if algorithm is not None:
            key_data["algorithm"] = algorithm

        if public_key is not None:
            key_data["public_key"] = base64.b64encode(public_key).decode("utf-8")

        if description is not None:
            key_data["description"] = description

        if tags is not None:
            key_data["tags"] = tags

        # Save the keystore
        self.save_keystore()

        return True

    def key_has_dual_encryption(self, key_id: str) -> bool:
        """
        Check if a key uses dual encryption

        Args:
            key_id: The key ID to check

        Returns:
            bool: True if the key uses dual encryption

        Raises:
            KeystoreError: If the keystore hasn't been loaded
            KeyNotFoundError: If the key doesn't exist
        """
        if not self.keystore_data:
            raise KeystoreError("Keystore not loaded")

        # Get key from keystore
        if "keys" not in self.keystore_data or key_id not in self.keystore_data["keys"]:
            raise KeyNotFoundError(f"Key not found: {key_id}")

        key_data = self.keystore_data["keys"][key_id]
        return key_data.get("dual_encryption", False)

    def _key_has_dual_encryption_flag(self, key_id: str, value: bool = True) -> None:
        """
        Mark a key as coming from a dual-encrypted file (metadata flag only)

        Args:
            key_id: The key ID to mark
            value: Flag value to set

        Raises:
            KeystoreError: If the keystore hasn't been loaded
            KeyNotFoundError: If the key doesn't exist
        """
        if not self.keystore_data:
            raise KeystoreError("Keystore not loaded")

        # Get key from keystore
        if "keys" not in self.keystore_data or key_id not in self.keystore_data["keys"]:
            raise KeyNotFoundError(f"Key not found: {key_id}")

        # Set the flag and save
        self.keystore_data["keys"][key_id]["from_dual_encrypted_file"] = value
        self.save_keystore()

    def get_default_key(self, algorithm: str, key_password: str = None) -> Tuple[str, bytes, bytes]:
        """
        Get the default key for an algorithm

        Args:
            algorithm: The algorithm name
            key_password: Password for the key if not using master password

        Returns:
            Tuple of (key_id, public_key, private_key)

        Raises:
            KeystoreError: If the keystore hasn't been loaded
            KeyNotFoundError: If no default key exists for the algorithm
        """
        if not self.keystore_data:
            raise KeystoreError("Keystore not loaded")

        # Check if default exists
        if "defaults" not in self.keystore_data or algorithm not in self.keystore_data["defaults"]:
            raise KeyNotFoundError(f"No default key for algorithm: {algorithm}")

        key_id = self.keystore_data["defaults"][algorithm]

        # Check if key exists
        if "keys" not in self.keystore_data or key_id not in self.keystore_data["keys"]:
            raise KeyNotFoundError(f"Default key not found: {key_id}")

        # Get the key
        public_key, private_key = self.get_key(key_id, key_password)

        return key_id, public_key, private_key

    def export_key(
        self, key_id: str, key_password: str = None, include_private: bool = True
    ) -> Dict[str, Any]:
        """
        Export a key from the keystore

        Args:
            key_id: The key ID to export
            key_password: Password for the key if not using master password
            include_private: Whether to include the private key

        Returns:
            Dictionary with key data

        Raises:
            KeystoreError: If the keystore hasn't been loaded
            KeyNotFoundError: If the key doesn't exist
        """
        if not self.keystore_data:
            raise KeystoreError("Keystore not loaded")

        # Get key from keystore
        if "keys" not in self.keystore_data or key_id not in self.keystore_data["keys"]:
            raise KeyNotFoundError(f"Key not found: {key_id}")

        key_data = self.keystore_data["keys"][key_id]

        # Get public key
        public_key = base64.b64decode(key_data["public_key"])

        result = {
            "algorithm": key_data.get("algorithm", "unknown"),
            "created": key_data.get("created", "unknown"),
            "description": key_data.get("description", ""),
            "tags": key_data.get("tags", []),
            "public_key": base64.b64encode(public_key).decode("utf-8"),
        }

        # Include private key if requested
        if include_private:
            # Get private key
            _, private_key = self.get_key(key_id, key_password)
            result["private_key"] = base64.b64encode(private_key).decode("utf-8")

        return result

    def import_key(
        self,
        key_data: Dict[str, Any],
        description: str = None,
        tags: List[str] = None,
        use_master_password: bool = True,
        key_password: str = None,
    ) -> str:
        """
        Import a key into the keystore

        Args:
            key_data: Dictionary with key data
            description: Optional description to override imported description
            tags: Optional tags to override imported tags
            use_master_password: Whether to use the master password
            key_password: Password for the key if not using master password

        Returns:
            The key ID

        Raises:
            KeystoreError: If the keystore hasn't been loaded
            ValueError: If the key data is invalid
        """
        if not self.keystore_data:
            raise KeystoreError("Keystore not loaded")

        # Validate key data
        if "algorithm" not in key_data:
            raise ValueError("Missing algorithm in key data")

        if "public_key" not in key_data:
            raise ValueError("Missing public key in key data")

        if "private_key" not in key_data:
            raise ValueError("Missing private key in key data")

        # Decode keys
        try:
            public_key = base64.b64decode(key_data["public_key"])
            private_key = base64.b64decode(key_data["private_key"])
        except Exception as e:
            raise ValueError(f"Invalid key format: {e}")

        # Add the key
        return self.add_key(
            algorithm=key_data["algorithm"],
            public_key=public_key,
            private_key=private_key,
            description=description or key_data.get("description", ""),
            tags=tags or key_data.get("tags", []),
            use_master_password=use_master_password,
            key_password=key_password,
        )

    def clear_cache(self) -> None:
        """Clear the key cache for security"""
        self._key_cache = {}

    def _derive_master_key(
        self, password: str, salt: bytes, security_level: KeystoreSecurityLevel
    ) -> bytes:
        """
        Derive the master key from the password

        Args:
            password: The master password
            salt: The salt for key derivation
            security_level: The security level for parameters

        Returns:
            The derived key
        """
        return self._derive_key(password, salt, security_level)

    def _derive_key(
        self, password: str, salt: bytes, security_level: KeystoreSecurityLevel
    ) -> bytes:
        """
        Derive an encryption key from a password

        Args:
            password: The password
            salt: The salt for key derivation
            security_level: The security level for parameters

        Returns:
            The derived key
        """
        # Get parameters for the security level
        params = self.SECURITY_PARAMS[security_level]

        # First try Argon2
        try:
            from argon2 import low_level

            key = low_level.hash_secret_raw(
                password.encode("utf-8"),
                salt,
                time_cost=params["argon2_time_cost"],
                memory_cost=params["argon2_memory_cost"],
                parallelism=params["argon2_parallelism"],
                hash_len=32,
                type=low_level.Type.ID,
            )
            return key
        except ImportError:
            # Fall back to PBKDF2
            import hashlib

            key = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt, params["pbkdf2_iterations"], dklen=32
            )
            return key

    def _encrypt_data(self, data: bytes) -> bytes:
        """
        Encrypt data with the master key

        Args:
            data: The data to encrypt

        Returns:
            The encrypted data

        Raises:
            KeystoreError: If the master key is not available
        """
        if not self.master_key:
            raise KeystoreError("Master key not available")

        return self._encrypt_data_with_key(data, self.master_key)

    def _decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data with the master key

        Args:
            encrypted_data: The encrypted data

        Returns:
            The decrypted data

        Raises:
            KeystoreError: If the master key is not available
        """
        if not self.master_key:
            raise KeystoreError("Master key not available")

        return self._decrypt_data_with_key(encrypted_data, self.master_key)

    def _encrypt_data_with_key(self, data: bytes, key: bytes) -> bytes:
        """
        Encrypt data with a key

        Args:
            data: The data to encrypt
            key: The encryption key

        Returns:
            The encrypted data
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            # Generate a random nonce
            nonce = os.urandom(12)

            # Encrypt the data
            aes = AESGCM(key)
            ciphertext = aes.encrypt(nonce, data, None)

            # Combine nonce and ciphertext
            return nonce + ciphertext
        except ImportError:
            # Fall back to Fernet
            from cryptography.fernet import Fernet

            # Adjust key if needed
            if len(key) != 32:
                key = hashlib.sha256(key).digest()

            # Create a Fernet object
            f = Fernet(base64.urlsafe_b64encode(key))

            # Encrypt the data
            return f.encrypt(data)

    def _decrypt_data_with_key(self, encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypt data with a key

        Args:
            encrypted_data: The encrypted data
            key: The encryption key

        Returns:
            The decrypted data
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            # Split nonce and ciphertext
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]

            # Decrypt the data
            aes = AESGCM(key)
            return aes.decrypt(nonce, ciphertext, None)
        except ImportError:
            # Fall back to Fernet
            from cryptography.fernet import Fernet

            # Adjust key if needed
            if len(key) != 32:
                key = hashlib.sha256(key).digest()

            # Create a Fernet object
            f = Fernet(base64.urlsafe_b64encode(key))

            # Decrypt the data
            return f.decrypt(encrypted_data)


def get_key_from_keystore(
    keystore_path: str,
    key_id: str,
    keystore_password: str,
    key_password: str = None,
    quiet: bool = False,
    file_password: str = None,
) -> Tuple[bytes, bytes]:
    """
    Get a key from a keystore (convenience function)

    Args:
        keystore_path: Path to the keystore
        key_id: The key ID
        keystore_password: Password for the keystore
        key_password: Password for the key if not using master password
        quiet: Whether to suppress output
        file_password: File password for dual encryption

    Returns:
        Tuple of (public_key, private_key)
    """
    # Load the keystore
    keystore = PQCKeystore(keystore_path)
    try:
        keystore.load_keystore(keystore_password)
    except Exception as e:
        if not quiet:
            print(f"Error loading keystore: {e}")
        raise

    # Get the key
    try:
        public_key, private_key = keystore.get_key(key_id, key_password, file_password)
    except Exception as e:
        if not quiet:
            print(f"Error getting key: {e}")
        raise
    finally:
        # Clear the cache for security
        keystore.clear_cache()

    return public_key, private_key


def add_key_to_keystore(
    keystore_path: str,
    algorithm: str,
    public_key: bytes,
    private_key: bytes,
    keystore_password: str,
    description: str = "",
    tags: List[str] = None,
    use_master_password: bool = True,
    key_password: str = None,
    create_if_missing: bool = False,
    security_level: str = "standard",
    quiet: bool = False,
    dual_encryption: bool = False,
    file_password: str = None,
) -> str:
    """
    Add a key to a keystore (convenience function)

    Args:
        keystore_path: Path to the keystore
        algorithm: The PQC algorithm name
        public_key: The public key bytes
        private_key: The private key bytes
        keystore_password: Password for the keystore
        description: Optional description of the key
        tags: Optional list of tags for the key
        use_master_password: Whether to use the master password or a separate one
        key_password: Password for the key if not using master password
        create_if_missing: Whether to create the keystore if it doesn't exist
        security_level: Security level for new keystores ("standard", "high", "paranoid")
        quiet: Whether to suppress output
        dual_encryption: Whether to use dual encryption with file password
        file_password: File password for dual encryption

    Returns:
        The key ID
    """
    # Create or load the keystore
    keystore = PQCKeystore(keystore_path)

    if os.path.exists(keystore_path):
        try:
            keystore.load_keystore(keystore_password)
        except Exception as e:
            if not quiet:
                print(f"Error loading keystore: {e}")
            raise
    elif create_if_missing:
        try:
            security = KeystoreSecurityLevel(security_level)
            keystore.create_keystore(keystore_password, security)
        except Exception as e:
            if not quiet:
                print(f"Error creating keystore: {e}")
            raise
    else:
        raise FileNotFoundError(f"Keystore not found at {keystore_path}")

    # Add the key
    try:
        key_id = keystore.add_key(
            algorithm=algorithm,
            public_key=public_key,
            private_key=private_key,
            description=description,
            tags=tags,
            use_master_password=use_master_password,
            key_password=key_password,
            dual_encryption=dual_encryption,
            file_password=file_password,
        )

        # Save the keystore
        keystore.save_keystore()
    except Exception as e:
        if not quiet:
            print(f"Error adding key: {e}")
        raise
    finally:
        # Clear the cache for security
        keystore.clear_cache()

    return key_id


def main():
    """
    Main CLI entrypoint for keystore management
    """
    parser = argparse.ArgumentParser(description="PQC Keystore Management")

    # Common arguments
    parser.add_argument("--keystore", help="Path to the keystore file", default="keystore.pqc")
    parser.add_argument("--keystore-password", help="Password for the keystore")
    parser.add_argument("--keystore-password-file", help="File containing the keystore password")
    parser.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Create keystore
    create_parser = subparsers.add_parser("create", help="Create a new keystore")
    create_parser.add_argument(
        "--keystore-standard", action="store_true", help="Use standard security settings (default)"
    )
    create_parser.add_argument(
        "--keystore-high-security", action="store_true", help="Use high security settings"
    )
    create_parser.add_argument(
        "--keystore-paranoid", action="store_true", help="Use paranoid security settings"
    )
    create_parser.add_argument("--force", action="store_true", help="Overwrite existing keystore")

    # Add key
    add_parser = subparsers.add_parser("add-key", help="Add a key to the keystore")
    add_parser.add_argument("algorithm", help="The PQC algorithm name")
    add_parser.add_argument("--key-description", help="Description of the key")
    add_parser.add_argument("--key-tags", help="Comma-separated list of tags")
    add_parser.add_argument(
        "--prompt-key-password", action="store_true", help="Use a separate password for the key"
    )
    add_parser.add_argument("--key-password-file", help="File containing the key password")

    # List keys
    list_parser = subparsers.add_parser("list-keys", help="List keys in the keystore")
    list_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # Remove key
    remove_parser = subparsers.add_parser("remove-key", help="Remove a key from the keystore")
    remove_parser.add_argument("key_id", help="The key ID to remove")

    # Set default key
    default_parser = subparsers.add_parser(
        "set-default", help="Set a key as the default for its algorithm"
    )
    default_parser.add_argument("key_id", help="The key ID to set as default")

    # Change master password
    chpass_parser = subparsers.add_parser(
        "change-master-password", help="Change the master password"
    )

    # Change key password
    chkey_parser = subparsers.add_parser("change-key-password", help="Change a key password")
    chkey_parser.add_argument("key_id", help="The key ID to change")
    chkey_parser.add_argument(
        "--convert-key-to-master", action="store_true", help="Convert to using the master password"
    )
    chkey_parser.add_argument(
        "--convert-key-to-separate",
        action="store_true",
        help="Convert to using a separate password",
    )

    # Keystore info
    info_parser = subparsers.add_parser("info", help="Show keystore information")

    # Import key
    import_parser = subparsers.add_parser("import-key", help="Import a key from a file")
    import_parser.add_argument("key_file", help="Path to the key file")
    import_parser.add_argument("--key-file-password", help="Password for the key file")
    import_parser.add_argument("--key-description", help="Description for the imported key")
    import_parser.add_argument("--key-tags", help="Comma-separated list of tags")
    import_parser.add_argument(
        "--prompt-key-password", action="store_true", help="Use a separate password for the key"
    )
    import_parser.add_argument("--key-password-file", help="File containing the key password")

    # Export key
    export_parser = subparsers.add_parser("export-key", help="Export a key to a file")
    export_parser.add_argument("key_id", help="The key ID to export")
    export_parser.add_argument("output_file", help="Path to save the key")
    export_parser.add_argument(
        "--public-only", action="store_true", help="Export only the public key"
    )
    export_parser.add_argument("--key-password-file", help="File containing the key password")

    # Export key to QR code
    export_qr_parser = subparsers.add_parser("export-qr", help="Export a key as QR code(s)")
    export_qr_parser.add_argument("key_id", help="The key ID to export")
    export_qr_parser.add_argument("output_path", help="Path to save QR image(s)")
    export_qr_parser.add_argument(
        "--public-only", action="store_true", help="Export only the public key"
    )
    export_qr_parser.add_argument(
        "--multi-qr", action="store_true", help="Allow multi-QR for large keys"
    )
    export_qr_parser.add_argument("--key-password-file", help="File containing the key password")
    export_qr_parser.add_argument(
        "--compression",
        action="store_true",
        default=True,
        help="Compress key data (default: enabled)",
    )

    # Import key from QR code
    import_qr_parser = subparsers.add_parser("import-qr", help="Import a key from QR code(s)")
    import_qr_parser.add_argument("qr_images", nargs="+", help="Path(s) to QR image file(s)")
    import_qr_parser.add_argument("--key-description", help="Description for the imported key")
    import_qr_parser.add_argument("--key-tags", help="Comma-separated list of tags")
    import_qr_parser.add_argument(
        "--prompt-key-password", action="store_true", help="Use a separate password for the key"
    )
    import_qr_parser.add_argument("--key-password-file", help="File containing the key password")

    # Create portable USB drive
    create_usb_parser = subparsers.add_parser(
        "create-usb", help="Create encrypted portable USB drive"
    )
    create_usb_parser.add_argument("usb_path", help="Path to USB drive (e.g., /dev/sdb1, E:\\)")
    create_usb_parser.add_argument("--password", help="Master password for USB encryption")
    create_usb_parser.add_argument("--password-file", help="File containing the master password")
    create_usb_parser.add_argument(
        "--executable", help="Path to OpenSSL Encrypt executable to include"
    )
    create_usb_parser.add_argument("--include-keystore", help="Path to keystore file to include")
    create_usb_parser.add_argument(
        "--security-profile",
        choices=["standard", "high-security", "paranoid"],
        default="standard",
        help="Security profile for USB encryption (default: standard)",
    )
    create_usb_parser.add_argument(
        "--enable-logs", action="store_true", help="Enable logging on USB drive"
    )

    # Add hash chaining arguments to create-usb
    _add_hash_arguments_to_parser(create_usb_parser)

    # Verify USB drive integrity
    verify_usb_parser = subparsers.add_parser("verify-usb", help="Verify USB drive integrity")
    verify_usb_parser.add_argument("usb_path", help="Path to USB drive to verify")
    verify_usb_parser.add_argument("--password", help="Master password for verification")
    verify_usb_parser.add_argument("--password-file", help="File containing the master password")

    # Add hash chaining arguments to verify-usb
    _add_hash_arguments_to_parser(verify_usb_parser)

    # Parse arguments
    args = parser.parse_args()

    # Get keystore password
    keystore_password = None
    if args.keystore_password:
        keystore_password = args.keystore_password
    elif args.keystore_password_file:
        try:
            with open(args.keystore_password_file, "r") as f:
                keystore_password = f.read().strip()
        except Exception as e:
            print(f"Error reading keystore password file: {e}")
            return 1

    # Execute command
    try:
        if args.command == "create":
            # Determine security level
            security_level = KeystoreSecurityLevel.STANDARD
            if args.keystore_high_security:
                security_level = KeystoreSecurityLevel.HIGH
            elif args.keystore_paranoid:
                security_level = KeystoreSecurityLevel.PARANOID

            # Check if keystore exists
            if os.path.exists(args.keystore) and not args.force:
                print(f"Keystore already exists at {args.keystore}. Use --force to overwrite.")
                return 1

            # Prompt for password if not provided
            if not keystore_password:
                keystore_password = getpass.getpass("Enter keystore password: ")
                confirm = getpass.getpass("Confirm password: ")
                if keystore_password != confirm:
                    print("Passwords do not match")
                    return 1

            # Create keystore
            keystore = PQCKeystore(args.keystore)
            keystore.create_keystore(keystore_password, security_level)

            if not args.quiet:
                print(f"Keystore created successfully at {args.keystore}")
                print(f"Security level: {security_level.value}")

        elif args.command == "add-key":
            # Not implemented in CLI, requires keypair
            print("This command is not implemented in the CLI.")
            print("Use the programmatic API to add keys.")
            return 1

        elif args.command == "list-keys":
            # Prompt for password if not provided
            if not keystore_password:
                keystore_password = getpass.getpass("Enter keystore password: ")

            # Load keystore
            keystore = PQCKeystore(args.keystore)
            keystore.load_keystore(keystore_password)

            # List keys
            keys = keystore.list_keys()

            if args.json:
                import json

                print(json.dumps(keys, indent=2))
            else:
                if not keys:
                    print("No keys in keystore")
                else:
                    print(f"Keys in {args.keystore}:")
                    for key in keys:
                        tags = ", ".join(key.get("tags", []))
                        print(f"ID: {key['key_id']}")
                        print(f"  Algorithm: {key.get('algorithm', 'unknown')}")
                        print(f"  Created: {key.get('created', 'unknown')}")
                        print(f"  Description: {key.get('description', '')}")
                        print(f"  Tags: {tags}")
                        print(f"  Uses master password: {key.get('use_master_password', True)}")
                        print()

        elif args.command == "remove-key":
            # Prompt for password if not provided
            if not keystore_password:
                keystore_password = getpass.getpass("Enter keystore password: ")

            # Load keystore
            keystore = PQCKeystore(args.keystore)
            keystore.load_keystore(keystore_password)

            # Remove key
            if keystore.remove_key(args.key_id):
                keystore.save_keystore()
                if not args.quiet:
                    print(f"Key {args.key_id} removed from keystore")
            else:
                print(f"Key {args.key_id} not found in keystore")
                return 1

        elif args.command == "set-default":
            # Prompt for password if not provided
            if not keystore_password:
                keystore_password = getpass.getpass("Enter keystore password: ")

            # Load keystore
            keystore = PQCKeystore(args.keystore)
            keystore.load_keystore(keystore_password)

            # Set default key
            keystore.set_default_key(args.key_id)

            if not args.quiet:
                # Get key info to show algorithm
                keys = keystore.list_keys()
                key_info = next((k for k in keys if k["key_id"] == args.key_id), None)
                if key_info:
                    algorithm = key_info.get("algorithm", "unknown")
                    print(f"Key {args.key_id} set as default for algorithm {algorithm}")
                else:
                    print(f"Key {args.key_id} set as default")

        elif args.command == "change-master-password":
            # Prompt for passwords
            if not keystore_password:
                keystore_password = getpass.getpass("Enter current keystore password: ")

            new_password = getpass.getpass("Enter new keystore password: ")
            confirm = getpass.getpass("Confirm new password: ")

            if new_password != confirm:
                print("New passwords do not match")
                return 1

            # Load keystore
            keystore = PQCKeystore(args.keystore)

            # Change password
            keystore.change_master_password(keystore_password, new_password)

            if not args.quiet:
                print("Keystore password changed successfully")

        elif args.command == "change-key-password":
            # Determine how to handle the key
            if args.convert_key_to_master and args.convert_key_to_separate:
                print("Cannot specify both --convert-key-to-master and --convert-key-to-separate")
                return 1

            use_master_password = None
            if args.convert_key_to_master:
                use_master_password = True
            elif args.convert_key_to_separate:
                use_master_password = False

            # Prompt for keystore password
            if not keystore_password:
                keystore_password = getpass.getpass("Enter keystore password: ")

            # Load keystore
            keystore = PQCKeystore(args.keystore)
            keystore.load_keystore(keystore_password)

            # Get key info to determine if it uses master password
            keys = keystore.list_keys()
            key_info = next((k for k in keys if k["key_id"] == args.key_id), None)

            if not key_info:
                print(f"Key {args.key_id} not found in keystore")
                return 1

            current_uses_master = key_info.get("use_master_password", True)

            # Get old key password if needed
            old_password = None
            if not current_uses_master:
                if args.key_password_file:
                    try:
                        with open(args.key_password_file, "r") as f:
                            old_password = f.read().strip()
                    except Exception as e:
                        print(f"Error reading key password file: {e}")
                        return 1
                else:
                    old_password = getpass.getpass("Enter current key password: ")

            # Get new key password if needed
            new_password = None
            new_uses_master = (
                use_master_password if use_master_password is not None else current_uses_master
            )

            if not new_uses_master:
                new_password = getpass.getpass("Enter new key password: ")
                confirm = getpass.getpass("Confirm new key password: ")

                if new_password != confirm:
                    print("New passwords do not match")
                    return 1

            # Change key password
            keystore.change_key_password(
                args.key_id, old_password, new_password, use_master_password
            )

            if not args.quiet:
                if new_uses_master:
                    print(f"Key {args.key_id} now uses the master password")
                else:
                    print(f"Key {args.key_id} password changed successfully")

        elif args.command == "info":
            # Prompt for password if not provided
            if not keystore_password:
                keystore_password = getpass.getpass("Enter keystore password: ")

            # Load keystore
            keystore = PQCKeystore(args.keystore)
            keystore.load_keystore(keystore_password)

            # Get keystore info
            data = keystore.keystore_data

            # Print info
            print(f"Keystore: {args.keystore}")
            print(f"Version: {data.get('version', 'unknown')}")
            print(f"Created: {data.get('created', 'unknown')}")
            print(f"Last modified: {data.get('last_modified', 'unknown')}")
            print(f"Security level: {data.get('security_level', 'standard')}")

            # Count keys by algorithm
            keys = keystore.list_keys()
            algorithms = {}
            for key in keys:
                algo = key.get("algorithm", "unknown")
                algorithms[algo] = algorithms.get(algo, 0) + 1

            print(f"Keys: {len(keys)}")
            for algo, count in algorithms.items():
                print(f"  {algo}: {count}")

            # Show default keys
            defaults = data.get("defaults", {})
            if defaults:
                print("Default keys:")
                for algo, key_id in defaults.items():
                    print(f"  {algo}: {key_id}")

        elif args.command == "import-key":
            # Not implemented in CLI
            print("This command is not implemented in the CLI.")
            print("Use the programmatic API to import keys.")
            return 1

        elif args.command == "export-key":
            # Not implemented in CLI
            print("This command is not implemented in the CLI.")
            print("Use the programmatic API to export keys.")
            return 1

        elif args.command == "export-qr":
            # Export key as QR code(s)
            return handle_export_qr_command(args, keystore_password)

        elif args.command == "import-qr":
            # Import key from QR code(s)
            return handle_import_qr_command(args, keystore_password)

        elif args.command == "create-usb":
            # Create portable USB drive
            return handle_create_usb_command(args)

        elif args.command == "verify-usb":
            # Verify USB drive integrity
            return handle_verify_usb_command(args)

        else:
            parser.print_help()
            return 1

    except KeystorePasswordError:
        print("Incorrect keystore password")
        return 1
    except KeyNotFoundError as e:
        print(str(e))
        return 1
    except KeystoreError as e:
        print(f"Keystore error: {e}")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


def handle_export_qr_command(args, keystore_password):
    """Handle export-qr command"""
    if not QR_AVAILABLE:
        print("QR code functionality not available.")
        print("Install required dependencies: pip install qrcode[pil] pyzbar")
        return 1

    try:
        # Prompt for password if not provided
        if not keystore_password:
            keystore_password = getpass.getpass("Enter keystore password: ")

        # Load keystore
        keystore = PQCKeystore(args.keystore)
        keystore.load_keystore(keystore_password)

        # Get key password if needed
        key_password = None
        if args.key_password_file:
            with open(args.key_password_file, "r") as f:
                key_password = f.read().strip()

        # Export key data
        print(f"Exporting key '{args.key_id}' to QR code...")
        key_data = keystore.export_key(args.key_id, key_password, not args.public_only)

        # Serialize key data to bytes (JSON format)
        import json

        key_json = json.dumps(key_data, separators=(",", ":")).encode("utf-8")

        # Determine QR format
        qr_format = QRKeyFormat.V1_MULTI if args.multi_qr else QRKeyFormat.V1_SINGLE

        # Create QR code(s)
        qr_dist = QRKeyDistribution()
        qr_images = qr_dist.create_key_qr(key_json, args.key_id, qr_format, args.compression)

        # Save QR image(s)
        if isinstance(qr_images, list):
            # Multi-QR: save with part numbers
            base_path = os.path.splitext(args.output_path)[0]
            for i, img in enumerate(qr_images, 1):
                part_path = f"{base_path}_part_{i:02d}.png"
                img.save(part_path)
                print(f"Saved QR part {i}/{len(qr_images)}: {part_path}")
            print(f"Key exported to {len(qr_images)} QR codes")
        else:
            # Single QR: save directly
            qr_images.save(args.output_path)
            print(f"Key exported to QR code: {args.output_path}")

        key_type = "public+private" if not args.public_only else "public only"
        print(f"Successfully exported {key_type} key '{args.key_id}' to QR code(s)")
        return 0

    except QRKeyError as e:
        print(f"QR export error: {e}")
        return 1
    except Exception as e:
        print(f"Export failed: {e}")
        return 1


def handle_import_qr_command(args, keystore_password):
    """Handle import-qr command"""
    if not QR_AVAILABLE:
        print("QR code functionality not available.")
        print("Install required dependencies: pip install qrcode[pil] pyzbar")
        return 1

    try:
        # Prompt for password if not provided
        if not keystore_password:
            keystore_password = getpass.getpass("Enter keystore password: ")

        # Load keystore
        keystore = PQCKeystore(args.keystore)
        keystore.load_keystore(keystore_password)

        # Read key from QR code(s)
        print(f"Reading key from {len(args.qr_images)} QR image(s)...")
        qr_dist = QRKeyDistribution()

        # Handle single vs multiple QR images
        if len(args.qr_images) == 1:
            qr_input = args.qr_images[0]
        else:
            qr_input = args.qr_images

        key_data_bytes, original_key_name = qr_dist.read_key_qr(qr_input)

        # Deserialize key data from JSON
        import json

        key_data = json.loads(key_data_bytes.decode("utf-8"))

        # Get key password if needed
        key_password = None
        if args.prompt_key_password:
            key_password = getpass.getpass(f"Enter password for key '{original_key_name}': ")
        elif args.key_password_file:
            with open(args.key_password_file, "r") as f:
                key_password = f.read().strip()

        # Parse tags
        tags = []
        if args.key_tags:
            tags = [tag.strip() for tag in args.key_tags.split(",")]

        # Import the key
        # Note: This would need to be implemented in the keystore
        print(f"Importing key '{original_key_name}' from QR code...")

        # For now, show what we would import
        print(f"Key name: {original_key_name}")
        print(f"Key data size: {len(key_data_bytes)} bytes")
        print(f"Description: {args.key_description or 'Imported from QR code'}")
        print(f"Tags: {tags}")

        # This would need actual keystore.import_key_data() method
        print("Note: Key import from QR codes requires keystore API enhancement")
        print("Key data successfully read and validated from QR code(s)")
        return 0

    except QRKeyError as e:
        print(f"QR import error: {e}")
        return 1
    except Exception as e:
        print(f"Import failed: {e}")
        return 1


def _add_hash_arguments_to_parser(parser):
    """Add hash chaining arguments to a parser (same as main CLI)"""
    # Hash Options group
    hash_group = parser.add_argument_group(
        "Hash Options", "Configure hashing algorithms for key derivation"
    )

    # SHA family arguments
    hash_group.add_argument(
        "--sha512-rounds", type=int, default=0, help="Number of SHA-512 iterations"
    )
    hash_group.add_argument(
        "--sha384-rounds", type=int, default=0, help="Number of SHA-384 iterations"
    )
    hash_group.add_argument(
        "--sha256-rounds", type=int, default=0, help="Number of SHA-256 iterations"
    )
    hash_group.add_argument(
        "--sha224-rounds", type=int, default=0, help="Number of SHA-224 iterations"
    )
    hash_group.add_argument(
        "--sha3-256-rounds", type=int, default=0, help="Number of SHA3-256 iterations"
    )
    hash_group.add_argument(
        "--sha3-512-rounds", type=int, default=0, help="Number of SHA3-512 iterations"
    )
    hash_group.add_argument(
        "--sha3-384-rounds", type=int, default=0, help="Number of SHA3-384 iterations"
    )
    hash_group.add_argument(
        "--sha3-224-rounds", type=int, default=0, help="Number of SHA3-224 iterations"
    )
    hash_group.add_argument(
        "--blake2b-rounds", type=int, default=0, help="Number of BLAKE2b iterations"
    )
    hash_group.add_argument(
        "--blake3-rounds", type=int, default=0, help="Number of BLAKE3 iterations"
    )
    hash_group.add_argument(
        "--shake256-rounds", type=int, default=0, help="Number of SHAKE-256 iterations"
    )
    hash_group.add_argument(
        "--shake128-rounds", type=int, default=0, help="Number of SHAKE-128 iterations"
    )
    hash_group.add_argument(
        "--whirlpool-rounds", type=int, default=0, help="Number of Whirlpool iterations"
    )
    hash_group.add_argument(
        "--pbkdf2-iterations", type=int, default=0, help="Number of PBKDF2 iterations"
    )

    # Scrypt group
    scrypt_group = parser.add_argument_group(
        "Scrypt Options", "Configure Scrypt memory-hard function"
    )
    scrypt_group.add_argument(
        "--enable-scrypt", action="store_true", help="Use Scrypt password hashing"
    )
    scrypt_group.add_argument("--scrypt-rounds", type=int, default=0, help="Scrypt iterations")
    scrypt_group.add_argument(
        "--scrypt-n", type=int, default=16384, help="Scrypt CPU/memory cost parameter"
    )
    scrypt_group.add_argument("--scrypt-r", type=int, default=8, help="Scrypt block size parameter")
    scrypt_group.add_argument(
        "--scrypt-p", type=int, default=1, help="Scrypt parallelization parameter"
    )

    # Argon2 group
    argon2_group = parser.add_argument_group(
        "Argon2 Options", "Configure Argon2 memory-hard function"
    )
    argon2_group.add_argument(
        "--enable-argon2", action="store_true", help="Use Argon2 password hashing"
    )
    argon2_group.add_argument("--argon2-rounds", type=int, default=0, help="Argon2 iterations")
    argon2_group.add_argument(
        "--argon2-time", type=int, default=3, help="Argon2 time cost parameter"
    )
    argon2_group.add_argument(
        "--argon2-memory", type=int, default=65536, help="Argon2 memory cost in KB"
    )
    argon2_group.add_argument(
        "--argon2-parallelism", type=int, default=4, help="Argon2 parallelism factor"
    )
    argon2_group.add_argument(
        "--argon2-hash-len", type=int, default=32, help="Argon2 hash length in bytes"
    )

    # Balloon group
    balloon_group = parser.add_argument_group("Balloon Hashing Options")
    balloon_group.add_argument(
        "--enable-balloon", action="store_true", help="Enable Balloon Hashing KDF"
    )
    balloon_group.add_argument(
        "--balloon-rounds", type=int, default=0, help="Balloon hashing iterations"
    )
    balloon_group.add_argument("--balloon-time-cost", type=int, default=4, help="Balloon time cost")
    balloon_group.add_argument(
        "--balloon-space-cost", type=int, default=16, help="Balloon space cost"
    )
    balloon_group.add_argument(
        "--balloon-parallelism", type=int, default=1, help="Balloon parallelism"
    )

    # HKDF group
    hkdf_group = parser.add_argument_group("HKDF Options")
    hkdf_group.add_argument("--enable-hkdf", action="store_true", help="Enable HKDF key derivation")
    hkdf_group.add_argument("--hkdf-rounds", type=int, default=0, help="HKDF iterations")
    hkdf_group.add_argument("--hkdf-algorithm", default="sha256", help="HKDF hash algorithm")
    hkdf_group.add_argument("--hkdf-info", default="", help="HKDF info parameter")


def _build_hash_config_from_args(args):
    """Build hash configuration from CLI arguments (same format as main CLI)"""
    # Build hash configuration similar to main CLI
    hash_config = {
        "sha512": getattr(args, "sha512_rounds", 0),
        "sha384": getattr(args, "sha384_rounds", 0),
        "sha256": getattr(args, "sha256_rounds", 0),
        "sha224": getattr(args, "sha224_rounds", 0),
        "sha3_256": getattr(args, "sha3_256_rounds", 0),
        "sha3_384": getattr(args, "sha3_384_rounds", 0),
        "sha3_512": getattr(args, "sha3_512_rounds", 0),
        "sha3_224": getattr(args, "sha3_224_rounds", 0),
        "blake2b": getattr(args, "blake2b_rounds", 0),
        "blake3": getattr(args, "blake3_rounds", 0),
        "shake256": getattr(args, "shake256_rounds", 0),
        "shake128": getattr(args, "shake128_rounds", 0),
        "whirlpool": getattr(args, "whirlpool_rounds", 0),
        "scrypt": {
            "enabled": getattr(args, "enable_scrypt", False),
            "n": getattr(args, "scrypt_n", 16384),
            "r": getattr(args, "scrypt_r", 8),
            "p": getattr(args, "scrypt_p", 1),
            "rounds": getattr(args, "scrypt_rounds", 0),
        },
        "argon2": {
            "enabled": getattr(args, "enable_argon2", False),
            "time_cost": getattr(args, "argon2_time", 3),
            "memory_cost": getattr(args, "argon2_memory", 65536),
            "parallelism": getattr(args, "argon2_parallelism", 4),
            "hash_len": getattr(args, "argon2_hash_len", 32),
            "type": 2,  # Default to argon2id
            "rounds": getattr(args, "argon2_rounds", 0),
        },
        "balloon": {
            "enabled": getattr(args, "enable_balloon", False),
            "time_cost": getattr(args, "balloon_time_cost", 4),
            "space_cost": getattr(args, "balloon_space_cost", 16),
            "parallelism": getattr(args, "balloon_parallelism", 1),
            "rounds": getattr(args, "balloon_rounds", 0),
        },
        "hkdf": {
            "enabled": getattr(args, "enable_hkdf", False),
            "rounds": getattr(args, "hkdf_rounds", 0),
            "algorithm": getattr(args, "hkdf_algorithm", "sha256"),
            "info": getattr(args, "hkdf_info", ""),
        },
        "pbkdf2_iterations": getattr(args, "pbkdf2_iterations", 0),
    }

    # Return None if all values are default (no hash chaining requested)
    if all(
        v == 0 or (isinstance(v, dict) and not v.get("enabled", False))
        for v in hash_config.values()
    ):
        return None

    return hash_config


def handle_create_usb_command(args):
    """Handle create-usb command"""
    if not USB_AVAILABLE:
        print("USB functionality not available.")
        print("Install required dependencies: pip install cryptography")
        return 1

    try:
        # Get USB password
        usb_password = None
        if args.password:
            usb_password = args.password
        elif args.password_file:
            with open(args.password_file, "r") as f:
                usb_password = f.read().strip()
        else:
            usb_password = getpass.getpass("Enter master password for USB encryption: ")

        if not usb_password:
            print("USB master password is required")
            return 1

        print(f"Creating portable USB drive at: {args.usb_path}")
        print(f"Security profile: {args.security_profile}")

        # Build hash configuration from CLI arguments
        hash_config = _build_hash_config_from_args(args)
        if hash_config:
            print("Using custom hash chaining configuration")
        else:
            print("Using default key derivation (Argon2 with PBKDF2 fallback)")

        # Prepare options
        options = {
            "security_profile": args.security_profile,
            "executable_path": args.executable,
            "keystore_path": args.include_keystore,
            "include_logs": args.enable_logs,
        }

        # Remove None values
        options = {k: v for k, v in options.items() if v is not None}

        # Create USB drive with hash configuration
        result = create_portable_usb(
            args.usb_path, usb_password, hash_config=hash_config, **options
        )

        if result["success"]:
            print("✅ Portable USB drive created successfully!")
            print(f"   Portable root: {result['portable_root']}")
            print(f"   Security profile: {result['security_profile']}")

            if result["executable"]["included"]:
                print(f"   Executable included: {result['executable']['path']}")
            else:
                print(f"   Executable: {result['executable']['note']}")

            if result["keystore"]["included"]:
                print(f"   Keystore included: {result['keystore']['path']}")
                print(f"   Keystore size: {result['keystore']['original_size']} bytes")
            else:
                print("   Keystore: Not included")

            print(
                f"   Workspace: {result['workspace']['path']} ({result['workspace']['encryption']})"
            )
            print(f"   Auto-run files: {', '.join(result['autorun']['files_created'])}")
            print(
                f"   Integrity protection: {result['integrity']['files_verified']} files verified"
            )

            print("\n🔒 Security Notes:")
            print("   - All workspace files are automatically encrypted")
            print("   - USB integrity is protected with tamper detection")
            print("   - Use the same master password to access the USB")
            print("   - Auto-run files enable easy launching on different platforms")

        return 0

    except USBCreationError as e:
        print(f"USB creation error: {e}")
        return 1
    except Exception as e:
        print(f"USB creation failed: {e}")
        return 1


def handle_verify_usb_command(args):
    """Handle verify-usb command"""
    if not USB_AVAILABLE:
        print("USB functionality not available.")
        print("Install required dependencies: pip install cryptography")
        return 1

    try:
        # Get USB password
        usb_password = None
        if args.password:
            usb_password = args.password
        elif args.password_file:
            with open(args.password_file, "r") as f:
                usb_password = f.read().strip()
        else:
            usb_password = getpass.getpass("Enter master password for USB verification: ")

        if not usb_password:
            print("USB master password is required")
            return 1

        print(f"Verifying USB drive integrity: {args.usb_path}")

        # Build hash configuration from CLI arguments
        hash_config = _build_hash_config_from_args(args)
        if hash_config:
            print("Using custom hash chaining configuration for verification")

        # Verify USB integrity
        result = verify_usb_integrity(args.usb_path, usb_password, hash_config=hash_config)

        print(f"📊 Verification Results:")
        print(f"   Overall integrity: {'✅ PASSED' if result['integrity_ok'] else '❌ FAILED'}")
        print(f"   Files verified: {result['verified_files']}")
        print(f"   Files failed: {result['failed_files']}")
        print(f"   Files missing: {result['missing_files']}")
        print(f"   Original file count: {result['original_file_count']}")

        if result["tampered_files"]:
            print(f"\n⚠️  Tampered files detected:")
            for file_path in result["tampered_files"]:
                print(f"      - {file_path}")

        if result["missing_file_list"]:
            print(f"\n⚠️  Missing files:")
            for file_path in result["missing_file_list"]:
                print(f"      - {file_path}")

        if result["integrity_ok"]:
            print(f"\n✅ USB drive integrity verified successfully!")
            print(f"   Created: {time.ctime(result['created_at'])}")
            return 0
        else:
            print(f"\n❌ USB drive integrity check FAILED!")
            print(f"   The drive may have been tampered with or corrupted.")
            return 1

    except USBCreationError as e:
        print(f"USB verification error: {e}")
        return 1
    except Exception as e:
        print(f"USB verification failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
