#!/usr/bin/env python3
"""
Command-line interface for PQC keystore
"""

import os
import sys
import uuid
import json
import base64
import getpass
import hashlib
import argparse
import datetime
from enum import Enum
from typing import Dict, Any, List, Tuple, Optional

# Add UTC constant for Python < 3.11
if not hasattr(datetime, 'UTC'):
    datetime.UTC = datetime.timezone.utc

from .crypt_errors import (
    KeystoreError, KeystorePasswordError, KeyNotFoundError, 
    KeystoreCorruptedError, KeystoreVersionError
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
            "argon2_parallelism": 4
        },
        KeystoreSecurityLevel.HIGH: {
            "pbkdf2_iterations": 500000,
            "argon2_time_cost": 6,
            "argon2_memory_cost": 262144,
            "argon2_parallelism": 8
        },
        KeystoreSecurityLevel.PARANOID: {
            "pbkdf2_iterations": 1000000,
            "argon2_time_cost": 8,
            "argon2_memory_cost": 1048576,
            "argon2_parallelism": 8
        }
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
        
    def create_keystore(self, password: str, security_level: KeystoreSecurityLevel = KeystoreSecurityLevel.STANDARD) -> None:
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
            "created": datetime.datetime.now(datetime.UTC).isoformat() + "Z",
            "last_modified": datetime.datetime.now(datetime.UTC).isoformat() + "Z",
            "security_level": security_level.value,
            "encryption": {
                "salt": base64.b64encode(salt).decode('utf-8'),
                **self.SECURITY_PARAMS[security_level]
            },
            "keys": {}
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
            with open(self.keystore_path, 'r') as f:
                self.keystore_data = json.load(f)
        except json.JSONDecodeError:
            raise KeystoreCorruptedError("Keystore file is corrupted or invalid JSON")
            
        # Validate version
        if "version" not in self.keystore_data or self.keystore_data["version"] != self.KEYSTORE_VERSION:
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
        self.keystore_data["last_modified"] = datetime.datetime.now(datetime.UTC).isoformat() + "Z"
        
        # Add a test key for password verification if it doesn't exist
        if "test_key" not in self.keystore_data and self.master_key:
            test_data = b"Keystore password verification data"
            encrypted = self._encrypt_data(test_data)
            self.keystore_data["test_key"] = base64.b64encode(encrypted).decode('utf-8')
        
        # Create a temporary file first
        temp_path = self.keystore_path + ".tmp"
        with open(temp_path, 'w') as f:
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
                "use_master_password": key_data.get("use_master_password", True)
            }
            keys.append(key_info)
            
        # Sort by creation date, newest first
        return sorted(keys, key=lambda k: k.get("created", ""), reverse=True)
        
    def add_key(self, algorithm: str, public_key: bytes, private_key: bytes, 
                 description: str = "", tags: List[str] = None, 
                 use_master_password: bool = True, key_password: str = None,
                 dual_encryption: bool = False, file_password: str = None) -> str:
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
        public_key_b64 = base64.b64encode(public_key).decode('utf-8')
        
        # Apply dual encryption if enabled
        private_key_to_encrypt = private_key
        dual_encryption_salt = None
        
        if dual_encryption and file_password:
            try:
                # Generate a salt for file password key derivation
                dual_encryption_salt = os.urandom(16)
                
                # Determine security level
                security_level = KeystoreSecurityLevel(self.keystore_data.get("security_level", "standard"))
                
                # Derive encryption key from file password
                file_encryption_key = self._derive_key(file_password, dual_encryption_salt, security_level)
                
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
            security_level = KeystoreSecurityLevel(self.keystore_data.get("security_level", "standard"))
            key_encryption_key = self._derive_key(key_password, key_salt, security_level)
            
            # Encrypt with key-specific encryption key
            encrypted_private_key = self._encrypt_data_with_key(private_key_to_encrypt, key_encryption_key)
            
            # Clean up the key
            secure_memzero(key_encryption_key)
            
        # Add to keystore
        self.keystore_data.setdefault("keys", {})
        self.keystore_data["keys"][key_id] = {
            "algorithm": algorithm,
            "created": datetime.datetime.now(datetime.UTC).isoformat() + "Z",
            "description": description,
            "tags": tags or [],
            "use_master_password": use_master_password,
            "public_key": public_key_b64,
            "private_key": base64.b64encode(encrypted_private_key).decode('utf-8')
        }
        
        # Add salt if using separate password
        if not use_master_password:
            self.keystore_data["keys"][key_id]["salt"] = base64.b64encode(key_salt).decode('utf-8')
            
        # Add dual encryption flag and salt if using dual encryption
        if dual_encryption:
            self.keystore_data["keys"][key_id]["dual_encryption"] = True
            self.keystore_data["keys"][key_id]["dual_encryption_salt"] = base64.b64encode(dual_encryption_salt).decode('utf-8')
            
        return key_id
        
    def get_key(self, key_id: str, key_password: str = None, file_password: str = None) -> Tuple[bytes, bytes]:
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
        dual_encryption = key_data.get("dual_encryption", False) or \
                         key_data.get("from_dual_encrypted_file", False)
        
        # Prepare file_password if it's provided
        file_password_bytes = None
        if file_password is not None:
            if isinstance(file_password, str):
                file_password_bytes = file_password.encode('utf-8')
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
            security_level = KeystoreSecurityLevel(self.keystore_data.get("security_level", "standard"))
            
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
                    raise KeystoreError("Missing dual encryption salt - make sure the key was created with dual encryption")
                    
                dual_salt = base64.b64decode(key_data["dual_encryption_salt"])
                
                # Determine security level
                security_level = KeystoreSecurityLevel(self.keystore_data.get("security_level", "standard"))
                
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
        self.keystore_data["encryption"]["salt"] = base64.b64encode(new_salt).decode('utf-8')
        
        # Switch to new master key
        old_master_key = self.master_key
        self.master_key = new_master_key
        
        # Reencrypt keys
        for key_id, public_key, private_key in keys_to_reencrypt:
            # Encrypt with new master key
            encrypted_private_key = self._encrypt_data(private_key)
            
            # Update keystore
            self.keystore_data["keys"][key_id]["private_key"] = base64.b64encode(encrypted_private_key).decode('utf-8')
            
        # Update the test key
        if "test_key" in self.keystore_data:
            test_data = b"Keystore password verification data"
            encrypted = self._encrypt_data(test_data)
            self.keystore_data["test_key"] = base64.b64encode(encrypted).decode('utf-8')
            
        # Clean up
        secure_memzero(old_master_key)
        
        # Save the keystore
        self.save_keystore()
        
    def change_key_password(self, key_id: str, old_password: str, new_password: str, 
                            use_master_password: bool = None) -> None:
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
        new_uses_master = use_master_password if use_master_password is not None else current_uses_master
        
        # Get the key with the old password
        try:
            public_key, private_key = self.get_key(key_id, old_password if not current_uses_master else None)
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
            security_level = KeystoreSecurityLevel(self.keystore_data.get("security_level", "standard"))
            
            # Derive key-specific encryption key
            key_encryption_key = self._derive_key(new_password, key_salt, security_level)
            
            # Encrypt with key-specific encryption key
            encrypted_private_key = self._encrypt_data_with_key(private_key, key_encryption_key)
            
            # Clean up
            secure_memzero(key_encryption_key)
            
            # Add salt
            key_data["salt"] = base64.b64encode(key_salt).decode('utf-8')
            
        # Update keystore
        key_data["use_master_password"] = new_uses_master
        key_data["private_key"] = base64.b64encode(encrypted_private_key).decode('utf-8')
        
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
        
    def update_key(self, key_id: str, algorithm: str = None, public_key: bytes = None, 
                  private_key: bytes = None, description: str = None, tags: List[str] = None, 
                  dual_encryption: bool = None, file_password: str = None) -> bool:
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
        new_dual_encryption = dual_encryption if dual_encryption is not None else current_dual_encryption
        
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
                    security_level = KeystoreSecurityLevel(self.keystore_data.get("security_level", "standard"))
                    
                    # Derive encryption key from file password
                    file_encryption_key = self._derive_key(file_password, dual_encryption_salt, security_level)
                    
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
                    key_data["dual_encryption_salt"] = base64.b64encode(dual_encryption_salt).decode('utf-8')
                except Exception as e:
                    raise KeystoreError(f"Failed to apply dual encryption: {e}")
                    
            # Encrypt with keystore mechanism (always uses master password for simplicity)
            encrypted_private_key = self._encrypt_data(private_key_to_encrypt)
            
            # Update the private key
            key_data["private_key"] = base64.b64encode(encrypted_private_key).decode('utf-8')
            
            # Remove from cache
            if key_id in self._key_cache:
                del self._key_cache[key_id]
            
        # Update other fields if provided
        if algorithm is not None:
            key_data["algorithm"] = algorithm
            
        if public_key is not None:
            key_data["public_key"] = base64.b64encode(public_key).decode('utf-8')
            
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
        
    def export_key(self, key_id: str, key_password: str = None, 
                   include_private: bool = True) -> Dict[str, Any]:
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
            "public_key": base64.b64encode(public_key).decode('utf-8')
        }
        
        # Include private key if requested
        if include_private:
            # Get private key
            _, private_key = self.get_key(key_id, key_password)
            result["private_key"] = base64.b64encode(private_key).decode('utf-8')
            
        return result
        
    def import_key(self, key_data: Dict[str, Any], description: str = None, 
                   tags: List[str] = None, use_master_password: bool = True, 
                   key_password: str = None) -> str:
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
            key_password=key_password
        )
        
    def clear_cache(self) -> None:
        """Clear the key cache for security"""
        self._key_cache = {}
        
    def _derive_master_key(self, password: str, salt: bytes, 
                          security_level: KeystoreSecurityLevel) -> bytes:
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
        
    def _derive_key(self, password: str, salt: bytes, 
                   security_level: KeystoreSecurityLevel) -> bytes:
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
                password.encode('utf-8'),
                salt,
                time_cost=params["argon2_time_cost"],
                memory_cost=params["argon2_memory_cost"],
                parallelism=params["argon2_parallelism"],
                hash_len=32,
                type=low_level.Type.ID
            )
            return key
        except ImportError:
            # Fall back to PBKDF2
            import hashlib
            
            key = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                params["pbkdf2_iterations"],
                dklen=32
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


def get_key_from_keystore(keystore_path: str, key_id: str, 
                         keystore_password: str, key_password: str = None,
                         quiet: bool = False, file_password: str = None) -> Tuple[bytes, bytes]:
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


def add_key_to_keystore(keystore_path: str, algorithm: str, public_key: bytes, 
                       private_key: bytes, keystore_password: str,
                       description: str = "", tags: List[str] = None,
                       use_master_password: bool = True, key_password: str = None,
                       create_if_missing: bool = False, security_level: str = "standard",
                       quiet: bool = False, dual_encryption: bool = False, 
                       file_password: str = None) -> str:
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
            file_password=file_password
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
    parser.add_argument('--keystore', help='Path to the keystore file',
                       default='keystore.pqc')
    parser.add_argument('--keystore-password', help='Password for the keystore')
    parser.add_argument('--keystore-password-file', help='File containing the keystore password')
    parser.add_argument('--quiet', action='store_true', help='Suppress non-error output')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Create keystore
    create_parser = subparsers.add_parser('create', help='Create a new keystore')
    create_parser.add_argument('--keystore-standard', action='store_true',
                             help='Use standard security settings (default)')
    create_parser.add_argument('--keystore-high-security', action='store_true',
                             help='Use high security settings')
    create_parser.add_argument('--keystore-paranoid', action='store_true',
                             help='Use paranoid security settings')
    create_parser.add_argument('--force', action='store_true',
                             help='Overwrite existing keystore')
    
    # Add key
    add_parser = subparsers.add_parser('add-key', help='Add a key to the keystore')
    add_parser.add_argument('algorithm', help='The PQC algorithm name')
    add_parser.add_argument('--key-description', help='Description of the key')
    add_parser.add_argument('--key-tags', help='Comma-separated list of tags')
    add_parser.add_argument('--prompt-key-password', action='store_true',
                          help='Use a separate password for the key')
    add_parser.add_argument('--key-password-file', help='File containing the key password')
    
    # List keys
    list_parser = subparsers.add_parser('list-keys', help='List keys in the keystore')
    list_parser.add_argument('--json', action='store_true',
                           help='Output as JSON')
    
    # Remove key
    remove_parser = subparsers.add_parser('remove-key', help='Remove a key from the keystore')
    remove_parser.add_argument('key_id', help='The key ID to remove')
    
    # Set default key
    default_parser = subparsers.add_parser('set-default', help='Set a key as the default for its algorithm')
    default_parser.add_argument('key_id', help='The key ID to set as default')
    
    # Change master password
    chpass_parser = subparsers.add_parser('change-master-password', help='Change the master password')
    
    # Change key password
    chkey_parser = subparsers.add_parser('change-key-password', help='Change a key password')
    chkey_parser.add_argument('key_id', help='The key ID to change')
    chkey_parser.add_argument('--convert-key-to-master', action='store_true',
                            help='Convert to using the master password')
    chkey_parser.add_argument('--convert-key-to-separate', action='store_true',
                            help='Convert to using a separate password')
    
    # Keystore info
    info_parser = subparsers.add_parser('info', help='Show keystore information')
    
    # Import key
    import_parser = subparsers.add_parser('import-key', help='Import a key from a file')
    import_parser.add_argument('key_file', help='Path to the key file')
    import_parser.add_argument('--key-file-password', help='Password for the key file')
    import_parser.add_argument('--key-description', help='Description for the imported key')
    import_parser.add_argument('--key-tags', help='Comma-separated list of tags')
    import_parser.add_argument('--prompt-key-password', action='store_true',
                             help='Use a separate password for the key')
    import_parser.add_argument('--key-password-file', help='File containing the key password')
    
    # Export key
    export_parser = subparsers.add_parser('export-key', help='Export a key to a file')
    export_parser.add_argument('key_id', help='The key ID to export')
    export_parser.add_argument('output_file', help='Path to save the key')
    export_parser.add_argument('--public-only', action='store_true',
                             help='Export only the public key')
    export_parser.add_argument('--key-password-file', help='File containing the key password')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Get keystore password
    keystore_password = None
    if args.keystore_password:
        keystore_password = args.keystore_password
    elif args.keystore_password_file:
        try:
            with open(args.keystore_password_file, 'r') as f:
                keystore_password = f.read().strip()
        except Exception as e:
            print(f"Error reading keystore password file: {e}")
            return 1
    
    # Execute command
    try:
        if args.command == 'create':
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
                
        elif args.command == 'add-key':
            # Not implemented in CLI, requires keypair
            print("This command is not implemented in the CLI.")
            print("Use the programmatic API to add keys.")
            return 1
            
        elif args.command == 'list-keys':
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
                        
        elif args.command == 'remove-key':
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
                
        elif args.command == 'set-default':
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
                    
        elif args.command == 'change-master-password':
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
                
        elif args.command == 'change-key-password':
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
                        with open(args.key_password_file, 'r') as f:
                            old_password = f.read().strip()
                    except Exception as e:
                        print(f"Error reading key password file: {e}")
                        return 1
                else:
                    old_password = getpass.getpass("Enter current key password: ")
                    
            # Get new key password if needed
            new_password = None
            new_uses_master = use_master_password if use_master_password is not None else current_uses_master
            
            if not new_uses_master:
                new_password = getpass.getpass("Enter new key password: ")
                confirm = getpass.getpass("Confirm new key password: ")
                
                if new_password != confirm:
                    print("New passwords do not match")
                    return 1
                    
            # Change key password
            keystore.change_key_password(args.key_id, old_password, new_password, use_master_password)
            
            if not args.quiet:
                if new_uses_master:
                    print(f"Key {args.key_id} now uses the master password")
                else:
                    print(f"Key {args.key_id} password changed successfully")
                    
        elif args.command == 'info':
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
                    
        elif args.command == 'import-key':
            # Not implemented in CLI
            print("This command is not implemented in the CLI.")
            print("Use the programmatic API to import keys.")
            return 1
            
        elif args.command == 'export-key':
            # Not implemented in CLI
            print("This command is not implemented in the CLI.")
            print("Use the programmatic API to export keys.")
            return 1
            
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

if __name__ == "__main__":
    sys.exit(main())