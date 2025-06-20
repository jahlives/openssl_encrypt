#!/usr/bin/env python3
"""
Detailed debug script to identify the PQCKeystore loading issue
"""

import os
import sys
import tempfile
import base64
import json
import hashlib
from typing import Dict, Tuple, Optional
import traceback

# Add the project to path
sys.path.insert(0, os.path.abspath('.'))
from openssl_encrypt.modules.pqc_keystore import (
    PQCKeystore, KeystoreSecurityLevel, KeystoreProtectionMethod
)

# Import necessary cryptography modules directly
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Check for Argon2 support
try:
    import argon2
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

def derive_key_from_password(password: str, method: str, params: Dict) -> bytes:
    """
    Derive a key from a password using the specified method and parameters
    
    Args:
        password: Password to derive key from
        method: Protection method (argon2id+aes-256-gcm, scrypt+chacha20-poly1305, etc.)
        params: Method-specific parameters
        
    Returns:
        bytes: Derived key
    """
    if method == KeystoreProtectionMethod.ARGON2ID_AES_GCM.value:
        if not ARGON2_AVAILABLE:
            raise ValueError("Argon2 is required but not available")
            
        # Extract parameters
        salt_b64 = params["salt"]
        argon2_params = params["argon2_params"]
        
        # Derive key with Argon2
        ph = PasswordHasher(
            time_cost=argon2_params["time_cost"],
            memory_cost=argon2_params["memory_cost"],
            parallelism=argon2_params["parallelism"],
            hash_len=32
        )
        
        # Hash the password with Argon2id
        hash_result = ph.hash(password + salt_b64)
        derived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()
        
    elif method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
        # Extract parameters
        salt = base64.b64decode(params["salt"])
        scrypt_params = params["scrypt_params"]
        
        # Derive key with Scrypt
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=scrypt_params["n"],
            r=scrypt_params["r"],
            p=scrypt_params["p"]
        )
        derived_key = kdf.derive(password.encode('utf-8'))
        
    elif method == KeystoreProtectionMethod.PBKDF2_AES_GCM.value:
        # Extract parameters
        salt = base64.b64decode(params["salt"])
        pbkdf2_params = params["pbkdf2_params"]
        
        # Derive key with PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=pbkdf2_params["iterations"]
        )
        derived_key = kdf.derive(password.encode('utf-8'))
        
    else:
        raise ValueError(f"Unsupported protection method: {method}")
        
    return derived_key

def manual_keystore_decrypt(file_path: str, password: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
    """
    Manually decrypt a keystore file
    
    Args:
        file_path: Path to the keystore file
        password: Master password
        
    Returns:
        Tuple[bool, Optional[Dict], Optional[str]]: (success, decrypted_data, error_message)
    """
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
            
        # Parse the encrypted data
        header_size = int.from_bytes(encrypted_data[:4], byteorder='big')
        header_bytes = encrypted_data[4:4+header_size]
        header_str = header_bytes.decode('utf-8')
        header = json.loads(header_str)
        ciphertext = encrypted_data[4+header_size:]
        
        print(f"Manual decrypt - header: {json.dumps(header, indent=2)}")
        print(f"Manual decrypt - ciphertext size: {len(ciphertext)}")
        
        # Extract parameters
        protection = header["protection"]
        method = protection["method"]
        params = protection["params"]
        
        # Get parameters
        nonce = base64.b64decode(params["nonce"])
        print(f"Manual decrypt - method: {method}")
        print(f"Manual decrypt - nonce (hex): {nonce.hex()}")
        print(f"Manual decrypt - nonce length: {len(nonce)}")
        
        # Create associated data
        associated_data = None
        if method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
            # ChaCha20Poly1305 uses the header as associated data
            associated_data = json.dumps(header).encode('utf-8')
            print(f"Manual decrypt - associated data provided for ChaCha20Poly1305")
        
        # Manually derive the key
        derived_key = derive_key_from_password(password, method, params)
        print(f"Manual decrypt - derived key (hex): {derived_key.hex()}")
        
        # Decrypt with the appropriate algorithm
        if method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            cipher = ChaCha20Poly1305(derived_key)
            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=associated_data)
        else:
            # AES-GCM (used by both Argon2id and PBKDF2 methods)
            cipher = AESGCM(derived_key)
            try:
                # First try with associated_data=None (creation)
                plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
                print("Manual decrypt - Successfully decrypted with associated_data=None")
            except Exception as e1:
                print(f"Manual decrypt - Failed with associated_data=None: {e1}")
                try:
                    # Then try with header as associated data (loading)
                    header_associated_data = json.dumps(header).encode('utf-8')
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=header_associated_data)
                    print("Manual decrypt - Successfully decrypted with header as associated_data")
                except Exception as e2:
                    print(f"Manual decrypt - Failed with header as associated_data: {e2}")
                    try:
                        # Try with just the header bytes
                        plaintext = cipher.decrypt(nonce, ciphertext, associated_data=header_bytes)
                        print("Manual decrypt - Successfully decrypted with header_bytes as associated_data")
                    except Exception as e3:
                        print(f"Manual decrypt - Failed with header_bytes as associated_data: {e3}")
                        return False, None, f"Decryption failed: {e1} / {e2} / {e3}"
        
        # Parse the decrypted data
        decrypted_data = json.loads(plaintext.decode('utf-8'))
        return True, decrypted_data, None
        
    except Exception as e:
        traceback.print_exc()
        return False, None, f"Error: {str(e)}"

def compare_save_and_load_processes():
    """Compare the encryption/decryption processes when saving vs loading keystores"""
    # Create a temporary directory for test files
    temp_dir = tempfile.mkdtemp()
    keystore_path = os.path.join(temp_dir, "test_keystore.pqc")
    
    # Master password for tests
    master_password = "test_master_password"
    
    print("\n=== Testing for differences between saving and loading processes ===")
    
    # Create a simple keystore
    print("\nStep 1: Creating keystore")
    keystore = PQCKeystore(keystore_path)
    keystore.create_keystore(master_password, KeystoreSecurityLevel.STANDARD)
    
    # Manually inspect the keystore file and try to decrypt it
    print("\nStep 2: Manually decrypting the keystore file")
    success, decrypted_data, error = manual_keystore_decrypt(keystore_path, master_password)
    
    if success:
        print("Manual decryption succeeded!")
        print(f"Decrypted data: {json.dumps(decrypted_data, indent=2)}")
    else:
        print(f"Manual decryption failed: {error}")
    
    # Create a modified version of the keystore to test AES-GCM associated data parameters
    print("\n=== Creating modified keystore for testing associated data handling ===")
    
    # Get the keystore file content
    with open(keystore_path, 'rb') as f:
        data = f.read()
    
    # Modify with associated data differences
    keystore_path_mod1 = os.path.join(temp_dir, "test_keystore_mod1.pqc")
    keystore_path_mod2 = os.path.join(temp_dir, "test_keystore_mod2.pqc")
    
    # Create a temporary working directory
    os.makedirs(os.path.dirname(keystore_path_mod1), exist_ok=True)
    
    # Extract header
    header_size = int.from_bytes(data[:4], byteorder='big')
    header_json = data[4:4+header_size].decode('utf-8')
    header = json.loads(header_json)
    
    # Create a customized keystore file
    temp_keystore = PQCKeystore(keystore_path_mod1)
    temp_keystore.create_keystore(master_password, KeystoreSecurityLevel.STANDARD)
    
    # Attempt to load it
    print("\nTesting standard keystore load")
    try:
        load_keystore = PQCKeystore(keystore_path_mod1)
        load_keystore.load_keystore(master_password)
        print("Keystore loaded successfully!")
    except Exception as e:
        print(f"Failed to load keystore: {e}")
        
if __name__ == "__main__":
    compare_save_and_load_processes()