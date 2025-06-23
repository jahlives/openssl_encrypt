#!/usr/bin/env python3
"""
Debug script to analyze PQCKeystore encryption and decryption parameters
"""

import os
import sys
import tempfile
import base64
import json
import hashlib
import traceback
from typing import Dict, List, Tuple, Any
import copy

# Add the project to path
sys.path.insert(0, os.path.abspath('.'))
from openssl_encrypt.modules.pqc_keystore import (
    PQCKeystore, KeystoreSecurityLevel, KeystoreProtectionMethod
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# Monkey patch the AESGCM class to log encryption and decryption parameters
original_encrypt = AESGCM.encrypt
original_decrypt = AESGCM.decrypt

def debug_encrypt(self, nonce, data, associated_data):
    """Debug wrapper for encrypt method"""
    print("\n=== AESGCM ENCRYPT ===")
    print(f"Nonce: {base64.b64encode(nonce).decode('utf-8')}")
    print(f"Associated data: {associated_data!r}")
    if associated_data is not None:
        print(f"  - Type: {type(associated_data)}")
        print(f"  - Value (base64): {base64.b64encode(associated_data).decode('utf-8')}")
    result = original_encrypt(self, nonce, data, associated_data)
    print(f"Ciphertext length: {len(result)}")
    print("=== END ENCRYPT ===\n")
    return result

def debug_decrypt(self, nonce, data, associated_data):
    """Debug wrapper for decrypt method"""
    print("\n=== AESGCM DECRYPT ===")
    print(f"Nonce: {base64.b64encode(nonce).decode('utf-8')}")
    print(f"Associated data: {associated_data!r}")
    if associated_data is not None:
        print(f"  - Type: {type(associated_data)}")
        print(f"  - Value (base64): {base64.b64encode(associated_data).decode('utf-8')}")
    print(f"Ciphertext length: {len(data)}")
    try:
        result = original_decrypt(self, nonce, data, associated_data)
        print("Decrypt SUCCESS")
        print("=== END DECRYPT ===\n")
        return result
    except Exception as e:
        print(f"Decrypt FAILED: {e}")
        print("=== END DECRYPT ===\n")
        raise

# Patch the methods
AESGCM.encrypt = debug_encrypt
AESGCM.decrypt = debug_decrypt

def load_keystore_with_debug(keystore_path, master_password):
    """Load a keystore with detailed debug output"""
    print("\n=== DEBUG: LOADING KEYSTORE ===")
    
    # Read the file directly to see header structure
    with open(keystore_path, 'rb') as f:
        encrypted_data = f.read()
        
    # Parse the encrypted data
    header_size = int.from_bytes(encrypted_data[:4], byteorder='big')
    header_bytes = encrypted_data[4:4+header_size]
    header = json.loads(header_bytes.decode('utf-8'))
    ciphertext = encrypted_data[4+header_size:]
    
    print(f"File size: {len(encrypted_data)} bytes")
    print(f"Header size: {header_size} bytes")
    print(f"Header content: {json.dumps(header, indent=2)}")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    
    # Extract parameters
    protection = header["protection"]
    method = protection["method"]
    params = protection["params"]
    
    print(f"Method: {method}")
    print(f"Nonce (base64): {params['nonce']}")
    
    # Now try different associated_data values for decryption
    # in a way that doesn't affect the original code
    
    if method.endswith("aes-256-gcm"):
        # These are the possible associated_data values to try
        test_values = [
            ("None", None),
            ("Empty bytes", b''),
            ("Header JSON", json.dumps(header).encode('utf-8')),
            ("Protection JSON", json.dumps({"protection": protection}).encode('utf-8')),
        ]
        
        # We'll derive the key ourselves for testing
        # This is simplified to just test AES-GCM - would need to handle other methods in real code
        print("\nDeriving key from master password...")
        
        # Basic Argon2id parameters for paranoid level
        import argon2
        from argon2 import PasswordHasher
        
        # Derive key with Argon2 - simplifying for debug only
        argon2_params = params.get("argon2_params", {
            "time_cost": 8,
            "memory_cost": 262144,  # 256 MB
            "parallelism": 4
        })
        
        ph = PasswordHasher(
            time_cost=argon2_params["time_cost"],
            memory_cost=argon2_params["memory_cost"],
            parallelism=argon2_params["parallelism"],
            hash_len=32
        )
        
        # Encode salt as required by argon2-cffi
        salt_b64 = params["salt"]
        
        # Hash the password with Argon2id
        hash_result = ph.hash(master_password + salt_b64)
        derived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()
        
        print(f"Derived key (base64): {base64.b64encode(derived_key).decode('utf-8')}")
        
        # Now try each associated_data value
        print("\nTesting decryption with different associated_data values:")
        nonce = base64.b64decode(params["nonce"])
        
        for name, value in test_values:
            print(f"\nTesting with associated_data = {name}")
            cipher = AESGCM(derived_key)
            try:
                plaintext = cipher.decrypt(nonce, ciphertext, associated_data=value)
                print(f"SUCCESS! Decryption worked with {name}")
                print(f"Decrypted plaintext start: {plaintext[:100]}")
                # Try to parse as JSON to confirm it's the right content
                json_data = json.loads(plaintext.decode('utf-8'))
                print(f"Parsed as valid JSON - contains {len(json_data)} keys: {list(json_data.keys())}")
            except Exception as e:
                print(f"FAILED with {name}: {e}")
        
    print("\n=== END DEBUG: LOADING KEYSTORE ===\n")

def test_with_debug():
    """Test the PQCKeystore with debug output"""
    # Create a temporary directory for test files
    temp_dir = tempfile.mkdtemp()
    keystore_path = os.path.join(temp_dir, "debug_keystore.pqc")
    
    # Master password for tests
    master_password = "test_master_password"
    
    print("\n=== DEBUG TESTING: PQCKeystore ===")
    
    # Create a standard keystore
    print("\nStep 1: Creating keystore with standard security level")
    keystore = PQCKeystore(keystore_path)
    try:
        result = keystore.create_keystore(master_password, KeystoreSecurityLevel.STANDARD)
        print(f"Keystore created successfully: {result}")
    except Exception as e:
        print(f"Error creating keystore: {str(e)}")
        traceback.print_exc()
        return
    
    # Now run our debug loader
    print("\nStep 2: Debugging keystore loading...")
    try:
        load_keystore_with_debug(keystore_path, master_password)
    except Exception as e:
        print(f"Debug loader encountered error: {str(e)}")
        traceback.print_exc()
    
    # Now try using the original loader to see what happens
    print("\nStep 3: Trying original keystore.load_keystore...")
    keystore2 = PQCKeystore(keystore_path)
    try:
        result = keystore2.load_keystore(master_password)
        print(f"Original loader result: {result}")
    except Exception as e:
        print(f"Original loader error: {str(e)}")
        traceback.print_exc()

if __name__ == "__main__":
    test_with_debug()