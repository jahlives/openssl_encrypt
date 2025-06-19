#!/usr/bin/env python3
"""
Debug script to diagnose the PQCKeystore issue
"""

import os
import sys
import tempfile
import json
import base64
import secrets
import hashlib
import time
import traceback

# Add the project to path
sys.path.insert(0, os.path.abspath('.'))
from openssl_encrypt.modules.pqc_keystore import (
    PQCKeystore, KeystoreSecurityLevel, KeystoreProtectionMethod
)
from openssl_encrypt.modules.crypt_errors import InternalError

# Import crypto libraries directly
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def inspect_keystore_file(keystore_path):
    """Inspect the contents of a keystore file"""
    print(f"\n=== Inspecting keystore file: {keystore_path} ===")
    
    try:
        with open(keystore_path, 'rb') as f:
            encrypted_data = f.read()
            
        # Parse the encrypted data
        header_size = int.from_bytes(encrypted_data[:4], byteorder='big')
        header_bytes = encrypted_data[4:4+header_size]
        header = json.loads(header_bytes.decode('utf-8'))
        ciphertext = encrypted_data[4+header_size:]
        
        print(f"Header size: {header_size}")
        print(f"Header: {json.dumps(header, indent=2)}")
        print(f"Ciphertext length: {len(ciphertext)}")
        
        return header, ciphertext
        
    except Exception as e:
        print(f"Error inspecting keystore: {e}")
        traceback.print_exc()
        return None, None

def debug_keystore_creation():
    """Debug the keystore creation and loading process"""
    # Create a temporary directory for test files
    temp_dir = tempfile.mkdtemp()
    keystore_path = os.path.join(temp_dir, "debug_keystore.pqc")
    
    # Master password for tests
    master_password = "test_master_password"
    
    print("\n=== Debugging PQCKeystore Creation and Loading ===")
    
    # Create a keystore
    print("\nStep 1: Creating keystore")
    keystore = PQCKeystore(keystore_path)
    try:
        result = keystore.create_keystore(master_password, KeystoreSecurityLevel.STANDARD)
        print(f"Keystore created successfully: {result}")
        
        # Inspect the created keystore file
        header, ciphertext = inspect_keystore_file(keystore_path)
        if header is None:
            return
        
        # Print the header and protection details
        protection = header["protection"]
        method = protection["method"]
        params = protection["params"]
        
        print(f"\nEncryption method: {method}")
        
        # Now intercept the encryption process and trace it step by step
        print("\nStep 2: Manual decryption attempt")
        
        # Derive the key manually
        derived_key = None
        
        if method == KeystoreProtectionMethod.ARGON2ID_AES_GCM.value:
            print("Using Argon2id key derivation")
            
            try:
                import argon2
                from argon2 import PasswordHasher
                argon2_params = params["argon2_params"]
                ph = PasswordHasher(
                    time_cost=argon2_params["time_cost"],
                    memory_cost=argon2_params["memory_cost"],
                    parallelism=argon2_params["parallelism"],
                    hash_len=32
                )
                
                salt_b64 = params["salt"]
                print(f"Salt (base64): {salt_b64}")
                
                # Hash the password with Argon2id
                hash_result = ph.hash(master_password + salt_b64)
                print(f"Hash result: {hash_result}")
                derived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()
                print(f"Derived key (hex): {derived_key.hex()}")
                
            except ImportError:
                print("Argon2 not available")
                return
                
        elif method == KeystoreProtectionMethod.SCRYPT_CHACHA20.value:
            print("Using Scrypt key derivation")
            
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
            print(f"Derived key (hex): {derived_key.hex()}")
            
        elif method == KeystoreProtectionMethod.PBKDF2_AES_GCM.value:
            print("Using PBKDF2 key derivation")
            
            salt = base64.b64decode(params["salt"])
            pbkdf2_params = params["pbkdf2_params"]
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=pbkdf2_params["iterations"]
            )
            derived_key = kdf.derive(master_password.encode('utf-8'))
            print(f"Derived key (hex): {derived_key.hex()}")
        
        else:
            print(f"Unsupported method: {method}")
            return
        
        # Now try to decrypt
        nonce = base64.b64decode(params["nonce"])
        print(f"Nonce (hex): {nonce.hex()}")
        
        # Try decryption with different associated_data values
        header_json = json.dumps(header).encode('utf-8')
        print(f"Header JSON: {header_json}")
        
        if "CHACHA20" in method:
            cipher = ChaCha20Poly1305(derived_key)
        else:  # AES-GCM
            cipher = AESGCM(derived_key)
            
        # Print the actual ciphertext for debugging
        print(f"Ciphertext (first 20 bytes hex): {ciphertext[:20].hex()}")
        
        # Try multiple approaches
        success = False
        
        print("\nAttempting decryption with the same header...")
        try:
            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=header_json)
            print(f"SUCCESS! Decrypted plaintext: {plaintext[:100]}...")
            json_data = json.loads(plaintext)
            print(f"JSON keys: {list(json_data.keys())}")
            success = True
        except Exception as e:
            print(f"Failed with header as associated_data: {e}")
        
        print("\nAttempting decryption with None...")
        try:
            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
            print(f"SUCCESS! Decrypted plaintext: {plaintext[:100]}...")
            json_data = json.loads(plaintext)
            print(f"JSON keys: {list(json_data.keys())}")
            success = True
        except Exception as e:
            print(f"Failed with None as associated_data: {e}")
        
        print("\nAttempting decryption with empty string...")
        try:
            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=b'')
            print(f"SUCCESS! Decrypted plaintext: {plaintext[:100]}...")
            json_data = json.loads(plaintext)
            print(f"JSON keys: {list(json_data.keys())}")
            success = True
        except Exception as e:
            print(f"Failed with empty string as associated_data: {e}")
            
        # Try using the protection object only as header
        protection_json = json.dumps({"protection": protection}).encode('utf-8')
        print("\nAttempting decryption with protection object only...")
        try:
            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=protection_json)
            print(f"SUCCESS! Decrypted plaintext: {plaintext[:100]}...")
            json_data = json.loads(plaintext)
            print(f"JSON keys: {list(json_data.keys())}")
            success = True
        except Exception as e:
            print(f"Failed with protection object as associated_data: {e}")
            
        # Now try the normal load_keystore method
        print("\nStep 3: Using normal load_keystore method")
        keystore2 = PQCKeystore(keystore_path)
        try:
            result = keystore2.load_keystore(master_password)
            print(f"Keystore loaded successfully: {result}")
            print("Verifying keystore data structure:")
            print(f"Keys in keystore data: {list(keystore2.keystore_data.keys())}")
            success = True
        except Exception as e:
            print(f"Error loading keystore with normal method: {e}")
            traceback.print_exc()
            
        if success:
            print("\n✅ Decryption succeeded with one of the methods! But the load_keystore method still has issues.")
        else:
            print("\n❌ Decryption failed with all methods. Need to fix the encryption-decryption mismatch.")
        
    except Exception as e:
        print(f"Error during debugging: {e}")
        traceback.print_exc()
        return
        
if __name__ == "__main__":
    debug_keystore_creation()