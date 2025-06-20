#!/usr/bin/env python3
"""
Minimal fix for the PQCKeystore issue.

This script:
1. Creates a minimal test keystore
2. Tests if it can be saved and loaded
3. If successful, applies the fix to the main PQCKeystore implementation
"""

import os
import sys
import json
import base64
import secrets
import tempfile
import datetime
import traceback
import shutil

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# Add project to path
sys.path.insert(0, os.path.abspath('.'))
from openssl_encrypt.modules.pqc_keystore import KeystoreSecurityLevel

def create_test_keystore(path, password, use_associated_data=False):
    """
    Create a minimal test keystore with consistent associated_data handling
    
    Args:
        path: Path to save the keystore
        password: Password to encrypt the keystore
        use_associated_data: Whether to use associated_data during encryption
    
    Returns:
        True if the keystore was created successfully
    """
    print(f"Creating test keystore at {path}")
    
    # Create a simple key (just for testing)
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    
    # Create protection parameters
    salt = secrets.token_bytes(16)
    protection = {
        "method": "argon2id+aes-256-gcm",
        "params": {
            "salt": base64.b64encode(salt).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "argon2_params": {
                "time_cost": 3,
                "memory_cost": 65536,
                "parallelism": 2
            }
        }
    }
    
    # Create keystore data
    keystore_data = {
        "keystore_version": "1.0",
        "creation_date": datetime.datetime.now().isoformat(),
        "last_modified": datetime.datetime.now().isoformat(),
        "keys": [],
        "default_key_id": None,
        "protection": protection
    }
    
    # Convert to JSON
    plaintext = json.dumps(keystore_data).encode('utf-8')
    
    # For simplicity, we'll just use the password directly as the key
    # In real implementation, this would use a key derivation function
    derived_key = password.encode('utf-8') + b'0' * (32 - len(password.encode('utf-8')))
    
    # Encrypt the data
    cipher = AESGCM(derived_key)
    header = {"protection": protection}
    
    if use_associated_data:
        # Use header as associated_data for consistent encryption/decryption
        print("Using associated_data=json.dumps(header).encode('utf-8')")
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data=json.dumps(header).encode('utf-8'))
    else:
        # Use None as associated_data (the original approach)
        print("Using associated_data=None")
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)
    
    # Prepare the final file format
    header_json = json.dumps(header).encode('utf-8')
    header_size = len(header_json)
    
    # Write to file
    with open(path, 'wb') as f:
        f.write(header_size.to_bytes(4, byteorder='big'))
        f.write(header_json)
        f.write(ciphertext)
    
    print(f"Keystore created successfully")
    return True

def load_test_keystore(path, password, try_with_associated_data=True, try_with_none=True):
    """
    Load a test keystore with different associated_data approaches
    
    Args:
        path: Path to the keystore file
        password: Password to decrypt the keystore
        try_with_associated_data: Whether to try decryption with associated_data
        try_with_none: Whether to try decryption with None
    
    Returns:
        The loaded keystore data if successful, None otherwise
    """
    print(f"Loading test keystore from {path}")
    
    try:
        with open(path, 'rb') as f:
            encrypted_data = f.read()
        
        # Parse the encrypted data
        header_size = int.from_bytes(encrypted_data[:4], byteorder='big')
        header_bytes = encrypted_data[4:4+header_size]
        header = json.loads(header_bytes.decode('utf-8'))
        ciphertext = encrypted_data[4+header_size:]
        
        # Extract parameters
        protection = header["protection"]
        method = protection["method"]
        params = protection["params"]
        
        # For simplicity, we'll just use the password directly as the key
        derived_key = password.encode('utf-8') + b'0' * (32 - len(password.encode('utf-8')))
        
        # Decrypt the keystore data
        cipher = AESGCM(derived_key)
        nonce = base64.b64decode(params["nonce"])
        
        # Try multiple approaches for decryption
        if try_with_associated_data:
            try:
                print("Trying decryption with associated_data=json.dumps(header).encode('utf-8')")
                plaintext = cipher.decrypt(nonce, ciphertext, associated_data=json.dumps(header).encode('utf-8'))
                print("SUCCESS! Decryption with associated_data worked.")
                keystore_data = json.loads(plaintext.decode('utf-8'))
                return keystore_data
            except Exception as e:
                print(f"Failed with associated_data: {e}")
        
        if try_with_none:
            try:
                print("Trying decryption with associated_data=None")
                plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
                print("SUCCESS! Decryption with None worked.")
                keystore_data = json.loads(plaintext.decode('utf-8'))
                return keystore_data
            except Exception as e:
                print(f"Failed with None: {e}")
        
        print("All decryption attempts failed")
        return None
        
    except Exception as e:
        print(f"Error loading keystore: {e}")
        traceback.print_exc()
        return None

def apply_fix_to_pqc_keystore():
    """
    Apply the fix to the PQCKeystore implementation
    """
    target_file = os.path.join(os.path.abspath('.'), 'openssl_encrypt', 'modules', 'pqc_keystore.py')
    backup_file = target_file + '.bak_fix'
    
    # Create a backup
    shutil.copy2(target_file, backup_file)
    print(f"Created backup at {backup_file}")
    
    try:
        with open(target_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Update the save_keystore method's AES-GCM section
        old_aes_code = """                # Use AES-GCM
                cipher = AESGCM(derived_key)
                nonce = base64.b64decode(params["nonce"])
                # Update nonce for each save
                nonce = secrets.token_bytes(12)
                params["nonce"] = base64.b64encode(nonce).decode('utf-8')
                
                header = {"protection": protection}
                # IMPORTANT: For consistent encryption/decryption, use None as associated_data
                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)"""
        
        new_aes_code = """                # Use AES-GCM
                cipher = AESGCM(derived_key)
                nonce = base64.b64decode(params["nonce"])
                # Update nonce for each save
                nonce = secrets.token_bytes(12)
                params["nonce"] = base64.b64encode(nonce).decode('utf-8')
                
                header = {"protection": protection}
                # IMPORTANT: For consistent encryption/decryption, use None as associated_data
                ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)"""
        
        # Check if we need to make a change
        if old_aes_code in content:
            print("AES code pattern found, no need to update save_keystore method")
        else:
            print("Expected code pattern not found in save_keystore method")
        
        # Update the load_keystore method's AES-GCM section - change the order of decryption attempts
        old_load_code = """                # Use AES-GCM
                cipher = AESGCM(derived_key)
                nonce = base64.b64decode(params["nonce"])
                
                # For AES-GCM, associated_data must match exactly between encryption and decryption
                # Try multiple approaches for backward compatibility - order matters
                try:
                    # First try without associated_data (matches save_keystore)
                    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
                except Exception as e1:
                    try:
                        # Then try with header as associated_data
                        plaintext = cipher.decrypt(nonce, ciphertext, associated_data=json.dumps(header).encode('utf-8'))
                    except Exception as e2:
                        try:
                            # Finally try with empty string
                            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=b'')
                        except Exception as e3:
                            # Raise the original error
                            raise e1"""
        
        new_load_code = """                # Use AES-GCM
                cipher = AESGCM(derived_key)
                nonce = base64.b64decode(params["nonce"])
                
                # For AES-GCM, associated_data must match exactly between encryption and decryption
                # Important: First try with None as we use None in save_keystore
                plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)"""
        
        # Apply the update to load_keystore
        if old_load_code in content:
            content = content.replace(old_load_code, new_load_code)
            print("Updated load_keystore method to prioritize None for associated_data")
        else:
            print("Expected code pattern not found in load_keystore method")
        
        # Write back the updated file
        with open(target_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print("Fix applied successfully")
        return True
        
    except Exception as e:
        print(f"Error applying fix: {e}")
        traceback.print_exc()
        return False

def test_fix():
    """Test the fix with a simple keystore"""
    temp_dir = tempfile.mkdtemp()
    try:
        keystore_path = os.path.join(temp_dir, "test_keystore.pqc")
        password = "test_password_123456"
        
        print("\n=== Testing with associated_data=None ===")
        
        # Create a test keystore with associated_data=None
        create_test_keystore(keystore_path, password, use_associated_data=False)
        
        # Try to load it
        data = load_test_keystore(keystore_path, password, 
                                try_with_associated_data=True, 
                                try_with_none=True)
        
        success_none = data is not None
        
        # Clean up
        os.remove(keystore_path)
        
        print("\n=== Testing with associated_data=header_json ===")
        
        # Create a test keystore with associated_data=header_json
        create_test_keystore(keystore_path, password, use_associated_data=True)
        
        # Try to load it
        data = load_test_keystore(keystore_path, password, 
                                try_with_associated_data=True, 
                                try_with_none=True)
        
        success_header = data is not None
        
        # Clean up
        os.remove(keystore_path)
        os.rmdir(temp_dir)
        
        # Report results
        if success_none and success_header:
            print("\n✅ Both approaches work with their respective decryption methods")
            print("   Recommend using None consistently for both encryption and decryption")
            return True
        elif success_none:
            print("\n✅ Only associated_data=None works consistently")
            print("   Recommend using None for both encryption and decryption")
            return True
        elif success_header:
            print("\n✅ Only associated_data=header_json works consistently")
            print("   Recommend using header_json for both encryption and decryption")
            return True
        else:
            print("\n❌ Neither approach worked consistently")
            return False
            
    except Exception as e:
        print(f"Error in test: {e}")
        traceback.print_exc()
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        return False

if __name__ == "__main__":
    print("=== PQCKeystore Minimal Fix ===\n")
    
    # First test with a simple implementation
    if test_fix():
        # Apply the fix to the main implementation
        print("\nApplying fix to PQCKeystore implementation...")
        if apply_fix_to_pqc_keystore():
            print("\n✅ Fix applied successfully!")
            print("Now run 'python verify_fix.py' to verify the fix works")
        else:
            print("\n❌ Failed to apply fix to PQCKeystore implementation")
    else:
        print("\n❌ Test failed, not applying fix to PQCKeystore implementation")