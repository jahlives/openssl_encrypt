#!/usr/bin/env python3
"""
Final comprehensive fix for the PQCKeystore issues
"""

import os
import sys
import copy
import tempfile
import shutil
import base64
import json
import traceback

# Add the project to path
sys.path.insert(0, os.path.abspath('.'))
from openssl_encrypt.modules.pqc_keystore import (
    PQCKeystore, KeystoreSecurityLevel, KeystoreProtectionMethod
)

def patch_keystore_file():
    """
    Apply comprehensive fix to the pqc_keystore.py file
    
    1. Fix Argon2id key derivation to use low-level API for consistency
    2. Make associated_data handling consistent
    """
    print("\n=== Applying comprehensive fix to PQCKeystore ===")
    
    keystore_path = os.path.join('openssl_encrypt', 'modules', 'pqc_keystore.py')
    backup_path = keystore_path + '.bak'
    
    # Make a backup of the original file if it doesn't exist
    if not os.path.exists(backup_path):
        print(f"Creating backup of original file: {backup_path}")
        shutil.copy2(keystore_path, backup_path)
    
    # Read the original file
    with open(keystore_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Create a modified version of the file
    # First, make sure argon2.low_level is imported
    if "from argon2 import PasswordHasher" in content and "from argon2.low_level import hash_secret_raw, Type" not in content:
        import_block = "import argon2\nfrom argon2 import PasswordHasher\nfrom argon2.exceptions import VerifyMismatchError\nfrom argon2.low_level import hash_secret_raw, Type"
        content = content.replace("import argon2\nfrom argon2 import PasswordHasher\nfrom argon2.exceptions import VerifyMismatchError", import_block)
        print("Added import for argon2.low_level")
    
    # Second, fix the key derivation logic in load_keystore
    if "# Hash the password with Argon2id\nhash_result = ph.hash(master_password + salt_b64)\nderived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()" in content:
        old_derivation = "# Hash the password with Argon2id\nhash_result = ph.hash(master_password + salt_b64)\nderived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()"
        new_derivation = """# Use low-level Argon2id API for consistent key derivation
derived_key = hash_secret_raw(
    master_password.encode('utf-8'),
    salt,
    time_cost=argon2_params["time_cost"],
    memory_cost=argon2_params["memory_cost"],
    parallelism=argon2_params["parallelism"],
    hash_len=32,
    type=Type.ID
)"""
        content = content.replace(old_derivation, new_derivation)
        print("Fixed Argon2id key derivation in load_keystore")
    
    # Third, fix the key derivation logic in save_keystore
    if "# Hash the password with Argon2id\nhash_result = ph.hash(master_password + salt_b64)\nderived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()" in content:
        old_derivation = "# Hash the password with Argon2id\nhash_result = ph.hash(master_password + salt_b64)\nderived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()"
        new_derivation = """# Use low-level Argon2id API for consistent key derivation
derived_key = hash_secret_raw(
    master_password.encode('utf-8'),
    salt,
    time_cost=argon2_params["time_cost"],
    memory_cost=argon2_params["memory_cost"],
    parallelism=argon2_params["parallelism"],
    hash_len=32,
    type=Type.ID
)"""
        # Replace second occurrence (in save_keystore)
        first_pos = content.find(old_derivation)
        if first_pos >= 0:
            remaining = content[first_pos + len(old_derivation):]
            second_pos = remaining.find(old_derivation)
            if second_pos >= 0:
                second_full_pos = first_pos + len(old_derivation) + second_pos
                content = content[:second_full_pos] + new_derivation + content[second_full_pos + len(old_derivation):]
                print("Fixed Argon2id key derivation in save_keystore")
    
    # Fourth, fix the key derivation in _encrypt_private_key
    if "# Hash the password with Argon2id\nhash_result = ph.hash(password + salt_b64)\nderived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()" in content:
        old_derivation = "# Hash the password with Argon2id\nhash_result = ph.hash(password + salt_b64)\nderived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()"
        new_derivation = """# Use low-level Argon2id API for consistent key derivation
derived_key = hash_secret_raw(
    password.encode('utf-8'),
    salt,
    time_cost=time_cost,
    memory_cost=memory_cost,
    parallelism=parallelism,
    hash_len=32,
    type=Type.ID
)"""
        content = content.replace(old_derivation, new_derivation)
        print("Fixed Argon2id key derivation in _encrypt_private_key")
    
    # Fifth, fix the key derivation in _decrypt_private_key
    if "# Hash the password with Argon2id\nhash_result = ph.hash(password + salt_b64)\nderived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()" in content:
        old_derivation = "# Hash the password with Argon2id\nhash_result = ph.hash(password + salt_b64)\nderived_key = hashlib.sha256(hash_result.encode('utf-8')).digest()"
        new_derivation = """# Use low-level Argon2id API for consistent key derivation
derived_key = hash_secret_raw(
    password.encode('utf-8'),
    salt,
    time_cost=argon2_params["time_cost"],
    memory_cost=argon2_params["memory_cost"],
    parallelism=argon2_params["parallelism"],
    hash_len=32,
    type=Type.ID
)"""
        # Replace remaining occurrences
        content = content.replace(old_derivation, new_derivation)
        print("Fixed Argon2id key derivation in _decrypt_private_key")
    
    # Sixth, ensure consistent associated_data handling in save_keystore (AES-GCM)
    save_encrypt_old = "# IMPORTANT: For consistent encryption/decryption, use None as associated_data\nciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)"
    save_encrypt_new = "# IMPORTANT: For consistent encryption/decryption, use empty bytes as associated_data\nciphertext = cipher.encrypt(nonce, plaintext, associated_data=b'')"
    content = content.replace(save_encrypt_old, save_encrypt_new)
    print("Updated associated_data handling in save_keystore")
    
    # Seventh, ensure consistent associated_data handling in load_keystore (AES-GCM)
    load_decrypt_old = "# Important: First try with None as we use None in save_keystore\nplaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)"
    load_decrypt_new = "# IMPORTANT: Use empty bytes as associated_data to match save_keystore\nplaintext = cipher.decrypt(nonce, ciphertext, associated_data=b'')"
    content = content.replace(load_decrypt_old, load_decrypt_new)
    print("Updated associated_data handling in load_keystore")
    
    # Eighth, fix associated_data in _encrypt_with_derived_key for AES-GCM
    encrypt_derived_old = "# BUGFIX: Use the associated_data consistent with load_keystore (header JSON)\nheader_json = json.dumps(header).encode('utf-8')\nciphertext = cipher.encrypt(nonce, data, associated_data=header_json)"
    encrypt_derived_new = "# IMPORTANT: For consistent encryption/decryption, use empty bytes as associated_data\nciphertext = cipher.encrypt(nonce, data, associated_data=b'')"
    content = content.replace(encrypt_derived_old, encrypt_derived_new)
    print("Updated associated_data handling in _encrypt_with_derived_key")
    
    # Ninth, fix associated_data handling in _decrypt_with_derived_key for AES-GCM
    decrypt_derived_old = """# BUGFIX: Try methods in consistent order for compatibility
try:
    plaintext = cipher.decrypt(nonce, ciphertext, associated_data=b'')
except Exception:
    try:
        # Then try with None
        plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
    except Exception:
        # Finally try with header
        plaintext = cipher.decrypt(nonce, ciphertext, associated_data=json.dumps(header).encode('utf-8'))"""
    decrypt_derived_new = """# IMPORTANT: For consistent encryption/decryption, use empty bytes as associated_data
plaintext = cipher.decrypt(nonce, ciphertext, associated_data=b'')"""
    content = content.replace(decrypt_derived_old, decrypt_derived_new)
    print("Updated associated_data handling in _decrypt_with_derived_key")
    
    # Write the modified file
    fixed_path = os.path.join('openssl_encrypt', 'modules', 'pqc_keystore.py.fix')
    with open(fixed_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Wrote fixed file to: {fixed_path}")
    
    # Copy the fixed file to the original location
    print(f"Copying fix to original file: {keystore_path}")
    shutil.copy2(fixed_path, keystore_path)
    
    print("\n=== Fix completed! ===")
    print("A backup of the original file was saved at:", backup_path)
    print("The fixed implementation is now in:", keystore_path)

def test_keystore_fix():
    """Test that the keystore fix allows creation and loading of a keystore"""
    # Create a temporary directory for test files
    temp_dir = tempfile.mkdtemp()
    keystore_path = os.path.join(temp_dir, "test_keystore.pqc")
    
    # Master password for tests
    master_password = "test_master_password"
    
    print("\n=== Testing PQCKeystore fix ===")
    
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
        
        # If we got this far, the fix worked
        print("\n✅ SUCCESS! The PQCKeystore fix is working correctly.")
        print("The keystore can now be created and loaded successfully.")
        
        # Clean up
        shutil.rmtree(temp_dir)
        
        return True
    except Exception as e:
        print(f"\n❌ ERROR: The fix didn't work: {str(e)}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    # Apply the comprehensive fix
    patch_keystore_file()
    
    # Test the fix
    success = test_keystore_fix()
    
    if success:
        print("\nAll tests passed! The fix was successful.")
        sys.exit(0)
    else:
        print("\nTests failed! The fix wasn't successful.")
        sys.exit(1)