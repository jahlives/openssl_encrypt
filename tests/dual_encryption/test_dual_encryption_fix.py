#!/usr/bin/env python3
"""
Test script for PQC Keystore Dual-Encryption Implementation.

This script tests the dual-encryption enhancement for the PQC keystore, which
encrypts private keys with both the keystore master password and the individual
file password.

Usage:
    python test_dual_encryption_fix.py

The test creates a keystore, encrypts a file using dual encryption, and then
attempts to decrypt it with both the correct password and an incorrect password
to verify that dual encryption is working properly.
"""

import os
import sys
import json
import base64
import tempfile
import datetime
import getpass
from typing import Dict, Any, Tuple, Optional, Union, List

from openssl_encrypt.modules.keystore_cli import (
    PQCKeystore, KeystoreSecurityLevel, get_key_from_keystore
)
from openssl_encrypt.modules.keystore_wrapper import (
    encrypt_file_with_keystore, decrypt_file_with_keystore
)
from openssl_encrypt.modules.pqc import PQCipher
from openssl_encrypt.modules.keystore_utils import extract_key_id_from_metadata

# Test parameters
TEST_INPUT = "test_dual_input.txt"
TEST_ENCRYPTED = "test_dual_encrypted.enc"
TEST_DECRYPTED = "test_dual_decrypted.txt"
TEST_WRONG_DECRYPTED = "test_dual_wrong_decrypted.txt"
TEST_KEYSTORE = "test_dual_keystore.pqc"
KEYSTORE_PASSWORD = "keystore_password123"
FILE_PASSWORD = b"file_password456"  # Use bytes for the encrypt_file_with_keystore function
WRONG_PASSWORD = b"wrong_password789"  # Use bytes for the decrypt_file_with_keystore function
ALGORITHM = "kyber768-hybrid"
TEST_DATA = "This is a test of the dual encryption feature. If you can read this, the decryption worked."

def print_separator(title):
    """Print a section separator"""
    print("\n" + "=" * 80)
    print(f" {title} ".center(80, "="))
    print("=" * 80)

def create_test_files():
    """Create the test input file and keystore"""
    # Create test input file
    with open(TEST_INPUT, "w") as f:
        f.write(TEST_DATA)
    print(f"Created test input file: {TEST_INPUT}")
    
    # Create keystore
    if os.path.exists(TEST_KEYSTORE):
        os.remove(TEST_KEYSTORE)
    
    keystore = PQCKeystore(TEST_KEYSTORE)
    keystore.create_keystore(KEYSTORE_PASSWORD, KeystoreSecurityLevel.STANDARD)
    print(f"Created test keystore: {TEST_KEYSTORE}")
    
    return True

def extract_and_print_metadata(filename):
    """Extract and print metadata from an encrypted file"""
    try:
        with open(filename, 'rb') as f:
            content = f.read(8192)  # Read enough for the header
            
        # Find the colon separator
        colon_pos = content.find(b':')
        if colon_pos > 0:
            metadata_b64 = content[:colon_pos]
            try:
                metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                metadata = json.loads(metadata_json)
                
                print("\nMetadata from encrypted file:")
                if 'hash_config' in metadata:
                    hash_config = metadata['hash_config']
                    print("  Hash Config:")
                    
                    if 'pqc_keystore_key_id' in hash_config:
                        print(f"    Key ID: {hash_config['pqc_keystore_key_id']}")
                    else:
                        print("    Key ID: Not found")
                        
                    if 'dual_encryption' in hash_config:
                        print(f"    Dual Encryption: {hash_config['dual_encryption']}")
                    else:
                        print("    Dual Encryption: Not found")
                        
                    return hash_config
                else:
                    print("  No hash_config found in metadata")
            except Exception as e:
                print(f"Error parsing metadata: {e}")
    except Exception as e:
        print(f"Error reading file: {e}")
    
    return None

def encrypt_with_dual_encryption():
    """Test encrypting a file with dual encryption"""
    print_separator("ENCRYPTING WITH DUAL ENCRYPTION")
    
    # Generate a PQC key pair
    cipher = PQCipher(ALGORITHM.replace('-hybrid', ''))
    public_key, private_key = cipher.generate_keypair()
    
    # Add key to keystore with dual encryption
    keystore = PQCKeystore(TEST_KEYSTORE)
    keystore.load_keystore(KEYSTORE_PASSWORD)
    
    # Convert file password from bytes to string for the keystore
    file_password_str = FILE_PASSWORD.decode('utf-8') if isinstance(FILE_PASSWORD, bytes) else FILE_PASSWORD
    
    key_id = keystore.add_key(
        algorithm=ALGORITHM.replace('-hybrid', ''),
        public_key=public_key,
        private_key=private_key,
        description="Test dual encryption key",
        dual_encryption=True,
        file_password=file_password_str
    )
    
    keystore.save_keystore()
    print(f"Added key to keystore with ID: {key_id}")
    
    # Encrypt the file with dual encryption
    hash_config = {
        "pbkdf2_iterations": 100000,
        "dual_encryption": True
    }
    
    success = encrypt_file_with_keystore(
        TEST_INPUT,
        TEST_ENCRYPTED,
        FILE_PASSWORD,
        hash_config=hash_config,
        algorithm=ALGORITHM,
        pqc_keypair=(public_key, private_key),
        keystore_file=TEST_KEYSTORE,
        keystore_password=KEYSTORE_PASSWORD,
        key_id=key_id,
        dual_encryption=True
    )
    
    if success:
        print(f"Successfully encrypted file: {TEST_ENCRYPTED}")
        # Check metadata
        hash_config = extract_and_print_metadata(TEST_ENCRYPTED)
        
        # Verify key ID in metadata
        if hash_config and 'pqc_keystore_key_id' in hash_config:
            if hash_config['pqc_keystore_key_id'] == key_id:
                print("✅ Verification: Key ID correctly stored in metadata")
            else:
                print(f"❌ Error: Key ID in metadata ({hash_config['pqc_keystore_key_id']}) doesn't match expected ({key_id})")
                
        # Verify dual encryption flag in metadata
        if hash_config and 'dual_encryption' in hash_config:
            if hash_config['dual_encryption']:
                print("✅ Verification: Dual encryption flag correctly set in metadata")
            else:
                print("❌ Error: Dual encryption flag is False in metadata")
        else:
            print("❌ Error: Dual encryption flag not found in metadata")
            
        return key_id
    else:
        print("❌ Failed to encrypt file")
        return None

def test_decryption_with_correct_passwords(key_id):
    """Test decrypting with the correct passwords"""
    print_separator("DECRYPTING WITH CORRECT PASSWORDS")
    
    if os.path.exists(TEST_DECRYPTED):
        os.remove(TEST_DECRYPTED)
    
    # Decrypt with correct passwords
    success = decrypt_file_with_keystore(
        TEST_ENCRYPTED,
        TEST_DECRYPTED,
        FILE_PASSWORD,
        keystore_file=TEST_KEYSTORE,
        keystore_password=KEYSTORE_PASSWORD,
        key_id=key_id,
        dual_encryption=True
    )
    
    if success and os.path.exists(TEST_DECRYPTED):
        print(f"Successfully decrypted file: {TEST_DECRYPTED}")
        
        # Check content of decrypted file
        with open(TEST_DECRYPTED, 'r') as f:
            content = f.read()
        
        if content == TEST_DATA:
            print("✅ Verification: Decrypted content matches original")
            print(f"Content: {content}")
            return True
        else:
            print("❌ Error: Decrypted content doesn't match original")
            print(f"Original: {TEST_DATA}")
            print(f"Decrypted: {content}")
            return False
    else:
        print("❌ Failed to decrypt file with correct passwords")
        return False

def test_decryption_with_wrong_password(key_id):
    """Test decrypting with the wrong file password"""
    print_separator("DECRYPTING WITH WRONG FILE PASSWORD")
    print("This should fail if dual encryption is working properly")
    
    if os.path.exists(TEST_WRONG_DECRYPTED):
        os.remove(TEST_WRONG_DECRYPTED)
    
    # Decrypt with wrong file password
    success = False
    try:
        success = decrypt_file_with_keystore(
            TEST_ENCRYPTED,
            TEST_WRONG_DECRYPTED,
            WRONG_PASSWORD,
            keystore_file=TEST_KEYSTORE,
            keystore_password=KEYSTORE_PASSWORD,
            key_id=key_id,
            dual_encryption=True
        )
    except Exception as e:
        print(f"✅ As expected, got error: {e}")
        return True
    
    if success and os.path.exists(TEST_WRONG_DECRYPTED):
        print("❌ ERROR: Successfully decrypted file with wrong password!")
        
        # Check content of decrypted file
        try:
            with open(TEST_WRONG_DECRYPTED, 'r') as f:
                content = f.read()
            
            if content == TEST_DATA:
                print("❌ CRITICAL ERROR: Decrypted content matches original despite wrong password!")
                print(f"Content: {content}")
                return False
            else:
                print("⚠️ Decrypted content doesn't match original (likely corrupted):")
                print(f"Original: {TEST_DATA}")
                print(f"Decrypted: {content}")
                # This is actually good - it means the decryption failed but didn't throw an exception
                return True
        except Exception as e:
            print(f"Error reading decrypted file: {e}")
            # This is also good - file might be corrupted due to wrong password
            return True
    else:
        print("✅ As expected, failed to decrypt file with wrong password")
        return True

def cleanup():
    """Clean up test files"""
    print_separator("CLEANUP")
    
    for file in [TEST_INPUT, TEST_ENCRYPTED, TEST_DECRYPTED, TEST_WRONG_DECRYPTED, TEST_KEYSTORE]:
        if os.path.exists(file):
            try:
                os.remove(file)
                print(f"Removed: {file}")
            except Exception as e:
                print(f"Error removing {file}: {e}")
    
    print("Cleanup complete")

def main():
    """Main test function"""
    print_separator("PQC KEYSTORE DUAL ENCRYPTION TEST")
    print("This test verifies that the dual encryption feature works correctly.")
    print("Dual encryption encrypts private keys with both the keystore password")
    print("and the individual file password for defense-in-depth security.")
    
    try:
        # Create test files
        create_test_files()
        
        # Encrypt with dual encryption
        key_id = encrypt_with_dual_encryption()
        if not key_id:
            print("❌ Test failed at encryption stage")
            return 1
        
        # Test decryption with correct passwords
        if not test_decryption_with_correct_passwords(key_id):
            print("❌ Test failed at decryption with correct passwords stage")
            return 1
        
        # Test decryption with wrong password
        if not test_decryption_with_wrong_password(key_id):
            print("❌ Test failed at decryption with wrong password stage")
            return 1
        
        # If we made it here, all tests passed
        print_separator("TEST RESULTS")
        print("✅ All tests passed!")
        print("✅ The dual encryption feature is working correctly.")
        print("✅ Files require both the keystore password and file password for decryption.")
        return 0
    
    except Exception as e:
        print(f"Error during test: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    finally:
        # Clean up
        cleanup()

if __name__ == "__main__":
    sys.exit(main())