#!/usr/bin/env python3
"""
Test for dual encryption password validation

This script tests that the password validation fix works correctly for dual-encrypted files.
It verifies that:
1. Files can be decrypted with the correct keystore and file passwords
2. Files CANNOT be decrypted with incorrect file passwords
"""

import os
import sys
import base64
import json
import uuid
import subprocess
import hashlib

# Test parameters
TEST_DIR = "test_dual_encryption_validation"
TEST_KEYSTORE = f"{TEST_DIR}/test_keystore.pqc"
TEST_INPUT = f"{TEST_DIR}/test_input.txt"
TEST_ENCRYPTED = f"{TEST_DIR}/test_encrypted.enc"
TEST_DECRYPTED_CORRECT = f"{TEST_DIR}/test_decrypted_correct.txt"
TEST_DECRYPTED_WRONG = f"{TEST_DIR}/test_decrypted_wrong.txt"
KEYSTORE_PASSWORD = "test_keystore_password"
CORRECT_FILE_PASSWORD = "correct_file_password"
WRONG_FILE_PASSWORD = "wrong_file_password"
TEST_CONTENT = "This is a test file for the dual encryption password validation fix."

def setup():
    """Set up the test environment"""
    print("\n=== Setting up test environment ===")
    
    # Create test directory
    if not os.path.exists(TEST_DIR):
        os.makedirs(TEST_DIR)
        print(f"Created test directory: {TEST_DIR}")
    
    # Create test input file
    with open(TEST_INPUT, "w") as f:
        f.write(TEST_CONTENT)
    print(f"Created test input file: {TEST_INPUT}")
    
    # Create keystore
    cmd = [
        "python", "-m", "openssl_encrypt.keystore_cli_main", "create",
        "--keystore-path", TEST_KEYSTORE,
        "--keystore-password", KEYSTORE_PASSWORD
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Failed to create keystore: {result.stderr}")
        return False
    
    print(f"Created test keystore: {TEST_KEYSTORE}")
    return True

def encrypt_test_file():
    """Encrypt the test file with dual encryption"""
    print("\n=== Encrypting file with dual encryption ===")
    
    # Create command to encrypt with dual encryption
    cmd = [
        "python", "-m", "openssl_encrypt.crypt", "encrypt",
        "-i", TEST_INPUT,
        "-o", TEST_ENCRYPTED,
        "--algorithm", "kyber768-hybrid",
        "--password", CORRECT_FILE_PASSWORD,
        "--keystore", TEST_KEYSTORE,
        "--keystore-password", KEYSTORE_PASSWORD,
        "--dual-encrypt-key",
        "--auto-create-keystore",
        "--force-password"
    ]
    
    print("Encryption command:", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Encryption failed: {result.stderr}")
        return False
    
    print("Encryption output:")
    print(result.stdout)
    
    # Verify the file was created
    if not os.path.exists(TEST_ENCRYPTED):
        print(f"Encrypted file was not created: {TEST_ENCRYPTED}")
        return False
    
    print(f"Successfully encrypted file with dual encryption: {TEST_ENCRYPTED}")
    return True

def decrypt_with_correct_password():
    """Decrypt the file with the correct password"""
    print("\n=== Decrypting with correct password ===")
    
    # Create command to decrypt with correct password
    cmd = [
        "python", "-m", "openssl_encrypt.crypt", "decrypt",
        "-i", TEST_ENCRYPTED,
        "-o", TEST_DECRYPTED_CORRECT,
        "--password", CORRECT_FILE_PASSWORD,
        "--keystore", TEST_KEYSTORE,
        "--keystore-password", KEYSTORE_PASSWORD,
        "--force-password"
    ]
    
    print("Decryption command:", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Decryption with correct password failed: {result.stderr}")
        print(result.stdout)
        return False
    
    print("Decryption output:")
    print(result.stdout)
    
    # Verify the file was created and content matches
    if not os.path.exists(TEST_DECRYPTED_CORRECT):
        print(f"Decrypted file was not created: {TEST_DECRYPTED_CORRECT}")
        return False
    
    with open(TEST_DECRYPTED_CORRECT, "r") as f:
        content = f.read()
    
    if content != TEST_CONTENT:
        print(f"Decrypted content does not match expected content:\nExpected: {TEST_CONTENT}\nGot: {content}")
        return False
    
    print(f"Successfully decrypted file with correct password")
    return True

def decrypt_with_wrong_password():
    """Decrypt the file with the wrong password - should fail"""
    print("\n=== Decrypting with wrong password (should fail) ===")
    
    # Create command to decrypt with wrong password
    cmd = [
        "python", "-m", "openssl_encrypt.crypt", "decrypt",
        "-i", TEST_ENCRYPTED,
        "-o", TEST_DECRYPTED_WRONG,
        "--password", WRONG_FILE_PASSWORD,
        "--keystore", TEST_KEYSTORE,
        "--keystore-password", KEYSTORE_PASSWORD,
        "--force-password"
    ]
    
    print("Decryption command:", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # For the fix to be working, this should fail
    if result.returncode == 0:
        print("FAILURE: Decryption with wrong password succeeded when it should have failed!")
        
        # Check if the file contains the correct content
        if os.path.exists(TEST_DECRYPTED_WRONG):
            with open(TEST_DECRYPTED_WRONG, "r") as f:
                content = f.read()
            
            if content == TEST_CONTENT:
                print("CRITICAL FAILURE: Decrypted content matches original despite wrong password!")
            else:
                print("Decryption 'succeeded' but content is corrupted (still an issue)")
        
        return False
    
    print("Decryption with wrong password failed as expected")
    print("Error output:")
    print(result.stderr)
    
    return True

def analyze_metadata():
    """Analyze the metadata of the encrypted file to verify fix implementation"""
    print("\n=== Analyzing encrypted file metadata ===")
    
    try:
        with open(TEST_ENCRYPTED, 'rb') as f:
            data = f.read(8192)  # Read enough for the header
        
        # Find the colon separator
        colon_pos = data.find(b':')
        if colon_pos > 0:
            metadata_b64 = data[:colon_pos]
            try:
                metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
                metadata = json.loads(metadata_json)
                
                print("Metadata content:")
                
                # Check for key ID
                if 'hash_config' in metadata and 'pqc_keystore_key_id' in metadata['hash_config']:
                    key_id = metadata['hash_config']['pqc_keystore_key_id']
                    print(f"✓ Key ID: {key_id}")
                else:
                    print("× Missing key ID in metadata")
                
                # Check for dual encryption flag
                if 'hash_config' in metadata and 'dual_encryption' in metadata['hash_config']:
                    dual_flag = metadata['hash_config']['dual_encryption']
                    print(f"✓ Dual encryption flag: {dual_flag}")
                else:
                    print("× Missing dual encryption flag in metadata")
                
                # Check for password verification
                has_verify = ('hash_config' in metadata and 
                             'pqc_dual_encrypt_verify' in metadata['hash_config'] and 
                             'pqc_dual_encrypt_verify_salt' in metadata['hash_config'])
                
                if has_verify:
                    print("✓ Password verification is present in metadata")
                    print(f"  - Salt: {metadata['hash_config']['pqc_dual_encrypt_verify_salt'][:10]}...")
                    print(f"  - Hash: {metadata['hash_config']['pqc_dual_encrypt_verify'][:10]}...")
                else:
                    print("× Missing password verification in metadata")
                    print("  The password validation fix is not properly implemented!")
                
                return has_verify
                
            except Exception as e:
                print(f"Error parsing metadata: {e}")
    except Exception as e:
        print(f"Error reading file: {e}")
    
    return False

def cleanup():
    """Clean up test files"""
    print("\n=== Cleaning up ===")
    
    files_to_clean = [
        TEST_INPUT,
        TEST_ENCRYPTED,
        TEST_DECRYPTED_CORRECT,
        TEST_DECRYPTED_WRONG,
        TEST_KEYSTORE
    ]
    
    for file_path in files_to_clean:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"Removed: {file_path}")
            except Exception as e:
                print(f"Error removing {file_path}: {e}")
    
    # Remove test directory if empty
    try:
        os.rmdir(TEST_DIR)
        print(f"Removed directory: {TEST_DIR}")
    except Exception:
        # Directory might not be empty, that's fine
        pass

def main():
    """Main function"""
    print("\n=== DUAL ENCRYPTION PASSWORD VALIDATION TEST ===")
    print("This test verifies that dual-encrypted files require the correct file password.")
    
    success = True
    
    try:
        if not setup():
            print("Failed to set up test environment")
            return 1
        
        if not encrypt_test_file():
            print("Failed to encrypt test file")
            return 1
        
        has_verification = analyze_metadata()
        if not has_verification:
            print("\nWARNING: Password verification is not in metadata.")
            print("The fix may not be properly implemented.")
        
        correct_pwd_success = decrypt_with_correct_password()
        if not correct_pwd_success:
            print("Failed to decrypt with correct password")
            success = False
        
        wrong_pwd_success = decrypt_with_wrong_password()
        if not wrong_pwd_success:
            print("Failed the wrong password test (decryption succeeded when it should fail)")
            success = False
        
        print("\n=== TEST SUMMARY ===")
        print(f"Metadata contains password verification: {'YES' if has_verification else 'NO'}")
        print(f"Decryption with correct password: {'SUCCESS' if correct_pwd_success else 'FAILURE'}")
        print(f"Decryption with wrong password rejected: {'SUCCESS' if wrong_pwd_success else 'FAILURE'}")
        
        if success:
            print("\n✅ ALL TESTS PASSED - The dual encryption password validation is working correctly!")
            return 0
        else:
            print("\n❌ TESTS FAILED - The dual encryption password validation is not working correctly.")
            return 1
    
    except Exception as e:
        print(f"Error during testing: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    finally:
        cleanup()

if __name__ == "__main__":
    sys.exit(main())