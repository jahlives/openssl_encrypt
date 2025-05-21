#!/usr/bin/env python3
"""
Test for dual encryption architecture

This test verifies that the dual encryption architecture properly requires both
the keystore password and file password for decryption.
"""

import os
import sys
import subprocess
import base64
import json
import uuid

# Test parameters
TEST_DIR = "test_dual_architecture"
TEST_KEYSTORE = f"{TEST_DIR}/test_keystore.pqc"
TEST_INPUT = f"{TEST_DIR}/test_input.txt"
TEST_ENCRYPTED = f"{TEST_DIR}/test_encrypted.enc"
TEST_DECRYPTED = f"{TEST_DIR}/test_decrypted.txt"
KEYSTORE_PASSWORD = "test_keystore_password"
FILE_PASSWORD = "test_file_password"
WRONG_PASSWORD = "wrong_password"
TEST_CONTENT = "This is a test of the dual encryption architecture."

def setup():
    """Set up the test environment"""
    print("\n=== Setting up test environment ===")
    
    # Create test directory
    if not os.path.exists(TEST_DIR):
        os.makedirs(TEST_DIR)
    
    # Create test input file
    with open(TEST_INPUT, "w") as f:
        f.write(TEST_CONTENT)
    
    print(f"Created test files in {TEST_DIR}")
    return True

def generate_keys():
    """Generate keys in the keystore"""
    print("\n=== Generating keys in keystore ===")
    
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
    
    # We'll use the API directly to generate a key with dual encryption
    from openssl_encrypt.modules.keystore_cli import PQCKeystore
    from openssl_encrypt.modules.pqc import PQCipher
    
    # Load the keystore
    keystore = PQCKeystore(TEST_KEYSTORE)
    keystore.load_keystore(KEYSTORE_PASSWORD)
    
    # Generate a test key pair
    cipher = PQCipher("kyber768")
    public_key, private_key = cipher.generate_keypair()
    
    # Add the key with dual encryption
    key_id = keystore.add_key(
        algorithm="kyber768",
        public_key=public_key,
        private_key=private_key,
        description="Test dual encryption architecture",
        dual_encryption=True,
        file_password=FILE_PASSWORD
    )
    
    # Save the keystore
    keystore.save_keystore()
    
    print(f"Added key {key_id} to keystore with dual encryption")
    
    # Now we want to test that the private key is truly encrypted with both passwords
    # Try to get the key with just the keystore password
    try:
        keystore = PQCKeystore(TEST_KEYSTORE)
        keystore.load_keystore(KEYSTORE_PASSWORD)
        
        # This should fail since we're not providing the file password
        _, retrieved_private_key = keystore.get_key(key_id)
        
        print("FAILURE: Was able to retrieve private key without file password!")
        return False
    except Exception as e:
        if "Missing dual encryption salt" in str(e) or "Failed to handle dual encryption" in str(e) or "file_password" in str(e):
            print("✓ As expected, couldn't retrieve key without file password")
        else:
            print(f"Unexpected error: {e}")
    
    # Now try with the wrong file password
    try:
        keystore = PQCKeystore(TEST_KEYSTORE)
        keystore.load_keystore(KEYSTORE_PASSWORD)
        
        # This should fail since we're providing the wrong file password
        _, retrieved_private_key = keystore.get_key(key_id, None, WRONG_PASSWORD)
        
        print("FAILURE: Was able to retrieve private key with wrong file password!")
        return False
    except Exception as e:
        if "Incorrect file password" in str(e) or "Invalid" in str(e):
            print("✓ As expected, couldn't retrieve key with wrong file password")
        else:
            print(f"Unexpected error: {e}")
    
    # Now try with the correct passwords
    try:
        keystore = PQCKeystore(TEST_KEYSTORE)
        keystore.load_keystore(KEYSTORE_PASSWORD)
        
        # This should succeed
        _, retrieved_private_key = keystore.get_key(key_id, None, FILE_PASSWORD)
        
        print("✓ Successfully retrieved key with correct keystore and file passwords")
        return True
    except Exception as e:
        print(f"Failed to retrieve key with correct passwords: {e}")
        return False

def encrypt_file():
    """Encrypt a file using dual encryption"""
    print("\n=== Encrypting file with dual encryption ===")
    
    # Encrypt the file using the CLI
    cmd = [
        "python", "-m", "openssl_encrypt.crypt", "encrypt",
        "-i", TEST_INPUT,
        "-o", TEST_ENCRYPTED,
        "--algorithm", "kyber768-hybrid",
        "--password", FILE_PASSWORD,
        "--keystore", TEST_KEYSTORE,
        "--keystore-password", KEYSTORE_PASSWORD,
        "--dual-encrypt-key",
        "--force-password"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Failed to encrypt file: {result.stderr}")
        return False
    
    print("Successfully encrypted file with dual encryption")
    
    # Check that the metadata contains dual encryption flag
    try:
        with open(TEST_ENCRYPTED, 'rb') as f:
            data = f.read(8192)
        
        colon_pos = data.find(b':')
        if colon_pos > 0:
            metadata_b64 = data[:colon_pos]
            metadata_json = base64.b64decode(metadata_b64).decode('utf-8')
            metadata = json.loads(metadata_json)
            
            if 'hash_config' in metadata and 'dual_encryption' in metadata['hash_config']:
                print(f"✓ Metadata contains dual_encryption flag: {metadata['hash_config']['dual_encryption']}")
            else:
                print("✗ Metadata doesn't contain dual_encryption flag")
    except Exception as e:
        print(f"Error checking metadata: {e}")
    
    return True

def decrypt_with_correct_password():
    """Decrypt the file with the correct passwords"""
    print("\n=== Decrypting with correct passwords ===")
    
    # Decrypt the file using the CLI
    cmd = [
        "python", "-m", "openssl_encrypt.crypt", "decrypt",
        "-i", TEST_ENCRYPTED,
        "-o", TEST_DECRYPTED,
        "--password", FILE_PASSWORD,
        "--keystore", TEST_KEYSTORE,
        "--keystore-password", KEYSTORE_PASSWORD,
        "--force-password"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Failed to decrypt file: {result.stderr}")
        return False
    
    # Verify the content matches
    try:
        with open(TEST_DECRYPTED, 'r') as f:
            content = f.read()
        
        if content == TEST_CONTENT:
            print("✓ Decrypted content matches original")
        else:
            print("✗ Decrypted content doesn't match original")
            return False
    except Exception as e:
        print(f"Error checking decrypted content: {e}")
        return False
    
    return True

def decrypt_with_wrong_password():
    """Decrypt the file with the wrong file password"""
    print("\n=== Decrypting with wrong file password (should fail) ===")
    
    wrong_output = f"{TEST_DIR}/wrong_decrypted.txt"
    
    # Decrypt the file using the CLI
    cmd = [
        "python", "-m", "openssl_encrypt.crypt", "decrypt",
        "-i", TEST_ENCRYPTED,
        "-o", wrong_output,
        "--password", WRONG_PASSWORD,
        "--keystore", TEST_KEYSTORE,
        "--keystore-password", KEYSTORE_PASSWORD,
        "--force-password"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        print("✗ Decryption with wrong file password succeeded (this is a bug!)")
        return False
    else:
        print(f"✓ Decryption with wrong file password failed as expected.")
        print(f"Error message: {result.stderr}")
        return True

def cleanup():
    """Clean up test files"""
    print("\n=== Cleaning up ===")
    
    files_to_clean = [
        TEST_INPUT,
        TEST_ENCRYPTED,
        TEST_DECRYPTED,
        f"{TEST_DIR}/wrong_decrypted.txt",
        TEST_KEYSTORE
    ]
    
    for file_path in files_to_clean:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except:
                pass
    
    try:
        os.rmdir(TEST_DIR)
    except:
        pass

def main():
    """Main function"""
    print("=== DUAL ENCRYPTION ARCHITECTURE TEST ===")
    
    try:
        # Run the tests
        if not setup():
            print("Failed to set up test environment")
            return 1
        
        if not generate_keys():
            print("Failed to generate keys")
            return 1
        
        if not encrypt_file():
            print("Failed to encrypt file")
            return 1
        
        if not decrypt_with_correct_password():
            print("Failed to decrypt with correct password")
            return 1
        
        if not decrypt_with_wrong_password():
            print("Failed the wrong password test")
            return 1
        
        print("\n=== TEST RESULTS ===")
        print("✅ All tests passed! The dual encryption architecture is working correctly.")
        print("The private key is properly encrypted with both passwords and both are required for decryption.")
        
        return 0
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1
    finally:
        cleanup()

if __name__ == "__main__":
    sys.exit(main())