#!/usr/bin/env python3
"""
Setup script for dual encryption testing.

This script:
1. Creates a keystore if it doesn't exist
2. Adds a dual-encrypted key to the keystore
3. Prints the key ID for later use in CLI tests
"""

import os
import sys
from openssl_encrypt.modules.keystore_cli import PQCKeystore, KeystoreSecurityLevel
from openssl_encrypt.modules.pqc import PQCipher

# Test parameters
TEST_KEYSTORE = "test_cli_keystore.pqc"
KEYSTORE_PASSWORD = "keystore_password_cli"
FILE_PASSWORD = "file_password_cli"
ALGORITHM = "kyber768"

def main():
    print(f"Setting up test keystore: {TEST_KEYSTORE}")
    
    # Create or load keystore
    keystore = PQCKeystore(TEST_KEYSTORE)
    
    if os.path.exists(TEST_KEYSTORE):
        print(f"Loading existing keystore: {TEST_KEYSTORE}")
        keystore.load_keystore(KEYSTORE_PASSWORD)
    else:
        print(f"Creating new keystore: {TEST_KEYSTORE}")
        keystore.create_keystore(KEYSTORE_PASSWORD, KeystoreSecurityLevel.STANDARD)
    
    # Check for existing keys with dual encryption
    keys = keystore.list_keys()
    dual_enc_keys = [k for k in keys 
                    if k["algorithm"].lower() == ALGORITHM.lower() 
                    and k.get("dual_encryption", False) == True]
    
    if dual_enc_keys:
        key_id = dual_enc_keys[0]["key_id"]
        print(f"Found existing dual-encrypted key: {key_id}")
    else:
        # Generate a new key
        print(f"Generating new {ALGORITHM} key with dual encryption")
        
        cipher = PQCipher(ALGORITHM)
        public_key, private_key = cipher.generate_keypair()
        
        # Add to keystore with dual encryption
        key_id = keystore.add_key(
            algorithm=ALGORITHM,
            public_key=public_key,
            private_key=private_key,
            description=f"Test {ALGORITHM} key with dual encryption",
            dual_encryption=True,
            file_password=FILE_PASSWORD
        )
        
        # Save keystore
        keystore.save_keystore()
        print(f"Added new key to keystore with ID: {key_id}")
    
    print("\nTest keystore setup complete!")
    print(f"Keystore: {TEST_KEYSTORE}")
    print(f"Keystore password: {KEYSTORE_PASSWORD}")
    print(f"File password: {FILE_PASSWORD}")
    print(f"Key ID: {key_id}")
    print(f"Algorithm: {ALGORITHM}")
    
    print("\nUse these values for CLI tests:")
    print(f"python -m openssl_encrypt.crypt encrypt -i input.txt -o output.enc --algorithm {ALGORITHM}-hybrid --password {FILE_PASSWORD} --keystore {TEST_KEYSTORE} --keystore-password {KEYSTORE_PASSWORD} --key-id {key_id} --dual-encrypt-key --force-password")
    print(f"python -m openssl_encrypt.crypt decrypt -i output.enc -o decrypted.txt --password {FILE_PASSWORD} --keystore {TEST_KEYSTORE} --keystore-password {KEYSTORE_PASSWORD} --key-id {key_id} --force-password")
    
    return key_id

if __name__ == "__main__":
    main()