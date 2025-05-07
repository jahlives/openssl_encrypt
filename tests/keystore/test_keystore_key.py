#!/usr/bin/env python3
"""
Test script for encryption/decryption with PQC keystore
"""

import os
import sys
import argparse
from openssl_encrypt.modules.keystore_cli import PQCKeystore, KeystoreSecurityLevel
from openssl_encrypt.modules.pqc import PQCipher
from openssl_encrypt.modules.crypt_core import encrypt_file, decrypt_file

def test_keystore_encrypt_decrypt():
    """Test encryption and decryption with keystore key"""
    # Create a test keystore
    keystore_path = "test_keystore.pqc"
    keystore_password = "1234"
    input_file = "keystore_test_input.txt"
    encrypted_file = "keystore_test_encrypted.enc"
    decrypted_file = "keystore_test_decrypted.txt"
    
    # Clean up existing test files
    if os.path.exists(encrypted_file):
        os.remove(encrypted_file)
    if os.path.exists(decrypted_file):
        os.remove(decrypted_file)
    
    # Define password once for all uses
    keystore_password_str = "1234"
    
    # Create or load keystore
    print(f"Setting up keystore: {keystore_path}")
    keystore = PQCKeystore(keystore_path)
    if not os.path.exists(keystore_path):
        print("Creating new keystore")
        keystore.create_keystore(keystore_password_str, KeystoreSecurityLevel.STANDARD)
    else:
        print("Loading existing keystore")
        keystore.load_keystore(keystore_password_str)
    
    # Generate a new Kyber768 keypair
    print("Generating Kyber768 keypair")
    cipher = PQCipher("kyber768", quiet=True)
    public_key, private_key = cipher.generate_keypair()
    
    # Add to keystore
    print("Adding key to keystore")
    key_id = keystore.add_key(
        algorithm="kyber768",
        public_key=public_key,
        private_key=private_key,
        description="Test key for keystore test",
        tags=["test"],
        use_master_password=True
    )
    
    # Save keystore
    keystore.save_keystore()
    print(f"Added key with ID: {key_id}")
    
    # Create a hash config for encryption
    hash_config = {
        "sha512": 0,
        "sha256": 0,
        "sha3_256": 0,
        "sha3_512": 0,
        "blake2b": 0,
        "shake256": 0,
        "scrypt": {
            "enabled": False,
            "n": 128,
            "r": 8,
            "p": 1,
            "rounds": 1
        },
        "argon2": {
            "enabled": False,
            "time_cost": 3,
            "memory_cost": 65536,
            "parallelism": 4,
            "hash_len": 32,
            "type": 2,
            "rounds": 1
        },
        "pbkdf2_iterations": 0,
        "pqc_keystore_key_id": key_id  # Store key ID in metadata
    }
    
    # Encrypt the file
    print(f"\nEncrypting file: {input_file} -> {encrypted_file}")
    password_str = "test-password"
    success = encrypt_file(
        input_file,
        encrypted_file,
        password_str.encode(),
        hash_config,
        0,  # pbkdf2 iterations
        False,  # quiet
        "kyber768-hybrid",  # algorithm
        True,  # progress
        True,  # verbose
        pqc_keypair=(public_key, private_key),
        pqc_store_private_key=False  # DO NOT store private key in metadata
    )
    
    if not success:
        print("Encryption failed!")
        return False
    
    print(f"Encryption successful. File saved to {encrypted_file}")
    
    # Now decrypt using the key from keystore
    print(f"\nDecrypting file: {encrypted_file} -> {decrypted_file}")
    
    # Create a command-line args-like object to simulate CLI usage
    class Args:
        keystore = keystore_path
        keystore_password = keystore_password_str
        input = encrypted_file
        output = decrypted_file
        password = password_str
        quiet = False
        verbose = True
        progress = True
    
    # Import the keystore utilities
    from openssl_encrypt.modules.keystore_utils import get_pqc_key_for_decryption
    
    # Get the key from keystore
    args = Args()
    pqc_keypair, pqc_private_key, found_key_id = get_pqc_key_for_decryption(args, hash_config)
    
    print(f"Found key from keystore: {found_key_id}")
    
    # Decrypt with the keystore key
    if pqc_private_key is None:
        print("Failed to get PQC private key from keystore!")
        return False
    
    success = decrypt_file(
        args.input,
        args.output,
        args.password.encode(),
        args.quiet,
        args.progress,
        args.verbose,
        pqc_private_key=pqc_private_key
    )
    
    if not success:
        print("Decryption failed!")
        return False
    
    # Verify decrypted content
    with open(decrypted_file, "r") as f:
        decrypted_content = f.read()
    
    # Verify with original content
    with open(input_file, "r") as f:
        original_content = f.read()
    
    content_match = decrypted_content == original_content
    print(f"Original content: '{original_content}'")
    print(f"Decrypted content: '{decrypted_content}'")
    print(f"Content match: {content_match}")
    
    # Clean up keystore
    keystore.clear_cache()
    
    return content_match

def main():
    """Main function"""
    print("=" * 60)
    print("Testing PQC keystore encryption/decryption")
    print("=" * 60)
    
    success = test_keystore_encrypt_decrypt()
    
    print("\nTest result:", "SUCCESS" if success else "FAILURE")
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())