#!/usr/bin/env python3
"""
Test script for PQC keystore operations
"""

import sys
import os
import argparse
from openssl_encrypt.modules.keystore_cli import PQCKeystore, KeystoreSecurityLevel, get_key_from_keystore, add_key_to_keystore
from openssl_encrypt.modules.keystore_utils import extract_key_id_from_metadata, get_pqc_key_for_decryption
from openssl_encrypt.modules.pqc import PQCipher
from openssl_encrypt.modules.crypt_core import encrypt_file, decrypt_file

def test_keystore_operations():
    """Test basic keystore operations"""
    # Create a test keystore
    keystore_path = "test_keystore.pqc"
    keystore_password = "1234"
    
    # Clean up existing test files
    if os.path.exists(keystore_path):
        os.remove(keystore_path)
    
    print(f"Creating test keystore: {keystore_path}")
    keystore = PQCKeystore(keystore_path)
    keystore.create_keystore(keystore_password, KeystoreSecurityLevel.STANDARD)
    
    # Generate keypair
    print("Generating Kyber768 keypair")
    cipher = PQCipher("kyber768", quiet=True)
    public_key, private_key = cipher.generate_keypair()
    
    # Add to keystore
    print("Adding key to keystore")
    key_id = keystore.add_key(
        algorithm="kyber768",
        public_key=public_key,
        private_key=private_key,
        description="Test key",
        tags=["test"],
        use_master_password=True
    )
    
    # Save keystore
    keystore.save_keystore()
    
    print(f"Key ID: {key_id}")
    
    # List keys
    print("\nListing keys:")
    keys = keystore.list_keys()
    for key in keys:
        print(f"  ID: {key['key_id']}")
        print(f"  Algorithm: {key['algorithm']}")
        print(f"  Description: {key['description']}")
        print(f"  Tags: {', '.join(key['tags'])}")
        print()
    
    # Retrieve key
    print("Retrieving key from keystore")
    retrieved_public_key, retrieved_private_key = keystore.get_key(key_id)
    
    # Verify keys match
    public_key_match = public_key == retrieved_public_key
    private_key_match = private_key == retrieved_private_key
    
    print(f"Public key match: {public_key_match}")
    print(f"Private key match: {private_key_match}")
    
    # Clean up
    keystore.clear_cache()
    print(f"Test completed")
    
    return key_id

def test_file_encryption_decryption(key_id):
    """Test file encryption and decryption with keystore key"""
    # Create test files
    input_file = "test_input.txt"
    encrypted_file = "test_encrypted.enc"
    decrypted_file = "test_decrypted.txt"
    test_content = "Hello World"
    
    # Clean up existing test files
    for file in [input_file, encrypted_file, decrypted_file]:
        if os.path.exists(file):
            os.remove(file)
    
    # Create input file
    with open(input_file, "w") as f:
        f.write(test_content)
    
    print(f"\nCreated test file: {input_file} with content '{test_content}'")
    
    # Create arguments object for encryption
    class Args:
        pass
    
    encrypt_args = Args()
    encrypt_args.keystore = "test_keystore.pqc"
    encrypt_args.input = input_file
    encrypt_args.output = encrypted_file
    encrypt_args.algorithm = "kyber768-hybrid"
    encrypt_args.password = "1234"
    encrypt_args.keystore_password = "1234"
    encrypt_args.quiet = False
    encrypt_args.verbose = True
    encrypt_args.progress = True
    encrypt_args.pqc_store_key = True  # Store private key in metadata
    
    # Create a hash config
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
        "pbkdf2_iterations": 0
    }
    
    # Get key for encryption from keystore
    from openssl_encrypt.modules.keystore_utils import auto_generate_pqc_key
    pqc_keypair, pqc_private_key = auto_generate_pqc_key(encrypt_args, hash_config)
    
    # Encrypt the file
    print("\nEncrypting test file")
    success = encrypt_file(
        encrypt_args.input,
        encrypt_args.output,
        encrypt_args.password.encode(),
        hash_config,
        0,  # pbkdf2 iterations
        encrypt_args.quiet,
        encrypt_args.algorithm,
        encrypt_args.progress,
        encrypt_args.verbose,
        pqc_keypair=pqc_keypair,
        pqc_store_private_key=encrypt_args.pqc_store_key
    )
    
    if not success:
        print("Encryption failed")
        return False
    
    print(f"Encrypted file created: {encrypted_file}")
    
    # Now decrypt using the file's embedded key
    decrypt_args = Args()
    decrypt_args.input = encrypted_file
    decrypt_args.output = decrypted_file
    decrypt_args.password = "1234"
    decrypt_args.keystore = "test_keystore.pqc"
    decrypt_args.keystore_password = "1234"
    decrypt_args.quiet = False
    decrypt_args.verbose = True
    decrypt_args.progress = True
    
    print("\nDecrypting file using embedded key")
    success = decrypt_file(
        decrypt_args.input,
        decrypt_args.output,
        decrypt_args.password.encode(),
        decrypt_args.quiet,
        decrypt_args.progress,
        decrypt_args.verbose
    )
    
    if not success:
        print("Decryption failed")
        return False
    
    # Verify decrypted content
    with open(decrypted_file, "r") as f:
        decrypted_content = f.read()
    
    content_match = decrypted_content == test_content
    print(f"Decrypted content: '{decrypted_content}'")
    print(f"Content match: {content_match}")
    
    return content_match

def test_real_file():
    """Test decryption of a real file"""
    test_file = "/tmp/test.txt"
    output_file = "test_decrypted_real.txt"
    
    # Clean up previous output file
    if os.path.exists(output_file):
        os.remove(output_file)
    
    if not os.path.exists(test_file):
        print(f"Test file {test_file} does not exist")
        return False
    
    print(f"\nTesting decryption of real file: {test_file}")
    
    # Create arguments object for decryption
    class Args:
        pass
    
    decrypt_args = Args()
    decrypt_args.input = test_file
    decrypt_args.output = output_file
    decrypt_args.password = "1234"
    decrypt_args.quiet = False
    decrypt_args.verbose = True
    decrypt_args.progress = True
    
    # Decrypt file
    success = decrypt_file(
        decrypt_args.input,
        decrypt_args.output,
        decrypt_args.password.encode(),
        decrypt_args.quiet,
        decrypt_args.progress,
        decrypt_args.verbose
    )
    
    if not success:
        print("Decryption of real file failed")
        return False
    
    # Verify decrypted content
    with open(output_file, "r") as f:
        decrypted_content = f.read()
    
    print(f"Decrypted content: '{decrypted_content}'")
    print("Decryption of real file successful")
    
    return True

def main():
    """Main test function"""
    parser = argparse.ArgumentParser(description="Test PQC keystore operations")
    parser.add_argument('--all', action='store_true', help='Run all tests')
    parser.add_argument('--keystore', action='store_true', help='Test keystore operations')
    parser.add_argument('--encrypt', action='store_true', help='Test file encryption/decryption')
    parser.add_argument('--real', action='store_true', help='Test real file decryption')
    
    args = parser.parse_args()
    
    # Default to all tests if none specified
    if not (args.all or args.keystore or args.encrypt or args.real):
        args.all = True
    
    if args.all or args.keystore:
        print("=" * 60)
        print("Testing keystore operations")
        print("=" * 60)
        key_id = test_keystore_operations()
    else:
        key_id = None
    
    if args.all or args.encrypt:
        if not key_id:
            key_id = "test"  # Placeholder
        print("=" * 60)
        print("Testing file encryption/decryption")
        print("=" * 60)
        test_file_encryption_decryption(key_id)
    
    if args.all or args.real:
        print("=" * 60)
        print("Testing real file decryption")
        print("=" * 60)
        test_real_file()
    
    print("\nAll tests completed")

if __name__ == "__main__":
    main()