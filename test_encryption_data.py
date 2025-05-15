#!/usr/bin/env python3
"""
Integration test for the configurable data encryption with Kyber feature.
This script tests encryption and decryption with different symmetric algorithms.
"""

import os
import sys
import tempfile
import shutil
import argparse
from typing import List

# Import the necessary modules
from openssl_encrypt.modules.crypt_core import encrypt_file, decrypt_file
from openssl_encrypt.modules.pqc import PQCipher

def run_tests(test_password: bytes = b"test_password_123", cleanup: bool = True) -> bool:
    """
    Run integration tests for the configurable data encryption algorithms.
    
    Args:
        test_password: Password to use for encryption
        cleanup: Whether to remove test files after testing
    
    Returns:
        bool: True if all tests pass, False otherwise
    """
    # Create temporary test directory
    test_dir = tempfile.mkdtemp()
    test_files = []
    success = True
    
    try:
        # Create a test file
        test_file = os.path.join(test_dir, "test_content.txt")
        with open(test_file, "w") as f:
            f.write("This is a test file for the configurable data encryption feature.\n")
            f.write("We want to ensure all algorithms work correctly with different data sizes.\n")
            f.write("123456789" * 100)  # Add some more data for a good test
        
        print(f"Created test file: {test_file}")
        
        # Define the algorithms to test
        algorithms = [
            'aes-gcm', 
            'aes-gcm-siv', 
            'aes-ocb3', 
            'aes-siv',
            'chacha20-poly1305', 
            'xchacha20-poly1305'
        ]
        
        kyber_versions = ["kyber512-hybrid", "kyber768-hybrid", "kyber1024-hybrid"]
        
        # Basic hash config for testing (simplified for speed)
        hash_config = {
            'sha512': 0,
            'sha256': 100,
            'sha3_256': 0,
            'sha3_512': 0,
            'blake2b': 0,
            'shake256': 0,
            'whirlpool': 0,
            'scrypt': {
                'enabled': False,
                'n': 16,
                'r': 8,
                'p': 1,
                'rounds': 1
            },
            'argon2': {
                'enabled': False,
                'time_cost': 1,
                'memory_cost': 8192,
                'parallelism': 1,
                'hash_len': 32,
                'type': 2,
                'rounds': 1
            },
            'pbkdf2_iterations': 1000
        }
        
        # Test each Kyber variant with each data encryption algorithm
        for kyber_alg in kyber_versions:
            print(f"\nTesting {kyber_alg}:")
            
            for encryption_data in algorithms:
                print(f"  With {encryption_data}... ", end="", flush=True)
                
                # Create output filename
                output_file = os.path.join(
                    test_dir, 
                    f"test_content_{kyber_alg}_{encryption_data.replace('-', '_')}.enc"
                )
                test_files.append(output_file)
                
                # Encrypt the file
                try:
                    encrypt_file(
                        test_file,
                        output_file,
                        test_password,
                        hash_config,
                        algorithm=kyber_alg,
                        encryption_data=encryption_data,
                        quiet=True
                    )
                    
                    # Decrypt the file to a new location
                    decrypted_file = os.path.join(
                        test_dir, 
                        f"decrypted_{kyber_alg}_{encryption_data.replace('-', '_')}.txt"
                    )
                    test_files.append(decrypted_file)
                    
                    decrypt_file(
                        output_file,
                        decrypted_file,
                        test_password,
                        quiet=True
                    )
                    
                    # Verify content
                    with open(test_file, 'rb') as f:
                        original_content = f.read()
                    with open(decrypted_file, 'rb') as f:
                        decrypted_content = f.read()
                        
                    if original_content == decrypted_content:
                        print("OK")
                    else:
                        print("FAILED - Content mismatch")
                        success = False
                        
                except Exception as e:
                    print(f"FAILED - {str(e)}")
                    success = False
        
        # Also test with PQCipher directly
        print("\nTesting direct PQCipher use:")
        
        for encryption_data in algorithms:
            print(f"  With {encryption_data}... ", end="", flush=True)
            
            try:
                # Read the original test file
                with open(test_file, 'rb') as f:
                    test_data = f.read()
                
                # Create cipher with the specific algorithm
                cipher = PQCipher("Kyber768", encryption_data=encryption_data)
                
                # Generate keypair
                public_key, private_key = cipher.generate_keypair()
                
                # Encrypt the data
                encrypted_data = cipher.encrypt(test_data, public_key)
                
                # Write to file
                pqcipher_file = os.path.join(
                    test_dir, 
                    f"pqcipher_{encryption_data.replace('-', '_')}.enc"
                )
                test_files.append(pqcipher_file)
                with open(pqcipher_file, 'wb') as f:
                    f.write(encrypted_data)
                
                # Decrypt with same cipher
                decrypted_data = cipher.decrypt(encrypted_data, private_key)
                
                # Verify content
                if test_data == decrypted_data:
                    print("OK")
                else:
                    print("FAILED - Content mismatch")
                    success = False
                
            except Exception as e:
                print(f"FAILED - {str(e)}")
                success = False
        
        # Print final result
        if success:
            print("\nALL TESTS PASSED!")
        else:
            print("\nSOME TESTS FAILED!")
        
        return success
        
    finally:
        # Clean up
        if cleanup:
            try:
                shutil.rmtree(test_dir)
                print(f"Removed test directory: {test_dir}")
            except Exception as e:
                print(f"Warning: Could not clean up test directory: {str(e)}")
        else:
            print(f"Test files located in: {test_dir}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Integration test for configurable data encryption")
    parser.add_argument(
        "--no-cleanup", 
        action="store_true", 
        help="Don't remove test files after testing"
    )
    
    args = parser.parse_args()
    
    # Run the tests
    success = run_tests(cleanup=not args.no_cleanup)
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)