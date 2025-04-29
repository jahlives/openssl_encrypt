#!/usr/bin/env python3
"""
Test Script for Secure File Encryption Tool

This script provides a simple way to test the functionality of the openssl_encrypt tool
by encrypting and decrypting a test file using various algorithms and hash configurations.
It helps verify that the encryption and decryption processes work correctly with different
parameters and settings.
"""

import os
import sys
import tempfile
import argparse
import shutil
from pathlib import Path

# Import from the modules package directly since we're within the openssl_encrypt package
from .modules.crypt_core import (
    encrypt_file, decrypt_file, EncryptionAlgorithm,
    generate_key, multi_hash_password, string_entropy
)

def create_test_file(content="This is a test file for encryption and decryption"):
    """Create a temporary test file with specified content."""
    temp_dir = tempfile.mkdtemp()
    test_file = os.path.join(temp_dir, "test_file.txt")
    with open(test_file, "w") as f:
        f.write(content)
    return temp_dir, test_file

def run_encryption_test(algorithm, hash_config=None, iterations=1, password=None):
    """
    Run an encryption and decryption test with the specified algorithm and hash config.
    
    Args:
        algorithm (str): The encryption algorithm to use (e.g., 'fernet', 'aes-gcm')
        hash_config (dict, optional): Hash configuration dictionary
        iterations (int): Number of times to run the test
        password (bytes, optional): Password to use for encryption/decryption
    
    Returns:
        bool: True if all tests passed, False otherwise
    """
    # Convert algorithm string to enum if needed
    if isinstance(algorithm, str):
        try:
            algorithm = EncryptionAlgorithm(algorithm)
        except ValueError:
            print(f"Error: Invalid algorithm '{algorithm}'")
            return False
    
    # Create a default hash config if none provided
    if hash_config is None:
        hash_config = {
            'sha512': 0,
            'sha256': 0,
            'sha3_256': 0,
            'sha3_512': 0,
            'blake2b': 0,
            'shake256': 0,
            'whirlpool': 0,
            'scrypt': {'enabled': False, 'n': 128, 'r': 8, 'p': 1},
            'argon2': {'enabled': False},
            'pbkdf2_iterations': 1000  # Use a lower value for testing
        }
    
    # Use a default password if none provided
    if password is None:
        password = b"TestPassword123!"
    
    # Display test information
    print(f"\n=== Testing {algorithm.value} encryption ===")
    print(f"Hash config: {hash_config}")
    print(f"Running {iterations} iterations")
    
    # Track success rate
    success_count = 0
    
    for i in range(iterations):
        try:
            # Create a temporary directory and test file
            temp_dir, test_file = create_test_file()
            
            # Create output file paths
            encrypted_file = os.path.join(temp_dir, f"test_encrypted_{algorithm.value}.bin")
            decrypted_file = os.path.join(temp_dir, f"test_decrypted_{algorithm.value}.txt")
            
            print(f"\nIteration {i+1}/{iterations}")
            print(f"Test file: {test_file}")
            print(f"Encrypted file: {encrypted_file}")
            print(f"Decrypted file: {decrypted_file}")
            
            # Encrypt the file
            print("Encrypting file...")
            encrypt_result = encrypt_file(
                test_file,
                encrypted_file,
                password,
                hash_config,
                quiet=False,
                algorithm=algorithm,
                progress=True
            )
            
            # Check if encryption was successful
            if not encrypt_result:
                print("Encryption failed!")
                continue
            
            # Verify the encrypted file exists
            if not os.path.exists(encrypted_file):
                print("Encrypted file was not created!")
                continue
            
            # Get file sizes for comparison
            original_size = os.path.getsize(test_file)
            encrypted_size = os.path.getsize(encrypted_file)
            print(f"Original file size: {original_size} bytes")
            print(f"Encrypted file size: {encrypted_size} bytes")
            
            # Decrypt the file
            print("\nDecrypting file...")
            decrypt_result = decrypt_file(
                encrypted_file,
                decrypted_file,
                password,
                quiet=False,
                progress=True
            )
            
            # Check if decryption was successful
            if not decrypt_result:
                print("Decryption failed!")
                continue
            
            # Verify the decrypted file exists
            if not os.path.exists(decrypted_file):
                print("Decrypted file was not created!")
                continue
            
            # Compare the original and decrypted file contents
            with open(test_file, "r") as original, open(decrypted_file, "r") as decrypted:
                original_content = original.read()
                decrypted_content = decrypted.read()
                
                if original_content == decrypted_content:
                    print("\n✅ Success: Decrypted content matches original content")
                    success_count += 1
                else:
                    print("\n❌ Error: Decrypted content does not match original content")
                    print(f"Original: {original_content}")
                    print(f"Decrypted: {decrypted_content}")
            
        except Exception as e:
            print(f"Error during test: {e}")
        finally:
            # Clean up temporary files
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass
    
    # Print summary
    print(f"\nTest Summary for {algorithm.value}:")
    print(f"Successful tests: {success_count}/{iterations} ({success_count/iterations*100:.1f}%)")
    
    return success_count == iterations

def run_all_algorithms_test(iterations=1):
    """Run tests on all available encryption algorithms."""
    # Get all algorithms from the EncryptionAlgorithm enum
    all_algorithms = [algo for algo in EncryptionAlgorithm]
    
    # Define a simple hash config for testing
    hash_config = {
        'sha512': 10,
        'sha256': 0,
        'sha3_256': 0,
        'sha3_512': 0,
        'blake2b': 10,
        'shake256': 10,
        'whirlpool': 0,
        'scrypt': {'enabled': False},
        'argon2': {'enabled': False},
        'pbkdf2_iterations': 100
    }
    
    # Test each algorithm
    results = {}
    for algo in all_algorithms:
        result = run_encryption_test(algo, hash_config, iterations)
        results[algo.value] = result
    
    # Print overall summary
    print("\n=== Overall Test Summary ===")
    for algo, result in results.items():
        status = "✅ Passed" if result else "❌ Failed"
        print(f"{algo}: {status}")
    
    # Check if all tests passed
    return all(results.values())

def run_hash_functions_test():
    """Test the hash functions implemented in the tool."""
    print("\n=== Testing Hash Functions ===")
    
    # Test data
    test_password = b"TestPassword123!"
    test_salt = os.urandom(16)
    
    # Test each hash algorithm individually
    hash_algorithms = ["sha256", "sha512", "sha3_256", "sha3_512", "blake2b", "shake256", "whirlpool"]
    
    for algo in hash_algorithms:
        # Create a config with only this algorithm enabled
        hash_config = {
            'sha512': 0,
            'sha256': 0,
            'sha3_256': 0,
            'sha3_512': 0,
            'blake2b': 0,
            'shake256': 0,
            'whirlpool': 0,
            'scrypt': {'enabled': False},
            'argon2': {'enabled': False},
            'pbkdf2_iterations': 0
        }
        
        # Enable just the algorithm we're testing with 10 iterations
        hash_config[algo] = 10
        
        print(f"\nTesting {algo} hash function:")
        try:
            # Hash the password
            hashed_password = multi_hash_password(test_password, test_salt, hash_config, quiet=True)
            
            # Test should produce a non-None result
            if hashed_password is not None:
                print(f"✅ {algo} hash successful")
                print(f"Hash length: {len(hashed_password)} bytes")
            else:
                print(f"❌ {algo} hash failed: returned None")
                return False
            
            # Hash again with the same parameters to check consistency
            hashed_password2 = multi_hash_password(test_password, test_salt, hash_config, quiet=True)
            
            if hashed_password == hashed_password2:
                print(f"✅ {algo} hash is deterministic (produces the same output for the same input)")
            else:
                print(f"❌ {algo} hash is not deterministic")
                return False
            
        except Exception as e:
            print(f"❌ {algo} hash test failed with error: {e}")
            return False
    
    print("\n✅ All hash function tests passed")
    return True

def test_password_entropy():
    """Test the password entropy evaluation function."""
    print("\n=== Testing Password Entropy Evaluation ===")
    
    test_cases = [
        ("short", "A short password with low entropy"),
        ("a", "Single character"),
        ("abcdefgh", "8 lowercase letters"),
        ("ABCDEFGH", "8 uppercase letters"),
        ("12345678", "8 digits"),
        ("!@#$%^&*", "8 special characters"),
        ("Abcd1234", "Mixed case with numbers"),
        ("Abcd1234!@#$", "Mixed case with numbers and special characters"),
        ("ThisIsALongPasswordWithHighEntropy123!@#", "Long complex password")
    ]
    
    print(f"{'Password':<40} {'Length':<10} {'Entropy (bits)':<15}")
    print("-" * 65)
    
    for password, description in test_cases:
        entropy = string_entropy(password)
        print(f"{password:<40} {len(password):<10} {entropy:.2f}")
    
    print("\n✅ Password entropy evaluation test completed")
    return True

def main():
    """Main function to parse arguments and run tests."""
    parser = argparse.ArgumentParser(description="Test the secure file encryption tool")
    parser.add_argument(
        "--algorithm", "-a", 
        choices=[algo.value for algo in EncryptionAlgorithm],
        help="Specific encryption algorithm to test"
    )
    parser.add_argument(
        "--iterations", "-i", type=int, default=1,
        help="Number of test iterations to run (default: 1)"
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Test all encryption algorithms"
    )
    parser.add_argument(
        "--hash-functions", action="store_true",
        help="Test hash functions"
    )
    parser.add_argument(
        "--entropy", action="store_true",
        help="Test password entropy evaluation"
    )
    
    args = parser.parse_args()
    
    # If no specific test is requested, show help
    if not (args.algorithm or args.all or args.hash_functions or args.entropy):
        parser.print_help()
        return
    
    # Run the requested tests
    if args.algorithm:
        run_encryption_test(args.algorithm, iterations=args.iterations)
    
    if args.all:
        run_all_algorithms_test(iterations=args.iterations)
    
    if args.hash_functions:
        run_hash_functions_test()
    
    if args.entropy:
        test_password_entropy()

if __name__ == "__main__":
    main()
