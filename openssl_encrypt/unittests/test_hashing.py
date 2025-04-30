#!/usr/bin/env python3
"""
Test suite for the hash functions in the Secure File Encryption Tool.

This module contains tests specifically for the new hash algorithms 
(BLAKE2b and SHAKE-256) added to the encryption tool.
"""

import os
import sys
import shutil
import tempfile
import unittest
from unittest import mock
import hashlib

# Add the parent directory to the path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the modules to test
from modules.crypt_core import (
    encrypt_file, decrypt_file, EncryptionAlgorithm,
    generate_key, multi_hash_password
)


class TestNewHashFunctions(unittest.TestCase):
    """Test cases for the new BLAKE2b and SHAKE-256 hash functions."""

    def setUp(self):
        """Set up test environment."""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.test_files = []

        # Create a test file with some content
        self.test_file = os.path.join(self.test_dir, "test_file.txt")
        with open(self.test_file, "w") as f:
            f.write("This is a test file for encryption and decryption.")
        self.test_files.append(self.test_file)

        # Test password
        self.test_password = b"TestPassword123!"
        
        # Salt for testing
        self.test_salt = os.urandom(16)

    def tearDown(self):
        """Clean up after tests."""
        # Remove any test files that were created
        for file_path in self.test_files:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception:
                    pass

        # Remove the temporary directory
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_blake2b_hashing(self):
        """Test BLAKE2b hash function implementation."""
        # Create hash config with only BLAKE2b enabled
        blake2b_config = {
            'sha512': 0,
            'sha256': 0,
            'sha3_256': 0,
            'sha3_512': 0,
            'blake2b': 1000,  # Use 1000 iterations for testing
            'shake256': 0,
            'whirlpool': 0,
            'scrypt': {
                'enabled': False,
                'n': 128, 
                'r': 8,
                'p': 1
            },
            'argon2': {
                'enabled': False
            },
            'pbkdf2_iterations': 0
        }
        
        # Generate a hash of the password using BLAKE2b
        hash_result = multi_hash_password(
            self.test_password, 
            self.test_salt, 
            blake2b_config, 
            quiet=True
        )
        
        # The hash should not be None
        self.assertIsNotNone(hash_result)
        
        # Running it again with the same parameters should give the same result
        hash_result2 = multi_hash_password(
            self.test_password, 
            self.test_salt, 
            blake2b_config, 
            quiet=True
        )
        
        self.assertEqual(hash_result, hash_result2)
        
        # Test with a different password should give a different result
        different_password = b"DifferentPassword456!"
        hash_result3 = multi_hash_password(
            different_password, 
            self.test_salt, 
            blake2b_config, 
            quiet=True
        )
        
        self.assertNotEqual(hash_result, hash_result3)
        
        # Test with a different salt should give a different result
        different_salt = os.urandom(16)
        hash_result4 = multi_hash_password(
            self.test_password, 
            different_salt, 
            blake2b_config, 
            quiet=True
        )
        
        self.assertNotEqual(hash_result, hash_result4)
        
        # Test with a different number of iterations
        blake2b_config['blake2b'] = 2000  # Double the iterations
        hash_result5 = multi_hash_password(
            self.test_password, 
            self.test_salt, 
            blake2b_config, 
            quiet=True
        )
        
        self.assertNotEqual(hash_result, hash_result5)

    def test_shake256_hashing(self):
        """Test SHAKE-256 hash function implementation."""
        # Create hash config with only SHAKE-256 enabled
        shake256_config = {
            'sha512': 0,
            'sha256': 0,
            'sha3_256': 0,
            'sha3_512': 0,
            'blake2b': 0,
            'shake256': 1000,  # Use 1000 iterations for testing
            'whirlpool': 0,
            'scrypt': {
                'enabled': False,
                'n': 128, 
                'r': 8,
                'p': 1
            },
            'argon2': {
                'enabled': False
            },
            'pbkdf2_iterations': 0
        }
        
        # Generate a hash of the password using SHAKE-256
        hash_result = multi_hash_password(
            self.test_password, 
            self.test_salt, 
            shake256_config, 
            quiet=True
        )
        
        # The hash should not be None
        self.assertIsNotNone(hash_result)
        
        # Running it again with the same parameters should give the same result
        hash_result2 = multi_hash_password(
            self.test_password, 
            self.test_salt, 
            shake256_config, 
            quiet=True
        )
        
        self.assertEqual(hash_result, hash_result2)
        
        # Test with a different password should give a different result
        different_password = b"DifferentPassword456!"
        hash_result3 = multi_hash_password(
            different_password, 
            self.test_salt, 
            shake256_config, 
            quiet=True
        )
        
        self.assertNotEqual(hash_result, hash_result3)
        
        # Test with a different salt should give a different result
        different_salt = os.urandom(16)
        hash_result4 = multi_hash_password(
            self.test_password, 
            different_salt, 
            shake256_config, 
            quiet=True
        )
        
        self.assertNotEqual(hash_result, hash_result4)
        
        # Test with a different number of iterations
        shake256_config['shake256'] = 2000  # Double the iterations
        hash_result5 = multi_hash_password(
            self.test_password, 
            self.test_salt, 
            shake256_config, 
            quiet=True
        )
        
        self.assertNotEqual(hash_result, hash_result5)

    def test_combined_hash_algorithms(self):
        """Test using BLAKE2b and SHAKE-256 together with other algorithms."""
        # Create hash config with multiple algorithms
        combined_config = {
            'sha512': 100,
            'sha256': 0,
            'sha3_256': 0,
            'sha3_512': 0,
            'blake2b': 100,
            'shake256': 100,
            'whirlpool': 0,
            'scrypt': {
                'enabled': False,
                'n': 128, 
                'r': 8,
                'p': 1
            },
            'argon2': {
                'enabled': False
            },
            'pbkdf2_iterations': 100
        }
        
        # Generate a hash with the combined algorithms
        hash_result = multi_hash_password(
            self.test_password, 
            self.test_salt, 
            combined_config, 
            quiet=True
        )
        
        # The hash should not be None
        self.assertIsNotNone(hash_result)
        
        # Test with only BLAKE2b
        blake2b_only_config = {**combined_config}
        blake2b_only_config.update({
            'sha512': 0,
            'sha256': 0,
            'shake256': 0,
            'pbkdf2_iterations': 0
        })
        
        hash_result2 = multi_hash_password(
            self.test_password, 
            self.test_salt, 
            blake2b_only_config, 
            quiet=True
        )
        
        # Results should be different
        self.assertNotEqual(hash_result, hash_result2)
        
        # Test with only SHAKE-256
        shake256_only_config = {**combined_config}
        shake256_only_config.update({
            'sha512': 0,
            'sha256': 0,
            'blake2b': 0,
            'pbkdf2_iterations': 0
        })
        
        hash_result3 = multi_hash_password(
            self.test_password, 
            self.test_salt, 
            shake256_only_config, 
            quiet=True
        )
        
        # Results should be different from combined and BLAKE2b only
        self.assertNotEqual(hash_result, hash_result3)
        self.assertNotEqual(hash_result2, hash_result3)

    def test_encryption_with_new_hashes(self):
        """Test encryption and decryption using new hash functions."""
        # Define output files
        blake2b_encrypted_file = os.path.join(self.test_dir, "blake2b_encrypted.bin")
        blake2b_decrypted_file = os.path.join(self.test_dir, "blake2b_decrypted.txt")
        shake256_encrypted_file = os.path.join(self.test_dir, "shake256_encrypted.bin")
        shake256_decrypted_file = os.path.join(self.test_dir, "shake256_decrypted.txt")
        
        self.test_files.extend([
            blake2b_encrypted_file, blake2b_decrypted_file,
            shake256_encrypted_file, shake256_decrypted_file
        ])
        
        # BLAKE2b hash config
        blake2b_config = {
            'sha512': 0,
            'sha256': 0,
            'sha3_256': 0,
            'sha3_512': 0,
            'blake2b': 1000,
            'shake256': 0,
            'whirlpool': 0,
            'scrypt': {
                'enabled': False,
                'n': 128, 
                'r': 8,
                'p': 1
            },
            'argon2': {
                'enabled': False
            },
            'pbkdf2_iterations': 0
        }
        
        # Encrypt using BLAKE2b
        result = encrypt_file(
            self.test_file,
            blake2b_encrypted_file,
            self.test_password,
            blake2b_config,
            quiet=True,
            algorithm=EncryptionAlgorithm.AES_GCM
        )
        
        self.assertTrue(result)
        self.assertTrue(os.path.exists(blake2b_encrypted_file))
        
        # Decrypt the file
        result = decrypt_file(
            blake2b_encrypted_file,
            blake2b_decrypted_file,
            self.test_password,
            quiet=True
        )
        
        self.assertTrue(result)
        self.assertTrue(os.path.exists(blake2b_decrypted_file))
        
        # Verify the content
        with open(self.test_file, "r") as original, open(blake2b_decrypted_file, "r") as decrypted:
            self.assertEqual(original.read(), decrypted.read())
        
        # SHAKE-256 hash config
        shake256_config = {
            'sha512': 0,
            'sha256': 0,
            'sha3_256': 0,
            'sha3_512': 0,
            'blake2b': 0,
            'shake256': 1000,
            'whirlpool': 0,
            'scrypt': {
                'enabled': False,
                'n': 128, 
                'r': 8,
                'p': 1
            },
            'argon2': {
                'enabled': False
            },
            'pbkdf2_iterations': 0
        }
        
        # Encrypt using SHAKE-256
        result = encrypt_file(
            self.test_file,
            shake256_encrypted_file,
            self.test_password,
            shake256_config,
            quiet=True,
            algorithm=EncryptionAlgorithm.AES_GCM
        )
        
        self.assertTrue(result)
        self.assertTrue(os.path.exists(shake256_encrypted_file))
        
        # Decrypt the file
        result = decrypt_file(
            shake256_encrypted_file,
            shake256_decrypted_file,
            self.test_password,
            quiet=True
        )
        
        self.assertTrue(result)
        self.assertTrue(os.path.exists(shake256_decrypted_file))
        
        # Verify the content
        with open(self.test_file, "r") as original, open(shake256_decrypted_file, "r") as decrypted:
            self.assertEqual(original.read(), decrypted.read())

    def test_new_hash_algorithms_expected_output_size(self):
        """Test that the new hash algorithms produce output of expected size."""
        # BLAKE2b should produce a 64-byte (512-bit) digest
        blake2b_config = {
            'sha512': 0,
            'sha256': 0,
            'sha3_256': 0,
            'sha3_512': 0,
            'blake2b': 1,  # Just one iteration for this test
            'shake256': 0,
            'whirlpool': 0,
            'scrypt': {'enabled': False},
            'argon2': {'enabled': False},
            'pbkdf2_iterations': 0
        }
        
        # Direct use of hashlib to get expected output size
        expected_blake2b = hashlib.blake2b(self.test_password, digest_size=64).digest()
        self.assertEqual(len(expected_blake2b), 64)  # Verify our expectation
        
        # Run through our multi_hash_password with just one iteration
        # (should be equivalent to a single hash call)
        result_blake2b = multi_hash_password(
            self.test_password, 
            self.test_salt, 
            blake2b_config, 
            quiet=True
        )
        
        # Should match the expected output size
        self.assertEqual(len(result_blake2b), 64)
        
        # SHAKE-256 can produce variable-length output, we expect it to be set to 64 bytes
        shake256_config = {
            'sha512': 0,
            'sha256': 0,
            'sha3_256': 0,
            'sha3_512': 0,
            'blake2b': 0,
            'shake256': 1,  # Just one iteration for this test
            'whirlpool': 0,
            'scrypt': {'enabled': False},
            'argon2': {'enabled': False},
            'pbkdf2_iterations': 0
        }
        
        # Direct use of hashlib to get expected output size
        expected_shake256 = hashlib.shake_256(self.test_password).digest(64)
        self.assertEqual(len(expected_shake256), 64)  # Verify our expectation
        
        # Run through our multi_hash_password with just one iteration
        result_shake256 = multi_hash_password(
            self.test_password, 
            self.test_salt, 
            shake256_config, 
            quiet=True
        )
        
        # Should match the expected output size
        self.assertEqual(len(result_shake256), 64)


if __name__ == "__main__":
    unittest.main()