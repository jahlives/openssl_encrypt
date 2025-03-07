#!/usr/bin/env python3

import unittest
import os
import sys
import tempfile
import shutil
import random
import string
import hashlib
import json
import base64
from unittest.mock import patch, MagicMock
import subprocess
import time

# Import functions from crypt.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from crypt import (
        generate_key, encrypt_file, decrypt_file, secure_shred_file, 
        multi_hash_password, calculate_hash, request_confirmation,
        expand_glob_patterns
    )
except ImportError:
    print("Error: Could not import from crypt.py. Make sure it's in the same directory.")
    sys.exit(1)

class TestCryptFunctions(unittest.TestCase):
    """Unit tests for individual functions in crypt.py"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create a test password
        self.password = "test_password".encode()
        
        # Create a sample file for testing
        self.test_content = b"This is a test file with some content for encryption and decryption tests."
        self.test_file = os.path.join(self.test_dir, "test_file.txt")
        with open(self.test_file, "wb") as f:
            f.write(self.test_content)
            
        # Create a random file of 1MB for testing larger files
        self.large_file = os.path.join(self.test_dir, "large_file.bin")
        with open(self.large_file, "wb") as f:
            f.write(os.urandom(1024 * 1024))  # 1MB of random data
            
        # Create a directory with some files for testing
        self.test_dir_to_shred = os.path.join(self.test_dir, "dir_to_shred")
        os.makedirs(self.test_dir_to_shred)
        for i in range(3):
            with open(os.path.join(self.test_dir_to_shred, f"file{i}.txt"), "wb") as f:
                f.write(f"Test file {i} content".encode())
        
        # Create test files for glob pattern testing
        for i in range(3):
            with open(os.path.join(self.test_dir, f"glob_test_{i}.txt"), "wb") as f:
                f.write(f"Glob test file {i}".encode())
    
    def tearDown(self):
        """Clean up test environment"""
        # Remove the temporary directory and all its contents
        try:
            shutil.rmtree(self.test_dir)
        except Exception as e:
            print(f"Error during tearDown: {e}")
    
    def test_calculate_hash(self):
        """Test the calculate_hash function"""
        test_data = b"test data for hashing"
        expected_hash = hashlib.sha256(test_data).hexdigest()
        actual_hash = calculate_hash(test_data)
        self.assertEqual(expected_hash, actual_hash)
    
    def test_generate_key(self):
        """Test the generate_key function"""
        # Basic key generation
        key, salt, hash_config = generate_key(self.password)
        self.assertIsNotNone(key)
        self.assertEqual(len(base64.urlsafe_b64decode(key)), 32)  # Fernet key is 32 bytes
        
        # Same password + salt should generate same key
        key2, _, _ = generate_key(self.password, salt, hash_config)
        self.assertEqual(key, key2)
        
        # Different salt should generate different key
        different_salt = os.urandom(16)
        key3, _, _ = generate_key(self.password, different_salt, hash_config)
        self.assertNotEqual(key, key3)
        
        # Test with custom hash_config
        hash_config = {
            'sha512': 10,
            'sha256': 0,
            'sha3_256': 0,
            'sha3_512': 0,
            'whirlpool': 0,
            'scrypt': {'n': 1024, 'r': 8, 'p': 1}
        }
        key4, _, _ = generate_key(self.password, salt, hash_config, 10000)
        self.assertNotEqual(key, key4)  # Different config should produce different key
    
    def test_encrypt_and_decrypt_file(self):
        """Test encryption and decryption of a file"""
        encrypted_file = os.path.join(self.test_dir, "encrypted.bin")
        decrypted_file = os.path.join(self.test_dir, "decrypted.txt")
        
        # Encrypt the test file
        success = encrypt_file(self.test_file, encrypted_file, self.password)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(encrypted_file))
        
        # Verify that the encrypted file is different from the original
        with open(encrypted_file, "rb") as f:
            encrypted_content = f.read()
        self.assertNotEqual(self.test_content, encrypted_content)
        
        # Decrypt the encrypted file
        success = decrypt_file(encrypted_file, decrypted_file, self.password)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(decrypted_file))
        
        # Verify that the decrypted content matches the original
        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()
        self.assertEqual(self.test_content, decrypted_content)
        
        # Test decryption with wrong password
        wrong_password = "wrong_password".encode()
        with self.assertRaises(ValueError):
            decrypt_file(encrypted_file, decrypted_file + ".wrong", wrong_password)
            
        # Test encryption/decryption with custom hash config
        hash_config = {
            'sha512': 10,
            'sha256': 5,
            'sha3_256': 0,
            'sha3_512': 0,
            'whirlpool': 0,
            'scrypt': {'n': 1024, 'r': 8, 'p': 1}
        }
        custom_encrypted = os.path.join(self.test_dir, "custom_encrypted.bin")
        custom_decrypted = os.path.join(self.test_dir, "custom_decrypted.txt")
        
        success = encrypt_file(self.test_file, custom_encrypted, self.password, hash_config, 5000)
        self.assertTrue(success)
        
        success = decrypt_file(custom_encrypted, custom_decrypted, self.password)
        self.assertTrue(success)
        
        with open(custom_decrypted, "rb") as f:
            custom_decrypted_content = f.read()
        self.assertEqual(self.test_content, custom_decrypted_content)
    
    def test_multi_hash_password(self):
        """Test the multi_hash_password function"""
        salt = os.urandom(16)
        
        # Test with no hashing algorithms
        hash_config = {
            'sha512': 0,
            'sha256': 0,
            'sha3_256': 0,
            'sha3_512': 0,
            'whirlpool': 0,
            'scrypt': {'n': 0, 'r': 8, 'p': 1}
        }
        result = multi_hash_password(self.password, salt, hash_config)
        self.assertEqual(result, self.password + salt)  # No hashing applied
        
        # Test with SHA-256 hashing
        hash_config['sha256'] = 10
        result_sha256 = multi_hash_password(self.password, salt, hash_config)
        self.assertNotEqual(result, result_sha256)  # Hashing applied
        
        # Test with SHA-512 hashing
        hash_config['sha256'] = 0
        hash_config['sha512'] = 10
        result_sha512 = multi_hash_password(self.password, salt, hash_config)
        self.assertNotEqual(result, result_sha512)  # Hashing applied
        self.assertNotEqual(result_sha256, result_sha512)  # Different algorithm
        
        # Test with SHA3-256 hashing if available
        if hasattr(hashlib, 'sha3_256'):
            hash_config['sha512'] = 0
            hash_config['sha3_256'] = 10
            result_sha3_256 = multi_hash_password(self.password, salt, hash_config)
            self.assertNotEqual(result, result_sha3_256)  # Hashing applied
            self.assertNotEqual(result_sha256, result_sha3_256)  # Different algorithm
        
        # Test with SHA3-512 hashing if available
        if hasattr(hashlib, 'sha3_512'):
            hash_config['sha3_256'] = 0
            hash_config['sha3_512'] = 10
            result_sha3_512 = multi_hash_password(self.password, salt, hash_config)
            self.assertNotEqual(result, result_sha3_512)  # Hashing applied
            self.assertNotEqual(result_sha256, result_sha3_512)  # Different algorithm
    
    @patch('builtins.input', return_value='y')
    def test_request_confirmation_yes(self, mock_input):
        """Test the request_confirmation function with 'yes' response"""
        self.assertTrue(request_confirmation("Test confirmation message"))
    
    @patch('builtins.input', return_value='n')
    def test_request_confirmation_no(self, mock_input):
        """Test the request_confirmation function with 'no' response"""
        self.assertFalse(request_confirmation("Test confirmation message"))
    
    def test_secure_shred_file(self):
        """Test the secure_shred_file function on a file"""
        test_shred_file = os.path.join(self.test_dir, "to_shred.txt")
        with open(test_shred_file, "wb") as f:
            f.write(b"This file will be securely shredded.")
        
        self.assertTrue(os.path.exists(test_shred_file))
        result = secure_shred_file(test_shred_file, passes=2, quiet=True)
        self.assertTrue(result)
        self.assertFalse(os.path.exists(test_shred_file))
    
    def test_secure_shred_directory(self):
        """Test securely shredding a directory"""
        self.assertTrue(os.path.exists(self.test_dir_to_shred))
        result = secure_shred_file(self.test_dir_to_shred, passes=1, quiet=True)
        self.assertTrue(result)
        self.assertFalse(os.path.exists(self.test_dir_to_shred))
    
    def test_secure_shred_nonexistent_file(self):
        """Test shredding a non-existent file (should return False)"""
        nonexistent_file = os.path.join(self.test_dir, "nonexistent.txt")
        result = secure_shred_file(nonexistent_file, quiet=True)
        self.assertFalse(result)
    
    def test_expand_glob_patterns(self):
        """Test the expand_glob_patterns function"""
        pattern = os.path.join(self.test_dir, "glob_test_*.txt")
        matched_files = expand_glob_patterns(pattern)
        self.assertEqual(len(matched_files), 3)
        
        non_matching_pattern = os.path.join(self.test_dir, "nonexistent_*.txt")
        matched_files = expand_glob_patterns(non_matching_pattern)
        self.assertEqual(len(matched_files), 0)


class TestCommandLineInterface(unittest.TestCase):
    """Integration tests for the command-line interface"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create a test file
        self.test_content = "This is a test file for CLI testing."
        self.test_file = os.path.join(self.test_dir, "cli_test.txt")
        with open(self.test_file, "w") as f:
            f.write(self.test_content)
        
        # Create test files for glob pattern testing
        for i in range(3):
            with open(os.path.join(self.test_dir, f"glob_{i}.txt"), "w") as f:
                f.write(f"Glob CLI test file {i}")
        
        # Script path
        self.script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crypt.py")
        self.assertTrue(os.path.exists(self.script_path), "crypt.py not found")
    
    def tearDown(self):
        """Clean up test environment"""
        try:
            shutil.rmtree(self.test_dir)
        except Exception as e:
            print(f"Error during tearDown: {e}")
    
    def run_command(self, args, input_text=None):
        """Run the script with given arguments and return stdout, stderr, and return code"""
        command = [sys.executable, self.script_path] + args
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if input_text else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate(input=input_text)
        return stdout, stderr, process.returncode
    
    def test_cli_encrypt_decrypt(self):
        """Test encryption and decryption via CLI"""
        # Test file paths
        encrypted_file = os.path.join(self.test_dir, "cli_encrypted.bin")
        decrypted_file = os.path.join(self.test_dir, "cli_decrypted.txt")
        
        # Encrypt the file
        stdout, stderr, returncode = self.run_command(
            ["encrypt", "-i", self.test_file, "-o", encrypted_file, "-p", "testpass"],
        )
        self.assertEqual(returncode, 0, f"Encryption failed: {stderr}")
        self.assertTrue(os.path.exists(encrypted_file))
        
        # Decrypt the file
        stdout, stderr, returncode = self.run_command(
            ["decrypt", "-i", encrypted_file, "-o", decrypted_file, "-p", "testpass"],
        )
        self.assertEqual(returncode, 0, f"Decryption failed: {stderr}")
        self.assertTrue(os.path.exists(decrypted_file))
        
        # Verify the decrypted content
        with open(decrypted_file, "r") as f:
            decrypted_content = f.read()
        self.assertEqual(self.test_content, decrypted_content)
        
        # Test with wrong password
        stdout, stderr, returncode = self.run_command(
            ["decrypt", "-i", encrypted_file, "-o", decrypted_file + ".wrong", "-p", "wrongpass"],
        )
        self.assertNotEqual(returncode, 0, "Decryption with wrong password should fail")
    
    def test_cli_overwrite(self):
        """Test the --overwrite option"""
        # Make a copy of the test file
        test_file_copy = os.path.join(self.test_dir, "overwrite_test.txt")
        shutil.copy(self.test_file, test_file_copy)
        
        # Encrypt with overwrite option
        stdout, stderr, returncode = self.run_command(
            ["encrypt", "-i", test_file_copy, "--overwrite", "-p", "testpass"],
        )
        self.assertEqual(returncode, 0, f"Encryption with overwrite failed: {stderr}")
        
        # Check that the file still exists but is now encrypted
        self.assertTrue(os.path.exists(test_file_copy))
        
        # Decrypt with overwrite option
        stdout, stderr, returncode = self.run_command(
            ["decrypt", "-i", test_file_copy, "--overwrite", "-p", "testpass"],
        )
        self.assertEqual(returncode, 0, f"Decryption with overwrite failed: {stderr}")
        
        # Verify the decrypted content matches original
        with open(test_file_copy, "r") as f:
            decrypted_content = f.read()
        self.assertEqual(self.test_content, decrypted_content)
    
    def test_cli_shred(self):
        """Test the shred command via CLI"""
        # Create a file to shred
        shred_file = os.path.join(self.test_dir, "to_shred_cli.txt")
        with open(shred_file, "w") as f:
            f.write("This file will be shredded via CLI.")
        
        # Shred the file
        stdout, stderr, returncode = self.run_command(
            ["shred", "-i", shred_file, "--shred-passes", "1"],
        )
        self.assertEqual(returncode, 0, f"Shredding failed: {stderr}")
        self.assertFalse(os.path.exists(shred_file))
    
    def test_cli_shred_glob(self):
        """Test shredding with glob patterns"""
        # Get the count of glob files before shredding
        glob_pattern = os.path.join(self.test_dir, "glob_*.txt")
        initial_count = len(expand_glob_patterns(glob_pattern))
        self.assertEqual(initial_count, 3)
        
        # Shred all glob files
        stdout, stderr, returncode = self.run_command(
            ["shred", "-i", glob_pattern, "--shred-passes", "1"],
        )
        self.assertEqual(returncode, 0, f"Shredding with glob pattern failed: {stderr}")
        
        # Check that all glob files are gone
        remaining_count = len(expand_glob_patterns(glob_pattern))
        self.assertEqual(remaining_count, 0)
    
    def test_cli_hash_algorithms(self):
        """Test using various hash algorithms via CLI"""
        encrypted_file = os.path.join(self.test_dir, "multi_hash_encrypted.bin")
        decrypted_file = os.path.join(self.test_dir, "multi_hash_decrypted.txt")
        
        # Encrypt with multiple hash algorithms
        stdout, stderr, returncode = self.run_command(
            ["encrypt", "-i", self.test_file, "-o", encrypted_file, 
             "--sha256", "100", "--sha512", "50", "--pbkdf2", "5000", 
             "-p", "complex_pass"],
        )
        self.assertEqual(returncode, 0, f"Multi-hash encryption failed: {stderr}")
        
        # Decrypt the file
        stdout, stderr, returncode = self.run_command(
            ["decrypt", "-i", encrypted_file, "-o", decrypted_file, "-p", "complex_pass"],
        )
        self.assertEqual(returncode, 0, f"Multi-hash decryption failed: {stderr}")
        
        # Verify content
        with open(decrypted_file, "r") as f:
            decrypted_content = f.read()
        self.assertEqual(self.test_content, decrypted_content)


if __name__ == "__main__":
    unittest.main()
