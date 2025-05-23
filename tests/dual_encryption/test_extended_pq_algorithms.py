#!/usr/bin/env python3
"""
Test for extended post-quantum algorithms via liboqs integration.

This test verifies that the extended post-quantum algorithms work correctly
with the existing architecture, testing both encryption and decryption with
various algorithm combinations.
"""

import os
import sys
import unittest
import tempfile
import binascii
from unittest import mock

# Ensure openssl_encrypt is in the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Import the modules to test
from openssl_encrypt.modules.crypt_core import (
    encrypt_file, decrypt_file, EncryptionAlgorithm, PQC_AVAILABLE, LIBOQS_AVAILABLE
)


class TestExtendedPQAlgorithms(unittest.TestCase):
    """Tests for the extended post-quantum algorithms."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test files."""
        # Create test data
        cls.test_data = b"Hello, post-quantum world!"
        
        # Create a temporary file for testing
        cls.test_file = tempfile.NamedTemporaryFile(delete=False)
        cls.test_file.write(cls.test_data)
        cls.test_file.close()
        
        # Output file paths
        cls.encrypted_file = tempfile.NamedTemporaryFile(delete=False).name
        cls.decrypted_file = tempfile.NamedTemporaryFile(delete=False).name
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test files."""
        try:
            os.unlink(cls.test_file.name)
        except OSError:
            pass
        
        try:
            os.unlink(cls.encrypted_file)
        except OSError:
            pass
        
        try:
            os.unlink(cls.decrypted_file)
        except OSError:
            pass
    
    @unittest.skipIf(not PQC_AVAILABLE, "Post-quantum cryptography not available")
    def test_ml_kem_algorithms(self):
        """Test ML-KEM (Kyber) algorithms."""
        # Test ML-KEM-512-HYBRID
        self._test_algorithm(EncryptionAlgorithm.ML_KEM_512_HYBRID)
        
        # Test ML-KEM-768-HYBRID
        self._test_algorithm(EncryptionAlgorithm.ML_KEM_768_HYBRID)
        
        # Test ML-KEM-1024-HYBRID
        self._test_algorithm(EncryptionAlgorithm.ML_KEM_1024_HYBRID)
    
    @unittest.skipIf(not PQC_AVAILABLE, "Post-quantum cryptography not available")
    def test_ml_kem_chacha20_algorithms(self):
        """Test ML-KEM with ChaCha20 algorithms."""
        try:
            # Test ML-KEM-512-CHACHA20
            self._test_algorithm(EncryptionAlgorithm.ML_KEM_512_CHACHA20, 
                               encryption_data="chacha20-poly1305")
            
            # Test ML-KEM-768-CHACHA20
            self._test_algorithm(EncryptionAlgorithm.ML_KEM_768_CHACHA20,
                               encryption_data="chacha20-poly1305")
            
            # Test ML-KEM-1024-CHACHA20
            self._test_algorithm(EncryptionAlgorithm.ML_KEM_1024_CHACHA20,
                               encryption_data="chacha20-poly1305")
        except AttributeError:
            self.skipTest("ML-KEM-CHACHA20 algorithms not available")
    
    @unittest.skipIf(not (PQC_AVAILABLE and LIBOQS_AVAILABLE), 
                    "liboqs not available")
    def test_hqc_algorithms(self):
        """Test HQC algorithms."""
        try:
            # Test HQC-128-HYBRID
            self._test_algorithm(EncryptionAlgorithm.HQC_128_HYBRID)
            
            # Test HQC-192-HYBRID
            self._test_algorithm(EncryptionAlgorithm.HQC_192_HYBRID)
            
            # Test HQC-256-HYBRID
            self._test_algorithm(EncryptionAlgorithm.HQC_256_HYBRID)
        except (AttributeError, ValueError):
            self.skipTest("HQC algorithms not available")
    
    def _test_algorithm(self, algorithm, encryption_data=None):
        """Test encryption and decryption with a specific algorithm."""
        # Generate a PQC keypair
        if encryption_data:
            encrypted, keypair = encrypt_file(
                self.test_file.name, 
                self.encrypted_file,
                algorithm=algorithm,
                encryption_data=encryption_data,
                quiet=True
            )
        else:
            encrypted, keypair = encrypt_file(
                self.test_file.name, 
                self.encrypted_file,
                algorithm=algorithm,
                quiet=True
            )
        
        self.assertTrue(encrypted)
        self.assertIsNotNone(keypair)
        
        # Decrypt the file with the PQC keypair
        decrypted = decrypt_file(
            self.encrypted_file, 
            self.decrypted_file,
            algorithm=algorithm,
            pqc_private_key=keypair[1],
            quiet=True
        )
        
        self.assertTrue(decrypted)
        
        # Verify the decrypted content
        with open(self.decrypted_file, 'rb') as f:
            decrypted_data = f.read()
        
        self.assertEqual(decrypted_data, self.test_data)


if __name__ == '__main__':
    unittest.main()