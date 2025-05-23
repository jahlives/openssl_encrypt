#!/usr/bin/env python3
"""
Test script for the post-quantum cryptography adapter module.

This script tests the integration between our native post-quantum cryptography
implementation and the liboqs wrapper, ensuring that all algorithms work
correctly through a unified interface.
"""

import os
import sys
import unittest
from unittest import mock

# Ensure openssl_encrypt is in the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the modules to test
from openssl_encrypt.modules.pqc_adapter import (
    ExtendedPQCipher,
    get_security_level,
    get_available_pq_algorithms,
    LIBOQS_AVAILABLE
)


class TestPQCAdapter(unittest.TestCase):
    """Tests for the post-quantum cryptography adapter module."""
    
    def test_get_available_pq_algorithms(self):
        """Test the get_available_pq_algorithms function."""
        algorithms = get_available_pq_algorithms(quiet=True)
        
        # Basic ML-KEM algorithms should always be available
        self.assertIn("ML-KEM-512", algorithms)
        self.assertIn("ML-KEM-768", algorithms)
        self.assertIn("ML-KEM-1024", algorithms)
        
        # Legacy Kyber names should be included by default
        self.assertIn("Kyber512", algorithms)
        self.assertIn("Kyber768", algorithms)
        self.assertIn("Kyber1024", algorithms)
        
        # Check excluding legacy names
        legacy_excluded = get_available_pq_algorithms(include_legacy=False, quiet=True)
        self.assertNotIn("Kyber512", legacy_excluded)
        self.assertNotIn("Kyber768", legacy_excluded)
        self.assertNotIn("Kyber1024", legacy_excluded)
    
    def test_get_security_level(self):
        """Test the get_security_level function."""
        # Test ML-KEM/Kyber security levels
        self.assertEqual(get_security_level("ML-KEM-512"), 1)
        self.assertEqual(get_security_level("ML-KEM-768"), 3)
        self.assertEqual(get_security_level("ML-KEM-1024"), 5)
        
        # Test legacy names
        self.assertEqual(get_security_level("Kyber512"), 1)
        self.assertEqual(get_security_level("Kyber768"), 3)
        self.assertEqual(get_security_level("Kyber1024"), 5)
        
        # Test other algorithms
        self.assertEqual(get_security_level("HQC-128"), 1)
        self.assertEqual(get_security_level("ML-DSA-44"), 1)
        self.assertEqual(get_security_level("SLH-DSA-SHA2-256F"), 5)
        
        # Test unknown algorithm
        self.assertEqual(get_security_level("Unknown-Algorithm"), 0)
    
    def test_extended_pqcipher_native(self):
        """Test the ExtendedPQCipher class with native algorithms."""
        # Test with ML-KEM-512 (native implementation)
        cipher = ExtendedPQCipher("ML-KEM-512", quiet=True)
        
        # Verify that we're using the native implementation
        self.assertFalse(cipher.use_liboqs)
        
        # Generate keypair
        public_key, private_key = cipher.generate_keypair()
        self.assertIsInstance(public_key, bytes)
        self.assertIsInstance(private_key, bytes)
        
        # Test encryption and decryption
        message = b"Hello, post-quantum world!"
        encrypted = cipher.encrypt(message, public_key)
        decrypted = cipher.decrypt(encrypted, private_key)
        
        self.assertEqual(message, decrypted)
        
        # Test with legacy name
        legacy_cipher = ExtendedPQCipher("Kyber512", quiet=True)
        self.assertFalse(legacy_cipher.use_liboqs)
        
        # Generate keypair
        public_key, private_key = legacy_cipher.generate_keypair()
        
        # Test encryption and decryption
        encrypted = legacy_cipher.encrypt(message, public_key)
        decrypted = legacy_cipher.decrypt(encrypted, private_key)
        
        self.assertEqual(message, decrypted)
    
    @unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
    def test_extended_pqcipher_liboqs(self):
        """Test the ExtendedPQCipher class with liboqs algorithms."""
        # Get available algorithms
        algorithms = get_available_pq_algorithms(quiet=True)
        
        # Test with HQC-128 if available
        if "HQC-128" in algorithms:
            cipher = ExtendedPQCipher("HQC-128", quiet=True)
            
            # Verify that we're using the liboqs implementation
            self.assertTrue(cipher.use_liboqs)
            
            # Generate keypair
            public_key, private_key = cipher.generate_keypair()
            self.assertIsInstance(public_key, bytes)
            self.assertIsInstance(private_key, bytes)
            
            # Test encryption and decryption
            message = b"Hello, post-quantum world!"
            encrypted = cipher.encrypt(message, public_key)
            decrypted = cipher.decrypt(encrypted, private_key)
            
            self.assertEqual(message, decrypted)
        else:
            self.skipTest("HQC-128 not available")
    
    @unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
    def test_extended_pqcipher_signature(self):
        """Test the ExtendedPQCipher class with signature algorithms."""
        # Get available algorithms
        algorithms = get_available_pq_algorithms(quiet=True)
        
        # Test with ML-DSA-44 if available
        if "ML-DSA-44" in algorithms:
            signer = ExtendedPQCipher("ML-DSA-44", quiet=True)
            
            # Verify that we're using the liboqs implementation
            self.assertTrue(signer.use_liboqs)
            self.assertFalse(signer.is_kem)
            
            # Generate keypair
            public_key, private_key = signer.generate_keypair()
            self.assertIsInstance(public_key, bytes)
            self.assertIsInstance(private_key, bytes)
            
            # Test signing and verification
            message = b"Hello, post-quantum world!"
            signature = signer.sign(message, private_key)
            
            self.assertTrue(signer.verify(message, signature, public_key))
            self.assertFalse(signer.verify(b"Modified message", signature, public_key))
        else:
            self.skipTest("ML-DSA-44 not available")
    
    @mock.patch('openssl_encrypt.modules.pqc_adapter.LIBOQS_AVAILABLE', False)
    def test_liboqs_not_available(self):
        """Test behavior when liboqs is not available."""
        # Native algorithms should still work
        cipher = ExtendedPQCipher("ML-KEM-512", quiet=True)
        self.assertFalse(cipher.use_liboqs)
        
        # liboqs-only algorithms should fail
        with self.assertRaises(ImportError):
            ExtendedPQCipher("HQC-128", quiet=True)
        
        with self.assertRaises(ImportError):
            ExtendedPQCipher("ML-DSA-44", quiet=True)


if __name__ == '__main__':
    unittest.main()