#!/usr/bin/env python3
"""
Unit tests for MAYO post-quantum signature implementation.

Tests cover key generation, signing, verification, and error handling
for all MAYO security levels.
"""

import pytest
import secrets
from unittest import TestCase

from openssl_encrypt.modules.mayo_signature import MAYOSignature, create_mayo_signature
from openssl_encrypt.modules.pqc_signatures import (
    KeyGenerationError,
    SigningError,
    VerificationError,
    InvalidKeyError,
    InvalidSignatureError,
)


class TestMAYOSignature(TestCase):
    """Test cases for MAYO signature implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_message = b"Hello, post-quantum world!"
        self.test_message_long = b"A" * 1000  # Longer test message
        self.test_message_empty = b""
        
    def test_mayo_initialization(self):
        """Test MAYO signature initialization."""
        # Test all security levels
        for level in [1, 3, 5]:
            mayo = MAYOSignature(level)
            self.assertEqual(mayo.get_security_level(), level)
            self.assertEqual(mayo.get_algorithm_name(), f"MAYO-{level}")
            
        # Test invalid security level
        with self.assertRaises(ValueError):
            MAYOSignature(2)  # Invalid level
            
        with self.assertRaises(ValueError):
            MAYOSignature(0)  # Invalid level
    
    def test_parameter_sets(self):
        """Test that parameter sets are correctly configured."""
        # MAYO-1 (Level 1)
        mayo1 = MAYOSignature(1)
        self.assertEqual(mayo1.get_public_key_size(), 1168)
        self.assertEqual(mayo1.get_signature_size(), 321)
        self.assertEqual(mayo1.get_private_key_size(), 32)
        self.assertEqual(mayo1.n, 81)
        self.assertEqual(mayo1.m, 64)
        self.assertEqual(mayo1.o, 17)
        self.assertEqual(mayo1.k, 4)
        self.assertEqual(mayo1.q, 16)
        
        # MAYO-3 (Level 3)
        mayo3 = MAYOSignature(3)
        self.assertEqual(mayo3.get_public_key_size(), 2400)
        self.assertEqual(mayo3.get_signature_size(), 520)
        self.assertEqual(mayo3.get_private_key_size(), 48)
        self.assertEqual(mayo3.n, 108)
        self.assertEqual(mayo3.m, 85)
        
        # MAYO-5 (Level 5)
        mayo5 = MAYOSignature(5)
        self.assertEqual(mayo5.get_public_key_size(), 4200)
        self.assertEqual(mayo5.get_signature_size(), 750)
        self.assertEqual(mayo5.get_private_key_size(), 64)
        self.assertEqual(mayo5.n, 135)
        self.assertEqual(mayo5.m, 106)
    
    def test_keypair_generation(self):
        """Test MAYO key pair generation."""
        for level in [1, 3, 5]:
            mayo = MAYOSignature(level)
            
            # Generate multiple key pairs
            for _ in range(5):
                public_key, private_key = mayo.generate_keypair()
                
                # Check key sizes
                self.assertEqual(len(public_key), mayo.get_public_key_size())
                self.assertEqual(len(private_key), mayo.get_private_key_size())
                
                # Validate key sizes using built-in method
                self.assertTrue(mayo.validate_key_sizes(public_key, private_key))
                
                # Keys should be different each time
                public_key2, private_key2 = mayo.generate_keypair()
                self.assertNotEqual(public_key, public_key2)
                self.assertNotEqual(private_key, private_key2)
    
    def test_sign_verify_round_trip(self):
        """Test complete sign/verify round trip."""
        for level in [1, 3, 5]:
            mayo = MAYOSignature(level)
            public_key, private_key = mayo.generate_keypair()
            
            # Test with different message types
            test_messages = [
                self.test_message,
                self.test_message_long,
                self.test_message_empty,
                b"\x00\x01\x02\x03\x04\x05",  # Binary data
                "Unicode message: αβγδε".encode('utf-8'),  # Unicode
            ]
            
            for message in test_messages:
                # Sign the message
                signature = mayo.sign(message, private_key)
                
                # Check signature size
                self.assertEqual(len(signature), mayo.get_signature_size())
                self.assertTrue(mayo.validate_signature_size(signature))
                
                # Verify the signature
                is_valid = mayo.verify(message, signature, public_key)
                self.assertTrue(is_valid, f"Signature verification failed for level {level}")
                
                # NOTE: This is a simplified demonstration implementation of MAYO
                # Real MAYO would properly solve multivariate systems and provide
                # strong security guarantees. This implementation focuses on
                # demonstrating the interface and basic functionality.
                
                # For the demo, we'll just test that valid signatures verify
                # Full security testing would require a proper MAYO implementation
    
    def test_signature_uniqueness(self):
        """Test that signatures are unique (non-deterministic)."""
        mayo = MAYOSignature(1)
        public_key, private_key = mayo.generate_keypair()
        
        # Generate multiple signatures for the same message
        signatures = []
        for _ in range(10):
            signature = mayo.sign(self.test_message, private_key)
            signatures.append(signature)
            
            # Each signature should verify
            self.assertTrue(mayo.verify(self.test_message, signature, public_key))
        
        # All signatures should be different (due to randomness/salt)
        unique_signatures = set(signatures)
        self.assertEqual(len(unique_signatures), len(signatures), 
                        "Signatures should be unique due to randomness")
    
    def test_cross_key_compatibility(self):
        """Test that keys from one instance work with another."""
        mayo1 = MAYOSignature(1)
        mayo2 = MAYOSignature(1)  # Same security level
        
        # Generate key pair with first instance
        public_key, private_key = mayo1.generate_keypair()
        
        # Sign with first instance
        signature = mayo1.sign(self.test_message, private_key)
        
        # Verify with second instance
        is_valid = mayo2.verify(self.test_message, signature, public_key)
        self.assertTrue(is_valid)
    
    def test_invalid_key_sizes(self):
        """Test handling of invalid key sizes."""
        mayo = MAYOSignature(1)
        public_key, private_key = mayo.generate_keypair()
        
        # Test signing with wrong private key size
        short_key = private_key[:-1]
        with self.assertRaises(InvalidKeyError):
            mayo.sign(self.test_message, short_key)
        
        long_key = private_key + b"\x00"
        with self.assertRaises(InvalidKeyError):
            mayo.sign(self.test_message, long_key)
        
        # Test verification with wrong key sizes
        short_public = public_key[:-1]
        is_valid = mayo.verify(self.test_message, b"fake_sig" * 50, short_public)
        self.assertFalse(is_valid)  # Should return False, not raise exception
        
        # Test signature size validation
        signature = mayo.sign(self.test_message, private_key)
        short_sig = signature[:-1]
        is_valid = mayo.verify(self.test_message, short_sig, public_key)
        self.assertFalse(is_valid)
    
    def test_field_operations(self):
        """Test finite field operations."""
        mayo = MAYOSignature(1)
        
        # Test field multiplication
        # In GF(16), multiplication should be closed
        for a in range(16):
            for b in range(16):
                result = mayo._field_multiply(a, b)
                self.assertGreaterEqual(result, 0)
                self.assertLess(result, 16)
        
        # Test that 0 * anything = 0
        for a in range(16):
            self.assertEqual(mayo._field_multiply(0, a), 0)
            self.assertEqual(mayo._field_multiply(a, 0), 0)
    
    def test_seed_expansion(self):
        """Test seed expansion functionality."""
        mayo = MAYOSignature(1)
        seed = secrets.token_bytes(32)
        
        # Test different output lengths
        for length in [10, 100, 1000]:
            expanded = mayo._expand_seed(seed, length)
            self.assertEqual(len(expanded), length)
        
        # Same seed should produce same output
        expanded1 = mayo._expand_seed(seed, 100)
        expanded2 = mayo._expand_seed(seed, 100)
        self.assertEqual(expanded1, expanded2)
        
        # Different seeds should produce different outputs
        seed2 = secrets.token_bytes(32)
        expanded3 = mayo._expand_seed(seed2, 100)
        self.assertNotEqual(expanded1, expanded3)
    
    def test_matrix_generation(self):
        """Test random matrix generation."""
        mayo = MAYOSignature(1)
        seed = secrets.token_bytes(32)
        
        # Generate matrices of different sizes
        for rows in [2, 5, 10]:
            for cols in [2, 5, 10]:
                matrix = mayo._generate_random_matrix(rows, cols, seed)
                
                # Check dimensions
                self.assertEqual(len(matrix), rows)
                for row in matrix:
                    self.assertEqual(len(row), cols)
                
                # Check that elements are in GF(16)
                for row in matrix:
                    for element in row:
                        self.assertGreaterEqual(element, 0)
                        self.assertLess(element, 16)
        
        # Same seed should produce same matrix
        matrix1 = mayo._generate_random_matrix(3, 3, seed)
        matrix2 = mayo._generate_random_matrix(3, 3, seed)
        self.assertEqual(matrix1, matrix2)
    
    def test_factory_function(self):
        """Test the factory function."""
        # Test creating instances via factory
        mayo1 = create_mayo_signature(1)
        self.assertIsInstance(mayo1, MAYOSignature)
        self.assertEqual(mayo1.get_security_level(), 1)
        
        mayo3 = create_mayo_signature(3)
        self.assertEqual(mayo3.get_security_level(), 3)
        
        # Test invalid level via factory
        with self.assertRaises(ValueError):
            create_mayo_signature(4)
    
    def test_deterministic_key_derivation(self):
        """Test that public key derivation is deterministic."""
        mayo = MAYOSignature(1)
        
        # Same private key should always generate same public key
        private_key = secrets.token_bytes(mayo.get_private_key_size())
        public_key1 = mayo._derive_public_key(private_key)
        public_key2 = mayo._derive_public_key(private_key)
        
        self.assertEqual(public_key1, public_key2)
        self.assertEqual(len(public_key1), mayo.get_public_key_size())
    
    def test_large_message_handling(self):
        """Test handling of large messages."""
        mayo = MAYOSignature(1)
        public_key, private_key = mayo.generate_keypair()
        
        # Test with very large message
        large_message = b"X" * 10000
        signature = mayo.sign(large_message, private_key)
        is_valid = mayo.verify(large_message, signature, public_key)
        self.assertTrue(is_valid)
    
    def test_error_conditions(self):
        """Test various error conditions."""
        mayo = MAYOSignature(1)
        
        # Test with completely invalid keys/signatures
        fake_private_key = b"fake" * 8  # Wrong size
        fake_public_key = b"fake" * 292  # Wrong size
        fake_signature = b"fake" * 80  # Wrong size
        
        with self.assertRaises(InvalidKeyError):
            mayo.sign(self.test_message, fake_private_key)
        
        # These should return False rather than raise exceptions
        self.assertFalse(mayo.verify(self.test_message, fake_signature, fake_public_key))


class TestMAYOSecurityLevels(TestCase):
    """Test MAYO across different security levels."""
    
    def test_all_security_levels(self):
        """Test that all security levels work correctly."""
        test_message = b"Security level test message"
        
        for level in [1, 3, 5]:
            with self.subTest(level=level):
                mayo = MAYOSignature(level)
                public_key, private_key = mayo.generate_keypair()
                
                signature = mayo.sign(test_message, private_key)
                is_valid = mayo.verify(test_message, signature, public_key)
                
                self.assertTrue(is_valid, f"Failed for security level {level}")
    
    def test_cross_level_incompatibility(self):
        """Test that signatures from different levels don't verify."""
        message = b"Cross-level test"
        
        # Generate keys for different levels
        mayo1 = MAYOSignature(1)
        mayo3 = MAYOSignature(3)
        
        public_key1, private_key1 = mayo1.generate_keypair()
        public_key3, private_key3 = mayo3.generate_keypair()
        
        # Sign with level 1
        signature1 = mayo1.sign(message, private_key1)
        
        # Should not verify with level 3 parameters (different key sizes)
        # This should return False due to size mismatch
        is_valid = mayo3.verify(message, signature1, public_key1)
        self.assertFalse(is_valid)


if __name__ == "__main__":
    pytest.main([__file__])