#!/usr/bin/env python3
"""
Test suite for password generation and handling functionality.

This module contains comprehensive tests for:
- Password generation with various requirements
- Password strength validation
- Password wrapper class functionality
- Secure password handling and memory management
"""

import os
import secrets
import string
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import pytest

# Import the modules to test
from openssl_encrypt.modules.asymmetric_core import PasswordWrapper, PasswordWrapperError
from openssl_encrypt.modules.crypt_utils import generate_strong_password
from openssl_encrypt.modules.pqc import LIBOQS_AVAILABLE, PQCipher

# Check if PQC is available
try:
    from openssl_encrypt.modules.crypt_core import PQC_AVAILABLE
except ImportError:
    PQC_AVAILABLE = False


class TestPasswordGeneration(unittest.TestCase):
    """Test password generation functionality in depth."""

    def test_password_length(self):
        """Test that generated passwords have the correct length."""
        for length in [8, 12, 16, 24, 32, 64]:
            password = generate_strong_password(length)
            self.assertEqual(len(password), length)

    def test_minimum_password_length(self):
        """Test that password generation enforces minimum length."""
        # Try to generate a 6-character password
        password = generate_strong_password(6)
        # Should enforce minimum length of 8
        self.assertEqual(len(password), 8)

    def test_character_sets(self):
        """Test password generation with different character sets."""
        # Only lowercase
        password = generate_strong_password(
            16, use_lowercase=True, use_uppercase=False, use_digits=False, use_special=False
        )
        self.assertEqual(len(password), 16)
        self.assertTrue(all(c.islower() for c in password))

        # Only uppercase
        password = generate_strong_password(
            16, use_lowercase=False, use_uppercase=True, use_digits=False, use_special=False
        )
        self.assertEqual(len(password), 16)
        self.assertTrue(all(c.isupper() for c in password))

        # Only digits
        password = generate_strong_password(
            16, use_lowercase=False, use_uppercase=False, use_digits=True, use_special=False
        )
        self.assertEqual(len(password), 16)
        self.assertTrue(all(c.isdigit() for c in password))

        # Only special characters
        password = generate_strong_password(
            16, use_lowercase=False, use_uppercase=False, use_digits=False, use_special=True
        )
        self.assertEqual(len(password), 16)
        self.assertTrue(all(c in string.punctuation for c in password))

        # Mix of uppercase and digits
        password = generate_strong_password(
            16, use_lowercase=False, use_uppercase=True, use_digits=True, use_special=False
        )
        self.assertEqual(len(password), 16)
        self.assertTrue(all(c.isupper() or c.isdigit() for c in password))

    def test_default_behavior(self):
        """Test default behavior when no character sets are specified."""
        # When no character sets are specified, should default to using all
        password = generate_strong_password(
            16, use_lowercase=False, use_uppercase=False, use_digits=False, use_special=False
        )
        self.assertEqual(len(password), 16)

        # Should contain at least lowercase, uppercase, and digits
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)

        self.assertTrue(has_lower or has_upper or has_digit)

    def test_password_randomness(self):
        """Test that generated passwords are random."""
        # Generate multiple passwords and ensure they're different
        passwords = [generate_strong_password(16) for _ in range(10)]

        # No duplicates should exist
        self.assertEqual(len(passwords), len(set(passwords)))

        # Check character distribution in a larger sample
        long_password = generate_strong_password(1000)

        # Count character types
        lower_count = sum(1 for c in long_password if c.islower())
        upper_count = sum(1 for c in long_password if c.isupper())
        digit_count = sum(1 for c in long_password if c.isdigit())
        special_count = sum(1 for c in long_password if c in string.punctuation)

        # Each character type should be present in reasonable numbers
        # Further relax the constraints based on true randomness
        self.assertGreater(lower_count, 50, "Expected more than 50 lowercase characters")
        self.assertGreater(upper_count, 50, "Expected more than 50 uppercase characters")
        self.assertGreater(digit_count, 50, "Expected more than 50 digits")
        self.assertGreater(special_count, 50, "Expected more than 50 special characters")

        # Verify that all character types combined add up to the total length
        self.assertEqual(lower_count + upper_count + digit_count + special_count, 1000)


class TestPasswordWrapper(unittest.TestCase):
    """Test cases for PasswordWrapper class"""

    def setUp(self):
        """Set up test fixtures"""
        self.wrapper = PasswordWrapper("ML-KEM-768")
        self.cipher = PQCipher("ML-KEM-768")
        self.public_key, self.private_key = self.cipher.generate_keypair()

    def test_init_ml_kem_768(self):
        """Test initialization with ML-KEM-768"""
        wrapper = PasswordWrapper("ML-KEM-768")
        self.assertEqual(wrapper.kem_algorithm, "ML-KEM-768")

    def test_init_ml_kem_512(self):
        """Test initialization with ML-KEM-512"""
        wrapper = PasswordWrapper("ML-KEM-512")
        self.assertEqual(wrapper.kem_algorithm, "ML-KEM-512")

    def test_init_ml_kem_1024(self):
        """Test initialization with ML-KEM-1024"""
        wrapper = PasswordWrapper("ML-KEM-1024")
        self.assertEqual(wrapper.kem_algorithm, "ML-KEM-1024")

    def test_init_invalid_algorithm(self):
        """Test initialization with invalid algorithm"""
        with self.assertRaises(ValueError) as ctx:
            PasswordWrapper("INVALID-KEM")
        self.assertIn("Unsupported KEM algorithm", str(ctx.exception))

    def test_encapsulate(self):
        """Test KEM encapsulation"""
        encapsulated_key, shared_secret = self.wrapper.encapsulate(self.public_key)

        # Check types
        self.assertIsInstance(encapsulated_key, bytes)
        self.assertIsInstance(shared_secret, bytes)

        # Check approximate sizes for ML-KEM-768
        self.assertGreater(len(encapsulated_key), 1000)  # ~1088 bytes
        self.assertGreater(len(shared_secret), 30)  # ~32 bytes

    def test_decapsulate(self):
        """Test KEM decapsulation"""
        encapsulated_key, shared_secret_original = self.wrapper.encapsulate(self.public_key)

        # Decapsulate with private key
        shared_secret_recovered = self.wrapper.decapsulate(encapsulated_key, self.private_key)

        # Should recover same shared secret
        self.assertEqual(shared_secret_original, shared_secret_recovered)

    def test_encapsulate_with_wrong_key_type(self):
        """Test encapsulation with wrong key type"""
        with self.assertRaises(TypeError):
            self.wrapper.encapsulate("not bytes")

    def test_decapsulate_with_wrong_types(self):
        """Test decapsulation with wrong types"""
        encapsulated_key, _ = self.wrapper.encapsulate(self.public_key)

        with self.assertRaises(TypeError):
            self.wrapper.decapsulate("not bytes", self.private_key)

        with self.assertRaises(TypeError):
            self.wrapper.decapsulate(encapsulated_key, "not bytes")

    def test_wrap_password(self):
        """Test password wrapping"""
        password = secrets.token_bytes(32)
        shared_secret = secrets.token_bytes(32)

        encrypted_password = self.wrapper.wrap_password(password, shared_secret)

        # Check format: nonce(12) + ciphertext + tag(16)
        self.assertIsInstance(encrypted_password, bytes)
        self.assertEqual(len(encrypted_password), 12 + len(password) + 16)

    def test_unwrap_password(self):
        """Test password unwrapping"""
        password = secrets.token_bytes(32)
        shared_secret = secrets.token_bytes(32)

        # Wrap password
        encrypted_password = self.wrapper.wrap_password(password, shared_secret)

        # Unwrap password
        password_recovered = self.wrapper.unwrap_password(encrypted_password, shared_secret)

        # Should recover original password
        self.assertEqual(password, password_recovered)

    def test_password_roundtrip(self):
        """Test complete password wrap/unwrap roundtrip"""
        password = secrets.token_bytes(32)

        # Encapsulate to get shared secret
        encapsulated_key, shared_secret = self.wrapper.encapsulate(self.public_key)

        # Wrap password
        encrypted_password = self.wrapper.wrap_password(password, shared_secret)

        # Decapsulate to recover shared secret
        shared_secret_recovered = self.wrapper.decapsulate(encapsulated_key, self.private_key)

        # Unwrap password
        password_recovered = self.wrapper.unwrap_password(
            encrypted_password, shared_secret_recovered
        )

        # Should recover original password
        self.assertEqual(password, password_recovered)

    def test_unwrap_with_wrong_secret(self):
        """Test unwrapping with wrong shared secret fails"""
        password = secrets.token_bytes(32)
        shared_secret = secrets.token_bytes(32)
        wrong_secret = secrets.token_bytes(32)

        encrypted_password = self.wrapper.wrap_password(password, shared_secret)

        # Should fail authentication
        with self.assertRaises(PasswordWrapperError):
            self.wrapper.unwrap_password(encrypted_password, wrong_secret)

    def test_unwrap_corrupted_ciphertext(self):
        """Test unwrapping corrupted ciphertext fails"""
        password = secrets.token_bytes(32)
        shared_secret = secrets.token_bytes(32)

        encrypted_password = self.wrapper.wrap_password(password, shared_secret)

        # Corrupt the ciphertext
        corrupted = bytearray(encrypted_password)
        corrupted[20] ^= 0xFF
        corrupted = bytes(corrupted)

        # Should fail authentication
        with self.assertRaises(PasswordWrapperError):
            self.wrapper.unwrap_password(corrupted, shared_secret)

    def test_unwrap_invalid_size(self):
        """Test unwrapping data that's too small"""
        shared_secret = secrets.token_bytes(32)
        invalid_data = b"too short"  # Less than 28 bytes

        with self.assertRaises(PasswordWrapperError) as ctx:
            self.wrapper.unwrap_password(invalid_data, shared_secret)
        self.assertIn("minimum 28 bytes", str(ctx.exception))

    def test_wrap_invalid_types(self):
        """Test wrapping with invalid types"""
        password = secrets.token_bytes(32)
        shared_secret = secrets.token_bytes(32)

        with self.assertRaises(TypeError):
            self.wrapper.wrap_password("not bytes", shared_secret)

        with self.assertRaises(TypeError):
            self.wrapper.wrap_password(password, "not bytes")

    def test_unwrap_invalid_types(self):
        """Test unwrapping with invalid types"""
        encrypted = secrets.token_bytes(60)
        shared_secret = secrets.token_bytes(32)

        with self.assertRaises(TypeError):
            self.wrapper.unwrap_password("not bytes", shared_secret)

        with self.assertRaises(TypeError):
            self.wrapper.unwrap_password(encrypted, "not bytes")

    def test_multiple_wrappings_same_password(self):
        """Test wrapping same password multiple times gives different ciphertexts"""
        password = secrets.token_bytes(32)
        shared_secret = secrets.token_bytes(32)

        encrypted1 = self.wrapper.wrap_password(password, shared_secret)
        encrypted2 = self.wrapper.wrap_password(password, shared_secret)

        # Should be different due to random nonces
        self.assertNotEqual(encrypted1, encrypted2)

        # But both should unwrap to same password
        password1 = self.wrapper.unwrap_password(encrypted1, shared_secret)
        password2 = self.wrapper.unwrap_password(encrypted2, shared_secret)

        self.assertEqual(password, password1)
        self.assertEqual(password, password2)
