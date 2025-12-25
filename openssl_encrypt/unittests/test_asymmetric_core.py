#!/usr/bin/env python3
"""
Unit tests for the Asymmetric Core Module (asymmetric_core.py)

Tests PasswordWrapper and MetadataCanonicalizer including:
- KEM encapsulation/decapsulation
- Password wrapping/unwrapping
- Metadata canonicalization for signatures
- Error handling
"""

import json
import secrets
import unittest

from openssl_encrypt.modules.asymmetric_core import (
    MetadataCanonicalizer,
    PasswordWrapper,
    PasswordWrapperError,
    unwrap_password_for_recipient,
    wrap_password_for_recipient,
)
from openssl_encrypt.modules.pqc import PQCipher
from openssl_encrypt.modules.pqc_signing import LIBOQS_AVAILABLE


@unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
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


@unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
class TestConvenienceFunctions(unittest.TestCase):
    """Test cases for convenience functions"""

    def setUp(self):
        """Set up test fixtures"""
        cipher = PQCipher("ML-KEM-768")
        self.public_key, self.private_key = cipher.generate_keypair()

    def test_wrap_password_for_recipient(self):
        """Test convenience function for wrapping password"""
        password = secrets.token_bytes(32)

        encapsulated_key, encrypted_password = wrap_password_for_recipient(
            password, self.public_key, "ML-KEM-768"
        )

        self.assertIsInstance(encapsulated_key, bytes)
        self.assertIsInstance(encrypted_password, bytes)
        self.assertGreater(len(encapsulated_key), 1000)
        self.assertGreater(len(encrypted_password), 40)

    def test_unwrap_password_for_recipient(self):
        """Test convenience function for unwrapping password"""
        password = secrets.token_bytes(32)

        encapsulated_key, encrypted_password = wrap_password_for_recipient(
            password, self.public_key
        )

        password_recovered = unwrap_password_for_recipient(
            encapsulated_key, encrypted_password, self.private_key
        )

        self.assertEqual(password, password_recovered)

    def test_convenience_roundtrip(self):
        """Test full roundtrip with convenience functions"""
        password = b"test_password_32_bytes_long!!!!!"

        # Sender side
        encapsulated_key, encrypted_password = wrap_password_for_recipient(
            password, self.public_key, "ML-KEM-768"
        )

        # Recipient side
        password_recovered = unwrap_password_for_recipient(
            encapsulated_key,
            encrypted_password,
            self.private_key,
            "ML-KEM-768",
        )

        self.assertEqual(password, password_recovered)


class TestMetadataCanonicalizer(unittest.TestCase):
    """Test cases for MetadataCanonicalizer class"""

    def test_canonicalize_simple_metadata(self):
        """Test canonicalization of simple metadata"""
        metadata = {"format_version": 7, "mode": "asymmetric"}

        canonical = MetadataCanonicalizer.canonicalize(metadata)

        self.assertIsInstance(canonical, bytes)
        self.assertGreater(len(canonical), 0)

        # Should be valid JSON
        json.loads(canonical.decode("utf-8"))

    def test_canonicalize_removes_signature(self):
        """Test that signature field is removed"""
        metadata = {
            "format_version": 7,
            "asymmetric": {"sender": {"key_id": "abc123"}},
            "signature": {
                "algorithm": "ML-DSA-65",
                "value": "should_be_removed",
            },
        }

        canonical = MetadataCanonicalizer.canonicalize(metadata)
        canonical_str = canonical.decode("utf-8")

        # Signature should not appear in output
        self.assertNotIn('"signature"', canonical_str)
        self.assertNotIn("should_be_removed", canonical_str)

    def test_canonicalize_nested_signature_removal(self):
        """Test removal of signature in nested structures"""
        metadata = {"top_level": {"nested": {"signature": "should_be_removed"}}}

        canonical = MetadataCanonicalizer.canonicalize(metadata)
        canonical_str = canonical.decode("utf-8")

        # No signature fields should appear anywhere
        self.assertNotIn('"signature"', canonical_str)

    def test_canonicalize_sorted_keys(self):
        """Test that keys are sorted"""
        metadata = {"zebra": "last", "apple": "first", "middle": "second"}

        canonical = MetadataCanonicalizer.canonicalize(metadata)
        canonical_str = canonical.decode("utf-8")

        # Check that keys appear in sorted order
        apple_pos = canonical_str.find('"apple"')
        middle_pos = canonical_str.find('"middle"')
        zebra_pos = canonical_str.find('"zebra"')

        self.assertLess(apple_pos, middle_pos)
        self.assertLess(middle_pos, zebra_pos)

    def test_canonicalize_no_whitespace(self):
        """Test that output has no unnecessary whitespace"""
        metadata = {"key": "value", "number": 42, "nested": {"inner": "data"}}

        canonical = MetadataCanonicalizer.canonicalize(metadata)
        canonical_str = canonical.decode("utf-8")

        # Should not contain spaces after colons or commas
        # (except inside string values)
        self.assertNotIn(": ", canonical_str)
        self.assertNotIn(", ", canonical_str)

    def test_canonicalize_deterministic(self):
        """Test that canonicalization is deterministic"""
        metadata = {
            "format_version": 7,
            "asymmetric": {
                "recipients": [
                    {"key_id": "user1", "data": "abc"},
                    {"key_id": "user2", "data": "xyz"},
                ]
            },
            "signature": {"value": "removed"},
        }

        canonical1 = MetadataCanonicalizer.canonicalize(metadata)
        canonical2 = MetadataCanonicalizer.canonicalize(metadata)

        self.assertEqual(canonical1, canonical2)

    def test_canonicalize_preserves_values(self):
        """Test that values are preserved correctly"""
        metadata = {
            "string": "hello",
            "number": 42,
            "float": 3.14,
            "bool": True,
            "null": None,
            "list": [1, 2, 3],
            "nested": {"key": "value"},
        }

        canonical = MetadataCanonicalizer.canonicalize(metadata)
        reconstructed = json.loads(canonical.decode("utf-8"))

        # All values should be preserved
        self.assertEqual(reconstructed["string"], "hello")
        self.assertEqual(reconstructed["number"], 42)
        self.assertAlmostEqual(reconstructed["float"], 3.14)
        self.assertEqual(reconstructed["bool"], True)
        self.assertIsNone(reconstructed["null"])
        self.assertEqual(reconstructed["list"], [1, 2, 3])
        self.assertEqual(reconstructed["nested"]["key"], "value")

    def test_canonicalize_utf8_encoding(self):
        """Test UTF-8 encoding of non-ASCII characters"""
        metadata = {
            "german": "Schön",  # ö
            "japanese": "日本語",  # Japanese
            "emoji": "😀",  # Grinning face emoji
            "russian": "Привет",  # Russian
        }

        canonical = MetadataCanonicalizer.canonicalize(metadata)

        # Should be valid UTF-8
        canonical_str = canonical.decode("utf-8")
        reconstructed = json.loads(canonical_str)

        self.assertEqual(reconstructed["german"], "Schön")
        self.assertEqual(reconstructed["japanese"], "日本語")
        self.assertEqual(reconstructed["emoji"], "😀")
        self.assertEqual(reconstructed["russian"], "Привет")

    def test_canonicalize_invalid_type(self):
        """Test canonicalization with invalid type"""
        with self.assertRaises(ValueError):
            MetadataCanonicalizer.canonicalize("not a dict")

        with self.assertRaises(ValueError):
            MetadataCanonicalizer.canonicalize([1, 2, 3])

    def test_verify_determinism_helper(self):
        """Test the verify_determinism helper method"""
        metadata = {"test": "data", "signature": "removed"}

        is_deterministic = MetadataCanonicalizer.verify_determinism(metadata)
        self.assertTrue(is_deterministic)

    def test_canonicalize_original_not_modified(self):
        """Test that original metadata is not modified"""
        original = {"key": "value", "signature": {"value": "test"}}

        # Make a copy to compare later
        original_copy = json.loads(json.dumps(original))

        # Canonicalize
        MetadataCanonicalizer.canonicalize(original)

        # Original should be unchanged
        self.assertEqual(original, original_copy)
        self.assertIn("signature", original)


if __name__ == "__main__":
    unittest.main()
