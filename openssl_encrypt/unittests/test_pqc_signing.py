#!/usr/bin/env python3
"""
Unit tests for the PQC Signing Module (pqc_signing.py)

Tests ML-DSA signature operations including:
- Keypair generation
- Message signing
- Signature verification
- Algorithm support (ML-DSA-44, ML-DSA-65, ML-DSA-87)
- Legacy name compatibility
- Fingerprint calculation
- Error handling
"""

import unittest

from openssl_encrypt.modules.pqc_signing import (
    LIBOQS_AVAILABLE,
    PQCSigner,
    calculate_fingerprint,
    sign_with_ml_dsa_65,
    verify_signature_with_timing,
    verify_with_ml_dsa_65,
)
from openssl_encrypt.modules.secure_memory import SecureBytes


@unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
class TestPQCSigner(unittest.TestCase):
    """Test cases for PQCSigner class"""

    def test_init_ml_dsa_65(self):
        """Test initialization with ML-DSA-65 (default)"""
        signer = PQCSigner("ML-DSA-65", quiet=True)
        self.assertEqual(signer.algorithm, "ML-DSA-65")
        self.assertEqual(signer.liboqs_name, "Dilithium3")

    def test_init_ml_dsa_44(self):
        """Test initialization with ML-DSA-44"""
        signer = PQCSigner("ML-DSA-44", quiet=True)
        self.assertEqual(signer.algorithm, "ML-DSA-44")
        self.assertEqual(signer.liboqs_name, "Dilithium2")

    def test_init_ml_dsa_87(self):
        """Test initialization with ML-DSA-87"""
        signer = PQCSigner("ML-DSA-87", quiet=True)
        self.assertEqual(signer.algorithm, "ML-DSA-87")
        self.assertEqual(signer.liboqs_name, "Dilithium5")

    def test_init_legacy_dilithium2(self):
        """Test initialization with legacy Dilithium2 name"""
        signer = PQCSigner("Dilithium2", quiet=True)
        self.assertEqual(signer.algorithm, "ML-DSA-44")

    def test_init_legacy_dilithium3(self):
        """Test initialization with legacy Dilithium3 name"""
        signer = PQCSigner("Dilithium3", quiet=True)
        self.assertEqual(signer.algorithm, "ML-DSA-65")

    def test_init_legacy_dilithium5(self):
        """Test initialization with legacy Dilithium5 name"""
        signer = PQCSigner("Dilithium5", quiet=True)
        self.assertEqual(signer.algorithm, "ML-DSA-87")

    def test_init_unsupported_algorithm(self):
        """Test initialization with unsupported algorithm"""
        with self.assertRaises(ValueError) as ctx:
            PQCSigner("INVALID-ALGO", quiet=True)
        self.assertIn("Unsupported signature algorithm", str(ctx.exception))

    def test_generate_keypair_ml_dsa_65(self):
        """Test keypair generation for ML-DSA-65"""
        signer = PQCSigner("ML-DSA-65", quiet=True)
        public_key, private_key = signer.generate_keypair()

        # Check types
        self.assertIsInstance(public_key, bytes)
        self.assertIsInstance(private_key, bytes)

        # Check approximate sizes (ML-DSA-65)
        self.assertGreater(len(public_key), 1900)  # ~1952 bytes
        self.assertLess(len(public_key), 2000)
        self.assertGreater(len(private_key), 3900)  # ~4032 bytes
        self.assertLess(len(private_key), 4100)

    def test_generate_keypair_ml_dsa_44(self):
        """Test keypair generation for ML-DSA-44"""
        signer = PQCSigner("ML-DSA-44", quiet=True)
        public_key, private_key = signer.generate_keypair()

        # Check approximate sizes (ML-DSA-44)
        self.assertGreater(len(public_key), 1250)  # ~1312 bytes
        self.assertLess(len(public_key), 1400)
        self.assertGreater(len(private_key), 2500)  # ~2560 bytes
        self.assertLess(len(private_key), 2650)

    def test_sign_and_verify_roundtrip(self):
        """Test complete sign and verify roundtrip"""
        signer = PQCSigner("ML-DSA-65", quiet=True)
        public_key, private_key = signer.generate_keypair()

        # Test message
        message = b"Hello, Post-Quantum World!"

        # Sign with secure memory
        with SecureBytes(private_key) as secure_key:
            signature = signer.sign(message, bytes(secure_key))

        # Check signature
        self.assertIsInstance(signature, bytes)
        self.assertGreater(len(signature), 3200)  # ~3309 bytes for ML-DSA-65

        # Verify signature
        is_valid = signer.verify(message, signature, public_key)
        self.assertTrue(is_valid)

    def test_verify_wrong_message(self):
        """Test verification with wrong message"""
        signer = PQCSigner("ML-DSA-65", quiet=True)
        public_key, private_key = signer.generate_keypair()

        message = b"Original message"
        wrong_message = b"Wrong message"

        # Sign original message
        with SecureBytes(private_key) as secure_key:
            signature = signer.sign(message, bytes(secure_key))

        # Verify with wrong message should fail
        is_valid = signer.verify(wrong_message, signature, public_key)
        self.assertFalse(is_valid)

    def test_verify_corrupted_signature(self):
        """Test verification with corrupted signature"""
        signer = PQCSigner("ML-DSA-65", quiet=True)
        public_key, private_key = signer.generate_keypair()

        message = b"Test message"

        # Sign message
        with SecureBytes(private_key) as secure_key:
            signature = signer.sign(message, bytes(secure_key))

        # Corrupt signature (flip some bits)
        corrupted_signature = bytearray(signature)
        corrupted_signature[100] ^= 0xFF
        corrupted_signature = bytes(corrupted_signature)

        # Verification should fail
        is_valid = signer.verify(message, corrupted_signature, public_key)
        self.assertFalse(is_valid)

    def test_verify_wrong_public_key(self):
        """Test verification with wrong public key"""
        signer = PQCSigner("ML-DSA-65", quiet=True)
        public_key1, private_key1 = signer.generate_keypair()
        public_key2, _ = signer.generate_keypair()

        message = b"Test message"

        # Sign with key1
        with SecureBytes(private_key1) as secure_key:
            signature = signer.sign(message, bytes(secure_key))

        # Verify with key2 should fail
        is_valid = signer.verify(message, signature, public_key2)
        self.assertFalse(is_valid)

    def test_sign_invalid_types(self):
        """Test signing with invalid types"""
        signer = PQCSigner("ML-DSA-65", quiet=True)
        _, private_key = signer.generate_keypair()

        # Test with non-bytes message
        with self.assertRaises(TypeError):
            signer.sign("not bytes", private_key)

        # Test with non-bytes private key
        with self.assertRaises(TypeError):
            signer.sign(b"message", "not bytes")

    def test_verify_invalid_types(self):
        """Test verification with invalid types"""
        signer = PQCSigner("ML-DSA-65", quiet=True)
        public_key, _ = signer.generate_keypair()

        # Test with non-bytes message
        with self.assertRaises(TypeError):
            signer.verify("not bytes", b"signature", public_key)

        # Test with non-bytes signature
        with self.assertRaises(TypeError):
            signer.verify(b"message", "not bytes", public_key)

        # Test with non-bytes public key
        with self.assertRaises(TypeError):
            signer.verify(b"message", b"signature", "not bytes")

    def test_get_signature_size(self):
        """Test getting signature size for different algorithms"""
        signer44 = PQCSigner("ML-DSA-44", quiet=True)
        signer65 = PQCSigner("ML-DSA-65", quiet=True)
        signer87 = PQCSigner("ML-DSA-87", quiet=True)

        size44 = signer44.get_signature_size()
        size65 = signer65.get_signature_size()
        size87 = signer87.get_signature_size()

        # ML-DSA-44 < ML-DSA-65 < ML-DSA-87
        self.assertLess(size44, size65)
        self.assertLess(size65, size87)

        # Approximate expected sizes
        self.assertGreater(size44, 2300)  # ~2420 bytes
        self.assertGreater(size65, 3200)  # ~3309 bytes
        self.assertGreater(size87, 4500)  # ~4627 bytes

    def test_get_public_key_size(self):
        """Test getting public key size"""
        signer = PQCSigner("ML-DSA-65", quiet=True)
        size = signer.get_public_key_size()
        self.assertGreater(size, 1900)  # ~1952 bytes

    def test_get_private_key_size(self):
        """Test getting private key size"""
        signer = PQCSigner("ML-DSA-65", quiet=True)
        size = signer.get_private_key_size()
        self.assertGreater(size, 3900)  # ~4032 bytes

    def test_multiple_signatures_same_key(self):
        """Test creating multiple signatures with same key"""
        signer = PQCSigner("ML-DSA-65", quiet=True)
        public_key, private_key = signer.generate_keypair()

        message1 = b"Message 1"
        message2 = b"Message 2"
        message3 = b"Message 3"

        with SecureBytes(private_key) as secure_key:
            sig1 = signer.sign(message1, bytes(secure_key))
            sig2 = signer.sign(message2, bytes(secure_key))
            sig3 = signer.sign(message3, bytes(secure_key))

        # All signatures should verify correctly
        self.assertTrue(signer.verify(message1, sig1, public_key))
        self.assertTrue(signer.verify(message2, sig2, public_key))
        self.assertTrue(signer.verify(message3, sig3, public_key))

        # Cross verification should fail
        self.assertFalse(signer.verify(message1, sig2, public_key))
        self.assertFalse(signer.verify(message2, sig3, public_key))


class TestFingerprintCalculation(unittest.TestCase):
    """Test cases for fingerprint calculation"""

    def test_calculate_fingerprint_sha256(self):
        """Test fingerprint calculation with SHA256"""
        public_key = b"test public key data"
        fingerprint = calculate_fingerprint(public_key, "SHA256")

        # Should be hex string with colons
        self.assertIn(":", fingerprint)
        self.assertEqual(len(fingerprint), 95)  # 32 bytes * 2 hex + 31 colons

    def test_calculate_fingerprint_sha512(self):
        """Test fingerprint calculation with SHA512"""
        public_key = b"test public key data"
        fingerprint = calculate_fingerprint(public_key, "SHA512")

        # Should be longer than SHA256
        self.assertIn(":", fingerprint)
        self.assertGreater(len(fingerprint), 100)

    def test_calculate_fingerprint_blake2b(self):
        """Test fingerprint calculation with BLAKE2b"""
        public_key = b"test public key data"
        fingerprint = calculate_fingerprint(public_key, "BLAKE2b")

        self.assertIn(":", fingerprint)
        self.assertEqual(len(fingerprint), 95)  # 32 bytes with colons

    def test_calculate_fingerprint_unsupported_algo(self):
        """Test fingerprint calculation with unsupported algorithm"""
        public_key = b"test public key data"

        with self.assertRaises(ValueError) as ctx:
            calculate_fingerprint(public_key, "MD5")
        self.assertIn("Unsupported hash algorithm", str(ctx.exception))

    def test_fingerprint_deterministic(self):
        """Test that fingerprint is deterministic"""
        public_key = b"test public key data"

        fp1 = calculate_fingerprint(public_key, "SHA256")
        fp2 = calculate_fingerprint(public_key, "SHA256")

        self.assertEqual(fp1, fp2)

    def test_fingerprint_different_keys(self):
        """Test that different keys produce different fingerprints"""
        key1 = b"key1"
        key2 = b"key2"

        fp1 = calculate_fingerprint(key1, "SHA256")
        fp2 = calculate_fingerprint(key2, "SHA256")

        self.assertNotEqual(fp1, fp2)


@unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
class TestSignatureWithTiming(unittest.TestCase):
    """Test cases for signature verification with timing"""

    def test_verify_with_timing_valid(self):
        """Test timed verification with valid signature"""
        signer = PQCSigner("ML-DSA-65", quiet=True)
        public_key, private_key = signer.generate_keypair()

        message = b"Test message for timing"

        with SecureBytes(private_key) as secure_key:
            signature = signer.sign(message, bytes(secure_key))

        is_valid, timing = verify_signature_with_timing(message, signature, public_key, "ML-DSA-65")

        self.assertTrue(is_valid)
        self.assertGreater(timing, 0)
        self.assertLess(timing, 0.1)  # Should be fast (< 100ms)

    def test_verify_with_timing_invalid(self):
        """Test timed verification with invalid signature"""
        signer = PQCSigner("ML-DSA-65", quiet=True)
        public_key, private_key = signer.generate_keypair()

        message = b"Test message"
        wrong_message = b"Wrong message"

        with SecureBytes(private_key) as secure_key:
            signature = signer.sign(message, bytes(secure_key))

        is_valid, timing = verify_signature_with_timing(
            wrong_message, signature, public_key, "ML-DSA-65"
        )

        self.assertFalse(is_valid)
        self.assertGreater(timing, 0)
        self.assertLess(timing, 0.1)  # Should still be fast


@unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
class TestConvenienceFunctions(unittest.TestCase):
    """Test cases for convenience functions"""

    def test_sign_with_ml_dsa_65(self):
        """Test convenience function for signing with ML-DSA-65"""
        signer = PQCSigner("ML-DSA-65", quiet=True)
        public_key, private_key = signer.generate_keypair()

        message = b"Test message"

        signature = sign_with_ml_dsa_65(message, private_key)

        self.assertIsInstance(signature, bytes)
        self.assertGreater(len(signature), 3000)

        # Verify with main class
        is_valid = signer.verify(message, signature, public_key)
        self.assertTrue(is_valid)

    def test_verify_with_ml_dsa_65(self):
        """Test convenience function for verifying with ML-DSA-65"""
        signer = PQCSigner("ML-DSA-65", quiet=True)
        public_key, private_key = signer.generate_keypair()

        message = b"Test message"

        # Sign with main class
        with SecureBytes(private_key) as secure_key:
            signature = signer.sign(message, bytes(secure_key))

        # Verify with convenience function
        is_valid = verify_with_ml_dsa_65(message, signature, public_key)
        self.assertTrue(is_valid)


if __name__ == "__main__":
    unittest.main()
