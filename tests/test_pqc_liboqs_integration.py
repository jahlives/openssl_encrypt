#!/usr/bin/env python3
"""
Test script for the post-quantum cryptography liboqs integration module.

This script tests both the presence and absence of liboqs, ensuring that the
module gracefully handles the case when liboqs is not available.
"""

import os
import sys
import unittest
from unittest import mock

# Ensure openssl_encrypt is in the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import the module to test
from openssl_encrypt.modules.pqc_liboqs import (
    LIBOQS_AVAILABLE,
    PQAlgorithm,
    PQEncapsulator,
    PQSigner,
    check_liboqs_support,
)


class TestPQCLibOQSIntegration(unittest.TestCase):
    """Tests for the post-quantum cryptography liboqs integration module."""

    def test_check_liboqs_support(self):
        """Test the check_liboqs_support function."""
        available, version, algorithms = check_liboqs_support(quiet=True)

        # Even if liboqs is not installed, this function should run without errors
        self.assertIsInstance(available, bool)
        self.assertIsInstance(algorithms, list)

        if available:
            self.assertIsNotNone(version)
            self.assertTrue(len(algorithms) > 0)
        else:
            print("liboqs is not available, skipping detailed tests")

    def test_pq_algorithm_enum(self):
        """Test the PQAlgorithm enum."""
        # All algorithms should be present in the enum
        self.assertTrue(hasattr(PQAlgorithm, "ML_KEM_512"))
        self.assertTrue(hasattr(PQAlgorithm, "ML_DSA_44"))
        self.assertTrue(hasattr(PQAlgorithm, "HQC_128"))
        self.assertTrue(hasattr(PQAlgorithm, "SLH_DSA_SHA2_128F"))
        self.assertTrue(hasattr(PQAlgorithm, "FN_DSA_512"))

        # Check the values
        self.assertEqual(PQAlgorithm.ML_KEM_512.value, "ML-KEM-512")
        self.assertEqual(PQAlgorithm.ML_DSA_44.value, "ML-DSA-44")

    @unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
    def test_pq_encapsulator(self):
        """Test the PQEncapsulator class with liboqs."""
        available, _, algorithms = check_liboqs_support(quiet=True)
        if not available or len(algorithms) == 0:
            self.skipTest("liboqs not available or no algorithms supported")

        # Try to find a supported algorithm
        supported_algorithm = None
        for alg_name in ["ML_KEM_512", "Kyber512"]:
            if alg_name in algorithms:
                supported_algorithm = alg_name
                break

        if supported_algorithm is None:
            self.skipTest("No supported KEM algorithms found")

        # Test with the supported algorithm
        kem = PQEncapsulator(supported_algorithm, quiet=True)
        public_key, secret_key = kem.generate_keypair()

        self.assertIsInstance(public_key, bytes)
        self.assertIsInstance(secret_key, bytes)

        # Test encapsulation and decapsulation
        ciphertext, shared_secret = kem.encapsulate(public_key)
        decapsulated_secret = kem.decapsulate(ciphertext, secret_key)

        self.assertEqual(shared_secret, decapsulated_secret)

    @unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
    def test_pq_signer(self):
        """Test the PQSigner class with liboqs."""
        available, _, algorithms = check_liboqs_support(quiet=True)
        if not available or len(algorithms) == 0:
            self.skipTest("liboqs not available or no algorithms supported")

        # Try to find a supported algorithm
        supported_algorithm = None
        for alg_name in ["ML_DSA_44", "Dilithium2"]:
            if alg_name in algorithms:
                supported_algorithm = alg_name
                break

        if supported_algorithm is None:
            self.skipTest("No supported DSA algorithms found")

        # Test with the supported algorithm
        dsa = PQSigner(supported_algorithm, quiet=True)
        public_key, secret_key = dsa.generate_keypair()

        self.assertIsInstance(public_key, bytes)
        self.assertIsInstance(secret_key, bytes)

        # Test signing and verification
        message = b"Test message"
        signature = dsa.sign(message, secret_key)

        self.assertTrue(dsa.verify(message, signature, public_key))
        self.assertFalse(dsa.verify(b"Modified message", signature, public_key))

    @mock.patch("openssl_encrypt.modules.pqc_liboqs.LIBOQS_AVAILABLE", False)
    @mock.patch("openssl_encrypt.modules.pqc_liboqs.oqs", None)
    def test_liboqs_not_available(self):
        """Test behavior when liboqs is not available."""
        # check_liboqs_support should return False but not raise an exception
        available, version, algorithms = check_liboqs_support(quiet=True)
        self.assertFalse(available)
        self.assertIsNone(version)
        self.assertEqual(algorithms, [])

        # PQEncapsulator and PQSigner should raise ImportError
        with self.assertRaises(ImportError):
            PQEncapsulator("ML-KEM-512", quiet=True)

        with self.assertRaises(ImportError):
            PQSigner("ML-DSA-44", quiet=True)


if __name__ == "__main__":
    unittest.main()
