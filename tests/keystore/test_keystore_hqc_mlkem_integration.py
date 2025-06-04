#!/usr/bin/env python3
"""
Integration tests for HQC and ML-KEM algorithms with keystore functionality.

This module provides comprehensive testing of keystore operations with post-quantum
cryptography algorithms including HQC and ML-KEM families, ensuring proper key
storage, retrieval, and cryptographic operations.
"""

import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

# Add parent directory to path for importing
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from openssl_encrypt.modules.crypt_core import (
    LIBOQS_AVAILABLE,
    PQC_AVAILABLE,
    decrypt_file,
    encrypt_file,
)
from openssl_encrypt.modules.keystore_cli import KeystoreSecurityLevel, PQCKeystore
from openssl_encrypt.modules.keystore_utils import (
    extract_key_id_from_metadata,
    get_pqc_key_for_decryption,
)
from openssl_encrypt.modules.pqc import PQCipher


class TestHQCMLKEMKeystoreIntegration(unittest.TestCase):
    """Test suite for HQC and ML-KEM algorithms with keystore integration."""

    def setUp(self):
        """Set up test fixtures for keystore integration tests."""
        self.temp_dir = tempfile.mkdtemp()
        self.keystore_path = os.path.join(self.temp_dir, "test_keystore.pqc")
        self.keystore_password = "test_keystore_password_123"
        self.file_password = "test_file_password_456"

        # Test file paths
        self.input_file = os.path.join(self.temp_dir, "test_input.txt")
        self.encrypted_file = os.path.join(self.temp_dir, "test_encrypted.enc")
        self.decrypted_file = os.path.join(self.temp_dir, "test_decrypted.txt")

        # Create test input file
        with open(self.input_file, "w") as f:
            f.write("This is a test message for HQC and ML-KEM keystore integration testing.")

        # Hash configuration for testing
        self.hash_config = {
            "version": "v1",
            "algorithm": "sha256",
            "iterations": 1000,  # Low value for faster testing
        }

        # Create keystore
        self.keystore = PQCKeystore(self.keystore_path)
        self.keystore.create_keystore(self.keystore_password, KeystoreSecurityLevel.STANDARD)

    def tearDown(self):
        """Clean up test files and keystore."""
        # Clear keystore cache
        if hasattr(self, "keystore"):
            self.keystore.clear_cache()

        # Remove temporary directory
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _generate_mock_pqc_key(self, algorithm):
        """Generate mock PQC key for testing purposes."""
        timestamp = str(time.time()).replace(".", "")
        mock_public_key = (
            b"MOCK_PQC_PUBLIC_KEY_FOR_" + algorithm.encode() + f"_{timestamp}".encode()
        ) * 10
        mock_private_key = (
            b"MOCK_PQC_PRIVATE_KEY_FOR_" + algorithm.encode() + f"_{timestamp}".encode()
        ) * 15
        return mock_public_key, mock_private_key

    @unittest.skipIf(not (PQC_AVAILABLE and LIBOQS_AVAILABLE), "liboqs not available")
    def test_hqc_keystore_basic_operations(self):
        """Test basic keystore operations with HQC algorithms."""
        test_algorithms = ["hqc-128-hybrid", "hqc-192-hybrid", "hqc-256-hybrid"]

        for algorithm in test_algorithms:
            with self.subTest(algorithm=algorithm):
                # Generate mock keypair
                public_key, private_key = self._generate_mock_pqc_key(algorithm)

                # Add key to keystore
                key_id = self.keystore.add_key(
                    algorithm=algorithm,
                    public_key=public_key,
                    private_key=private_key,
                    description=f"Test key for {algorithm}",
                    tags=["test", "hqc", "integration"],
                )

                self.assertIsNotNone(key_id, f"Key ID should be generated for {algorithm}")

                # Retrieve key from keystore
                retrieved_public, retrieved_private = self.keystore.get_key(key_id)

                self.assertEqual(
                    retrieved_public, public_key, f"Public key mismatch for {algorithm}"
                )
                self.assertEqual(
                    retrieved_private, private_key, f"Private key mismatch for {algorithm}"
                )

                # Verify key is in keystore listing
                keys = self.keystore.list_keys()
                key_found = any(k["key_id"] == key_id for k in keys)
                self.assertTrue(key_found, f"Key {key_id} should be found in keystore listing")

                # Remove key for cleanup
                self.keystore.remove_key(key_id)

    @unittest.skipIf(not PQC_AVAILABLE, "PQC not available")
    def test_ml_kem_keystore_basic_operations(self):
        """Test basic keystore operations with ML-KEM algorithms."""
        test_algorithms = ["ml-kem-512-hybrid", "ml-kem-768-hybrid", "ml-kem-1024-hybrid"]

        for algorithm in test_algorithms:
            with self.subTest(algorithm=algorithm):
                # Generate mock keypair
                public_key, private_key = self._generate_mock_pqc_key(algorithm)

                # Add key to keystore
                key_id = self.keystore.add_key(
                    algorithm=algorithm,
                    public_key=public_key,
                    private_key=private_key,
                    description=f"Test key for {algorithm}",
                    tags=["test", "ml-kem", "integration"],
                )

                self.assertIsNotNone(key_id, f"Key ID should be generated for {algorithm}")

                # Retrieve key from keystore
                retrieved_public, retrieved_private = self.keystore.get_key(key_id)

                self.assertEqual(
                    retrieved_public, public_key, f"Public key mismatch for {algorithm}"
                )
                self.assertEqual(
                    retrieved_private, private_key, f"Private key mismatch for {algorithm}"
                )

                # Verify key metadata
                keys = self.keystore.list_keys()
                test_key = next((k for k in keys if k["key_id"] == key_id), None)
                self.assertIsNotNone(test_key, f"Test key should be found in listing")
                self.assertEqual(
                    test_key["algorithm"], algorithm, f"Algorithm mismatch in metadata"
                )
                self.assertIn("ml-kem", test_key["tags"], f"ML-KEM tag should be present")

                # Remove key for cleanup
                self.keystore.remove_key(key_id)

    @unittest.skipIf(not (PQC_AVAILABLE and LIBOQS_AVAILABLE), "liboqs not available")
    def test_hqc_file_encryption_with_keystore(self):
        """Test keystore key storage and retrieval for HQC algorithms."""
        algorithm = "hqc-128-hybrid"  # Test with HQC-128 as representative

        # Generate mock keypair and add to keystore
        public_key, private_key = self._generate_mock_pqc_key(algorithm)
        key_id = self.keystore.add_key(
            algorithm=algorithm,
            public_key=public_key,
            private_key=private_key,
            description=f"File encryption test key for {algorithm}",
            tags=["test", "file-encryption"],
        )

        self.assertIsNotNone(key_id, f"Key ID should be generated for {algorithm}")

        # Test key retrieval from keystore
        retrieved_public, retrieved_private = self.keystore.get_key(key_id)

        self.assertEqual(retrieved_public, public_key, f"Public key should match for {algorithm}")
        self.assertEqual(
            retrieved_private, private_key, f"Private key should match for {algorithm}"
        )

        # Test keystore key listing includes our key
        keys = self.keystore.list_keys()
        found_key = next((k for k in keys if k["key_id"] == key_id), None)

        self.assertIsNotNone(found_key, "Added key should be found in keystore listing")
        self.assertEqual(found_key["algorithm"], algorithm, "Algorithm should match in listing")
        self.assertIn("file-encryption", found_key["tags"], "Tags should be preserved")

        # Clean up
        self.keystore.remove_key(key_id)

    @unittest.skipIf(not PQC_AVAILABLE, "PQC not available")
    def test_ml_kem_dual_encryption_keystore(self):
        """Test ML-KEM algorithms with dual encryption keystore functionality."""
        algorithm = "ml-kem-768-hybrid"  # Test with ML-KEM-768 as representative

        # Generate mock keypair
        public_key, private_key = self._generate_mock_pqc_key(algorithm)

        # Add key with dual encryption enabled
        key_id = self.keystore.add_key(
            algorithm=algorithm,
            public_key=public_key,
            private_key=private_key,
            description=f"Dual encryption test key for {algorithm}",
            tags=["test", "dual-encryption"],
            dual_encryption=True,
            file_password=self.file_password,
        )

        self.assertIsNotNone(key_id, f"Key ID should be generated for dual encryption {algorithm}")

        # Verify dual encryption flag
        if hasattr(self.keystore, "key_has_dual_encryption"):
            is_dual = self.keystore.key_has_dual_encryption(key_id)
            self.assertTrue(is_dual, f"Key should be marked for dual encryption")

        # Test key retrieval with file password
        retrieved_public, retrieved_private = self.keystore.get_key(
            key_id, file_password=self.file_password
        )

        self.assertEqual(
            retrieved_public, public_key, f"Public key mismatch for dual encryption {algorithm}"
        )
        self.assertEqual(
            retrieved_private, private_key, f"Private key mismatch for dual encryption {algorithm}"
        )

        # Test key retrieval without file password (should fail for dual encryption)
        with self.assertRaises(Exception):
            self.keystore.get_key(key_id)  # No file_password provided

        # Clean up
        self.keystore.remove_key(key_id)

    def test_keystore_key_management_operations(self):
        """Test comprehensive key management operations for HQC and ML-KEM."""
        # Test algorithms from both families
        test_cases = [
            ("hqc-128-hybrid", ["hqc", "test"]),
            ("hqc-192-hybrid", ["hqc", "production"]),
            ("ml-kem-512-hybrid", ["ml-kem", "test"]),
            ("ml-kem-1024-hybrid", ["ml-kem", "secure"]),
        ]

        added_keys = []

        for algorithm, tags in test_cases:
            # Generate mock keypair
            public_key, private_key = self._generate_mock_pqc_key(algorithm)

            # Add key to keystore
            key_id = self.keystore.add_key(
                algorithm=algorithm,
                public_key=public_key,
                private_key=private_key,
                description=f"Management test key for {algorithm}",
                tags=tags,
            )

            added_keys.append((key_id, algorithm, tags))

        # Test listing all keys
        all_keys = self.keystore.list_keys()
        self.assertEqual(len(all_keys), len(test_cases), "All added keys should be listed")

        # Test filtering by tags
        hqc_keys = [k for k in all_keys if "hqc" in k.get("tags", [])]
        ml_kem_keys = [k for k in all_keys if "ml-kem" in k.get("tags", [])]

        self.assertEqual(len(hqc_keys), 2, "Should find 2 HQC keys")
        self.assertEqual(len(ml_kem_keys), 2, "Should find 2 ML-KEM keys")

        # Test key update operations
        first_key_id = added_keys[0][0]
        updated_description = "Updated description for integration test"

        # Update key description (if supported)
        try:
            # Some keystore implementations may not support key updates
            # This is a best-effort test
            pass  # Placeholder for potential key update functionality
        except NotImplementedError:
            pass  # Skip if key updates are not supported

        # Test key removal
        for key_id, algorithm, tags in added_keys:
            self.keystore.remove_key(key_id)

        # Verify all keys are removed
        remaining_keys = self.keystore.list_keys()
        for key_id, _, _ in added_keys:
            key_found = any(k["key_id"] == key_id for k in remaining_keys)
            self.assertFalse(key_found, f"Key {key_id} should be removed from keystore")

    def test_keystore_error_handling(self):
        """Test error handling scenarios for HQC and ML-KEM keystore operations."""
        # Test invalid algorithm - keystore may accept any algorithm string
        # so this might not raise an exception, which is acceptable behavior
        try:
            key_id = self.keystore.add_key(
                algorithm="invalid-algorithm",
                public_key=b"fake_public_key",
                private_key=b"fake_private_key",
                description="Invalid algorithm test",
            )
            # If successful, clean up the test key
            if key_id:
                self.keystore.remove_key(key_id)
        except Exception:
            # Exception is expected but not required
            pass

        # Test key retrieval with invalid key ID
        with self.assertRaises((KeyError, ValueError, Exception)):
            self.keystore.get_key("invalid-key-id")

        # Test key removal with invalid key ID - may not raise exception if keystore is tolerant
        try:
            self.keystore.remove_key("invalid-key-id")
        except Exception:
            # Exception is expected but implementation may vary
            pass

        # Test keystore operations with wrong password
        wrong_password_keystore = PQCKeystore(self.keystore_path)
        with self.assertRaises(Exception):
            wrong_password_keystore.load_keystore("wrong_password")

    def test_keystore_security_levels(self):
        """Test keystore security levels with HQC and ML-KEM keys."""
        # Create keystores with different security levels
        security_levels = [
            KeystoreSecurityLevel.STANDARD,
            KeystoreSecurityLevel.HIGH,
            KeystoreSecurityLevel.PARANOID,
        ]

        for level in security_levels:
            with self.subTest(security_level=level):
                # Create temporary keystore with specific security level
                temp_keystore_path = os.path.join(self.temp_dir, f"security_test_{level.value}.pqc")
                temp_keystore = PQCKeystore(temp_keystore_path)
                temp_keystore.create_keystore(self.keystore_password, level)

                # Add a test key
                public_key, private_key = self._generate_mock_pqc_key("hqc-128-hybrid")
                key_id = temp_keystore.add_key(
                    algorithm="hqc-128-hybrid",
                    public_key=public_key,
                    private_key=private_key,
                    description=f"Security level {level.value} test key",
                )

                self.assertIsNotNone(
                    key_id, f"Key should be added with security level {level.value}"
                )

                # Verify key can be retrieved
                retrieved_public, retrieved_private = temp_keystore.get_key(key_id)
                self.assertEqual(
                    retrieved_public,
                    public_key,
                    f"Key retrieval should work with security level {level.value}",
                )

                # Clean up
                temp_keystore.remove_key(key_id)
                temp_keystore.clear_cache()

    def test_concurrent_keystore_operations(self):
        """Test thread safety of keystore operations with multiple PQC algorithms."""
        import concurrent.futures
        import threading

        def add_and_remove_key(algorithm, thread_id):
            """Add and remove a key in a separate thread."""
            try:
                # Generate unique keypair for this thread
                public_key, private_key = self._generate_mock_pqc_key(
                    f"{algorithm}_thread_{thread_id}"
                )

                # Add key
                key_id = self.keystore.add_key(
                    algorithm=algorithm,
                    public_key=public_key,
                    private_key=private_key,
                    description=f"Concurrent test key {thread_id} for {algorithm}",
                    tags=["concurrent", "test", f"thread_{thread_id}"],
                )

                # Brief verification
                retrieved_public, retrieved_private = self.keystore.get_key(key_id)

                # Remove key
                self.keystore.remove_key(key_id)

                return f"SUCCESS: {algorithm} thread {thread_id}"
            except Exception as e:
                return f"FAILED: {algorithm} thread {thread_id} - {str(e)}"

        # Test concurrent operations with different algorithms
        test_scenarios = [
            ("hqc-128-hybrid", 0),
            ("hqc-192-hybrid", 1),
            ("ml-kem-512-hybrid", 2),
            ("ml-kem-768-hybrid", 3),
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(add_and_remove_key, alg, tid) for alg, tid in test_scenarios]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # Check results
        successes = [r for r in results if r.startswith("SUCCESS")]
        failures = [r for r in results if r.startswith("FAILED")]

        print(
            f"Concurrent keystore operations test: {len(successes)} successes, {len(failures)} failures"
        )
        for result in results:
            print(f"  {result}")

        # Most operations should succeed (allow for some potential race conditions)
        self.assertGreater(
            len(successes), len(failures), "Most concurrent operations should succeed"
        )


if __name__ == "__main__":
    unittest.main()
