#!/usr/bin/env python3
"""
Unit tests for Integrity Plugin integration with encrypt/decrypt operations.

This test suite focuses on preventing regressions related to:
1. File ID consistency between encryption and decryption
2. Hash storage and retrieval (mocked, no remote server needed)
3. Tampering detection
4. Edge cases with file paths

NOTE: These tests use mocked integrity plugin - no remote server required.
"""

import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from openssl_encrypt.modules.crypt_core import (
    EncryptionAlgorithm,
    decrypt_file,
    encrypt_file,
)
from openssl_encrypt.modules.crypt_errors import DecryptionError


class MockIntegrityHashStorage:
    """
    In-memory hash storage to simulate remote integrity server.

    This allows testing without requiring actual server access,
    making tests suitable for CI/CD pipelines.
    """

    def __init__(self):
        self.hashes = {}  # {file_id: metadata_hash}
        self.store_calls = []
        self.verify_calls = []

    def store(self, file_id, metadata_hash):
        """Store a hash (simulates POST /hashes)."""
        self.store_calls.append((file_id, metadata_hash))
        self.hashes[file_id] = metadata_hash
        return {"file_id": file_id, "status": "stored"}

    def verify(self, file_id, metadata_hash):
        """Verify a hash (simulates POST /verify)."""
        self.verify_calls.append((file_id, metadata_hash))

        if file_id not in self.hashes:
            return (False, {
                "match": False,
                "warning": "Hash not found for this file. Store a hash first with POST /hashes."
            })

        stored_hash = self.hashes[file_id]
        match = (stored_hash == metadata_hash)

        if match:
            return (True, {"match": True})
        else:
            return (False, {
                "match": False,
                "warning": "INTEGRITY VIOLATION: Metadata has been modified! "
                          "The stored hash does not match the provided hash."
            })

    def clear(self):
        """Clear all stored hashes."""
        self.hashes.clear()
        self.store_calls.clear()
        self.verify_calls.clear()


class TestIntegrityFileIDConsistency(unittest.TestCase):
    """
    Test that file_id is computed consistently during encryption and decryption.

    REGRESSION TEST: Previously, encryption used output_file (temp file path)
    while decryption used input_file, causing hash lookup failures.
    """

    def setUp(self):
        """Set up test environment with mock integrity storage."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.password = b"test_password_123"
        self.mock_storage = MockIntegrityHashStorage()

        # Create test file
        with open(self.test_file, "w") as f:
            f.write("Test content for integrity verification")

    def tearDown(self):
        """Clean up test files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_mock_plugin(self):
        """Create a mock IntegrityPlugin that uses in-memory storage."""
        mock_plugin = Mock()
        mock_plugin.__enter__ = Mock(return_value=mock_plugin)
        mock_plugin.__exit__ = Mock(return_value=False)

        # Wire up to mock storage
        mock_plugin.store_hash = lambda **kwargs: self.mock_storage.store(
            kwargs['file_id'], kwargs['metadata_hash']
        )
        mock_plugin.verify = lambda file_id, metadata_hash: self.mock_storage.verify(
            file_id, metadata_hash
        )

        return mock_plugin

    @patch('openssl_encrypt.modules.crypt_core._INTEGRITY_PLUGIN_AVAILABLE', True)
    @patch('openssl_encrypt.modules.crypt_core.IntegrityConfig')
    @patch('openssl_encrypt.modules.crypt_core.IntegrityPlugin')
    def test_file_id_matches_encryption_and_decryption(
        self, mock_plugin_class, mock_config_class
    ):
        """
        Test that encryption and decryption compute the same file_id.

        This is the CRITICAL regression test that would have caught the bug.
        """
        # Setup mocks
        mock_config = Mock()
        mock_config.enabled = True
        mock_config_class.from_file.return_value = mock_config

        mock_plugin = self._create_mock_plugin()
        mock_plugin_class.return_value = mock_plugin

        # Mock the static methods with deterministic implementations
        def compute_file_id_mock(path):
            """Mock that returns SHA-256 of absolute path."""
            abs_path = str(Path(path).resolve())
            return hashlib.sha256(abs_path.encode('utf-8')).hexdigest().lower()

        def compute_metadata_hash_mock(metadata):
            """Mock that returns SHA-256 of metadata."""
            if isinstance(metadata, str):
                metadata = metadata.encode('utf-8')
            return hashlib.sha256(metadata).hexdigest().lower()

        mock_plugin_class.compute_file_id = compute_file_id_mock
        mock_plugin_class.compute_metadata_hash = compute_metadata_hash_mock

        # Encrypt with integrity flag
        encrypt_file(
            input_file=self.test_file,
            output_file=self.test_file,
            password=self.password,
            quiet=True,
            integrity=True,
        )

        # Get the file_id used during encryption
        self.assertEqual(len(self.mock_storage.store_calls), 1,
                        "store_hash should be called exactly once")
        encryption_file_id, encryption_hash = self.mock_storage.store_calls[0]

        # Decrypt with verify-integrity flag
        decrypt_file(
            input_file=self.test_file,
            output_file=self.test_file + ".decrypted",
            password=self.password,
            quiet=True,
            verify_integrity=True,
        )

        # Get the file_id used during decryption
        self.assertEqual(len(self.mock_storage.verify_calls), 1,
                        "verify should be called exactly once")
        decryption_file_id, decryption_hash = self.mock_storage.verify_calls[0]

        # CRITICAL ASSERTION: file_ids must match
        self.assertEqual(
            encryption_file_id,
            decryption_file_id,
            msg=f"File ID mismatch! Encryption used '{encryption_file_id}' "
                f"but decryption used '{decryption_file_id}'. "
                f"This will cause hash lookup failures."
        )

        # Both should be based on the original input file
        expected_file_id = compute_file_id_mock(Path(self.test_file))
        self.assertEqual(encryption_file_id, expected_file_id)
        self.assertEqual(decryption_file_id, expected_file_id)

        # Hashes should also match (no tampering)
        self.assertEqual(
            encryption_hash,
            decryption_hash,
            msg="Metadata hash should be identical between encryption and decryption"
        )

    @patch('openssl_encrypt.modules.crypt_core._INTEGRITY_PLUGIN_AVAILABLE', True)
    @patch('openssl_encrypt.modules.crypt_core.IntegrityConfig')
    @patch('openssl_encrypt.modules.crypt_core.IntegrityPlugin')
    def test_file_id_uses_input_not_temp_file(
        self, mock_plugin_class, mock_config_class
    ):
        """
        Test that file_id is computed from input file, not temporary output file.

        Regression test: Previously used output_file which could be a temp file.
        """
        mock_config = Mock()
        mock_config.enabled = True
        mock_config_class.from_file.return_value = mock_config

        mock_plugin = self._create_mock_plugin()
        mock_plugin_class.return_value = mock_plugin

        # Track what paths are used for compute_file_id
        file_id_paths = []

        def compute_file_id_spy(path):
            path_str = str(path)
            file_id_paths.append(path_str)
            abs_path = str(Path(path).resolve())
            return hashlib.sha256(abs_path.encode('utf-8')).hexdigest().lower()

        mock_plugin_class.compute_file_id = compute_file_id_spy
        mock_plugin_class.compute_metadata_hash = lambda m: hashlib.sha256(
            m if isinstance(m, bytes) else m.encode('utf-8')
        ).hexdigest()

        # Encrypt
        encrypt_file(
            input_file=self.test_file,
            output_file=self.test_file,
            password=self.password,
            quiet=True,
            integrity=True,
        )

        # Verify compute_file_id was called
        self.assertGreater(len(file_id_paths), 0, "compute_file_id was not called")

        # Check that the path used matches the input file (not a temp file)
        used_path = Path(file_id_paths[0]).resolve()
        expected_path = Path(self.test_file).resolve()

        self.assertEqual(
            used_path,
            expected_path,
            msg=f"File ID computed from wrong path! "
                f"Expected '{expected_path}' but got '{used_path}'. "
                f"This suggests a temp file was used instead of input file."
        )

        # Ensure it's not a temp file path (no .tmp extension)
        for path in file_id_paths:
            self.assertNotIn('.tmp', path.lower(),
                           msg=f"File ID should not be computed from temp file: {path}")


class TestIntegrityHashStorageAndRetrieval(unittest.TestCase):
    """Test hash storage during encryption and retrieval during decryption."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "data.txt")
        self.password = b"secure_password"
        self.mock_storage = MockIntegrityHashStorage()

        with open(self.test_file, "w") as f:
            f.write("Important data")

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_mock_plugin(self):
        """Create a mock IntegrityPlugin that uses in-memory storage."""
        mock_plugin = Mock()
        mock_plugin.__enter__ = Mock(return_value=mock_plugin)
        mock_plugin.__exit__ = Mock(return_value=False)

        # Wire up to mock storage
        mock_plugin.store_hash = lambda **kwargs: self.mock_storage.store(
            kwargs['file_id'], kwargs['metadata_hash']
        )
        mock_plugin.verify = lambda file_id, metadata_hash: self.mock_storage.verify(
            file_id, metadata_hash
        )

        return mock_plugin

    @patch('openssl_encrypt.modules.crypt_core._INTEGRITY_PLUGIN_AVAILABLE', True)
    @patch('openssl_encrypt.modules.crypt_core.IntegrityConfig')
    @patch('openssl_encrypt.modules.crypt_core.IntegrityPlugin')
    def test_hash_stored_during_encryption(
        self, mock_plugin_class, mock_config_class
    ):
        """Test that metadata hash is stored during encryption."""
        mock_config = Mock()
        mock_config.enabled = True
        mock_config_class.from_file.return_value = mock_config

        mock_plugin = self._create_mock_plugin()
        mock_plugin_class.return_value = mock_plugin

        # Use deterministic hash functions
        mock_plugin_class.compute_file_id = lambda p: "static_file_id_abc123"
        mock_plugin_class.compute_metadata_hash = lambda m: "static_hash_def456"

        # Encrypt with integrity
        encrypt_file(
            input_file=self.test_file,
            output_file=self.test_file,
            password=self.password,
            quiet=True,
            integrity=True,
        )

        # Verify hash was stored
        self.assertEqual(len(self.mock_storage.store_calls), 1)
        stored_file_id, stored_hash = self.mock_storage.store_calls[0]

        self.assertEqual(stored_file_id, "static_file_id_abc123")
        self.assertEqual(stored_hash, "static_hash_def456")

        # Verify it's in storage
        self.assertIn("static_file_id_abc123", self.mock_storage.hashes)
        self.assertEqual(
            self.mock_storage.hashes["static_file_id_abc123"],
            "static_hash_def456"
        )

    @patch('openssl_encrypt.modules.crypt_core._INTEGRITY_PLUGIN_AVAILABLE', True)
    @patch('openssl_encrypt.modules.crypt_core.IntegrityConfig')
    @patch('openssl_encrypt.modules.crypt_core.IntegrityPlugin')
    def test_hash_verified_during_decryption(
        self, mock_plugin_class, mock_config_class
    ):
        """Test that metadata hash is verified during decryption."""
        # First encrypt without integrity to create encrypted file
        encrypt_file(
            input_file=self.test_file,
            output_file=self.test_file,
            password=self.password,
            quiet=True,
            integrity=False,
        )

        # Pre-populate mock storage with the expected hash
        self.mock_storage.store("static_file_id_789", "static_hash_abc")

        # Setup mocks for decryption
        mock_config = Mock()
        mock_config.enabled = True
        mock_config_class.from_file.return_value = mock_config

        mock_plugin = self._create_mock_plugin()
        mock_plugin_class.return_value = mock_plugin

        # Use deterministic hash functions
        mock_plugin_class.compute_file_id = lambda p: "static_file_id_789"
        mock_plugin_class.compute_metadata_hash = lambda m: "static_hash_abc"

        # Decrypt with verify-integrity
        decrypt_file(
            input_file=self.test_file,
            output_file=self.test_file + ".dec",
            password=self.password,
            quiet=True,
            verify_integrity=True,
        )

        # Verify that verify() was called with correct parameters
        self.assertEqual(len(self.mock_storage.verify_calls), 1)
        verified_file_id, verified_hash = self.mock_storage.verify_calls[0]

        self.assertEqual(verified_file_id, "static_file_id_789")
        self.assertEqual(verified_hash, "static_hash_abc")

    @patch('openssl_encrypt.modules.crypt_core._INTEGRITY_PLUGIN_AVAILABLE', True)
    @patch('openssl_encrypt.modules.crypt_core.IntegrityConfig')
    @patch('openssl_encrypt.modules.crypt_core.IntegrityPlugin')
    def test_end_to_end_encrypt_decrypt_with_integrity(
        self, mock_plugin_class, mock_config_class
    ):
        """
        Full end-to-end test: encrypt with --integrity, decrypt with --verify-integrity.

        This simulates the complete workflow without requiring a remote server.
        """
        mock_config = Mock()
        mock_config.enabled = True
        mock_config_class.from_file.return_value = mock_config

        mock_plugin = self._create_mock_plugin()
        mock_plugin_class.return_value = mock_plugin

        # Use deterministic hash functions
        file_id_value = "e2e_file_id_xyz"

        def compute_file_id_deterministic(p):
            return file_id_value

        def compute_metadata_hash_real(m):
            # Use real hash but make it deterministic
            if isinstance(m, str):
                m = m.encode('utf-8')
            return hashlib.sha256(m).hexdigest().lower()

        mock_plugin_class.compute_file_id = compute_file_id_deterministic
        mock_plugin_class.compute_metadata_hash = compute_metadata_hash_real

        # Step 1: Encrypt with integrity
        encrypt_file(
            input_file=self.test_file,
            output_file=self.test_file,
            password=self.password,
            quiet=True,
            integrity=True,
        )

        # Verify hash was stored
        self.assertEqual(len(self.mock_storage.store_calls), 1)
        stored_file_id, stored_hash = self.mock_storage.store_calls[0]
        self.assertEqual(stored_file_id, file_id_value)

        # Step 2: Decrypt with verify-integrity
        decrypt_file(
            input_file=self.test_file,
            output_file=self.test_file + ".dec",
            password=self.password,
            quiet=True,
            verify_integrity=True,
        )

        # Verify hash was checked
        self.assertEqual(len(self.mock_storage.verify_calls), 1)
        verified_file_id, verified_hash = self.mock_storage.verify_calls[0]

        # File IDs should match
        self.assertEqual(stored_file_id, verified_file_id)

        # Hashes should match (no tampering)
        self.assertEqual(stored_hash, verified_hash)

        # Verification should have passed
        match, details = self.mock_storage.verify(verified_file_id, verified_hash)
        self.assertTrue(match, "Integrity verification should pass")


class TestIntegrityTamperingDetection(unittest.TestCase):
    """Test detection of metadata tampering."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "secret.txt")
        self.password = b"password123"
        self.mock_storage = MockIntegrityHashStorage()

        with open(self.test_file, "w") as f:
            f.write("Secret information")

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_mock_plugin(self):
        """Create a mock IntegrityPlugin that uses in-memory storage."""
        mock_plugin = Mock()
        mock_plugin.__enter__ = Mock(return_value=mock_plugin)
        mock_plugin.__exit__ = Mock(return_value=False)

        # Wire up to mock storage
        mock_plugin.store_hash = lambda **kwargs: self.mock_storage.store(
            kwargs['file_id'], kwargs['metadata_hash']
        )
        mock_plugin.verify = lambda file_id, metadata_hash: self.mock_storage.verify(
            file_id, metadata_hash
        )

        return mock_plugin

    @patch('openssl_encrypt.modules.crypt_core._INTEGRITY_PLUGIN_AVAILABLE', True)
    @patch('openssl_encrypt.modules.crypt_core.IntegrityConfig')
    @patch('openssl_encrypt.modules.crypt_core.IntegrityPlugin')
    def test_hash_not_found_in_storage(
        self, mock_plugin_class, mock_config_class
    ):
        """Test behavior when hash is not found in storage (never uploaded)."""
        # Encrypt without integrity
        encrypt_file(
            input_file=self.test_file,
            output_file=self.test_file,
            password=self.password,
            quiet=True,
            integrity=False,
        )

        # Storage is empty (no hash uploaded)
        self.assertEqual(len(self.mock_storage.hashes), 0)

        # Setup mocks for decryption
        mock_config = Mock()
        mock_config.enabled = True
        mock_config_class.from_file.return_value = mock_config

        mock_plugin = self._create_mock_plugin()
        mock_plugin_class.return_value = mock_plugin
        mock_plugin_class.compute_file_id = lambda p: "missing_file_id"
        mock_plugin_class.compute_metadata_hash = lambda m: "some_hash"

        # Attempt to decrypt with verification should detect missing hash
        with patch('builtins.input', return_value='n'):  # User chooses not to proceed
            with self.assertRaises(DecryptionError):
                decrypt_file(
                    input_file=self.test_file,
                    output_file=self.test_file + ".dec",
                    password=self.password,
                    quiet=False,
                    verify_integrity=True,
                )

        # Verify that verify() detected the missing hash
        match, details = self.mock_storage.verify("missing_file_id", "some_hash")
        self.assertFalse(match)
        self.assertIn("not found", details["warning"].lower())

    @patch('openssl_encrypt.modules.crypt_core._INTEGRITY_PLUGIN_AVAILABLE', True)
    @patch('openssl_encrypt.modules.crypt_core.IntegrityConfig')
    @patch('openssl_encrypt.modules.crypt_core.IntegrityPlugin')
    def test_hash_mismatch_detected(
        self, mock_plugin_class, mock_config_class
    ):
        """Test that hash mismatch is detected (metadata tampering)."""
        # Encrypt first
        encrypt_file(
            input_file=self.test_file,
            output_file=self.test_file,
            password=self.password,
            quiet=True,
            integrity=False,
        )

        # Store the original hash
        file_id = "tampered_file_id"
        original_hash = "original_hash_12345"
        self.mock_storage.store(file_id, original_hash)

        # Setup mocks for decryption with tampered hash
        mock_config = Mock()
        mock_config.enabled = True
        mock_config_class.from_file.return_value = mock_config

        mock_plugin = self._create_mock_plugin()
        mock_plugin_class.return_value = mock_plugin
        mock_plugin_class.compute_file_id = lambda p: file_id
        # Return different hash (simulating tampering)
        mock_plugin_class.compute_metadata_hash = lambda m: "tampered_hash_67890"

        # Attempt to decrypt should detect tampering
        with patch('builtins.input', return_value='n'):
            with self.assertRaises(DecryptionError):
                decrypt_file(
                    input_file=self.test_file,
                    output_file=self.test_file + ".dec",
                    password=self.password,
                    quiet=False,
                    verify_integrity=True,
                )

        # Verify that mismatch was detected
        match, details = self.mock_storage.verify(file_id, "tampered_hash_67890")
        self.assertFalse(match)
        self.assertIn("modified", details["warning"].lower())

    def test_metadata_tampering_changes_hash(self):
        """Test that modifying metadata actually changes its hash."""
        # Create original metadata
        metadata = {
            "format_version": 6,
            "derivation_config": {
                "hash_config": {
                    "sha512": {"rounds": 10000}
                }
            }
        }

        original_json = json.dumps(metadata, separators=(',', ': ')).encode('utf-8')
        original_hash = hashlib.sha256(original_json).hexdigest()

        # Tamper with metadata (reduce rounds - DoS attack vector)
        metadata["derivation_config"]["hash_config"]["sha512"]["rounds"] = 100
        tampered_json = json.dumps(metadata, separators=(',', ': ')).encode('utf-8')
        tampered_hash = hashlib.sha256(tampered_json).hexdigest()

        # Hashes should differ
        self.assertNotEqual(
            original_hash,
            tampered_hash,
            msg="Hash should change when metadata is tampered with"
        )


class TestIntegrityEdgeCases(unittest.TestCase):
    """Test edge cases for integrity verification."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_file_id_consistent_for_absolute_path(self):
        """Test that file_id is same whether path is relative or absolute."""
        from openssl_encrypt.plugins.integrity import IntegrityPlugin

        test_file = os.path.join(self.temp_dir, "file.txt")
        Path(test_file).touch()

        # Compute file_id with absolute path
        abs_file_id = IntegrityPlugin.compute_file_id(Path(test_file).resolve())

        # Compute file_id with relative path (if possible)
        original_cwd = os.getcwd()
        try:
            os.chdir(self.temp_dir)
            rel_file_id = IntegrityPlugin.compute_file_id(Path("file.txt"))

            # Should be the same (both resolve to absolute)
            self.assertEqual(
                abs_file_id,
                rel_file_id,
                msg="File ID should be consistent for absolute and relative paths"
            )
        finally:
            os.chdir(original_cwd)

    def test_file_id_different_for_different_paths(self):
        """Test that different file paths produce different file_ids."""
        from openssl_encrypt.plugins.integrity import IntegrityPlugin

        file1 = Path(self.temp_dir) / "file1.txt"
        file2 = Path(self.temp_dir) / "file2.txt"

        file_id1 = IntegrityPlugin.compute_file_id(file1)
        file_id2 = IntegrityPlugin.compute_file_id(file2)

        self.assertNotEqual(
            file_id1,
            file_id2,
            msg="Different files should have different file_ids"
        )

    def test_metadata_hash_deterministic(self):
        """Test that the same metadata always produces the same hash."""
        from openssl_encrypt.plugins.integrity import IntegrityPlugin

        metadata = b"test metadata content"

        hash1 = IntegrityPlugin.compute_metadata_hash(metadata)
        hash2 = IntegrityPlugin.compute_metadata_hash(metadata)

        self.assertEqual(hash1, hash2, msg="Hash computation should be deterministic")

    def test_metadata_hash_different_for_different_data(self):
        """Test that different metadata produces different hashes."""
        from openssl_encrypt.plugins.integrity import IntegrityPlugin

        metadata1 = b"original metadata"
        metadata2 = b"modified metadata"

        hash1 = IntegrityPlugin.compute_metadata_hash(metadata1)
        hash2 = IntegrityPlugin.compute_metadata_hash(metadata2)

        self.assertNotEqual(hash1, hash2, msg="Different metadata should have different hashes")

    def test_file_id_is_64_char_hex(self):
        """Test that file_id is always 64-character hex string (SHA-256)."""
        from openssl_encrypt.plugins.integrity import IntegrityPlugin

        test_file = Path(self.temp_dir) / "test.txt"
        file_id = IntegrityPlugin.compute_file_id(test_file)

        self.assertEqual(len(file_id), 64, msg="File ID should be 64 characters (SHA-256)")
        self.assertTrue(
            all(c in '0123456789abcdef' for c in file_id),
            msg="File ID should be lowercase hex"
        )

    def test_metadata_hash_is_64_char_hex(self):
        """Test that metadata_hash is always 64-character hex string (SHA-256)."""
        from openssl_encrypt.plugins.integrity import IntegrityPlugin

        metadata = b"test metadata"
        metadata_hash = IntegrityPlugin.compute_metadata_hash(metadata)

        self.assertEqual(len(metadata_hash), 64, msg="Hash should be 64 characters (SHA-256)")
        self.assertTrue(
            all(c in '0123456789abcdef' for c in metadata_hash),
            msg="Hash should be lowercase hex"
        )


class TestIntegrityAEADAndNonAEAD(unittest.TestCase):
    """Test integrity verification works with both AEAD and non-AEAD algorithms."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.password = b"test_pass"
        self.mock_storage = MockIntegrityHashStorage()

        with open(self.test_file, "w") as f:
            f.write("Test data for AEAD/non-AEAD")

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_mock_plugin(self):
        """Create a mock IntegrityPlugin that uses in-memory storage."""
        mock_plugin = Mock()
        mock_plugin.__enter__ = Mock(return_value=mock_plugin)
        mock_plugin.__exit__ = Mock(return_value=False)

        # Wire up to mock storage
        mock_plugin.store_hash = lambda **kwargs: self.mock_storage.store(
            kwargs['file_id'], kwargs['metadata_hash']
        )

        return mock_plugin

    @patch('openssl_encrypt.modules.crypt_core._INTEGRITY_PLUGIN_AVAILABLE', True)
    @patch('openssl_encrypt.modules.crypt_core.IntegrityConfig')
    @patch('openssl_encrypt.modules.crypt_core.IntegrityPlugin')
    def test_integrity_with_aead_algorithm(
        self, mock_plugin_class, mock_config_class
    ):
        """Test integrity works with AEAD algorithm (e.g., AES-GCM)."""
        mock_config = Mock()
        mock_config.enabled = True
        mock_config_class.from_file.return_value = mock_config

        mock_plugin = self._create_mock_plugin()
        mock_plugin_class.return_value = mock_plugin
        mock_plugin_class.compute_file_id = lambda p: "aead_file_id"
        mock_plugin_class.compute_metadata_hash = lambda m: "aead_hash"

        # Test with AEAD algorithm
        encrypt_file(
            input_file=self.test_file,
            output_file=self.test_file,
            password=self.password,
            algorithm=EncryptionAlgorithm.AES_GCM,
            quiet=True,
            integrity=True,
        )

        # Verify hash was stored
        self.assertEqual(len(self.mock_storage.store_calls), 1,
                        msg="Integrity hash should be stored for AEAD algorithms")
        stored_file_id, stored_hash = self.mock_storage.store_calls[0]
        self.assertEqual(stored_file_id, "aead_file_id")
        self.assertEqual(stored_hash, "aead_hash")

    @patch('openssl_encrypt.modules.crypt_core._INTEGRITY_PLUGIN_AVAILABLE', True)
    @patch('openssl_encrypt.modules.crypt_core.IntegrityConfig')
    @patch('openssl_encrypt.modules.crypt_core.IntegrityPlugin')
    def test_integrity_with_non_aead_algorithm(
        self, mock_plugin_class, mock_config_class
    ):
        """Test integrity works with non-AEAD algorithm (e.g., Fernet)."""
        mock_config = Mock()
        mock_config.enabled = True
        mock_config_class.from_file.return_value = mock_config

        mock_plugin = self._create_mock_plugin()
        mock_plugin_class.return_value = mock_plugin
        mock_plugin_class.compute_file_id = lambda p: "fernet_file_id"
        mock_plugin_class.compute_metadata_hash = lambda m: "fernet_hash"

        # Test with non-AEAD algorithm
        encrypt_file(
            input_file=self.test_file,
            output_file=self.test_file,
            password=self.password,
            algorithm=EncryptionAlgorithm.FERNET,
            quiet=True,
            integrity=True,
        )

        # Verify hash was stored
        self.assertEqual(len(self.mock_storage.store_calls), 1,
                        msg="Integrity hash should be stored for non-AEAD algorithms")
        stored_file_id, stored_hash = self.mock_storage.store_calls[0]
        self.assertEqual(stored_file_id, "fernet_file_id")
        self.assertEqual(stored_hash, "fernet_hash")


if __name__ == "__main__":
    unittest.main()
