#!/usr/bin/env python3
"""
Test suite for specific encryption algorithms and bindings.

This module contains comprehensive tests for:
- Algorithm deprecation warnings
- RandomX KDF integration
- AEAD (Authenticated Encryption with Associated Data) bindings
"""

import base64
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import warnings
from io import StringIO
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

# Import the modules to test
from openssl_encrypt.modules.crypt_core import (
    EncryptionAlgorithm,
    decrypt_file,
    encrypt_file,
    extract_file_metadata,
    is_aead_algorithm,
)
from openssl_encrypt.modules.crypt_errors import (
    AuthenticationError,
    DecryptionError,
    ValidationError,
)

# Try to import PQC modules
try:
    from openssl_encrypt.modules.crypt_core import PQC_AVAILABLE
    from openssl_encrypt.modules.pqc import (
        LIBOQS_AVAILABLE,
        PQCAlgorithm,
        PQCipher,
        check_pqc_support,
    )
except ImportError:
    LIBOQS_AVAILABLE = False
    PQC_AVAILABLE = False


class LogCapture(logging.Handler):
    """A custom logging handler that captures log records for testing."""

    def __init__(self):
        super().__init__()
        self.records = []
        self.output = StringIO()

    def emit(self, record):
        self.records.append(record)
        msg = self.format(record)
        self.output.write(msg + "\n")

    def get_output(self):
        return self.output.getvalue()

    def clear(self):
        self.records = []
        self.output = StringIO()


@unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs-python not available, skipping keystore tests")
class TestAlgorithmWarnings(unittest.TestCase):
    """Tests for algorithm deprecation warning system."""

    def setUp(self):
        """Set up test environment."""
        # Import the warnings module
        from openssl_encrypt.modules.algorithm_warnings import (
            DEPRECATED_ALGORITHMS,
            AlgorithmWarningConfig,
            DeprecationLevel,
            get_recommended_replacement,
            is_deprecated,
            warn_deprecated_algorithm,
        )

        self.AlgorithmWarningConfig = AlgorithmWarningConfig
        self.warn_deprecated_algorithm = warn_deprecated_algorithm
        self.is_deprecated = is_deprecated
        self.get_recommended_replacement = get_recommended_replacement
        self.DeprecationLevel = DeprecationLevel
        self.DEPRECATED_ALGORITHMS = DEPRECATED_ALGORITHMS

        # Reset warning config to defaults before each test
        self.AlgorithmWarningConfig.reset()

        # Set up log capture
        self.log_capture = LogCapture()
        logger = logging.getLogger("openssl_encrypt.modules.algorithm_warnings")
        logger.addHandler(self.log_capture)
        logger.setLevel(logging.DEBUG)

        # Capture warnings
        self.warnings_capture = []
        self.original_warn = warnings.warn
        warnings.warn = self._capture_warning

    def tearDown(self):
        """Clean up after test."""
        # Restore original warning function
        warnings.warn = self.original_warn

        # Reset warning config
        self.AlgorithmWarningConfig.reset()

        # Remove log handler
        logger = logging.getLogger("openssl_encrypt.modules.algorithm_warnings")
        logger.removeHandler(self.log_capture)

    def _capture_warning(self, message, category=None, stacklevel=1, source=None):
        """Capture warnings for testing."""
        self.warnings_capture.append(
            {"message": str(message), "category": category, "stacklevel": stacklevel}
        )

    def test_is_deprecated_function(self):
        """Test the is_deprecated function.

        In v1.5.0 all previously deprecated algorithms (kyber, aes-ocb3, camellia,
        whirlpool, pbkdf2) have been fully removed. The DEPRECATED_ALGORITHMS dict
        is now empty, so is_deprecated returns False for all algorithms.
        """
        # Previously deprecated algorithms are now fully removed — not in the dict
        self.assertFalse(self.is_deprecated("kyber512-hybrid"))
        self.assertFalse(self.is_deprecated("Kyber512"))
        self.assertFalse(self.is_deprecated("aes-ocb3"))
        self.assertFalse(self.is_deprecated("camellia"))

        # Current algorithms are not deprecated
        self.assertFalse(self.is_deprecated("ml-kem-512-hybrid"))
        self.assertFalse(self.is_deprecated("aes-gcm"))
        self.assertFalse(self.is_deprecated("fernet"))

        # Case insensitive checks — still not deprecated (fully removed)
        self.assertFalse(self.is_deprecated("KYBER512-HYBRID"))
        self.assertFalse(self.is_deprecated("kyber_512_hybrid"))

    def test_get_recommended_replacement(self):
        """Test the get_recommended_replacement function.

        In v1.5.0 all deprecated algorithms are fully removed from the dict,
        so get_recommended_replacement returns None for all algorithms.
        """
        # Fully removed algorithms have no replacement entry
        self.assertIsNone(self.get_recommended_replacement("kyber512-hybrid"))
        self.assertIsNone(self.get_recommended_replacement("Kyber512"))
        self.assertIsNone(self.get_recommended_replacement("aes-ocb3"))

        # Current algorithms also return None
        self.assertIsNone(self.get_recommended_replacement("aes-gcm"))

        # Case normalization — still None (fully removed)
        self.assertIsNone(self.get_recommended_replacement("KYBER768-HYBRID"))

    def test_warning_configuration(self):
        """Test AlgorithmWarningConfig class."""
        # Test default configuration
        self.assertTrue(self.AlgorithmWarningConfig._show_warnings)
        self.assertEqual(self.AlgorithmWarningConfig._min_warning_level, self.DeprecationLevel.INFO)
        self.assertTrue(self.AlgorithmWarningConfig._log_warnings)
        self.assertTrue(self.AlgorithmWarningConfig._show_once)

        # Test configuration changes
        self.AlgorithmWarningConfig.configure(
            show_warnings=False,
            min_level=self.DeprecationLevel.WARNING,
            log_warnings=False,
            show_once=False,
            verbose_mode=True,
        )

        self.assertFalse(self.AlgorithmWarningConfig._show_warnings)
        self.assertEqual(
            self.AlgorithmWarningConfig._min_warning_level, self.DeprecationLevel.WARNING
        )
        self.assertFalse(self.AlgorithmWarningConfig._log_warnings)
        self.assertFalse(self.AlgorithmWarningConfig._show_once)
        self.assertTrue(self.AlgorithmWarningConfig._verbose_mode)

        # Test reset
        self.AlgorithmWarningConfig.reset()
        self.assertTrue(self.AlgorithmWarningConfig._show_warnings)
        self.assertEqual(self.AlgorithmWarningConfig._min_warning_level, self.DeprecationLevel.INFO)

    def test_should_warn_logic(self):
        """Test the should_warn method logic."""
        # Test with warnings enabled
        self.assertTrue(
            self.AlgorithmWarningConfig.should_warn("test-algo", self.DeprecationLevel.INFO)
        )
        self.assertTrue(
            self.AlgorithmWarningConfig.should_warn("test-algo", self.DeprecationLevel.WARNING)
        )

        # Test with higher minimum level
        self.AlgorithmWarningConfig.configure(min_level=self.DeprecationLevel.WARNING)
        self.assertFalse(
            self.AlgorithmWarningConfig.should_warn("test-algo", self.DeprecationLevel.INFO)
        )
        self.assertTrue(
            self.AlgorithmWarningConfig.should_warn("test-algo", self.DeprecationLevel.WARNING)
        )

        # Test show_once behavior
        self.AlgorithmWarningConfig.reset()
        self.assertTrue(
            self.AlgorithmWarningConfig.should_warn("test-algo", self.DeprecationLevel.INFO)
        )
        self.AlgorithmWarningConfig.mark_warned("test-algo")
        self.assertFalse(
            self.AlgorithmWarningConfig.should_warn("test-algo", self.DeprecationLevel.INFO)
        )

        # Test with warnings disabled
        self.AlgorithmWarningConfig.configure(show_warnings=False)
        self.assertFalse(
            self.AlgorithmWarningConfig.should_warn("other-algo", self.DeprecationLevel.WARNING)
        )

    def test_warn_deprecated_algorithm_basic(self):
        """Test basic warning functionality.

        In v1.5.0, DEPRECATED_ALGORITHMS is empty (all removed), so
        warn_deprecated_algorithm should not issue any warnings for
        previously deprecated algorithms.
        """
        # Reset warnings capture
        self.warnings_capture = []

        # Enable verbose mode to ensure warnings are shown during tests
        self.AlgorithmWarningConfig.configure(verbose_mode=True)

        # Previously deprecated algorithms are now fully removed — no warning issued
        self.warn_deprecated_algorithm("kyber512-hybrid", "test context")
        self.assertEqual(len(self.warnings_capture), 0)

        # Non-deprecated algorithms also produce no warning
        self.warn_deprecated_algorithm("aes-gcm", "test context")
        self.assertEqual(len(self.warnings_capture), 0)

    def test_warn_deprecated_algorithm_levels(self):
        """Test warning levels and categories.

        In v1.5.0, all deprecated algorithms are fully removed from the registry.
        No warnings should be issued for any of them.
        """
        self.warnings_capture = []

        # Enable verbose mode to ensure warnings are shown during tests
        self.AlgorithmWarningConfig.configure(verbose_mode=True)

        # All previously deprecated algorithms are fully removed — no warnings
        self.warn_deprecated_algorithm("kyber512-hybrid")
        self.assertEqual(len(self.warnings_capture), 0)

        self.warn_deprecated_algorithm("aes-ocb3")
        self.assertEqual(len(self.warnings_capture), 0)

        self.warn_deprecated_algorithm("camellia")
        self.assertEqual(len(self.warnings_capture), 0)

    def test_warn_deprecated_algorithm_configuration_effects(self):
        """Test how configuration affects warning behavior.

        In v1.5.0, DEPRECATED_ALGORITHMS is empty. Configuration still works
        but no warnings are issued since there are no deprecated algorithms.
        """
        self.warnings_capture = []

        # Test with warnings disabled — no warnings
        self.AlgorithmWarningConfig.configure(show_warnings=False)
        self.warn_deprecated_algorithm("ml-kem-512-hybrid")
        self.assertEqual(len(self.warnings_capture), 0)

        # Test with higher minimum level — no warnings (dict is empty)
        self.AlgorithmWarningConfig.configure(
            show_warnings=True, min_level=self.DeprecationLevel.WARNING
        )
        self.warn_deprecated_algorithm("ml-kem-512-hybrid")
        self.assertEqual(len(self.warnings_capture), 0)

        # Previously deprecated algorithms are fully removed — no warning even with config
        self.warn_deprecated_algorithm("aes-ocb3")
        self.assertEqual(len(self.warnings_capture), 0)

    def test_non_deprecated_algorithm_warning(self):
        """Test that non-deprecated algorithms don't trigger warnings."""
        self.warnings_capture = []

        # Test with algorithms that are not in the deprecated list
        self.warn_deprecated_algorithm("aes-gcm")
        self.warn_deprecated_algorithm("ml-kem-512-hybrid")
        self.warn_deprecated_algorithm("fernet")

        # No warnings should be issued
        self.assertEqual(len(self.warnings_capture), 0)

    def test_cli_integration_encrypt(self):
        """Test that warnings are properly integrated in CLI encrypt operations.

        In v1.5.0, DEPRECATED_ALGORITHMS is empty. Verify the warning functions
        are still importable from the CLI module and work correctly (returning
        False/None for fully removed algorithms).
        """
        # Test that the warning functions are properly imported in CLI
        from openssl_encrypt.modules.crypt_cli import (
            get_recommended_replacement,
            is_deprecated,
            warn_deprecated_algorithm,
        )

        # Fully removed algorithms are no longer in the deprecated dict
        self.assertFalse(is_deprecated("kyber512-hybrid"))
        self.assertIsNone(get_recommended_replacement("kyber512-hybrid"))

        # Current algorithms are not deprecated
        self.assertFalse(is_deprecated("ml-kem-512-hybrid"))

        # Calling warn for a removed algorithm produces no warning
        self.warnings_capture = []
        self.AlgorithmWarningConfig.configure(verbose_mode=True)
        warn_deprecated_algorithm("kyber768-hybrid", "command-line encryption")
        self.assertEqual(len(self.warnings_capture), 0)

    def test_extract_file_metadata_integration(self):
        """Test that extract_file_metadata works for warning system."""
        from openssl_encrypt.modules.crypt_core import (
            EncryptionAlgorithm,
            encrypt_file,
            extract_file_metadata,
        )

        # Create a test file with a deprecated algorithm
        test_input = "Test content for metadata extraction"

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_input:
            temp_input.write(test_input)
            temp_input_path = temp_input.name

        with tempfile.NamedTemporaryFile(delete=False) as temp_output:
            temp_output_path = temp_output.name

        try:
            # Encrypt with a deprecated algorithm - use Kyber512 which is deprecated
            password = b"test_password_123"
            hash_config = {
                "sha512": 0,
                "sha256": 0,
                "sha3_256": 0,
                "sha3_512": 0,
                "blake2b": 0,
                "shake256": 0,
                "scrypt": {"enabled": False, "n": 0, "r": 0, "p": 0, "rounds": 0},
                "argon2": {
                    "enabled": False,
                    "time_cost": 0,
                    "memory_cost": 0,
                    "parallelism": 0,
                    "hash_len": 0,
                    "type": 0,
                    "rounds": 0,
                },
                "balloon": {
                    "enabled": False,
                    "time_cost": 0,
                    "space_cost": 0,
                    "parallelism": 0,
                    "rounds": 0,
                },
            }
            # Since deprecated algorithms are blocked for encryption in v1.2.0,
            # we'll test with a current algorithm and then test the deprecation
            # system logic separately
            encrypt_file(
                temp_input_path,
                temp_output_path,
                password,
                algorithm=EncryptionAlgorithm.ML_KEM_512_HYBRID,  # Current algorithm
                hash_config=hash_config,
                quiet=True,
            )

            # Extract metadata
            metadata = extract_file_metadata(temp_output_path)

            # Verify we get the correct algorithm and that it's NOT deprecated
            self.assertEqual(metadata["algorithm"], "ml-kem-512-hybrid")
            self.assertFalse(self.is_deprecated(metadata["algorithm"]))

            # Fully removed algorithms are no longer in the deprecated dict
            self.assertFalse(self.is_deprecated("kyber512-hybrid"))
            self.assertIsNone(self.get_recommended_replacement("kyber512-hybrid"))

        finally:
            # Clean up
            if os.path.exists(temp_input_path):
                os.unlink(temp_input_path)
            if os.path.exists(temp_output_path):
                os.unlink(temp_output_path)


class TestRandomXIntegration(unittest.TestCase):
    """Test class for RandomX KDF integration functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.test_dir, "test_file.txt")
        self.test_password = "test_password_123"

        # Create test file
        with open(self.test_file, "w", encoding="utf-8") as f:
            f.write("This is a test file for RandomX encryption testing.")

        # Import the basic config structure that works for comparison (flattened)
        self.basic_hash_config = {
            "sha512": 0,  # Reduced from potentially higher values
            "sha256": 0,
            "sha3_256": 0,  # Reduced from potentially higher values
            "sha3_512": 0,
            "blake2b": 0,  # Added for testing new hash function
            "shake256": 0,  # Added for testing new hash function
            "scrypt": {
                "enabled": False,
                "n": 1024,  # Reduced from potentially higher values
                "r": 8,
                "p": 1,
                "rounds": 1,
            },
            "argon2": {
                "enabled": False,
                "time_cost": 1,
                "memory_cost": 8192,
                "parallelism": 1,
                "hash_len": 32,
                "type": 2,  # Argon2id
                "rounds": 1,
            },
        }

        # RandomX test configuration (flattened structure)
        self.randomx_hash_config = {
            "sha512": 0,
            "sha256": 0,
            "sha3_256": 0,
            "sha3_512": 0,
            "blake2b": 0,
            "shake256": 0,
            "scrypt": {
                "enabled": False,
                "n": 1024,
                "r": 8,
                "p": 1,
                "rounds": 0,
            },
            "argon2": {
                "enabled": False,
                "time_cost": 1,
                "memory_cost": 8192,
                "parallelism": 1,
                "hash_len": 32,
                "type": 2,
                "rounds": 0,
            },
            "randomx": {
                "enabled": True,
                "rounds": 2,
                "mode": "light",
                "height": 1,
                "hash_len": 32,
            },
        }

        # Config with hashes before RandomX (no security warning expected)
        # Using flattened structure that matches what create_metadata_v5 expects
        self.safe_randomx_config = {
            "sha512": 100,  # Prior hashing present
            "sha256": 0,
            "sha3_256": 0,
            "sha3_512": 0,
            "blake2b": 0,
            "shake256": 0,
            "scrypt": {
                "enabled": False,
                "n": 1024,
                "r": 8,
                "p": 1,
                "rounds": 0,
            },
            "argon2": {
                "enabled": False,
                "time_cost": 1,
                "memory_cost": 8192,
                "parallelism": 1,
                "hash_len": 32,
                "type": 2,
                "rounds": 0,
            },
            "randomx": {
                "enabled": True,
                "rounds": 1,
                "mode": "light",
                "height": 1,
                "hash_len": 32,
            },
        }

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _check_randomx_available(self):
        """Helper method to skip tests if RandomX is not available."""
        try:
            from ..modules.randomx import RANDOMX_AVAILABLE

            if not RANDOMX_AVAILABLE:
                self.skipTest(
                    "RandomX library not available (CPU incompatibility or missing dependency)"
                )
        except ImportError:
            self.skipTest("RandomX module not available")

    def test_randomx_availability(self):
        """Test that RandomX module is available and can be loaded."""
        self._check_randomx_available()

        try:
            from ..modules.randomx import RANDOMX_AVAILABLE, check_randomx_support, get_randomx_info

            # Check that RandomX is available
            self.assertTrue(RANDOMX_AVAILABLE, "RandomX should be available for testing")

            # Check support function (returns bool)
            support_available = check_randomx_support()
            self.assertIsInstance(support_available, bool, "Support check should return boolean")
            self.assertTrue(support_available, "RandomX support should be available")

            # Check info function (returns dict)
            info = get_randomx_info()
            self.assertIsInstance(info, dict, "RandomX info should be a dictionary")
            self.assertIn("available", info, "Info should include availability")
            self.assertTrue(info["available"], "RandomX should be available in info")

        except ImportError as e:
            self.fail(f"Failed to import RandomX module: {e}")

    def test_randomx_encryption_decryption(self):
        """Test that RandomX is properly used in encryption and decryption."""
        self._check_randomx_available()

        from ..modules.crypt_core import EncryptionAlgorithm, decrypt_file, encrypt_file

        encrypted_file = self.test_file + ".enc"

        try:
            # Encrypt with RandomX and explicit algorithm
            result = encrypt_file(
                self.test_file,
                encrypted_file,
                self.test_password,
                self.safe_randomx_config,
                quiet=True,
                algorithm=EncryptionAlgorithm.AES_GCM,
            )

            self.assertTrue(result, "Encryption should succeed")
            self.assertTrue(os.path.exists(encrypted_file), "Encrypted file should exist")

            # Decrypt the file
            decrypted_file = self.test_file + ".dec"
            result = decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

            self.assertTrue(result, "Decryption should succeed")
            self.assertTrue(os.path.exists(decrypted_file), "Decrypted file should exist")

            # Verify content matches
            with open(self.test_file, "r", encoding="utf-8") as original, open(
                decrypted_file, "r", encoding="utf-8"
            ) as decrypted:
                self.assertEqual(
                    original.read(), decrypted.read(), "Decrypted content should match original"
                )

        except Exception as e:
            if "RandomX requested but not available" in str(e):
                self.skipTest("RandomX library not available")
            else:
                raise

    def test_randomx_metadata_presence(self):
        """Test that RandomX configuration is properly stored in metadata."""
        self._check_randomx_available()

        from ..modules.crypt_core import EncryptionAlgorithm, encrypt_file, extract_file_metadata

        encrypted_file = self.test_file + ".enc"

        try:
            # Encrypt with RandomX
            result = encrypt_file(
                self.test_file,
                encrypted_file,
                self.test_password,
                self.safe_randomx_config,
                quiet=True,
                algorithm=EncryptionAlgorithm.AES_GCM,
            )

            self.assertTrue(result, "Encryption should succeed")

            # Read and verify metadata
            metadata = extract_file_metadata(encrypted_file)
            self.assertIsNotNone(metadata, "Metadata should be present")

            # Check RandomX configuration in nested metadata structure
            self.assertIn("metadata", metadata, "Metadata should contain metadata field")
            inner_metadata = metadata["metadata"]
            self.assertIn(
                "derivation_config",
                inner_metadata,
                "Inner metadata should contain derivation_config",
            )
            self.assertIn(
                "kdf_config",
                inner_metadata["derivation_config"],
                "derivation_config should contain kdf_config",
            )

            # Check RandomX configuration in metadata
            kdf_config = inner_metadata["derivation_config"]["kdf_config"]
            self.assertIn("randomx", kdf_config, "KDF config should contain randomx configuration")

            randomx_config = kdf_config["randomx"]
            self.assertTrue(randomx_config["enabled"], "RandomX should be enabled in metadata")
            self.assertEqual(randomx_config["rounds"], 1, "RandomX rounds should match")
            self.assertEqual(randomx_config["mode"], "light", "RandomX mode should match")

        except Exception as e:
            if "RandomX requested but not available" in str(e):
                self.skipTest("RandomX library not available")
            else:
                raise

    @unittest.mock.patch("sys.stdin.isatty", return_value=True)
    @unittest.mock.patch("builtins.input", return_value="n")
    @unittest.mock.patch("sys.exit")
    def test_security_warning_randomx_no_hashing(self, mock_exit, mock_input, mock_isatty):
        """Test that security warning appears when RandomX is used without prior hashing."""
        self._check_randomx_available()

        from ..modules.crypt_core import encrypt_file

        encrypted_file = self.test_file + ".enc"

        try:
            # Attempt encryption with RandomX but no prior hashing (should trigger warning)
            with self.assertLogs(level="INFO") as cm:
                encrypt_file(
                    self.test_file,
                    encrypted_file,
                    self.test_password,
                    self.randomx_hash_config,  # No prior hashing
                    quiet=False,  # Don't suppress warnings
                )

            # Verify that user was prompted and operation was cancelled
            mock_input.assert_called_once()
            mock_exit.assert_called_once_with(1)

        except Exception as e:
            if "RandomX requested but not available" in str(e):
                self.skipTest("RandomX library not available")
            else:
                # Check if the exit was called due to security warning
                if not mock_exit.called:
                    raise

    @unittest.mock.patch("sys.stdin.isatty", return_value=True)
    @unittest.mock.patch("builtins.input", return_value="y")
    def test_security_warning_randomx_user_accepts(self, mock_input, mock_isatty):
        """Test that encryption proceeds when user accepts security warning."""
        self._check_randomx_available()

        from ..modules.crypt_core import EncryptionAlgorithm, encrypt_file

        encrypted_file = self.test_file + ".enc"

        try:
            # Encrypt with RandomX but no prior hashing, user accepts warning
            result = encrypt_file(
                self.test_file,
                encrypted_file,
                self.test_password,
                self.randomx_hash_config,  # No prior hashing
                quiet=False,  # Don't suppress warnings
                algorithm=EncryptionAlgorithm.AES_GCM,
            )

            self.assertTrue(result, "Encryption should succeed after user acceptance")

            # Verify encryption succeeded
            self.assertTrue(
                os.path.exists(encrypted_file), "Encrypted file should exist after user acceptance"
            )
            mock_input.assert_called_once()

        except Exception as e:
            if "RandomX requested but not available" in str(e):
                self.skipTest("RandomX library not available")
            else:
                raise

    def test_no_security_warning_with_prior_hashing(self):
        """Test that no security warning appears when RandomX is used with prior hashing."""
        self._check_randomx_available()

        from ..modules.crypt_core import EncryptionAlgorithm, encrypt_file

        encrypted_file = self.test_file + ".enc"

        try:
            # This should not trigger any security warnings since we have prior hashing
            with unittest.mock.patch("builtins.input") as mock_input:
                result = encrypt_file(
                    self.test_file,
                    encrypted_file,
                    self.test_password,
                    self.safe_randomx_config,  # Has prior hashing (SHA-512: 100)
                    quiet=False,
                    algorithm=EncryptionAlgorithm.AES_GCM,
                )

                self.assertTrue(result, "Encryption should succeed")

                # Verify no user input was requested (no warning)
                mock_input.assert_not_called()

            self.assertTrue(os.path.exists(encrypted_file), "Encrypted file should exist")

        except Exception as e:
            if "RandomX requested but not available" in str(e):
                self.skipTest("RandomX library not available")
            else:
                raise


class TestAEADBinding(unittest.TestCase):
    """
    Tests for AEAD (Authenticated Encryption with Associated Data) binding.

    These tests verify that:
    1. AEAD algorithms properly bind metadata via AAD
    2. Non-AEAD algorithms use hash-based verification
    3. Metadata tampering is detected for both types
    4. Backward compatibility is maintained
    """

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.test_files = []

    def tearDown(self):
        """Clean up test files."""
        for test_file in self.test_files:
            if os.path.exists(test_file):
                try:
                    os.unlink(test_file)
                except Exception:
                    pass
        if os.path.exists(self.test_dir):
            try:
                shutil.rmtree(self.test_dir)
            except Exception:
                pass

    def test_pure_aead_algorithm_detection(self):
        """Test that pure AEAD algorithms are correctly identified."""
        aead_algorithms = [
            EncryptionAlgorithm.AES_GCM,
            EncryptionAlgorithm.AES_GCM_SIV,
            EncryptionAlgorithm.AES_SIV,
            EncryptionAlgorithm.CHACHA20_POLY1305,
            EncryptionAlgorithm.XCHACHA20_POLY1305,
        ]
        for algo in aead_algorithms:
            self.assertTrue(is_aead_algorithm(algo), f"{algo.value} should be AEAD")

    def test_pqc_hybrid_algorithm_detection(self):
        """Test that PQC hybrid algorithms are correctly identified as AEAD."""
        pqc_algorithms = [
            EncryptionAlgorithm.ML_KEM_512_HYBRID,
            EncryptionAlgorithm.ML_KEM_768_HYBRID,
            EncryptionAlgorithm.ML_KEM_1024_HYBRID,
            EncryptionAlgorithm.ML_KEM_512_CHACHA20,
            EncryptionAlgorithm.ML_KEM_768_CHACHA20,
            EncryptionAlgorithm.ML_KEM_1024_CHACHA20,
            EncryptionAlgorithm.HQC_128_HYBRID,
            EncryptionAlgorithm.HQC_192_HYBRID,
            EncryptionAlgorithm.HQC_256_HYBRID,
            EncryptionAlgorithm.MAYO_1_HYBRID,
            EncryptionAlgorithm.MAYO_3_HYBRID,
            EncryptionAlgorithm.MAYO_5_HYBRID,
            EncryptionAlgorithm.CROSS_128_HYBRID,
            EncryptionAlgorithm.CROSS_192_HYBRID,
            EncryptionAlgorithm.CROSS_256_HYBRID,
        ]
        for algo in pqc_algorithms:
            self.assertTrue(
                is_aead_algorithm(algo),
                f"{algo.value} should be AEAD (uses AEAD for symmetric layer)",
            )

    def test_non_aead_algorithm_detection(self):
        """Test that non-AEAD algorithms are correctly identified."""
        non_aead_algorithms = [
            EncryptionAlgorithm.FERNET,
        ]
        for algo in non_aead_algorithms:
            self.assertFalse(is_aead_algorithm(algo), f"{algo.value} should NOT be AEAD")

    def test_aead_metadata_has_binding_marker(self):
        """Test that AEAD-encrypted files have aead_binding marker."""
        input_file = os.path.join(self.test_dir, "input.txt")
        encrypted_file = os.path.join(self.test_dir, "encrypted.bin")
        self.test_files.extend([input_file, encrypted_file])

        # Create test file
        with open(input_file, "w", encoding="utf-8") as f:
            f.write("test data")

        # Encrypt with AEAD algorithm
        encrypt_file(
            input_file,
            encrypted_file,
            b"password",
            algorithm=EncryptionAlgorithm.AES_GCM,
            quiet=True,
        )

        # Read and parse metadata
        with open(encrypted_file, "rb") as f:
            content = f.read()
        metadata_b64, _ = content.split(b":", 1)
        metadata = json.loads(base64.b64decode(metadata_b64))

        # Check for AEAD binding marker
        self.assertIn("aead_binding", metadata, "AEAD file should have aead_binding field")
        self.assertTrue(metadata["aead_binding"], "aead_binding should be True")

        # Check that encrypted_hash is NOT present
        self.assertNotIn(
            "encrypted_hash", metadata.get("hashes", {}), "AEAD file should not have encrypted_hash"
        )

        # Check that original_hash IS present
        self.assertIn(
            "original_hash", metadata.get("hashes", {}), "AEAD file should have original_hash"
        )

    def test_non_aead_metadata_has_encrypted_hash(self):
        """Test that non-AEAD-encrypted files have encrypted_hash."""
        input_file = os.path.join(self.test_dir, "input.txt")
        encrypted_file = os.path.join(self.test_dir, "encrypted.bin")
        self.test_files.extend([input_file, encrypted_file])

        # Create test file
        with open(input_file, "w", encoding="utf-8") as f:
            f.write("test data")

        # Encrypt with non-AEAD algorithm
        encrypt_file(
            input_file,
            encrypted_file,
            b"password",
            algorithm=EncryptionAlgorithm.FERNET,
            quiet=True,
        )

        # Read and parse metadata
        with open(encrypted_file, "rb") as f:
            content = f.read()
        metadata_b64, _ = content.split(b":", 1)
        metadata = json.loads(base64.b64decode(metadata_b64))

        # Check that aead_binding is NOT present or False
        aead_binding = metadata.get("aead_binding", False)
        self.assertFalse(aead_binding, "Non-AEAD file should not have aead_binding=True")

        # Check that encrypted_hash IS present
        self.assertIn(
            "encrypted_hash", metadata.get("hashes", {}), "Non-AEAD file should have encrypted_hash"
        )

        # Check that original_hash IS present
        self.assertIn(
            "original_hash", metadata.get("hashes", {}), "Non-AEAD file should have original_hash"
        )

    def test_aead_metadata_tampering_detected(self):
        """Test that tampering AEAD metadata causes decryption failure."""
        input_file = os.path.join(self.test_dir, "input.txt")
        encrypted_file = os.path.join(self.test_dir, "encrypted.bin")
        output_file = os.path.join(self.test_dir, "output.txt")
        self.test_files.extend([input_file, encrypted_file, output_file])

        # Create test file
        with open(input_file, "w", encoding="utf-8") as f:
            f.write("test data for tampering")

        # Encrypt with AEAD algorithm
        encrypt_file(
            input_file,
            encrypted_file,
            b"password",
            algorithm=EncryptionAlgorithm.AES_GCM,
            quiet=True,
        )

        # Read encrypted file
        with open(encrypted_file, "rb") as f:
            content = f.read()
        metadata_b64, encrypted_data = content.split(b":", 1)

        # Tamper with metadata (add a fake field)
        metadata = json.loads(base64.b64decode(metadata_b64))
        metadata["tampered"] = True
        tampered_metadata_b64 = base64.b64encode(json.dumps(metadata).encode("utf-8"))

        # Write tampered file
        with open(encrypted_file, "wb") as f:
            f.write(tampered_metadata_b64 + b":" + encrypted_data)

        # Attempt to decrypt - should fail due to AAD mismatch
        with self.assertRaises(Exception):  # Should raise authentication error
            decrypt_file(
                encrypted_file,
                output_file,
                b"password",
                quiet=True,
            )

    def test_aead_algorithms_encrypt_and_decrypt(self):
        """Test that each AEAD algorithm properly encrypts and decrypts with AAD."""
        algorithms = [
            EncryptionAlgorithm.AES_GCM,
            EncryptionAlgorithm.CHACHA20_POLY1305,
            EncryptionAlgorithm.XCHACHA20_POLY1305,
            EncryptionAlgorithm.AES_GCM_SIV,
            EncryptionAlgorithm.AES_SIV,
            # AES_OCB3 is blocked for encryption (deprecated), so excluded from this test
        ]

        for algorithm in algorithms:
            with self.subTest(algorithm=algorithm.value):
                input_file = os.path.join(self.test_dir, f"input_{algorithm.value}.txt")
                encrypted_file = os.path.join(self.test_dir, f"encrypted_{algorithm.value}.bin")
                output_file = os.path.join(self.test_dir, f"output_{algorithm.value}.txt")
                self.test_files.extend([input_file, encrypted_file, output_file])

                # Create test file
                test_data = f"test data for {algorithm.value}"
                with open(input_file, "w", encoding="utf-8") as f:
                    f.write(test_data)

                # Encrypt
                encrypt_file(
                    input_file,
                    encrypted_file,
                    b"password",
                    algorithm=algorithm,
                    quiet=True,
                )

                # Verify metadata has AEAD binding
                with open(encrypted_file, "rb") as f:
                    content = f.read()
                metadata_b64, _ = content.split(b":", 1)
                metadata = json.loads(base64.b64decode(metadata_b64))
                self.assertTrue(
                    metadata.get("aead_binding"), f"{algorithm.value} should use AEAD binding"
                )

                # Decrypt
                decrypt_file(
                    encrypted_file,
                    output_file,
                    b"password",
                    quiet=True,
                )

                # Verify content matches
                with open(output_file, "r", encoding="utf-8") as f:
                    decrypted_data = f.read()
                self.assertEqual(decrypted_data, test_data, f"{algorithm.value} decryption failed")
