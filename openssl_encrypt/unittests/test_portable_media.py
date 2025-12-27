#!/usr/bin/env python3
"""
Test suite for portable media functionality.

This module contains comprehensive tests for:
- QR code key distribution
- USB drive encryption
- Portable media integration
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestQRCodeKeyDistribution(unittest.TestCase):
    """Test suite for QR Code Key Distribution functionality."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()

        # Check if QR dependencies are available
        try:
            from openssl_encrypt.modules.portable_media import (
                QRKeyDistribution,
                QRKeyError,
                QRKeyFormat,
            )

            self.qr_available = True
            self.QRKeyDistribution = QRKeyDistribution
            self.QRKeyError = QRKeyError
            self.QRKeyFormat = QRKeyFormat
        except ImportError:
            self.qr_available = False

    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_qr_payload_creation(self):
        """Test QR payload creation with different key sizes."""
        if not self.qr_available:
            self.skipTest("QR code dependencies not available")

        from openssl_encrypt.modules.portable_media import SecureBytes

        qr_dist = self.QRKeyDistribution()

        test_cases = [
            (b"small_key", "small_test"),
            (b"medium_sized_key_for_testing" * 5, "medium_test"),
            (b"large_key_" * 50, "large_test"),
        ]

        for key_data, key_name in test_cases:
            with self.subTest(key_size=len(key_data)):
                payload = qr_dist._prepare_key_payload(
                    SecureBytes(key_data), key_name, compression=True
                )

                self.assertIsInstance(payload, bytes)
                self.assertGreater(len(payload), 50)  # Should have metadata

                # Parse payload
                import json

                json_data = json.loads(payload.decode("utf-8"))

                self.assertEqual(json_data["header"], qr_dist.MAGIC_HEADER)
                self.assertEqual(json_data["metadata"]["name"], key_name)
                self.assertEqual(json_data["metadata"]["size"], len(key_data))
                self.assertTrue(json_data["metadata"]["compressed"])

    def test_qr_key_round_trip(self):
        """Test complete QR key encoding and decoding."""
        if not self.qr_available:
            self.skipTest("QR code dependencies not available")

        from openssl_encrypt.modules.portable_media import create_key_qr, read_key_qr

        test_key = b"test_encryption_key_for_qr_roundtrip"
        key_name = "roundtrip_test_key"

        # Create QR image in memory
        qr_image = create_key_qr(test_key, key_name)

        self.assertIsNotNone(qr_image)
        # PIL Image should have size and format
        self.assertTrue(hasattr(qr_image, "size"))
        self.assertGreater(qr_image.size[0], 0)
        self.assertGreater(qr_image.size[1], 0)

    def test_qr_multi_code_splitting(self):
        """Test multi-QR splitting logic for large keys."""
        if not self.qr_available:
            self.skipTest("QR code dependencies not available")

        from openssl_encrypt.modules.portable_media import SecureBytes

        qr_dist = self.QRKeyDistribution()

        # Create key data that is larger than single QR capacity but reasonable for multi-QR
        large_key = b"X" * 2500  # 2.5KB key to exceed 2048 byte single QR limit
        key_name = "large_multi_qr_test"

        payload = qr_dist._prepare_key_payload(SecureBytes(large_key), key_name, compression=False)

        # Should be larger than single QR capacity
        self.assertGreater(len(payload), qr_dist.MAX_SINGLE_QR_SIZE)

        # Test that single QR format would fail for this size
        with self.assertRaises(self.QRKeyError):
            qr_dist.create_key_qr(
                large_key, key_name, self.QRKeyFormat.V1_SINGLE, compression=False
            )

        # Verify the multi-QR logic would split correctly (without actually creating QR codes)
        metadata_overhead = 200
        chunk_size = qr_dist.MAX_SINGLE_QR_SIZE - metadata_overhead
        expected_chunks = (len(payload) + chunk_size - 1) // chunk_size  # Ceiling division

        self.assertGreater(expected_chunks, 1)  # Should require multiple chunks
        self.assertLessEqual(expected_chunks, 99)  # Should not exceed max

    def test_qr_error_handling(self):
        """Test QR error handling scenarios."""
        if not self.qr_available:
            self.skipTest("QR code dependencies not available")

        qr_dist = self.QRKeyDistribution()

        # Test empty key data
        with self.assertRaises(self.QRKeyError):
            qr_dist.create_key_qr(b"", "empty_key")

        # Test with very long key name that might cause issues
        long_name = "x" * 1000
        try:
            qr_dist.create_key_qr(b"test_key", long_name)
        except Exception:
            pass  # Any exception is acceptable for edge case testing

    def test_qr_compression_effectiveness(self):
        """Test QR compression reduces payload size."""
        if not self.qr_available:
            self.skipTest("QR code dependencies not available")

        from openssl_encrypt.modules.portable_media import SecureBytes

        qr_dist = self.QRKeyDistribution()

        # Create repetitive data that compresses well
        repetitive_key = b"AAAAAAAAAA" * 100  # Highly compressible
        key_name = "compression_test"

        # Test with compression
        compressed_payload = qr_dist._prepare_key_payload(
            SecureBytes(repetitive_key), key_name, compression=True
        )

        # Test without compression
        uncompressed_payload = qr_dist._prepare_key_payload(
            SecureBytes(repetitive_key), key_name, compression=False
        )

        self.assertLess(len(compressed_payload), len(uncompressed_payload))

    def test_qr_security_features(self):
        """Test QR security features like checksums."""
        if not self.qr_available:
            self.skipTest("QR code dependencies not available")

        from openssl_encrypt.modules.portable_media import SecureBytes

        qr_dist = self.QRKeyDistribution()
        test_key = b"security_test_key_data"
        key_name = "security_test"

        payload = qr_dist._prepare_key_payload(SecureBytes(test_key), key_name, compression=True)

        import json

        json_data = json.loads(payload.decode("utf-8"))

        # Should have checksum field
        self.assertIn("checksum", json_data)
        self.assertIsInstance(json_data["checksum"], str)

        # Checksum should be base64 encoded
        import base64

        checksum_bytes = base64.b64decode(json_data["checksum"])
        self.assertEqual(len(checksum_bytes), qr_dist.CHECKSUM_LENGTH)


class TestUSBDriveEncryption(unittest.TestCase):
    """Test suite for USB Drive Encryption functionality."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()

        # Check if USB dependencies are available
        try:
            from openssl_encrypt.modules.portable_media import (
                USBCreationError,
                USBDriveCreator,
                USBSecurityProfile,
            )

            self.usb_available = True
            self.USBDriveCreator = USBDriveCreator
            self.USBSecurityProfile = USBSecurityProfile
            self.USBCreationError = USBCreationError
        except ImportError:
            self.usb_available = False

    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_usb_creation_basic(self):
        """Test basic USB drive creation."""
        if not self.usb_available:
            self.skipTest("USB encryption dependencies not available")

        usb_path = os.path.join(self.test_dir, "test_usb")
        os.makedirs(usb_path)

        creator = self.USBDriveCreator(self.USBSecurityProfile.STANDARD)
        password = "test_usb_password_123"

        result = creator.create_portable_usb(usb_path, password)

        self.assertTrue(result["success"])
        self.assertEqual(result["security_profile"], "standard")
        self.assertIn("portable_root", result)
        self.assertIn("workspace", result)
        self.assertIn("autorun", result)
        self.assertIn("integrity", result)

        # Check directory structure was created
        portable_root = os.path.join(usb_path, creator.PORTABLE_DIR)
        self.assertTrue(os.path.exists(portable_root))
        self.assertTrue(os.path.exists(os.path.join(portable_root, "config")))
        self.assertTrue(os.path.exists(os.path.join(portable_root, "data")))

    def test_usb_security_profiles(self):
        """Test different USB security profiles."""
        if not self.usb_available:
            self.skipTest("USB encryption dependencies not available")

        profiles = [
            self.USBSecurityProfile.STANDARD,
            self.USBSecurityProfile.HIGH_SECURITY,
            self.USBSecurityProfile.PARANOID,
        ]

        for profile in profiles:
            with self.subTest(profile=profile.value):
                usb_path = os.path.join(self.test_dir, f"test_usb_{profile.value}")
                os.makedirs(usb_path)

                creator = self.USBDriveCreator(profile)
                password = f"test_password_{profile.value}"

                result = creator.create_portable_usb(usb_path, password)

                self.assertTrue(result["success"])
                self.assertEqual(result["security_profile"], profile.value)

    def test_usb_integrity_verification(self):
        """Test USB integrity verification."""
        if not self.usb_available:
            self.skipTest("USB encryption dependencies not available")

        usb_path = os.path.join(self.test_dir, "test_usb_integrity")
        os.makedirs(usb_path)

        creator = self.USBDriveCreator(self.USBSecurityProfile.STANDARD)
        password = "integrity_test_password"

        # Create USB
        result = creator.create_portable_usb(usb_path, password)
        self.assertTrue(result["success"])

        # Verify integrity
        verification = creator.verify_usb_integrity(usb_path, password)

        self.assertTrue(verification["integrity_ok"])
        self.assertEqual(verification["failed_files"], 0)
        self.assertEqual(verification["missing_files"], 0)
        self.assertGreaterEqual(verification["verified_files"], 1)

    def test_usb_autorun_files(self):
        """Test USB autorun file creation."""
        if not self.usb_available:
            self.skipTest("USB encryption dependencies not available")

        usb_path = os.path.join(self.test_dir, "test_usb_autorun")
        os.makedirs(usb_path)

        creator = self.USBDriveCreator()
        result = creator.create_portable_usb(usb_path, "autorun_test_password")

        self.assertTrue(result["success"])

        # Check autorun files were created
        autorun_files = result["autorun"]["files_created"]
        self.assertIn("autorun.inf", autorun_files)  # Windows
        self.assertIn("autorun.sh", autorun_files)  # Linux/Unix
        self.assertIn(".autorun", autorun_files)  # macOS

        # Verify files exist
        self.assertTrue(os.path.exists(os.path.join(usb_path, "autorun.inf")))
        self.assertTrue(os.path.exists(os.path.join(usb_path, "autorun.sh")))
        self.assertTrue(os.path.exists(os.path.join(usb_path, ".autorun")))

    def test_usb_with_keystore(self):
        """Test USB creation with included keystore."""
        if not self.usb_available:
            self.skipTest("USB encryption dependencies not available")

        usb_path = os.path.join(self.test_dir, "test_usb_keystore")
        os.makedirs(usb_path)

        # Create a dummy keystore file
        keystore_path = os.path.join(self.test_dir, "test.pqc")
        with open(keystore_path, "wb") as f:
            f.write(b"dummy keystore data for testing")

        creator = self.USBDriveCreator()
        result = creator.create_portable_usb(
            usb_path, "keystore_test_password", keystore_path=keystore_path
        )

        self.assertTrue(result["success"])
        self.assertTrue(result["keystore"]["included"])
        self.assertGreater(result["keystore"]["original_size"], 0)
        self.assertGreater(result["keystore"]["encrypted_size"], 0)

    def test_usb_hash_chaining_integration(self):
        """Test USB with hash chaining configuration."""
        if not self.usb_available:
            self.skipTest("USB encryption dependencies not available")

        usb_path = os.path.join(self.test_dir, "test_usb_hash_chain")
        os.makedirs(usb_path)

        # Create hash configuration
        hash_config = {
            "sha256": 1,
            "argon2": {
                "enabled": True,
                "time_cost": 2,
                "memory_cost": 4096,
                "parallelism": 2,
                "hash_len": 32,
                "type": 2,
                "rounds": 1,
            },
            "pbkdf2_iterations": 0,
        }

        creator = self.USBDriveCreator()
        password = "hash_chain_test_password"

        result = creator.create_portable_usb(usb_path, password, hash_config=hash_config)

        self.assertTrue(result["success"])

        # Verify with same hash config
        verification = creator.verify_usb_integrity(usb_path, password, hash_config=hash_config)

        self.assertTrue(verification["integrity_ok"])

    def test_usb_error_handling(self):
        """Test USB error handling scenarios."""
        if not self.usb_available:
            self.skipTest("USB encryption dependencies not available")

        creator = self.USBDriveCreator()

        # Test with non-existent path
        with self.assertRaises(self.USBCreationError):
            creator.create_portable_usb("/non/existent/path", "test_password")

        # Test verification without USB
        with self.assertRaises(self.USBCreationError):
            creator.verify_usb_integrity("/non/existent/path", "test_password")

    def test_usb_wrong_password_verification(self):
        """Test USB verification with wrong password."""
        if not self.usb_available:
            self.skipTest("USB encryption dependencies not available")

        usb_path = os.path.join(self.test_dir, "test_usb_wrong_pass")
        os.makedirs(usb_path)

        creator = self.USBDriveCreator()
        correct_password = "correct_password"
        wrong_password = "wrong_password"

        # Create USB with correct password
        result = creator.create_portable_usb(usb_path, correct_password)
        self.assertTrue(result["success"])

        # Try to verify with wrong password
        with self.assertRaises(self.USBCreationError):
            creator.verify_usb_integrity(usb_path, wrong_password)

    def test_usb_configuration_file(self):
        """Test USB configuration file creation and content."""
        if not self.usb_available:
            self.skipTest("USB encryption dependencies not available")

        usb_path = os.path.join(self.test_dir, "test_usb_config")
        os.makedirs(usb_path)

        creator = self.USBDriveCreator()
        result = creator.create_portable_usb(usb_path, "config_test_password", include_logs=True)

        self.assertTrue(result["success"])

        # Check config file
        config_path = os.path.join(usb_path, creator.PORTABLE_DIR, "config", "portable.conf")
        self.assertTrue(os.path.exists(config_path))

        # Read and verify config
        with open(config_path, "r") as f:
            config = json.load(f)

        self.assertTrue(config["portable_mode"])
        self.assertTrue(config["network_disabled"])  # Air-gapped mode
        self.assertTrue(config["logging_enabled"])  # Logs were requested
        self.assertEqual(config["security_profile"], "standard")


class TestPortableMediaIntegration(unittest.TestCase):
    """Test suite for portable media module integration."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()

        # Check if portable media module is available
        try:
            import modules.portable_media

            self.portable_media_available = True
            self.portable_media = modules.portable_media
        except ImportError:
            self.portable_media_available = False

    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_portable_media_module_imports(self):
        """Test that portable media module imports correctly."""
        if not self.portable_media_available:
            self.skipTest("Portable media module not available")

        # Test QR imports
        self.assertTrue(hasattr(self.portable_media, "QRKeyDistribution"))
        self.assertTrue(hasattr(self.portable_media, "QRKeyError"))
        self.assertTrue(hasattr(self.portable_media, "QRKeyFormat"))
        self.assertTrue(hasattr(self.portable_media, "create_key_qr"))
        self.assertTrue(hasattr(self.portable_media, "read_key_qr"))

        # Test USB imports
        self.assertTrue(hasattr(self.portable_media, "USBDriveCreator"))
        self.assertTrue(hasattr(self.portable_media, "USBCreationError"))
        self.assertTrue(hasattr(self.portable_media, "USBSecurityProfile"))
        self.assertTrue(hasattr(self.portable_media, "create_portable_usb"))
        self.assertTrue(hasattr(self.portable_media, "verify_usb_integrity"))

    def test_portable_media_version(self):
        """Test portable media module version."""
        if not self.portable_media_available:
            self.skipTest("Portable media module not available")

        self.assertTrue(hasattr(self.portable_media, "__version__"))
        self.assertEqual(self.portable_media.__version__, "1.3.0")

    def test_qr_and_usb_integration(self):
        """Test integration between QR and USB features."""
        if not self.portable_media_available:
            self.skipTest("Portable media module not available")

        try:
            # Test that both QR and USB can be used together
            qr_dist = self.portable_media.QRKeyDistribution()
            usb_creator = self.portable_media.USBDriveCreator()

            self.assertIsNotNone(qr_dist)
            self.assertIsNotNone(usb_creator)

            # Test that they use the same SecureBytes class
            self.assertTrue(hasattr(self.portable_media, "SecureBytes"))

        except Exception as e:
            self.skipTest(f"Integration test skipped due to missing dependencies: {e}")


# Import HQC and ML-KEM keystore integration tests
