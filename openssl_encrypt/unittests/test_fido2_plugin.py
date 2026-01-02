"""
Unit tests for FIDO2 HSM Pepper Plugin.

These tests verify the FIDO2 plugin functionality without requiring actual
FIDO2 hardware. Tests use mocks for hardware interactions to enable CI/CD testing.
"""

import json
import os
import secrets
import unittest
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime

# Mock FIDO2 availability before import
import sys
sys.modules['fido2'] = MagicMock()
sys.modules['fido2.hid'] = MagicMock()
sys.modules['fido2.client'] = MagicMock()
sys.modules['fido2.webauthn'] = MagicMock()
sys.modules['fido2.ctap2'] = MagicMock()
sys.modules['fido2.ctap2.extensions'] = MagicMock()

from openssl_encrypt.plugins.hsm.fido2_pepper import FIDO2HSMPlugin
from openssl_encrypt.modules.plugin_system.plugin_base import (
    PluginResult,
    PluginSecurityContext,
    PluginCapability,
)


class TestFIDO2CredentialStorage(unittest.TestCase):
    """Test credential storage and loading functionality."""

    def setUp(self):
        """Set up test environment with temporary config directory."""
        self.test_dir = Path("/tmp/test_fido2_plugin")
        self.test_dir.mkdir(exist_ok=True)
        self.credential_file = self.test_dir / "credentials.json"

        # Clean up any existing test file
        if self.credential_file.exists():
            self.credential_file.unlink()

        self.plugin = FIDO2HSMPlugin(credential_file=self.credential_file)

    def tearDown(self):
        """Clean up test files."""
        if self.credential_file.exists():
            self.credential_file.unlink()
        if self.test_dir.exists():
            self.test_dir.rmdir()

    def test_credential_storage_roundtrip(self):
        """Test saving and loading credentials."""
        # Create test credential data
        credential_data = {
            "id": "primary",
            "credential_id": "dGVzdF9jcmVkZW50aWFsX2lk",  # base64 encoded
            "created_at": "2026-01-02T12:00:00Z",
            "authenticator_aaguid": "12345678-1234-1234-1234-123456789012",
            "description": "Test YubiKey",
            "is_backup": False,
        }

        # Save credential
        self.plugin._save_credential(credential_data)

        # Verify file exists with correct permissions
        self.assertTrue(self.credential_file.exists())
        file_stat = os.stat(self.credential_file)
        file_mode = file_stat.st_mode & 0o777
        self.assertEqual(file_mode, 0o600, "Credential file should have 0o600 permissions")

        # Load credentials
        loaded_credentials = self.plugin._load_credentials()

        # Verify loaded data matches saved data
        self.assertEqual(len(loaded_credentials), 1)
        self.assertEqual(loaded_credentials[0]["id"], credential_data["id"])
        self.assertEqual(loaded_credentials[0]["credential_id"], credential_data["credential_id"])
        self.assertEqual(loaded_credentials[0]["description"], credential_data["description"])

    def test_multiple_credentials(self):
        """Test storing multiple credentials (primary + backups)."""
        # Save primary credential
        primary = {
            "id": "primary",
            "credential_id": "cHJpbWFyeQ==",
            "created_at": "2026-01-02T12:00:00Z",
            "authenticator_aaguid": "aaaa-bbbb-cccc-dddd",
            "description": "Primary YubiKey",
            "is_backup": False,
        }
        self.plugin._save_credential(primary)

        # Save backup credential
        backup = {
            "id": "backup-1",
            "credential_id": "YmFja3VwMQ==",
            "created_at": "2026-01-03T10:00:00Z",
            "authenticator_aaguid": "1111-2222-3333-4444",
            "description": "Backup Nitrokey",
            "is_backup": True,
        }
        self.plugin._save_credential(backup)

        # Load and verify both credentials
        credentials = self.plugin._load_credentials()
        self.assertEqual(len(credentials), 2)

        # Verify primary
        primary_cred = next(c for c in credentials if c["id"] == "primary")
        self.assertFalse(primary_cred["is_backup"])

        # Verify backup
        backup_cred = next(c for c in credentials if c["id"] == "backup-1")
        self.assertTrue(backup_cred["is_backup"])

    def test_load_nonexistent_credentials(self):
        """Test loading credentials when file doesn't exist."""
        credentials = self.plugin._load_credentials()
        self.assertEqual(credentials, [])

    def test_is_registered(self):
        """Test checking registration status."""
        # Initially not registered
        self.assertFalse(self.plugin.is_registered())

        # Save a credential
        credential_data = {
            "id": "primary",
            "credential_id": "dGVzdA==",
            "created_at": "2026-01-02T12:00:00Z",
            "authenticator_aaguid": "test-aaguid",
            "description": "Test Device",
            "is_backup": False,
        }
        self.plugin._save_credential(credential_data)

        # Now registered
        self.assertTrue(self.plugin.is_registered())


class TestFIDO2PluginInitialization(unittest.TestCase):
    """Test plugin initialization and configuration."""

    def setUp(self):
        """Set up test environment."""
        self.plugin = FIDO2HSMPlugin()

    def test_plugin_metadata(self):
        """Test plugin metadata attributes."""
        self.assertEqual(self.plugin.plugin_id, "fido2_hsm")
        self.assertEqual(self.plugin.name, "FIDO2 hmac-secret HSM")
        self.assertEqual(self.plugin.version, "1.0.0")

    def test_required_capabilities(self):
        """Test required plugin capabilities."""
        capabilities = self.plugin.get_required_capabilities()
        self.assertIn(PluginCapability.ACCESS_CONFIG, capabilities)
        self.assertIn(PluginCapability.WRITE_LOGS, capabilities)

    def test_description(self):
        """Test plugin description."""
        description = self.plugin.get_description()
        self.assertIn("FIDO2", description)
        self.assertIn("hmac-secret", description)
        self.assertIn("hardware-bound", description)

    def test_custom_rp_id(self):
        """Test plugin initialization with custom RP ID."""
        custom_rp_id = "custom-app.example.com"
        plugin = FIDO2HSMPlugin(rp_id=custom_rp_id)
        self.assertEqual(plugin.rp_id, custom_rp_id)

    def test_default_rp_id(self):
        """Test plugin initialization with default RP ID."""
        plugin = FIDO2HSMPlugin()
        self.assertEqual(plugin.rp_id, FIDO2HSMPlugin.DEFAULT_RP_ID)

    def test_initialize_success(self):
        """Test successful plugin initialization."""
        result = self.plugin.initialize()
        self.assertTrue(result.success)
        self.assertIn("initialized", result.message.lower())


class TestFIDO2PepperValidation(unittest.TestCase):
    """Test pepper derivation validation."""

    def setUp(self):
        """Set up test environment with mock device."""
        self.test_dir = Path("/tmp/test_fido2_plugin")
        self.test_dir.mkdir(exist_ok=True)
        self.credential_file = self.test_dir / "credentials.json"

        # Clean up any existing test file
        if self.credential_file.exists():
            self.credential_file.unlink()

        self.plugin = FIDO2HSMPlugin(credential_file=self.credential_file)

    def tearDown(self):
        """Clean up test files."""
        if self.credential_file.exists():
            self.credential_file.unlink()
        if self.test_dir.exists():
            self.test_dir.rmdir()

    def test_invalid_salt_length_short(self):
        """Test rejection of salt that's too short."""
        context = PluginSecurityContext(
            plugin_id=self.plugin.plugin_id,
            capabilities=self.plugin.get_required_capabilities()
        )

        # Try with 8-byte salt (should be 16 bytes)
        short_salt = secrets.token_bytes(8)
        result = self.plugin.get_hsm_pepper(short_salt, context)

        self.assertFalse(result.success)
        self.assertIn("salt length", result.message.lower())

    def test_invalid_salt_length_long(self):
        """Test rejection of salt that's too long."""
        context = PluginSecurityContext(
            plugin_id=self.plugin.plugin_id,
            capabilities=self.plugin.get_required_capabilities()
        )

        # Try with 32-byte salt (should be 16 bytes)
        long_salt = secrets.token_bytes(32)
        result = self.plugin.get_hsm_pepper(long_salt, context)

        self.assertFalse(result.success)
        self.assertIn("salt length", result.message.lower())

    def test_no_credentials_registered(self):
        """Test error when no credentials are registered."""
        context = PluginSecurityContext(
            plugin_id=self.plugin.plugin_id,
            capabilities=self.plugin.get_required_capabilities()
        )

        # Valid salt but no credentials
        salt = secrets.token_bytes(16)
        result = self.plugin.get_hsm_pepper(salt, context)

        self.assertFalse(result.success)
        self.assertIn("no fido2 credentials", result.message.lower())


class TestFIDO2MockPepperDerivation(unittest.TestCase):
    """Test pepper derivation with mocked FIDO2 operations."""

    def setUp(self):
        """Set up test environment with mock device and credentials."""
        self.test_dir = Path("/tmp/test_fido2_plugin")
        self.test_dir.mkdir(exist_ok=True)
        self.credential_file = self.test_dir / "credentials.json"

        # Clean up any existing test file
        if self.credential_file.exists():
            self.credential_file.unlink()

        self.plugin = FIDO2HSMPlugin(credential_file=self.credential_file)

        # Create test credential
        credential_data = {
            "id": "primary",
            "credential_id": "dGVzdF9jcmVkZW50aWFsX2lk",
            "created_at": "2026-01-02T12:00:00Z",
            "authenticator_aaguid": "test-aaguid",
            "description": "Test Device",
            "is_backup": False,
        }
        self.plugin._save_credential(credential_data)

    def tearDown(self):
        """Clean up test files."""
        if self.credential_file.exists():
            self.credential_file.unlink()
        if self.test_dir.exists():
            self.test_dir.rmdir()

    @patch('openssl_encrypt.plugins.hsm.fido2_pepper.CtapHidDevice')
    @patch('openssl_encrypt.plugins.hsm.fido2_pepper.Fido2Client')
    @patch('openssl_encrypt.plugins.hsm.fido2_pepper.Ctap2')
    def test_mock_pepper_derivation(self, mock_ctap2, mock_client_class, mock_device_class):
        """Test successful pepper derivation with mocked FIDO2."""
        # Mock device detection
        mock_device = Mock()
        mock_device_class.list_devices.return_value = [mock_device]

        # Mock hmac-secret support check
        mock_info = Mock()
        mock_info.extensions = ['hmac-secret']
        mock_ctap2.return_value.get_info.return_value = mock_info

        # Mock FIDO2 client and assertion
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Mock assertion result with hmac-secret output (v1.2+ API)
        mock_auth_response = Mock()
        mock_auth_response.client_extension_results = {
            "hmac-secret": {
                "output1": secrets.token_bytes(32)  # 32-byte pepper
            }
        }
        mock_assertion_selection = Mock()
        mock_assertion_selection.get_response.return_value = mock_auth_response
        mock_client.get_assertion.return_value = mock_assertion_selection

        # Test pepper derivation
        context = PluginSecurityContext(
            plugin_id=self.plugin.plugin_id,
            capabilities=self.plugin.get_required_capabilities()
        )
        salt = secrets.token_bytes(16)
        result = self.plugin.get_hsm_pepper(salt, context)

        # Verify success
        self.assertTrue(result.success)
        self.assertIn("hsm_pepper", result.data)

        # Verify pepper properties
        pepper = result.data["hsm_pepper"]
        self.assertEqual(len(pepper), 32, "Pepper should be 32 bytes")
        self.assertIsInstance(pepper, bytes)


class TestFIDO2Unregister(unittest.TestCase):
    """Test credential removal functionality."""

    def setUp(self):
        """Set up test environment with test credentials."""
        self.test_dir = Path("/tmp/test_fido2_plugin")
        self.test_dir.mkdir(exist_ok=True)
        self.credential_file = self.test_dir / "credentials.json"

        # Clean up any existing test file
        if self.credential_file.exists():
            self.credential_file.unlink()

        self.plugin = FIDO2HSMPlugin(credential_file=self.credential_file)

        # Create test credentials
        primary = {
            "id": "primary",
            "credential_id": "cHJpbWFyeQ==",
            "created_at": "2026-01-02T12:00:00Z",
            "authenticator_aaguid": "aaaa-bbbb",
            "description": "Primary",
            "is_backup": False,
        }
        self.plugin._save_credential(primary)

        backup = {
            "id": "backup-1",
            "credential_id": "YmFja3VwMQ==",
            "created_at": "2026-01-03T10:00:00Z",
            "authenticator_aaguid": "1111-2222",
            "description": "Backup",
            "is_backup": True,
        }
        self.plugin._save_credential(backup)

    def tearDown(self):
        """Clean up test files."""
        if self.credential_file.exists():
            self.credential_file.unlink()
        if self.test_dir.exists():
            self.test_dir.rmdir()

    def test_unregister_specific_credential(self):
        """Test removing a specific credential."""
        # Initially have 2 credentials
        credentials = self.plugin._load_credentials()
        self.assertEqual(len(credentials), 2)

        # Remove primary
        result = self.plugin.unregister(credential_id="primary")
        self.assertTrue(result.success)

        # Should have 1 credential remaining (backup)
        credentials = self.plugin._load_credentials()
        self.assertEqual(len(credentials), 1)
        self.assertEqual(credentials[0]["id"], "backup-1")

    def test_unregister_all_credentials(self):
        """Test removing all credentials."""
        # Initially have 2 credentials
        credentials = self.plugin._load_credentials()
        self.assertEqual(len(credentials), 2)

        # Remove all
        result = self.plugin.unregister(remove_all=True)
        self.assertTrue(result.success)

        # Credential file should be deleted
        self.assertFalse(self.credential_file.exists())

        # Plugin should report not registered
        self.assertFalse(self.plugin.is_registered())

    def test_unregister_nonexistent_credential(self):
        """Test error when trying to remove non-existent credential."""
        result = self.plugin.unregister(credential_id="nonexistent")
        self.assertFalse(result.success)
        self.assertIn("not found", result.message.lower())


class TestFIDO2DeviceListing(unittest.TestCase):
    """Test device listing functionality."""

    def setUp(self):
        """Set up test environment."""
        self.plugin = FIDO2HSMPlugin()

    @patch('openssl_encrypt.plugins.hsm.fido2_pepper.CtapHidDevice')
    @patch('openssl_encrypt.plugins.hsm.fido2_pepper.Ctap2')
    def test_list_devices_with_mock(self, mock_ctap2, mock_device_class):
        """Test listing connected devices with mocked hardware."""
        # Mock device
        mock_device = Mock()
        mock_device.product_name = "Test YubiKey"
        mock_device.manufacturer = "Yubico"
        mock_device_class.list_devices.return_value = [mock_device]

        # Mock device info
        mock_info = Mock()
        mock_info.aaguid = "cb69481e-8ff7-4039-93ec-0a2729a154a8"
        mock_info.versions = ["FIDO_2_0", "FIDO_2_1"]
        mock_info.extensions = ["hmac-secret", "credProtect"]
        mock_ctap2.return_value.get_info.return_value = mock_info

        # List devices
        devices = self.plugin.list_devices()

        # Verify device information
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["product_name"], "Test YubiKey")
        self.assertEqual(devices[0]["manufacturer"], "Yubico")
        self.assertIn("hmac-secret", devices[0]["extensions"])
        self.assertTrue(devices[0]["hmac_secret_support"])

    @patch('openssl_encrypt.plugins.hsm.fido2_pepper.CtapHidDevice')
    def test_list_devices_none_found(self, mock_device_class):
        """Test listing devices when none are connected."""
        mock_device_class.list_devices.return_value = []

        devices = self.plugin.list_devices()

        self.assertEqual(len(devices), 0)


class TestFIDO2ConfigDirectory(unittest.TestCase):
    """Test configuration directory creation and permissions."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = Path("/tmp/test_fido2_config")
        self.credential_file = self.test_dir / "credentials.json"

        # Clean up any existing test directory
        if self.test_dir.exists():
            if self.credential_file.exists():
                self.credential_file.unlink()
            self.test_dir.rmdir()

    def tearDown(self):
        """Clean up test files."""
        if self.credential_file.exists():
            self.credential_file.unlink()
        if self.test_dir.exists():
            self.test_dir.rmdir()

    def test_config_directory_creation(self):
        """Test automatic creation of config directory."""
        plugin = FIDO2HSMPlugin(credential_file=self.credential_file)

        # Directory should be created
        self.assertTrue(self.test_dir.exists())

        # Check permissions
        dir_stat = os.stat(self.test_dir)
        dir_mode = dir_stat.st_mode & 0o777
        self.assertEqual(dir_mode, 0o700, "Config directory should have 0o700 permissions")


if __name__ == "__main__":
    unittest.main()
