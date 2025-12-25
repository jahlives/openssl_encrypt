#!/usr/bin/env python3
"""
Unit tests for Identity CLI Module

Tests CLI commands for identity management:
- create, list, show, export, import, delete, change-password
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from openssl_encrypt.modules.identity import Identity, IdentityStore
from openssl_encrypt.modules.identity_cli import (
    cmd_change_password,
    cmd_create,
    cmd_delete,
    cmd_export,
    cmd_import,
    cmd_list,
    cmd_show,
)
from openssl_encrypt.modules.pqc_signing import LIBOQS_AVAILABLE


@unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
class TestIdentityCLI(unittest.TestCase):
    """Test cases for Identity CLI commands"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.identity_store_path = Path(self.temp_dir) / "identities"
        self.store = IdentityStore(base_path=self.identity_store_path)

    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cmd_create(self):
        """Test create command"""
        # Mock args
        args = MagicMock()
        args.name = "TestUser"
        args.email = "test@example.com"
        args.kem_algorithm = "ML-KEM-768"
        args.sig_algorithm = "ML-DSA-65"
        args.overwrite = False
        args.identity_store = self.identity_store_path

        # Mock getpass to return test passphrase
        with patch("openssl_encrypt.modules.identity_cli.getpass.getpass") as mock_getpass:
            mock_getpass.side_effect = [
                "testpass123",
                "testpass123",
            ]  # passphrase + confirmation

            # Create identity
            result = cmd_create(args)

            self.assertEqual(result, 0)  # Success

            # Verify identity was created
            identity = self.store.get_by_name("TestUser", None, load_private_keys=False)
            self.assertIsNotNone(identity)
            self.assertEqual(identity.name, "TestUser")
            self.assertEqual(identity.email, "test@example.com")

    def test_cmd_create_weak_password(self):
        """Test create command with weak password"""
        args = MagicMock()
        args.name = "WeakPass"
        args.email = None
        args.kem_algorithm = "ML-KEM-768"
        args.sig_algorithm = "ML-DSA-65"
        args.overwrite = False
        args.identity_store = self.identity_store_path

        # Mock getpass to return weak passphrase
        with patch("openssl_encrypt.modules.identity_cli.getpass.getpass") as mock_getpass:
            mock_getpass.side_effect = ["weak", "weak"]  # Too short

            result = cmd_create(args)

            self.assertEqual(result, 1)  # Should fail

    def test_cmd_list_empty(self):
        """Test list command with no identities"""
        args = MagicMock()
        args.identity_store = self.identity_store_path
        args.include_contacts = True

        result = cmd_list(args)
        self.assertEqual(result, 0)

    def test_cmd_list_with_identities(self):
        """Test list command with identities"""
        # Create test identity
        identity = Identity.generate("Alice", "alice@example.com", "pass123")
        self.store.add_identity(identity, "pass123")

        args = MagicMock()
        args.identity_store = self.identity_store_path
        args.include_contacts = True

        result = cmd_list(args)
        self.assertEqual(result, 0)

    def test_cmd_show_existing(self):
        """Test show command for existing identity"""
        # Create test identity
        identity = Identity.generate("Bob", "bob@example.com", "pass123")
        self.store.add_identity(identity, "pass123")

        args = MagicMock()
        args.identity_name = "Bob"
        args.identity_store = self.identity_store_path

        result = cmd_show(args)
        self.assertEqual(result, 0)

    def test_cmd_show_nonexistent(self):
        """Test show command for non-existent identity"""
        args = MagicMock()
        args.identity_name = "NonExistent"
        args.identity_store = self.identity_store_path

        result = cmd_show(args)
        self.assertEqual(result, 1)  # Should fail

    def test_cmd_export(self):
        """Test export command"""
        # Create test identity
        identity = Identity.generate("Charlie", "charlie@example.com", "pass123")
        self.store.add_identity(identity, "pass123")

        args = MagicMock()
        args.identity_name = "Charlie"
        args.output = os.path.join(self.temp_dir, "charlie_public.json")
        args.overwrite = False
        args.identity_store = self.identity_store_path

        result = cmd_export(args)
        self.assertEqual(result, 0)

        # Verify file was created
        self.assertTrue(os.path.exists(args.output))

        # Verify it's valid JSON with public keys
        with open(args.output, "r") as f:
            data = json.load(f)
            self.assertEqual(data["name"], "Charlie")
            self.assertIn("encryption_public_key", data)
            self.assertIn("signing_public_key", data)
            self.assertNotIn("encryption_private_key", data)

    def test_cmd_export_default_output(self):
        """Test export command with default output filename"""
        # Create test identity
        identity = Identity.generate("Diana", None, "pass123")
        self.store.add_identity(identity, "pass123")

        args = MagicMock()
        args.identity_name = "Diana"
        args.output = None  # Default output
        args.overwrite = False
        args.identity_store = self.identity_store_path

        # Change to temp directory for test
        original_dir = os.getcwd()
        os.chdir(self.temp_dir)

        try:
            result = cmd_export(args)
            self.assertEqual(result, 0)

            # Check default filename was created
            default_file = "Diana_public.json"
            self.assertTrue(os.path.exists(default_file))
        finally:
            os.chdir(original_dir)

    def test_cmd_import(self):
        """Test import command"""
        # Create and export test identity
        identity = Identity.generate("Eve", "eve@example.com", "pass123")
        public_data = identity.export_public()

        # Write to file
        import_file = os.path.join(self.temp_dir, "eve_public.json")
        with open(import_file, "w") as f:
            json.dump(public_data, f)

        args = MagicMock()
        args.file = import_file
        args.overwrite = False
        args.identity_store = self.identity_store_path

        result = cmd_import(args)
        self.assertEqual(result, 0)

        # Verify identity was imported
        imported = self.store.get_by_name("Eve", None, load_private_keys=False)
        self.assertIsNotNone(imported)
        self.assertEqual(imported.name, "Eve")
        self.assertFalse(imported.is_own_identity)  # Should be contact

    def test_cmd_import_invalid_file(self):
        """Test import command with invalid file"""
        args = MagicMock()
        args.file = "/nonexistent/file.json"
        args.overwrite = False
        args.identity_store = self.identity_store_path

        result = cmd_import(args)
        self.assertEqual(result, 1)  # Should fail

    def test_cmd_delete_existing(self):
        """Test delete command for existing identity"""
        # Create test identity
        identity = Identity.generate("Frank", None, "pass123")
        self.store.add_identity(identity, "pass123")

        args = MagicMock()
        args.identity_name = "Frank"
        args.force = True  # Skip confirmation
        args.identity_store = self.identity_store_path

        result = cmd_delete(args)
        self.assertEqual(result, 0)

        # Verify identity was deleted
        deleted = self.store.get_by_name("Frank", None, load_private_keys=False)
        self.assertIsNone(deleted)

    def test_cmd_delete_with_confirmation(self):
        """Test delete command with confirmation prompt"""
        # Create test identity
        identity = Identity.generate("Grace", None, "pass123")
        self.store.add_identity(identity, "pass123")

        args = MagicMock()
        args.identity_name = "Grace"
        args.force = False  # Require confirmation
        args.identity_store = self.identity_store_path

        # Mock user input to cancel
        with patch("builtins.input", return_value="no"):
            result = cmd_delete(args)
            self.assertEqual(result, 0)  # Success but cancelled

            # Verify identity was NOT deleted
            still_exists = self.store.get_by_name("Grace", None, load_private_keys=False)
            self.assertIsNotNone(still_exists)

    def test_cmd_delete_nonexistent(self):
        """Test delete command for non-existent identity"""
        args = MagicMock()
        args.identity_name = "NonExistent"
        args.force = True
        args.identity_store = self.identity_store_path

        result = cmd_delete(args)
        self.assertEqual(result, 1)  # Should fail

    def test_cmd_change_password(self):
        """Test change-password command"""
        # Create test identity
        identity = Identity.generate("Henry", None, "oldpass123")
        self.store.add_identity(identity, "oldpass123")

        args = MagicMock()
        args.identity_name = "Henry"
        args.identity_store = self.identity_store_path

        # Mock getpass
        with patch("openssl_encrypt.modules.identity_cli.getpass.getpass") as mock_getpass:
            mock_getpass.side_effect = [
                "oldpass123",  # Old password
                "newpass456",  # New password
                "newpass456",  # Confirm new password
            ]

            result = cmd_change_password(args)
            self.assertEqual(result, 0)

            # Verify we can load with new password
            reloaded = self.store.get_by_name("Henry", "newpass456", load_private_keys=True)
            self.assertIsNotNone(reloaded)
            self.assertEqual(reloaded.name, "Henry")

            # Verify old password doesn't work
            with self.assertRaises(ValueError):
                self.store.get_by_name("Henry", "oldpass123", load_private_keys=True)

    def test_cmd_change_password_wrong_old(self):
        """Test change-password command with wrong old password"""
        # Create test identity
        identity = Identity.generate("Iris", None, "correctpass")
        self.store.add_identity(identity, "correctpass")

        args = MagicMock()
        args.identity_name = "Iris"
        args.identity_store = self.identity_store_path

        # Mock getpass with wrong old password
        with patch("openssl_encrypt.modules.identity_cli.getpass.getpass") as mock_getpass:
            mock_getpass.return_value = "wrongpass"

            result = cmd_change_password(args)
            self.assertEqual(result, 1)  # Should fail

    def test_cmd_change_password_contact(self):
        """Test change-password command on contact (should fail)"""
        # Create public-only identity (contact)
        identity_full = Identity.generate("Jack", None, "pass123")
        public_data = identity_full.export_public()
        identity_contact = Identity.import_public(public_data)
        self.store.add_identity(identity_contact, None)

        args = MagicMock()
        args.identity_name = "Jack"
        args.identity_store = self.identity_store_path

        result = cmd_change_password(args)
        self.assertEqual(result, 1)  # Should fail (no private keys)


if __name__ == "__main__":
    unittest.main()
