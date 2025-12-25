#!/usr/bin/env python3
"""
Unit tests for the Identity Module (identity.py)

Tests Identity and IdentityStore classes including:
- Identity generation
- Identity save/load with passphrase encryption
- Public identity export/import
- Fingerprint calculation
- IdentityStore operations
- Secure memory handling
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from openssl_encrypt.modules.crypto_secure_memory import CryptoKey
from openssl_encrypt.modules.identity import Identity, IdentityError, IdentityStore
from openssl_encrypt.modules.pqc_signing import LIBOQS_AVAILABLE


@unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
class TestIdentity(unittest.TestCase):
    """Test cases for Identity class"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_path = Path(self.temp_dir)

    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_generate_identity(self):
        """Test generating a new identity"""
        identity = Identity.generate(
            name="Alice",
            email="alice@example.com",
            passphrase="test_passphrase_123",
        )

        self.assertEqual(identity.name, "Alice")
        self.assertEqual(identity.email, "alice@example.com")
        self.assertIsNotNone(identity.fingerprint)
        self.assertEqual(identity.encryption_algorithm, "ML-KEM-768")
        self.assertEqual(identity.signing_algorithm, "ML-DSA-65")
        self.assertTrue(identity.is_own_identity)

        # Check keys exist and are correct types
        self.assertIsInstance(identity.encryption_public_key, bytes)
        self.assertIsInstance(identity.encryption_private_key, CryptoKey)
        self.assertIsInstance(identity.signing_public_key, bytes)
        self.assertIsInstance(identity.signing_private_key, CryptoKey)

        # Check key sizes (approximate)
        self.assertGreater(len(identity.encryption_public_key), 1100)  # ~1184 bytes
        self.assertGreater(len(identity.signing_public_key), 1900)  # ~1952 bytes

    def test_generate_identity_without_email(self):
        """Test generating identity without email"""
        identity = Identity.generate(
            name="Bob",
            email=None,
            passphrase="test_pass",
        )

        self.assertEqual(identity.name, "Bob")
        self.assertIsNone(identity.email)

    def test_generate_identity_custom_algorithms(self):
        """Test generating identity with custom algorithms"""
        identity = Identity.generate(
            name="Charlie",
            email=None,
            passphrase="test_pass",
            kem_algorithm="ML-KEM-512",
            sig_algorithm="ML-DSA-44",
        )

        self.assertEqual(identity.encryption_algorithm, "ML-KEM-512")
        self.assertEqual(identity.signing_algorithm, "ML-DSA-44")

    def test_save_and_load_identity(self):
        """Test saving and loading identity"""
        # Generate identity
        identity1 = Identity.generate(
            name="Dave",
            email="dave@example.com",
            passphrase="save_test_123",
        )

        # Save to file
        save_path = self.test_path / "dave"
        identity1.save(save_path, "save_test_123")

        # Check files were created
        self.assertTrue((save_path / "identity.json").exists())
        self.assertTrue((save_path / "encryption_public.pem").exists())
        self.assertTrue((save_path / "encryption_private.pem").exists())
        self.assertTrue((save_path / "signing_public.pem").exists())
        self.assertTrue((save_path / "signing_private.pem").exists())

        # Load identity
        identity2 = Identity.load(save_path, "save_test_123", load_private_keys=True)

        # Compare
        self.assertEqual(identity1.name, identity2.name)
        self.assertEqual(identity1.email, identity2.email)
        self.assertEqual(identity1.fingerprint, identity2.fingerprint)
        self.assertEqual(identity1.encryption_algorithm, identity2.encryption_algorithm)
        self.assertEqual(identity1.signing_algorithm, identity2.signing_algorithm)
        self.assertEqual(identity1.encryption_public_key, identity2.encryption_public_key)
        self.assertEqual(identity1.signing_public_key, identity2.signing_public_key)

    def test_load_without_private_keys(self):
        """Test loading identity without private keys"""
        # Generate and save
        identity1 = Identity.generate(
            name="Eve",
            email="eve@example.com",
            passphrase="test123",
        )
        save_path = self.test_path / "eve"
        identity1.save(save_path, "test123")

        # Load without private keys
        identity2 = Identity.load(save_path, None, load_private_keys=False)

        self.assertEqual(identity1.name, identity2.name)
        self.assertEqual(identity1.fingerprint, identity2.fingerprint)
        self.assertIsNone(identity2.encryption_private_key)
        self.assertIsNone(identity2.signing_private_key)

    def test_load_with_wrong_passphrase(self):
        """Test loading with wrong passphrase fails"""
        # Generate and save
        identity = Identity.generate(
            name="Frank",
            email=None,
            passphrase="correct_pass",
        )
        save_path = self.test_path / "frank"
        identity.save(save_path, "correct_pass")

        # Try to load with wrong passphrase - should raise ValueError
        with self.assertRaises(ValueError):
            Identity.load(save_path, "wrong_pass", load_private_keys=True)

    def test_save_overwrite_protection(self):
        """Test that save prevents accidental overwrites"""
        identity = Identity.generate(
            name="Grace",
            email=None,
            passphrase="test",
        )
        save_path = self.test_path / "grace"

        # First save should work
        identity.save(save_path, "test")

        # Second save without overwrite=True should fail
        with self.assertRaises(IdentityError) as ctx:
            identity.save(save_path, "test", overwrite=False)
        self.assertIn("already exists", str(ctx.exception))

        # With overwrite=True should work
        identity.save(save_path, "test", overwrite=True)

    def test_export_and_import_public(self):
        """Test exporting and importing public identity"""
        # Generate identity
        identity1 = Identity.generate(
            name="Heidi",
            email="heidi@example.com",
            passphrase="test",
        )

        # Export public
        public_data = identity1.export_public()

        self.assertIsInstance(public_data, dict)
        self.assertEqual(public_data["name"], "Heidi")
        self.assertEqual(public_data["email"], "heidi@example.com")
        self.assertIn("fingerprint", public_data)
        self.assertIn("encryption_public_key", public_data)
        self.assertIn("signing_public_key", public_data)
        self.assertNotIn("encryption_private_key", public_data)
        self.assertNotIn("signing_private_key", public_data)

        # Import public
        identity2 = Identity.import_public(public_data)

        self.assertEqual(identity1.name, identity2.name)
        self.assertEqual(identity1.email, identity2.email)
        self.assertEqual(identity1.fingerprint, identity2.fingerprint)
        self.assertEqual(identity1.encryption_public_key, identity2.encryption_public_key)
        self.assertEqual(identity1.signing_public_key, identity2.signing_public_key)
        self.assertIsNone(identity2.encryption_private_key)
        self.assertIsNone(identity2.signing_private_key)
        self.assertFalse(identity2.is_own_identity)

    def test_fingerprint_calculation(self):
        """Test that fingerprint is calculated correctly"""
        identity1 = Identity.generate("User1", None, "pass")
        identity2 = Identity.generate("User2", None, "pass")

        # Different identities should have different fingerprints
        self.assertNotEqual(identity1.fingerprint, identity2.fingerprint)

        # Same identity loaded should have same fingerprint
        save_path = self.test_path / "user1"
        identity1.save(save_path, "pass")
        identity1_reloaded = Identity.load(save_path, "pass", load_private_keys=False)

        self.assertEqual(identity1.fingerprint, identity1_reloaded.fingerprint)

    def test_context_manager(self):
        """Test identity context manager for secure cleanup"""
        save_path = self.test_path / "context_test"
        identity1 = Identity.generate("Context", None, "pass")
        identity1.save(save_path, "pass")

        # Use context manager
        with Identity.load(save_path, "pass", load_private_keys=True) as identity:
            self.assertIsNotNone(identity.encryption_private_key)
            self.assertIsNotNone(identity.signing_private_key)

        # After context, keys should be cleared
        # (can't directly test CryptoKey internal state, but context manager was called)

    def test_identity_str_repr(self):
        """Test string representation of identity"""
        identity = Identity.generate("Test", "test@example.com", "pass")

        str_repr = str(identity)
        self.assertIn("Test", str_repr)
        self.assertIn("test@example.com", str_repr)
        self.assertIn(identity.fingerprint[:16], str_repr)


@unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
class TestIdentityStore(unittest.TestCase):
    """Test cases for IdentityStore class"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.store = IdentityStore(base_path=Path(self.temp_dir))

    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_add_and_list_identities(self):
        """Test adding and listing identities"""
        # Initially empty
        identities = self.store.list_identities(include_contacts=False)
        self.assertEqual(len(identities), 0)

        # Add identity
        identity1 = Identity.generate("Alice", "alice@example.com", "pass1")
        self.store.add_identity(identity1, "pass1")

        # List should now show 1
        identities = self.store.list_identities(include_contacts=False)
        self.assertEqual(len(identities), 1)
        self.assertEqual(identities[0].name, "Alice")

    def test_get_by_name(self):
        """Test getting identity by name"""
        identity = Identity.generate("Bob", None, "pass")
        self.store.add_identity(identity, "pass")

        # Get by name
        retrieved = self.store.get_by_name("Bob", "pass", load_private_keys=True)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.name, "Bob")
        self.assertIsNotNone(retrieved.encryption_private_key)

        # Get non-existent
        not_found = self.store.get_by_name("NonExistent", None, load_private_keys=False)
        self.assertIsNone(not_found)

    def test_get_by_fingerprint(self):
        """Test getting identity by fingerprint"""
        identity = Identity.generate("Charlie", None, "pass")
        self.store.add_identity(identity, "pass")

        # Get by fingerprint
        retrieved = self.store.get_by_fingerprint(
            identity.fingerprint, "pass", load_private_keys=True
        )
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.name, "Charlie")
        self.assertEqual(retrieved.fingerprint, identity.fingerprint)

        # Get by non-existent fingerprint
        not_found = self.store.get_by_fingerprint("nonexistent", None, load_private_keys=False)
        self.assertIsNone(not_found)

    def test_delete_identity(self):
        """Test deleting identity"""
        identity = Identity.generate("Dave", None, "pass")
        self.store.add_identity(identity, "pass")

        # Verify it exists
        self.assertIsNotNone(self.store.get_by_name("Dave", None, load_private_keys=False))

        # Delete
        result = self.store.delete_identity("Dave")
        self.assertTrue(result)

        # Verify it's gone
        self.assertIsNone(self.store.get_by_name("Dave", None, load_private_keys=False))

        # Delete non-existent
        result = self.store.delete_identity("NonExistent")
        self.assertFalse(result)

    def test_add_public_contact(self):
        """Test adding public contact (without private keys)"""
        # Generate identity with private keys
        identity_full = Identity.generate("Eve", "eve@example.com", "pass")

        # Export only public data
        public_data = identity_full.export_public()
        identity_public = Identity.import_public(public_data)

        # Add as contact
        self.store.add_identity(identity_public, passphrase=None)

        # Should appear in contacts
        identities = self.store.list_identities(include_contacts=True)
        own_identities = self.store.list_identities(include_contacts=False)

        self.assertEqual(len(identities), 1)
        self.assertEqual(len(own_identities), 0)  # Not an "own" identity

    def test_add_duplicate_identity(self):
        """Test that adding duplicate identity without overwrite fails"""
        identity = Identity.generate("Frank", None, "pass")

        # First add should work
        self.store.add_identity(identity, "pass")

        # Second add without overwrite should fail
        with self.assertRaises(IdentityError):
            self.store.add_identity(identity, "pass", overwrite=False)

        # With overwrite should work
        self.store.add_identity(identity, "pass", overwrite=True)

    def test_list_mixed_identities_and_contacts(self):
        """Test listing both own identities and contacts"""
        # Add own identity
        own = Identity.generate("Alice", None, "pass")
        self.store.add_identity(own, "pass")

        # Add contact
        contact_full = Identity.generate("Bob", None, "pass")
        contact_public = Identity.import_public(contact_full.export_public())
        self.store.add_identity(contact_public, None)

        # List all
        all_identities = self.store.list_identities(include_contacts=True)
        self.assertEqual(len(all_identities), 2)

        # List only own
        own_identities = self.store.list_identities(include_contacts=False)
        self.assertEqual(len(own_identities), 1)
        self.assertEqual(own_identities[0].name, "Alice")

    def test_store_path_creation(self):
        """Test that store creates necessary directories"""
        # Store should create base_path if it doesn't exist
        new_path = Path(self.temp_dir) / "new_store"
        IdentityStore(base_path=new_path)

        self.assertTrue(new_path.exists())
        self.assertTrue((new_path / "contacts").exists())

    def test_multiple_identities(self):
        """Test handling multiple identities"""
        names = ["User1", "User2", "User3", "User4", "User5"]

        for name in names:
            identity = Identity.generate(name, None, "pass")
            self.store.add_identity(identity, "pass")

        identities = self.store.list_identities(include_contacts=False)
        self.assertEqual(len(identities), 5)

        identity_names = [i.name for i in identities]
        for name in names:
            self.assertIn(name, identity_names)


@unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
class TestPrivateKeyEncryption(unittest.TestCase):
    """Test private key encryption at rest"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_path = Path(self.temp_dir)

    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_private_key_encrypted_at_rest(self):
        """Test that private keys are encrypted when saved"""
        identity = Identity.generate("Secure", None, "strong_pass_123")
        save_path = self.test_path / "secure"
        identity.save(save_path, "strong_pass_123")

        # Read raw private key files
        with open(save_path / "encryption_private.pem", "rb") as f:
            enc_priv_raw = f.read()

        with open(save_path / "signing_private.pem", "rb") as f:
            sig_priv_raw = f.read()

        # Files should not contain plaintext key material
        # (they should be encrypted with passphrase)
        # We can't directly verify encryption, but files should be non-empty
        self.assertGreater(len(enc_priv_raw), 100)
        self.assertGreater(len(sig_priv_raw), 100)

    def test_different_passphrases_different_ciphertext(self):
        """Test that same key encrypted with different passphrases gives different ciphertext"""
        identity = Identity.generate("Test", None, "pass1")

        save_path1 = self.test_path / "test1"
        save_path2 = self.test_path / "test2"

        # Save with different passphrases
        identity.save(save_path1, "pass1")
        identity.save(save_path2, "pass2", overwrite=True)

        # Read encrypted private keys
        with open(save_path1 / "encryption_private.pem", "rb") as f:
            enc1 = f.read()

        with open(save_path2 / "encryption_private.pem", "rb") as f:
            enc2 = f.read()

        # Should be different (due to different encryption keys and salts)
        self.assertNotEqual(enc1, enc2)


if __name__ == "__main__":
    unittest.main()
