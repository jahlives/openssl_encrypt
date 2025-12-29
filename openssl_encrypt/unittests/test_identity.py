#!/usr/bin/env python3
"""
Test suite for identity and asymmetric encryption functionality.

This module contains comprehensive tests for:
- Identity generation, storage, and management
- Asymmetric encryption and decryption
- PQC signing and verification
- Identity CLI commands
- Metadata V7 creation
"""

import base64
import json
import os
import secrets
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Import the modules to test
from openssl_encrypt.modules.crypt_core import (
    create_metadata_v7,
    decrypt_file_asymmetric,
    encrypt_file_asymmetric,
)
from openssl_encrypt.modules.crypto_secure_memory import CryptoKey
from openssl_encrypt.modules.identity import Identity, IdentityError, IdentityStore
from openssl_encrypt.modules.identity_cli import (
    cmd_change_password,
    cmd_create,
    cmd_delete,
    cmd_export,
    cmd_import,
    cmd_list,
    cmd_show,
)
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
class TestAsymmetricEncryption(unittest.TestCase):
    """Test cases for asymmetric encryption"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()

        # Create test identities
        self.alice = Identity.generate("Alice", "alice@example.com", "alice_pass")
        self.bob = Identity.generate("Bob", "bob@example.com", "bob_pass")
        self.charlie = Identity.generate("Charlie", None, "charlie_pass")

        # Create test file
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        with open(self.test_file, "w") as f:
            f.write("This is a secret message for testing asymmetric encryption!")

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_encrypt_single_recipient(self):
        """Test encrypting for a single recipient"""
        output_file = os.path.join(self.temp_dir, "encrypted.enc")

        result = encrypt_file_asymmetric(
            input_file=self.test_file,
            output_file=output_file,
            recipients=[self.bob],
            sender=self.alice,
            quiet=True,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["recipients"], 1)
        self.assertEqual(result["sender"], self.alice.fingerprint)
        self.assertTrue(os.path.exists(output_file))

        # Verify file structure
        with open(output_file, "rb") as f:
            content = f.read()
            self.assertIn(b":", content)

            # Parse metadata (format: base64(metadata):base64(data))
            colon_pos = content.index(b":")
            metadata_b64 = content[:colon_pos]
            metadata_json = base64.b64decode(metadata_b64)
            metadata = json.loads(metadata_json)

            # Verify format
            self.assertEqual(metadata["format_version"], 7)
            self.assertEqual(metadata["mode"], "asymmetric")
            self.assertEqual(len(metadata["asymmetric"]["recipients"]), 1)
            self.assertEqual(
                metadata["asymmetric"]["sender"]["key_id"],
                self.alice.fingerprint,
            )
            self.assertIn("signature", metadata)

    def test_encrypt_multiple_recipients(self):
        """Test encrypting for multiple recipients"""
        output_file = os.path.join(self.temp_dir, "encrypted_multi.enc")

        result = encrypt_file_asymmetric(
            input_file=self.test_file,
            output_file=output_file,
            recipients=[self.alice, self.bob, self.charlie],
            sender=self.alice,
            quiet=True,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["recipients"], 3)

        # Verify metadata
        with open(output_file, "rb") as f:
            content = f.read()
            colon_pos = content.index(b":")
            metadata_b64 = content[:colon_pos]
            metadata_json = base64.b64decode(metadata_b64)
            metadata = json.loads(metadata_json)

            self.assertEqual(len(metadata["asymmetric"]["recipients"]), 3)

            # Check all recipients are present
            recipient_ids = [r["key_id"] for r in metadata["asymmetric"]["recipients"]]
            self.assertIn(self.alice.fingerprint, recipient_ids)
            self.assertIn(self.bob.fingerprint, recipient_ids)
            self.assertIn(self.charlie.fingerprint, recipient_ids)

    def test_encrypt_custom_hash_config(self):
        """Test encryption with custom hash configuration"""
        output_file = os.path.join(self.temp_dir, "encrypted_custom.enc")

        custom_hash_config = {
            "sha512": 10,
            "blake2b": 5,
            "pbkdf2_iterations": 200000,
        }

        result = encrypt_file_asymmetric(
            input_file=self.test_file,
            output_file=output_file,
            recipients=[self.bob],
            sender=self.alice,
            hash_config=custom_hash_config,
            quiet=True,
        )

        self.assertTrue(result["success"])

        # Verify hash config in metadata
        with open(output_file, "rb") as f:
            content = f.read()
            colon_pos = content.index(b":")
            metadata_b64 = content[:colon_pos]
            metadata_json = base64.b64decode(metadata_b64)
            metadata = json.loads(metadata_json)

            hash_cfg = metadata["derivation_config"]["hash_config"]
            self.assertEqual(hash_cfg["sha512"]["rounds"], 10)
            self.assertEqual(hash_cfg["blake2b"]["rounds"], 5)

            kdf_cfg = metadata["derivation_config"]["kdf_config"]
            self.assertEqual(kdf_cfg["pbkdf2"]["rounds"], 200000)

    def test_encrypt_no_recipients(self):
        """Test that encryption fails with no recipients"""
        output_file = os.path.join(self.temp_dir, "should_fail.enc")

        with self.assertRaises(ValueError) as ctx:
            encrypt_file_asymmetric(
                input_file=self.test_file,
                output_file=output_file,
                recipients=[],
                sender=self.alice,
                quiet=True,
            )
        self.assertIn("At least one recipient required", str(ctx.exception))

    def test_encrypt_no_sender(self):
        """Test that encryption fails without sender"""
        output_file = os.path.join(self.temp_dir, "should_fail.enc")

        with self.assertRaises(ValueError) as ctx:
            encrypt_file_asymmetric(
                input_file=self.test_file,
                output_file=output_file,
                recipients=[self.bob],
                sender=None,
                quiet=True,
            )
        self.assertIn("Sender identity required", str(ctx.exception))

    def test_encrypt_sender_without_signing_key(self):
        """Test that encryption fails if sender has no signing key"""
        # Create public-only identity (no private keys)
        public_data = self.alice.export_public()
        alice_public = Identity.import_public(public_data)

        output_file = os.path.join(self.temp_dir, "should_fail.enc")

        with self.assertRaises(ValueError) as ctx:
            encrypt_file_asymmetric(
                input_file=self.test_file,
                output_file=output_file,
                recipients=[self.bob],
                sender=alice_public,
                quiet=True,
            )
        self.assertIn("signing private key", str(ctx.exception))

    def test_encrypt_recipient_without_encryption_key(self):
        """Test that encryption fails if recipient has no encryption key"""
        # Create public-only identity and remove encryption key
        public_data = self.bob.export_public()
        bob_public = Identity.import_public(public_data)
        bob_public.encryption_public_key = None

        output_file = os.path.join(self.temp_dir, "should_fail.enc")

        with self.assertRaises(ValueError) as ctx:
            encrypt_file_asymmetric(
                input_file=self.test_file,
                output_file=output_file,
                recipients=[bob_public],
                sender=self.alice,
                quiet=True,
            )
        self.assertIn("encryption_public_key", str(ctx.exception))


@unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
class TestAsymmetricDecryption(unittest.TestCase):
    """Test cases for asymmetric decryption"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()

        # Create test identities
        self.alice = Identity.generate("Alice", "alice@example.com", "alice_pass")
        self.bob = Identity.generate("Bob", "bob@example.com", "bob_pass")
        self.charlie = Identity.generate("Charlie", None, "charlie_pass")

        # Create test file
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.test_content = "This is a secret message for testing asymmetric encryption!"
        with open(self.test_file, "w") as f:
            f.write(self.test_content)

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_decrypt_single_recipient(self):
        """Test encrypting and decrypting for a single recipient"""
        from openssl_encrypt.modules.crypt_core import decrypt_file_asymmetric

        encrypted_file = os.path.join(self.temp_dir, "encrypted.enc")
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        # Encrypt
        encrypt_file_asymmetric(
            input_file=self.test_file,
            output_file=encrypted_file,
            recipients=[self.bob],
            sender=self.alice,
            quiet=True,
        )

        # Decrypt
        decrypt_file_asymmetric(
            input_file=encrypted_file,
            output_file=decrypted_file,
            recipient=self.bob,
            sender_public_key=self.alice.signing_public_key,
            quiet=True,
        )

        # Verify
        self.assertTrue(os.path.exists(decrypted_file))
        with open(decrypted_file, "r") as f:
            decrypted_content = f.read()
        self.assertEqual(decrypted_content, self.test_content)

    def test_decrypt_multiple_recipients(self):
        """Test that all recipients can decrypt"""
        from openssl_encrypt.modules.crypt_core import decrypt_file_asymmetric

        encrypted_file = os.path.join(self.temp_dir, "encrypted_multi.enc")

        # Encrypt for 3 recipients
        encrypt_file_asymmetric(
            input_file=self.test_file,
            output_file=encrypted_file,
            recipients=[self.alice, self.bob, self.charlie],
            sender=self.alice,
            quiet=True,
        )

        # Each recipient should be able to decrypt
        for i, recipient in enumerate([self.alice, self.bob, self.charlie]):
            decrypted_file = os.path.join(self.temp_dir, f"decrypted_{i}.txt")

            decrypt_file_asymmetric(
                input_file=encrypted_file,
                output_file=decrypted_file,
                recipient=recipient,
                sender_public_key=self.alice.signing_public_key,
                quiet=True,
            )

            with open(decrypted_file, "r") as f:
                decrypted_content = f.read()
            self.assertEqual(decrypted_content, self.test_content)

    def test_decrypt_wrong_recipient_fails(self):
        """Test that non-recipient cannot decrypt"""
        from openssl_encrypt.modules.crypt_core import decrypt_file_asymmetric

        encrypted_file = os.path.join(self.temp_dir, "encrypted.enc")
        decrypted_file = os.path.join(self.temp_dir, "should_fail.txt")

        # Encrypt for Bob only
        encrypt_file_asymmetric(
            input_file=self.test_file,
            output_file=encrypted_file,
            recipients=[self.bob],
            sender=self.alice,
            quiet=True,
        )

        # Charlie should not be able to decrypt
        with self.assertRaises(ValueError) as ctx:
            decrypt_file_asymmetric(
                input_file=encrypted_file,
                output_file=decrypted_file,
                recipient=self.charlie,
                sender_public_key=self.alice.signing_public_key,
                quiet=True,
            )
        self.assertIn("not encrypted for recipient", str(ctx.exception))

    def test_decrypt_invalid_signature_fails(self):
        """Test that tampering with signature causes decryption failure"""
        from openssl_encrypt.modules.crypt_core import decrypt_file_asymmetric

        encrypted_file = os.path.join(self.temp_dir, "encrypted.enc")
        decrypted_file = os.path.join(self.temp_dir, "should_fail.txt")

        # Encrypt
        encrypt_file_asymmetric(
            input_file=self.test_file,
            output_file=encrypted_file,
            recipients=[self.bob],
            sender=self.alice,
            quiet=True,
        )

        # Tamper with signature
        with open(encrypted_file, "rb") as f:
            content = f.read()

        # Corrupt one byte in the signature (format: base64(metadata):base64(data))
        colon_pos = content.index(b":")
        metadata_b64 = content[:colon_pos]
        encrypted_data_b64 = content[colon_pos + 1 :]

        metadata_json = base64.b64decode(metadata_b64)
        metadata = json.loads(metadata_json)

        sig_b64 = metadata["signature"]["value"]
        sig_bytes = bytearray(base64.b64decode(sig_b64))
        sig_bytes[100] ^= 0xFF  # Flip one byte
        metadata["signature"]["value"] = base64.b64encode(bytes(sig_bytes)).decode("utf-8")

        # Rewrite file with tampered metadata
        tampered_metadata_json = json.dumps(metadata)
        tampered_metadata_b64 = base64.b64encode(tampered_metadata_json.encode("utf-8"))

        with open(encrypted_file, "wb") as f:
            f.write(tampered_metadata_b64 + b":" + encrypted_data_b64)

        # Decryption should fail
        with self.assertRaises(ValueError) as ctx:
            decrypt_file_asymmetric(
                input_file=encrypted_file,
                output_file=decrypted_file,
                recipient=self.bob,
                sender_public_key=self.alice.signing_public_key,
                quiet=True,
            )
        self.assertIn("SIGNATURE VERIFICATION FAILED", str(ctx.exception))

    def test_decrypt_skip_verification(self):
        """Test that skip_verification allows decryption without checking signature"""
        from openssl_encrypt.modules.crypt_core import decrypt_file_asymmetric

        encrypted_file = os.path.join(self.temp_dir, "encrypted.enc")
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        # Encrypt
        encrypt_file_asymmetric(
            input_file=self.test_file,
            output_file=encrypted_file,
            recipients=[self.bob],
            sender=self.alice,
            quiet=True,
        )

        # Decrypt with skip_verification=True (no sender_public_key needed)
        decrypt_file_asymmetric(
            input_file=encrypted_file,
            output_file=decrypted_file,
            recipient=self.bob,
            skip_verification=True,
            quiet=True,
        )

        # Should succeed
        with open(decrypted_file, "r") as f:
            decrypted_content = f.read()
        self.assertEqual(decrypted_content, self.test_content)

    def test_decrypt_no_sender_public_key_fails(self):
        """Test that decryption requires sender public key for verification"""
        from openssl_encrypt.modules.crypt_core import decrypt_file_asymmetric

        encrypted_file = os.path.join(self.temp_dir, "encrypted.enc")
        decrypted_file = os.path.join(self.temp_dir, "should_fail.txt")

        # Encrypt
        encrypt_file_asymmetric(
            input_file=self.test_file,
            output_file=encrypted_file,
            recipients=[self.bob],
            sender=self.alice,
            quiet=True,
        )

        # Try to decrypt without sender_public_key
        with self.assertRaises(ValueError) as ctx:
            decrypt_file_asymmetric(
                input_file=encrypted_file,
                output_file=decrypted_file,
                recipient=self.bob,
                sender_public_key=None,  # No sender key!
                skip_verification=False,
                quiet=True,
            )
        self.assertIn("Sender's public key required", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()


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
        args.hsm = None  # Explicitly set to None to avoid MagicMock

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
        args.hsm = None  # Explicitly set to None to avoid MagicMock

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


@unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
class TestMetadataV7Creation(unittest.TestCase):
    """Test cases for create_metadata_v7 function"""

    def setUp(self):
        """Set up test fixtures"""
        self.salt = secrets.token_bytes(16)
        self.hash_config = {
            "sha512": 5,
            "blake2b": 3,
            "pbkdf2_iterations": 100000,
        }
        self.original_hash = "abcd1234" * 8  # 64 char hex
        self.algorithm = "aes-gcm"
        self.signature = secrets.token_bytes(3309)  # ML-DSA-65 signature size

    def test_create_v7_single_recipient(self):
        """Test creating V7 metadata with single recipient"""
        recipients = [
            {
                "key_id": "alice_fingerprint_12345",
                "kem_algorithm": "ML-KEM-768",
                "encapsulated_key": secrets.token_bytes(1088),
                "encrypted_password": secrets.token_bytes(60),
            }
        ]

        metadata = create_metadata_v7(
            salt=self.salt,
            hash_config=self.hash_config,
            original_hash=self.original_hash,
            algorithm=self.algorithm,
            recipients=recipients,
            sender_key_id="sender_fingerprint_67890",
            sender_sig_algo="ML-DSA-65",
            signature=self.signature,
        )

        # Check format version
        self.assertEqual(metadata["format_version"], 7)
        self.assertEqual(metadata["mode"], "asymmetric")

        # Check recipients
        self.assertEqual(len(metadata["asymmetric"]["recipients"]), 1)
        recipient = metadata["asymmetric"]["recipients"][0]
        self.assertEqual(recipient["key_id"], "alice_fingerprint_12345")
        self.assertEqual(recipient["kem_algorithm"], "ML-KEM-768")
        self.assertIn("encapsulated_key", recipient)
        self.assertIn("encrypted_password", recipient)

        # Check sender
        sender = metadata["asymmetric"]["sender"]
        self.assertEqual(sender["key_id"], "sender_fingerprint_67890")
        self.assertEqual(sender["sig_algorithm"], "ML-DSA-65")

        # Check signature
        self.assertIn("signature", metadata)
        self.assertEqual(metadata["signature"]["algorithm"], "ML-DSA-65")
        self.assertIn("value", metadata["signature"])

        # Check derivation_config
        self.assertIn("derivation_config", metadata)
        self.assertIn("salt", metadata["derivation_config"])
        self.assertIn("hash_config", metadata["derivation_config"])
        self.assertIn("kdf_config", metadata["derivation_config"])

    def test_create_v7_multiple_recipients(self):
        """Test creating V7 metadata with multiple recipients"""
        recipients = [
            {
                "key_id": "alice_fingerprint",
                "kem_algorithm": "ML-KEM-768",
                "encapsulated_key": secrets.token_bytes(1088),
                "encrypted_password": secrets.token_bytes(60),
            },
            {
                "key_id": "bob_fingerprint",
                "kem_algorithm": "ML-KEM-768",
                "encapsulated_key": secrets.token_bytes(1088),
                "encrypted_password": secrets.token_bytes(60),
            },
            {
                "key_id": "charlie_fingerprint",
                "kem_algorithm": "ML-KEM-768",
                "encapsulated_key": secrets.token_bytes(1088),
                "encrypted_password": secrets.token_bytes(60),
            },
        ]

        metadata = create_metadata_v7(
            salt=self.salt,
            hash_config=self.hash_config,
            original_hash=self.original_hash,
            algorithm=self.algorithm,
            recipients=recipients,
            sender_key_id="sender_fp",
            sender_sig_algo="ML-DSA-65",
            signature=self.signature,
        )

        # Check all recipients are present
        self.assertEqual(len(metadata["asymmetric"]["recipients"]), 3)

        # Verify each recipient
        recipient_ids = [r["key_id"] for r in metadata["asymmetric"]["recipients"]]
        self.assertIn("alice_fingerprint", recipient_ids)
        self.assertIn("bob_fingerprint", recipient_ids)
        self.assertIn("charlie_fingerprint", recipient_ids)

    def test_create_v7_with_encrypted_hash(self):
        """Test V7 metadata with encrypted_hash included"""
        encrypted_hash = "1234abcd" * 8
        recipients = [
            {
                "key_id": "alice_fp",
                "kem_algorithm": "ML-KEM-768",
                "encapsulated_key": secrets.token_bytes(1088),
                "encrypted_password": secrets.token_bytes(60),
            }
        ]

        metadata = create_metadata_v7(
            salt=self.salt,
            hash_config=self.hash_config,
            original_hash=self.original_hash,
            algorithm=self.algorithm,
            recipients=recipients,
            sender_key_id="sender_fp",
            sender_sig_algo="ML-DSA-65",
            signature=self.signature,
            encrypted_hash=encrypted_hash,
            include_encrypted_hash=True,
        )

        # Should include both hashes
        self.assertIn("original_hash", metadata["hashes"])
        self.assertIn("encrypted_hash", metadata["hashes"])
        self.assertEqual(metadata["hashes"]["encrypted_hash"], encrypted_hash)

    def test_create_v7_without_encrypted_hash(self):
        """Test V7 metadata without encrypted_hash (AAD mode)"""
        recipients = [
            {
                "key_id": "alice_fp",
                "kem_algorithm": "ML-KEM-768",
                "encapsulated_key": secrets.token_bytes(1088),
                "encrypted_password": secrets.token_bytes(60),
            }
        ]

        metadata = create_metadata_v7(
            salt=self.salt,
            hash_config=self.hash_config,
            original_hash=self.original_hash,
            algorithm=self.algorithm,
            recipients=recipients,
            sender_key_id="sender_fp",
            sender_sig_algo="ML-DSA-65",
            signature=self.signature,
            include_encrypted_hash=False,
        )

        # Should only include original_hash
        self.assertIn("original_hash", metadata["hashes"])
        self.assertNotIn("encrypted_hash", metadata["hashes"])

    def test_create_v7_aad_mode(self):
        """Test V7 metadata with AAD binding mode"""
        recipients = [
            {
                "key_id": "alice_fp",
                "kem_algorithm": "ML-KEM-768",
                "encapsulated_key": secrets.token_bytes(1088),
                "encrypted_password": secrets.token_bytes(60),
            }
        ]

        metadata = create_metadata_v7(
            salt=self.salt,
            hash_config=self.hash_config,
            original_hash=self.original_hash,
            algorithm=self.algorithm,
            recipients=recipients,
            sender_key_id="sender_fp",
            sender_sig_algo="ML-DSA-65",
            signature=self.signature,
            aad_mode=True,
        )

        # Should have aead_binding marker
        self.assertIn("aead_binding", metadata)
        self.assertTrue(metadata["aead_binding"])

    def test_create_v7_hash_algorithms(self):
        """Test V7 metadata with various hash algorithms"""
        hash_config = {
            "sha512": 5,
            "sha256": 3,
            "blake2b": 4,
            "sha3_512": 2,
            "pbkdf2_iterations": 50000,
        }

        recipients = [
            {
                "key_id": "alice_fp",
                "kem_algorithm": "ML-KEM-768",
                "encapsulated_key": secrets.token_bytes(1088),
                "encrypted_password": secrets.token_bytes(60),
            }
        ]

        metadata = create_metadata_v7(
            salt=self.salt,
            hash_config=hash_config,
            original_hash=self.original_hash,
            algorithm=self.algorithm,
            recipients=recipients,
            sender_key_id="sender_fp",
            sender_sig_algo="ML-DSA-65",
            signature=self.signature,
        )

        # Check hash algorithms are in hash_config
        hash_cfg = metadata["derivation_config"]["hash_config"]
        self.assertIn("sha512", hash_cfg)
        self.assertEqual(hash_cfg["sha512"]["rounds"], 5)
        self.assertIn("sha256", hash_cfg)
        self.assertEqual(hash_cfg["sha256"]["rounds"], 3)
        self.assertIn("blake2b", hash_cfg)
        self.assertEqual(hash_cfg["blake2b"]["rounds"], 4)

    def test_create_v7_kdf_algorithms(self):
        """Test V7 metadata with KDF algorithms"""
        hash_config = {
            "sha512": 3,
            "pbkdf2_iterations": 100000,
            "argon2": {"time_cost": 3, "memory_cost": 65536, "parallelism": 4},
            "scrypt": {"n": 16384, "r": 8, "p": 1},
        }

        recipients = [
            {
                "key_id": "alice_fp",
                "kem_algorithm": "ML-KEM-768",
                "encapsulated_key": secrets.token_bytes(1088),
                "encrypted_password": secrets.token_bytes(60),
            }
        ]

        metadata = create_metadata_v7(
            salt=self.salt,
            hash_config=hash_config,
            original_hash=self.original_hash,
            algorithm=self.algorithm,
            recipients=recipients,
            sender_key_id="sender_fp",
            sender_sig_algo="ML-DSA-65",
            signature=self.signature,
        )

        # Check KDF configurations
        kdf_cfg = metadata["derivation_config"]["kdf_config"]
        self.assertIn("pbkdf2", kdf_cfg)
        self.assertEqual(kdf_cfg["pbkdf2"]["rounds"], 100000)
        self.assertIn("argon2", kdf_cfg)
        self.assertIn("scrypt", kdf_cfg)

    def test_create_v7_json_serializable(self):
        """Test that V7 metadata is JSON serializable"""
        recipients = [
            {
                "key_id": "alice_fp",
                "kem_algorithm": "ML-KEM-768",
                "encapsulated_key": secrets.token_bytes(1088),
                "encrypted_password": secrets.token_bytes(60),
            }
        ]

        metadata = create_metadata_v7(
            salt=self.salt,
            hash_config=self.hash_config,
            original_hash=self.original_hash,
            algorithm=self.algorithm,
            recipients=recipients,
            sender_key_id="sender_fp",
            sender_sig_algo="ML-DSA-65",
            signature=self.signature,
        )

        # Should be serializable to JSON
        json_str = json.dumps(metadata)
        self.assertIsInstance(json_str, str)

        # Should be deserializable
        metadata_copy = json.loads(json_str)
        self.assertEqual(metadata_copy["format_version"], 7)

    def test_create_v7_base64_encoding(self):
        """Test that binary data is properly base64 encoded"""
        recipients = [
            {
                "key_id": "alice_fp",
                "kem_algorithm": "ML-KEM-768",
                "encapsulated_key": b"test_encapsulated_key_data",
                "encrypted_password": b"test_encrypted_password",
            }
        ]

        metadata = create_metadata_v7(
            salt=b"test_salt_16byte",
            hash_config=self.hash_config,
            original_hash=self.original_hash,
            algorithm=self.algorithm,
            recipients=recipients,
            sender_key_id="sender_fp",
            sender_sig_algo="ML-DSA-65",
            signature=b"test_signature_data",
        )

        # Check salt is base64 encoded
        decoded_salt = base64.b64decode(metadata["derivation_config"]["salt"])
        self.assertEqual(decoded_salt, b"test_salt_16byte")

        # Check recipient data is base64 encoded
        recipient = metadata["asymmetric"]["recipients"][0]
        decoded_encap = base64.b64decode(recipient["encapsulated_key"])
        self.assertEqual(decoded_encap, b"test_encapsulated_key_data")
        decoded_pwd = base64.b64decode(recipient["encrypted_password"])
        self.assertEqual(decoded_pwd, b"test_encrypted_password")

        # Check signature is base64 encoded
        decoded_sig = base64.b64decode(metadata["signature"]["value"])
        self.assertEqual(decoded_sig, b"test_signature_data")


if __name__ == "__main__":
    unittest.main()


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
class TestConvenienceFunctionsV2(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
