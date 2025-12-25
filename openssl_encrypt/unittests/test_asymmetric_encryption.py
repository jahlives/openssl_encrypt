#!/usr/bin/env python3
"""
Unit tests for Asymmetric Encryption Pipeline

Tests the complete encrypt_file_asymmetric() function.
"""

import base64
import json
import os
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import encrypt_file_asymmetric
from openssl_encrypt.modules.identity import Identity
from openssl_encrypt.modules.pqc_signing import LIBOQS_AVAILABLE


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
        with open(output_file, "r") as f:
            content = f.read()
            self.assertIn("---ENCRYPTED_DATA---", content)

            # Parse metadata
            metadata_str = content.split("---ENCRYPTED_DATA---")[0]
            metadata = json.loads(metadata_str)

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
        with open(output_file, "r") as f:
            metadata_str = f.read().split("---ENCRYPTED_DATA---")[0]
            metadata = json.loads(metadata_str)

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
        with open(output_file, "r") as f:
            metadata_str = f.read().split("---ENCRYPTED_DATA---")[0]
            metadata = json.loads(metadata_str)

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
        with open(encrypted_file, "r") as f:
            content = f.read()

        # Corrupt one byte in the signature
        metadata_str, encrypted_data = content.split("---ENCRYPTED_DATA---")
        metadata = json.loads(metadata_str)
        sig_b64 = metadata["signature"]["value"]
        sig_bytes = bytearray(base64.b64decode(sig_b64))
        sig_bytes[100] ^= 0xFF  # Flip one byte
        metadata["signature"]["value"] = base64.b64encode(bytes(sig_bytes)).decode("utf-8")

        with open(encrypted_file, "w") as f:
            f.write(json.dumps(metadata, indent=2))
            f.write("\n---ENCRYPTED_DATA---\n")
            f.write(encrypted_data.strip())

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
