#!/usr/bin/env python3
"""
Unit tests for Metadata V7 Format

Tests metadata creation and parsing for Format Version 7 (asymmetric mode).
"""

import base64
import json
import secrets
import unittest

from openssl_encrypt.modules.crypt_core import create_metadata_v7
from openssl_encrypt.modules.pqc_signing import LIBOQS_AVAILABLE


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
