#!/usr/bin/env python3
"""
Test script for format_version 4 metadata structure and backward compatibility.
"""

import base64
import json
import os
import tempfile
import unittest
from typing import Any, Dict

from openssl_encrypt.modules.crypt_core import (
    convert_metadata_v3_to_v4,
    convert_metadata_v4_to_v3,
    decrypt_file,
    encrypt_file,
)


class TestFormatVersion4(unittest.TestCase):
    """Test suite for format_version 4 and backward compatibility."""

    def setUp(self):
        """Set up test environment."""
        # Create temp files for testing
        self.temp_input = tempfile.NamedTemporaryFile(delete=False, mode="wb")
        self.temp_input.write(b"This is test data for encryption and decryption.")
        self.temp_input.close()

        # Create test password (as bytes which is what the encrypt_file expects)
        self.password = "testpassword123".encode("utf-8")

    def tearDown(self):
        """Clean up test environment."""
        # Remove temp files
        try:
            os.unlink(self.temp_input.name)
        except:
            pass

    def read_metadata(self, file_path):
        """Read metadata from encrypted file."""
        with open(file_path, "rb") as f:
            content = f.read(8192)  # Read enough for the header

        # Find the colon separator
        colon_pos = content.find(b":")
        if colon_pos > 0:
            metadata_b64 = content[:colon_pos]
            metadata_json = base64.b64decode(metadata_b64).decode("utf-8")
            return json.loads(metadata_json)

        return None

    def test_format_version4_encryption(self):
        """Test that encryption uses format_version 4."""
        # Create temp output file
        temp_output = tempfile.NamedTemporaryFile(delete=False)
        temp_output.close()

        try:
            # Encrypt with default options and a simple hash_config
            hash_config = {
                "sha256": 10000,
                "sha512": 0,
                "sha3_256": 0,
                "sha3_512": 0,
                "blake2b": 0,
                "shake256": 0,
                "whirlpool": 0,
                "pbkdf2_iterations": 100000,
                "derivation_config": {"kdf_config": {"pbkdf2": {"rounds": 100000}}},
            }

            result = encrypt_file(
                self.temp_input.name, temp_output.name, self.password, hash_config=hash_config
            )

            # Check encryption was successful
            self.assertTrue(result)

            # Read metadata to check format version
            metadata = self.read_metadata(temp_output.name)
            self.assertIsNotNone(metadata)
            self.assertEqual(metadata.get("format_version"), 4)

            # Verify structure of metadata
            self.assertIn("derivation_config", metadata)
            self.assertIn("salt", metadata["derivation_config"])
            self.assertIn("hash_config", metadata["derivation_config"])
            self.assertIn("kdf_config", metadata["derivation_config"])

            # Verify hash_config has nested structure with 'rounds'
            hash_config = metadata["derivation_config"]["hash_config"]
            for algo in [
                "sha256",
                "sha512",
                "sha3_256",
                "sha3_512",
                "blake2b",
                "shake256",
                "whirlpool",
            ]:
                if algo in hash_config:
                    self.assertIsInstance(hash_config[algo], dict)
                    self.assertIn("rounds", hash_config[algo])

            # Verify pbkdf2 is in kdf_config with proper structure
            kdf_config = metadata["derivation_config"]["kdf_config"]
            if "pbkdf2" in kdf_config:
                self.assertIsInstance(kdf_config["pbkdf2"], dict)
                self.assertIn("rounds", kdf_config["pbkdf2"])

            self.assertIn("hashes", metadata)
            self.assertIn("original_hash", metadata["hashes"])
            self.assertIn("encrypted_hash", metadata["hashes"])

            self.assertIn("encryption", metadata)
            self.assertIn("algorithm", metadata["encryption"])

            # Decrypt the file
            temp_decrypt = tempfile.NamedTemporaryFile(delete=False)
            temp_decrypt.close()

            decrypt_result = decrypt_file(temp_output.name, temp_decrypt.name, self.password)

            # Check decryption was successful
            self.assertTrue(decrypt_result)

            # Verify decrypted content matches original
            with open(self.temp_input.name, "rb") as f:
                original_content = f.read()

            with open(temp_decrypt.name, "rb") as f:
                decrypted_content = f.read()

            self.assertEqual(original_content, decrypted_content)

            # Clean up
            os.unlink(temp_decrypt.name)
        finally:
            # Clean up output file
            os.unlink(temp_output.name)

    def test_backward_compatibility(self):
        """Test backward compatibility with format_version 3."""
        # Create temp files
        temp_v3_output = tempfile.NamedTemporaryFile(delete=False)
        temp_v3_output.close()

        # First use format_version 4 (default)
        hash_config = {
            "sha256": 10000,
            "sha512": 0,
            "sha3_256": 0,
            "sha3_512": 0,
            "blake2b": 0,
            "shake256": 0,
            "whirlpool": 0,
            "pbkdf2_iterations": 100000,
            "derivation_config": {"kdf_config": {"pbkdf2": {"rounds": 100000}}},
        }

        encrypt_file(
            self.temp_input.name, temp_v3_output.name, self.password, hash_config=hash_config
        )

        # Read the metadata
        metadata_v4 = self.read_metadata(temp_v3_output.name)
        self.assertEqual(metadata_v4.get("format_version"), 4)

        # Convert to version 3
        metadata_v3 = convert_metadata_v4_to_v3(metadata_v4)
        self.assertEqual(metadata_v3.get("format_version"), 3)

        # Check the key fields are preserved in the conversion
        self.assertEqual(metadata_v3.get("salt"), metadata_v4["derivation_config"]["salt"])

        # For hash_config, we need to handle the nested structure
        v4_hash_config = metadata_v4["derivation_config"]["hash_config"]
        for algo, config in v4_hash_config.items():
            if isinstance(config, dict) and "rounds" in config:
                self.assertEqual(metadata_v3["hash_config"][algo], config["rounds"])

        self.assertEqual(metadata_v3.get("original_hash"), metadata_v4["hashes"]["original_hash"])
        self.assertEqual(metadata_v3.get("encrypted_hash"), metadata_v4["hashes"]["encrypted_hash"])
        self.assertEqual(metadata_v3.get("algorithm"), metadata_v4["encryption"]["algorithm"])

        # Convert back to version 4
        metadata_v4_roundtrip = convert_metadata_v3_to_v4(metadata_v3)
        self.assertEqual(metadata_v4_roundtrip.get("format_version"), 4)

        # Verify structure is preserved in round-trip conversion
        for key in ["format_version", "derivation_config", "hashes", "encryption"]:
            self.assertIn(key, metadata_v4_roundtrip)

        # Verify nested structure
        self.assertIn("salt", metadata_v4_roundtrip["derivation_config"])
        self.assertIn("hash_config", metadata_v4_roundtrip["derivation_config"])
        self.assertIn("kdf_config", metadata_v4_roundtrip["derivation_config"])

        # Clean up
        os.unlink(temp_v3_output.name)

    def test_multi_format_cross_decryption(self):
        """Test decryption of both format_version 3 and 4 files."""
        # Create temp files for both formats
        temp_v3_output = tempfile.NamedTemporaryFile(delete=False)
        temp_v3_output.close()

        temp_v4_output = tempfile.NamedTemporaryFile(delete=False)
        temp_v4_output.close()

        # Encrypt with format_version 4 (default)
        hash_config = {
            "sha256": 10000,
            "sha512": 0,
            "sha3_256": 0,
            "sha3_512": 0,
            "blake2b": 0,
            "shake256": 0,
            "whirlpool": 0,
            "pbkdf2_iterations": 100000,
            "derivation_config": {"kdf_config": {"pbkdf2": {"rounds": 100000}}},
        }

        encrypt_file(
            self.temp_input.name, temp_v4_output.name, self.password, hash_config=hash_config
        )

        # Read the metadata and verify it's v4
        metadata_v4 = self.read_metadata(temp_v4_output.name)
        self.assertEqual(metadata_v4.get("format_version"), 4)

        # Manually create a v3 format by converting
        metadata_v3 = convert_metadata_v4_to_v3(metadata_v4)

        # Write the v3 metadata back
        with open(temp_v4_output.name, "rb") as f:
            content = f.read()

        # Find the colon separator
        colon_pos = content.find(b":")
        if colon_pos > 0:
            encrypted_data = content[colon_pos:]
            metadata_v3_json = json.dumps(metadata_v3)
            metadata_v3_b64 = base64.b64encode(metadata_v3_json.encode("utf-8"))

            # Write the file with v3 metadata
            with open(temp_v3_output.name, "wb") as f:
                f.write(metadata_v3_b64)
                f.write(encrypted_data)

        # Verify the metadata formats
        v3_meta = self.read_metadata(temp_v3_output.name)
        v4_meta = self.read_metadata(temp_v4_output.name)
        self.assertEqual(v3_meta.get("format_version"), 3)
        self.assertEqual(v4_meta.get("format_version"), 4)

        # Decrypt both formats
        temp_v3_decrypt = tempfile.NamedTemporaryFile(delete=False)
        temp_v3_decrypt.close()

        temp_v4_decrypt = tempfile.NamedTemporaryFile(delete=False)
        temp_v4_decrypt.close()

        # Decrypt format_version 3
        v3_result = decrypt_file(temp_v3_output.name, temp_v3_decrypt.name, self.password)

        # Decrypt format_version 4
        v4_result = decrypt_file(temp_v4_output.name, temp_v4_decrypt.name, self.password)

        # Check both decryptions were successful
        self.assertTrue(v3_result)
        self.assertTrue(v4_result)

        # Verify decrypted content matches original
        with open(self.temp_input.name, "rb") as f:
            original_content = f.read()

        with open(temp_v3_decrypt.name, "rb") as f:
            v3_content = f.read()

        with open(temp_v4_decrypt.name, "rb") as f:
            v4_content = f.read()

        self.assertEqual(original_content, v3_content)
        self.assertEqual(original_content, v4_content)

        # Clean up
        os.unlink(temp_v3_decrypt.name)
        os.unlink(temp_v4_decrypt.name)
        os.unlink(temp_v3_output.name)
        os.unlink(temp_v4_output.name)

    def test_nested_kdf_config_structure(self):
        """Test the nested structure in kdf_config for dual encryption and keystore keys."""
        # Create a metadata structure in v3 format with dual encryption and keystore key ID
        metadata_v3 = {
            "format_version": 3,
            "salt": "base64encodedstring",
            "hash_config": {"sha256": 10000, "sha512": 0},
            "pbkdf2_iterations": 100000,
            "dual_encryption": True,
            "pqc_keystore_key_id": "12345678-1234-1234-1234-123456789012",
            "original_hash": "abc123",
            "encrypted_hash": "def456",
            "algorithm": "kyber768-hybrid",
        }

        # Convert to v4
        metadata_v4 = convert_metadata_v3_to_v4(metadata_v3)

        # Verify structure
        self.assertEqual(metadata_v4["format_version"], 4)

        # Verify hash structure
        self.assertEqual(metadata_v4["derivation_config"]["hash_config"]["sha256"]["rounds"], 10000)
        self.assertEqual(metadata_v4["derivation_config"]["hash_config"]["sha512"]["rounds"], 0)

        # Verify KDF structure
        self.assertEqual(metadata_v4["derivation_config"]["kdf_config"]["pbkdf2"]["rounds"], 100000)

        # Verify dual encryption flag
        self.assertTrue(metadata_v4["derivation_config"]["kdf_config"]["dual_encryption"])

        # Verify keystore key ID
        self.assertEqual(
            metadata_v4["derivation_config"]["kdf_config"]["pqc_keystore_key_id"],
            "12345678-1234-1234-1234-123456789012",
        )

        # Convert back to v3
        metadata_v3_roundtrip = convert_metadata_v4_to_v3(metadata_v4)

        # Verify structure after round-trip
        self.assertEqual(metadata_v3_roundtrip["format_version"], 3)
        self.assertEqual(metadata_v3_roundtrip["hash_config"]["sha256"], 10000)
        self.assertEqual(metadata_v3_roundtrip["hash_config"]["sha512"], 0)
        self.assertEqual(metadata_v3_roundtrip["pbkdf2_iterations"], 100000)
        self.assertTrue(metadata_v3_roundtrip["dual_encryption"])
        self.assertEqual(
            metadata_v3_roundtrip["pqc_keystore_key_id"], "12345678-1234-1234-1234-123456789012"
        )


if __name__ == "__main__":
    unittest.main()
