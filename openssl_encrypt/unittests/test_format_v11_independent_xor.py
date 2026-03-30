#!/usr/bin/env python3
"""
Unit tests for metadata format version 11 (Independent XOR composition - Massey).

Tests v11 encryption/decryption, independent XOR composition logic, and various algorithm combinations.
Verifies that each algorithm processes the original input independently (no chaining).
All code in English as per project requirements.
"""

import hashlib
import json
import os
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import (
    EncryptionAlgorithm,
    decrypt_file,
    encrypt_file,
    extract_file_metadata,
    generate_key,
    generate_key_independent_xor,
)


class TestFormatV11IndependentXOR(unittest.TestCase):
    """Test suite for metadata format version 11 (Independent XOR - Massey)."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.test_files = []

        # Create test file
        self.test_file = os.path.join(self.test_dir, "test_v11.txt")
        with open(self.test_file, "w", encoding="utf-8") as f:
            f.write("Test data for v11 Independent XOR (Massey)\n" * 10)
        self.test_files.append(self.test_file)

        # Test password
        self.test_password = "test_password_v11_independent"

        # Minimal hash config for faster tests
        self.minimal_config = {
            "sha512": 10,
            "argon2": {
                "enabled": True,
                "time_cost": 1,
                "memory_cost": 512,
                "parallelism": 1,
                "type": "id",
            },
        }

    def tearDown(self):
        """Clean up test files."""
        for test_file in self.test_files:
            if os.path.exists(test_file):
                os.remove(test_file)
        if os.path.exists(self.test_dir):
            try:
                os.rmdir(self.test_dir)
            except OSError:
                pass

    def test_v11_basic_round_trip(self):
        """Test basic v11 encryption/decryption round-trip."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_v11.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_v11.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        # Read original content
        with open(self.test_file, "rb") as f:
            original_content = f.read()

        # Encrypt with v11
        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=self.minimal_config,
            quiet=True,
            format_version=11,
        )

        # Verify metadata has v11 and xor_mode='independent'
        metadata = extract_file_metadata(encrypted_file)
        self.assertEqual(metadata["format_version"], 11, "Should use format version 11")
        self.assertEqual(
            metadata.get("xor_mode"),
            "independent",
            "Should have xor_mode='independent' for v11",
        )

        # Decrypt
        decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        # Verify content
        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(
            original_content,
            decrypted_content,
            "Decrypted content should match original",
        )

    def test_v11_produces_different_key_than_v10(self):
        """Verify v11 produces different keys than v10 (different XOR mode)."""
        password = b"test_password"
        salt = os.urandom(16)
        config = {
            "sha512": 100,
            "argon2": {
                "enabled": True,
                "time_cost": 1,
                "memory_cost": 512,
                "parallelism": 1,
            },
        }

        # Generate key with v10 (sequential XOR)
        key_v10, _, _ = generate_key(password, salt, config, quiet=True, format_version=10)

        # Generate key with v11 (independent XOR)
        key_v11, _, _ = generate_key_independent_xor(
            password, salt, config, quiet=True, format_version=11
        )

        # Keys MUST be different due to different XOR modes
        self.assertNotEqual(
            key_v10,
            key_v11,
            "v10 (sequential) and v11 (independent) must produce different keys",
        )

    def test_v11_with_sha512_only(self):
        """Test v11 with SHA-512 hash only (no KDF)."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_sha512_v11.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_sha512_v11.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        config = {"sha512": 100}

        with open(self.test_file, "rb") as f:
            original_content = f.read()

        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=config,
            quiet=True,
            format_version=11,
        )

        # Verify xor_mode
        metadata = extract_file_metadata(encrypted_file)
        self.assertEqual(metadata.get("xor_mode"), "independent")

        decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content)

    def test_v11_with_argon2_only(self):
        """Test v11 with Argon2 KDF only (no hashing)."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_argon2_v11.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_argon2_v11.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        config = {
            "argon2": {
                "enabled": True,
                "time_cost": 2,
                "memory_cost": 1024,
                "parallelism": 1,
                "type": "id",
            }
        }

        with open(self.test_file, "rb") as f:
            original_content = f.read()

        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=config,
            quiet=True,
            format_version=11,
        )

        decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content)

    def test_v11_with_multiple_hashes(self):
        """Test v11 with multiple hash algorithms."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_multihash_v11.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_multihash_v11.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        config = {
            "sha256": 50,
            "sha512": 50,
            "blake2b": 50,
        }

        with open(self.test_file, "rb") as f:
            original_content = f.read()

        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=config,
            quiet=True,
            format_version=11,
        )

        decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content)

    def test_v11_with_scrypt(self):
        """Test v11 with Scrypt KDF."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_scrypt_v11.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_scrypt_v11.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        config = {
            "sha256": 10,
            "scrypt": {"enabled": True, "n": 1024, "r": 8, "p": 1},
        }

        with open(self.test_file, "rb") as f:
            original_content = f.read()

        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=config,
            quiet=True,
            format_version=11,
        )

        decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content)

    def test_v11_with_hkdf(self):
        """Test v11 with HKDF."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_hkdf_v11.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_hkdf_v11.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        config = {
            "sha512": 10,
            "hkdf": {"enabled": True, "info": "test-info"},
        }

        with open(self.test_file, "rb") as f:
            original_content = f.read()

        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=config,
            quiet=True,
            format_version=11,
        )

        decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content)

    def test_v11_with_all_algorithms(self):
        """Test v11 with multiple hashes and multiple KDFs."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_all_v11.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_all_v11.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        config = {
            "sha256": 10,
            "sha512": 10,
            "blake2b": 10,
            "argon2": {
                "enabled": True,
                "time_cost": 1,
                "memory_cost": 512,
                "parallelism": 1,
            },
            "scrypt": {"enabled": True, "n": 1024, "r": 8, "p": 1},
        }

        with open(self.test_file, "rb") as f:
            original_content = f.read()

        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=config,
            quiet=True,
            format_version=11,
        )

        decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content)

    # NOTE: Backward compatibility tests for v9/v10 are covered by the main test suite
    # (test_format_versions.py, test_xor_composition.py, etc.)
    # These tests are not specific to v11 independent XOR functionality

    def test_v11_with_different_algorithms(self):
        """Test v11 with different encryption algorithms."""
        algorithms = ["aes-gcm", "chacha20-poly1305", "xchacha20-poly1305"]

        for algo in algorithms:
            with self.subTest(algorithm=algo):
                encrypted_file = os.path.join(self.test_dir, f"encrypted_{algo}_v11.enc")
                decrypted_file = os.path.join(self.test_dir, f"decrypted_{algo}_v11.txt")
                self.test_files.extend([encrypted_file, decrypted_file])

                with open(self.test_file, "rb") as f:
                    original_content = f.read()

                encrypt_file(
                    self.test_file,
                    encrypted_file,
                    self.test_password,
                    hash_config=self.minimal_config,
                    quiet=True,
                    algorithm=algo,
                    format_version=11,
                )

                decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

                with open(decrypted_file, "rb") as f:
                    decrypted_content = f.read()

                self.assertEqual(original_content, decrypted_content)

    def test_v11_wrong_password_fails(self):
        """Test that decryption with wrong password fails for v11."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_wrong_pw_v11.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_wrong_pw_v11.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        # Encrypt
        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=self.minimal_config,
            quiet=True,
            format_version=11,
        )

        # Try to decrypt with wrong password - should fail
        with self.assertRaises(Exception):
            decrypt_file(encrypted_file, decrypted_file, "wrong_password", quiet=True)

    def test_v11_metadata_structure(self):
        """Verify v11 metadata has correct structure."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_metadata_v11.enc")
        self.test_files.append(encrypted_file)

        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=self.minimal_config,
            quiet=True,
            format_version=11,
        )

        result = extract_file_metadata(encrypted_file)

        # Check top-level fields
        self.assertIn("format_version", result)
        self.assertEqual(result["format_version"], 11)

        self.assertIn("xor_mode", result)
        self.assertEqual(result["xor_mode"], "independent")

        # Check nested metadata structure
        self.assertIn("metadata", result)
        metadata = result["metadata"]

        self.assertIn("derivation_config", metadata)
        self.assertIn("salt", metadata["derivation_config"])
        self.assertIn("hash_config", metadata["derivation_config"])

        self.assertIn("encryption", metadata)
        self.assertIn("algorithm", metadata["encryption"])


if __name__ == "__main__":
    unittest.main()
