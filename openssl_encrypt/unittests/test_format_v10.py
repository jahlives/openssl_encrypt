#!/usr/bin/env python3
"""
Unit tests for metadata format version 10 (Sequential + XOR composition).

Tests v10 encryption/decryption, XOR composition logic, and various algorithm combinations.
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
    multi_hash_password,
)


class TestFormatV10(unittest.TestCase):
    """Test suite for metadata format version 10 (XOR composition)."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.test_files = []

        # Create test file
        self.test_file = os.path.join(self.test_dir, "test_v10.txt")
        with open(self.test_file, "w") as f:
            f.write("Test data for v10 XOR composition\n" * 10)
        self.test_files.append(self.test_file)

        # Test password
        self.test_password = "test_password_v10"

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

    def test_v10_basic_round_trip(self):
        """Test basic v10 encryption/decryption round-trip."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_v10.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_v10.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        # Read original content
        with open(self.test_file, "rb") as f:
            original_content = f.read()

        # Encrypt with v10
        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=self.minimal_config,
            quiet=True,
        )

        # Verify metadata has v10
        metadata = extract_file_metadata(encrypted_file)
        self.assertEqual(metadata["format_version"], 10, "Should use format version 10")

        # Decrypt
        decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        # Verify content
        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content, "Decrypted content should match original")

    def test_v10_with_sha512_only(self):
        """Test v10 with SHA-512 hash only (no KDF)."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_sha512.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_sha512.txt")
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
        )

        decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content)

    def test_v10_with_argon2_only(self):
        """Test v10 with Argon2 KDF only (no hashing)."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_argon2.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_argon2.txt")
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
        )

        decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content)

    def test_v10_with_multiple_hashes_and_kdfs(self):
        """Test v10 with multiple hash algorithms and KDFs."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_multi.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_multi.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        config = {
            "sha512": 10,
            "blake2b": 10,
            "sha3_256": 10,
            "argon2": {
                "enabled": True,
                "time_cost": 1,
                "memory_cost": 512,
                "parallelism": 1,
                "type": "id",
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
        )

        decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content)

    def test_v10_with_all_hash_algorithms(self):
        """Test v10 with all hash algorithms enabled."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_all_hashes.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_all_hashes.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        config = {
            "sha512": 5,
            "sha256": 5,
            "sha3_256": 5,
            "sha3_512": 5,
            "blake2b": 5,
            "blake3": 5,
            "shake256": 5,
        }

        with open(self.test_file, "rb") as f:
            original_content = f.read()

        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=config,
            quiet=True,
        )

        decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content)

    def test_v10_different_from_v9(self):
        """Verify v10 produces different keys than v9 (due to XOR)."""
        password = b"test_password"
        salt = os.urandom(16)
        hash_config = {
            "sha512": 10,
            "argon2": {
                "enabled": True,
                "time_cost": 1,
                "memory_cost": 512,
                "parallelism": 1,
                "type": "id",
            },
        }

        # Generate key with v9
        key_v9, _, _ = generate_key(
            password, salt, hash_config, format_version=9, quiet=True
        )

        # Generate key with v10
        key_v10, _, _ = generate_key(
            password, salt, hash_config, format_version=10, quiet=True
        )

        # Keys MUST be different due to XOR in v10
        self.assertNotEqual(key_v9, key_v10, "v9 and v10 should produce different keys")

    def test_v10_deterministic(self):
        """Verify v10 key derivation is deterministic."""
        password = b"deterministic_test"
        salt = b"1234567890123456"  # Fixed salt
        hash_config = {"sha512": 10, "argon2": {"enabled": True, "time_cost": 1}}

        # Generate key twice with same inputs
        key1, _, _ = generate_key(
            password, salt, hash_config, format_version=10, quiet=True
        )
        key2, _, _ = generate_key(
            password, salt, hash_config, format_version=10, quiet=True
        )

        self.assertEqual(key1, key2, "v10 key derivation should be deterministic")

    def test_v10_with_different_algorithms(self):
        """Test v10 with different encryption algorithms."""
        algorithms = [
            EncryptionAlgorithm.AES_GCM,
            EncryptionAlgorithm.CHACHA20_POLY1305,
            EncryptionAlgorithm.AES_GCM_SIV,
        ]

        for algorithm in algorithms:
            with self.subTest(algorithm=algorithm.value):
                encrypted_file = os.path.join(self.test_dir, f"encrypted_{algorithm.value}.enc")
                decrypted_file = os.path.join(self.test_dir, f"decrypted_{algorithm.value}.txt")
                self.test_files.extend([encrypted_file, decrypted_file])

                with open(self.test_file, "rb") as f:
                    original_content = f.read()

                encrypt_file(
                    self.test_file,
                    encrypted_file,
                    self.test_password,
                    hash_config=self.minimal_config,
                    algorithm=algorithm.value,
                    quiet=True,
                )

                decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

                with open(decrypted_file, "rb") as f:
                    decrypted_content = f.read()

                self.assertEqual(original_content, decrypted_content)

    def test_v10_wrong_password_fails(self):
        """Verify v10 decryption fails with wrong password."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_wrong_pw.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_wrong_pw.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=self.minimal_config,
            quiet=True,
        )

        # Try to decrypt with wrong password - should fail
        with self.assertRaises(Exception):
            decrypt_file(encrypted_file, decrypted_file, "wrong_password", quiet=True)

    def test_v10_metadata_structure(self):
        """Verify v10 metadata has correct structure."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_metadata.enc")
        self.test_files.append(encrypted_file)

        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=self.minimal_config,
            quiet=True,
        )

        metadata = extract_file_metadata(encrypted_file)

        # Verify required fields
        self.assertIn("format_version", metadata)
        self.assertEqual(metadata["format_version"], 10)
        self.assertIn("derivation_config", metadata)
        self.assertIn("salt", metadata["derivation_config"])
        self.assertIn("hash_config", metadata["derivation_config"])
        self.assertIn("encryption", metadata)

    def test_v10_with_pbkdf2(self):
        """Test v10 with PBKDF2 iterations."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_pbkdf2.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_pbkdf2.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        config = {"sha512": 10, "pbkdf2_iterations": 1000}

        with open(self.test_file, "rb") as f:
            original_content = f.read()

        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=config,
            quiet=True,
        )

        decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content)

    def test_v10_empty_file(self):
        """Test v10 with empty file."""
        empty_file = os.path.join(self.test_dir, "empty.txt")
        encrypted_file = os.path.join(self.test_dir, "encrypted_empty.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_empty.txt")
        self.test_files.extend([empty_file, encrypted_file, decrypted_file])

        # Create empty file
        open(empty_file, "w").close()

        encrypt_file(
            empty_file,
            encrypted_file,
            self.test_password,
            hash_config=self.minimal_config,
            quiet=True,
        )

        decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        self.assertTrue(os.path.exists(decrypted_file))
        self.assertEqual(os.path.getsize(decrypted_file), 0)

    def test_v10_large_file(self):
        """Test v10 with larger file."""
        large_file = os.path.join(self.test_dir, "large.txt")
        encrypted_file = os.path.join(self.test_dir, "encrypted_large.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_large.txt")
        self.test_files.extend([large_file, encrypted_file, decrypted_file])

        # Create larger file (1MB)
        with open(large_file, "wb") as f:
            f.write(b"X" * 1024 * 1024)

        with open(large_file, "rb") as f:
            original_content = f.read()

        encrypt_file(
            large_file,
            encrypted_file,
            self.test_password,
            hash_config=self.minimal_config,
            quiet=True,
        )

        decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content)

    def test_v10_binary_file(self):
        """Test v10 with binary file."""
        binary_file = os.path.join(self.test_dir, "binary.dat")
        encrypted_file = os.path.join(self.test_dir, "encrypted_binary.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_binary.dat")
        self.test_files.extend([binary_file, encrypted_file, decrypted_file])

        # Create binary file with random data
        binary_content = os.urandom(10240)  # 10KB random data
        with open(binary_file, "wb") as f:
            f.write(binary_content)

        encrypt_file(
            binary_file,
            encrypted_file,
            self.test_password,
            hash_config=self.minimal_config,
            quiet=True,
        )

        decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(binary_content, decrypted_content)


if __name__ == "__main__":
    unittest.main()
