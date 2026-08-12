#!/usr/bin/env python3
"""
Unit tests for parallel KDF functionality in v11 Independent XOR.

Tests the parallel derivation entry point (since gitlab#224 a thread-pool run
of the same shared component implementation as sequential mode) and verifies
key consistency with sequential mode.
"""

import os
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import (
    decrypt_file,
    encrypt_file,
    extract_file_metadata,
    generate_key_independent_xor,
)
from openssl_encrypt.modules.parallel_kdf import generate_key_independent_xor_parallel


class TestParallelKDF(unittest.TestCase):
    """Test suite for parallel KDF functionality."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.test_files = []

        # Create test file
        self.test_file = os.path.join(self.test_dir, "test_parallel.txt")
        with open(self.test_file, "w", encoding="utf-8") as f:
            f.write("Test data for parallel KDF\n" * 10)
        self.test_files.append(self.test_file)

        # Test password
        self.test_password = "test_password_parallel_kdf"

        # Hash config with multiple algorithms for meaningful parallelism
        self.hash_config = {
            "sha256": 100,
            "sha512": 100,
            "blake2b": 100,
            "argon2": {
                "enabled": True,
                "time_cost": 1,
                "memory_cost": 512,
                "parallelism": 1,
                "type": "id",
            },
            "scrypt": {
                "enabled": True,
                "n": 1024,
                "r": 1,
                "p": 1,
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

    def test_parallel_produces_same_key_as_sequential(self):
        """CRITICAL: Verify parallel and sequential modes produce identical keys."""
        password = self.test_password.encode("utf-8")
        salt = os.urandom(16)

        # Generate key with sequential mode
        key_seq, _, _ = generate_key_independent_xor(
            password,
            salt,
            self.hash_config,
            quiet=True,
            format_version=11,
        )

        # Generate key with parallel mode
        key_par, _, _ = generate_key_independent_xor_parallel(
            password,
            salt,
            self.hash_config,
            quiet=True,
            format_version=11,
        )

        # Keys must be identical
        self.assertEqual(
            key_seq,
            key_par,
            "Parallel and sequential modes must produce identical keys",
        )

    def test_parallel_round_trip(self):
        """Test encrypt/decrypt with parallel KDF."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_parallel.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_parallel.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        # Read original content
        with open(self.test_file, "rb") as f:
            original_content = f.read()

        # Encrypt with parallel KDF
        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=self.hash_config,
            quiet=True,
            format_version=11,
            parallel_kdf=True,
        )

        # Verify metadata
        metadata = extract_file_metadata(encrypted_file)
        self.assertEqual(metadata["format_version"], 11)
        self.assertEqual(metadata.get("xor_mode"), "independent")

        # Decrypt with parallel KDF
        decrypt_file(
            encrypted_file,
            decrypted_file,
            self.test_password,
            quiet=True,
            parallel_kdf=True,
        )

        # Verify content
        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content)

    def test_parallel_decrypt_sequential_encrypted(self):
        """Test decrypting sequentially-encrypted file with parallel mode."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_seq.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_par.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        # Read original content
        with open(self.test_file, "rb") as f:
            original_content = f.read()

        # Encrypt with sequential mode
        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=self.hash_config,
            quiet=True,
            format_version=11,
            parallel_kdf=False,
        )

        # Decrypt with parallel mode
        decrypt_file(
            encrypted_file,
            decrypted_file,
            self.test_password,
            quiet=True,
            parallel_kdf=True,
        )

        # Verify content
        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content)

    def test_sequential_decrypt_parallel_encrypted(self):
        """Test decrypting parallel-encrypted file with sequential mode."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_par.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_seq.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        # Read original content
        with open(self.test_file, "rb") as f:
            original_content = f.read()

        # Encrypt with parallel mode
        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=self.hash_config,
            quiet=True,
            format_version=11,
            parallel_kdf=True,
        )

        # Decrypt with sequential mode
        decrypt_file(
            encrypted_file,
            decrypted_file,
            self.test_password,
            quiet=True,
            parallel_kdf=False,
        )

        # Verify content
        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content)

    def test_parallel_with_single_algorithm(self):
        """Test parallel mode with only one algorithm (edge case)."""
        # Config with only one hash algorithm
        minimal_config = {"sha256": 50}

        password = self.test_password.encode("utf-8")
        salt = os.urandom(16)

        # Should work even with single algorithm
        key_par, _, _ = generate_key_independent_xor_parallel(
            password,
            salt,
            minimal_config,
            quiet=True,
            format_version=11,
        )

        # Verify key was generated
        self.assertIsNotNone(key_par)
        self.assertGreater(len(key_par), 0)

    def test_parallel_with_different_ciphers(self):
        """Test parallel KDF with different encryption algorithms."""
        test_algorithms = ["aes-gcm", "chacha20-poly1305", "aes-siv"]

        password = self.test_password.encode("utf-8")
        salt = os.urandom(16)

        keys = {}

        for algo in test_algorithms:
            key, _, _ = generate_key_independent_xor_parallel(
                password,
                salt,
                self.hash_config,
                algorithm=algo,
                quiet=True,
                format_version=11,
            )
            keys[algo] = key

        # Different algorithms should produce keys of correct length
        # aes-gcm: 32 bytes, aes-siv: 64 bytes (after SHA-512)
        self.assertEqual(len(keys["aes-gcm"]), 32)
        self.assertEqual(len(keys["chacha20-poly1305"]), 32)
        self.assertEqual(len(keys["aes-siv"]), 64)

    def test_parallel_with_custom_worker_count(self):
        """Test parallel KDF with custom number of workers."""
        password = self.test_password.encode("utf-8")
        salt = os.urandom(16)

        # Test with 2 workers
        key1, _, _ = generate_key_independent_xor_parallel(
            password,
            salt,
            self.hash_config,
            quiet=True,
            format_version=11,
            max_workers=2,
        )

        # Test with 4 workers
        key2, _, _ = generate_key_independent_xor_parallel(
            password,
            salt,
            self.hash_config,
            quiet=True,
            format_version=11,
            max_workers=4,
        )

        # Worker count shouldn't affect key (deterministic XOR order)
        self.assertEqual(key1, key2)

    def test_parallel_wrong_password_fails(self):
        """Test that wrong password fails decryption with parallel KDF."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_wrong_pw.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_wrong_pw.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        # Encrypt with parallel KDF
        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=self.hash_config,
            quiet=True,
            format_version=11,
            parallel_kdf=True,
        )

        # Try to decrypt with wrong password
        with self.assertRaises(Exception):
            decrypt_file(
                encrypted_file,
                decrypted_file,
                "wrong_password",
                quiet=True,
                parallel_kdf=True,
            )

    def test_parallel_all_hash_algorithms(self):
        """Test parallel mode with all supported hash algorithms."""
        # Config with all hash algorithms. (Whirlpool participates since
        # gitlab#224; its dedicated equivalence tests live in
        # test_parallel_kdf_legacy_route_224.py.)
        full_hash_config = {
            "sha256": 10,
            "sha512": 10,
            "sha3_256": 10,
            "sha3_512": 10,
            "blake2b": 10,
            "blake3": 10,
            "shake256": 10,
        }

        password = self.test_password.encode("utf-8")
        salt = os.urandom(16)

        # Sequential mode
        key_seq, _, _ = generate_key_independent_xor(
            password,
            salt,
            full_hash_config,
            quiet=True,
            format_version=11,
        )

        # Parallel mode
        key_par, _, _ = generate_key_independent_xor_parallel(
            password,
            salt,
            full_hash_config,
            quiet=True,
            format_version=11,
        )

        # Keys must match
        self.assertEqual(key_seq, key_par)

    def test_parallel_all_kdfs(self):
        """Test parallel mode with all supported KDFs."""
        # Config with all KDFs (except balloon which may not be installed)
        kdf_config = {
            "argon2": {
                "enabled": True,
                "time_cost": 1,
                "memory_cost": 512,
                "parallelism": 1,
                "type": "id",
            },
            "scrypt": {
                "enabled": True,
                "n": 1024,
                "r": 1,
                "p": 1,
            },
            "hkdf": {
                "enabled": True,
                "info": b"test-hkdf-info",
            },
        }

        password = self.test_password.encode("utf-8")
        salt = os.urandom(16)

        # Sequential mode
        key_seq, _, _ = generate_key_independent_xor(
            password,
            salt,
            kdf_config,
            quiet=True,
            format_version=11,
        )

        # Parallel mode
        key_par, _, _ = generate_key_independent_xor_parallel(
            password,
            salt,
            kdf_config,
            quiet=True,
            format_version=11,
        )

        # Keys must match
        self.assertEqual(key_seq, key_par)

    def test_parallel_empty_config_raises_error(self):
        """Test that empty config raises ValueError."""
        password = self.test_password.encode("utf-8")
        salt = os.urandom(16)

        # Empty config should raise error
        with self.assertRaises(ValueError):
            generate_key_independent_xor_parallel(
                password,
                salt,
                {},
                quiet=True,
                format_version=11,
            )


if __name__ == "__main__":
    unittest.main()
