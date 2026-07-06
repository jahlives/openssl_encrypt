#!/usr/bin/env python3
"""
Cross-version compatibility tests for v8 (1.3 branch) and v10 (1.4 branch).

Tests that:
1. v8 and v10 produce identical keys with same inputs
2. Files encrypted with v8 can be decrypted by v10 code
3. Both versions use the same XOR composition logic
All code in English as per project requirements.
"""

import os
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import (
    EncryptionAlgorithm,
    decrypt_file,
    encrypt_file,
    extract_file_metadata,
    generate_key,
)


class TestCrossVersionV8V10(unittest.TestCase):
    """Test suite for v8/v10 cross-version compatibility."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.test_files = []

        # Create test file
        self.test_file = os.path.join(self.test_dir, "test_cross_version.txt")
        with open(self.test_file, "w", encoding="utf-8") as f:
            f.write("Cross-version compatibility test data\n" * 10)
        self.test_files.append(self.test_file)

        # Test password
        self.test_password = "cross_version_password"

        # Minimal config for faster tests
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

    def test_v8_and_v10_produce_same_key(self):
        """
        CRITICAL: Verify v8 and v10 produce IDENTICAL keys with same inputs.

        This proves cross-version compatibility at the key derivation level.
        """
        password = b"identical_password"
        salt = b"1234567890123456"  # Fixed 16-byte salt
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

        # Generate key with v8 (1.3 branch format)
        key_v8, _, _ = generate_key(password, salt, hash_config, format_version=8, quiet=True)

        # Generate key with v10 (1.4 branch format)
        key_v10, _, _ = generate_key(password, salt, hash_config, format_version=10, quiet=True)

        # Keys MUST be identical for cross-version compatibility
        self.assertEqual(
            key_v8,
            key_v10,
            "v8 and v10 must produce identical keys for cross-version compatibility!",
        )

    def test_v8_encrypt_v10_decrypt(self):
        """
        Test that files encrypted with v8 can be decrypted by v10 code.

        This simulates: User encrypts file with 1.3 (v8), then decrypts with 1.4 (v10).
        """
        encrypted_file = os.path.join(self.test_dir, "encrypted_v8.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_v8_by_v10.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        with open(self.test_file, "rb") as f:
            original_content = f.read()

        # Encrypt with v8 (simulating 1.3 branch)
        # v8 is decrypt-only for new encryption; the explicit legacy hatch lets
        # this backward-compat test still produce a v8 fixture on purpose.
        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=self.minimal_config,
            quiet=True,
            format_version=8,
            allow_insecure_legacy_xor=True,
        )

        # Verify metadata shows v8
        metadata = extract_file_metadata(encrypted_file)
        self.assertEqual(metadata["format_version"], 8)

        # Decrypt with current 1.4 code (should auto-detect v8 and use XOR logic)
        decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(
            original_content,
            decrypted_content,
            "v10 code should decrypt v8 files correctly",
        )

    def test_v8_key_derivation_deterministic(self):
        """Verify v8 key derivation is deterministic."""
        password = b"v8_deterministic_test"
        salt = b"fixed_salt_12345"
        hash_config = {
            "sha512": 10,
            "argon2": {"enabled": True, "time_cost": 1, "memory_cost": 512},
        }

        key1, _, _ = generate_key(password, salt, hash_config, format_version=8, quiet=True)
        key2, _, _ = generate_key(password, salt, hash_config, format_version=8, quiet=True)

        self.assertEqual(key1, key2, "v8 key derivation should be deterministic")

    def test_v10_key_derivation_deterministic(self):
        """Verify v10 key derivation is deterministic."""
        password = b"v10_deterministic_test"
        salt = b"fixed_salt_67890"
        hash_config = {
            "sha512": 10,
            "argon2": {"enabled": True, "time_cost": 1, "memory_cost": 512},
        }

        key1, _, _ = generate_key(password, salt, hash_config, format_version=10, quiet=True)
        key2, _, _ = generate_key(password, salt, hash_config, format_version=10, quiet=True)

        self.assertEqual(key1, key2, "v10 key derivation should be deterministic")

    def test_v8_v10_with_multiple_algorithms(self):
        """Test v8/v10 key equivalence with multiple algorithms.

        Both v8 and v10 use SECURE CHAINED derivation (prevents precomputation attacks).
        v8 has no legacy files (it was introduced fresh in 1.3 with XOR), so it uses
        the same secure derivation as v10 for full compatibility between 1.3 and 1.4.

        Both preserve dict order to ensure deterministic encryption/decryption.
        """
        password = b"multi_algo_test"
        salt = b"salt_for_testing"
        hash_config = {
            "sha512": 5,
            "blake2b": 5,
            "sha3_256": 5,
            "argon2": {
                "enabled": True,
                "time_cost": 1,
                "memory_cost": 512,
                "parallelism": 1,
            },
            "scrypt": {"enabled": True, "n": 1024, "r": 8, "p": 1},
        }

        key_v8, _, _ = generate_key(password, salt, hash_config, format_version=8, quiet=True)
        key_v10, _, _ = generate_key(password, salt, hash_config, format_version=10, quiet=True)

        # v8 and v10 should produce SAME keys (both use secure derivation)
        self.assertEqual(key_v8, key_v10, "Keys should match with multiple algorithms")

    def test_v8_v10_with_pbkdf2(self):
        """Test v8/v10 key equivalence with PBKDF2."""
        password = b"pbkdf2_test"
        salt = b"pbkdf2_salt_1234"
        hash_config = {"sha512": 10, "pbkdf2_iterations": 1000}

        key_v8, _, _ = generate_key(password, salt, hash_config, format_version=8, quiet=True)
        key_v10, _, _ = generate_key(password, salt, hash_config, format_version=10, quiet=True)

        self.assertEqual(key_v8, key_v10, "Keys should match with PBKDF2")

    def test_v8_v10_with_single_hash(self):
        """Test v8/v10 key equivalence with single hash algorithm."""
        password = b"single_hash_test"
        salt = b"single_hash_salt"
        hash_config = {"sha512": 100}

        key_v8, _, _ = generate_key(password, salt, hash_config, format_version=8, quiet=True)
        key_v10, _, _ = generate_key(password, salt, hash_config, format_version=10, quiet=True)

        self.assertEqual(key_v8, key_v10, "Keys should match with single hash")

    def test_v8_v10_with_no_hashing(self):
        """Test v8/v10 key equivalence with KDF only (no hashing)."""
        password = b"kdf_only_test"
        salt = b"kdf_only_salt_12"
        hash_config = {
            "argon2": {
                "enabled": True,
                "time_cost": 2,
                "memory_cost": 1024,
                "parallelism": 1,
            }
        }

        key_v8, _, _ = generate_key(password, salt, hash_config, format_version=8, quiet=True)
        key_v10, _, _ = generate_key(password, salt, hash_config, format_version=10, quiet=True)

        self.assertEqual(key_v8, key_v10, "Keys should match with KDF only")

    def test_v8_v10_different_from_v9(self):
        """Verify both v8 and v10 produce different keys than v9."""
        password = b"v9_comparison_test"
        salt = b"v9_comparison_slt"
        hash_config = {
            "sha512": 10,
            "argon2": {"enabled": True, "time_cost": 1, "memory_cost": 512},
        }

        key_v8, _, _ = generate_key(password, salt, hash_config, format_version=8, quiet=True)
        key_v9, _, _ = generate_key(password, salt, hash_config, format_version=9, quiet=True)
        key_v10, _, _ = generate_key(password, salt, hash_config, format_version=10, quiet=True)

        # v8 and v10 should be identical
        self.assertEqual(key_v8, key_v10)

        # But both should differ from v9 (no XOR)
        self.assertNotEqual(key_v8, key_v9, "v8 should differ from v9 (XOR vs no XOR)")
        self.assertNotEqual(key_v10, key_v9, "v10 should differ from v9 (XOR vs no XOR)")

    def test_v8_v10_with_different_salts(self):
        """Verify v8/v10 produce different keys with different salts."""
        password = b"salt_sensitivity_test"
        salt1 = b"salt_one_1234567"
        salt2 = b"salt_two_7654321"
        hash_config = {"sha512": 10, "argon2": {"enabled": True, "time_cost": 1}}

        # Keys with different salts should differ
        key_v8_salt1, _, _ = generate_key(
            password, salt1, hash_config, format_version=8, quiet=True
        )
        key_v8_salt2, _, _ = generate_key(
            password, salt2, hash_config, format_version=8, quiet=True
        )

        self.assertNotEqual(
            key_v8_salt1, key_v8_salt2, "Different salts should produce different keys"
        )

    def test_v8_v10_with_different_passwords(self):
        """Verify v8/v10 produce different keys with different passwords."""
        password1 = b"password_one"
        password2 = b"password_two"
        salt = b"common_salt_1234"
        hash_config = {"sha512": 10, "argon2": {"enabled": True, "time_cost": 1}}

        key_v8_pw1, _, _ = generate_key(password1, salt, hash_config, format_version=8, quiet=True)
        key_v8_pw2, _, _ = generate_key(password2, salt, hash_config, format_version=8, quiet=True)

        self.assertNotEqual(
            key_v8_pw1, key_v8_pw2, "Different passwords should produce different keys"
        )

    def test_v8_v10_key_length_consistency(self):
        """Verify v8/v10 produce keys of correct length."""
        password = b"key_length_test"
        salt = b"key_length_salt1"
        hash_config = {"sha512": 10, "argon2": {"enabled": True, "time_cost": 1}}

        key_v8, _, _ = generate_key(
            password,
            salt,
            hash_config,
            algorithm=EncryptionAlgorithm.AES_GCM.value,
            format_version=8,
            quiet=True,
        )
        key_v10, _, _ = generate_key(
            password,
            salt,
            hash_config,
            algorithm=EncryptionAlgorithm.AES_GCM.value,
            format_version=10,
            quiet=True,
        )

        # AES-GCM requires 32 bytes
        self.assertEqual(len(key_v8), 32, "v8 should produce 32-byte key for AES-GCM")
        self.assertEqual(len(key_v10), 32, "v10 should produce 32-byte key for AES-GCM")

    def test_backward_compatibility_v9_still_works(self):
        """Verify v9 files can still be decrypted (backward compatibility)."""
        encrypted_file = os.path.join(self.test_dir, "encrypted_v9_compat.enc")
        decrypted_file = os.path.join(self.test_dir, "decrypted_v9_compat.txt")
        self.test_files.extend([encrypted_file, decrypted_file])

        with open(self.test_file, "rb") as f:
            original_content = f.read()

        # Encrypt with the secure default (now v9) and verify round-trip.
        encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=self.minimal_config,
            quiet=True,
        )

        decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content)


if __name__ == "__main__":
    unittest.main()
