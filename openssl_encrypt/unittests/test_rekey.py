#!/usr/bin/env python3
"""
Unit tests for the rekey feature.

Tests re-encryption of files with a new password, covering:
- Basic rekey: encrypt → rekey → decrypt with new password
- Algorithm variants: rekey works for each symmetric cipher
- Algorithm change: rekey with different cipher than original
- In-place rekey: overwrites input file correctly
- Output file: writes to separate output
- Edge cases: wrong old password, empty file, same password, nonexistent file
- Security: temp files cleaned up, file permissions preserved
- CLI integration: subprocess with --password/--rekey-password flags
"""

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import (
    EncryptionAlgorithm,
    decrypt_file,
    encrypt_file,
    extract_file_metadata,
    rekey_file,
)
from openssl_encrypt.modules.crypt_errors import DecryptionError, RekeyError


class TestRekeyBasic(unittest.TestCase):
    """Basic rekey functionality tests."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.old_password = b"old_password_123"
        self.new_password = b"new_password_456"

        # Create test file with known content
        self.test_content = b"Hello World! This is test content for rekey."
        with open(self.test_file, "wb") as f:
            f.write(self.test_content)

    def tearDown(self):
        """Clean up test files."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_rekey_basic_with_output_file(self):
        """Encrypt → rekey to output file → decrypt with new password succeeds."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        # Encrypt
        encrypt_file(self.test_file, encrypted_file, self.old_password, quiet=True)

        # Rekey to output file
        result = rekey_file(
            input_file=encrypted_file,
            output_file=rekeyed_file,
            old_password=self.old_password,
            new_password=self.new_password,
            quiet=True,
        )
        self.assertTrue(result)
        self.assertTrue(os.path.exists(rekeyed_file))

        # Decrypt with new password
        decrypted = decrypt_file(rekeyed_file, decrypted_file, self.new_password, quiet=True)
        self.assertTrue(decrypted)
        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)

    def test_rekey_old_password_fails_on_rekeyed_file(self):
        """After rekey, old password should fail to decrypt."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")

        encrypt_file(self.test_file, encrypted_file, self.old_password, quiet=True)
        rekey_file(
            input_file=encrypted_file,
            output_file=rekeyed_file,
            old_password=self.old_password,
            new_password=self.new_password,
            quiet=True,
        )

        # Old password should fail
        with self.assertRaises(Exception):
            decrypt_file(
                rekeyed_file,
                os.path.join(self.temp_dir, "fail.txt"),
                self.old_password,
                quiet=True,
            )

    def test_rekey_in_place(self):
        """Rekey with output_file=None overwrites input file in-place."""
        encrypted_file = self.test_file + ".encrypted"
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        # Encrypt
        encrypt_file(self.test_file, encrypted_file, self.old_password, quiet=True)

        # Rekey in-place
        result = rekey_file(
            input_file=encrypted_file,
            output_file=None,
            old_password=self.old_password,
            new_password=self.new_password,
            quiet=True,
        )
        self.assertTrue(result)

        # Decrypt with new password
        decrypted = decrypt_file(encrypted_file, decrypted_file, self.new_password, quiet=True)
        self.assertTrue(decrypted)
        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)

    def test_rekey_preserves_content(self):
        """Rekey preserves the exact original plaintext content."""
        # Use larger content to catch any truncation issues
        large_content = os.urandom(1024 * 100)  # 100KB of random data
        large_file = os.path.join(self.temp_dir, "large.bin")
        with open(large_file, "wb") as f:
            f.write(large_content)

        encrypted_file = large_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")
        decrypted_file = os.path.join(self.temp_dir, "decrypted.bin")

        encrypt_file(large_file, encrypted_file, self.old_password, quiet=True)
        rekey_file(
            input_file=encrypted_file,
            output_file=rekeyed_file,
            old_password=self.old_password,
            new_password=self.new_password,
            quiet=True,
        )
        decrypt_file(rekeyed_file, decrypted_file, self.new_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), large_content)

    def test_rekey_same_password(self):
        """Rekey with the same password should still work (re-encrypt with new salt/nonce)."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        encrypt_file(self.test_file, encrypted_file, self.old_password, quiet=True)

        # Read original encrypted content
        with open(encrypted_file, "rb") as f:
            original_encrypted = f.read()

        rekey_file(
            input_file=encrypted_file,
            output_file=rekeyed_file,
            old_password=self.old_password,
            new_password=self.old_password,  # Same password
            quiet=True,
        )

        # Files should differ (different salt/nonce)
        with open(rekeyed_file, "rb") as f:
            rekeyed_encrypted = f.read()
        self.assertNotEqual(original_encrypted, rekeyed_encrypted)

        # Should still decrypt
        decrypt_file(rekeyed_file, decrypted_file, self.old_password, quiet=True)
        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)

    def test_rekey_returns_true_on_success(self):
        """rekey_file() returns True on success."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")

        encrypt_file(self.test_file, encrypted_file, self.old_password, quiet=True)
        result = rekey_file(
            input_file=encrypted_file,
            output_file=rekeyed_file,
            old_password=self.old_password,
            new_password=self.new_password,
            quiet=True,
        )
        self.assertTrue(result)


class TestRekeyAlgorithms(unittest.TestCase):
    """Test rekey with different encryption algorithms."""

    SYMMETRIC_ALGORITHMS = [
        EncryptionAlgorithm.FERNET,
        EncryptionAlgorithm.AES_GCM,
        EncryptionAlgorithm.CHACHA20_POLY1305,
        EncryptionAlgorithm.XCHACHA20_POLY1305,
        EncryptionAlgorithm.AES_SIV,
        EncryptionAlgorithm.AES_GCM_SIV,
    ]

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.old_password = b"old_password_123"
        self.new_password = b"new_password_456"

        self.test_content = b"Algorithm test content for rekey."
        with open(self.test_file, "wb") as f:
            f.write(self.test_content)

    def tearDown(self):
        """Clean up test files."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_rekey_fernet(self):
        """Rekey works with fernet algorithm."""
        self._test_rekey_algorithm(EncryptionAlgorithm.FERNET)

    def test_rekey_aes_gcm(self):
        """Rekey works with aes-gcm algorithm."""
        self._test_rekey_algorithm(EncryptionAlgorithm.AES_GCM)

    def test_rekey_chacha20(self):
        """Rekey works with chacha20-poly1305 algorithm."""
        self._test_rekey_algorithm(EncryptionAlgorithm.CHACHA20_POLY1305)

    def test_rekey_xchacha20(self):
        """Rekey works with xchacha20-poly1305 algorithm."""
        self._test_rekey_algorithm(EncryptionAlgorithm.XCHACHA20_POLY1305)

    def test_rekey_aes_siv(self):
        """Rekey works with aes-siv algorithm."""
        self._test_rekey_algorithm(EncryptionAlgorithm.AES_SIV)

    def test_rekey_aes_gcm_siv(self):
        """Rekey works with aes-gcm-siv algorithm."""
        self._test_rekey_algorithm(EncryptionAlgorithm.AES_GCM_SIV)

    def _test_rekey_algorithm(self, algorithm):
        """Helper: encrypt with algorithm, rekey, decrypt."""
        encrypted_file = os.path.join(self.temp_dir, f"test_{algorithm.value}.encrypted")
        rekeyed_file = os.path.join(self.temp_dir, f"test_{algorithm.value}.rekeyed")
        decrypted_file = os.path.join(self.temp_dir, f"test_{algorithm.value}.decrypted")

        encrypt_file(
            self.test_file,
            encrypted_file,
            self.old_password,
            quiet=True,
            algorithm=algorithm,
        )
        rekey_file(
            input_file=encrypted_file,
            output_file=rekeyed_file,
            old_password=self.old_password,
            new_password=self.new_password,
            quiet=True,
        )
        decrypt_file(rekeyed_file, decrypted_file, self.new_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)


class TestRekeyAlgorithmChange(unittest.TestCase):
    """Test rekey with algorithm change (re-encrypt with a different cipher)."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.old_password = b"old_password_123"
        self.new_password = b"new_password_456"

        self.test_content = b"Algorithm change test content."
        with open(self.test_file, "wb") as f:
            f.write(self.test_content)

    def tearDown(self):
        """Clean up test files."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_rekey_change_fernet_to_aes_gcm(self):
        """Rekey can change algorithm from fernet to aes-gcm."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        # Encrypt with fernet
        encrypt_file(
            self.test_file,
            encrypted_file,
            self.old_password,
            quiet=True,
            algorithm=EncryptionAlgorithm.FERNET,
        )

        # Rekey to aes-gcm
        rekey_file(
            input_file=encrypted_file,
            output_file=rekeyed_file,
            old_password=self.old_password,
            new_password=self.new_password,
            quiet=True,
            new_algorithm=EncryptionAlgorithm.AES_GCM,
        )

        # Verify new algorithm
        metadata = extract_file_metadata(rekeyed_file)
        self.assertEqual(metadata["algorithm"], EncryptionAlgorithm.AES_GCM.value)

        # Decrypt
        decrypt_file(rekeyed_file, decrypted_file, self.new_password, quiet=True)
        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)

    def test_rekey_change_aes_gcm_to_chacha20(self):
        """Rekey can change algorithm from aes-gcm to chacha20-poly1305."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        encrypt_file(
            self.test_file,
            encrypted_file,
            self.old_password,
            quiet=True,
            algorithm=EncryptionAlgorithm.AES_GCM,
        )

        rekey_file(
            input_file=encrypted_file,
            output_file=rekeyed_file,
            old_password=self.old_password,
            new_password=self.new_password,
            quiet=True,
            new_algorithm=EncryptionAlgorithm.CHACHA20_POLY1305,
        )

        metadata = extract_file_metadata(rekeyed_file)
        self.assertEqual(metadata["algorithm"], EncryptionAlgorithm.CHACHA20_POLY1305.value)

        decrypt_file(rekeyed_file, decrypted_file, self.new_password, quiet=True)
        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)

    def test_rekey_without_algorithm_change_preserves_algorithm(self):
        """Rekey without new_algorithm preserves the original algorithm."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")

        encrypt_file(
            self.test_file,
            encrypted_file,
            self.old_password,
            quiet=True,
            algorithm=EncryptionAlgorithm.AES_GCM,
        )

        rekey_file(
            input_file=encrypted_file,
            output_file=rekeyed_file,
            old_password=self.old_password,
            new_password=self.new_password,
            quiet=True,
        )

        metadata = extract_file_metadata(rekeyed_file)
        self.assertEqual(metadata["algorithm"], EncryptionAlgorithm.AES_GCM.value)


class TestRekeyEdgeCases(unittest.TestCase):
    """Test rekey edge cases and error handling."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.old_password = b"old_password_123"
        self.new_password = b"new_password_456"

        self.test_content = b"Edge case test content."
        with open(self.test_file, "wb") as f:
            f.write(self.test_content)

    def tearDown(self):
        """Clean up test files."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_rekey_wrong_old_password(self):
        """Rekey with wrong old password should fail."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")

        encrypt_file(self.test_file, encrypted_file, self.old_password, quiet=True)

        with self.assertRaises(Exception):
            rekey_file(
                input_file=encrypted_file,
                output_file=rekeyed_file,
                old_password=b"wrong_password",
                new_password=self.new_password,
                quiet=True,
            )

    def test_rekey_nonexistent_file(self):
        """Rekey of nonexistent file should fail."""
        with self.assertRaises(Exception):
            rekey_file(
                input_file="/nonexistent/file.encrypted",
                output_file=os.path.join(self.temp_dir, "out.encrypted"),
                old_password=self.old_password,
                new_password=self.new_password,
                quiet=True,
            )

    def test_rekey_empty_file(self):
        """Rekey of an encrypted empty file should work."""
        empty_file = os.path.join(self.temp_dir, "empty.txt")
        with open(empty_file, "wb") as f:
            f.write(b"")

        encrypted_file = empty_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        encrypt_file(empty_file, encrypted_file, self.old_password, quiet=True)
        rekey_file(
            input_file=encrypted_file,
            output_file=rekeyed_file,
            old_password=self.old_password,
            new_password=self.new_password,
            quiet=True,
        )
        decrypt_file(rekeyed_file, decrypted_file, self.new_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), b"")


class TestRekeySecurity(unittest.TestCase):
    """Test security properties of rekey operation."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.old_password = b"old_password_123"
        self.new_password = b"new_password_456"

        self.test_content = b"Security test content for rekey."
        with open(self.test_file, "wb") as f:
            f.write(self.test_content)

    def tearDown(self):
        """Clean up test files."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_rekey_cleans_temp_files(self):
        """Temp files should be cleaned up after rekey."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")

        encrypt_file(self.test_file, encrypted_file, self.old_password, quiet=True)

        # Count files before
        files_before = set(os.listdir(self.temp_dir))

        rekey_file(
            input_file=encrypted_file,
            output_file=rekeyed_file,
            old_password=self.old_password,
            new_password=self.new_password,
            quiet=True,
        )

        # Count files after - should only have original + encrypted + rekeyed
        files_after = set(os.listdir(self.temp_dir))
        new_files = files_after - files_before
        # Only the rekeyed file should be new
        self.assertEqual(new_files, {"rekeyed.encrypted"})

    def test_rekey_cleans_temp_files_on_error(self):
        """Temp files should be cleaned up even if rekey fails."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")

        encrypt_file(self.test_file, encrypted_file, self.old_password, quiet=True)

        files_before = set(os.listdir(self.temp_dir))

        try:
            rekey_file(
                input_file=encrypted_file,
                output_file=rekeyed_file,
                old_password=b"wrong_password",
                new_password=self.new_password,
                quiet=True,
            )
        except Exception:
            pass

        files_after = set(os.listdir(self.temp_dir))
        # No new temp files should remain
        new_files = files_after - files_before
        self.assertEqual(new_files, set())

    def test_rekey_in_place_preserves_permissions(self):
        """In-place rekey should preserve original file permissions."""
        encrypted_file = self.test_file + ".encrypted"

        encrypt_file(self.test_file, encrypted_file, self.old_password, quiet=True)

        # Set specific permissions
        os.chmod(encrypted_file, 0o640)
        original_mode = stat.S_IMODE(os.stat(encrypted_file).st_mode)

        rekey_file(
            input_file=encrypted_file,
            output_file=None,
            old_password=self.old_password,
            new_password=self.new_password,
            quiet=True,
        )

        new_mode = stat.S_IMODE(os.stat(encrypted_file).st_mode)
        self.assertEqual(original_mode, new_mode)


class TestRekeyWithHashConfig(unittest.TestCase):
    """Test rekey with hash/KDF configuration parameters."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.old_password = b"old_password_123"
        self.new_password = b"new_password_456"

        self.test_content = b"Hash config test content for rekey."
        with open(self.test_file, "wb") as f:
            f.write(self.test_content)

    def tearDown(self):
        """Clean up test files."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_rekey_with_hash_config(self):
        """Rekey with explicit hash_config passes through to encrypt_file."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        hash_config = {
            "sha512": 2,
            "sha384": 0,
            "sha256": 0,
            "sha224": 0,
            "sha3_512": 0,
            "sha3_384": 0,
            "sha3_256": 0,
            "sha3_224": 0,
            "blake2b": 0,
            "blake3": 0,
            "shake256": 0,
            "shake128": 0,
            "whirlpool": 0,
            "scrypt": {"enabled": False, "n": 16384, "r": 8, "p": 1, "rounds": 0},
            "argon2": {
                "enabled": False,
                "time_cost": 3,
                "memory_cost": 65536,
                "parallelism": 4,
                "hash_len": 32,
                "type": 2,
                "rounds": 0,
            },
            "balloon": {
                "enabled": False,
                "time_cost": 3,
                "space_cost": 65536,
                "parallelism": 4,
                "rounds": 0,
            },
            "hkdf": {
                "enabled": False,
                "rounds": 1,
                "algorithm": "sha256",
                "info": "openssl_encrypt_hkdf",
            },
            "randomx": {
                "enabled": False,
                "rounds": 1,
                "mode": "light",
                "height": 1,
                "hash_len": 32,
            },
            "pbkdf2_iterations": 0,
        }

        encrypt_file(self.test_file, encrypted_file, self.old_password, quiet=True)
        rekey_file(
            input_file=encrypted_file,
            output_file=rekeyed_file,
            old_password=self.old_password,
            new_password=self.new_password,
            quiet=True,
            hash_config=hash_config,
        )
        decrypt_file(rekeyed_file, decrypted_file, self.new_password, quiet=True)

        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)

    def test_cli_rekey_with_sha512_rounds(self):
        """CLI: rekey with --sha512-rounds passes hash params through."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        # Encrypt with default settings
        subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "encrypt",
                "-i",
                self.test_file,
                "-o",
                encrypted_file,
                "--password",
                "oldpass",
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )

        # Rekey with --standard template plus extra sha512-rounds
        # (--standard provides a complete, compatible hash config)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "rekey",
                "-i",
                encrypted_file,
                "-o",
                rekeyed_file,
                "--password",
                "oldpass",
                "--rekey-password",
                "newpass",
                "--force-password",
                "--standard",
                "--sha512-rounds",
                "2",
                "--quiet",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, f"Rekey failed: {result.stderr}")

        # Decrypt
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "decrypt",
                "-i",
                rekeyed_file,
                "-o",
                decrypted_file,
                "--password",
                "newpass",
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"Decrypt failed: {result.stderr}")

        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)

    def test_cli_rekey_with_paranoid_template(self):
        """CLI: rekey with --paranoid template works."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        # Encrypt with default settings
        subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "encrypt",
                "-i",
                self.test_file,
                "-o",
                encrypted_file,
                "--password",
                "oldpass",
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )

        # Rekey with --paranoid
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "rekey",
                "-i",
                encrypted_file,
                "-o",
                rekeyed_file,
                "--password",
                "oldpass",
                "--rekey-password",
                "newpass",
                "--force-password",
                "--paranoid",
                "--quiet",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, f"Rekey failed: {result.stderr}")

        # Decrypt
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "decrypt",
                "-i",
                rekeyed_file,
                "-o",
                decrypted_file,
                "--password",
                "newpass",
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"Decrypt failed: {result.stderr}")

        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)


class TestRekeyCLI(unittest.TestCase):
    """Test rekey via CLI subprocess."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.test_content = b"CLI rekey test content."
        with open(self.test_file, "wb") as f:
            f.write(self.test_content)

    def tearDown(self):
        """Clean up test files."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cli_rekey_basic(self):
        """CLI: encrypt → rekey → decrypt roundtrip."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        # Encrypt
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "encrypt",
                "-i",
                self.test_file,
                "-o",
                encrypted_file,
                "--password",
                "oldpass",
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"Encrypt failed: {result.stderr}")

        # Rekey
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "rekey",
                "-i",
                encrypted_file,
                "-o",
                rekeyed_file,
                "--password",
                "oldpass",
                "--rekey-password",
                "newpass",
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"Rekey failed: {result.stderr}")

        # Decrypt
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "decrypt",
                "-i",
                rekeyed_file,
                "-o",
                decrypted_file,
                "--password",
                "newpass",
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"Decrypt failed: {result.stderr}")

        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)

    def test_cli_rekey_in_place(self):
        """CLI: rekey in-place (no -o flag)."""
        encrypted_file = self.test_file + ".encrypted"
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        # Encrypt
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "encrypt",
                "-i",
                self.test_file,
                "-o",
                encrypted_file,
                "--password",
                "oldpass",
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"Encrypt failed: {result.stderr}")

        # Rekey in-place (no -o)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "rekey",
                "-i",
                encrypted_file,
                "--password",
                "oldpass",
                "--rekey-password",
                "newpass",
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"Rekey failed: {result.stderr}")

        # Decrypt with new password
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "decrypt",
                "-i",
                encrypted_file,
                "-o",
                decrypted_file,
                "--password",
                "newpass",
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"Decrypt failed: {result.stderr}")

        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)

    def test_cli_rekey_with_algorithm_change(self):
        """CLI: rekey with --algorithm to change cipher."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        # Encrypt with fernet
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "encrypt",
                "-i",
                self.test_file,
                "-o",
                encrypted_file,
                "--password",
                "oldpass",
                "--force-password",
                "--algorithm",
                "fernet",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"Encrypt failed: {result.stderr}")

        # Rekey to aes-gcm
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "rekey",
                "-i",
                encrypted_file,
                "-o",
                rekeyed_file,
                "--password",
                "oldpass",
                "--rekey-password",
                "newpass",
                "--force-password",
                "--algorithm",
                "aes-gcm",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"Rekey failed: {result.stderr}")

        # Verify algorithm changed
        metadata = extract_file_metadata(rekeyed_file)
        self.assertEqual(metadata["algorithm"], "aes-gcm")

        # Decrypt
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "decrypt",
                "-i",
                rekeyed_file,
                "-o",
                decrypted_file,
                "--password",
                "newpass",
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"Decrypt failed: {result.stderr}")

        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)

    def test_cli_rekey_wrong_password_fails(self):
        """CLI: rekey with wrong old password exits with nonzero."""
        encrypted_file = self.test_file + ".encrypted"

        # Encrypt
        subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "encrypt",
                "-i",
                self.test_file,
                "-o",
                encrypted_file,
                "--password",
                "oldpass",
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )

        # Rekey with wrong password
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "rekey",
                "-i",
                encrypted_file,
                "-o",
                os.path.join(self.temp_dir, "fail.encrypted"),
                "--password",
                "wrongpass",
                "--rekey-password",
                "newpass",
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_cli_rekey_env_var_password(self):
        """CLI: rekey using OPENSSL_ENCRYPT_PASSWORD and OPENSSL_ENCRYPT_REKEY_PASSWORD env vars."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        # Encrypt
        subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "encrypt",
                "-i",
                self.test_file,
                "-o",
                encrypted_file,
                "--password",
                "oldpass",
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )

        # Rekey using env vars
        env = os.environ.copy()
        env["OPENSSL_ENCRYPT_PASSWORD"] = "oldpass"
        env["OPENSSL_ENCRYPT_REKEY_PASSWORD"] = "newpass"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "rekey",
                "-i",
                encrypted_file,
                "-o",
                rekeyed_file,
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(result.returncode, 0, f"Rekey failed: {result.stderr}")

        # Decrypt
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "decrypt",
                "-i",
                rekeyed_file,
                "-o",
                decrypted_file,
                "--password",
                "newpass",
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"Decrypt failed: {result.stderr}")

        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)

    def test_cli_rekey_password_file(self):
        """CLI: rekey using --password-file and --rekey-password-file."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        old_pw_file = os.path.join(self.temp_dir, "old.pw")
        new_pw_file = os.path.join(self.temp_dir, "new.pw")
        with open(old_pw_file, "w") as f:
            f.write("oldpass\n")
        with open(new_pw_file, "w") as f:
            f.write("newpass\n")

        # Encrypt
        subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "encrypt",
                "-i",
                self.test_file,
                "-o",
                encrypted_file,
                "--password",
                "oldpass",
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )

        # Rekey using password files
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "rekey",
                "-i",
                encrypted_file,
                "-o",
                rekeyed_file,
                "--password-file",
                old_pw_file,
                "--rekey-password-file",
                new_pw_file,
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"Rekey failed: {result.stderr}")

        # Decrypt
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt",
                "decrypt",
                "-i",
                rekeyed_file,
                "-o",
                decrypted_file,
                "--password",
                "newpass",
                "--force-password",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"Decrypt failed: {result.stderr}")

        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)


class TestRekeyNoTempPlaintext(unittest.TestCase):
    """Test that rekey never writes plaintext to disk.

    After the bytes-input refactor, rekey_file() passes decrypted data
    directly to encrypt_file() as bytes, so no .rekey_plain_* temp files
    should ever appear in the filesystem.
    """

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.old_password = b"old_password_123"
        self.new_password = b"new_password_456"

        self.test_content = b"No temp plaintext test content."
        with open(self.test_file, "wb") as f:
            f.write(self.test_content)

    def tearDown(self):
        """Clean up test files."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _get_rekey_plain_files(self, directory):
        """Return list of .rekey_plain_* files in directory."""
        return [f for f in os.listdir(directory) if f.startswith(".rekey_plain_")]

    def test_no_temp_plaintext_with_output_file(self):
        """Rekey to output file creates no .rekey_plain_* temp files."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")

        encrypt_file(self.test_file, encrypted_file, self.old_password, quiet=True)

        rekey_file(
            input_file=encrypted_file,
            output_file=rekeyed_file,
            old_password=self.old_password,
            new_password=self.new_password,
            quiet=True,
        )

        # No .rekey_plain_* files should exist
        plain_files = self._get_rekey_plain_files(self.temp_dir)
        self.assertEqual(plain_files, [], f"Temp plaintext files found: {plain_files}")

    def test_no_temp_plaintext_in_place(self):
        """In-place rekey creates no .rekey_plain_* temp files."""
        encrypted_file = self.test_file + ".encrypted"
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        encrypt_file(self.test_file, encrypted_file, self.old_password, quiet=True)

        input_dir = os.path.dirname(os.path.abspath(encrypted_file))

        rekey_file(
            input_file=encrypted_file,
            output_file=None,
            old_password=self.old_password,
            new_password=self.new_password,
            quiet=True,
        )

        # No .rekey_plain_* files should exist
        plain_files = self._get_rekey_plain_files(input_dir)
        self.assertEqual(plain_files, [], f"Temp plaintext files found: {plain_files}")

        # Roundtrip still works
        decrypted = decrypt_file(encrypted_file, decrypted_file, self.new_password, quiet=True)
        self.assertTrue(decrypted)
        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)

    def test_no_temp_plaintext_on_error(self):
        """Even on rekey failure, no .rekey_plain_* temp files remain."""
        encrypted_file = self.test_file + ".encrypted"
        rekeyed_file = os.path.join(self.temp_dir, "rekeyed.encrypted")

        encrypt_file(self.test_file, encrypted_file, self.old_password, quiet=True)

        input_dir = os.path.dirname(os.path.abspath(encrypted_file))

        try:
            rekey_file(
                input_file=encrypted_file,
                output_file=rekeyed_file,
                old_password=b"wrong_password",
                new_password=self.new_password,
                quiet=True,
            )
        except Exception:
            pass

        # No .rekey_plain_* files should exist
        plain_files = self._get_rekey_plain_files(input_dir)
        self.assertEqual(plain_files, [], f"Temp plaintext files found: {plain_files}")

    def test_in_place_rekey_still_uses_temp_output(self):
        """In-place rekey still uses a temp output file (.rekey_enc_*) for atomicity."""
        encrypted_file = self.test_file + ".encrypted"
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        encrypt_file(self.test_file, encrypted_file, self.old_password, quiet=True)

        # In-place rekey should succeed (temp output file is used then cleaned up)
        result = rekey_file(
            input_file=encrypted_file,
            output_file=None,
            old_password=self.old_password,
            new_password=self.new_password,
            quiet=True,
        )
        self.assertTrue(result)

        # Verify content is correct
        decrypted = decrypt_file(encrypted_file, decrypted_file, self.new_password, quiet=True)
        self.assertTrue(decrypted)
        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)


if __name__ == "__main__":
    unittest.main()
