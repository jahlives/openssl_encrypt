#!/usr/bin/env python3
"""
Unit tests for bytes input/output support in encrypt_file().

Tests that encrypt_file() can accept bytes/bytearray as input_file
and None as output_file (returning encrypted bytes), mirroring the
pattern already used by decrypt_file().

Test classes:
- TestEncryptBytesInput: bytes/bytearray as input_file with file output
- TestEncryptBytesOutput: output_file=None returns encrypted bytes
- TestEncryptBytesBoth: bytes in, bytes out (full in-memory roundtrip)
- TestEncryptBytesValidation: rejects invalid types, auto-pepper guard
"""

import os
import shutil
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import (EncryptionAlgorithm,
                                                decrypt_file, encrypt_file)
from openssl_encrypt.modules.crypt_errors import (KeyDerivationError,
                                                  ValidationError)


class TestEncryptBytesInput(unittest.TestCase):
    """Test encrypt_file() with bytes/bytearray as input_file."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.password = b"test_password_123"
        self.test_content = b"Hello World! Testing bytes input."

    def tearDown(self):
        """Clean up test files."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_bytes_input_file_output(self):
        """encrypt_file() accepts bytes as input_file and writes to output file."""
        output_file = os.path.join(self.temp_dir, "encrypted.bin")

        result = encrypt_file(
            input_file=self.test_content,
            output_file=output_file,
            password=self.password,
            quiet=True,
        )
        self.assertTrue(result)
        self.assertTrue(os.path.exists(output_file))

        # Verify decryption roundtrip
        decrypted = decrypt_file(
            input_file=output_file,
            output_file=None,
            password=self.password,
            quiet=True,
        )
        self.assertEqual(decrypted, self.test_content)

    def test_bytearray_input_file_output(self):
        """encrypt_file() accepts bytearray as input_file."""
        output_file = os.path.join(self.temp_dir, "encrypted.bin")
        input_data = bytearray(self.test_content)

        result = encrypt_file(
            input_file=input_data,
            output_file=output_file,
            password=self.password,
            quiet=True,
        )
        self.assertTrue(result)

        # Verify decryption roundtrip
        decrypted = decrypt_file(
            input_file=output_file,
            output_file=None,
            password=self.password,
            quiet=True,
        )
        self.assertEqual(decrypted, self.test_content)

    def test_empty_bytes_input(self):
        """encrypt_file() handles empty bytes input."""
        output_file = os.path.join(self.temp_dir, "encrypted.bin")

        result = encrypt_file(
            input_file=b"",
            output_file=output_file,
            password=self.password,
            quiet=True,
        )
        self.assertTrue(result)

        decrypted = decrypt_file(
            input_file=output_file,
            output_file=None,
            password=self.password,
            quiet=True,
        )
        self.assertEqual(decrypted, b"")

    def test_large_bytes_input(self):
        """encrypt_file() handles large (100KB) bytes input."""
        output_file = os.path.join(self.temp_dir, "encrypted.bin")
        large_data = os.urandom(100 * 1024)  # 100KB

        result = encrypt_file(
            input_file=large_data,
            output_file=output_file,
            password=self.password,
            quiet=True,
        )
        self.assertTrue(result)

        decrypted = decrypt_file(
            input_file=output_file,
            output_file=None,
            password=self.password,
            quiet=True,
        )
        self.assertEqual(decrypted, large_data)

    def test_bytes_input_roundtrip_with_file_decrypt(self):
        """Encrypt from bytes, decrypt to file — full roundtrip."""
        encrypted_file = os.path.join(self.temp_dir, "encrypted.bin")
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")

        encrypt_file(
            input_file=self.test_content,
            output_file=encrypted_file,
            password=self.password,
            quiet=True,
        )

        decrypt_file(
            input_file=encrypted_file,
            output_file=decrypted_file,
            password=self.password,
            quiet=True,
        )

        with open(decrypted_file, "rb") as f:
            self.assertEqual(f.read(), self.test_content)


class TestEncryptBytesOutput(unittest.TestCase):
    """Test encrypt_file() with output_file=None returning bytes."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.password = b"test_password_123"
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.test_content = b"Hello World! Testing bytes output."
        with open(self.test_file, "wb") as f:
            f.write(self.test_content)

    def tearDown(self):
        """Clean up test files."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_output_none_returns_bytes(self):
        """encrypt_file(output_file=None) returns encrypted bytes."""
        result = encrypt_file(
            input_file=self.test_file,
            output_file=None,
            password=self.password,
            quiet=True,
        )
        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), 0)
        # Should contain metadata:encrypted_data separator
        self.assertIn(b":", result)

    def test_output_none_roundtrip(self):
        """Encrypt to bytes, write to file, decrypt — roundtrip works."""
        encrypted_bytes = encrypt_file(
            input_file=self.test_file,
            output_file=None,
            password=self.password,
            quiet=True,
        )
        self.assertIsInstance(encrypted_bytes, bytes)

        # Write encrypted bytes to a file, then decrypt
        encrypted_file = os.path.join(self.temp_dir, "encrypted.bin")
        with open(encrypted_file, "wb") as f:
            f.write(encrypted_bytes)

        decrypted = decrypt_file(
            input_file=encrypted_file,
            output_file=None,
            password=self.password,
            quiet=True,
        )
        self.assertEqual(decrypted, self.test_content)

    def test_output_none_no_file_created(self):
        """encrypt_file(output_file=None) does not create any output file."""
        files_before = set(os.listdir(self.temp_dir))

        encrypt_file(
            input_file=self.test_file,
            output_file=None,
            password=self.password,
            quiet=True,
        )

        files_after = set(os.listdir(self.temp_dir))
        self.assertEqual(files_before, files_after)


class TestEncryptBytesBoth(unittest.TestCase):
    """Test encrypt_file() with bytes input AND output_file=None (full in-memory)."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.password = b"test_password_123"
        self.test_content = b"Full in-memory roundtrip test."

    def tearDown(self):
        """Clean up test files."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_bytes_in_bytes_out(self):
        """encrypt_file(bytes, None) returns encrypted bytes."""
        result = encrypt_file(
            input_file=self.test_content,
            output_file=None,
            password=self.password,
            quiet=True,
        )
        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), 0)

    def test_full_in_memory_roundtrip(self):
        """Encrypt bytes → get encrypted bytes → write to file → decrypt to bytes."""
        encrypted_bytes = encrypt_file(
            input_file=self.test_content,
            output_file=None,
            password=self.password,
            quiet=True,
        )

        # Write encrypted bytes to temp file for decryption
        encrypted_file = os.path.join(self.temp_dir, "encrypted.bin")
        with open(encrypted_file, "wb") as f:
            f.write(encrypted_bytes)

        decrypted = decrypt_file(
            input_file=encrypted_file,
            output_file=None,
            password=self.password,
            quiet=True,
        )
        self.assertEqual(decrypted, self.test_content)

    def test_multiple_algorithms_bytes_roundtrip(self):
        """In-memory roundtrip works for multiple encryption algorithms."""
        algorithms = [
            EncryptionAlgorithm.FERNET,
            EncryptionAlgorithm.AES_GCM,
            EncryptionAlgorithm.CHACHA20_POLY1305,
        ]

        for algo in algorithms:
            with self.subTest(algorithm=algo.value):
                encrypted_bytes = encrypt_file(
                    input_file=self.test_content,
                    output_file=None,
                    password=self.password,
                    quiet=True,
                    algorithm=algo,
                )
                self.assertIsInstance(encrypted_bytes, bytes)

                # Write to file and decrypt
                encrypted_file = os.path.join(self.temp_dir, f"enc_{algo.value}.bin")
                with open(encrypted_file, "wb") as f:
                    f.write(encrypted_bytes)

                decrypted = decrypt_file(
                    input_file=encrypted_file,
                    output_file=None,
                    password=self.password,
                    quiet=True,
                )
                self.assertEqual(decrypted, self.test_content)


class TestEncryptBytesValidation(unittest.TestCase):
    """Test input validation for bytes mode in encrypt_file()."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.password = b"test_password_123"

    def tearDown(self):
        """Clean up test files."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_rejects_int_input(self):
        """encrypt_file() rejects int as input_file."""
        output_file = os.path.join(self.temp_dir, "out.bin")
        with self.assertRaises((ValidationError, TypeError)):
            encrypt_file(
                input_file=42,
                output_file=output_file,
                password=self.password,
                quiet=True,
            )

    def test_rejects_list_input(self):
        """encrypt_file() rejects list as input_file."""
        output_file = os.path.join(self.temp_dir, "out.bin")
        with self.assertRaises((ValidationError, TypeError)):
            encrypt_file(
                input_file=[1, 2, 3],
                output_file=output_file,
                password=self.password,
                quiet=True,
            )

    def test_rejects_non_str_non_none_output(self):
        """encrypt_file() rejects non-str, non-None output_file."""
        with self.assertRaises((ValidationError, TypeError)):
            encrypt_file(
                input_file=b"test data",
                output_file=42,
                password=self.password,
                quiet=True,
            )

    def test_auto_pepper_raises_with_bytes_input(self):
        """encrypt_file() raises ValidationError when auto-pepper needs file path but gets bytes."""
        # Auto-pepper (pepper_plugin without pepper_name) requires os.path.abspath(input_file)
        # which fails with bytes input. The function should raise a clear error.
        # We use a mock pepper plugin to trigger the auto-pepper path.
        try:
            from unittest.mock import MagicMock

            mock_pepper = MagicMock()
            with self.assertRaises((ValidationError, KeyDerivationError)) as ctx:
                encrypt_file(
                    input_file=b"test data",
                    output_file=None,
                    password=self.password,
                    quiet=True,
                    pepper_plugin=mock_pepper,
                    pepper_name=None,  # No name → auto-generate → needs file path
                )
            self.assertIn("pepper", str(ctx.exception).lower())
        except ImportError:
            self.skipTest("unittest.mock not available")


if __name__ == "__main__":
    unittest.main()
