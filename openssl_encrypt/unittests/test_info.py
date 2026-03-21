#!/usr/bin/env python3
"""
Unit tests for the --info CLI action.

Tests that:
- info action displays metadata from encrypted files
- stdin pipe input works
- --json flag outputs valid JSON
- Invalid/corrupted file handling
- No password is needed (no decryption)
- encrypted_at is displayed when present
"""

import base64
import json
import os
import shutil
import sys
import tempfile
import unittest
from io import StringIO
from unittest import mock

from openssl_encrypt.modules.crypt_core import (
    EncryptionAlgorithm,
    encrypt_file,
    extract_file_metadata,
    print_file_info,
)


class TestPrintFileInfo(unittest.TestCase):
    """Test the print_file_info() function in crypt_core."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.password = b"test_password_123"
        self.test_content = b"Hello World! Testing info action."
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        with open(self.test_file, "wb") as f:
            f.write(self.test_content)
        self.encrypted_file = os.path.join(self.temp_dir, "encrypted.bin")
        encrypt_file(
            input_file=self.test_file,
            output_file=self.encrypted_file,
            password=self.password,
            quiet=True,
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_print_file_info_returns_metadata(self):
        """print_file_info() returns metadata dict."""
        result = print_file_info(self.encrypted_file, json_output=False)
        self.assertIsInstance(result, dict)
        self.assertIn("format_version", result)

    def test_print_file_info_shows_format_version(self):
        """Pretty-print output includes format version."""
        captured = StringIO()
        with mock.patch("sys.stderr", captured):
            print_file_info(self.encrypted_file, json_output=False)
        output = captured.getvalue()
        self.assertIn("Format Version", output)

    def test_print_file_info_shows_algorithm(self):
        """Pretty-print output includes algorithm name."""
        captured = StringIO()
        with mock.patch("sys.stderr", captured):
            print_file_info(self.encrypted_file, json_output=False)
        output = captured.getvalue()
        self.assertIn("Algorithm", output)

    def test_print_file_info_shows_encrypted_at(self):
        """Pretty-print output includes encrypted_at timestamp."""
        captured = StringIO()
        with mock.patch("sys.stderr", captured):
            print_file_info(self.encrypted_file, json_output=False)
        output = captured.getvalue()
        self.assertIn("Encrypted At", output)

    def test_print_file_info_json_mode(self):
        """JSON output mode produces valid JSON with metadata."""
        captured = StringIO()
        with mock.patch("sys.stdout", captured):
            print_file_info(self.encrypted_file, json_output=True)
        output = captured.getvalue()
        parsed = json.loads(output)
        self.assertIn("format_version", parsed)
        self.assertIn("encrypted_at", parsed)

    def test_print_file_info_invalid_file(self):
        """print_file_info() raises ValueError for non-encrypted files."""
        plain_file = os.path.join(self.temp_dir, "plain.txt")
        with open(plain_file, "w", encoding="utf-8") as f:
            f.write("Not an encrypted file")
        with self.assertRaises(ValueError):
            print_file_info(plain_file)

    def test_print_file_info_nonexistent_file(self):
        """print_file_info() raises ValueError for missing files."""
        with self.assertRaises(ValueError):
            print_file_info("/nonexistent/file.bin")

    def test_print_file_info_shows_salt(self):
        """Pretty-print output includes salt."""
        captured = StringIO()
        with mock.patch("sys.stderr", captured):
            print_file_info(self.encrypted_file, json_output=False)
        output = captured.getvalue()
        self.assertIn("Salt", output)

    def test_print_file_info_shows_hash_config(self):
        """Pretty-print output includes hash configuration."""
        captured = StringIO()
        with mock.patch("sys.stderr", captured):
            print_file_info(self.encrypted_file, json_output=False)
        output = captured.getvalue()
        # Should show at least one hash algorithm
        self.assertTrue(
            any(h in output for h in ["SHA-512", "SHA-256", "SHA3", "BLAKE"]),
            f"Expected hash algorithm in output: {output}",
        )


class TestPrintFileInfoAlgorithms(unittest.TestCase):
    """Test info display for different algorithms."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.password = b"test_password_123"
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        with open(self.test_file, "wb") as f:
            f.write(b"Algorithm test content.")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _encrypt_with_algorithm(self, algorithm: EncryptionAlgorithm) -> str:
        encrypted = os.path.join(self.temp_dir, f"enc_{algorithm.value}.bin")
        encrypt_file(
            input_file=self.test_file,
            output_file=encrypted,
            password=self.password,
            quiet=True,
            algorithm=algorithm,
        )
        return encrypted

    def test_info_aes_gcm(self):
        """info works for AES-GCM encrypted files."""
        enc = self._encrypt_with_algorithm(EncryptionAlgorithm.AES_GCM)
        result = print_file_info(enc, json_output=False)
        self.assertEqual(result["encryption"]["algorithm"], "aes-gcm")

    def test_info_chacha20(self):
        """info works for ChaCha20-Poly1305 encrypted files."""
        enc = self._encrypt_with_algorithm(EncryptionAlgorithm.CHACHA20_POLY1305)
        result = print_file_info(enc, json_output=False)
        self.assertEqual(result["encryption"]["algorithm"], "chacha20-poly1305")

    def test_info_fernet(self):
        """info works for Fernet encrypted files."""
        enc = self._encrypt_with_algorithm(EncryptionAlgorithm.FERNET)
        result = print_file_info(enc, json_output=False)
        self.assertEqual(result["encryption"]["algorithm"], "fernet")


class TestInfoCLI(unittest.TestCase):
    """Test info action through CLI interface."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.password = b"test_password_123"
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        with open(self.test_file, "wb") as f:
            f.write(b"CLI info test content.")
        self.encrypted_file = os.path.join(self.temp_dir, "encrypted.bin")
        encrypt_file(
            input_file=self.test_file,
            output_file=self.encrypted_file,
            password=self.password,
            quiet=True,
        )
        self.original_argv = sys.argv

    def tearDown(self):
        sys.argv = self.original_argv
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_info_action_no_password_needed(self):
        """info action should not require a password."""
        from openssl_encrypt.modules.crypt_cli import main as cli_main

        sys.argv = [
            "crypt.py",
            "info",
            "--input",
            self.encrypted_file,
        ]

        captured = StringIO()
        with mock.patch("sys.stderr", captured):
            with mock.patch("sys.exit") as mock_exit:
                cli_main()
                # First call should be exit(0) from info handler
                mock_exit.assert_any_call(0)

        output = captured.getvalue()
        self.assertIn("Format Version", output)

    def test_info_action_json_flag(self):
        """info action with --json outputs valid JSON."""
        from openssl_encrypt.modules.crypt_cli import main as cli_main

        sys.argv = [
            "crypt.py",
            "info",
            "--input",
            self.encrypted_file,
            "--json",
        ]

        captured = StringIO()
        with mock.patch("sys.stdout", captured):
            with mock.patch("sys.exit") as mock_exit:
                cli_main()
                mock_exit.assert_any_call(0)

        output = captured.getvalue()
        parsed = json.loads(output)
        self.assertIn("format_version", parsed)

    def test_info_action_stdin(self):
        """info action reads from stdin when input is /dev/stdin."""
        from openssl_encrypt.modules.crypt_cli import main as cli_main

        with open(self.encrypted_file, "rb") as f:
            encrypted_data = f.read()

        sys.argv = [
            "crypt.py",
            "info",
            "--input",
            "/dev/stdin",
        ]

        captured = StringIO()
        mock_stdin = mock.MagicMock()
        mock_stdin.buffer.read.return_value = encrypted_data

        with mock.patch("sys.stderr", captured):
            with mock.patch("sys.stdin", mock_stdin):
                with mock.patch("sys.exit") as mock_exit:
                    cli_main()
                    mock_exit.assert_any_call(0)

        output = captured.getvalue()
        self.assertIn("Format Version", output)


if __name__ == "__main__":
    unittest.main()
