#!/usr/bin/env python3
"""
Tests for the derive-password CLI action.

This action derives a key from a password using configured hash/KDF algorithms
and prints only the derived key to stdout. All other output goes to stderr.
"""

import base64
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

# Ensure package is importable
sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from openssl_encrypt.modules.crypt_cli import main as cli_main


def run_derive_password(extra_args, password="testpassword123!", env=None):
    """Helper to run derive-password action and capture stdout/stderr.

    Returns (exit_code, stdout_text, stderr_text).
    """
    base_args = [
        "crypt.py",
        "--quiet",
        "derive-password",
        "--force-password",
    ]
    sys.argv = base_args + extra_args

    old_stdout = sys.stdout
    old_stderr = sys.stderr
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    exit_code = None
    old_env = os.environ.copy()

    try:
        if env:
            os.environ.update(env)

        # If --password not in extra_args and no env password, mock getpass
        has_password = any(
            a in extra_args
            for a in ["--password", "-p", "--password-file", "--password-fd"]
        )
        has_env_pw = env and "OPENSSL_ENCRYPT_PASSWORD" in env

        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        with mock.patch("sys.exit") as mock_exit:
            mock_exit.side_effect = SystemExit

            if not has_password and not has_env_pw:
                with mock.patch("getpass.getpass", return_value=password):
                    try:
                        cli_main()
                    except SystemExit as e:
                        exit_code = (
                            e.code
                            if e.code is not None
                            else mock_exit.call_args[0][0] if mock_exit.called else 0
                        )
            else:
                try:
                    cli_main()
                except SystemExit as e:
                    exit_code = (
                        e.code
                        if e.code is not None
                        else mock_exit.call_args[0][0] if mock_exit.called else 0
                    )

            if exit_code is None and mock_exit.called:
                exit_code = mock_exit.call_args[0][0] if mock_exit.call_args[0] else 0
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        # Restore environment
        os.environ.clear()
        os.environ.update(old_env)

    return exit_code, stdout_capture.getvalue(), stderr_capture.getvalue()


class TestDerivePasswordAction(unittest.TestCase):
    """Tests for the derive-password action feature."""

    FIXED_SALT = "aa" * 16  # 16-byte salt in hex

    def test_basic_hex_output(self):
        """derive-password with fixed salt produces valid hex on stdout."""
        exit_code, stdout, stderr = run_derive_password(
            [
                "--password",
                "testpassword123!",
                "--salt",
                self.FIXED_SALT,
            ]
        )
        self.assertEqual(
            exit_code, 0, f"Expected exit 0, got {exit_code}. stderr: {stderr}"
        )
        output = stdout.strip()
        # Must be valid hex
        self.assertRegex(output, r"^[0-9a-f]+$", f"Output is not valid hex: {output!r}")
        # Default 32 bytes = 64 hex chars
        self.assertEqual(len(output), 64, f"Expected 64 hex chars, got {len(output)}")

    def test_base64_output(self):
        """derive-password with --output-format base64 produces valid base64."""
        exit_code, stdout, stderr = run_derive_password(
            [
                "--password",
                "testpassword123!",
                "--salt",
                self.FIXED_SALT,
                "--output-format",
                "base64",
            ]
        )
        self.assertEqual(exit_code, 0, f"stderr: {stderr}")
        output = stdout.strip()
        # Must decode as valid base64
        try:
            decoded = base64.b64decode(output)
        except Exception as e:
            self.fail(f"Output is not valid base64: {output!r} ({e})")
        self.assertEqual(len(decoded), 32, f"Expected 32 bytes, got {len(decoded)}")

    def test_raw_output(self):
        """derive-password with --output-format raw produces raw bytes."""
        # For raw output we need to capture stdout.buffer instead
        base_args = [
            "crypt.py",
            "--quiet",
            "derive-password",
            "--force-password",
            "--password",
            "testpassword123!",
            "--salt",
            self.FIXED_SALT,
            "--output-format",
            "raw",
        ]
        sys.argv = base_args

        stdout_buffer = io.BytesIO()

        old_stdout = sys.stdout
        old_stderr = sys.stderr
        stderr_capture = io.StringIO()

        try:
            # Create a mock stdout that has a buffer attribute
            mock_stdout = mock.MagicMock()
            mock_stdout.buffer = stdout_buffer
            sys.stdout = mock_stdout
            sys.stderr = stderr_capture

            with mock.patch("sys.exit") as mock_exit:
                mock_exit.side_effect = SystemExit
                try:
                    cli_main()
                except SystemExit:
                    pass
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        raw_output = stdout_buffer.getvalue()
        self.assertEqual(
            len(raw_output), 32, f"Expected 32 raw bytes, got {len(raw_output)}"
        )

    def test_reproducible_with_same_salt(self):
        """Same password + same salt = same derived key."""
        args = [
            "--password",
            "testpassword123!",
            "--salt",
            self.FIXED_SALT,
        ]
        _, stdout1, _ = run_derive_password(args)
        _, stdout2, _ = run_derive_password(args)
        self.assertEqual(
            stdout1.strip(), stdout2.strip(), "Derivation is not reproducible"
        )

    def test_different_with_different_salt(self):
        """Same password + different salt = different derived key."""
        _, stdout1, _ = run_derive_password(
            [
                "--password",
                "testpassword123!",
                "--salt",
                "aa" * 16,
            ]
        )
        _, stdout2, _ = run_derive_password(
            [
                "--password",
                "testpassword123!",
                "--salt",
                "bb" * 16,
            ]
        )
        self.assertNotEqual(
            stdout1.strip(),
            stdout2.strip(),
            "Different salts should produce different keys",
        )

    def test_output_length(self):
        """--output-length 64 produces 128 hex chars."""
        exit_code, stdout, stderr = run_derive_password(
            [
                "--password",
                "testpassword123!",
                "--salt",
                self.FIXED_SALT,
                "--output-length",
                "64",
            ]
        )
        self.assertEqual(exit_code, 0, f"stderr: {stderr}")
        output = stdout.strip()
        self.assertEqual(
            len(output), 128, f"Expected 128 hex chars for 64 bytes, got {len(output)}"
        )

    def test_default_output_length(self):
        """Default output length is 32 bytes (64 hex chars)."""
        exit_code, stdout, _ = run_derive_password(
            [
                "--password",
                "testpassword123!",
                "--salt",
                self.FIXED_SALT,
            ]
        )
        self.assertEqual(exit_code, 0)
        self.assertEqual(len(stdout.strip()), 64)

    def test_show_salt_on_stderr(self):
        """--show-salt prints the salt to stderr, not stdout."""
        # Use a distinctive salt that won't appear as a substring in derived key hex
        distinctive_salt = "deadbeef" * 4  # 16-byte salt
        exit_code, stdout, stderr = run_derive_password(
            [
                "--password",
                "testpassword123!",
                "--salt",
                distinctive_salt,
                "--show-salt",
            ]
        )
        self.assertEqual(exit_code, 0)
        # Salt label should appear in stderr
        self.assertIn("Salt (hex):", stderr, "Salt label not found in stderr")
        self.assertIn(distinctive_salt, stderr, "Salt value not found in stderr")
        # stdout should contain ONLY the derived hex key (one line)
        lines = stdout.strip().split("\n")
        self.assertEqual(len(lines), 1, f"Expected 1 line on stdout, got {len(lines)}")
        self.assertRegex(lines[0], r"^[0-9a-f]+$")

    def test_nothing_else_on_stdout(self):
        """stdout contains ONLY the derived password line, nothing else."""
        exit_code, stdout, _ = run_derive_password(
            [
                "--password",
                "testpassword123!",
                "--salt",
                self.FIXED_SALT,
            ]
        )
        self.assertEqual(exit_code, 0)
        lines = stdout.strip().split("\n")
        self.assertEqual(
            len(lines),
            1,
            f"Expected exactly 1 line on stdout, got {len(lines)}: {lines!r}",
        )
        # The single line must be valid hex
        self.assertRegex(lines[0], r"^[0-9a-f]+$")


class TestDerivePasswordForbiddenArgs(unittest.TestCase):
    """Tests that encryption-specific arguments are rejected."""

    def test_reject_input_flag(self):
        """derive-password must reject -i/--input."""
        exit_code, stdout, stderr = run_derive_password(
            [
                "--password",
                "testpassword123!",
                "--salt",
                "aa" * 16,
                "--input",
                "foo.txt",
            ]
        )
        self.assertNotEqual(exit_code, 0, "Should have rejected --input")

    def test_reject_output_flag(self):
        """derive-password must reject -o/--output."""
        exit_code, stdout, stderr = run_derive_password(
            [
                "--password",
                "testpassword123!",
                "--salt",
                "aa" * 16,
                "--output",
                "bar.txt",
            ]
        )
        self.assertNotEqual(exit_code, 0, "Should have rejected --output")

    def test_reject_algorithm_flag(self):
        """derive-password must reject -a/--algorithm."""
        exit_code, stdout, stderr = run_derive_password(
            [
                "--password",
                "testpassword123!",
                "--salt",
                "aa" * 16,
                "--algorithm",
                "aes-256-gcm",
            ]
        )
        self.assertNotEqual(exit_code, 0, "Should have rejected --algorithm")

    def test_reject_cascade_flag(self):
        """derive-password must reject --cascade."""
        exit_code, stdout, stderr = run_derive_password(
            [
                "--password",
                "testpassword123!",
                "--salt",
                "aa" * 16,
                "--cascade",
            ]
        )
        self.assertNotEqual(exit_code, 0, "Should have rejected --cascade")


class TestDerivePasswordKDFIntegration(unittest.TestCase):
    """Tests that KDF options work correctly with derive-password."""

    FIXED_SALT = "aa" * 16

    def test_derive_with_sha512_rounds(self):
        """Using --sha512-rounds changes the output vs no rounds."""
        _, stdout_no_rounds, _ = run_derive_password(
            [
                "--password",
                "testpassword123!",
                "--salt",
                self.FIXED_SALT,
            ]
        )
        _, stdout_with_rounds, _ = run_derive_password(
            [
                "--password",
                "testpassword123!",
                "--salt",
                self.FIXED_SALT,
                "--sha512-rounds",
                "10",
            ]
        )
        self.assertNotEqual(
            stdout_no_rounds.strip(),
            stdout_with_rounds.strip(),
            "SHA-512 rounds should change the derived key",
        )

    def test_derive_with_argon2(self):
        """Using --enable-argon2 with derive-password works."""
        try:
            import argon2  # noqa: F401
        except ImportError:
            self.skipTest("argon2-cffi not installed")

        exit_code, stdout, stderr = run_derive_password(
            [
                "--password",
                "testpassword123!",
                "--salt",
                self.FIXED_SALT,
                "--enable-argon2",
                "--argon2-rounds",
                "1",
                "--argon2-time",
                "1",
                "--argon2-memory",
                "1024",
            ]
        )
        self.assertEqual(exit_code, 0, f"stderr: {stderr}")
        output = stdout.strip()
        self.assertRegex(output, r"^[0-9a-f]+$")
        self.assertEqual(len(output), 64)

    def test_derive_with_multiple_kdfs(self):
        """Combining SHA-512 + Argon2 differs from SHA-512 alone."""
        try:
            import argon2  # noqa: F401
        except ImportError:
            self.skipTest("argon2-cffi not installed")

        _, stdout_sha_only, _ = run_derive_password(
            [
                "--password",
                "testpassword123!",
                "--salt",
                self.FIXED_SALT,
                "--sha512-rounds",
                "10",
            ]
        )
        _, stdout_combined, _ = run_derive_password(
            [
                "--password",
                "testpassword123!",
                "--salt",
                self.FIXED_SALT,
                "--sha512-rounds",
                "10",
                "--enable-argon2",
                "--argon2-rounds",
                "1",
                "--argon2-time",
                "1",
                "--argon2-memory",
                "1024",
            ]
        )
        self.assertNotEqual(
            stdout_sha_only.strip(),
            stdout_combined.strip(),
            "Combining KDFs should produce a different key",
        )

    def test_derive_password_from_password_file(self):
        """--password-file reads the password from a file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("testpassword123!\n")
            pw_file = f.name

        try:
            exit_code, stdout, stderr = run_derive_password(
                [
                    "--password-file",
                    pw_file,
                    "--salt",
                    self.FIXED_SALT,
                ]
            )
            self.assertEqual(exit_code, 0, f"stderr: {stderr}")
            output = stdout.strip()
            self.assertRegex(output, r"^[0-9a-f]+$")

            # Should match --password result
            _, stdout_direct, _ = run_derive_password(
                [
                    "--password",
                    "testpassword123!",
                    "--salt",
                    self.FIXED_SALT,
                ]
            )
            self.assertEqual(
                output,
                stdout_direct.strip(),
                "Password file and direct password should produce the same key",
            )
        finally:
            os.unlink(pw_file)

    def test_derive_password_from_env_var(self):
        """OPENSSL_ENCRYPT_PASSWORD env var is consumed."""
        exit_code, stdout, stderr = run_derive_password(
            [
                "--salt",
                self.FIXED_SALT,
            ],
            env={"OPENSSL_ENCRYPT_PASSWORD": "testpassword123!"},
        )
        self.assertEqual(exit_code, 0, f"stderr: {stderr}")
        output = stdout.strip()
        self.assertRegex(output, r"^[0-9a-f]+$")


if __name__ == "__main__":
    unittest.main()
