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
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

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
            a in extra_args for a in ["--password", "-p", "--password-file", "--password-fd"]
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
        self.assertEqual(exit_code, 0, f"Expected exit 0, got {exit_code}. stderr: {stderr}")
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
        self.assertEqual(len(raw_output), 32, f"Expected 32 raw bytes, got {len(raw_output)}")

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
        self.assertEqual(stdout1.strip(), stdout2.strip(), "Derivation is not reproducible")

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


class TestDerivePasswordConfirm(unittest.TestCase):
    """The new --confirm flag: prompt twice and verify the two entries match."""

    FIXED_SALT = "aa" * 16

    def _run_with_two_prompts(self, first: str, second: str, extra_args=None):
        """Run derive-password --confirm with two mocked getpass returns."""
        extra_args = extra_args or []
        base_args = [
            "crypt.py",
            "--quiet",
            "derive-password",
            "--force-password",
            "--confirm",
            "--salt",
            self.FIXED_SALT,
        ] + extra_args
        sys.argv = base_args

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        old_stdout, old_stderr = sys.stdout, sys.stderr
        exit_code = None
        try:
            sys.stdout = stdout_capture
            sys.stderr = stderr_capture
            with mock.patch("getpass.getpass", side_effect=[first, second]):
                with mock.patch("sys.exit") as mock_exit:
                    mock_exit.side_effect = SystemExit
                    try:
                        cli_main()
                    except SystemExit as e:
                        exit_code = (
                            e.code
                            if e.code is not None
                            else (mock_exit.call_args[0][0] if mock_exit.called else 0)
                        )
        finally:
            sys.stdout, sys.stderr = old_stdout, old_stderr
        return exit_code, stdout_capture.getvalue(), stderr_capture.getvalue()

    def test_confirm_matching_passwords_succeeds(self):
        exit_code, stdout, stderr = self._run_with_two_prompts("samepass!", "samepass!")
        self.assertEqual(exit_code, 0, f"stderr: {stderr}")
        self.assertRegex(stdout.strip(), r"^[0-9a-f]+$")

    def test_confirm_mismatched_passwords_errors(self):
        exit_code, _stdout, stderr = self._run_with_two_prompts("first-typo", "second-typo")
        self.assertNotEqual(exit_code, 0)
        self.assertIn("match", stderr.lower())

    def test_confirm_with_password_flag_no_double_prompt(self):
        """--password set on CLI: --confirm is harmless no-op (no prompt)."""
        sys.argv = [
            "crypt.py",
            "--quiet",
            "derive-password",
            "--force-password",
            "--confirm",
            "--password",
            "supplied-on-cli",
            "--salt",
            self.FIXED_SALT,
        ]
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        old_stdout, old_stderr = sys.stdout, sys.stderr
        exit_code = None
        try:
            sys.stdout = stdout_capture
            sys.stderr = stderr_capture
            # If --confirm were to prompt despite --password being set,
            # getpass would be called and our (intentional) empty
            # side_effect list would raise StopIteration.
            with mock.patch("getpass.getpass", side_effect=[]):
                with mock.patch("sys.exit") as mock_exit:
                    mock_exit.side_effect = SystemExit
                    try:
                        cli_main()
                    except SystemExit as e:
                        exit_code = (
                            e.code
                            if e.code is not None
                            else (mock_exit.call_args[0][0] if mock_exit.called else 0)
                        )
        finally:
            sys.stdout, sys.stderr = old_stdout, old_stderr
        self.assertEqual(exit_code, 0, f"stderr: {stderr_capture.getvalue()}")
        self.assertRegex(stdout_capture.getvalue().strip(), r"^[0-9a-f]+$")


class TestDerivePasswordHsm(unittest.TestCase):
    """The --hsm flag plumbs a hardware-derived pepper into the KDF cascade."""

    FIXED_SALT = "aa" * 16

    def _run(self, extra_args, password="testpassword123!", patches=()):
        """Run derive-password with optional unittest.mock.patch contexts.

        Always enables Argon2 with minimal cost so generate_key actually
        runs the KDF — without any KDF/hash flags, derive-password
        short-circuits to ``password || salt`` and the HSM pepper would
        be truncated off the end, defeating the test's purpose.
        """
        import contextlib

        base = [
            "crypt.py",
            "--quiet",
            "derive-password",
            "--force-password",
            "--password",
            password,
            "--salt",
            self.FIXED_SALT,
            "--enable-argon2",
            "--argon2-rounds",
            "1",
            "--argon2-time",
            "1",
            "--argon2-memory",
            "8",
            "--argon2-parallelism",
            "1",
        ]
        sys.argv = base + extra_args
        stdout_capture, stderr_capture = io.StringIO(), io.StringIO()
        old_stdout, old_stderr = sys.stdout, sys.stderr
        exit_code = None
        try:
            sys.stdout = stdout_capture
            sys.stderr = stderr_capture
            with contextlib.ExitStack() as stack:
                for p in patches:
                    stack.enter_context(p)
                with mock.patch("sys.exit") as mock_exit:
                    mock_exit.side_effect = SystemExit
                    try:
                        cli_main()
                    except SystemExit as e:
                        exit_code = (
                            e.code
                            if e.code is not None
                            else (mock_exit.call_args[0][0] if mock_exit.called else 0)
                        )
        finally:
            sys.stdout, sys.stderr = old_stdout, old_stderr
        return exit_code, stdout_capture.getvalue(), stderr_capture.getvalue()

    def _mock_yubikey_plugin(self, pepper: bytes):
        """Patch YubikeyHSMPlugin so its get_hsm_pepper returns a fixed pepper."""
        from openssl_encrypt.modules.plugin_system.plugin_base import PluginResult

        fake_plugin = mock.MagicMock()
        fake_plugin.plugin_id = "yubikey_hsm"
        fake_plugin.name = "Yubikey Challenge-Response HSM"
        fake_plugin.get_required_capabilities.return_value = set()
        fake_plugin.initialize.return_value = PluginResult.success_result("initialized")
        fake_plugin.get_hsm_pepper.return_value = PluginResult.success_result(
            "ok",
            data={"hsm_pepper": pepper, "slot": 1},
        )
        return mock.patch(
            "openssl_encrypt.plugins.hsm.yubikey_challenge_response.YubikeyHSMPlugin",
            return_value=fake_plugin,
        )

    def test_hsm_yubikey_alters_output(self):
        """With same password+salt, --hsm yubikey produces a different output."""
        # Run 1: no HSM
        rc1, out1, _err1 = self._run([])
        self.assertEqual(rc1, 0)

        # Run 2: HSM yubikey with a fixed pepper
        rc2, out2, _err2 = self._run(
            ["--hsm", "yubikey"],
            patches=[self._mock_yubikey_plugin(b"\xab" * 20)],
        )
        self.assertEqual(rc2, 0)
        self.assertNotEqual(out1.strip(), out2.strip())

    def test_hsm_yubikey_deterministic_for_same_pepper(self):
        """Same pepper → same output (the property the use case needs)."""
        pepper = b"\xcd" * 20
        rc1, out1, _ = self._run(
            ["--hsm", "yubikey"],
            patches=[self._mock_yubikey_plugin(pepper)],
        )
        rc2, out2, _ = self._run(
            ["--hsm", "yubikey"],
            patches=[self._mock_yubikey_plugin(pepper)],
        )
        self.assertEqual(rc1, 0)
        self.assertEqual(rc2, 0)
        self.assertEqual(out1.strip(), out2.strip())

    def test_hsm_yubikey_different_peppers_differ(self):
        """Different peppers → different outputs."""
        rc1, out1, _ = self._run(
            ["--hsm", "yubikey"],
            patches=[self._mock_yubikey_plugin(b"\x11" * 20)],
        )
        rc2, out2, _ = self._run(
            ["--hsm", "yubikey"],
            patches=[self._mock_yubikey_plugin(b"\x22" * 20)],
        )
        self.assertEqual(rc1, 0)
        self.assertEqual(rc2, 0)
        self.assertNotEqual(out1.strip(), out2.strip())

    def test_unknown_hsm_value_errors(self):
        rc, _out, err = self._run(["--hsm", "no-such-plugin"])
        self.assertNotEqual(rc, 0)
        self.assertIn("hsm", err.lower())


class TestDerivePasswordHsmRandomSaltReminder(unittest.TestCase):
    """
    When --hsm is set without --salt (random salt mode), emit a stderr
    reminder so the user knows reproducing the output requires the same
    password, the same salt, AND the same hardware-loaded secret.
    """

    def _mock_yubikey_plugin(self, pepper: bytes = b"\xaa" * 20):
        from openssl_encrypt.modules.plugin_system.plugin_base import PluginResult

        fake = mock.MagicMock()
        fake.plugin_id = "yubikey_hsm"
        fake.name = "Yubikey Challenge-Response HSM"
        fake.get_required_capabilities.return_value = set()
        fake.initialize.return_value = PluginResult.success_result("initialized")
        fake.get_hsm_pepper.return_value = PluginResult.success_result(
            "ok",
            data={"hsm_pepper": pepper, "slot": 1},
        )
        return mock.patch(
            "openssl_encrypt.plugins.hsm.yubikey_challenge_response.YubikeyHSMPlugin",
            return_value=fake,
        )

    def _run(self, extra_args):
        import contextlib

        base = [
            "crypt.py",
            "--quiet",
            "derive-password",
            "--force-password",
            "--password",
            "testpassword123!",
        ] + extra_args
        sys.argv = base
        stdout_capture, stderr_capture = io.StringIO(), io.StringIO()
        old_stdout, old_stderr = sys.stdout, sys.stderr
        exit_code = None
        try:
            sys.stdout, sys.stderr = stdout_capture, stderr_capture
            with contextlib.ExitStack() as stack:
                stack.enter_context(self._mock_yubikey_plugin())
                with mock.patch("sys.exit") as mock_exit:
                    mock_exit.side_effect = SystemExit
                    try:
                        cli_main()
                    except SystemExit as e:
                        exit_code = (
                            e.code
                            if e.code is not None
                            else (mock_exit.call_args[0][0] if mock_exit.called else 0)
                        )
        finally:
            sys.stdout, sys.stderr = old_stdout, old_stderr
        return exit_code, stdout_capture.getvalue(), stderr_capture.getvalue()

    def test_hsm_with_random_salt_emits_reminder(self):
        """--hsm + no --salt → reminder about three reproducibility inputs."""
        rc, _out, err = self._run(["--hsm", "yubikey"])
        self.assertEqual(rc, 0)
        err_lower = err.lower()
        self.assertIn("hardware token", err_lower)
        # The reminder must mention all three reproducibility inputs:
        self.assertIn("password", err_lower)
        self.assertIn("salt", err_lower)
        self.assertIn("secret", err_lower)

    def test_hsm_with_explicit_salt_does_not_emit_reminder(self):
        """--hsm + explicit --salt → user already controls salt; no nag."""
        rc, _out, err = self._run(["--hsm", "yubikey", "--salt", "bb" * 16])
        self.assertEqual(rc, 0)
        # The reminder phrase must not appear.
        self.assertNotIn("hardware token", err.lower())


if __name__ == "__main__":
    unittest.main()
