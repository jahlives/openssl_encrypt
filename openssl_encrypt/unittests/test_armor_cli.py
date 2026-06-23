#!/usr/bin/env python3
"""
Integration tests for the ``--armor`` CLI flag (feature #2).

Drives the real CLI (``crypt_cli.main``) end-to-end:
- ``encrypt --armor`` produces an ASCII-armored file.
- ``decrypt`` auto-detects the armor and recovers the plaintext byte-exactly.
- Without ``--armor`` the output stays binary (control).
- A corrupted armored file is rejected on decrypt.
"""

import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from openssl_encrypt.modules.armor import is_armored_file
from openssl_encrypt.modules.crypt_cli import main as cli_main


class ArmorCLITestBase(unittest.TestCase):
    """Shared setup: temp dir, a plaintext file, sys.argv save/restore."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.plaintext = b"Paste-safe armor round-trip test content \x00\x01\x02\xfe\xff."
        self.test_file = os.path.join(self.test_dir, "msg.txt")
        with open(self.test_file, "wb") as f:
            f.write(self.plaintext)
        self.original_argv = sys.argv

    def tearDown(self):
        sys.argv = self.original_argv
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _run(self, argv, expect_exit=0):
        """Run the CLI with argv, asserting it exits with expect_exit."""
        sys.argv = ["crypt.py"] + argv
        original_stdout = sys.stdout
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
        try:
            with mock.patch("sys.exit") as mock_exit:
                cli_main()
                if expect_exit is not None:
                    # The CLI may call sys.exit multiple times in mocked mode;
                    # assert the intended code was requested.
                    codes = [c.args[0] if c.args else 0 for c in mock_exit.call_args_list]
                    self.assertIn(expect_exit, codes)
        finally:
            sys.stdout.close()
            sys.stdout = original_stdout

    def _encrypt(self, out, extra=None):
        argv = [
            "--quiet",
            "encrypt",
            "--input",
            self.test_file,
            "--output",
            out,
            "--force-password",
            "--algorithm",
            "fernet",
            "--argon2-rounds",
            "3",
        ]
        if extra:
            argv += extra
        self._run(argv)

    def _decrypt(self, src, out, expect_exit=0):
        self._run(
            [
                "--quiet",
                "decrypt",
                "--input",
                src,
                "--output",
                out,
                "--force-password",
            ],
            expect_exit=expect_exit,
        )


class TestArmorCLIRoundTrip(ArmorCLITestBase):
    """encrypt --armor / decrypt auto-detect round-trip."""

    PW = "TestPassword123!"

    @mock.patch("getpass.getpass")
    def test_encrypt_armor_then_decrypt_autodetect(self, mock_getpass):
        mock_getpass.return_value = self.PW
        enc = os.path.join(self.test_dir, "out.asc")
        dec = os.path.join(self.test_dir, "out.dec")

        self._encrypt(enc, extra=["--armor"])
        self.assertTrue(os.path.exists(enc))
        # Output must be ASCII-armored...
        self.assertTrue(is_armored_file(enc), "encrypt --armor did not produce armored output")
        # ...and printable ASCII text (paste-safe).
        with open(enc, "rb") as f:
            data = f.read()
        data.decode("ascii")  # must not raise

        # Decrypt without any flag: armor must be auto-detected.
        self._decrypt(enc, dec)
        self.assertTrue(os.path.exists(dec))
        with open(dec, "rb") as f:
            self.assertEqual(f.read(), self.plaintext)

    @mock.patch("getpass.getpass")
    def test_encrypt_without_armor_is_binary(self, mock_getpass):
        """Control: no --armor => not armored, still decryptable."""
        mock_getpass.return_value = self.PW
        enc = os.path.join(self.test_dir, "out.bin")
        dec = os.path.join(self.test_dir, "out.dec")

        self._encrypt(enc)
        self.assertTrue(os.path.exists(enc))
        self.assertFalse(is_armored_file(enc))

        self._decrypt(enc, dec)
        with open(dec, "rb") as f:
            self.assertEqual(f.read(), self.plaintext)

    @mock.patch("getpass.getpass")
    def test_corrupted_armor_rejected(self, mock_getpass):
        """A truncated armored body must fail to decrypt, not silently pass."""
        mock_getpass.return_value = self.PW
        enc = os.path.join(self.test_dir, "out.asc")
        dec = os.path.join(self.test_dir, "out.dec")

        self._encrypt(enc, extra=["--armor"])
        # Drop a line out of the middle of the armored body.
        with open(enc, "rb") as f:
            lines = f.read().split(b"\n")
        del lines[2]
        with open(enc, "wb") as f:
            f.write(b"\n".join(lines))

        # Decrypt should fail (non-zero exit), and not write good plaintext.
        self._decrypt(enc, dec, expect_exit=1)
        if os.path.exists(dec):
            with open(dec, "rb") as f:
                self.assertNotEqual(f.read(), self.plaintext)


class TestArmorStdoutStream(ArmorCLITestBase):
    """encrypt stdin -> armored stdout, then decrypt the armored stream back."""

    PW = "TestPassword123!"

    def _cli(self, args, stdin_bytes):
        import subprocess

        proc = subprocess.Popen(
            [sys.executable, "-m", "openssl_encrypt.crypt", "--quiet"] + args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.getcwd(),
        )
        out, err = proc.communicate(input=stdin_bytes, timeout=60)
        return proc.returncode, out, err

    def test_stdin_to_armored_stdout_roundtrip(self):
        # The no-output decrypt path prints text to stdout, so use ascii content.
        message = b"stream armor round-trip: hello world"
        try:
            rc, armored, err = self._cli(
                [
                    "encrypt",
                    "--input",
                    "/dev/stdin",
                    "--armor",
                    "--force-password",
                    "--algorithm",
                    "fernet",
                    "--argon2-rounds",
                    "3",
                    "--password",
                    self.PW,
                ],
                message,
            )
        except FileNotFoundError:
            self.skipTest("module not accessible for subprocess test")

        # The encrypt-to-stdout path must emit armor...
        self.assertEqual(rc, 0, err.decode("utf-8", "replace"))
        self.assertIn(b"-----BEGIN OPENSSL-ENCRYPT MESSAGE-----", armored)
        armored.decode("ascii")  # paste-safe

        # ...and feeding that armored stream back into decrypt via stdin must
        # auto-detect and recover the plaintext.
        rc, out, err = self._cli(
            [
                "decrypt",
                "--input",
                "/dev/stdin",
                "--password",
                self.PW,
                "--force-password",
            ],
            armored,
        )
        self.assertEqual(rc, 0, err.decode("utf-8", "replace"))
        self.assertIn(message, out)


if __name__ == "__main__":
    unittest.main()
