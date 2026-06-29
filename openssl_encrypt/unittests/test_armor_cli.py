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


class TestArmorDearmorSubcommands(ArmorCLITestBase):
    """Standalone ``armor`` / ``dearmor`` subcommands operating on an existing
    encrypted file (no decryption, no password — a pure transport transform)."""

    PW = "TestPassword123!"

    def _cli(self, args, stdin_bytes=None):
        """Run ``python -m openssl_encrypt <args>`` in a real subprocess."""
        import subprocess

        proc = subprocess.Popen(
            [sys.executable, "-m", "openssl_encrypt", "--quiet"] + args,
            stdin=subprocess.PIPE if stdin_bytes is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.getcwd(),
        )
        out, err = proc.communicate(input=stdin_bytes, timeout=120)
        return proc.returncode, out, err

    def _make_encrypted(self, path):
        """Produce a binary (non-armored) encrypted file at ``path``."""
        try:
            rc, _out, err = self._cli(
                [
                    "encrypt",
                    "--input",
                    self.test_file,
                    "--output",
                    path,
                    "--force-password",
                    "--algorithm",
                    "fernet",
                    "--argon2-rounds",
                    "3",
                    "--password",
                    self.PW,
                ]
            )
        except FileNotFoundError:
            self.skipTest("module not accessible for subprocess test")
        self.assertEqual(rc, 0, err.decode("utf-8", "replace"))
        self.assertTrue(os.path.exists(path))
        self.assertFalse(is_armored_file(path), "fixture should be binary, not armored")
        return path

    def test_armor_then_dearmor_roundtrip_byte_identical(self):
        """armor an existing file, dearmor it back -> byte-identical ciphertext."""
        enc = self._make_encrypted(os.path.join(self.test_dir, "msg.enc"))
        with open(enc, "rb") as f:
            original = f.read()

        asc = os.path.join(self.test_dir, "msg.asc")
        rc, _o, err = self._cli(["armor", "-i", enc, "-o", asc])
        self.assertEqual(rc, 0, err.decode("utf-8", "replace"))
        self.assertTrue(is_armored_file(asc), "armor subcommand did not produce armor")
        with open(asc, "rb") as f:
            f.read().decode("ascii")  # paste-safe

        back = os.path.join(self.test_dir, "msg.back")
        rc, _o, err = self._cli(["dearmor", "-i", asc, "-o", back])
        self.assertEqual(rc, 0, err.decode("utf-8", "replace"))
        with open(back, "rb") as f:
            self.assertEqual(f.read(), original, "dearmor must restore exact bytes")

    def test_armored_file_still_decrypts(self):
        """A file armored after encryption decrypts normally (auto-detected)."""
        enc = self._make_encrypted(os.path.join(self.test_dir, "msg.enc"))
        asc = os.path.join(self.test_dir, "msg.asc")
        self.assertEqual(self._cli(["armor", "-i", enc, "-o", asc])[0], 0)

        dec = os.path.join(self.test_dir, "msg.dec")
        rc, _o, err = self._cli(
            ["decrypt", "-i", asc, "-o", dec, "--password", self.PW, "--force-password"]
        )
        self.assertEqual(rc, 0, err.decode("utf-8", "replace"))
        with open(dec, "rb") as f:
            self.assertEqual(f.read(), self.plaintext)

    def test_armor_default_output_path(self):
        """`armor -i FILE` with no -o writes FILE.asc."""
        enc = self._make_encrypted(os.path.join(self.test_dir, "msg.enc"))
        rc, _o, err = self._cli(["armor", "-i", enc])
        self.assertEqual(rc, 0, err.decode("utf-8", "replace"))
        self.assertTrue(is_armored_file(enc + ".asc"))

    def test_armor_to_stdout(self):
        """`armor -i FILE -o /dev/stdout` emits the armored block on stdout."""
        enc = self._make_encrypted(os.path.join(self.test_dir, "msg.enc"))
        rc, out, err = self._cli(["armor", "-i", enc, "-o", "/dev/stdout"])
        self.assertEqual(rc, 0, err.decode("utf-8", "replace"))
        self.assertTrue(out.startswith(b"-----BEGIN OPENSSL-ENCRYPT MESSAGE-----"))

    def test_dearmor_to_stdout_roundtrip(self):
        """`dearmor -i FILE.asc -o /dev/stdout` emits the raw ciphertext bytes."""
        enc = self._make_encrypted(os.path.join(self.test_dir, "msg.enc"))
        with open(enc, "rb") as f:
            original = f.read()
        asc = os.path.join(self.test_dir, "msg.asc")
        self.assertEqual(self._cli(["armor", "-i", enc, "-o", asc])[0], 0)

        rc, out, err = self._cli(["dearmor", "-i", asc, "-o", "/dev/stdout"])
        self.assertEqual(rc, 0, err.decode("utf-8", "replace"))
        self.assertEqual(out, original)

    def test_dearmor_rejects_non_armored_input(self):
        """dearmor on a binary (non-armored) file fails cleanly, no output file."""
        enc = self._make_encrypted(os.path.join(self.test_dir, "msg.enc"))
        out = os.path.join(self.test_dir, "msg.out")
        rc, _o, err = self._cli(["dearmor", "-i", enc, "-o", out])
        self.assertEqual(rc, 1)
        self.assertIn(b"not", err.lower())
        self.assertFalse(os.path.exists(out))

    def test_armor_rejects_already_armored_input(self):
        """armoring an already-armored file fails (no silent double-wrap)."""
        enc = self._make_encrypted(os.path.join(self.test_dir, "msg.enc"))
        asc = os.path.join(self.test_dir, "msg.asc")
        self.assertEqual(self._cli(["armor", "-i", enc, "-o", asc])[0], 0)
        rc, _o, err = self._cli(["armor", "-i", asc, "-o", asc + ".2"])
        self.assertEqual(rc, 1)
        self.assertIn(b"already", err.lower())

    def test_armor_refuses_to_overwrite_without_force(self):
        """Existing output is protected unless --force is given."""
        enc = self._make_encrypted(os.path.join(self.test_dir, "msg.enc"))
        asc = os.path.join(self.test_dir, "msg.asc")
        with open(asc, "wb") as f:
            f.write(b"do not clobber me")
        rc, _o, err = self._cli(["armor", "-i", enc, "-o", asc])
        self.assertEqual(rc, 1)
        with open(asc, "rb") as f:
            self.assertEqual(f.read(), b"do not clobber me")
        # With --force it proceeds.
        rc, _o, err = self._cli(["armor", "-i", enc, "-o", asc, "--force"])
        self.assertEqual(rc, 0, err.decode("utf-8", "replace"))
        self.assertTrue(is_armored_file(asc))


if __name__ == "__main__":
    unittest.main()
