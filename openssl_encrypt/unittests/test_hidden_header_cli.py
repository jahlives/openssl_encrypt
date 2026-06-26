#!/usr/bin/env python3
"""
End-to-end CLI tests for the hidden-header flags.

Drives the real ``python -m openssl_encrypt`` entry point so the argparse
wiring, second-password resolution, and threading into encrypt/decrypt are all
exercised together. All code in English as per project requirements.
"""

import os
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PASSWORD = "primary-cli-pw"
SECOND_PW = "second-cli-pw"
PLAINTEXT = b"hidden-header CLI round-trip payload\n" * 8


def _is_hidden(path):
    from openssl_encrypt.modules.hidden_header import is_hidden_format

    with open(path, "rb") as f:
        return is_hidden_format(f.read())


class TestHiddenHeaderCLI(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.src = os.path.join(self.dir, "plain.bin")
        with open(self.src, "wb") as f:
            f.write(PLAINTEXT)
        self.enc = os.path.join(self.dir, "out.enc")
        self.dec = os.path.join(self.dir, "out.dec")

    def tearDown(self):
        import shutil

        shutil.rmtree(self.dir, ignore_errors=True)

    def _run(self, *args):
        proc = subprocess.run(
            [sys.executable, "-m", "openssl_encrypt", *args],
            cwd=REPO_ROOT,
            capture_output=True,
            timeout=120,
        )
        return proc

    def _encrypt(self, *extra):
        p = self._run(
            "encrypt",
            "-i",
            self.src,
            "-o",
            self.enc,
            "--password",
            PASSWORD,
            "--algorithm",
            "aes-gcm",
            "--quick",
            "--quiet",
            *extra,
        )
        self.assertEqual(p.returncode, 0, msg=p.stderr.decode(errors="replace"))

    def _decrypt(self, *extra):
        p = self._run(
            "decrypt",
            "-i",
            self.enc,
            "-o",
            self.dec,
            "--password",
            PASSWORD,
            "--quiet",
            *extra,
        )
        return p

    def _info(self, *extra):
        return self._run("info", "-i", self.enc, *extra)

    def test_info_keyless(self):
        self._encrypt("--hidden-header")
        p = self._info()
        self.assertEqual(p.returncode, 0, msg=p.stderr.decode(errors="replace"))
        self.assertIn(b"Format Version", p.stdout + p.stderr)

    def test_info_keyed_with_second_password(self):
        self._encrypt("--hidden-header", "--second-password", SECOND_PW)
        p = self._info("--second-password", SECOND_PW)
        self.assertEqual(p.returncode, 0, msg=p.stderr.decode(errors="replace"))
        self.assertIn(b"Format Version", p.stdout + p.stderr)

    def test_info_keyed_no_password_fails(self):
        # Non-interactive: keyed file without the second password fails generic
        # (no hang, no metadata leak).
        self._encrypt("--hidden-header", "--second-password", SECOND_PW)
        p = self._info()
        self.assertNotEqual(p.returncode, 0)

    def test_keyless_round_trip(self):
        self._encrypt("--hidden-header")
        self.assertTrue(_is_hidden(self.enc))
        p = self._decrypt()
        self.assertEqual(p.returncode, 0, msg=p.stderr.decode(errors="replace"))
        with open(self.dec, "rb") as f:
            self.assertEqual(f.read(), PLAINTEXT)

    def test_keyed_round_trip(self):
        self._encrypt("--hidden-header", "--second-password", SECOND_PW)
        self.assertTrue(_is_hidden(self.enc))
        p = self._decrypt("--second-password", SECOND_PW)
        self.assertEqual(p.returncode, 0, msg=p.stderr.decode(errors="replace"))
        with open(self.dec, "rb") as f:
            self.assertEqual(f.read(), PLAINTEXT)

    def test_keyed_wrong_second_password_fails(self):
        self._encrypt("--hidden-header", "--second-password", SECOND_PW)
        p = self._decrypt("--second-password", "wrong-pw")
        self.assertNotEqual(p.returncode, 0)

    def test_keyed_no_password_noninteractive_fails_fast(self):
        # The interactive fallback is TTY-gated: under a non-interactive
        # subprocess (stdin is a pipe) a keyed file must fail fast with the
        # generic error rather than hanging on a prompt.
        self._encrypt("--hidden-header", "--second-password", SECOND_PW)
        p = self._decrypt()  # no second password, non-TTY
        self.assertNotEqual(p.returncode, 0)

    def test_legacy_default_round_trip(self):
        self._encrypt()  # no hidden flag -> legacy format (current default)
        self.assertFalse(_is_hidden(self.enc))
        p = self._decrypt()
        self.assertEqual(p.returncode, 0, msg=p.stderr.decode(errors="replace"))
        with open(self.dec, "rb") as f:
            self.assertEqual(f.read(), PLAINTEXT)


if __name__ == "__main__":
    unittest.main()
