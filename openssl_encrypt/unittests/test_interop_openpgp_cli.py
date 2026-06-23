#!/usr/bin/env python3
"""
End-to-end CLI tests for `decrypt --from pgp` (feature #5, phase 2).

Drives the real CLI against committed GnuPG `gpg -c` fixtures.
"""

import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from openssl_encrypt.modules.crypt_cli import main as cli_main

_PW = "correct horse battery"
_DIR = os.path.join(os.path.dirname(__file__), "testfiles", "openpgp")
_SMALL = b"hello openpgp symmetric world"


class TestDecryptFromPgpCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.original_argv = sys.argv

    def tearDown(self):
        sys.argv = self.original_argv
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, argv):
        sys.argv = ["crypt.py"] + argv
        so = sys.stdout
        sys.stdout = open(os.devnull, "w")
        try:
            with mock.patch("getpass.getpass", return_value=""):
                try:
                    cli_main()
                    return 0
                except SystemExit as e:
                    return e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        finally:
            sys.stdout.close()
            sys.stdout = so

    def _decrypt(self, fixture, password):
        out = os.path.join(self.tmp, "out.txt")
        rc = self._run(
            [
                "--quiet",
                "decrypt",
                "--from",
                "pgp",
                "--input",
                os.path.join(_DIR, fixture),
                "--password",
                password,
                "--output",
                out,
            ]
        )
        return rc, out

    def test_decrypt_aes256(self):
        rc, out = self._decrypt("v_aes256.gpg", _PW)
        self.assertEqual(rc, 0)
        with open(out, "rb") as f:
            self.assertEqual(f.read(), _SMALL)

    def test_decrypt_armored(self):
        rc, out = self._decrypt("v_armored.asc", _PW)
        self.assertEqual(rc, 0)
        with open(out, "rb") as f:
            self.assertEqual(f.read(), _SMALL)

    def test_wrong_passphrase_fails(self):
        rc, out = self._decrypt("v_aes256.gpg", "wrong passphrase")
        self.assertEqual(rc, 1)
        self.assertFalse(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
