#!/usr/bin/env python3
"""
End-to-end CLI tests for `sign` / `verify-signature` (feature #1).

Drives the real CLI (crypt_cli.main) against a temp identity store:
- sign (armored default) -> .sig produced -> verify-signature exits 0
- sign --no-armor -> raw JSON .sig -> verify exits 0
- tampered file -> verify exits 1
- unknown signer (verifier store lacks the signer) -> verify exits 1
- --signer pin: matching ok; mismatched pin fails
"""

import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

try:
    from openssl_encrypt.modules.identity import Identity, IdentityStore
    from openssl_encrypt.modules.pqc_signing import LIBOQS_AVAILABLE
except Exception:  # pragma: no cover
    LIBOQS_AVAILABLE = False

from openssl_encrypt.modules.armor import is_armored_file
from openssl_encrypt.modules.crypt_cli import main as cli_main


@unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
class TestSignVerifyCLI(unittest.TestCase):
    PW = "signerpass"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store_path = os.path.join(self.tmp, "store")
        store = IdentityStore(base_path=self.store_path)
        store.add_identity(Identity.generate("Signer", "s@x", self.PW), passphrase=self.PW)
        self.infile = os.path.join(self.tmp, "doc.txt")
        with open(self.infile, "wb") as f:
            f.write(b"important document contents \x00\x01\xff")
        self.original_argv = sys.argv

    def tearDown(self):
        sys.argv = self.original_argv
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, argv, getpass_value=None):
        """Run the CLI; return the exit code (catches SystemExit)."""
        sys.argv = ["crypt.py"] + argv
        so = sys.stdout
        sys.stdout = open(os.devnull, "w")
        try:
            ctx = (
                mock.patch("getpass.getpass", return_value=getpass_value)
                if getpass_value is not None
                else mock.patch("getpass.getpass", return_value="")
            )
            with ctx:
                try:
                    cli_main()
                    return 0
                except SystemExit as e:
                    return e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        finally:
            sys.stdout.close()
            sys.stdout = so

    def _sign(self, sig_path=None, extra=None):
        argv = [
            "--quiet",
            "sign",
            "--input",
            self.infile,
            "--sign-with",
            "Signer",
            "--identity-store",
            self.store_path,
        ]
        if sig_path:
            argv += ["--output", sig_path]
        if extra:
            argv += extra
        return self._run(argv, getpass_value=self.PW)

    def _verify(self, sig_path=None, store=None, extra=None):
        argv = [
            "--quiet",
            "verify-signature",
            "--input",
            self.infile,
            "--identity-store",
            store or self.store_path,
        ]
        if sig_path:
            argv += ["--signature", sig_path]
        if extra:
            argv += extra
        return self._run(argv)

    def test_sign_armored_then_verify(self):
        sig = os.path.join(self.tmp, "doc.sig")
        self.assertEqual(self._sign(sig), 0)
        self.assertTrue(os.path.exists(sig))
        self.assertTrue(is_armored_file(sig))
        self.assertEqual(self._verify(sig), 0)

    def test_sign_default_sig_path(self):
        self.assertEqual(self._sign(), 0)
        self.assertTrue(os.path.exists(self.infile + ".sig"))
        self.assertEqual(self._verify(), 0)

    def test_sign_no_armor_then_verify(self):
        sig = os.path.join(self.tmp, "raw.sig")
        self.assertEqual(self._sign(sig, extra=["--no-armor"]), 0)
        self.assertFalse(is_armored_file(sig))
        self.assertEqual(self._verify(sig), 0)

    def test_tampered_file_fails_verify(self):
        sig = os.path.join(self.tmp, "doc.sig")
        self.assertEqual(self._sign(sig), 0)
        with open(self.infile, "ab") as f:
            f.write(b"tampered!")
        self.assertEqual(self._verify(sig), 1)

    def test_unknown_signer_fails_verify(self):
        sig = os.path.join(self.tmp, "doc.sig")
        self.assertEqual(self._sign(sig), 0)
        # A fresh empty store does not know the signer.
        empty = os.path.join(self.tmp, "empty_store")
        IdentityStore(base_path=empty)
        self.assertEqual(self._verify(sig, store=empty), 1)

    def test_signer_pin_match_and_mismatch(self):
        sig = os.path.join(self.tmp, "doc.sig")
        self.assertEqual(self._sign(sig), 0)
        # Correct pin verifies.
        self.assertEqual(self._verify(sig, extra=["--signer", "Signer"]), 0)
        # Pin to a different identity -> mismatch -> failure.
        store = IdentityStore(base_path=self.store_path)
        store.add_identity(Identity.generate("Other", "o@x", "pw2"), passphrase="pw2")
        self.assertEqual(self._verify(sig, extra=["--signer", "Other"]), 1)


if __name__ == "__main__":
    unittest.main()
