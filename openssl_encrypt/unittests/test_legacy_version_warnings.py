#!/usr/bin/env python3
"""
Post-v14 review INFO-1/INFO-2: visible, warn-only notices for explicit legacy
format_version requests on NEW encryptions and for the streaming version
upgrade. The warnings must NEVER turn into errors: explicit legacy versions
remain honored (API backward compatibility), streaming keeps upgrading
(never downgrading) to a streaming-capable version.
"""

import io
import logging
import os
import tempfile
import unittest
from contextlib import redirect_stderr

from openssl_encrypt.modules.crypt_core import (
    LATEST_STABLE_FORMAT_VERSION,
    decrypt_file,
    encrypt_file,
)

FAST_CONFIG = {"sha256": 1, "pbkdf2_iterations": 1000}
PASSWORD = b"legacy-warning-test-password"


class TestLegacyVersionWarnings(unittest.TestCase):
    def setUp(self):
        fd, self.src = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(b"legacy version warning payload")
        self.enc = self.src + ".enc"
        self.dec = self.src + ".dec"

    def tearDown(self):
        for p in (self.src, self.enc, self.dec):
            if os.path.exists(p):
                os.unlink(p)

    def _encrypt(self, quiet, **kw):
        return encrypt_file(
            self.src,
            self.enc,
            PASSWORD,
            FAST_CONFIG.copy(),
            quiet=quiet,
            algorithm="aes-gcm",
            **kw,
        )

    def test_explicit_legacy_version_warns_but_succeeds(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self._encrypt(quiet=False, format_version=13)
        self.assertIn("WARNING", stderr.getvalue())
        self.assertIn("legacy format_version 13", stderr.getvalue())
        # Honored unchanged: the file exists, decrypts, and is v13.
        decrypt_file(self.enc, self.dec, PASSWORD, quiet=True)
        with open(self.src, "rb") as a, open(self.dec, "rb") as b:
            self.assertEqual(a.read(), b.read())

    def test_explicit_legacy_version_quiet_no_stderr(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            with self.assertLogs(level=logging.WARNING):
                self._encrypt(quiet=True, format_version=13)
        self.assertEqual(stderr.getvalue(), "")

    def test_default_version_does_not_warn(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self._encrypt(quiet=False)
        self.assertNotIn("legacy format_version", stderr.getvalue())

    def test_explicit_latest_version_does_not_warn(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self._encrypt(quiet=False, format_version=LATEST_STABLE_FORMAT_VERSION)
        self.assertNotIn("legacy format_version", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
