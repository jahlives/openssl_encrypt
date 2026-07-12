#!/usr/bin/env python3
"""Regression tests for gitlab#114 (fable-review LOW-2): future format_version.

``encrypt_file`` bounded explicit format_version requests from below
(the v8/v10 sequential-XOR refusal) but not from above: an explicit
``format_version=15`` passed every ``>= 14`` gate, was stamped into the
metadata, and the decrypt side then failed closed on the unknown version
— a permanently unreadable file (data loss) carrying an on-disk version
whose semantics were never specified. New writes must fail closed on
versions above ``LATEST_STABLE_FORMAT_VERSION``, before any output is
produced.
"""

import os
import shutil
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import (
    LATEST_STABLE_FORMAT_VERSION,
    decrypt_file,
    encrypt_file,
)
from openssl_encrypt.modules.crypt_errors import ValidationError

TEST_PASSWORD = b"format-version-bound-password"
BASIC_HASH_CONFIG = {"sha256": 10, "pbkdf2_iterations": 1000}


class TestFormatVersionWriteUpperBound(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.plain = os.path.join(self.tmp, "in.txt")
        self.enc = os.path.join(self.tmp, "in.txt.enc")
        with open(self.plain, "wb") as f:
            f.write(b"future version payload")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _encrypt(self, version):
        return encrypt_file(
            input_file=self.plain,
            output_file=self.enc,
            password=TEST_PASSWORD,
            hash_config=dict(BASIC_HASH_CONFIG),
            quiet=True,
            format_version=version,
        )

    def test_version_above_latest_stable_is_refused(self):
        """One above the current maximum must fail closed."""
        with self.assertRaises((ValueError, ValidationError)) as ctx:
            self._encrypt(LATEST_STABLE_FORMAT_VERSION + 1)
        self.assertIn(str(LATEST_STABLE_FORMAT_VERSION), str(ctx.exception))

    def test_far_future_version_is_refused(self):
        with self.assertRaises((ValueError, ValidationError)):
            self._encrypt(99)

    def test_refusal_leaves_no_output_file(self):
        """The refusal must fire before any output artifact is produced."""
        with self.assertRaises((ValueError, ValidationError)):
            self._encrypt(LATEST_STABLE_FORMAT_VERSION + 1)
        self.assertFalse(os.path.exists(self.enc))

    def test_latest_stable_version_still_writes_and_reads(self):
        """The bound must not affect the current maximum version."""
        self._encrypt(LATEST_STABLE_FORMAT_VERSION)
        out = os.path.join(self.tmp, "out.txt")
        decrypt_file(self.enc, out, password=TEST_PASSWORD, quiet=True)
        with open(out, "rb") as f:
            self.assertEqual(f.read(), b"future version payload")


if __name__ == "__main__":
    unittest.main()
