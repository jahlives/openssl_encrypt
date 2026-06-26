#!/usr/bin/env python3
"""
Integration tests for the hidden-header format in encrypt_file/decrypt_file
(buffered, non-streaming path).

Covers:
  * keyless hidden round-trip (the on-disk file is indistinguishable from
    random and carries no legacy base64:colon structure);
  * keyed hidden round-trip with a second password, and failure without it;
  * legacy files still decrypt unchanged (auto-detection);
  * explicit format overrides.

All code in English as per project requirements.
"""

import os
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import decrypt_file, encrypt_file
from openssl_encrypt.modules.crypt_errors import AuthenticationError
from openssl_encrypt.modules.hidden_header import is_hidden_format, looks_like_legacy

# Minimal KDF config for fast inner-key derivation (mirrors other tests).
MINIMAL_CONFIG = {
    "sha512": 10,
    "argon2": {
        "enabled": True,
        "time_cost": 1,
        "memory_cost": 512,
        "parallelism": 1,
        "type": "id",
    },
}

PLAINTEXT = b"hidden-header integration plaintext \x00\x01\x02" * 40
PASSWORD = "primary-password"
SECOND_PW = "second-password"


class _Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.src = os.path.join(self.dir, "plain.txt")
        with open(self.src, "wb") as f:
            f.write(PLAINTEXT)
        self.enc = os.path.join(self.dir, "out.enc")
        self.dec = os.path.join(self.dir, "out.dec")

    def tearDown(self):
        import shutil

        shutil.rmtree(self.dir, ignore_errors=True)

    def _encrypt(self, **kw):
        encrypt_file(
            self.src,
            self.enc,
            PASSWORD,
            hash_config=MINIMAL_CONFIG,
            quiet=True,
            encryption_data="aes-gcm",
            **kw,
        )

    def _read_enc(self):
        with open(self.enc, "rb") as f:
            return f.read()

    def _decrypted(self):
        with open(self.dec, "rb") as f:
            return f.read()


class TestKeylessHidden(_Base):
    def test_round_trip(self):
        self._encrypt(hidden_header=True)
        decrypt_file(self.enc, self.dec, PASSWORD, quiet=True)
        self.assertEqual(self._decrypted(), PLAINTEXT)

    def test_file_is_not_legacy_structured(self):
        self._encrypt(hidden_header=True)
        raw = self._read_enc()
        self.assertTrue(is_hidden_format(raw))
        self.assertFalse(looks_like_legacy(raw))

    def test_in_memory_returns_hidden_bytes(self):
        out = encrypt_file(
            self.src,
            None,
            PASSWORD,
            hash_config=MINIMAL_CONFIG,
            quiet=True,
            encryption_data="aes-gcm",
            hidden_header=True,
        )
        self.assertTrue(is_hidden_format(out))


class TestKeyedHidden(_Base):
    def test_round_trip_with_second_password(self):
        self._encrypt(hidden_header=True, second_password=SECOND_PW)
        decrypt_file(self.enc, self.dec, PASSWORD, quiet=True, second_password=SECOND_PW)
        self.assertEqual(self._decrypted(), PLAINTEXT)

    def test_wrong_second_password_fails(self):
        self._encrypt(hidden_header=True, second_password=SECOND_PW)
        with self.assertRaises((AuthenticationError, ValueError)):
            decrypt_file(self.enc, self.dec, PASSWORD, quiet=True, second_password="wrong-pw")


class TestLegacyStillWorks(_Base):
    def test_legacy_round_trip_auto_detect(self):
        # Default (no hidden_header) produces the legacy format; decryption
        # auto-detects and decrypts it unchanged.
        self._encrypt()
        raw = self._read_enc()
        self.assertTrue(looks_like_legacy(raw))
        decrypt_file(self.enc, self.dec, PASSWORD, quiet=True)
        self.assertEqual(self._decrypted(), PLAINTEXT)


class TestOverrides(_Base):
    def test_force_legacy_on_hidden_file_fails(self):
        self._encrypt(hidden_header=True)
        with self.assertRaises(Exception):
            decrypt_file(self.enc, self.dec, PASSWORD, quiet=True, hidden_header=False)


if __name__ == "__main__":
    unittest.main()
