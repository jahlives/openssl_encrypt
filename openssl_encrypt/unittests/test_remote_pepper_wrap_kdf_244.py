#!/usr/bin/env python3
"""Remote-pepper wrap key must be salted + memory-hard, not HKDF(password, salt=None).

Scan finding F2 (gitlab#244, CWE-916). The remote pepper was sealed under
HKDF-SHA256(password, salt=None) (bare SHA-256 for format < 12) with no AAD, so
a hostile keyserver holding the wrapped blobs could precompute one fleet-wide
table and guess the password at ~2 SHA-256/guess. The v2 blob
(magic || salt(16) || nonce(12) || ct||tag) derives the wrap key with Argon2id
over the password and a fresh per-blob salt, and binds the pepper name as AAD.
Legacy blobs stay readable (read-only).
"""

import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from openssl_encrypt.modules import crypt_core
from openssl_encrypt.modules.crypt_core import (
    _PEPPER_WRAP_V2_MAGIC,
    _unwrap_remote_pepper,
    _wrap_remote_pepper,
)


@unittest.skipUnless(crypt_core.ARGON2_AVAILABLE, "argon2 required for v2 pepper wrap")
class TestRemotePepperWrapKdf(unittest.TestCase):
    def setUp(self):
        self.password = b"correct horse battery staple"
        self.pepper = bytes(range(32))
        self.name = "a" * 32

    def test_roundtrip(self):
        blob = _wrap_remote_pepper(self.password, self.pepper, self.name)
        out = _unwrap_remote_pepper(self.password, blob, self.name, format_version=14)
        self.assertEqual(bytes(out), self.pepper)

    def test_blob_is_v2_self_describing(self):
        blob = _wrap_remote_pepper(self.password, self.pepper, self.name)
        self.assertTrue(blob.startswith(_PEPPER_WRAP_V2_MAGIC))
        # magic(8) + salt(16) + nonce(12) + ct(32) + tag(16) == 84 for a 32B pepper
        self.assertEqual(len(blob), len(_PEPPER_WRAP_V2_MAGIC) + 16 + 12 + 32 + 16)

    def test_salt_is_fresh_per_blob(self):
        # Same password + pepper twice -> different salt -> different ciphertext.
        # This is the property HKDF(salt=None) violated (fleet-wide precompute).
        b1 = _wrap_remote_pepper(self.password, self.pepper, self.name)
        b2 = _wrap_remote_pepper(self.password, self.pepper, self.name)
        self.assertNotEqual(b1, b2)
        salt1 = b1[len(_PEPPER_WRAP_V2_MAGIC) : len(_PEPPER_WRAP_V2_MAGIC) + 16]
        salt2 = b2[len(_PEPPER_WRAP_V2_MAGIC) : len(_PEPPER_WRAP_V2_MAGIC) + 16]
        self.assertNotEqual(salt1, salt2)
        # Both still decrypt.
        self.assertEqual(
            bytes(_unwrap_remote_pepper(self.password, b1, self.name, 14)), self.pepper
        )
        self.assertEqual(
            bytes(_unwrap_remote_pepper(self.password, b2, self.name, 14)), self.pepper
        )

    def test_wrong_password_fails(self):
        blob = _wrap_remote_pepper(self.password, self.pepper, self.name)
        with self.assertRaises(Exception):
            _unwrap_remote_pepper(b"wrong password", blob, self.name, 14)

    def test_aad_binds_pepper_name(self):
        # A blob wrapped under one name must not unwrap under another (server-side
        # blob swap / confusion is detected by the AEAD tag).
        blob = _wrap_remote_pepper(self.password, self.pepper, self.name)
        with self.assertRaises(Exception):
            _unwrap_remote_pepper(self.password, blob, "b" * 32, 14)

    def test_params_not_taken_from_blob(self):
        # The v2 header carries NO argon2 parameters (fixed by the magic version),
        # so a hostile server cannot drive a decrypt-time memory-exhaustion DoS.
        # Header before ciphertext is exactly magic + salt + nonce.
        blob = _wrap_remote_pepper(self.password, self.pepper, self.name)
        header = len(_PEPPER_WRAP_V2_MAGIC) + 16 + 12
        # ciphertext length == pepper length; tag == 16. No room for a params field.
        self.assertEqual(len(blob) - header, len(self.pepper) + 16)

    def test_legacy_hkdf_blob_still_readable(self):
        # A pre-fix v12+ blob: nonce(12) || AESGCM(HKDF(password, salt=None)).
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"openssl_encrypt-pepper-key",
        ).derive(self.password)
        nonce = b"\x01" * 12
        ct = AESGCM(key).encrypt(nonce, self.pepper, None)
        legacy = nonce + ct
        self.assertFalse(legacy.startswith(_PEPPER_WRAP_V2_MAGIC))
        out = _unwrap_remote_pepper(self.password, legacy, self.name, format_version=14)
        self.assertEqual(bytes(out), self.pepper)

    def test_legacy_sha256_blob_still_readable(self):
        # A pre-fix < v12 blob: nonce(12) || AESGCM(SHA256(password)).
        import hashlib

        key = hashlib.sha256(self.password).digest()
        nonce = b"\x02" * 12
        ct = AESGCM(key).encrypt(nonce, self.pepper, None)
        legacy = nonce + ct
        out = _unwrap_remote_pepper(self.password, legacy, self.name, format_version=7)
        self.assertEqual(bytes(out), self.pepper)

    def test_unwrap_returns_wipeable_bytearray(self):
        blob = _wrap_remote_pepper(self.password, self.pepper, self.name)
        out = _unwrap_remote_pepper(self.password, blob, self.name, 14)
        self.assertIsInstance(out, bytearray)

    def test_missing_argon2_raises_keyderivationerror(self):
        # A v2 blob with Argon2 unavailable must surface a KeyDerivationError
        # (config/dependency problem), NOT be masked as a wrong password.
        from unittest import mock

        from openssl_encrypt.modules.crypt_core import KeyDerivationError

        blob = _wrap_remote_pepper(self.password, self.pepper, self.name)
        with mock.patch.object(crypt_core, "ARGON2_AVAILABLE", False):
            with self.assertRaises(KeyDerivationError):
                _unwrap_remote_pepper(self.password, blob, self.name, 14)


if __name__ == "__main__":
    unittest.main()
