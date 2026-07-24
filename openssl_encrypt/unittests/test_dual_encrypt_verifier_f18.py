"""Regression tests for the dual-encryption file-password authentication (gitlab#131 / F18).

The legacy dual-encryption second factor was pre-checked with a weak
10k-iteration PBKDF2 hash stored in cleartext metadata (brute-forceable offline).
That pre-check is no longer trusted; the file password is authenticated by the
keystore's own dual-encryption AES-GCM tag (Argon2id-derived key) in
``PQCKeystore.get_key``.

The one state where that AES-GCM tag would NOT gate the file password is a
metadata/keystore mismatch — a request that supplies a file password (because the
file claims dual encryption) against a keystore key entry that is NOT
dual-encrypted. ``get_key`` now fails closed in that case, so removing the weak
pre-check cannot let a wrong file password through. These tests pin: the
mismatch is refused; a real dual key still authenticates the file password via
AES-GCM (right password works, wrong password fails); and a plain non-dual
retrieval is unaffected.
"""

import os
import tempfile
import unittest

from openssl_encrypt.modules.keystore_cli import (
    KeystoreError,
    KeystorePasswordError,
    KeystoreSecurityLevel,
    PQCKeystore,
)


class TestDualEncryptVerifierF18(unittest.TestCase):
    MASTER = "master-keystore-password"
    FILE_PW = "file-password-1234"
    ALGO = "ml-kem-768-hybrid"
    PUB = b"\x01" * 32
    PRIV = b"\x02" * 64

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".pqks")
        os.close(fd)
        os.unlink(self.path)  # create_keystore refuses to overwrite
        self.ks = PQCKeystore(self.path)
        self.ks.create_keystore(self.MASTER, KeystoreSecurityLevel.STANDARD)

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def test_mismatch_file_password_on_non_dual_entry_is_refused(self):
        # gitlab#131 F18 core regression: supplying a file password against a
        # NON-dual key entry (the file/keystore mismatch) must fail closed, not
        # silently ignore the file password and accept any value.
        key_id = self.ks.add_key(self.ALGO, self.PUB, self.PRIV, dual_encryption=False)
        with self.assertRaises(KeystoreError) as ctx:
            self.ks.get_key(key_id, None, "any-file-password")
        self.assertIn("mismatch", str(ctx.exception).lower())

    def test_non_dual_retrieval_without_file_password_works(self):
        key_id = self.ks.add_key(self.ALGO, self.PUB, self.PRIV, dual_encryption=False)
        pub, priv = self.ks.get_key(key_id)
        self.assertEqual(priv, self.PRIV)

    def test_dual_key_correct_file_password_authenticates(self):
        key_id = self.ks.add_key(
            self.ALGO,
            self.PUB,
            self.PRIV,
            dual_encryption=True,
            file_password=self.FILE_PW,
        )
        pub, priv = self.ks.get_key(key_id, None, self.FILE_PW)
        self.assertEqual(priv, self.PRIV)

    def test_dual_key_wrong_file_password_is_rejected_by_aead(self):
        # The AES-GCM tag (not the removed weak verifier) rejects a wrong file
        # password for a genuine dual key.
        key_id = self.ks.add_key(
            self.ALGO,
            self.PUB,
            self.PRIV,
            dual_encryption=True,
            file_password=self.FILE_PW,
        )
        with self.assertRaises(KeystorePasswordError):
            self.ks.get_key(key_id, None, "wrong-file-password")

    def test_dual_key_missing_file_password_is_refused(self):
        # Pre-existing symmetric check: a dual entry requires a file password.
        key_id = self.ks.add_key(
            self.ALGO,
            self.PUB,
            self.PRIV,
            dual_encryption=True,
            file_password=self.FILE_PW,
        )
        with self.assertRaises(KeystoreError):
            self.ks.get_key(key_id, None, None)


if __name__ == "__main__":
    unittest.main()
