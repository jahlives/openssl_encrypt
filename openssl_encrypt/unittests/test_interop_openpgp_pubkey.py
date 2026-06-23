#!/usr/bin/env python3
"""
Tests for read-only OpenPGP PUBLIC-KEY decryption (feature #5, phase 3).

Functional coverage uses REAL GnuPG 2.2.40 keypairs + public-key-encrypted
messages (committed under testfiles/openpgp_pubkey/): RSA-3072, Curve25519
(cv25519 ECDH), and NIST P-256/384/521 ECDH. Negative tests cover a wrong key
passphrase and a non-matching key.
"""

import os
import unittest

from openssl_encrypt.modules.interop.openpgp import OpenPGPWrongPassphrase
from openssl_encrypt.modules.interop.openpgp_pubkey import (
    OpenPGPNoMatchingKey,
    decrypt,
    parse_secret_keys,
)

_PW = "keypw"
_DIR = os.path.join(os.path.dirname(__file__), "testfiles", "openpgp_pubkey")
_EXPECT = b"public-key openpgp interop test message"
_CURVES = ["rsa", "cv25519", "nistp256", "nistp384", "nistp521"]


def _read(name):
    with open(os.path.join(_DIR, name), "rb") as f:
        return f.read()


class TestOpenPGPPublicKeyVectors(unittest.TestCase):
    """Decrypt real GnuPG public-key messages across RSA + ECDH curves."""

    def _roundtrip(self, name):
        keys = parse_secret_keys(_read(f"sec_{name}.asc"), _PW)
        pt = decrypt(_read(f"msg_{name}.gpg"), secret_keys=keys)
        self.assertEqual(pt, _EXPECT)

    def test_rsa3072(self):
        self._roundtrip("rsa")

    def test_curve25519(self):
        self._roundtrip("cv25519")

    def test_nistp256(self):
        self._roundtrip("nistp256")

    def test_nistp384(self):
        self._roundtrip("nistp384")

    def test_nistp521(self):
        self._roundtrip("nistp521")


class TestOpenPGPPublicKeyRejection(unittest.TestCase):
    def test_wrong_key_passphrase(self):
        with self.assertRaises(OpenPGPWrongPassphrase):
            parse_secret_keys(_read("sec_rsa.asc"), "not the key passphrase")

    def test_non_matching_key(self):
        # Decrypt a cv25519 message with only the RSA key loaded.
        rsa_keys = parse_secret_keys(_read("sec_rsa.asc"), _PW)
        with self.assertRaises(OpenPGPNoMatchingKey):
            decrypt(_read("msg_cv25519.gpg"), secret_keys=rsa_keys)


if __name__ == "__main__":
    unittest.main()
