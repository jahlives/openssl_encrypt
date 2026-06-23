#!/usr/bin/env python3
"""
Tests for read-only OpenPGP symmetric (`gpg -c`) decryption (feature #5, phase 2).

Functional coverage uses REAL fixtures produced by GnuPG 2.2.40 (committed under
testfiles/openpgp/), exercising multiple ciphers, compression algorithms, S2K
hashes, ASCII armor, and a 200 KB file (partial-length packets). Negative tests
cover wrong passphrase, MDC tamper, the unauthenticated SED packet (refused),
and non-OpenPGP input.
"""

import hashlib
import os
import unittest

from openssl_encrypt.modules.interop.openpgp import (
    OpenPGPError,
    OpenPGPFormatError,
    OpenPGPWrongPassphrase,
    decrypt,
    is_openpgp_file,
)

_PW = "correct horse battery"
_DIR = os.path.join(os.path.dirname(__file__), "testfiles", "openpgp")
_SMALL = b"hello openpgp symmetric world"
_BIG_SHA256 = "7b28964e0d878c2ca373f816ec9bf18864cb058901416419ac25a56864f35cd8"


def _load(name):
    with open(os.path.join(_DIR, name), "rb") as f:
        return f.read()


class TestOpenPGPReferenceVectors(unittest.TestCase):
    """Decrypt real GnuPG `gpg -c` output across ciphers / options."""

    def _check_small(self, name):
        self.assertEqual(decrypt(_load(name), passphrase=_PW), _SMALL)

    def test_default(self):
        self._check_small("v_default.gpg")  # AES-256 + compression + MDC

    def test_aes256(self):
        self._check_small("v_aes256.gpg")

    def test_aes128(self):
        self._check_small("v_aes128.gpg")

    def test_cast5(self):
        self._check_small("v_cast5.gpg")

    def test_3des(self):
        self._check_small("v_3des.gpg")

    def test_zlib_compression(self):
        self._check_small("v_zlib.gpg")

    def test_sha512_s2k(self):
        self._check_small("v_sha512.gpg")

    def test_ascii_armored(self):
        self.assertTrue(is_openpgp_file(_load("v_armored.asc")))
        self._check_small("v_armored.asc")

    def test_large_partial_lengths(self):
        pt = decrypt(_load("v_big.gpg"), passphrase=_PW)
        self.assertEqual(hashlib.sha256(pt).hexdigest(), _BIG_SHA256)


class TestOpenPGPRejection(unittest.TestCase):
    def test_wrong_passphrase(self):
        with self.assertRaises(OpenPGPWrongPassphrase):
            decrypt(_load("v_aes256.gpg"), passphrase="not the passphrase")

    def test_tampered_ciphertext(self):
        data = bytearray(_load("v_aes256.gpg"))
        # Flip a byte well inside the encrypted data (past the SKESK + SEIPD
        # header and the CFB prefix) so the MDC, not the quick-check, catches it.
        data[-8] ^= 0x01
        with self.assertRaises(OpenPGPError):  # MDC failure (or quick-check)
            decrypt(bytes(data), passphrase=_PW)

    def test_sed_packet_refused(self):
        # A bare Symmetrically Encrypted Data packet (tag 9, no integrity).
        sed = bytes([0xA4, 0x01, 0x00])  # old-format tag 9, 1-byte body
        with self.assertRaises(OpenPGPFormatError):
            decrypt(sed, passphrase=_PW)

    def test_not_openpgp(self):
        self.assertFalse(is_openpgp_file(os.urandom(64)))
        with self.assertRaises(OpenPGPError):
            decrypt(os.urandom(64), passphrase=_PW)

    def test_no_seipd(self):
        # SKESK alone (no encrypted data) must fail closed, not hang/guess.
        skesk_only = _extract_first_packet(_load("v_aes256.gpg"))
        with self.assertRaises(OpenPGPFormatError):
            decrypt(skesk_only, passphrase=_PW)


def _extract_first_packet(data):
    """Return just the first packet (the SKESK) from a message."""
    from openssl_encrypt.modules.interop.openpgp import _read_packet

    _tag, _body, off = _read_packet(data, 0)
    return data[:off]


class TestOpenPGPDetection(unittest.TestCase):
    def test_detect_binary_skesk(self):
        self.assertTrue(is_openpgp_file(_load("v_aes256.gpg")))

    def test_detect_armored(self):
        self.assertTrue(is_openpgp_file(_load("v_armored.asc")))

    def test_reject_age_file(self):
        self.assertFalse(is_openpgp_file(b"age-encryption.org/v1\n-> X25519 ..."))


if __name__ == "__main__":
    unittest.main()
