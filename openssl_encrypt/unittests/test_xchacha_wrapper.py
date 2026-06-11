#!/usr/bin/env python3
"""
Test suite for the crypt_core.XChaCha20Poly1305 wrapper class.

The wrapper dispatches on nonce length:
- 24-byte nonce: real 192-bit XChaCha20-Poly1305 (HChaCha20 subkey
  derivation per draft-irtf-cfrg-xchacha-03) — new format.
- 12-byte nonce: direct ChaCha20-Poly1305 under the same key — legacy
  behavior used by all pre-1.5 file paths and the PQC hybrid path.
- Any other length: rejected.
"""

import secrets
import unittest

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from openssl_encrypt.modules.crypt_core import XChaCha20Poly1305
from openssl_encrypt.modules.crypt_errors import (
    AuthenticationError,
    ValidationError,
)
from openssl_encrypt.modules.xchacha import (
    xchacha20poly1305_decrypt,
    xchacha20poly1305_encrypt,
)

# draft-irtf-cfrg-xchacha-03 Appendix A.3 AEAD test vector
AEAD_KEY = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
AEAD_NONCE = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657")
AEAD_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
AEAD_PLAINTEXT = bytes.fromhex(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
    "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
    "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
    "637265656e20776f756c642062652069742e"
)
AEAD_SEALED = bytes.fromhex(
    "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
    "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
    "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
    "21f9664c97637da9768812f615c68b13b52e"
    "c0875924c1c7987947deafd8780acf49"
)


class TestXChaChaWrapperRealMode(unittest.TestCase):
    """24-byte nonces must use the real XChaCha20-Poly1305 construction."""

    def test_draft_vector_a3_through_wrapper(self):
        cipher = XChaCha20Poly1305(AEAD_KEY)
        self.assertEqual(cipher.encrypt(AEAD_NONCE, AEAD_PLAINTEXT, AEAD_AAD), AEAD_SEALED)
        self.assertEqual(cipher.decrypt(AEAD_NONCE, AEAD_SEALED, AEAD_AAD), AEAD_PLAINTEXT)

    def test_matches_primitive_helpers(self):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(24)
        cipher = XChaCha20Poly1305(key)
        sealed = cipher.encrypt(nonce, b"wrapper consistency", b"aad")
        self.assertEqual(
            sealed, xchacha20poly1305_encrypt(key, nonce, b"wrapper consistency", b"aad")
        )
        self.assertEqual(
            xchacha20poly1305_decrypt(key, nonce, sealed, b"aad"),
            b"wrapper consistency",
        )

    def test_round_trip(self):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(24)
        cipher = XChaCha20Poly1305(key)
        sealed = cipher.encrypt(nonce, b"round trip", None)
        self.assertEqual(cipher.decrypt(nonce, sealed, None), b"round trip")

    def test_full_nonce_is_effective(self):
        """Bytes 12-23 of the nonce must affect the ciphertext (regression
        test for the legacy behavior that sliced the nonce to 12 bytes)."""
        key = secrets.token_bytes(32)
        cipher = XChaCha20Poly1305(key)
        nonce = bytearray(secrets.token_bytes(24))
        baseline = cipher.encrypt(bytes(nonce), b"probe", None)
        for i in range(12, 24):
            modified = bytearray(nonce)
            modified[i] ^= 0x01
            self.assertNotEqual(
                baseline,
                cipher.encrypt(bytes(modified), b"probe", None),
                f"nonce byte {i} does not affect the ciphertext",
            )

    def test_not_legacy_keystream(self):
        """The 24-byte mode must NOT equal legacy first-12-bytes slicing."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(24)
        cipher = XChaCha20Poly1305(key)
        sealed = cipher.encrypt(nonce, b"distinct", None)
        legacy = ChaCha20Poly1305(key).encrypt(nonce[:12], b"distinct", None)
        self.assertNotEqual(sealed, legacy)

    def test_tamper_rejected(self):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(24)
        cipher = XChaCha20Poly1305(key)
        sealed = bytearray(cipher.encrypt(nonce, b"payload", None))
        sealed[0] ^= 0x01
        with self.assertRaises(AuthenticationError):
            cipher.decrypt(nonce, bytes(sealed), None)


class TestXChaChaWrapperLegacyMode(unittest.TestCase):
    """12-byte nonces must remain direct ChaCha20-Poly1305 under the same
    key — required to keep decrypting pre-1.5 files and the PQC path."""

    def test_legacy_equivalence_encrypt(self):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        sealed = XChaCha20Poly1305(key).encrypt(nonce, b"legacy data", b"aad")
        self.assertEqual(sealed, ChaCha20Poly1305(key).encrypt(nonce, b"legacy data", b"aad"))

    def test_legacy_equivalence_decrypt(self):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        sealed = ChaCha20Poly1305(key).encrypt(nonce, b"legacy data", None)
        self.assertEqual(XChaCha20Poly1305(key).decrypt(nonce, sealed, None), b"legacy data")

    def test_round_trip(self):
        key = secrets.token_bytes(32)
        cipher = XChaCha20Poly1305(key)
        nonce = secrets.token_bytes(12)
        sealed = cipher.encrypt(nonce, b"legacy round trip", None)
        self.assertEqual(cipher.decrypt(nonce, sealed, None), b"legacy round trip")


class TestXChaChaWrapperValidation(unittest.TestCase):
    """Input validation and error mapping."""

    def test_invalid_nonce_lengths_rejected(self):
        cipher = XChaCha20Poly1305(secrets.token_bytes(32))
        for bad_len in (0, 8, 11, 13, 16, 23, 25, 32):
            with self.assertRaises(ValidationError, msg=f"encrypt len {bad_len}"):
                cipher.encrypt(b"n" * bad_len, b"data", None)
            with self.assertRaises(ValidationError, msg=f"decrypt len {bad_len}"):
                cipher.decrypt(b"n" * bad_len, b"c" * 17, None)

    def test_none_nonce_rejected(self):
        cipher = XChaCha20Poly1305(secrets.token_bytes(32))
        with self.assertRaises(ValidationError):
            cipher.encrypt(None, b"data", None)

    def test_invalid_key_rejected(self):
        with self.assertRaises(ValidationError):
            XChaCha20Poly1305(None)
        with self.assertRaises(ValidationError):
            XChaCha20Poly1305(b"too short")

    def test_invalid_data_rejected(self):
        cipher = XChaCha20Poly1305(secrets.token_bytes(32))
        with self.assertRaises(ValidationError):
            cipher.encrypt(secrets.token_bytes(24), None, None)

    def test_invalid_aad_rejected(self):
        cipher = XChaCha20Poly1305(secrets.token_bytes(32))
        with self.assertRaises(ValidationError):
            cipher.encrypt(secrets.token_bytes(24), b"data", "not-bytes")

    def test_short_ciphertext_rejected(self):
        cipher = XChaCha20Poly1305(secrets.token_bytes(32))
        with self.assertRaises(ValidationError):
            cipher.decrypt(secrets.token_bytes(24), b"short", None)


if __name__ == "__main__":
    unittest.main()
