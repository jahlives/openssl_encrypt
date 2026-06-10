#!/usr/bin/env python3
"""
Test suite for the real 192-bit XChaCha20-Poly1305 primitives.

Validates the HChaCha20 subkey derivation and the XChaCha20-Poly1305 AEAD
construction in openssl_encrypt.modules.xchacha against the official test
vectors from draft-irtf-cfrg-xchacha-03 (sections 2.2.1 and A.3), an
independent pure-Python HChaCha20 reference implementation, and adversarial
input scenarios.
"""

import secrets
import struct
import unittest

from openssl_encrypt.modules.crypt_errors import (
    AuthenticationError,
    ValidationError,
)
from openssl_encrypt.modules.xchacha import (
    XCHACHA_NONCE_SIZE,
    hchacha20,
    xchacha20poly1305_decrypt,
    xchacha20poly1305_encrypt,
)

# --- Official test vectors from draft-irtf-cfrg-xchacha-03 ---

# Section 2.2.1: HChaCha20 test vector
HCHACHA_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
HCHACHA_NONCE = bytes.fromhex("000000090000004a0000000031415927")
HCHACHA_SUBKEY = bytes.fromhex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")

# Appendix A.3: AEAD_XCHACHA20_POLY1305 test vector
AEAD_PLAINTEXT = bytes.fromhex(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
    "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
    "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
    "637265656e20776f756c642062652069742e"
)
AEAD_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
AEAD_KEY = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
AEAD_NONCE = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657")
AEAD_CIPHERTEXT = bytes.fromhex(
    "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
    "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
    "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
    "21f9664c97637da9768812f615c68b13b52e"
)
AEAD_TAG = bytes.fromhex("c0875924c1c7987947deafd8780acf49")


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _quarter(s: list, a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] ^= s[a]
    s[d] = _rotl(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] ^= s[c]
    s[b] = _rotl(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] ^= s[a]
    s[d] = _rotl(s[d], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] ^= s[c]
    s[b] = _rotl(s[b], 7)


def hchacha20_reference(key: bytes, inp: bytes) -> bytes:
    """Independent pure-Python HChaCha20 per draft-irtf-cfrg-xchacha-03 §2.2."""
    state = (
        list(struct.unpack("<4I", b"expand 32-byte k"))
        + list(struct.unpack("<8I", key))
        + list(struct.unpack("<4I", inp))
    )
    for _ in range(10):
        _quarter(state, 0, 4, 8, 12)
        _quarter(state, 1, 5, 9, 13)
        _quarter(state, 2, 6, 10, 14)
        _quarter(state, 3, 7, 11, 15)
        _quarter(state, 0, 5, 10, 15)
        _quarter(state, 1, 6, 11, 12)
        _quarter(state, 2, 7, 8, 13)
        _quarter(state, 3, 4, 9, 14)
    return struct.pack("<8I", *(state[0:4] + state[12:16]))


class TestHChaCha20(unittest.TestCase):
    """HChaCha20 subkey derivation tests."""

    def test_draft_vector_2_2_1(self):
        """HChaCha20 must match the §2.2.1 test vector exactly."""
        self.assertEqual(hchacha20(HCHACHA_KEY, HCHACHA_NONCE), HCHACHA_SUBKEY)

    def test_matches_pure_python_reference_on_random_inputs(self):
        """The C-backed implementation must agree with an independent
        pure-Python implementation across random inputs."""
        for _ in range(50):
            key = secrets.token_bytes(32)
            inp = secrets.token_bytes(16)
            self.assertEqual(hchacha20(key, inp), hchacha20_reference(key, inp))

    def test_output_length(self):
        self.assertEqual(len(hchacha20(HCHACHA_KEY, HCHACHA_NONCE)), 32)

    def test_invalid_key_length_rejected(self):
        for bad_len in (0, 16, 31, 33, 64):
            with self.assertRaises(ValidationError):
                hchacha20(b"k" * bad_len, HCHACHA_NONCE)

    def test_invalid_input_length_rejected(self):
        for bad_len in (0, 12, 15, 17, 24):
            with self.assertRaises(ValidationError):
                hchacha20(HCHACHA_KEY, b"n" * bad_len)

    def test_none_inputs_rejected(self):
        with self.assertRaises(ValidationError):
            hchacha20(None, HCHACHA_NONCE)
        with self.assertRaises(ValidationError):
            hchacha20(HCHACHA_KEY, None)


class TestXChaCha20Poly1305AEAD(unittest.TestCase):
    """Full AEAD construction tests against the draft A.3 vector."""

    def test_draft_vector_a3_encrypt(self):
        """Encryption must reproduce the A.3 ciphertext and tag exactly."""
        result = xchacha20poly1305_encrypt(AEAD_KEY, AEAD_NONCE, AEAD_PLAINTEXT, AEAD_AAD)
        self.assertEqual(result, AEAD_CIPHERTEXT + AEAD_TAG)

    def test_draft_vector_a3_decrypt(self):
        """Decryption of the A.3 ciphertext+tag must yield the plaintext."""
        result = xchacha20poly1305_decrypt(
            AEAD_KEY, AEAD_NONCE, AEAD_CIPHERTEXT + AEAD_TAG, AEAD_AAD
        )
        self.assertEqual(result, AEAD_PLAINTEXT)

    def test_round_trip_random(self):
        for size in (0, 1, 63, 64, 65, 1024):
            key = secrets.token_bytes(32)
            nonce = secrets.token_bytes(XCHACHA_NONCE_SIZE)
            plaintext = secrets.token_bytes(size)
            aad = secrets.token_bytes(16)
            ct = xchacha20poly1305_encrypt(key, nonce, plaintext, aad)
            self.assertEqual(xchacha20poly1305_decrypt(key, nonce, ct, aad), plaintext)

    def test_round_trip_no_aad(self):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(XCHACHA_NONCE_SIZE)
        ct = xchacha20poly1305_encrypt(key, nonce, b"data", None)
        self.assertEqual(xchacha20poly1305_decrypt(key, nonce, ct, None), b"data")

    def test_full_192bit_nonce_is_effective(self):
        """Regression test for the legacy 96-bit-effective bug: flipping any
        single byte of the 24-byte nonce must change the ciphertext.

        The legacy implementation sliced the nonce to its first 12 bytes, so
        changes in bytes 12-23 did not affect the keystream."""
        key = secrets.token_bytes(32)
        nonce = bytearray(secrets.token_bytes(XCHACHA_NONCE_SIZE))
        plaintext = b"nonce effectiveness probe"
        baseline = xchacha20poly1305_encrypt(key, bytes(nonce), plaintext, None)
        for i in range(XCHACHA_NONCE_SIZE):
            modified = bytearray(nonce)
            modified[i] ^= 0x01
            variant = xchacha20poly1305_encrypt(key, bytes(modified), plaintext, None)
            self.assertNotEqual(
                baseline,
                variant,
                f"nonce byte {i} does not affect the ciphertext",
            )

    def test_tampered_ciphertext_rejected(self):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(XCHACHA_NONCE_SIZE)
        ct = bytearray(xchacha20poly1305_encrypt(key, nonce, b"payload", b"aad"))
        ct[0] ^= 0x01
        with self.assertRaises(AuthenticationError):
            xchacha20poly1305_decrypt(key, nonce, bytes(ct), b"aad")

    def test_tampered_tag_rejected(self):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(XCHACHA_NONCE_SIZE)
        ct = bytearray(xchacha20poly1305_encrypt(key, nonce, b"payload", None))
        ct[-1] ^= 0x01
        with self.assertRaises(AuthenticationError):
            xchacha20poly1305_decrypt(key, nonce, bytes(ct), None)

    def test_wrong_aad_rejected(self):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(XCHACHA_NONCE_SIZE)
        ct = xchacha20poly1305_encrypt(key, nonce, b"payload", b"aad-1")
        with self.assertRaises(AuthenticationError):
            xchacha20poly1305_decrypt(key, nonce, ct, b"aad-2")

    def test_wrong_nonce_rejected(self):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(XCHACHA_NONCE_SIZE)
        ct = xchacha20poly1305_encrypt(key, nonce, b"payload", None)
        other = bytearray(nonce)
        other[20] ^= 0x01  # differs only in the part legacy code ignored
        with self.assertRaises(AuthenticationError):
            xchacha20poly1305_decrypt(key, bytes(other), ct, None)

    def test_invalid_nonce_length_rejected(self):
        key = secrets.token_bytes(32)
        for bad_len in (0, 12, 16, 23, 25):
            with self.assertRaises(ValidationError):
                xchacha20poly1305_encrypt(key, b"n" * bad_len, b"data", None)
            with self.assertRaises(ValidationError):
                xchacha20poly1305_decrypt(key, b"n" * bad_len, b"c" * 17, None)

    def test_invalid_key_length_rejected(self):
        nonce = secrets.token_bytes(XCHACHA_NONCE_SIZE)
        with self.assertRaises(ValidationError):
            xchacha20poly1305_encrypt(b"short", nonce, b"data", None)

    def test_ciphertext_shorter_than_tag_rejected(self):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(XCHACHA_NONCE_SIZE)
        with self.assertRaises((ValidationError, AuthenticationError)):
            xchacha20poly1305_decrypt(key, nonce, b"short", None)


if __name__ == "__main__":
    unittest.main()
