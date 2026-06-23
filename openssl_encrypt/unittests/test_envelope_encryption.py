#!/usr/bin/env python3
"""Tests for password-based envelope (DEK/KEK) wrapping.

Feature #2 (see docs/PLAN_streaming-cascade-nonce_and_envelope.md). Bulk data
is encrypted under a random DEK; the DEK is wrapped by a password-derived KEK so
that rekey only rewraps the DEK instead of re-encrypting the bulk data.

Cycle 1 covers the standalone wrap/unwrap primitive in modules/envelope.py.
"""

import secrets
import unittest

from openssl_encrypt.modules.envelope import (
    DEK_SIZE,
    generate_dek,
    unwrap_dek,
    wrap_dek,
)


class TestEnvelopeWrapUnwrap(unittest.TestCase):
    """wrap_dek() / unwrap_dek() round-trip and failure modes."""

    def setUp(self):
        self.kek = secrets.token_bytes(32)
        self.dek = bytes(generate_dek())

    def test_generate_dek_size(self):
        """generate_dek() returns DEK_SIZE bytes of mutable buffer."""
        dek = generate_dek()
        self.assertEqual(len(dek), DEK_SIZE)
        self.assertEqual(DEK_SIZE, 32)
        self.assertIsInstance(dek, bytearray)  # mutable so callers can zero it

    def test_roundtrip(self):
        """unwrap_dek(wrap_dek(dek, kek), kek) == dek."""
        wrapped = wrap_dek(self.dek, self.kek)
        recovered = unwrap_dek(wrapped, self.kek)
        self.assertEqual(bytes(recovered), self.dek)

    def test_wrapped_is_not_plaintext_dek(self):
        """The wrapped blob must not expose the raw DEK."""
        wrapped = wrap_dek(self.dek, self.kek)
        self.assertNotIn(self.dek, wrapped)

    def test_output_size(self):
        """Wrapped format is nonce(12) + ciphertext(32) + tag(16) = 60 bytes."""
        wrapped = wrap_dek(self.dek, self.kek)
        self.assertEqual(len(wrapped), 12 + DEK_SIZE + 16)

    def test_unique_nonce_per_wrap(self):
        """Each wrap uses a fresh nonce, so identical inputs differ."""
        w1 = wrap_dek(self.dek, self.kek)
        w2 = wrap_dek(self.dek, self.kek)
        self.assertNotEqual(w1, w2)

    def test_wrong_kek_fails(self):
        """Unwrapping with the wrong KEK raises (authenticated)."""
        wrapped = wrap_dek(self.dek, self.kek)
        wrong_kek = secrets.token_bytes(32)
        with self.assertRaises(Exception):
            unwrap_dek(wrapped, wrong_kek)

    def test_tamper_fails(self):
        """Flipping any ciphertext/tag byte makes unwrap fail."""
        wrapped = bytearray(wrap_dek(self.dek, self.kek))
        wrapped[-1] ^= 0x01  # corrupt the tag
        with self.assertRaises(Exception):
            unwrap_dek(bytes(wrapped), self.kek)

    def test_truncated_blob_fails(self):
        """A too-short blob is rejected, not silently processed."""
        with self.assertRaises(Exception):
            unwrap_dek(b"too-short", self.kek)

    def test_short_kek_rejected(self):
        """A KEK shorter than 32 bytes is rejected."""
        with self.assertRaises(Exception):
            wrap_dek(self.dek, b"short")


if __name__ == "__main__":
    unittest.main()
