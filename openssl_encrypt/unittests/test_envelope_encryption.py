#!/usr/bin/env python3
"""Tests for password-based envelope (DEK/KEK) wrapping.

Feature #2 (see docs/PLAN_streaming-cascade-nonce_and_envelope.md). Bulk data
is encrypted under a random DEK; the DEK is wrapped by a password-derived KEK so
that rekey only rewraps the DEK instead of re-encrypting the bulk data.

Cycle 1 covers the standalone wrap/unwrap primitive in modules/envelope.py.
"""

import base64
import json
import os
import secrets
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import decrypt_file, encrypt_file
from openssl_encrypt.modules.envelope import (
    DEK_SIZE,
    generate_dek,
    unwrap_dek,
    wrap_dek,
)

_FAST_HASH = {"sha256": 1, "pbkdf2_iterations": 0}


def _tmp(data: bytes = b"") -> str:
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def _read_metadata(path: str) -> dict:
    with open(path, "rb") as f:
        raw = f.read()
    return json.loads(base64.b64decode(raw.split(b":", 1)[0]))


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


class TestEnvelopeIntegration(unittest.TestCase):
    """End-to-end envelope mode through encrypt_file / decrypt_file (opt-in)."""

    PASSWORD = b"envelope-integration-pw"

    def _roundtrip(self, algorithm=None, cascade=False, cipher_names=None, size=4096):
        data = secrets.token_bytes(size)
        ip = _tmp(data)
        op = _tmp()
        try:
            kwargs = dict(
                input_file=ip,
                output_file=op,
                password=self.PASSWORD,
                hash_config=dict(_FAST_HASH),
                quiet=True,
                envelope=True,
            )
            if cascade:
                kwargs.update(algorithm="cascade", cascade=True, cipher_names=cipher_names)
            else:
                kwargs.update(algorithm=algorithm)
            self.assertTrue(encrypt_file(**kwargs))

            meta = _read_metadata(op)
            decrypted = decrypt_file(
                input_file=op, output_file=None, password=self.PASSWORD, quiet=True
            )
            self.assertEqual(decrypted, data)
            return meta
        finally:
            for p in (ip, op):
                if os.path.exists(p):
                    os.unlink(p)

    def test_envelope_roundtrip_aes_gcm(self):
        """Envelope encrypt/decrypt round-trips for aes-gcm."""
        meta = self._roundtrip(algorithm="aes-gcm")
        self.assertIn("wrapped_dek", meta["encryption"])

    def test_envelope_roundtrip_chacha(self):
        """Envelope encrypt/decrypt round-trips for chacha20-poly1305."""
        self._roundtrip(algorithm="chacha20-poly1305")

    def test_envelope_roundtrip_cascade(self):
        """Envelope encrypt/decrypt round-trips for a cascade chain."""
        self._roundtrip(cascade=True, cipher_names=["aes-256-gcm", "chacha20-poly1305"])

    def test_wrapped_dek_is_base64(self):
        """The stored wrapped_dek is base64 and decodes to the expected size."""
        meta = self._roundtrip(algorithm="aes-gcm")
        wrapped = base64.b64decode(meta["encryption"]["wrapped_dek"])
        self.assertEqual(len(wrapped), 12 + DEK_SIZE + 16)

    def test_non_envelope_has_no_wrapped_dek(self):
        """Without --envelope, no wrapped_dek is written (unchanged behavior)."""
        data = secrets.token_bytes(4096)
        ip = _tmp(data)
        op = _tmp()
        try:
            self.assertTrue(
                encrypt_file(
                    input_file=ip,
                    output_file=op,
                    password=self.PASSWORD,
                    hash_config=dict(_FAST_HASH),
                    quiet=True,
                    algorithm="aes-gcm",
                )
            )
            meta = _read_metadata(op)
            self.assertNotIn("wrapped_dek", meta.get("encryption", {}))
            decrypted = decrypt_file(
                input_file=op, output_file=None, password=self.PASSWORD, quiet=True
            )
            self.assertEqual(decrypted, data)
        finally:
            for p in (ip, op):
                if os.path.exists(p):
                    os.unlink(p)

    def test_envelope_streaming_roundtrip(self):
        """Envelope mode works with the streaming path (key=DEK flows through)."""
        data = secrets.token_bytes(8 * 1024)
        ip = _tmp(data)
        op = _tmp()
        try:
            self.assertTrue(
                encrypt_file(
                    input_file=ip,
                    output_file=op,
                    password=self.PASSWORD,
                    hash_config=dict(_FAST_HASH),
                    quiet=True,
                    algorithm="aes-gcm",
                    envelope=True,
                    chunk_size=1024,
                    streaming_threshold=1024,
                )
            )
            meta = _read_metadata(op)
            self.assertTrue(meta.get("streaming", {}).get("enabled"))
            self.assertIn("wrapped_dek", meta["encryption"])
            decrypted = decrypt_file(
                input_file=op, output_file=None, password=self.PASSWORD, quiet=True
            )
            self.assertEqual(decrypted, data)
        finally:
            for p in (ip, op):
                if os.path.exists(p):
                    os.unlink(p)

    def test_envelope_wrong_password_fails(self):
        """A wrong password must not decrypt an envelope file."""
        data = secrets.token_bytes(4096)
        ip = _tmp(data)
        op = _tmp()
        try:
            encrypt_file(
                input_file=ip,
                output_file=op,
                password=self.PASSWORD,
                hash_config=dict(_FAST_HASH),
                quiet=True,
                algorithm="aes-gcm",
                envelope=True,
            )
            with self.assertRaises(Exception):
                decrypt_file(
                    input_file=op, output_file=None, password=b"wrong-password", quiet=True
                )
        finally:
            for p in (ip, op):
                if os.path.exists(p):
                    os.unlink(p)


if __name__ == "__main__":
    unittest.main()
