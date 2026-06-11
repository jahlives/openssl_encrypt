#!/usr/bin/env python3
"""
Regression tests for the streaming format_version mismatch bug.

Streaming files always record ``format_version: 12`` in their metadata, but
encryption used to derive the key (and configure pepper and cascade) with the
CALLER'S format_version (library default 10; the CLI passes 9/10/11 depending
on XOR flags). Decryption re-derives everything from the metadata version
(12), producing a different key — the freshly written file failed
authentication and could not be decrypted: silent data loss.

The fix forces format_version=12 for the whole streaming encrypt path before
any version-dependent derivation, matching what decryption will reconstruct.
"""

import base64
import json
import os
import secrets
import tempfile
import unittest
from pathlib import Path

from openssl_encrypt.modules.crypt_core import decrypt_file, encrypt_file

PASSWORD = b"streaming-fv-regression-pw"

# Big enough to cross a tiny streaming threshold, small enough to be fast
DATA = secrets.token_bytes(50 * 1024)

# Fast KDF settings so the suite stays quick
FAST_HASH_CONFIG = {"sha256": 1, "pbkdf2_iterations": 0}


def _roundtrip(algorithm: str, fmt_version=None, cascade_names=None) -> dict:
    """Encrypt DATA with streaming forced on, decrypt it back, return metadata.

    Raises on decryption failure — exactly what the original bug produced.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        plain = os.path.join(tmpdir, "plain.bin")
        enc = os.path.join(tmpdir, "enc.bin")
        Path(plain).write_bytes(DATA)

        kwargs = dict(
            input_file=plain,
            output_file=enc,
            password=PASSWORD,
            hash_config=dict(FAST_HASH_CONFIG),
            quiet=True,
            chunk_size=1024,
            streaming_threshold=1024,
        )
        if cascade_names:
            kwargs.update(algorithm="cascade", cascade=True, cipher_names=cascade_names)
        else:
            kwargs.update(algorithm=algorithm)
        if fmt_version is not None:
            kwargs.update(format_version=fmt_version)

        assert encrypt_file(**kwargs)

        raw = Path(enc).read_bytes()
        metadata = json.loads(base64.b64decode(raw.split(b":", 1)[0]))

        decrypted = decrypt_file(input_file=enc, output_file=None, password=PASSWORD, quiet=True)
        if decrypted != DATA:
            raise AssertionError("decrypted content does not match original")
        return metadata


class TestStreamingFormatVersionRoundTrip(unittest.TestCase):
    """Streaming files must decrypt regardless of the caller's format_version."""

    def test_default_format_version(self):
        """Library default (10) — the original data-loss repro."""
        meta = _roundtrip("aes-gcm")
        self.assertEqual(meta["format_version"], 12)

    def test_format_version_9(self):
        """CLI default without XOR flags."""
        meta = _roundtrip("aes-gcm", fmt_version=9)
        self.assertEqual(meta["format_version"], 12)

    def test_format_version_10(self):
        """CLI --use-xor-composition."""
        meta = _roundtrip("chacha20-poly1305", fmt_version=10)
        self.assertEqual(meta["format_version"], 12)

    def test_format_version_11(self):
        """CLI --independent-xor (worked before only by coincidence)."""
        meta = _roundtrip("aes-gcm", fmt_version=11)
        self.assertEqual(meta["format_version"], 12)

    def test_format_version_12_explicit(self):
        meta = _roundtrip("aes-gcm", fmt_version=12)
        self.assertEqual(meta["format_version"], 12)

    def test_xchacha_default_format_version(self):
        meta = _roundtrip("xchacha20-poly1305")
        self.assertEqual(meta["format_version"], 12)


class TestStreamingCascadeFormatVersion(unittest.TestCase):
    """Cascade gates per-layer salts and AAD scope on format_version >= 12,
    so cascade+streaming was broken for EVERY caller version except 12."""

    CHAIN = ["aes-gcm", "chacha20-poly1305"]

    def test_cascade_default_format_version(self):
        meta = _roundtrip(None, cascade_names=self.CHAIN)
        self.assertEqual(meta["format_version"], 12)
        self.assertTrue(meta["encryption"]["cascade"])

    def test_cascade_format_version_11(self):
        """fv=11 coincides with v12 key derivation but NOT with cascade
        per-layer salts — this was broken even at fv=11."""
        meta = _roundtrip(None, fmt_version=11, cascade_names=self.CHAIN)
        self.assertEqual(meta["format_version"], 12)

    def test_cascade_format_version_9(self):
        meta = _roundtrip(None, fmt_version=9, cascade_names=self.CHAIN)
        self.assertEqual(meta["format_version"], 12)


class TestOneShotUnaffected(unittest.TestCase):
    """The forced version applies ONLY to streaming; one-shot files must keep
    the caller's format_version and its derivation semantics."""

    def _oneshot(self, fmt_version=None) -> dict:
        small = b"one-shot payload, stays below any streaming threshold"
        kwargs = dict(
            input_file=small,
            output_file=None,
            password=PASSWORD,
            hash_config=dict(FAST_HASH_CONFIG),
            quiet=True,
        )
        if fmt_version is not None:
            kwargs.update(format_version=fmt_version)
        encrypted = encrypt_file(**kwargs)
        metadata = json.loads(base64.b64decode(encrypted.split(b":", 1)[0]))

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(encrypted)
            path = f.name
        try:
            decrypted = decrypt_file(
                input_file=path, output_file=None, password=PASSWORD, quiet=True
            )
        finally:
            os.unlink(path)
        self.assertEqual(decrypted, small)
        return metadata

    def test_oneshot_keeps_default_version(self):
        meta = self._oneshot()
        self.assertNotEqual(meta["format_version"], 12)

    def test_oneshot_keeps_explicit_version(self):
        for v in (9, 10, 11):
            meta = self._oneshot(fmt_version=v)
            self.assertEqual(meta["format_version"], v, f"fv={v} not preserved")

    def test_no_streaming_flag_keeps_version(self):
        """--no-streaming forces one-shot even for large files; the caller's
        format_version must survive."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plain = os.path.join(tmpdir, "plain.bin")
            enc = os.path.join(tmpdir, "enc.bin")
            Path(plain).write_bytes(DATA)
            self.assertTrue(
                encrypt_file(
                    input_file=plain,
                    output_file=enc,
                    password=PASSWORD,
                    hash_config=dict(FAST_HASH_CONFIG),
                    quiet=True,
                    format_version=10,
                    chunk_size=1024,
                    streaming_threshold=1024,
                    no_streaming=True,
                )
            )
            raw = Path(enc).read_bytes()
            meta = json.loads(base64.b64decode(raw.split(b":", 1)[0]))
            self.assertEqual(meta["format_version"], 10)
            decrypted = decrypt_file(
                input_file=enc, output_file=None, password=PASSWORD, quiet=True
            )
            self.assertEqual(decrypted, DATA)


if __name__ == "__main__":
    unittest.main()
