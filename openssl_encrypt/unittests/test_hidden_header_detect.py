#!/usr/bin/env python3
"""
Unit tests for hidden-vs-legacy file-format detection.

With keyless hidden mode as the default, decryption must reliably tell a
legacy ``base64(meta):base64(body)`` file from a hidden raw-binary file
*without* any magic bytes (which would re-introduce a fingerprint). Legacy
files are recognized by their structure (base64 metadata that decodes to a
JSON object, terminated by a colon); everything else of sufficient length is
treated as hidden. Misdetection is non-destructive: it yields a decryption
error the user can override with an explicit flag.

All code in English as per project requirements.
"""

import base64
import json
import os
import unittest

from openssl_encrypt.modules.crypt_errors import ValidationError
from openssl_encrypt.modules.hidden_header import (
    is_hidden_format,
    looks_like_legacy,
    wrap_hidden,
)

SALT = bytes(range(16))


def _legacy_blob(metadata: dict, body: bytes = b"payload-bytes") -> bytes:
    meta_b64 = base64.b64encode(json.dumps(metadata).encode("utf-8"))
    body_b64 = base64.b64encode(body)
    return meta_b64 + b":" + body_b64


class TestLegacyDetection(unittest.TestCase):
    def test_real_legacy_blob_is_legacy(self):
        blob = _legacy_blob({"format_version": 10, "salt": "abc", "kdf": "argon2"})
        self.assertTrue(looks_like_legacy(blob))
        self.assertFalse(is_hidden_format(blob))

    def test_legacy_with_large_metadata(self):
        blob = _legacy_blob({"format_version": 12, "pad": "x" * 50000})
        self.assertTrue(looks_like_legacy(blob))
        self.assertFalse(is_hidden_format(blob))


class TestHiddenDetection(unittest.TestCase):
    def test_keyless_wrap_is_hidden(self):
        blob = wrap_hidden(b'{"format_version": 10}', b"body" * 50, SALT)
        self.assertTrue(is_hidden_format(blob))
        self.assertFalse(looks_like_legacy(blob))

    def test_random_bytes_are_hidden(self):
        # Random data of sufficient length must not be mistaken for legacy.
        for _ in range(50):
            blob = os.urandom(200)
            self.assertFalse(looks_like_legacy(blob))
            self.assertTrue(is_hidden_format(blob))


class TestNegativeCases(unittest.TestCase):
    def test_no_colon_is_not_legacy(self):
        self.assertFalse(looks_like_legacy(base64.b64encode(b"x" * 100)))

    def test_non_base64_before_colon_is_not_legacy(self):
        self.assertFalse(looks_like_legacy(b"ab\x00cd:morestuff"))

    def test_base64_not_decoding_to_json_is_not_legacy(self):
        # base64("hello") + ":" -> decodes to b"hello", not a JSON object.
        blob = base64.b64encode(b"hello") + b":" + base64.b64encode(b"body")
        self.assertFalse(looks_like_legacy(blob))

    def test_too_short_is_not_hidden(self):
        # Below the minimum hidden-blob size, detection returns False (the
        # caller will surface a decryption error rather than mis-route).
        self.assertFalse(is_hidden_format(b"short"))

    def test_empty_is_not_hidden(self):
        self.assertFalse(is_hidden_format(b""))


class TestValidation(unittest.TestCase):
    def test_non_bytes_rejected(self):
        with self.assertRaises(ValidationError):
            is_hidden_format("not-bytes")
        with self.assertRaises(ValidationError):
            looks_like_legacy("not-bytes")


if __name__ == "__main__":
    unittest.main()
