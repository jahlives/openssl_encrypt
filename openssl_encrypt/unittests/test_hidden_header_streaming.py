#!/usr/bin/env python3
"""
Streaming + raw-body integration tests for the hidden-header format.

Large files take the streaming path (format v12). The hidden format frames
only the metadata header (whitened); the chunked body is written/read raw at
a known offset, so streaming memory behavior is preserved. These tests force
a tiny streaming threshold so modest files exercise the streaming path.

All code in English as per project requirements.
"""

import base64
import json
import os
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import decrypt_file, encrypt_file
from openssl_encrypt.modules.crypt_errors import AuthenticationError
from openssl_encrypt.modules.hidden_header import is_hidden_format, read_hidden_header

MINIMAL_CONFIG = {
    "sha512": 10,
    "argon2": {
        "enabled": True,
        "time_cost": 1,
        "memory_cost": 512,
        "parallelism": 1,
        "type": "id",
    },
}

PASSWORD = "primary-password"
SECOND_PW = "second-password"
# Large enough to span several chunks with a small threshold/chunk size.
PLAINTEXT = os.urandom(300_000)
SMALL_THRESHOLD = 50_000
SMALL_CHUNK = 16_384


class _Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.src = os.path.join(self.dir, "plain.bin")
        with open(self.src, "wb") as f:
            f.write(PLAINTEXT)
        self.enc = os.path.join(self.dir, "out.enc")
        self.dec = os.path.join(self.dir, "out.dec")

    def tearDown(self):
        import shutil

        shutil.rmtree(self.dir, ignore_errors=True)

    def _encrypt(self, **kw):
        encrypt_file(
            self.src,
            self.enc,
            PASSWORD,
            hash_config=MINIMAL_CONFIG,
            quiet=True,
            algorithm="aes-gcm",
            streaming_threshold=SMALL_THRESHOLD,
            chunk_size=SMALL_CHUNK,
            **kw,
        )

    def _assert_legacy_streaming_file(self):
        with open(self.enc, "rb") as f:
            head = f.read(1 << 16)
        meta = json.loads(base64.b64decode(head.split(b":", 1)[0]))
        self.assertIn(meta["format_version"], (12, 14))
        self.assertTrue(meta.get("streaming", {}).get("enabled", False))

    def _assert_hidden_streaming_file(self, second_password=None):
        # extract_file_metadata is hidden-aware only after the parse-site
        # routing increment; here we peel the header directly to confirm the
        # file is a streaming v12 file wrapped in the hidden format.
        with open(self.enc, "rb") as f:
            self.assertTrue(is_hidden_format(f.read()))
        with open(self.enc, "rb") as f:
            header_bytes, body_offset = read_hidden_header(f, second_password=second_password)
        meta = json.loads(header_bytes)
        self.assertIn(meta["format_version"], (12, 14))
        self.assertTrue(meta.get("streaming", {}).get("enabled", False))
        self.assertGreater(body_offset, 44)

    def _decrypted(self):
        with open(self.dec, "rb") as f:
            return f.read()


class TestKeylessStreaming(_Base):
    def test_round_trip(self):
        self._encrypt(hidden_header=True)
        self._assert_hidden_streaming_file()
        decrypt_file(self.enc, self.dec, PASSWORD, quiet=True)
        self.assertEqual(self._decrypted(), PLAINTEXT)

    def test_header_peels_to_streaming_metadata(self):
        self._encrypt(hidden_header=True)
        with open(self.enc, "rb") as f:
            header_bytes, body_offset = read_hidden_header(f)
        self.assertIn(b'"streaming"', header_bytes)
        self.assertGreater(body_offset, 44)


class TestKeyedStreaming(_Base):
    def test_round_trip_with_second_password(self):
        self._encrypt(hidden_header=True, second_password=SECOND_PW)
        self._assert_hidden_streaming_file(second_password=SECOND_PW.encode())
        decrypt_file(self.enc, self.dec, PASSWORD, quiet=True, second_password=SECOND_PW)
        self.assertEqual(self._decrypted(), PLAINTEXT)

    def test_wrong_second_password_fails(self):
        self._encrypt(hidden_header=True, second_password=SECOND_PW)
        with self.assertRaises((AuthenticationError, ValueError)):
            decrypt_file(self.enc, self.dec, PASSWORD, quiet=True, second_password="nope")


class TestLegacyStreamingStillWorks(_Base):
    def test_legacy_streaming_round_trip(self):
        self._encrypt()  # no hidden_header -> legacy streaming
        self._assert_legacy_streaming_file()
        decrypt_file(self.enc, self.dec, PASSWORD, quiet=True)
        self.assertEqual(self._decrypted(), PLAINTEXT)


if __name__ == "__main__":
    unittest.main()
