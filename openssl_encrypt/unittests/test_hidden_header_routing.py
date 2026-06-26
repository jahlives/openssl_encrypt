#!/usr/bin/env python3
"""
Tests for to_legacy_bytes(), the shared shim that lets format-parsing call
sites transparently handle hidden ("whitened") files.

It returns the reconstructed legacy ``base64(meta):base64(body)`` bytes for a
hidden file it can peel (keyless always; keyed with the right second password),
and returns the input unchanged otherwise (legacy files, or keyed files without
the password -- which then simply read as "not our format"). All code in
English as per project requirements.
"""

import base64
import json
import unittest

from openssl_encrypt.modules.hidden_header import to_legacy_bytes, wrap_hidden

SALT = bytes(range(16))
HEADER = json.dumps({"format_version": 10, "salt": "abc"}).encode("utf-8")
BODY = b"\x07\x08\x09" * 64
PW = b"routing-second-pw"

LEGACY = base64.b64encode(HEADER) + b":" + base64.b64encode(BODY)

FAST = __import__("openssl_encrypt.modules.hidden_header", fromlist=["KeyedProfile"]).KeyedProfile(
    sha3_iters=4,
    argon2_passes=2,
    argon2_time_cost=1,
    argon2_memory_kib=8,
    argon2_parallelism=1,
    scrypt_n=2,
    scrypt_r=1,
    scrypt_p=1,
)


class TestToLegacyBytes(unittest.TestCase):
    def test_legacy_passthrough(self):
        self.assertEqual(to_legacy_bytes(LEGACY), LEGACY)

    def test_short_random_passthrough(self):
        self.assertEqual(to_legacy_bytes(b"not-a-hidden-file"), b"not-a-hidden-file")

    def test_keyless_peeled_to_legacy(self):
        blob = wrap_hidden(HEADER, BODY, SALT)
        out = to_legacy_bytes(blob)
        meta_b64, _, body_b64 = out.partition(b":")
        self.assertEqual(base64.b64decode(meta_b64), HEADER)
        self.assertEqual(base64.b64decode(body_b64), BODY)

    def test_keyed_peeled_with_password(self):
        blob = wrap_hidden(HEADER, BODY, SALT, second_password=PW, profile=FAST)
        out = to_legacy_bytes(blob, second_password=PW, profile=FAST)
        meta_b64, _, body_b64 = out.partition(b":")
        self.assertEqual(base64.b64decode(meta_b64), HEADER)

    def test_keyed_without_password_passthrough(self):
        # Cannot peel a keyed blob without the password -> returned unchanged,
        # so the caller treats it as "not our (legacy) format".
        blob = wrap_hidden(HEADER, BODY, SALT, second_password=PW, profile=FAST)
        self.assertEqual(to_legacy_bytes(blob), blob)


if __name__ == "__main__":
    unittest.main()
