#!/usr/bin/env python3
"""
Regression tests for M10: secure_memzero must not falsely report success.

Previously secure_memzero(bytes/str) copied the data into a bytearray, zeroed
the copy, and returned True ("verified zeroed") - while the caller's original
immutable secret stayed in memory untouched. That is a false sense of security
and contradicts the project rule "secure memory handling for sensitive data".

The honest contract:
- mutable buffers (bytearray, SecureBytes, writable memoryview) are wiped in
  place and return True;
- immutable inputs (bytes, str) cannot be wiped in place, so they return False
  (or raise in strict mode) instead of claiming success.

See SECURITY_REVIEW_FINDINGS.md (M10).
"""

import unittest

from openssl_encrypt.modules.secure_memory import SecureBytes, secure_memzero, verify_memory_zeroed


class TestSecureMemzeroHonesty(unittest.TestCase):
    def test_bytearray_wiped_in_place_returns_true(self):
        buf = bytearray(b"\x11" * 64)
        self.assertTrue(secure_memzero(buf))
        self.assertTrue(all(b == 0 for b in buf))
        self.assertTrue(verify_memory_zeroed(buf))

    def test_securebytes_wiped_in_place_returns_true(self):
        sb = SecureBytes(b"\x22" * 48)
        self.assertTrue(secure_memzero(sb))
        self.assertTrue(all(b == 0 for b in sb))

    def test_writable_memoryview_wiped_in_place_returns_true(self):
        backing = bytearray(b"\x33" * 32)
        mv = memoryview(backing)
        self.assertTrue(secure_memzero(mv))
        self.assertTrue(all(b == 0 for b in backing))

    def test_immutable_bytes_returns_false(self):
        """bytes cannot be wiped in place - must NOT report success."""
        secret = b"super-secret-key-material"
        self.assertFalse(secure_memzero(secret))
        # the caller's object is necessarily unchanged (bytes are immutable)
        self.assertEqual(secret, b"super-secret-key-material")

    def test_immutable_str_returns_false(self):
        self.assertFalse(secure_memzero("super-secret-password"))

    def test_strict_mode_raises_on_bytes(self):
        with self.assertRaises(TypeError):
            secure_memzero(b"secret", strict=True)

    def test_strict_mode_raises_on_str(self):
        with self.assertRaises(TypeError):
            secure_memzero("secret", strict=True)

    def test_strict_mode_allows_bytearray(self):
        buf = bytearray(b"\x44" * 16)
        self.assertTrue(secure_memzero(buf, strict=True))
        self.assertTrue(all(b == 0 for b in buf))

    def test_none_is_noop_true(self):
        self.assertTrue(secure_memzero(None))

    def test_readonly_memoryview_not_reported_success(self):
        """A readonly memoryview cannot be wiped - must not report success."""
        ro = memoryview(b"immutable")
        self.assertTrue(ro.readonly)
        self.assertFalse(secure_memzero(ro))


if __name__ == "__main__":
    unittest.main()
