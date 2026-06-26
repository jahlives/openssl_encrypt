#!/usr/bin/env python3
"""
Unit tests for the hidden-header wrap/unwrap primitives.

The hidden format wraps a (metadata header, raw body) pair into a raw-binary
container that is indistinguishable from random:

    salt(16) | nonce(24) | whitened_len(4) | header_region(L) | auth(16) | body

Both modes share the exact same layout so an observer cannot tell whether a
second password was used:

  * keyless  -- header_region is XChaCha20 keystream-whitened, auth is random
                decoy bytes (no tag -> no free "this is our file" oracle);
  * keyed    -- header_region is XChaCha20-Poly1305 ciphertext, auth is the
                real Poly1305 tag, AAD binds salt|nonce|whitened_len.

All code in English as per project requirements.
"""

import unittest

from openssl_encrypt.modules.crypt_errors import AuthenticationError, ValidationError
from openssl_encrypt.modules.hidden_header import (
    AUTH_LEN,
    HEADER_OFFSET,
    LEN_FIELD_LEN,
    NONCE_LEN,
    SALT_LEN,
    KeyedProfile,
    unwrap_hidden,
    wrap_hidden,
)

FAST_PROFILE = KeyedProfile(
    sha3_iters=4,
    argon2_passes=2,
    argon2_time_cost=1,
    argon2_memory_kib=8,
    argon2_parallelism=1,
    scrypt_n=2,
    scrypt_r=1,
    scrypt_p=1,
)

SALT = bytes(range(16))
HEADER = b'{"format_version": 10, "salt": "abc", "kdf": "argon2"}'
BODY = b"\x00\x11\x22" * 100
PW = b"second-password"


class TestKeylessWrap(unittest.TestCase):
    def test_round_trip(self):
        blob = wrap_hidden(HEADER, BODY, SALT)
        header, body = unwrap_hidden(blob)
        self.assertEqual(header, HEADER)
        self.assertEqual(body, BODY)

    def test_blob_starts_with_salt(self):
        blob = wrap_hidden(HEADER, BODY, SALT)
        self.assertEqual(blob[:SALT_LEN], SALT)

    def test_total_length_matches_layout(self):
        blob = wrap_hidden(HEADER, BODY, SALT)
        expected = SALT_LEN + NONCE_LEN + LEN_FIELD_LEN + len(HEADER) + AUTH_LEN + len(BODY)
        self.assertEqual(len(blob), expected)

    def test_nonce_randomized_between_calls(self):
        # Same inputs -> different blobs (random nonce), but both round-trip.
        b1 = wrap_hidden(HEADER, BODY, SALT)
        b2 = wrap_hidden(HEADER, BODY, SALT)
        self.assertNotEqual(b1, b2)
        self.assertEqual(unwrap_hidden(b1), unwrap_hidden(b2))

    def test_no_plaintext_header_in_blob(self):
        # The whitened region must not expose the cleartext metadata header.
        blob = wrap_hidden(HEADER, BODY, SALT)
        self.assertNotIn(HEADER, blob)

    def test_empty_header_and_body(self):
        blob = wrap_hidden(b"", b"", SALT)
        self.assertEqual(unwrap_hidden(blob), (b"", b""))


class TestKeyedWrap(unittest.TestCase):
    def test_round_trip(self):
        blob = wrap_hidden(HEADER, BODY, SALT, second_password=PW, profile=FAST_PROFILE)
        header, body = unwrap_hidden(blob, second_password=PW, profile=FAST_PROFILE)
        self.assertEqual(header, HEADER)
        self.assertEqual(body, BODY)

    def test_wrong_second_password_fails(self):
        blob = wrap_hidden(HEADER, BODY, SALT, second_password=PW, profile=FAST_PROFILE)
        with self.assertRaises(AuthenticationError):
            unwrap_hidden(blob, second_password=b"wrong", profile=FAST_PROFILE)

    def test_tampered_header_region_fails(self):
        blob = bytearray(wrap_hidden(HEADER, BODY, SALT, second_password=PW, profile=FAST_PROFILE))
        blob[HEADER_OFFSET] ^= 0x01
        with self.assertRaises(AuthenticationError):
            unwrap_hidden(bytes(blob), second_password=PW, profile=FAST_PROFILE)

    def test_tampered_auth_tag_fails(self):
        blob = bytearray(wrap_hidden(HEADER, BODY, SALT, second_password=PW, profile=FAST_PROFILE))
        tag_pos = HEADER_OFFSET + len(HEADER)  # first byte of the auth tag
        blob[tag_pos] ^= 0x01
        with self.assertRaises(AuthenticationError):
            unwrap_hidden(bytes(blob), second_password=PW, profile=FAST_PROFILE)

    def test_tampered_length_field_fails(self):
        # whitened_len is bound as AAD, so flipping it must fail authentication
        # (or be rejected as a corrupt boundary), never silently succeed.
        blob = bytearray(wrap_hidden(HEADER, BODY, SALT, second_password=PW, profile=FAST_PROFILE))
        blob[SALT_LEN + NONCE_LEN] ^= 0x01
        with self.assertRaises((AuthenticationError, ValidationError)):
            unwrap_hidden(bytes(blob), second_password=PW, profile=FAST_PROFILE)


class TestLayoutParity(unittest.TestCase):
    """Keyless and keyed blobs must be structurally identical in size."""

    def test_same_total_length(self):
        keyless = wrap_hidden(HEADER, BODY, SALT)
        keyed = wrap_hidden(HEADER, BODY, SALT, second_password=PW, profile=FAST_PROFILE)
        self.assertEqual(len(keyless), len(keyed))


class TestCrossMode(unittest.TestCase):
    """Opening a keyed blob in keyless mode yields garbage, not the header."""

    def test_keyless_unwrap_of_keyed_blob_does_not_return_header(self):
        blob = wrap_hidden(HEADER, BODY, SALT, second_password=PW, profile=FAST_PROFILE)
        # No password -> keyless path. The password-whitened length decodes to
        # garbage, so this almost always fails the consistency check; if it
        # happens to parse, the header must not be the real one. Either way the
        # real header is never recovered without the second password.
        try:
            header, _ = unwrap_hidden(blob)
            self.assertNotEqual(header, HEADER)
        except (ValidationError, AuthenticationError):
            pass


class TestValidation(unittest.TestCase):
    def test_wrong_salt_length_rejected(self):
        with self.assertRaises(ValidationError):
            wrap_hidden(HEADER, BODY, b"too-short")

    def test_non_bytes_header_rejected(self):
        with self.assertRaises(ValidationError):
            wrap_hidden("not-bytes", BODY, SALT)

    def test_non_bytes_body_rejected(self):
        with self.assertRaises(ValidationError):
            wrap_hidden(HEADER, "not-bytes", SALT)

    def test_truncated_blob_rejected(self):
        with self.assertRaises(ValidationError):
            unwrap_hidden(b"too-short")

    def test_inconsistent_length_field_rejected(self):
        # A declared header length larger than the available bytes is corrupt.
        blob = bytearray(wrap_hidden(HEADER, BODY, SALT))
        # Truncate so the declared L no longer fits.
        with self.assertRaises(ValidationError):
            unwrap_hidden(bytes(blob[: HEADER_OFFSET + 2]))


if __name__ == "__main__":
    unittest.main()
