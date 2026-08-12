#!/usr/bin/env python3
"""
The USB drive key must actually be wipeable, and wiped on every path
(gitlab#201).

Every `secure_memzero` call on this path was a no-op whose return value was
discarded. `PBKDF2HMAC.derive()`, `multi_hash_password` and the
`sha256(...).digest()` normalisation all return immutable `bytes`, and
`secure_memzero` refuses immutable input and returns False without touching
the caller's buffer -- the documented M10 contract. So the AES-256 key
protecting a keystore and integrity manifest *on removable media* stayed
resident for the process lifetime while the code read as if it had been
wiped.

`verify_usb_integrity` also wiped on the success path only: a bare
`except: raise` with no `finally`, so the overwhelmingly common failure --
wrong password, or an actually tampered drive -- left key and password
resident. Its sibling `create_portable_usb` already had the `try/finally`
this one was missing.

These tests assert on the *type* and on the `secure_memzero` return rather
than trying to inspect freed memory: the contract is "held in a mutable
buffer so it can be wiped", and that is exactly what regressed.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from openssl_encrypt.modules.portable_media.usb_creator import USBDriveCreator
from openssl_encrypt.modules.secure_memory import SecureBytes, secure_memzero


class TestTheDerivedKeyIsWipeable(unittest.TestCase):
    def setUp(self):
        self.creator = USBDriveCreator()

    def test_the_pbkdf2_fallback_returns_a_mutable_buffer(self):
        key = self.creator._derive_key_pbkdf2_fallback(SecureBytes(b"pw"), b"x" * 16)
        self.assertIsInstance(
            key,
            bytearray,
            "the drive key is immutable, so secure_memzero cannot wipe it",
        )

    def test_the_main_derivation_returns_a_mutable_buffer(self):
        for config in (None, {"sha256": 10}, {"pbkdf2_iterations": 1000}):
            with self.subTest(config=config):
                key = self.creator._derive_encryption_key(SecureBytes(b"pw"), config, b"x" * 16)
                self.assertIsInstance(key, bytearray)

    def test_wiping_the_derived_key_actually_reports_success(self):
        """The bug in one line: secure_memzero returned False and the caller
        discarded it, so the code read as if the key were gone."""
        key = self.creator._derive_encryption_key(SecureBytes(b"pw"), None, b"x" * 16)
        self.assertTrue(
            secure_memzero(key),
            "secure_memzero refused the drive key; it is not held in a wipeable buffer",
        )
        self.assertEqual(bytes(key), b"\x00" * len(key))

    def test_the_key_is_still_the_right_length_and_usable(self):
        """A type change must not change the key.

        Both arms matter: AESGCM has to accept the buffer, and the derived
        value has to be unchanged, or existing drives stop verifying.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key = self.creator._derive_encryption_key(SecureBytes(b"pw"), None, b"x" * 16)
        self.assertEqual(len(key), self.creator.KEY_LENGTH)

        aead = AESGCM(bytes(key))
        nonce = b"n" * 12
        self.assertEqual(aead.decrypt(nonce, aead.encrypt(nonce, b"data", None), None), b"data")

    def test_the_derived_value_is_unchanged(self):
        """Golden-ish: the same password/salt must derive the same key as
        before, or every existing drive becomes unverifiable."""
        import hashlib

        expected = hashlib.pbkdf2_hmac("sha256", b"pw", b"x" * 16, 100_000, dklen=32)
        key = self.creator._derive_key_pbkdf2_fallback(SecureBytes(b"pw"), b"x" * 16)
        self.assertEqual(bytes(key), expected)


class TestTheFailurePathWipesToo(unittest.TestCase):
    """The load-bearing half: a wrong password is the common case."""

    def setUp(self):
        self.creator = USBDriveCreator()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_a_failed_verification_still_wipes_the_key(self):
        """Captures the key the code derived, then asserts it was zeroed
        after the call raised. Patching the derivation is the only way to
        get a reference to a local that the function is supposed to destroy.
        """
        from unittest import mock

        captured = []
        real_derive = self.creator._derive_encryption_key

        def capturing(password, hash_config, salt):
            key = real_derive(password, hash_config, salt)
            captured.append(key)
            return key

        (self.tmp / self.creator.PORTABLE_DIR).mkdir(parents=True, exist_ok=True)

        with mock.patch.object(self.creator, "_derive_encryption_key", capturing):
            with self.assertRaises(Exception):
                self.creator.verify_usb_integrity(str(self.tmp), "wrong-password")

        self.assertTrue(captured, "the derivation never ran; this test proves nothing")
        self.assertEqual(
            bytes(captured[0]),
            b"\x00" * len(captured[0]),
            "a failed verification left the drive key in memory",
        )


if __name__ == "__main__":
    unittest.main()
