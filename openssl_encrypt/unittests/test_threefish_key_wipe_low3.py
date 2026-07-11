#!/usr/bin/env python3
"""Regression tests for gitlab#115 (fable-review LOW-3): Threefish key wipe.

The native PQC Threefish branches (``PQCipher.encrypt`` /
``PQCipher._decrypt_impl``) derived the actual 64/128-byte Threefish
data-encryption key via HKDF as plain immutable ``bytes``, never wiped
it, and returned before the AEAD block's SecureBytes handling. The
adapter *decrypt* path was already upgraded (SecureBytes + finally
wipe); the native encrypt/decrypt paths and the adapter *encrypt*
threefish branch must follow the same pattern: the expanded key is held
in a wipeable buffer and zeroized in place on success and exception
paths (HKDF's immutable output is the documented M10 accepted
residual).

Each test spies on the threefish_native call to capture the exact key
bytes used, and asserts a recording secure_memzero wrapper saw that
content zeroed in the caller's own storage.
"""

import unittest
from unittest import mock

from openssl_encrypt.modules import pqc, pqc_adapter
from openssl_encrypt.modules.pqc import LIBOQS_AVAILABLE, PQCipher
from openssl_encrypt.modules.pqc_adapter import ExtendedPQCipher

try:
    import threefish_native

    THREEFISH_AVAILABLE = True
except ImportError:
    THREEFISH_AVAILABLE = False


class _WipeRecorder:
    """Wrap a module's secure_memzero, recording pre-wipe content and result."""

    def __init__(self, module):
        self.calls = []
        self._real = module.secure_memzero

    def __call__(self, data, *args, **kwargs):
        try:
            snapshot = bytes(data)
        except (TypeError, ValueError):
            snapshot = None
        result = self._real(data, *args, **kwargs)
        self.calls.append((snapshot, result))
        return result

    def wiped_in_place(self, content: bytes) -> bool:
        return any(snap == content and result for snap, result in self.calls)


class _ThreefishSpy:
    """Capture the key passed to a threefish_native function, then call it."""

    def __init__(self, real):
        self._real = real
        self.key = None

    def __call__(self, key, nonce, data, aad):
        self.key = bytes(key)
        return self._real(key, nonce, data, aad)


@unittest.skipUnless(
    LIBOQS_AVAILABLE and THREEFISH_AVAILABLE, "liboqs or threefish_native not available"
)
class TestNativeThreefishExpandedKeyWipe(unittest.TestCase):
    """PQCipher threefish branches must zero the expanded key in place."""

    def setUp(self):
        self.cipher = PQCipher(
            "ML-KEM-768", quiet=True, encryption_data="threefish-512", format_version=14
        )
        self.public_key, self.private_key = self.cipher.generate_keypair()

    def test_encrypt_wipes_expanded_key(self):
        spy = _ThreefishSpy(threefish_native.encrypt_512)
        recorder = _WipeRecorder(pqc)
        with mock.patch.object(threefish_native, "encrypt_512", spy), mock.patch.object(
            pqc, "secure_memzero", recorder
        ):
            self.cipher.encrypt(b"threefish key wipe probe", self.public_key)
        self.assertIsNotNone(spy.key, "threefish encrypt path was not exercised")
        self.assertEqual(len(spy.key), 64)
        self.assertTrue(
            recorder.wiped_in_place(spy.key),
            "expanded Threefish key was not zeroed in place on the encrypt path",
        )

    def test_decrypt_wipes_expanded_key(self):
        encrypted = self.cipher.encrypt(b"threefish key wipe probe", self.public_key)
        spy = _ThreefishSpy(threefish_native.decrypt_512)
        recorder = _WipeRecorder(pqc)
        with mock.patch.object(threefish_native, "decrypt_512", spy), mock.patch.object(
            pqc, "secure_memzero", recorder
        ):
            plaintext = self.cipher.decrypt(encrypted, self.private_key)
        self.assertEqual(plaintext, b"threefish key wipe probe")
        self.assertIsNotNone(spy.key, "threefish decrypt path was not exercised")
        self.assertEqual(len(spy.key), 64)
        self.assertTrue(
            recorder.wiped_in_place(spy.key),
            "expanded Threefish key was not zeroed in place on the decrypt path",
        )

    def test_decrypt_wipes_expanded_key_on_exception(self):
        """The wipe must also run when the threefish call itself fails."""
        encrypted = self.cipher.encrypt(b"threefish key wipe probe", self.public_key)

        captured = {}

        def failing(key, nonce, data, aad):
            captured["key"] = bytes(key)
            raise ValueError("injected threefish failure")

        recorder = _WipeRecorder(pqc)
        with mock.patch.object(threefish_native, "decrypt_512", failing), mock.patch.object(
            pqc, "secure_memzero", recorder
        ):
            with self.assertRaises(Exception):
                self.cipher.decrypt(encrypted, self.private_key)
        self.assertIn("key", captured)
        self.assertTrue(
            recorder.wiped_in_place(captured["key"]),
            "expanded Threefish key leaked on the decrypt exception path",
        )


@unittest.skipUnless(
    LIBOQS_AVAILABLE and THREEFISH_AVAILABLE, "liboqs or threefish_native not available"
)
class TestAdapterThreefishEncryptKeyWipe(unittest.TestCase):
    """The adapter's liboqs encrypt threefish branch must wipe like its decrypt."""

    def setUp(self):
        from openssl_encrypt.modules.pqc import check_pqc_support

        supported = check_pqc_support(quiet=True)[2]
        self.hqc = next((a for a in ("HQC-128", "HQC-192", "HQC-256") if a in supported), None)
        if self.hqc is None:
            self.skipTest("no HQC algorithm available for the liboqs adapter branch")

    def test_adapter_encrypt_wipes_expanded_key(self):
        cipher = ExtendedPQCipher(
            self.hqc, quiet=True, encryption_data="threefish-512", format_version=14
        )
        public_key, _ = cipher.generate_keypair()
        spy = _ThreefishSpy(threefish_native.encrypt_512)
        recorder = _WipeRecorder(pqc_adapter)
        with mock.patch.object(threefish_native, "encrypt_512", spy), mock.patch.object(
            pqc_adapter, "secure_memzero", recorder
        ):
            cipher.encrypt(b"adapter threefish key wipe probe", public_key)
        self.assertIsNotNone(spy.key, "adapter threefish encrypt path was not exercised")
        self.assertEqual(len(spy.key), 64)
        self.assertTrue(
            recorder.wiped_in_place(spy.key),
            "expanded Threefish key was not zeroed in place on the adapter encrypt path",
        )


if __name__ == "__main__":
    unittest.main()
