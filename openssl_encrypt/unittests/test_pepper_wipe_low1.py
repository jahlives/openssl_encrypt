#!/usr/bin/env python3
"""Regression tests for gitlab#113 (fable-review LOW-1): pepper material wipe.

The v14 TLV KDF seed is wiped in a ``finally`` block, but the pepper
material feeding it must be held to the same standard: the remote pepper
(AES-GCM decrypt output) and the combined HSM+remote pepper must live in
wipeable ``bytearray`` buffers and be zeroed in place before
``encrypt_file``/``decrypt_file`` return — on the encrypt AND decrypt
paths. Immutable transients that cannot be avoided (plugin-API ``bytes``,
``AESGCM.decrypt`` output) are documented accepted residuals (M10);
every buffer we allocate ourselves must be wiped in place.
"""

import os
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from openssl_encrypt.modules import crypt_core
from openssl_encrypt.modules.crypt_core import decrypt_file, encrypt_file

TEST_PASSWORD = b"pepper-wipe-low1-password"
BASIC_HASH_CONFIG = {"sha256": 10, "pbkdf2_iterations": 1000}
HSM_PEPPER = b"H" * 20  # plugin-API bytes, 16 <= len <= 128
REMOTE_PEPPER = b"R" * 32
PEPPER_NAME = "low1-test-pepper"


def _encrypted_pepper_blob() -> bytes:
    """Encrypt REMOTE_PEPPER the way the remote pepper store holds it."""
    key = crypt_core._derive_pepper_key(TEST_PASSWORD, format_version=14)
    nonce = b"\x00" * 12
    return nonce + AESGCM(bytes(key)).encrypt(nonce, REMOTE_PEPPER, None)


def _fake_hsm_plugin() -> mock.MagicMock:
    plugin = mock.MagicMock()
    plugin.plugin_id = "fake_hsm"
    plugin.name = "fake_hsm"
    plugin.get_hsm_pepper.return_value = SimpleNamespace(
        success=True, data={"hsm_pepper": HSM_PEPPER, "slot": None}, message=""
    )
    return plugin


class _WipeRecorder:
    """Wrap crypt_core.secure_memzero, recording pre-wipe content and result."""

    def __init__(self):
        self.calls = []
        self._real = crypt_core.secure_memzero

    def __call__(self, data, *args, **kwargs):
        try:
            snapshot = bytes(data)
        except (TypeError, ValueError):
            snapshot = None
        result = self._real(data, *args, **kwargs)
        self.calls.append((snapshot, result))
        return result

    def wiped_in_place(self, content: bytes) -> bool:
        """True if a buffer holding `content` was zeroed in the caller's storage."""
        return any(snap == content and result for snap, result in self.calls)


class TestCombinePeppers(unittest.TestCase):
    """_combine_peppers must return a fresh wipeable buffer, never an alias."""

    def test_both_peppers(self):
        combined = crypt_core._combine_peppers(HSM_PEPPER, bytearray(REMOTE_PEPPER))
        self.assertIsInstance(combined, bytearray)
        self.assertEqual(bytes(combined), HSM_PEPPER + REMOTE_PEPPER)

    def test_hsm_only_is_a_fresh_copy(self):
        hsm = bytearray(HSM_PEPPER)
        combined = crypt_core._combine_peppers(hsm, None)
        self.assertIsInstance(combined, bytearray)
        self.assertEqual(bytes(combined), HSM_PEPPER)
        self.assertIsNot(combined, hsm)

    def test_remote_only_is_a_fresh_copy(self):
        remote = bytearray(REMOTE_PEPPER)
        combined = crypt_core._combine_peppers(None, remote)
        self.assertIsInstance(combined, bytearray)
        self.assertEqual(bytes(combined), REMOTE_PEPPER)
        self.assertIsNot(combined, remote)

    def test_neither_pepper(self):
        self.assertIsNone(crypt_core._combine_peppers(None, None))
        self.assertIsNone(crypt_core._combine_peppers(b"", None))


class TestPepperWipeRoundTrip(unittest.TestCase):
    """encrypt_file/decrypt_file must zero remote and combined pepper buffers."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.plain = os.path.join(self.tmp, "in.txt")
        self.enc = os.path.join(self.tmp, "in.txt.enc")
        self.dec = os.path.join(self.tmp, "out.txt")
        with open(self.plain, "wb") as f:
            f.write(b"pepper wipe regression payload")
        self.pepper_blob = _encrypted_pepper_blob()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _encrypt(self):
        pepper_plugin = mock.MagicMock()
        pepper_plugin.get_pepper.return_value = self.pepper_blob
        encrypt_file(
            input_file=self.plain,
            output_file=self.enc,
            password=TEST_PASSWORD,
            hash_config=dict(BASIC_HASH_CONFIG),
            quiet=True,
            hsm_plugin=_fake_hsm_plugin(),
            pepper_plugin=pepper_plugin,
            pepper_name=PEPPER_NAME,
            format_version=14,
        )

    def test_encrypt_wipes_remote_and_combined_pepper(self):
        recorder = _WipeRecorder()
        with mock.patch.object(crypt_core, "secure_memzero", recorder):
            self._encrypt()
        self.assertTrue(
            recorder.wiped_in_place(REMOTE_PEPPER),
            "remote pepper was not zeroed in place on the encrypt path",
        )
        self.assertTrue(
            recorder.wiped_in_place(HSM_PEPPER + REMOTE_PEPPER),
            "combined HSM+remote pepper was not zeroed in place on the encrypt path",
        )

    def test_decrypt_wipes_remote_and_combined_pepper(self):
        self._encrypt()

        fake_config = SimpleNamespace(enabled=True)
        fake_plugin = mock.MagicMock()
        fake_plugin.get_pepper.return_value = self.pepper_blob

        recorder = _WipeRecorder()
        with mock.patch.object(crypt_core, "secure_memzero", recorder), mock.patch(
            "openssl_encrypt.plugins.pepper.PepperConfig"
        ) as config_cls, mock.patch(
            "openssl_encrypt.plugins.pepper.PepperPlugin", return_value=fake_plugin
        ):
            config_cls.from_file.return_value = fake_config
            decrypt_file(
                input_file=self.enc,
                output_file=self.dec,
                password=TEST_PASSWORD,
                quiet=True,
                hsm_plugin=_fake_hsm_plugin(),
            )

        with open(self.dec, "rb") as f:
            self.assertEqual(f.read(), b"pepper wipe regression payload")
        self.assertTrue(
            recorder.wiped_in_place(REMOTE_PEPPER),
            "remote pepper was not zeroed in place on the decrypt path",
        )
        self.assertTrue(
            recorder.wiped_in_place(HSM_PEPPER + REMOTE_PEPPER),
            "combined HSM+remote pepper was not zeroed in place on the decrypt path",
        )

    def test_encrypt_wipes_peppers_on_exception_after_key_generation(self):
        """A failure after pepper use must still zero all pepper buffers."""
        recorder = _WipeRecorder()
        with mock.patch.object(crypt_core, "secure_memzero", recorder), mock.patch.object(
            crypt_core,
            "generate_key_independent_xor",
            side_effect=RuntimeError("injected KDF failure"),
        ):
            with self.assertRaises(Exception):
                self._encrypt()
        self.assertTrue(
            recorder.wiped_in_place(REMOTE_PEPPER),
            "remote pepper leaked on the encrypt exception path",
        )
        self.assertTrue(
            recorder.wiped_in_place(HSM_PEPPER + REMOTE_PEPPER),
            "combined pepper leaked on the encrypt exception path",
        )

    def test_decrypt_wipes_peppers_on_exception_after_key_generation(self):
        """A decrypt-side failure after pepper use must still zero the buffers."""
        self._encrypt()

        fake_config = SimpleNamespace(enabled=True)
        fake_plugin = mock.MagicMock()
        fake_plugin.get_pepper.return_value = self.pepper_blob

        recorder = _WipeRecorder()
        with mock.patch.object(crypt_core, "secure_memzero", recorder), mock.patch(
            "openssl_encrypt.plugins.pepper.PepperConfig"
        ) as config_cls, mock.patch(
            "openssl_encrypt.plugins.pepper.PepperPlugin", return_value=fake_plugin
        ), mock.patch.object(
            crypt_core,
            "generate_key_independent_xor",
            side_effect=RuntimeError("injected KDF failure"),
        ):
            config_cls.from_file.return_value = fake_config
            with self.assertRaises(Exception):
                decrypt_file(
                    input_file=self.enc,
                    output_file=self.dec,
                    password=TEST_PASSWORD,
                    quiet=True,
                    hsm_plugin=_fake_hsm_plugin(),
                )
        self.assertTrue(
            recorder.wiped_in_place(REMOTE_PEPPER),
            "remote pepper leaked on the decrypt exception path",
        )
        self.assertTrue(
            recorder.wiped_in_place(HSM_PEPPER + REMOTE_PEPPER),
            "combined pepper leaked on the decrypt exception path",
        )


if __name__ == "__main__":
    unittest.main()
