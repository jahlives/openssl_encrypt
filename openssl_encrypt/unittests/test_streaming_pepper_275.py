#!/usr/bin/env python3
"""Regression tests for gitlab#275: streaming dropped the pepper/HSM metadata.

The streaming encrypt path built its metadata without the plugin reference
fields the non-streaming call sites pass (`pepper_plugin_name`, `pepper_name`,
`hsm_plugin_name`, `hsm_slot_used`, `keystore_id`) — so a file above the
streaming threshold encrypted with a remote pepper carried NO pepper reference,
decrypt never fetched the pepper, and the file was silently undecryptable with
the correct password. The header must now carry the same plugin metadata as
non-streamed files (including `pepper_wrap_version`, gitlab#274), making
streamed pepper/HSM files round-trip.
"""

import base64
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from openssl_encrypt.modules import crypt_core
from openssl_encrypt.modules.crypt_core import (
    _PEPPER_WRAP_V2_MAGIC,
    EncryptionAlgorithm,
    _wrap_remote_pepper,
    decrypt_file,
    encrypt_file,
)

TEST_PASSWORD = b"streaming-pepper-275-password"
BASIC_HASH_CONFIG = {"sha256": 10, "pbkdf2_iterations": 1000}
REMOTE_PEPPER = b"R" * 32
PEPPER_NAME = "stream-275-pepper"
HSM_PEPPER = b"H" * 20
STREAM_THRESHOLD = 1024 * 1024  # 1 MB
PAYLOAD_SIZE = 2 * 1024 * 1024  # 2 MB -> definitely streams


def _v2_blob() -> bytes:
    return _wrap_remote_pepper(TEST_PASSWORD, REMOTE_PEPPER, PEPPER_NAME)


def _legacy_blob() -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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


class TestStreamingPepperMetadata(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="stream275-")
        self.plain = os.path.join(self.tmp, "big.bin")
        self.enc = os.path.join(self.tmp, "big.bin.enc")
        self.dec = os.path.join(self.tmp, "big.bin.dec")
        self.payload = os.urandom(PAYLOAD_SIZE)
        with open(self.plain, "wb") as f:
            f.write(self.payload)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _encrypt(self, pepper_plugin=None, hsm_plugin=None, blob=None):
        if pepper_plugin is None and blob is not None:
            pepper_plugin = mock.MagicMock()
            pepper_plugin.get_pepper.return_value = blob
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            encrypt_file(
                input_file=self.plain,
                output_file=self.enc,
                password=TEST_PASSWORD,
                hash_config=dict(BASIC_HASH_CONFIG),
                quiet=True,
                algorithm=EncryptionAlgorithm.AES_GCM,
                streaming_threshold=STREAM_THRESHOLD,
                pepper_plugin=pepper_plugin,
                pepper_name=PEPPER_NAME if pepper_plugin is not None else None,
                hsm_plugin=hsm_plugin,
            )
        return pepper_plugin, err.getvalue()

    def _metadata(self):
        with open(self.enc, "rb") as f:
            metadata_b64 = f.read().split(b":", 1)[0]
        return json.loads(base64.b64decode(metadata_b64))

    def _decrypt(self, blob=None, hsm_plugin=None):
        fake_config = SimpleNamespace(enabled=True)
        fake_plugin = mock.MagicMock()
        if blob is not None:
            fake_plugin.get_pepper.return_value = blob
        err = io.StringIO()
        with contextlib.redirect_stderr(err), mock.patch(
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
                hsm_plugin=hsm_plugin,
            )

    def test_streamed_file_records_pepper_metadata(self):
        self._encrypt(blob=_v2_blob())
        md = self._metadata()
        self.assertTrue(md.get("streaming", {}).get("enabled"), "test must exercise streaming")
        enc = md.get("encryption", {})
        self.assertEqual(enc.get("pepper_plugin"), "remote")
        self.assertEqual(enc.get("pepper_name"), PEPPER_NAME)
        self.assertEqual(enc.get("pepper_wrap_version"), 2)

    def test_streamed_pepper_file_roundtrips(self):
        self._encrypt(blob=_v2_blob())
        self._decrypt(blob=_v2_blob())
        with open(self.dec, "rb") as f:
            self.assertEqual(f.read(), self.payload)

    def test_streamed_legacy_pepper_is_resealed_and_roundtrips(self):
        plugin, _ = self._encrypt(blob=_legacy_blob())
        plugin.update_pepper.assert_called_once()
        pushed = plugin.update_pepper.call_args.kwargs["pepper_encrypted"]
        self.assertTrue(pushed.startswith(_PEPPER_WRAP_V2_MAGIC))
        self.assertEqual(self._metadata().get("encryption", {}).get("pepper_wrap_version"), 2)
        # The server now holds the re-sealed v2 blob; decrypt against it.
        self._decrypt(blob=pushed)
        with open(self.dec, "rb") as f:
            self.assertEqual(f.read(), self.payload)

    def test_streamed_hsm_file_records_hsm_metadata_and_roundtrips(self):
        self._encrypt(hsm_plugin=_fake_hsm_plugin())
        md = self._metadata()
        self.assertTrue(md.get("streaming", {}).get("enabled"))
        self.assertEqual(md.get("encryption", {}).get("hsm_plugin"), "fake_hsm")
        self._decrypt(hsm_plugin=_fake_hsm_plugin())
        with open(self.dec, "rb") as f:
            self.assertEqual(f.read(), self.payload)

    def test_wrong_pepper_fails_chunk_authentication(self):
        """The pepper must actually be bound into the KDF, not just recorded:
        decrypting with a v2 blob wrapping a DIFFERENT pepper must fail."""
        self._encrypt(blob=_v2_blob())
        wrong = _wrap_remote_pepper(TEST_PASSWORD, b"X" * 32, PEPPER_NAME)
        with self.assertRaises(Exception):
            self._decrypt(blob=wrong)
        self.assertFalse(os.path.exists(self.dec) and open(self.dec, "rb").read() == self.payload)

    def test_streamed_envelope_pepper_roundtrips(self):
        """Envelope-streamed files bind envelope_aad(metadata) instead of the
        raw header bytes — the pepper fields must be covered there too."""
        pepper_plugin = mock.MagicMock()
        pepper_plugin.get_pepper.return_value = _v2_blob()
        with contextlib.redirect_stderr(io.StringIO()):
            encrypt_file(
                input_file=self.plain,
                output_file=self.enc,
                password=TEST_PASSWORD,
                hash_config=dict(BASIC_HASH_CONFIG),
                quiet=True,
                algorithm=EncryptionAlgorithm.AES_GCM,
                streaming_threshold=STREAM_THRESHOLD,
                pepper_plugin=pepper_plugin,
                pepper_name=PEPPER_NAME,
                envelope=True,
            )
        md = self._metadata()
        self.assertTrue(md.get("streaming", {}).get("enabled"))
        self.assertIn("wrapped_dek", md.get("encryption", {}))
        self.assertEqual(md.get("encryption", {}).get("pepper_wrap_version"), 2)
        self._decrypt(blob=_v2_blob())
        with open(self.dec, "rb") as f:
            self.assertEqual(f.read(), self.payload)

    def test_plain_streamed_file_unaffected(self):
        self._encrypt()
        md = self._metadata()
        self.assertTrue(md.get("streaming", {}).get("enabled"))
        enc = md.get("encryption", {})
        self.assertIsNone(enc.get("pepper_plugin"))
        self.assertIsNone(enc.get("pepper_wrap_version"))
        self._decrypt()
        with open(self.dec, "rb") as f:
            self.assertEqual(f.read(), self.payload)


if __name__ == "__main__":
    unittest.main()
