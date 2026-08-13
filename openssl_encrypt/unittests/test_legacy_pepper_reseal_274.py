#!/usr/bin/env python3
"""Regression tests for gitlab#274 (ADVISORY 2026-35 residuals).

1.4.9 fixed the weak remote-pepper wrap on the WRITE path (v2 ``OEPPWRP2``
Argon2id blob, gitlab#244), but left two residuals on the read side:

1. A pepper referenced by ``--pepper-name`` was unwrapped and used without
   ever being re-sealed, so the advisory's "re-encrypt to re-seal"
   mitigation never actually drained legacy blobs for named peppers.
   Encrypting with a named pepper whose server blob is legacy must now
   immediately re-wrap it to v2 and push it back with ``update_pepper``
   (non-fatal, warned, if the push fails).

2. Legacy blob acceptance was silent and unrecorded, so a hostile
   keyserver could serve (or restore) the weak blob forever without the
   client noticing. Every legacy unwrap now warns loudly, files record
   ``encryption.pepper_wrap_version`` at write time, and decrypt refuses a
   legacy blob for a file that recorded the v2 wrap unless the
   ``OPENSSL_ENCRYPT_ALLOW_LEGACY_PEPPER_WRAP=1`` escape hatch is set.
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

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from openssl_encrypt.modules import crypt_core
from openssl_encrypt.modules.crypt_core import (
    _PEPPER_WRAP_V2_MAGIC,
    KeyDerivationError,
    _unwrap_remote_pepper,
    _wrap_remote_pepper,
    decrypt_file,
    encrypt_file,
)

TEST_PASSWORD = b"legacy-pepper-reseal-274-password"
BASIC_HASH_CONFIG = {"sha256": 10, "pbkdf2_iterations": 1000}
REMOTE_PEPPER = b"R" * 32
PEPPER_NAME = "reseal-274-test-pepper"
OVERRIDE_ENV = "OPENSSL_ENCRYPT_ALLOW_LEGACY_PEPPER_WRAP"


def _legacy_blob(format_version=14) -> bytes:
    """A pre-1.4.9 wrapped pepper: nonce || AES-GCM(ct||tag), no magic, no AAD."""
    key = crypt_core._derive_pepper_key(TEST_PASSWORD, format_version=format_version)
    nonce = b"\x00" * 12
    return nonce + AESGCM(bytes(key)).encrypt(nonce, REMOTE_PEPPER, None)


def _v2_blob(name=PEPPER_NAME) -> bytes:
    return _wrap_remote_pepper(TEST_PASSWORD, REMOTE_PEPPER, name)


class TestLegacyUnwrapWarns(unittest.TestCase):
    """Fix 2a: every legacy unwrap warns loudly (single chokepoint)."""

    def test_legacy_unwrap_emits_warning(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            out = _unwrap_remote_pepper(TEST_PASSWORD, _legacy_blob(), PEPPER_NAME, 14)
        self.assertEqual(bytes(out), REMOTE_PEPPER)
        self.assertIn("pre-1.4.9", err.getvalue())

    def test_v2_unwrap_does_not_warn(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            out = _unwrap_remote_pepper(TEST_PASSWORD, _v2_blob(), PEPPER_NAME, 14)
        self.assertEqual(bytes(out), REMOTE_PEPPER)
        self.assertNotIn("pre-1.4.9", err.getvalue())


class _PepperFileMixin(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="reseal274-")
        self.plain = os.path.join(self.tmp, "plain.txt")
        self.enc = os.path.join(self.tmp, "plain.txt.enc")
        self.dec = os.path.join(self.tmp, "plain.txt.dec")
        with open(self.plain, "wb") as f:
            f.write(b"legacy pepper reseal regression payload")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _encrypt(self, plugin, quiet=True):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            encrypt_file(
                input_file=self.plain,
                output_file=self.enc,
                password=TEST_PASSWORD,
                hash_config=dict(BASIC_HASH_CONFIG),
                quiet=quiet,
                pepper_plugin=plugin,
                pepper_name=PEPPER_NAME,
            )
        return err.getvalue()

    def _decrypt(self, blob):
        fake_config = SimpleNamespace(enabled=True)
        fake_plugin = mock.MagicMock()
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
            )
        return err.getvalue()

    def _written_metadata(self):
        with open(self.enc, "rb") as f:
            metadata_b64 = f.read().split(b":", 1)[0]
        return json.loads(base64.b64decode(metadata_b64))

    def _written_wrap_version(self):
        return self._written_metadata().get("encryption", {}).get("pepper_wrap_version")

    def _tamper_wrap_version(self, value):
        with open(self.enc, "rb") as f:
            metadata_b64, payload = f.read().split(b":", 1)
        metadata = json.loads(base64.b64decode(metadata_b64))
        metadata.setdefault("encryption", {})["pepper_wrap_version"] = value
        with open(self.enc, "wb") as f:
            f.write(base64.b64encode(json.dumps(metadata).encode()) + b":" + payload)

    def _strip_wrap_version(self):
        """Rewrite the header WITHOUT the key — the pre-gitlab#274 file shape."""
        with open(self.enc, "rb") as f:
            metadata_b64, payload = f.read().split(b":", 1)
        metadata = json.loads(base64.b64decode(metadata_b64))
        metadata.get("encryption", {}).pop("pepper_wrap_version", None)
        with open(self.enc, "wb") as f:
            f.write(base64.b64encode(json.dumps(metadata).encode()) + b":" + payload)


class TestNamedPepperReseal(_PepperFileMixin):
    """Fix 1: a legacy blob behind --pepper-name is re-sealed to v2 in place."""

    def test_legacy_pepper_is_resealed_on_encrypt(self):
        plugin = mock.MagicMock()
        plugin.get_pepper.return_value = _legacy_blob()

        stderr = self._encrypt(plugin)

        plugin.update_pepper.assert_called_once()
        pushed = plugin.update_pepper.call_args.kwargs["pepper_encrypted"]
        self.assertTrue(pushed.startswith(_PEPPER_WRAP_V2_MAGIC))
        # The re-sealed blob must open to the SAME pepper under the v2 path.
        self.assertEqual(
            bytes(_unwrap_remote_pepper(TEST_PASSWORD, pushed, PEPPER_NAME, 14)),
            REMOTE_PEPPER,
        )
        self.assertIn("re-seal", stderr.lower())
        self.assertEqual(self._written_wrap_version(), 2)

    def test_v2_pepper_is_not_resealed(self):
        plugin = mock.MagicMock()
        plugin.get_pepper.return_value = _v2_blob()

        self._encrypt(plugin)

        plugin.update_pepper.assert_not_called()
        self.assertEqual(self._written_wrap_version(), 2)

    def test_reseal_failure_is_nonfatal_and_recorded_as_legacy(self):
        plugin = mock.MagicMock()
        plugin.get_pepper.return_value = _legacy_blob()
        plugin.update_pepper.side_effect = RuntimeError("server refused")

        stderr = self._encrypt(plugin)

        self.assertTrue(os.path.exists(self.enc), "encrypt must succeed despite reseal failure")
        self.assertIn("WARNING", stderr)
        # The server still holds the legacy blob, so the file must NOT claim v2
        # (a v2 claim would make the downgrade gate refuse its own pepper).
        self.assertEqual(self._written_wrap_version(), 1)


class TestDowngradeGate(_PepperFileMixin):
    """Fix 2b: files that recorded the v2 wrap refuse a legacy blob on decrypt."""

    def _encrypt_recording_v2(self):
        plugin = mock.MagicMock()
        plugin.get_pepper.return_value = _v2_blob()
        self._encrypt(plugin)
        self.assertEqual(self._written_wrap_version(), 2)

    def test_legacy_blob_refused_when_file_recorded_v2(self):
        self._encrypt_recording_v2()
        with self.assertRaises(KeyDerivationError) as ctx:
            self._decrypt(_legacy_blob())
        self.assertIn("legacy", str(ctx.exception).lower())
        self.assertIn(OVERRIDE_ENV, str(ctx.exception))

    def test_override_env_allows_legacy_blob(self):
        self._encrypt_recording_v2()
        with mock.patch.dict(os.environ, {OVERRIDE_ENV: "1"}):
            self._decrypt(_legacy_blob())
        with open(self.dec, "rb") as f:
            self.assertEqual(f.read(), b"legacy pepper reseal regression payload")

    def test_v2_blob_decrypts_normally(self):
        self._encrypt_recording_v2()
        self._decrypt(_v2_blob())
        with open(self.dec, "rb") as f:
            self.assertEqual(f.read(), b"legacy pepper reseal regression payload")

    def test_file_without_recorded_version_still_accepts_legacy(self):
        """Old files (no recorded wrap version) keep decrypting legacy blobs."""
        plugin = mock.MagicMock()
        plugin.get_pepper.return_value = _legacy_blob()
        plugin.update_pepper.side_effect = RuntimeError("server refused")
        self._encrypt(plugin)  # records 1, not 2
        self._decrypt(_legacy_blob())
        with open(self.dec, "rb") as f:
            self.assertEqual(f.read(), b"legacy pepper reseal regression payload")

    def test_pre_274_file_shape_still_accepts_legacy(self):
        """A file whose header has NO pepper_wrap_version at all (written by a
        release before gitlab#274) must keep decrypting a legacy blob."""
        self._encrypt_recording_v2()
        self._strip_wrap_version()
        self.assertIsNone(self._written_wrap_version())
        self._decrypt(_legacy_blob())
        with open(self.dec, "rb") as f:
            self.assertEqual(f.read(), b"legacy pepper reseal regression payload")

    def test_garbage_recorded_version_is_ignored(self):
        """An attacker-typed wrap version must not crash the gate (untrusted int)."""
        self._encrypt_recording_v2()
        # Tamper the (non-AEAD-bound) header directly: non-int wrap version.
        self._tamper_wrap_version({"v": 2})
        self._decrypt(_v2_blob())
        with open(self.dec, "rb") as f:
            self.assertEqual(f.read(), b"legacy pepper reseal regression payload")


if __name__ == "__main__":
    unittest.main()
