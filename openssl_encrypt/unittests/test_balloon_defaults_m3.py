#!/usr/bin/env python3
"""
Regression tests for M3: Balloon hashing default was not memory-hard.

On the independent-XOR (v11) path, an enabled Balloon KDF with no explicit
space_cost fell back to space_cost=16 -> ~512 bytes of buffer, i.e. the
memory-hard stretching the user expected was effectively absent (GPU-trivial),
and the value was not even persisted in metadata.

Fix (encrypt-time only, so legacy files stay decryptable): a memory-hard
default space_cost is applied and persisted for new files; an explicit
sub-floor value is warned about but respected (M4 decision). The decrypt path
is NOT touched, so files written with the old unstored default still derive the
same key.

See SECURITY_REVIEW_FINDINGS.md (M3).
"""

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock

from openssl_encrypt.modules import crypt_core
from openssl_encrypt.modules.crypt_core import (
    BALLOON_DEFAULT_SPACE_COST,
    BALLOON_MIN_SAFE_SPACE_COST,
    EncryptionAlgorithm,
    _apply_balloon_security_defaults,
    decrypt_file,
    encrypt_file,
)


class TestBalloonNormalizationUnit(unittest.TestCase):
    """Unit tests for the encrypt-time normalization helper."""

    def test_default_fill_top_level(self):
        cfg = {"balloon": {"enabled": True}}
        _apply_balloon_security_defaults(cfg, quiet=True)
        self.assertEqual(cfg["balloon"]["space_cost"], BALLOON_DEFAULT_SPACE_COST)
        self.assertIn("time_cost", cfg["balloon"])

    def test_default_fill_nested(self):
        cfg = {"derivation_config": {"kdf_config": {"balloon": {"enabled": True}}}}
        _apply_balloon_security_defaults(cfg, quiet=True)
        self.assertEqual(
            cfg["derivation_config"]["kdf_config"]["balloon"]["space_cost"],
            BALLOON_DEFAULT_SPACE_COST,
        )

    def test_default_is_memory_hard(self):
        # 16 (the old default) gave 512 bytes; the new default must be >= 512 KiB
        self.assertGreaterEqual(BALLOON_DEFAULT_SPACE_COST * 32, 512 * 1024)

    def test_explicit_value_respected_and_warned(self):
        cfg = {"balloon": {"enabled": True, "space_cost": 16}}
        err = io.StringIO()
        with redirect_stderr(err):
            _apply_balloon_security_defaults(cfg, quiet=False)
        # explicit value kept (M4: the expert's choice)
        self.assertEqual(cfg["balloon"]["space_cost"], 16)
        # but warned loudly with the byte cost
        self.assertIn("WARNING", err.getvalue())
        self.assertIn("memory hardness", err.getvalue())

    def test_explicit_safe_value_not_warned(self):
        cfg = {"balloon": {"enabled": True, "space_cost": BALLOON_MIN_SAFE_SPACE_COST}}
        err = io.StringIO()
        with redirect_stderr(err):
            _apply_balloon_security_defaults(cfg, quiet=False)
        self.assertEqual(cfg["balloon"]["space_cost"], BALLOON_MIN_SAFE_SPACE_COST)
        self.assertNotIn("WARNING", err.getvalue())

    def test_disabled_balloon_untouched(self):
        cfg = {"balloon": {"enabled": False}}
        _apply_balloon_security_defaults(cfg, quiet=True)
        self.assertNotIn("space_cost", cfg["balloon"])

    def test_quiet_suppresses_warning(self):
        cfg = {"balloon": {"enabled": True, "space_cost": 16}}
        err = io.StringIO()
        with redirect_stderr(err):
            _apply_balloon_security_defaults(cfg, quiet=True)
        self.assertEqual(err.getvalue(), "")

    def test_non_dict_is_noop(self):
        self.assertIsNone(_apply_balloon_security_defaults(None))


class TestBalloonEncryptIntegration(unittest.TestCase):
    """End-to-end: new files are memory-hard and persist the value; old weak
    files still decrypt."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.src = os.path.join(self.dir, "in.txt")
        with open(self.src, "w") as f:
            f.write("balloon m3 payload")
        self.balloon_cfg = {
            "sha512": 0,
            "sha256": 0,
            "sha3_256": 0,
            "sha3_512": 0,
            "blake2b": 0,
            "shake256": 0,
            "whirlpool": 0,
            "scrypt": {"enabled": False},
            "argon2": {"enabled": False},
            "balloon": {"enabled": True},
            "pbkdf2_iterations": 0,
        }

    def tearDown(self):
        import shutil

        shutil.rmtree(self.dir, ignore_errors=True)

    def _read_balloon_meta(self, path):
        import base64
        import json

        raw = open(path, "rb").read(8192)
        meta = json.loads(base64.b64decode(raw[: raw.find(b":")]).decode())
        return meta["derivation_config"]["kdf_config"].get("balloon", {})

    def test_new_v11_balloon_is_strong_and_persisted(self):
        enc = os.path.join(self.dir, "new.enc")
        dec = os.path.join(self.dir, "new.dec")
        encrypt_file(
            self.src,
            enc,
            b"pw12345678",
            dict(self.balloon_cfg),
            quiet=True,
            algorithm=EncryptionAlgorithm.AES_GCM,
            format_version=11,
        )
        balloon = self._read_balloon_meta(enc)
        self.assertEqual(balloon.get("space_cost"), BALLOON_DEFAULT_SPACE_COST)
        self.assertTrue(decrypt_file(enc, dec, b"pw12345678", quiet=True))
        self.assertEqual(open(dec).read(), "balloon m3 payload")

    def test_legacy_weak_file_still_decrypts(self):
        """A file written BEFORE the fix (balloon {'enabled': true}, space_cost
        unstored, derived with the old default 16) must still decrypt - the fix
        must not change the decrypt-side default."""
        enc = os.path.join(self.dir, "old.enc")
        dec = os.path.join(self.dir, "old.dec")
        # Simulate pre-fix encryption by disabling the normalization helper.
        with mock.patch.object(
            crypt_core, "_apply_balloon_security_defaults", side_effect=lambda hc, quiet=False: hc
        ):
            encrypt_file(
                self.src,
                enc,
                b"pw12345678",
                dict(self.balloon_cfg),
                quiet=True,
                algorithm=EncryptionAlgorithm.AES_GCM,
                format_version=11,
            )
        # The legacy file did not persist space_cost (weak default path).
        self.assertNotIn("space_cost", self._read_balloon_meta(enc))
        # Decrypt with the REAL (post-fix) code path - must still work.
        self.assertTrue(decrypt_file(enc, dec, b"pw12345678", quiet=True))
        self.assertEqual(open(dec).read(), "balloon m3 payload")


if __name__ == "__main__":
    unittest.main()
