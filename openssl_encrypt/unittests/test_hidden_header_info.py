#!/usr/bin/env python3
"""
Tests for key-aware metadata inspection (`info` / extract_file_metadata) on
hidden files.

extract_file_metadata must peel a keyless hidden file transparently and a keyed
hidden file when given the second password; a keyed file without the password
fails (its metadata is confidential). Legacy files are unaffected.

All code in English as per project requirements.
"""

import os
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import (
    _reconstruct_cli_from_metadata,
    encrypt_file,
    extract_file_metadata,
)

MINIMAL_CONFIG = {
    "sha512": 5,
    "argon2": {
        "enabled": True,
        "time_cost": 1,
        "memory_cost": 512,
        "parallelism": 1,
        "type": "id",
    },
}
PRIMARY = "primary-pw"
SECOND = "second-pw"
PLAINTEXT = b"info metadata payload\n" * 4


class TestExtractMetadataHidden(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.keyless = os.path.join(self.dir, "keyless.enc")
        self.keyed = os.path.join(self.dir, "keyed.enc")
        self.legacy = os.path.join(self.dir, "legacy.enc")
        common = dict(
            hash_config=MINIMAL_CONFIG, quiet=True, encryption_data="aes-gcm", algorithm="aes-gcm"
        )
        encrypt_file(PLAINTEXT, self.keyless, PRIMARY, hidden_header=True, **common)
        encrypt_file(
            PLAINTEXT, self.keyed, PRIMARY, hidden_header=True, second_password=SECOND, **common
        )
        encrypt_file(PLAINTEXT, self.legacy, PRIMARY, hidden_header=False, **common)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.dir, ignore_errors=True)

    def test_keyless_no_password(self):
        meta = extract_file_metadata(self.keyless)
        self.assertIn("format_version", meta)

    def test_keyed_with_second_password(self):
        meta = extract_file_metadata(self.keyed, second_password=SECOND)
        self.assertIn("format_version", meta)

    def test_keyed_without_password_fails(self):
        with self.assertRaises(ValueError):
            extract_file_metadata(self.keyed)

    def test_legacy_unaffected(self):
        meta = extract_file_metadata(self.legacy)
        self.assertIn("format_version", meta)

    # --- hidden/keyed reporting for the reconstructed CLI ---

    def test_extract_reports_keyless(self):
        info = extract_file_metadata(self.keyless)
        self.assertTrue(info.get("hidden"))
        self.assertFalse(info.get("keyed"))

    def test_extract_reports_keyed(self):
        info = extract_file_metadata(self.keyed, second_password=SECOND)
        self.assertTrue(info.get("hidden"))
        self.assertTrue(info.get("keyed"))

    def test_extract_reports_legacy(self):
        info = extract_file_metadata(self.legacy)
        self.assertFalse(info.get("hidden"))
        self.assertFalse(info.get("keyed"))


class TestReconstructHiddenFlags(unittest.TestCase):
    META = {"encryption": {"algorithm": "aes-gcm"}}

    def test_legacy_no_hidden_flags(self):
        out = _reconstruct_cli_from_metadata(self.META, hidden=False, keyed=False)
        self.assertNotIn("--hidden-header", out)
        self.assertNotIn("--second-password", out)

    def test_keyless_adds_hidden_header(self):
        out = _reconstruct_cli_from_metadata(self.META, hidden=True, keyed=False)
        self.assertIn("--hidden-header", out)
        self.assertNotIn("--second-password", out)

    def test_keyed_adds_hidden_and_second_password(self):
        out = _reconstruct_cli_from_metadata(self.META, hidden=True, keyed=True)
        self.assertIn("--hidden-header", out)
        self.assertIn("--second-password-prompt", out)


if __name__ == "__main__":
    unittest.main()
