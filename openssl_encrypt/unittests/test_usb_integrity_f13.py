"""Regression tests for portable-USB integrity coverage (gitlab#132 / F13).

Before the fix, ``_verify_integrity_file`` only iterated the stored checksum
list, so a file ADDED to the drive (including a root-level ``autorun.*`` payload,
which lives above the portable directory and is auto-executed by the OS) was
never noticed and verification still passed. The v2 manifest is an ALLOWLIST of
every file in the tool tree, so verification flags ANY added file (a planted
binary/script of any type), while excluding the user-mutable workspace
(``data/``) and ``logs/``.

These tests drive ``_create_integrity_file`` / ``_verify_integrity_file``
directly on a temporary tree (no full drive build).
"""

import os
import tempfile
import unittest
from pathlib import Path

from openssl_encrypt.modules.portable_media.usb_creator import USBDriveCreator


class TestUsbIntegrityF13(unittest.TestCase):
    def setUp(self):
        self.creator = USBDriveCreator()
        self.key = os.urandom(32)
        self.usb_root = Path(tempfile.mkdtemp())
        self.portable_root = self.usb_root / self.creator.PORTABLE_DIR
        self.portable_root.mkdir(parents=True)
        # Tool-tree files (recorded in the allowlist). A mix of types to prove
        # coverage is not limited to a fixed extension set.
        (self.portable_root / "app.py").write_text("print('hi')\n")
        (self.portable_root / "portable.conf").write_text("{}\n")
        (self.portable_root / "readme.txt").write_text("hello\n")
        lib = self.portable_root / "openssl_encrypt_lib"
        lib.mkdir()
        (lib / "native.so").write_bytes(b"\x7fELF fake\n")
        # The user-mutable workspace (excluded from added-detection).
        (self.portable_root / self.creator.DATA_DIR).mkdir()
        (self.portable_root / self.creator.DATA_DIR / "existing.enc").write_bytes(b"\x00c\x00")
        # A root-level autorun file (above portable_root).
        (self.usb_root / "autorun.inf").write_text("[autorun]\n")

    def tearDown(self):
        import shutil

        shutil.rmtree(self.usb_root, ignore_errors=True)

    def _create(self, usb_root=None):
        return self.creator._create_integrity_file(
            self.portable_root,
            self.key,
            usb_root=usb_root if usb_root is not None else self.usb_root,
        )

    def _verify(self, usb_root=None):
        return self.creator._verify_integrity_file(
            self.portable_root,
            self.key,
            usb_root=usb_root if usb_root is not None else self.usb_root,
        )

    def test_clean_drive_verifies_ok(self):
        self._create()
        result = self._verify()
        self.assertTrue(result["integrity_ok"], result)
        self.assertEqual(result["added_files"], 0)

    def test_added_executable_is_detected(self):
        self._create()
        # Attacker drops a malicious script.
        (self.portable_root / "evil.sh").write_text("#!/bin/sh\nrm -rf ~\n")
        result = self._verify()
        self.assertFalse(result["integrity_ok"])
        self.assertGreaterEqual(result["added_files"], 1)
        self.assertIn("evil.sh", result["added_file_list"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX mkfifo")
    def test_planted_special_file_is_detected(self):
        # A FIFO/socket/device planted on the drive is neither a legit tool file
        # nor a directory — it must be flagged, not silently skipped.
        self._create()
        os.mkfifo(self.portable_root / "openssl_encrypt_lib" / "pipe")
        result = self._verify()
        self.assertFalse(result["integrity_ok"])
        self.assertTrue(any("pipe" in p for p in result["added_file_list"]))

    def test_added_nested_executable_is_detected(self):
        self._create()
        sub = self.portable_root / "sub" / "dir"
        sub.mkdir(parents=True)
        (sub / "payload.py").write_text("import os\n")
        result = self._verify()
        self.assertFalse(result["integrity_ok"])
        self.assertTrue(any("payload.py" in p for p in result["added_file_list"]))

    def test_added_non_scripted_binary_is_detected(self):
        # H1 regression: an allowlist catches ANY added file, not just a fixed
        # extension set — e.g. a planted native library that a denylist of
        # script/exe extensions would miss.
        self._create()
        (self.portable_root / "openssl_encrypt_lib" / "evil.dll").write_bytes(b"MZ\x00")
        result = self._verify()
        self.assertFalse(result["integrity_ok"])
        self.assertTrue(any("evil.dll" in p for p in result["added_file_list"]))

    def test_added_user_data_in_workspace_is_not_flagged(self):
        # The normal use case: the user encrypts more files into the workspace.
        self._create()
        (self.portable_root / self.creator.DATA_DIR / "my_secret.enc").write_bytes(b"\x00new\x00")
        (self.portable_root / self.creator.DATA_DIR / "decrypted").mkdir()
        (self.portable_root / self.creator.DATA_DIR / "decrypted" / "out.txt").write_text("x\n")
        result = self._verify()
        self.assertTrue(result["integrity_ok"], result)
        self.assertEqual(result["added_files"], 0)

    def test_modified_manifested_file_is_detected(self):
        self._create()
        (self.portable_root / "app.py").write_text("print('tampered')\n")
        result = self._verify()
        self.assertFalse(result["integrity_ok"])
        self.assertIn("app.py", result["tampered_files"])

    def test_root_autorun_tampered_is_detected(self):
        self._create()
        (self.usb_root / "autorun.inf").write_text("[autorun]\nopen=evil.exe\n")
        result = self._verify()
        self.assertFalse(result["integrity_ok"])
        self.assertIn("autorun.inf", result["tampered_files"])

    def test_added_root_autorun_is_detected(self):
        # No autorun.sh existed at creation; attacker adds one.
        self._create()
        (self.usb_root / "autorun.sh").write_text("#!/bin/sh\n")
        result = self._verify()
        self.assertFalse(result["integrity_ok"])
        self.assertIn("autorun.sh", result["added_file_list"])

    def test_removed_root_autorun_is_detected(self):
        self._create()
        (self.usb_root / "autorun.inf").unlink()
        result = self._verify()
        self.assertFalse(result["integrity_ok"])
        self.assertIn("autorun.inf", result["missing_file_list"])

    def test_legacy_v1_manifest_skips_added_detection(self):
        # A pre-fix (v1) manifest has no scan_version; verification must behave
        # exactly as before — only listed files checked, added files ignored —
        # so existing drives keep verifying.
        import hashlib
        import json

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        checksums = {}
        for name in ("app.py", "portable.conf"):
            checksums[name] = hashlib.sha256((self.portable_root / name).read_bytes()).hexdigest()
        legacy = {
            "version": self.creator.VERSION,
            "created_at": 0.0,
            "security_profile": self.creator.security_profile.value,
            "checksums": checksums,
            "file_count": len(checksums),
            "hash_config": None,
        }
        blob = json.dumps(legacy, separators=(",", ":")).encode("utf-8")
        nonce = os.urandom(self.creator.NONCE_LENGTH)
        enc = AESGCM(self.key).encrypt(nonce, blob, None)
        (self.portable_root / self.creator.INTEGRITY_FILE).write_bytes(nonce + enc)

        # Add an executable that a v2 manifest would flag.
        (self.portable_root / "added.py").write_text("x=1\n")
        result = self._verify()
        # Legacy behavior: added files are NOT detected, so still "ok".
        self.assertTrue(result["integrity_ok"], result)
        self.assertEqual(result["added_files"], 0)


if __name__ == "__main__":
    unittest.main()
