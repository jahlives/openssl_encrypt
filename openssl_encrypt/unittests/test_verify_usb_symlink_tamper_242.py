#!/usr/bin/env python3
"""verify-usb must treat a planted directory/file symlink as tampering
(gitlab#242, scan F26, CWE-59).

The v2 added-file scan enumerated the drive with rglob("*"), which never
descends a symlinked directory. An evil-maid attacker could replace a tool-tree
directory with a symlink to a copy holding the same files plus a planted
__pycache__/*.pyc; the listed files hashed clean through the symlink, the
planted file was never enumerated, added_files stayed 0, and verify reported
PASSED -> code execution. The scan now uses os.walk(followlinks=False) and flags
any symlinked path component.
"""

import json
import os
import secrets
import shutil
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from openssl_encrypt.modules.portable_media.usb_creator import (
    USBCreationError,
    USBDriveCreator,
)


class TestVerifyUsbSymlinkTamper(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = Path(self.tmp) / "portable"
        (self.root / "openssl_encrypt").mkdir(parents=True)
        self.key = secrets.token_bytes(32)
        self.creator = USBDriveCreator()
        # One legit tool file recorded in the manifest.
        self.legit = self.root / "openssl_encrypt" / "tool.py"
        self.legit.write_text("print('ok')\n")
        checksums = {str(self.legit.relative_to(self.root)): self.creator._sha256_file(self.legit)}
        self._write_manifest(checksums)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_manifest(self, checksums):
        data = json.dumps(
            {
                "version": self.creator.VERSION,
                "scan_version": self.creator.INTEGRITY_SCAN_VERSION,
                "created_at": 0,
                "security_profile": self.creator.security_profile.value,
                "checksums": checksums,
                "root_checksums": {},
                "file_count": len(checksums),
                "hash_config": None,
            }
        ).encode("utf-8")
        nonce = secrets.token_bytes(self.creator.NONCE_LENGTH)
        blob = nonce + AESGCM(self.key).encrypt(nonce, data, None)
        (self.root / self.creator.INTEGRITY_FILE).write_bytes(blob)

    def test_clean_install_verifies(self):
        res = self.creator._verify_integrity_file(self.root, self.key)
        self.assertEqual(res["added_files"], 0)
        self.assertTrue(res["integrity_ok"])

    def test_planted_directory_symlink_is_flagged_as_tampering(self):
        # Evil-maid: a symlinked directory to a tree holding a planted .pyc.
        evil = Path(self.tmp) / "evil_pkg"
        (evil / "__pycache__").mkdir(parents=True)
        (evil / "__pycache__" / "tool.cpython-311.pyc").write_bytes(b"MALICIOUS")
        os.symlink(evil, self.root / "openssl_encrypt" / "pkg")

        res = self.creator._verify_integrity_file(self.root, self.key)
        self.assertGreaterEqual(res["added_files"], 1, "the symlinked dir must be flagged")
        self.assertFalse(res["integrity_ok"], "a symlinked tree must fail verification")

    def test_planted_file_symlink_is_flagged(self):
        target = Path(self.tmp) / "outside.py"
        target.write_text("evil\n")
        os.symlink(target, self.root / "openssl_encrypt" / "extra.py")
        res = self.creator._verify_integrity_file(self.root, self.key)
        self.assertGreaterEqual(res["added_files"], 1)
        self.assertFalse(res["integrity_ok"])

    def test_create_refuses_symlinked_file(self):
        # A legit source-tree file symlink must fail creation with a clear error,
        # not an opaque O_NOFOLLOW OSError and not a silently-omitted manifest.
        target = Path(self.tmp) / "outside.py"
        target.write_text("x\n")
        os.symlink(target, self.root / "openssl_encrypt" / "link.py")
        with self.assertRaises(USBCreationError) as ctx:
            self.creator._create_integrity_file(self.root, self.key)
        self.assertIn("symlink", str(ctx.exception).lower())

    def test_create_refuses_symlinked_dir(self):
        ext = Path(self.tmp) / "ext"
        (ext / "sub").mkdir(parents=True)
        (ext / "sub" / "payload.py").write_text("evil\n")
        os.symlink(ext, self.root / "openssl_encrypt" / "extdir")
        with self.assertRaises(USBCreationError) as ctx:
            self.creator._create_integrity_file(self.root, self.key)
        self.assertIn("symlink", str(ctx.exception).lower())

    def test_verify_flags_symlink_wearing_excluded_name(self):
        # islink is checked BEFORE the data/logs exclusion prune: an evil-maid
        # replacing the user-mutable workspace with a symlink (data redirection)
        # must still be caught, not skipped as an excluded tree.
        ext = Path(self.tmp) / "elsewhere"
        ext.mkdir()
        os.symlink(ext, self.root / "data")
        res = self.creator._verify_integrity_file(self.root, self.key)
        self.assertGreaterEqual(res["added_files"], 1)
        self.assertFalse(res["integrity_ok"])

    def test_create_refuses_symlink_wearing_excluded_name(self):
        ext = Path(self.tmp) / "elsewhere"
        ext.mkdir()
        os.symlink(ext, self.root / "logs")
        with self.assertRaises(USBCreationError) as ctx:
            self.creator._create_integrity_file(self.root, self.key)
        self.assertIn("symlink", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
