#!/usr/bin/env python3
"""
`create-usb` must not copy private keys onto removable media (gitlab#203).

`_copy_openssl_encrypt_project` called `shutil.copytree` with no `ignore=`
and the default `symlinks=False`, so run from a source checkout -- which the
project-root walk explicitly targets -- it copied the entire tree. Measured
against this checkout before the fix:

    private keys copied to the 'drive': 4
       unittests/testfiles/asymmetric_wrap/*/encryption_private.pem
       unittests/testfiles/asymmetric_wrap/*/signing_private.pem
    total size: 23 MB

They landed unencrypted on a drive that is by design carried around,
typically on FAT32 where the mode bits `copy2` preserves are meaningless.
The keys in the tree are test fixtures rather than production secrets, so
the direct impact is limited -- but "the tool wrote private key files onto a
USB stick without telling you" is not a defensible default, and the same
path would copy a real key a user had placed in the tree.

`symlinks=True` matters separately: dereferencing meant a symlink in the
tree pulled its target's *contents* onto the drive, which is how something
outside the copied subtree gets copied anyway.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from openssl_encrypt.modules.portable_media.usb_creator import USBDriveCreator


class TestTheCopyFilterExcludesSecrets(unittest.TestCase):
    def setUp(self):
        self.creator = USBDriveCreator()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _ignore(self, directory, names):
        return self.creator._project_copy_ignore(directory, names)

    def test_key_material_is_excluded(self):
        names = [
            "signing_private.pem",
            "encryption_private.pem",
            "server.key",
            "identity.pqc",
            "keep_me.py",
        ]
        ignored = self._ignore("/some/dir", names)
        for secret in names[:4]:
            self.assertIn(secret, ignored, f"{secret} would be copied to the drive")
        self.assertNotIn("keep_me.py", ignored, "the filter is excluding real source")

    def test_the_test_tree_and_caches_are_excluded(self):
        names = ["unittests", "__pycache__", "module.pyc", ".git", "modules"]
        ignored = self._ignore("/some/dir", names)
        for junk in ("unittests", "__pycache__", "module.pyc", ".git"):
            self.assertIn(junk, ignored)
        self.assertNotIn("modules", ignored, "the tool's own package was excluded")

    def test_a_real_copy_carries_no_private_keys(self):
        """End to end against a tree shaped like the real one.

        Asserting on the filter alone would pass even if copytree were never
        told to use it -- which is exactly the bug.
        """
        src = self.tmp / "openssl_encrypt"
        (src / "modules").mkdir(parents=True)
        (src / "modules" / "crypt_core.py").write_text("# real source\n")
        (src / "__pycache__").mkdir()
        (src / "__pycache__" / "x.cpython-311.pyc").write_bytes(b"\x00")
        fixtures = src / "unittests" / "testfiles" / "asymmetric_wrap" / "sender_identity"
        fixtures.mkdir(parents=True)
        (fixtures / "signing_private.pem").write_text("-----BEGIN PRIVATE KEY-----\n")
        (fixtures / "encryption_private.pem").write_text("-----BEGIN PRIVATE KEY-----\n")

        dest = self.tmp / "drive" / "openssl_encrypt"
        shutil.copytree(src, dest, ignore=self.creator._project_copy_ignore, symlinks=True)

        self.assertEqual(
            [str(p.relative_to(dest)) for p in dest.rglob("*_private.pem")],
            [],
            "private keys were copied onto the drive",
        )
        self.assertEqual(list(dest.rglob("*.pyc")), [])
        self.assertFalse((dest / "unittests").exists())
        self.assertTrue(
            (dest / "modules" / "crypt_core.py").is_file(),
            "the filter removed source the portable install needs",
        )

    def test_a_symlink_is_copied_as_a_link_not_dereferenced(self):
        """Dereferencing pulls a file's contents in from outside the tree."""
        outside = self.tmp / "outside-secret.txt"
        outside.write_text("secret that lives outside the copied tree")

        src = self.tmp / "openssl_encrypt"
        src.mkdir()
        (src / "real.py").write_text("# source\n")
        os.symlink(outside, src / "link.txt")

        dest = self.tmp / "drive2" / "openssl_encrypt"
        shutil.copytree(src, dest, ignore=self.creator._project_copy_ignore, symlinks=True)

        copied = dest / "link.txt"
        self.assertTrue(copied.is_symlink(), "the symlink was dereferenced")
        self.assertFalse(
            copied.exists() and not copied.is_symlink(),
            "the target's contents were copied onto the drive",
        )


class TestTheCallerUsesTheFilter(unittest.TestCase):
    """The filter is only worth anything if copytree is told about it."""

    def test_copytree_is_called_with_the_filter_and_symlinks(self):
        import inspect

        source = inspect.getsource(USBDriveCreator._copy_openssl_encrypt_project)
        self.assertIn("_project_copy_ignore", source)
        self.assertIn("symlinks=True", source)


if __name__ == "__main__":
    unittest.main()
