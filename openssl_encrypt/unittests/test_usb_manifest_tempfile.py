#!/usr/bin/env python3
"""
The manifest encryption must not write through a planted symlink
(gitlab#204).

`_create_hash_manifest` built its output path by string
concatenation -- `temp_output_path = temp_input_path + ".enc"` -- so while
the *input* was a claimed 0600 `NamedTemporaryFile`, the output was an
unclaimed sibling in the shared temp directory whose name is derivable by
anyone who can list it. `encrypt_file` defaults to `secure_mode=False`, and
`safe_open_file` only applies `O_NOFOLLOW` when that is true.

A local attacker who pre-planted `…tmpXXXX.enc` as a symlink therefore got
an arbitrary file overwrite as the invoking user. Demonstrated before the
fix:

    victim content after: b'eyJmb3JtYXRfdmVyc2lvbiI6IDE0LC'
    victim overwritten:   True

and `set_secure_permissions` then chmod'd the symlink target.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from openssl_encrypt.modules.crypt_core import encrypt_file


class TestEncryptFileRefusesASymlinkOutputInSecureMode(unittest.TestCase):
    """The primitive itself, at the layer the fix relies on.

    If `secure_mode=True` did not actually refuse a symlink, passing it in
    the USB path would be cargo cult.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.source = self.tmp / "input.txt"
        self.source.write_text("manifest json")
        self.victim = self.tmp / "VICTIM"
        self.victim.write_bytes(b"important original content")

    def test_a_planted_symlink_output_is_refused(self):
        planted = self.tmp / "output.enc"
        os.symlink(self.victim, planted)

        with self.assertRaises(Exception):
            encrypt_file(
                input_file=str(self.source),
                output_file=str(planted),
                password=b"Tr0ub4dor&3-Correct-Horse!",
                quiet=True,
                secure_mode=True,
            )

        self.assertEqual(
            self.victim.read_bytes(),
            b"important original content",
            "the symlink was followed and the victim file overwritten",
        )

    def test_a_normal_output_still_works_in_secure_mode(self):
        """The negative arm: secure_mode must not break ordinary writes."""
        out = self.tmp / "normal.enc"
        encrypt_file(
            input_file=str(self.source),
            output_file=str(out),
            password=b"Tr0ub4dor&3-Correct-Horse!",
            quiet=True,
            secure_mode=True,
        )
        self.assertTrue(out.is_file())
        self.assertGreater(out.stat().st_size, 0)


class TestTheManifestPathClaimsItsOutput(unittest.TestCase):
    """Observed by running the real function, not by reading its source.

    The first version of this asserted the source no longer contained
    `temp_input_path + ".enc"` -- and then matched the *comment* explaining
    the fix. Source-text assertions fail that way; these watch what the
    function actually does.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.portable_root = self.tmp / "portable"
        self.portable_root.mkdir()
        (self.portable_root / "app.py").write_text("print('x')\n")

    def _run_and_capture(self):
        """Run the manifest builder, capturing every mkstemp path and the
        encrypt_file call it makes."""
        from unittest import mock

        from openssl_encrypt.modules.portable_media.usb_creator import USBDriveCreator

        creator = USBDriveCreator()
        allocated = []
        captured = {}

        real_mkstemp = tempfile.mkstemp

        def tracking_mkstemp(*args, **kwargs):
            fd, path = real_mkstemp(*args, **kwargs)
            allocated.append(path)
            return fd, path

        def fake_encrypt_file(**kwargs):
            captured.update(kwargs)
            with open(kwargs["output_file"], "wb") as handle:
                handle.write(b"ciphertext")
            return True

        with mock.patch("tempfile.mkstemp", tracking_mkstemp):
            with mock.patch("openssl_encrypt.modules.crypt_core.encrypt_file", fake_encrypt_file):
                creator._create_hash_manifest(self.portable_root, "master-password")

        return allocated, captured

    def test_the_output_path_is_independently_allocated(self):
        allocated, captured = self._run_and_capture()

        self.assertGreaterEqual(
            len(allocated), 2, "the output path was not claimed by its own mkstemp"
        )
        self.assertIn(
            captured.get("output_file"),
            allocated,
            "the output path was derived rather than claimed, so nothing "
            "stopped an attacker planting a symlink there first",
        )
        self.assertNotEqual(captured.get("output_file"), captured.get("input_file"))

    def test_the_encryption_refuses_symlinks(self):
        _allocated, captured = self._run_and_capture()
        self.assertTrue(
            captured.get("secure_mode"),
            "encrypt_file was called without secure_mode, so O_NOFOLLOW is "
            "not applied to the output",
        )

    def test_both_temp_files_are_removed(self):
        allocated, _captured = self._run_and_capture()
        leftover = [path for path in allocated if os.path.exists(path)]
        self.assertEqual(leftover, [], "temporary files were left in the shared temp directory")


if __name__ == "__main__":
    unittest.main()
