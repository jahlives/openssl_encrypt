#!/usr/bin/env python3
"""
`create-usb` must not quietly destroy things at a mistyped path, and must
not leave the drive's secrets world-readable (gitlab#207).

`_is_removable_drive` is a substring test for `/media/`, `/mnt/`,
`/Volumes/` and only logs a warning when it fails -- the operation proceeds
either way. So `create-usb --usb-path ~` created `~/openssl_encrypt_portable/`
and **overwrote** `~/autorun.inf`, `~/autorun.sh` and `~/.autorun` with no
existence check at all.

And nothing was chmod'd except the three files deliberately made 0755, so
`config/keystore.encrypted`, `config/salt.bin`, `.integrity` and
`hash_manifest.enc` were created at the process umask -- typically 0644.
Irrelevant on FAT32, exposed the moment the target is a real filesystem,
which this code permits.

The interactive confirmation for a non-removable target lives at the CLI
layer, not here: a library function that prompts is untestable and unusable
from a script. What the library owes its callers is that it does not
silently overwrite, which is what these pin.
"""

import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from openssl_encrypt.modules.portable_media.usb_creator import USBCreationError, USBDriveCreator

PASSWORD = "Tr0ub4dor&3-Correct-Horse!"


class TestExistingAutorunFilesAreNotClobbered(unittest.TestCase):
    def setUp(self):
        self.creator = USBDriveCreator()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_a_pre_existing_autorun_stops_the_operation(self):
        existing = self.tmp / "autorun.inf"
        existing.write_text("[autorun]\nopen=something-the-user-put-here.exe\n")

        with self.assertRaises(USBCreationError):
            self.creator.create_portable_usb(usb_path=str(self.tmp), password=PASSWORD)

        self.assertIn(
            "something-the-user-put-here",
            existing.read_text(),
            "the user's own autorun.inf was overwritten",
        )

    def test_force_allows_it(self):
        """The escape hatch, so re-creating a drive stays possible."""
        existing = self.tmp / "autorun.inf"
        existing.write_text("[autorun]\nopen=old.exe\n")

        result = self.creator.create_portable_usb(
            usb_path=str(self.tmp), password=PASSWORD, force=True
        )
        self.assertTrue(result["success"])
        self.assertNotIn("old.exe", existing.read_text())

    def test_a_clean_target_needs_no_force(self):
        """The negative arm: refusing everything would break normal use."""
        result = self.creator.create_portable_usb(usb_path=str(self.tmp), password=PASSWORD)
        self.assertTrue(result["success"])


class TestTheDriveSecretsAreOwnerOnly(unittest.TestCase):
    def setUp(self):
        self.creator = USBDriveCreator()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.creator.create_portable_usb(usb_path=str(self.tmp), password=PASSWORD)
        self.portable_root = self.tmp / self.creator.PORTABLE_DIR

    def _mode(self, relative):
        path = self.portable_root / relative
        if not path.exists():
            self.skipTest(f"{relative} was not produced by this configuration")
        return stat.S_IMODE(path.stat().st_mode)

    def test_the_salt_is_not_group_or_world_readable(self):
        self.assertEqual(self._mode(f"{self.creator.CONFIG_DIR}/salt.bin") & 0o077, 0)

    def test_the_integrity_manifest_is_not_group_or_world_readable(self):
        self.assertEqual(self._mode(self.creator.INTEGRITY_FILE) & 0o077, 0)

    def test_the_portable_config_is_not_group_or_world_readable(self):
        self.assertEqual(self._mode(f"{self.creator.CONFIG_DIR}/portable.conf") & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
