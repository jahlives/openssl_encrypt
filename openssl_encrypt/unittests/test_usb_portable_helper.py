#!/usr/bin/env python3
"""
What `create-usb` writes onto the drive must work and must not teach bad
habits (gitlab#206).

The drive ships a standalone `crypt.py`, chmods it 0755, and points the
workspace README and the Windows batch files at it. Its template carried a
package-relative import at top level:

    from ..crypt_utils import eprint

which in a standalone script raises `ImportError: attempted relative import
with no known parent package`. Confirmed before the fix -- the helper could
not run at all.

Two more things the same generator got wrong: the batch files were written
from a non-raw string containing `\\n`, so each is one line with a literal
escape in it; and the generated help told users to pass the master password
as `--password mypass`, putting it in the process list and shell history --
guidance written *by* the security tool onto the medium, which carries more
weight than a user's own habit.

Finally, a path option that was given but does not exist was silently
skipped, so a mistyped `--keystore-to-include` left the user believing
their keystore was on the drive.
"""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from openssl_encrypt.modules.portable_media.usb_creator import USBCreationError, USBDriveCreator


class TestTheGeneratedHelperRuns(unittest.TestCase):
    def setUp(self):
        self.creator = USBDriveCreator()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.portable_root = self.tmp / "portable"
        self.portable_root.mkdir()
        self.creator._create_transparent_encryption_helpers(self.portable_root)
        self.script = self.portable_root / "crypt.py"

    def test_the_helper_was_written(self):
        self.assertTrue(self.script.is_file())

    def test_it_is_importable_python(self):
        """Compile rather than exec: a syntax or import-shape error must not
        need the script to be run to be caught."""
        import ast

        ast.parse(self.script.read_text(encoding="utf-8"))

    def test_it_has_no_package_relative_imports(self):
        """The specific defect. A standalone script has no parent package."""
        source = self.script.read_text(encoding="utf-8")
        offenders = [
            line
            for line in source.splitlines()
            if line.startswith("from ..") or line.startswith("from .")
        ]
        self.assertEqual(
            offenders,
            [],
            "the generated standalone script uses a package-relative import "
            "and will fail with ImportError on first run",
        )

    def test_it_actually_executes(self):
        """The end-to-end arm: the AST check above passes on the broken
        version too, because a relative import is valid syntax."""
        result = subprocess.run(
            [sys.executable, str(self.script), "--help"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        combined = (result.stdout or "") + (result.stderr or "")
        self.assertNotIn("ImportError", combined, combined[-300:])
        self.assertNotIn("Traceback", combined, combined[-300:])


class TestTheGeneratedGuidanceDoesNotLeakThePassword(unittest.TestCase):
    def setUp(self):
        self.creator = USBDriveCreator()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.portable_root = self.tmp / "portable"
        self.portable_root.mkdir()
        self.creator._create_transparent_encryption_helpers(self.portable_root)

    def test_the_help_does_not_show_a_password_on_the_command_line(self):
        source = (self.portable_root / "crypt.py").read_text(encoding="utf-8")
        bad = [
            line.strip()
            for line in source.splitlines()
            if "--password " in line and "eprint(" in line
        ]
        self.assertEqual(
            bad,
            [],
            "the generated help tells users to put the master password on the "
            "command line, where it is visible in the process list:\n" + "\n".join(bad),
        )

    def test_the_environment_variable_is_offered_instead(self):
        source = (self.portable_root / "crypt.py").read_text(encoding="utf-8")
        self.assertIn("CRYPT_PASSWORD", source)


class TestPathOptionsFailLoudly(unittest.TestCase):
    """A silently skipped keystore is a user who thinks it is on the drive."""

    def setUp(self):
        self.creator = USBDriveCreator()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_a_missing_executable_path_is_an_error(self):
        with self.assertRaises(USBCreationError) as caught:
            self.creator.create_portable_usb(
                usb_path=str(self.tmp),
                password="Tr0ub4dor&3-Correct-Horse!",
                executable_path=str(self.tmp / "does-not-exist"),
            )
        self.assertIn("does-not-exist", str(caught.exception))

    def test_a_missing_keystore_path_is_an_error(self):
        with self.assertRaises(USBCreationError) as caught:
            self.creator.create_portable_usb(
                usb_path=str(self.tmp),
                password="Tr0ub4dor&3-Correct-Horse!",
                keystore_path=str(self.tmp / "no-such-keystore"),
            )
        self.assertIn("no-such-keystore", str(caught.exception))

    def test_omitting_them_entirely_is_still_fine(self):
        """Not supplying an optional path must stay optional."""
        result = self.creator.create_portable_usb(
            usb_path=str(self.tmp),
            password="Tr0ub4dor&3-Correct-Horse!",
        )
        self.assertTrue(result["success"])


if __name__ == "__main__":
    unittest.main()
