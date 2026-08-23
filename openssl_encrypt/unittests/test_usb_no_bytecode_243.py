#!/usr/bin/env python3
"""The portable USB tool must not write bytecode onto the media (gitlab#243).

The generated ``crypt.py`` wrapper imports the bundled library and spawns the
bundled CLI; without bytecode suppression, first use writes
``__pycache__/*.pyc`` throughout ``openssl_encrypt_lib`` — files outside the
v2 integrity manifest, so every subsequent ``verify-usb`` reports
``integrity_ok=False`` (false positive), training users to ignore the exact
signal the F13/F26 evil-maid checks exist to give. Suppressing bytecode
(option 2 of the issue) keeps the manifest a strict allowlist.
"""

import os
import tempfile
import unittest
from pathlib import Path

from openssl_encrypt.modules.portable_media.usb_creator import USBDriveCreator


class TestPortableWrapperWritesNoBytecode(unittest.TestCase):
    """The generated wrapper suppresses bytecode for itself and children."""

    @classmethod
    def setUpClass(cls):
        """Generate the portable helper script into a temp dir once."""
        cls.tmp = Path(tempfile.mkdtemp())
        creator = USBDriveCreator()
        creator._create_transparent_encryption_helpers(cls.tmp)
        cls.wrapper = (cls.tmp / "crypt.py").read_text()

    def test_wrapper_disables_own_bytecode(self):
        """The wrapper never caches its own or the bundled lib's imports."""
        self.assertIn("sys.dont_write_bytecode = True", self.wrapper)

    def test_wrapper_children_inherit_suppression(self):
        """Spawned CLI subprocesses inherit PYTHONDONTWRITEBYTECODE."""
        self.assertIn('os.environ["PYTHONDONTWRITEBYTECODE"] = "1"', self.wrapper)

    def test_suppression_precedes_lib_imports(self):
        """The guard must run before any bundled-library import can cache."""
        guard = self.wrapper.index("sys.dont_write_bytecode = True")
        lib_import = self.wrapper.index("openssl_encrypt_lib")
        self.assertLess(guard, lib_import)

    def test_wrapper_import_writes_no_pycache(self):
        """Executing the wrapper's guard prologue leaves the media clean."""
        import subprocess
        import sys

        probe = self.tmp / "probe_module.py"
        probe.write_text("VALUE = 42\n")
        runner = self.tmp / "runner.py"
        # Reproduce the wrapper's prologue, then import a module from the
        # "drive": no __pycache__ may appear.
        prologue = "\n".join(
            line
            for line in self.wrapper.splitlines()
            if "dont_write_bytecode" in line or "PYTHONDONTWRITEBYTECODE" in line
        )
        runner.write_text(
            "import sys, os\n"
            + prologue
            + "\nsys.path.insert(0, os.path.dirname(__file__))\n"
            + "import probe_module\nprint(probe_module.VALUE)\n"
        )
        result = subprocess.run(
            [sys.executable, str(runner)], capture_output=True, text=True, timeout=60
        )
        self.assertEqual(result.stdout.strip(), "42", msg=result.stderr)
        self.assertFalse(
            (self.tmp / "__pycache__").exists(),
            msg="wrapper prologue must prevent bytecode on the media",
        )
