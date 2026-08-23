#!/usr/bin/env python3
"""The compiled lockfiles must stay fully hash-pinned (gitlab#300).

pip's hash-checking mode is all-or-nothing per file, and pip only enforces it
automatically when hashes are present — so a regeneration that silently drops
the hashes (e.g. pip-compile without --generate-hashes) would downgrade every
``--require-hashes`` consumer back to unpinned installs without an error.
These tests pin the hashed state, and that the refresh script keeps it.
"""

import os
import re
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOCKFILES = ("requirements-prod.txt", "requirements-dev.txt")

_REQ_LINE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\[\]-]*==", re.M)


class TestLockfilesStayHashed(unittest.TestCase):
    """Every pinned requirement carries at least one --hash entry."""

    def test_every_pin_is_hashed(self):
        """No pinned entry may appear without hashes (all-or-nothing mode)."""
        for name in LOCKFILES:
            with self.subTest(lockfile=name):
                text = open(os.path.join(REPO_ROOT, name)).read()
                pins = len(_REQ_LINE.findall(text))
                self.assertGreater(pins, 0, msg=f"{name}: no pins parsed")
                # In --generate-hashes output every pinned requirement line
                # ends with the continuation marker introducing its hashes.
                unhashed = [
                    line
                    for line in text.splitlines()
                    if _REQ_LINE.match(line) and not line.rstrip().endswith("\\")
                ]
                self.assertEqual(
                    unhashed,
                    [],
                    msg=f"{name}: pinned entries without hash continuation "
                    "(regenerate with pip-compile --generate-hashes): " + repr(unhashed),
                )
                self.assertIn("--hash=sha256:", text, msg=f"{name}: no hashes at all")

    def test_requirements_txt_is_a_pure_include(self):
        """requirements.txt must stay a pointer to the hashed lockfile.

        gitlab#301: the documented ``pip install -r requirements.txt`` path
        is folded onto requirements-prod.txt via an include — pip enforces
        hash-checking automatically through it. A version specifier creeping
        back into this file would reintroduce an unhashed install surface
        silently, so none may appear.
        """
        text = open(os.path.join(REPO_ROOT, "requirements.txt")).read()
        self.assertIn("-r requirements-prod.txt", text)
        speclike = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith(("#", "-r "))
        ]
        self.assertEqual(
            speclike,
            [],
            msg="requirements.txt must contain only comments and the lockfile "
            "include (gitlab#301); found: " + repr(speclike),
        )

    def test_update_script_keeps_hashes(self):
        """scripts/update_dependencies.sh must regenerate WITH hashes."""
        text = open(os.path.join(REPO_ROOT, "scripts", "update_dependencies.sh")).read()
        compile_lines = [line for line in text.splitlines() if "pip-compile" in line]
        self.assertTrue(compile_lines, msg="no pip-compile lines found")
        for line in compile_lines:
            self.assertIn(
                "--generate-hashes",
                line,
                msg="pip-compile without --generate-hashes would silently "
                "drop the hash pins (gitlab#300): " + line,
            )
