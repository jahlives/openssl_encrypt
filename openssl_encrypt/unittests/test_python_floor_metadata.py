#!/usr/bin/env python3
"""
Packaging metadata consistency: declared Python floor.

The pinned dependency set dictates the real floor (numpy 2.3 requires
Python >=3.11), so the declared metadata must match it everywhere —
otherwise pip happily starts an install on 3.9/3.10 that fails halfway
through dependency resolution. One floor, declared identically in the
main package and the threefish extension.
"""

import re
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON_FLOOR = ">=3.11"
SUPPORTED_MINORS = ["3.11", "3.12", "3.13", "3.14"]
DROPPED_MINORS = ["3.7", "3.8", "3.9", "3.10"]


class TestMainPackageFloor(unittest.TestCase):
    """setup.py must declare the real floor and matching classifiers."""

    def setUp(self):
        self.setup_py = (REPO_ROOT / "setup.py").read_text()

    def test_python_requires_is_3_11(self):
        match = re.search(r"python_requires\s*=\s*[\"']([^\"']+)[\"']", self.setup_py)
        self.assertIsNotNone(match, "setup.py must declare python_requires")
        self.assertEqual(match.group(1), PYTHON_FLOOR)

    def test_classifiers_match_floor(self):
        for minor in DROPPED_MINORS:
            self.assertNotIn(
                f"Programming Language :: Python :: {minor}",
                self.setup_py,
                msg=f"Classifier for unsupported Python {minor} must be removed",
            )
        for minor in SUPPORTED_MINORS:
            self.assertIn(
                f"Programming Language :: Python :: {minor}",
                self.setup_py,
                msg=f"Classifier for supported Python {minor} must be present",
            )


class TestThreefishExtensionFloor(unittest.TestCase):
    """The threefish extension must declare the same floor."""

    def setUp(self):
        path = REPO_ROOT / "threefish_native" / "pyproject.toml"
        self.pyproject = tomllib.loads(path.read_text())
        self.classifiers = self.pyproject["project"]["classifiers"]

    def test_requires_python_is_3_11(self):
        self.assertEqual(self.pyproject["project"]["requires-python"], PYTHON_FLOOR)

    def test_classifiers_match_floor(self):
        for minor in DROPPED_MINORS:
            self.assertNotIn(f"Programming Language :: Python :: {minor}", self.classifiers)
        for minor in SUPPORTED_MINORS:
            self.assertIn(f"Programming Language :: Python :: {minor}", self.classifiers)


if __name__ == "__main__":
    unittest.main()
