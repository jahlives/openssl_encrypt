#!/usr/bin/env python3
"""
Published package metadata must be PyPI-uploadable and free of direct URLs.

setup.py historically derived install_requires by reading requirements-prod.txt
line-by-line (gitlab#283). That broke two ways once the lockfile gained the
aarch64 RandomX fork pin (gitlab#282):

- a PEP 508 direct reference (``randomx @ git+https://...``) landed in
  Requires-Dist, which Warehouse rejects outright — the next upload would fail,
  and it would put a personal git repository into the shipped dependency
  metadata of every aarch64 install;
- pip-compile's indented ``# via ...`` comments passed the raw
  ``line.startswith("#")`` filter and reached install_requires as invalid
  requirement strings.

These tests capture the kwargs setup.py passes to setuptools.setup() and pin
the contract: every declared requirement parses as PEP 508, none is a direct
URL, RandomX stays scoped off aarch64, and the declared set cannot drift from
requirements-prod.in.
"""

import os
import re
import runpy
import unittest
from pathlib import Path
from unittest import mock

from packaging.requirements import InvalidRequirement, Requirement

REPO_ROOT = Path(__file__).resolve().parents[2]


def _normalize(name: str) -> str:
    """PEP 503 package-name normalization (RandomX == randomx)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _captured_setup_kwargs() -> dict:
    """Execute setup.py with setuptools.setup() replaced by a recorder.

    Returns:
        The keyword arguments setup.py passed to setuptools.setup().
    """
    captured = {}

    def _record(**kwargs):
        captured.update(kwargs)

    old_cwd = os.getcwd()
    os.chdir(REPO_ROOT)  # setup.py opens its inputs via relative paths
    try:
        with mock.patch("setuptools.setup", _record):
            runpy.run_path(str(REPO_ROOT / "setup.py"), run_name="__main__")
    finally:
        os.chdir(old_cwd)
    return captured


def _all_declared_requirements(kwargs: dict) -> list:
    """Flatten install_requires plus every extras_require list.

    Returns:
        List of (origin, requirement_string) tuples for error messages.
    """
    entries = [("install_requires", line) for line in kwargs.get("install_requires", [])]
    for extra, lines in kwargs.get("extras_require", {}).items():
        entries.extend((f"extras_require[{extra}]", line) for line in lines)
    return entries


class TestPublishedMetadata(unittest.TestCase):
    """Requires-Dist content must be valid and PyPI-acceptable."""

    @classmethod
    def setUpClass(cls):
        cls.kwargs = _captured_setup_kwargs()
        cls.entries = _all_declared_requirements(cls.kwargs)

    def test_setup_declares_requirements(self):
        self.assertTrue(
            self.kwargs.get("install_requires"),
            msg="setup.py must declare install_requires",
        )
        self.assertGreaterEqual(
            len(self.kwargs["install_requires"]),
            10,
            msg="install_requires suspiciously small — parsing likely broke",
        )

    def test_every_requirement_parses_as_pep508(self):
        """Catches pip-compile '# via ...' comment lines leaking into metadata."""
        bad = []
        for origin, line in self.entries:
            try:
                Requirement(line)
            except InvalidRequirement:
                bad.append((origin, line))
        self.assertEqual(
            bad,
            [],
            msg="Invalid requirement strings in published metadata: " + repr(bad),
        )

    def test_no_direct_url_requirements(self):
        """PyPI rejects any distribution whose metadata contains a direct URL."""
        direct = []
        for origin, line in self.entries:
            try:
                if Requirement(line).url is not None:
                    direct.append((origin, line))
            except InvalidRequirement:
                # Reported by test_every_requirement_parses_as_pep508; a raw
                # URL fragment still counts as a direct reference here.
                if "://" in line or "git+" in line:
                    direct.append((origin, line))
        self.assertEqual(
            direct,
            [],
            msg="Direct-URL requirements must never reach published metadata "
            "(Warehouse rejects them; they add install-time trust in external "
            "repositories): " + repr(direct),
        )

    def test_randomx_declared_only_off_aarch64(self):
        """The PyPI RandomX build is broken on aarch64 (gitlab#282); published
        metadata must scope it away instead of shipping the git fork."""
        randomx = [
            Requirement(line)
            for line in self.kwargs.get("install_requires", [])
            if _normalize(Requirement(line).name) == "randomx"
        ]
        self.assertEqual(
            len(randomx),
            1,
            msg="install_requires must declare RandomX exactly once "
            "(the aarch64 fork line must not be there): " + repr([str(r) for r in randomx]),
        )
        req = randomx[0]
        self.assertIsNone(req.url, msg="RandomX must come from PyPI, not a URL")
        self.assertIsNotNone(req.marker, msg="RandomX must carry a platform_machine marker")
        self.assertIn(
            'platform_machine != "aarch64"',
            str(req.marker),
            msg="RandomX must be excluded on aarch64, where the PyPI build " "cannot import",
        )

    def test_install_requires_matches_requirements_prod_in(self):
        """Anti-drift: the explicit declaration must cover exactly the packages
        named in requirements-prod.in (the abstract dependency input)."""
        declared = {
            _normalize(Requirement(line).name) for line in self.kwargs.get("install_requires", [])
        }
        in_file = set()
        for raw in (REPO_ROOT / "requirements-prod.in").read_text().splitlines():
            # Strip trailing inline comments ("pkg>=1.0  # rationale")
            line = re.sub(r"\s+#.*$", "", raw.strip())
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            in_file.add(_normalize(Requirement(line).name))
        self.assertEqual(
            declared,
            in_file,
            msg="setup.py install_requires and requirements-prod.in name "
            "different package sets; update both together",
        )


if __name__ == "__main__":
    unittest.main()
