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

    setup.py regenerates openssl_encrypt/version.py at import time; that file
    is snapshotted and restored so a parallel test worker importing the
    package never observes a half-written file.

    Returns:
        The keyword arguments setup.py passed to setuptools.setup().
    """
    captured = {}

    def _record(**kwargs):
        captured.update(kwargs)

    version_path = REPO_ROOT / "openssl_encrypt" / "version.py"
    version_snapshot = version_path.read_bytes() if version_path.exists() else None
    old_cwd = os.getcwd()
    os.chdir(REPO_ROOT)  # setup.py opens its inputs via relative paths
    try:
        with mock.patch("setuptools.setup", _record):
            runpy.run_path(str(REPO_ROOT / "setup.py"), run_name="__main__")
    finally:
        os.chdir(old_cwd)
        if version_snapshot is not None:
            version_path.write_bytes(version_snapshot)
        elif version_path.exists():
            version_path.unlink()
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


@unittest.skipUnless(
    (REPO_ROOT / "setup.py").exists() and (REPO_ROOT / "requirements-prod.in").exists(),
    "packaging metadata checks need a repository checkout",
)
class TestPublishedMetadata(unittest.TestCase):
    """Requires-Dist content must be valid and PyPI-acceptable."""

    @classmethod
    def setUpClass(cls):
        """Capture the setup() kwargs once for all assertions."""
        cls.kwargs = _captured_setup_kwargs()
        cls.entries = _all_declared_requirements(cls.kwargs)

    def test_setup_declares_requirements(self):
        """A non-empty install_requires reaches setuptools.setup().

        Completeness is enforced exactly by
        test_install_requires_matches_requirements_prod_in.
        """
        self.assertTrue(
            self.kwargs.get("install_requires"),
            msg="setup.py must declare install_requires",
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
        """Published metadata must not contain direct URLs (rejected by PyPI)."""
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

    def test_randomx_ships_as_project_binding_on_every_arch(self):
        """The RandomX stage ships as the project-owned openssl-encrypt-randomx binding
        (gitlab#285/#293); the abandoned PyPI ``RandomX`` package and the
        aarch64 fork (gitlab#282 history) must not reappear in metadata.
        """
        legacy = [
            line
            for line in self.kwargs.get("install_requires", [])
            if _normalize(Requirement(line).name) == "randomx"
        ]
        self.assertEqual(
            legacy,
            [],
            msg="The abandoned PyPI RandomX package must not be declared "
            "(gitlab#293 replaced it): " + repr(legacy),
        )
        binding = [
            Requirement(line)
            for line in self.kwargs.get("install_requires", [])
            if _normalize(Requirement(line).name) == "openssl-encrypt-randomx"
        ]
        self.assertEqual(
            len(binding),
            1,
            msg="install_requires must declare openssl-encrypt-randomx "
            "exactly once: " + repr([str(r) for r in binding]),
        )
        req = binding[0]
        self.assertIsNone(req.url, msg="openssl-encrypt-randomx must come from PyPI, not a URL")
        self.assertIsNone(
            req.marker,
            msg="openssl-encrypt-randomx serves every arch — no platform "
            "marker (the aarch64 split ended with the fork retirement)",
        )

    def test_install_requires_matches_requirements_prod_in(self):
        """Anti-drift: the explicit declaration must cover exactly the packages
        named in requirements-prod.in (the abstract dependency input).
        """
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


class TestReadRequirementsHashedLockfiles(unittest.TestCase):
    """pip-compile --generate-hashes lockfiles must parse cleanly (gitlab#300).

    Hash mode writes each requirement as ``name==ver \\`` followed by
    indented ``--hash=sha256:...`` continuation lines. The option lines are
    already skipped (they start with ``-``), but the trailing backslash on
    the requirement itself must be stripped or it reaches extras metadata as
    an invalid requirement string.
    """

    def test_hash_continuation_lines_stripped(self):
        """A hashed-lockfile entry yields a clean PEP 508 string."""
        import tempfile

        version_path = REPO_ROOT / "openssl_encrypt" / "version.py"
        version_snapshot = version_path.read_bytes() if version_path.exists() else None
        old_cwd = os.getcwd()
        os.chdir(REPO_ROOT)
        try:
            with mock.patch("setuptools.setup", lambda **kwargs: None):
                module_globals = runpy.run_path(str(REPO_ROOT / "setup.py"), run_name="__main__")
        finally:
            os.chdir(old_cwd)
            if version_snapshot is not None:
                version_path.write_bytes(version_snapshot)
            elif version_path.exists():
                version_path.unlink()
        read_requirements = module_globals["read_requirements"]

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "requirements-hashed.txt")
            with open(path, "w") as f:
                f.write(
                    "annotated-types==0.7.0 \\\n"
                    "    --hash=sha256:aaaa \\\n"
                    "    --hash=sha256:bbbb\n"
                    "    # via pydantic\n"
                    "zxcvbn==4.5.0\n"
                )
            self.assertEqual(read_requirements(path), ["annotated-types==0.7.0", "zxcvbn==4.5.0"])


if __name__ == "__main__":
    unittest.main()
