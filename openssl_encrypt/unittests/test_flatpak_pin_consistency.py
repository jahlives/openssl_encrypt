#!/usr/bin/env python3
"""
Flatpak manifest pins must match requirements-prod.txt.

The flatpak manifest installs production dependencies with its own
hard-coded `pip3 install 'pkg==version'` commands, which historically
drifted behind requirements-prod.txt (at one point three different
version sets existed across branches, including a cryptography pinned
two minors behind a CVE fix). This check fails whenever a package pinned
in BOTH files disagrees on the version.

Packages that appear in only one of the files are ignored: the manifest
legitimately carries GUI-only dependencies, and not every production
dependency ships in the flatpak.
"""

import json
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "flatpak" / "com.opensslencrypt.OpenSSLEncrypt.json"
REQUIREMENTS = REPO_ROOT / "requirements-prod.txt"

_PIN_RE = re.compile(r"'([A-Za-z0-9_.-]+)==([^']+)'")
_REQ_RE = re.compile(r"^([A-Za-z0-9_.\[\]-]+)==(\S+)", re.M)


def _normalize(name: str) -> str:
    """PEP 503 package-name normalization (Pillow == pillow, RandomX == randomx)."""
    return re.sub(r"[-_.]+", "-", name.split("[")[0]).lower()


def flatpak_pins(manifest_text: str) -> dict:
    """Extract {normalized_name: version} from pip install commands in the manifest.

    Args:
        manifest_text: Raw JSON text of the flatpak manifest.

    Returns:
        Mapping of normalized package name to pinned version string.
    """
    pins = {}
    manifest = json.loads(manifest_text)
    for module in manifest.get("modules", []):
        for command in module.get("build-commands", []):
            if "pip3 install" in command or "pip install" in command:
                for name, version in _PIN_RE.findall(command):
                    pins[_normalize(name)] = version
    return pins


def requirements_pins(requirements_text: str) -> dict:
    """Extract {normalized_name: version} from a pinned requirements file.

    Args:
        requirements_text: Raw text of requirements-prod.txt.

    Returns:
        Mapping of normalized package name to pinned version string.
    """
    pins = {}
    for name, version in _REQ_RE.findall(requirements_text):
        # Strip environment markers ("1 ; python_version >= ...")
        pins[_normalize(name)] = version.split(";")[0].strip()
    return pins


def find_mismatches(manifest_text: str, requirements_text: str) -> list:
    """Compare both pin sets; return mismatches for packages present in both.

    Returns:
        List of (package, manifest_version, requirements_version) tuples.
    """
    fp = flatpak_pins(manifest_text)
    rp = requirements_pins(requirements_text)
    return [(pkg, fp[pkg], rp[pkg]) for pkg in sorted(fp.keys() & rp.keys()) if fp[pkg] != rp[pkg]]


class TestPinExtraction(unittest.TestCase):
    """The parsers must handle name normalization and markers."""

    def test_flatpak_parser_normalizes_names(self):
        manifest = json.dumps(
            {
                "modules": [
                    {
                        "build-commands": [
                            "pip3 install --prefix=x 'Pillow==12.2.0'",
                            "pip3 install --prefix=x 'PyYAML==6.0.2' 'RandomX==1.1.10.post3'",
                        ]
                    }
                ]
            }
        )
        pins = flatpak_pins(manifest)
        self.assertEqual(pins["pillow"], "12.2.0")
        self.assertEqual(pins["pyyaml"], "6.0.2")
        self.assertEqual(pins["randomx"], "1.1.10.post3")

    def test_requirements_parser_strips_extras_and_markers(self):
        text = "qrcode[pil]==8.2\nwhirlpool-py311==1 ; python_version >= '3.11'\npillow==12.2.0\n"
        pins = requirements_pins(text)
        self.assertEqual(pins["qrcode"], "8.2")
        self.assertEqual(pins["whirlpool-py311"], "1")
        self.assertEqual(pins["pillow"], "12.2.0")

    def test_mismatch_detection(self):
        manifest = json.dumps(
            {"modules": [{"build-commands": ["pip3 install 'Pillow==12.1.0' 'idna==3.15'"]}]}
        )
        reqs = "pillow==12.2.0\nidna==3.15\nonly-in-reqs==1.0\n"
        self.assertEqual(find_mismatches(manifest, reqs), [("pillow", "12.1.0", "12.2.0")])

    def test_packages_in_only_one_file_are_ignored(self):
        manifest = json.dumps(
            {"modules": [{"build-commands": ["pip3 install 'gui-only-dep==1.0'"]}]}
        )
        self.assertEqual(find_mismatches(manifest, "prod-only==2.0\n"), [])


class TestRealFilesConsistent(unittest.TestCase):
    """The actual manifest must agree with the actual requirements-prod.txt."""

    def test_manifest_matches_requirements_prod(self):
        mismatches = find_mismatches(MANIFEST.read_text(), REQUIREMENTS.read_text())
        self.assertEqual(
            mismatches,
            [],
            msg="Flatpak manifest pins disagree with requirements-prod.txt "
            "(package, manifest, requirements): " + repr(mismatches),
        )

    def test_check_has_teeth(self):
        """The real files must share enough packages for the check to mean anything."""
        common = flatpak_pins(MANIFEST.read_text()).keys() & requirements_pins(
            REQUIREMENTS.read_text()
        )
        self.assertGreaterEqual(
            len(common),
            10,
            msg="Fewer than 10 packages pinned in both files — parsing likely broke.",
        )


def _module_installs_randomx_from_git(module: dict) -> bool:
    """True if any build command installs RandomX from a git URL."""
    return any(
        "randomx" in command.lower() and "git+" in command
        for command in module.get("build-commands", [])
    )


def _module_installs_randomx_from_pypi(module: dict) -> bool:
    """True if any build command installs a pinned RandomX from PyPI."""
    return any(
        _normalize(name) == "randomx"
        for command in module.get("build-commands", [])
        if "git+" not in command
        for name, _version in _PIN_RE.findall(command)
    )


class TestRandomXArchScoping(unittest.TestCase):
    """The personal RandomX fork is an aarch64 workaround (gitlab#282) and must
    not become the trust root for other architectures (gitlab#284).

    RandomX is a password-KDF stage: a tampered build could silently weaken
    derived keys, so the fork's blast radius must stay confined to the one
    arch whose PyPI build cannot import.
    """

    @classmethod
    def setUpClass(cls):
        cls.modules = json.loads(MANIFEST.read_text()).get("modules", [])

    def test_git_fork_confined_to_aarch64(self):
        offenders = [
            module["name"]
            for module in self.modules
            if _module_installs_randomx_from_git(module)
            and module.get("only-arches") != ["aarch64"]
        ]
        self.assertEqual(
            offenders,
            [],
            msg="Modules installing the RandomX git fork without "
            '"only-arches": ["aarch64"]: ' + repr(offenders),
        )

    def test_non_aarch64_gets_pypi_randomx(self):
        pypi_modules = [
            module
            for module in self.modules
            if _module_installs_randomx_from_pypi(module)
            and module.get("only-arches") != ["aarch64"]
        ]
        self.assertEqual(
            len(pypi_modules),
            1,
            msg="Expected exactly one module installing RandomX from PyPI for "
            "non-aarch64 arches",
        )
        self.assertEqual(
            pypi_modules[0].get("exclude-arches"),
            ["aarch64"],
            msg="The PyPI RandomX module must exclude aarch64, where that "
            "build cannot import (gitlab#282)",
        )


class TestRandomXForkCommitPin(unittest.TestCase):
    """The aarch64 RandomX fork must stay pinned to one full commit hash
    everywhere it is referenced (gitlab#283/#284 follow-up).

    A mutable ref (branch/tag) on a KDF-stage dependency is the CWE-494
    exposure test_liboqs_supply_chain_pin_252.py closes for liboqs; and a
    partial bump would hand aarch64 flatpak users a different RandomX binary
    than aarch64 pip users.
    """

    FORK_RE = re.compile(r"RandomX-Python(@[^\s'\"#;]*)?")
    COMMIT_RE = re.compile(r"@([0-9a-f]{40})\b")

    PIN_FILES = [
        MANIFEST,
        REPO_ROOT / "requirements.txt",
        REPO_ROOT / "requirements-prod.in",
        REPO_ROOT / "requirements-prod.txt",
        REPO_ROOT / "requirements-dev.txt",
        REPO_ROOT / "README.md",
    ]

    def test_every_fork_reference_is_commit_pinned_and_identical(self):
        shas = {}
        for path in self.PIN_FILES:
            text = path.read_text()
            refs = self.FORK_RE.findall(text)
            self.assertTrue(refs, msg=f"{path.name}: expected at least one fork reference")
            for ref in refs:
                match = self.COMMIT_RE.fullmatch(ref or "")
                self.assertIsNotNone(
                    match,
                    msg=f"{path.name}: fork reference must be pinned by a "
                    f"full 40-hex commit, found {ref!r}",
                )
                shas.setdefault(match.group(1), []).append(path.name)
        self.assertEqual(
            len(shas),
            1,
            msg="All fork references must pin the SAME commit: " + repr(shas),
        )


if __name__ == "__main__":
    unittest.main()
