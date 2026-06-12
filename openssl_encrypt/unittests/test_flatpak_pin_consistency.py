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


if __name__ == "__main__":
    unittest.main()
