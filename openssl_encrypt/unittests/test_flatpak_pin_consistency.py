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
        """Package names in pip commands normalize per PEP 503."""
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
        """Extras and environment markers are stripped from pins."""
        text = "qrcode[pil]==8.2\nwhirlpool-py311==1 ; python_version >= '3.11'\npillow==12.2.0\n"
        pins = requirements_pins(text)
        self.assertEqual(pins["qrcode"], "8.2")
        self.assertEqual(pins["whirlpool-py311"], "1")
        self.assertEqual(pins["pillow"], "12.2.0")

    def test_mismatch_detection(self):
        """A version disagreement on a shared package is reported."""
        manifest = json.dumps(
            {"modules": [{"build-commands": ["pip3 install 'Pillow==12.1.0' 'idna==3.15'"]}]}
        )
        reqs = "pillow==12.2.0\nidna==3.15\nonly-in-reqs==1.0\n"
        self.assertEqual(find_mismatches(manifest, reqs), [("pillow", "12.1.0", "12.2.0")])

    def test_packages_in_only_one_file_are_ignored(self):
        """Packages pinned in only one file produce no mismatch."""
        manifest = json.dumps(
            {"modules": [{"build-commands": ["pip3 install 'gui-only-dep==1.0'"]}]}
        )
        self.assertEqual(find_mismatches(manifest, "prod-only==2.0\n"), [])


class TestRealFilesConsistent(unittest.TestCase):
    """The actual manifest must agree with the actual requirements-prod.txt."""

    def test_manifest_matches_requirements_prod(self):
        """Every shared pin agrees between manifest and lockfile."""
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


class TestRandomXProjectBinding(unittest.TestCase):
    """RandomX ships as the project-owned openssl-encrypt-randomx binding on
    every arch (gitlab#285/#293), replacing the abandoned PyPI `RandomX`
    package and the aarch64 fork workaround (gitlab#282/#284 history).

    RandomX is a password-KDF stage: a tampered or diverging build could
    silently weaken derived keys, so neither legacy install source may creep
    back in, and every install surface must pin the SAME version — a partial
    bump would hand flatpak users a different RandomX binary than pip users.
    """

    # The retired fork (jahlives/RandomX-Python) — must not reappear anywhere.
    FORK_RE = re.compile(r"RandomX-Python")
    # A legacy `RandomX`/`randomx` pin or git install. The leading
    # (?<![\w-]) keeps `openssl-encrypt-randomx==...` from matching.
    LEGACY_RE = re.compile(r"(?i)(?<![\w-])randomx\s*(?:==|>=|@)")

    PIN_FILES = [
        MANIFEST,
        REPO_ROOT / "requirements.txt",
        REPO_ROOT / "requirements-prod.in",
        REPO_ROOT / "requirements-prod.txt",
        REPO_ROOT / "requirements-dev.txt",
        REPO_ROOT / "README.md",
        REPO_ROOT / "setup.py",
    ]

    def test_no_fork_or_legacy_randomx_references(self):
        """No file references the retired fork or the abandoned PyPI pin."""
        offenders = {}
        for path in self.PIN_FILES:
            text = path.read_text()
            hits = self.FORK_RE.findall(text) + self.LEGACY_RE.findall(text)
            if hits:
                offenders[path.name] = hits
        self.assertEqual(
            offenders,
            {},
            msg="Legacy RandomX/fork install references must not reappear "
            "(gitlab#293 retired them): " + repr(offenders),
        )

    def test_project_binding_pinned_same_version_everywhere(self):
        """Every install surface pins the same binding version."""
        versions = {}
        install_files = [
            MANIFEST,
            REPO_ROOT / "requirements.txt",
            REPO_ROOT / "requirements-prod.in",
            REPO_ROOT / "requirements-prod.txt",
            REPO_ROOT / "requirements-dev.txt",
        ]
        for path in install_files:
            text = path.read_text()
            pins = flatpak_pins(text) if path == MANIFEST else requirements_pins(text)
            version = pins.get("openssl-encrypt-randomx")
            self.assertIsNotNone(
                version,
                msg=f"{path.name}: expected an exact openssl-encrypt-randomx "
                "pin (the RandomX KDF binding must ship on every arch)",
            )
            versions.setdefault(version, []).append(path.name)
        self.assertEqual(
            len(versions),
            1,
            msg="All install surfaces must pin the SAME "
            "openssl-encrypt-randomx version: " + repr(versions),
        )

    def test_manifest_module_covers_all_arches(self):
        """Exactly one flatpak module installs the binding, unrestricted."""
        modules = json.loads(MANIFEST.read_text()).get("modules", [])
        randomx_modules = [
            module
            for module in modules
            for command in module.get("build-commands", [])
            if "openssl-encrypt-randomx" in command
        ]
        self.assertEqual(
            len(randomx_modules),
            1,
            msg="Expected exactly one flatpak module installing " "openssl-encrypt-randomx",
        )
        module = randomx_modules[0]
        self.assertNotIn(
            "only-arches",
            module,
            msg="The openssl-encrypt-randomx module must serve every arch",
        )
        self.assertNotIn(
            "exclude-arches",
            module,
            msg="The openssl-encrypt-randomx module must serve every arch",
        )

    def test_setup_py_requires_project_binding(self):
        """The published metadata declares the project-owned binding."""
        text = (REPO_ROOT / "setup.py").read_text()
        self.assertIn(
            "openssl-encrypt-randomx",
            text,
            msg="setup.py install_requires must carry the project-owned " "RandomX binding",
        )


if __name__ == "__main__":
    unittest.main()
