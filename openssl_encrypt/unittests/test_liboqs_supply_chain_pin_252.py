#!/usr/bin/env python3
"""liboqs / liboqs-python must be built from pinned commit SHAs, not mutable tags
(scan findings F31/F33, gitlab#252, CWE-494).

The dependency build previously cloned liboqs from `--branch <tag>` and pip
installed liboqs-python from `@<tag>` with no integrity check, so a repointed
upstream tag could build/load arbitrary post-quantum crypto code on the user's
machine. Every build site now pins the commit and fails closed on mismatch: the
interactive installers (build_local_deps.sh, build_local_deps.ps1, the crypt_cli
inline fallback), the published Docker base image (docker/build-base-image.sh),
and the CI pipelines (.gitlab-ci.yml, .gitlab-ci-docker.yml) — plus the RandomX
assembly download in the PowerShell installer.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_SH = _ROOT / "scripts" / "build_local_deps.sh"
_PS1 = _ROOT / "scripts" / "build_local_deps.ps1"
_CLI = _ROOT / "openssl_encrypt" / "modules" / "crypt_cli.py"
_DOCKER = _ROOT / "docker" / "build-base-image.sh"
_CI = _ROOT / ".gitlab-ci.yml"
_CI_DOCKER = _ROOT / ".gitlab-ci-docker.yml"

_LIBOQS_SHA = "f4b96220e4bd208895172acc4fedb5a191d9f5b1"
_LIBOQS_PY_SHA = "7906e7879a099fa34217035957d977314f99757d"
_RANDOMX_SHA = "f9ae3f235183c452962edd2a15384bdc67f7a11e"


class TestLiboqsSupplyChainPin(unittest.TestCase):
    def _read(self, path):
        self.assertTrue(path.exists(), f"missing {path}")
        return path.read_text()

    def test_pinned_shas_are_full_40_hex(self):
        for sha in (_LIBOQS_SHA, _LIBOQS_PY_SHA):
            self.assertRegex(sha, r"^[0-9a-f]{40}$")

    def test_shell_script_pins_and_verifies(self):
        s = self._read(_SH)
        self.assertIn(_LIBOQS_SHA, s)
        self.assertIn(_LIBOQS_PY_SHA, s)
        # fail-closed verification of the clone against the pinned commit
        self.assertIn("rev-parse HEAD", s)
        self.assertRegex(s, r"LIBOQS_HEAD.*!=.*LIBOQS_COMMIT|LIBOQS_COMMIT.*!=.*LIBOQS_HEAD")
        # liboqs-python pip installs from the commit, not the mutable tag
        self.assertIn("liboqs-python.git@${LIBOQS_PYTHON_COMMIT}", s)
        self.assertNotIn("liboqs-python.git@${LIBOQS_PYTHON_VERSION}", s)

    def test_powershell_script_pins_and_verifies(self):
        s = self._read(_PS1)
        self.assertIn(_LIBOQS_SHA, s)
        self.assertIn(_LIBOQS_PY_SHA, s)
        self.assertIn("rev-parse HEAD", s)
        self.assertIn("-ne $LiboqsCommit", s)
        self.assertIn("liboqs-python.git@$LiboqsPythonCommit", s)
        self.assertNotIn("liboqs-python.git@$LiboqsPythonVersion", s)

    def test_cli_inline_fallback_pins_and_verifies(self):
        s = self._read(_CLI)
        self.assertIn(f'LIBOQS_PINNED_COMMIT = "{_LIBOQS_SHA}"', s)
        self.assertIn(f'LIBOQS_PYTHON_PINNED_COMMIT = "{_LIBOQS_PY_SHA}"', s)
        # the inline clone is verified against the pin
        self.assertIn("!= LIBOQS_PINNED_COMMIT", s)
        self.assertIn("rev-parse", s)
        # no mutable-tag liboqs-python install remains
        self.assertNotIn("liboqs-python.git@0.12.0", s)

    def test_docker_base_image_pins_and_verifies(self):
        s = self._read(_DOCKER)
        self.assertIn(_LIBOQS_SHA, s)
        self.assertIn(_LIBOQS_PY_SHA, s)
        self.assertIn("rev-parse HEAD", s)
        self.assertIn("${LIBOQS_COMMIT}", s)
        self.assertIn("liboqs-python.git@${LIBOQS_PYTHON_COMMIT}", s)

    def test_ci_docker_pins_and_verifies(self):
        s = self._read(_CI_DOCKER)
        self.assertIn(_LIBOQS_SHA, s)
        self.assertIn(_LIBOQS_PY_SHA, s)
        self.assertIn("rev-parse HEAD", s)
        self.assertIn("liboqs-python.git@${LIBOQS_PYTHON_COMMIT}", s)

    def test_ci_yaml_no_longer_floats_and_pins(self):
        s = self._read(_CI)
        self.assertIn(_LIBOQS_SHA, s)
        self.assertIn(_LIBOQS_PY_SHA, s)
        # the clone was floating on the default branch; it now pins + verifies
        self.assertIn("rev-parse HEAD", s)
        self.assertIn('= "$LIBOQS_COMMIT"', s)
        self.assertIn("liboqs-python.git@$LIBOQS_PYTHON_COMMIT", s)

    def test_randomx_asm_pinned_to_commit(self):
        s = self._read(_PS1)
        self.assertIn(_RANDOMX_SHA, s)
        self.assertIn("RandomX/$RandomXCommit/src", s)
        # the mutable refs/tags raw URL is gone
        self.assertNotIn("RandomX/refs/tags/$RandomXGitTag", s)

    def test_no_mutable_tag_liboqs_python_install_anywhere(self):
        # Guard against any file reintroducing the @<tag> form for liboqs-python.
        pat = re.compile(
            r"liboqs-python\.git@(0\.\d+\.\d+|\$?\{?LIBOQS_PYTHON_VERSION\}?|\$LiboqsPythonVersion\b)"
        )
        for path in (_SH, _PS1, _CLI, _DOCKER, _CI, _CI_DOCKER):
            self.assertIsNone(pat.search(self._read(path)), f"mutable tag install in {path.name}")

    def test_no_floating_liboqs_clone_anywhere(self):
        # A liboqs clone with neither --branch nor a following SHA verify is the
        # worst case; ensure every clone site carries a rev-parse verification.
        for path in (_SH, _PS1, _CLI, _DOCKER, _CI, _CI_DOCKER):
            s = self._read(path)
            if "liboqs.git" in s and "git clone" in s:
                self.assertIn(
                    "rev-parse HEAD", s, f"{path.name} clones liboqs without a SHA verify"
                )


if __name__ == "__main__":
    unittest.main()
