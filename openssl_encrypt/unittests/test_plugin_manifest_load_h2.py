"""End-to-end tests for signed-manifest package loading (H2 [PLUGIN-1]).

A package's __init__.py transitively imports sibling modules. With only a
single-file signature over __init__.py, a signed __init__.py + malicious
unsigned helper.py runs unchecked. The signed per-package manifest covers every
*.py; under ENFORCE a tampered/unlisted sibling must be refused.

Requires gpg (skipped otherwise).
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


def _gpg_or_skip(test):
    gpg = shutil.which("gpg")
    if not gpg:
        test.skipTest("gpg binary not available")
    return gpg


def _make_key(gpg, home: Path, uid: str):
    home.mkdir(mode=0o700, exist_ok=True)
    env = {"GNUPGHOME": str(home), "PATH": os.environ.get("PATH", "")}
    subprocess.run(
        [
            gpg,
            "--homedir",
            str(home),
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            uid,
            "ed25519",
            "sign",
            "0",
        ],
        check=True,
        capture_output=True,
        env=env,
    )
    listing = subprocess.run(
        [gpg, "--homedir", str(home), "--batch", "--with-colons", "--list-keys"],
        check=True,
        capture_output=True,
        env=env,
        text=True,
    ).stdout
    fpr = next(ln.split(":")[9] for ln in listing.splitlines() if ln.startswith("fpr:"))
    pub = subprocess.run(
        [gpg, "--homedir", str(home), "--batch", "--armor", "--export", fpr],
        check=True,
        capture_output=True,
        env=env,
    ).stdout
    return fpr, pub


PKG_INIT = b"""\
from .helper import CONTRIBUTION
from openssl_encrypt.modules.plugin_system import (
    PluginCapability,
    PluginResult,
    PluginType,
    PreProcessorPlugin,
)


class ManifestPkgPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("manifest_pkg", "Manifest Pkg Plugin", "1.0.0")

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES}

    def get_description(self):
        return "H2 manifest package plugin"

    def process_file(self, file_path, context):
        return PluginResult.success_result(CONTRIBUTION)
"""

PKG_HELPER = b"CONTRIBUTION = 'ok'\n"


@unittest.skipIf(shutil.which("gpg") is None, "gpg not available")
class TestManifestPackageLoad(unittest.TestCase):
    def setUp(self):
        self.gpg = _gpg_or_skip(self)
        self.tmp = Path(tempfile.mkdtemp())
        os.chmod(self.tmp, 0o700)
        self.fpr, self.pub = _make_key(self.gpg, self.tmp / "home", "Author <a@x.invalid>")

        # Trust-anchor store with the author key.
        self.anchor_dir = self.tmp / "anchors"
        self.anchor_dir.mkdir(mode=0o700)
        os.chmod(self.anchor_dir, 0o700)
        (self.anchor_dir / "author.asc").write_bytes(self.pub)

        # Package plugin dir (owner-only so H8 does not reject).
        self.pkg = self.tmp / "manifest_pkg"
        self.pkg.mkdir(mode=0o700)
        os.chmod(self.pkg, 0o700)
        (self.pkg / "__init__.py").write_bytes(PKG_INIT)
        (self.pkg / "helper.py").write_bytes(PKG_HELPER)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _sign_manifest(self):
        from openssl_encrypt.integrity.gpg_runner import detached_sign
        from openssl_encrypt.modules.plugin_system.plugin_manifest import (
            MANIFEST_FILENAME,
            build_manifest,
        )

        manifest = build_manifest(str(self.pkg))
        (self.pkg / MANIFEST_FILENAME).write_bytes(manifest)
        sig = detached_sign(manifest, self.fpr, home=self.tmp / "home")
        (self.pkg / (MANIFEST_FILENAME + ".asc")).write_bytes(sig)

    def _manager(self, policy):
        from openssl_encrypt.modules.plugin_system import PluginManager
        from openssl_encrypt.modules.plugin_system.plugin_config import PluginConfigManager
        from openssl_encrypt.modules.plugin_system.plugin_signature import PluginSignaturePolicy

        return PluginManager(
            config_manager=PluginConfigManager(),
            strict_security_mode=True,
            signature_policy=PluginSignaturePolicy(policy),
            trusted_keys_dir=str(self.anchor_dir),
            include_project_anchor=False,
        )

    # These assert on the security gate (_validate_plugin_file) directly: the
    # full load_plugin round-trip for a package under /tmp trips an unrelated
    # module-naming limitation (packages outside the project root), which is not
    # what H2 governs. The gate is exactly the signed-manifest boundary.

    def _init(self):
        return str(self.pkg / "__init__.py")

    def test_valid_manifest_package_passes_gate_under_enforce(self):
        self._sign_manifest()
        self.assertTrue(self._manager("enforce")._validate_plugin_file(self._init()))

    def test_tampered_sibling_refused_under_enforce(self):
        self._sign_manifest()
        # Attacker rewrites a sibling AFTER the manifest was signed.
        (self.pkg / "helper.py").write_bytes(b"CONTRIBUTION = 'pwned'\nimport os\n")
        self.assertFalse(self._manager("enforce")._validate_plugin_file(self._init()))

    def test_unlisted_sibling_refused_under_enforce(self):
        self._sign_manifest()
        # Attacker drops a new sibling not covered by the signed manifest.
        (self.pkg / "evil.py").write_bytes(b"BAD = 1\n")
        self.assertFalse(self._manager("enforce")._validate_plugin_file(self._init()))

    def test_impostor_signed_manifest_refused_under_enforce(self):
        # Manifest signed by a key that is NOT a trust anchor must be refused.
        from openssl_encrypt.integrity.gpg_runner import detached_sign
        from openssl_encrypt.modules.plugin_system.plugin_manifest import (
            MANIFEST_FILENAME,
            build_manifest,
        )

        imp_fpr, _ = _make_key(self.gpg, self.tmp / "imp", "Imp <i@x.invalid>")
        manifest = build_manifest(str(self.pkg))
        (self.pkg / MANIFEST_FILENAME).write_bytes(manifest)
        (self.pkg / (MANIFEST_FILENAME + ".asc")).write_bytes(
            detached_sign(manifest, imp_fpr, home=self.tmp / "imp")
        )
        self.assertFalse(self._manager("enforce")._validate_plugin_file(self._init()))

    def test_no_manifest_refused_under_enforce(self):
        self.assertFalse(self._manager("enforce")._validate_plugin_file(self._init()))

    def test_no_manifest_passes_gate_under_warn(self):
        self.assertTrue(self._manager("warn")._validate_plugin_file(self._init()))

    def test_cli_sign_package_round_trips_under_enforce(self):
        """The operator CLI helper sign_plugin_package must produce a manifest
        the loader accepts (sign -> verify round-trip)."""
        from openssl_encrypt.modules.plugin_system.plugin_signing_cli import sign_plugin_package

        sig_path = sign_plugin_package(str(self.pkg), self.fpr, home=self.tmp / "home")
        self.assertTrue(os.path.isfile(sig_path))
        self.assertTrue(self._manager("enforce")._validate_plugin_file(self._init()))

    def test_cli_sign_accepts_init_py_path(self):
        """Signing accepts the package __init__.py path (not just the dir)."""
        from openssl_encrypt.modules.plugin_system.plugin_signing_cli import sign_plugin_package

        sign_plugin_package(self._init(), self.fpr, home=self.tmp / "home")
        self.assertTrue(self._manager("enforce")._validate_plugin_file(self._init()))


if __name__ == "__main__":
    unittest.main()
