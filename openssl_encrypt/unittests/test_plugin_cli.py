"""Tests for the `plugin` management CLI (sign / trust-key / list-keys) — #66.

Drives plugin_cli.main() with argparse-style namespaces, so it exercises the
dispatch and argument handling without spawning a subprocess. Needs gpg;
skips cleanly without it.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path


def _gpg_or_skip(test: unittest.TestCase) -> str:
    gpg = shutil.which("gpg")
    if not gpg:
        test.skipTest("gpg binary not available")
    return gpg


def _make_key(gpg: str, home: Path, uid: str) -> tuple:
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


class TestPluginCli(unittest.TestCase):
    def setUp(self) -> None:
        self.gpg = _gpg_or_skip(self)
        self.tmp = Path(tempfile.mkdtemp())
        self.home = self.tmp / "home"
        self.fpr, self.pub = _make_key(self.gpg, self.home, "Me <me@example.invalid>")
        self.store = self.tmp / "trusted_plugin_keys"
        self.plugin = self.tmp / "p.py"
        self.plugin.write_text("VALUE = 1\n")
        self.keyfile = self.tmp / "me.pub"
        self.keyfile.write_bytes(self.pub)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _main(self, **kw) -> int:
        from openssl_encrypt.modules.plugin_system.plugin_cli import main

        ns = Namespace(
            plugin_action=kw.get("plugin_action"),
            plugin_file=kw.get("plugin_file"),
            signing_key=kw.get("signing_key"),
            trust_key_file=kw.get("trust_key_file"),
            trust_fingerprint=kw.get("trust_fingerprint"),
            trusted_keys_dir=kw.get("trusted_keys_dir", str(self.store)),
            gpg_home=kw.get("gpg_home"),
        )
        return main(ns)

    def test_trust_key_then_list(self) -> None:
        rc = self._main(
            plugin_action="trust-key",
            trust_key_file=str(self.keyfile),
            trust_fingerprint=self.fpr,
        )
        self.assertEqual(rc, 0)
        rc = self._main(plugin_action="list-keys")
        self.assertEqual(rc, 0)
        # The key file landed in the store.
        self.assertTrue(any(p.suffix == ".asc" for p in self.store.iterdir()))

    def test_trust_key_requires_fingerprint(self) -> None:
        rc = self._main(plugin_action="trust-key", trust_key_file=str(self.keyfile))
        self.assertNotEqual(rc, 0)

    def test_trust_key_rejects_wrong_fingerprint(self) -> None:
        rc = self._main(
            plugin_action="trust-key",
            trust_key_file=str(self.keyfile),
            trust_fingerprint="DEADBEEF" * 5,
        )
        self.assertNotEqual(rc, 0)

    def test_sign_writes_sidecar(self) -> None:
        rc = self._main(
            plugin_action="sign",
            plugin_file=str(self.plugin),
            signing_key=self.fpr,
            gpg_home=str(self.home),
        )
        self.assertEqual(rc, 0)
        self.assertTrue((self.tmp / "p.py.asc").is_file())

    def test_sign_missing_plugin(self) -> None:
        rc = self._main(
            plugin_action="sign",
            plugin_file=str(self.tmp / "nope.py"),
            signing_key=self.fpr,
            gpg_home=str(self.home),
        )
        self.assertNotEqual(rc, 0)

    def test_unknown_action(self) -> None:
        rc = self._main(plugin_action=None)
        self.assertNotEqual(rc, 0)

    def test_end_to_end_enrolled_and_signed_loads(self) -> None:
        """trust-key + sign via CLI produce an enforce-loadable plugin."""
        self._main(
            plugin_action="trust-key",
            trust_key_file=str(self.keyfile),
            trust_fingerprint=self.fpr,
        )
        pdir = self.tmp / "plugins"
        pdir.mkdir(mode=0o700)
        plugin = pdir / "signed_plugin.py"
        plugin.write_text(
            "from openssl_encrypt.modules.plugin_system import ("
            "PluginCapability, PluginResult, PluginType, PreProcessorPlugin)\n\n\n"
            "class P(PreProcessorPlugin):\n"
            "    def __init__(self):\n"
            "        super().__init__('cli_signed', 'CLI Signed', '1.0.0')\n"
            "    def get_plugin_type(self):\n"
            "        return PluginType.PRE_PROCESSOR\n"
            "    def get_required_capabilities(self):\n"
            "        return {PluginCapability.READ_FILES}\n"
            "    def get_description(self):\n"
            "        return 'x'\n"
            "    def process_file(self, file_path, context):\n"
            "        return PluginResult.success_result('ok')\n"
        )
        self._main(
            plugin_action="sign",
            plugin_file=str(plugin),
            signing_key=self.fpr,
            gpg_home=str(self.home),
        )

        from openssl_encrypt.modules.plugin_system import PluginManager
        from openssl_encrypt.modules.plugin_system.plugin_config import PluginConfigManager
        from openssl_encrypt.modules.plugin_system.plugin_signature import (
            PluginSignaturePolicy,
        )

        mgr = PluginManager(
            config_manager=PluginConfigManager(),
            signature_policy=PluginSignaturePolicy.ENFORCE,
            trusted_keys_dir=str(self.store),
        )
        result = mgr.load_plugin(str(plugin))
        self.assertTrue(result.success, result.message)


if __name__ == "__main__":
    unittest.main()
