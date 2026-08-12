"""Tests for signature-gated plugin loading (#66 / CLI-3).

Covers the verifier module (trust-anchor store + detached-signature check)
in isolation. Loader-integration and policy-matrix tests live alongside the
existing plugin tests once the loader wiring lands.

These tests need a real ``gpg`` binary; they skip cleanly without one.
"""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path


def _gpg_or_skip(test: unittest.TestCase) -> str:
    gpg = shutil.which("gpg")
    if not gpg:
        test.skipTest("gpg binary not available")
    return gpg


def _make_ephemeral_key(gpg: str, home: Path, uid: str) -> tuple:
    """Create an Ed25519 signing key in an isolated GNUPGHOME.

    Returns (fingerprint, armored_public_key_bytes).
    """
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
    fpr = ""
    for line in listing.splitlines():
        if line.startswith("fpr:"):
            fpr = line.split(":")[9]
            break
    pub = subprocess.run(
        [gpg, "--homedir", str(home), "--batch", "--armor", "--export", fpr],
        check=True,
        capture_output=True,
        env=env,
    ).stdout
    return fpr, pub


class _SigningFixture(unittest.TestCase):
    """Base fixture: two independent ephemeral keys (author + impostor)."""

    def setUp(self) -> None:
        self.gpg = _gpg_or_skip(self)
        self.tmp = Path(tempfile.mkdtemp())
        self.author_fpr, self.author_pub = _make_ephemeral_key(
            self.gpg, self.tmp / "author_home", "Plugin Author <author@example.invalid>"
        )
        self.impostor_fpr, self.impostor_pub = _make_ephemeral_key(
            self.gpg, self.tmp / "impostor_home", "Impostor <evil@example.invalid>"
        )
        self.plugin_bytes = b"# a totally legitimate plugin\nVALUE = 1\n"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _sign(self, data: bytes, fpr: str, home_name: str) -> bytes:
        from openssl_encrypt.integrity.gpg_runner import detached_sign

        return detached_sign(data, fpr, home=self.tmp / home_name)


class TestTrustAnchorStore(_SigningFixture):
    """Loading enrolled public keys from an owner-only directory."""

    def _store_dir(self, mode: int = 0o700) -> Path:
        d = self.tmp / "trusted_plugin_keys"
        d.mkdir(mode=mode, exist_ok=True)
        os.chmod(d, mode)
        return d

    def test_loads_enrolled_key(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signature import TrustAnchorStore

        d = self._store_dir()
        (d / "author.asc").write_bytes(self.author_pub)
        anchors = TrustAnchorStore(str(d)).load_anchors()
        self.assertEqual(len(anchors), 1)
        self.assertTrue(
            self.author_fpr.endswith(anchors[0].fingerprint)
            or anchors[0].fingerprint == self.author_fpr
        )

    def test_ignores_non_asc_files(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signature import TrustAnchorStore

        d = self._store_dir()
        (d / "author.asc").write_bytes(self.author_pub)
        (d / "README.txt").write_bytes(b"not a key")
        self.assertEqual(len(TrustAnchorStore(str(d)).load_anchors()), 1)

    def test_missing_dir_yields_no_anchors(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signature import TrustAnchorStore

        anchors = TrustAnchorStore(str(self.tmp / "does_not_exist")).load_anchors()
        self.assertEqual(anchors, [])

    @unittest.skipIf(os.name == "nt", "POSIX permission semantics")
    def test_group_writable_store_is_refused(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signature import (
            TrustAnchorError,
            TrustAnchorStore,
        )

        d = self._store_dir(mode=0o770)
        (d / "author.asc").write_bytes(self.author_pub)
        with self.assertRaises(TrustAnchorError):
            TrustAnchorStore(str(d)).load_anchors()

    @unittest.skipIf(os.name == "nt", "POSIX permission semantics")
    def test_group_writable_key_file_is_skipped(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signature import TrustAnchorStore

        d = self._store_dir()
        good = d / "author.asc"
        good.write_bytes(self.author_pub)
        bad = d / "impostor.asc"
        bad.write_bytes(self.impostor_pub)
        os.chmod(bad, 0o666)  # world-writable key file: an injected anchor
        anchors = TrustAnchorStore(str(d)).load_anchors()
        fprs = [a.fingerprint for a in anchors]
        self.assertTrue(any(self.author_fpr.endswith(f) for f in fprs))
        self.assertFalse(any(self.impostor_fpr.endswith(f) for f in fprs))


class TestVerifyPluginSignature(_SigningFixture):
    """The detached-signature gate over plugin bytes."""

    def _anchor(self, pub: bytes, fpr: str):
        from openssl_encrypt.modules.plugin_system.plugin_signature import TrustAnchor

        return TrustAnchor(fingerprint=fpr, public_key=pub, label="test")

    def test_valid_signature_from_enrolled_key(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signature import verify_plugin_signature

        sig = self._sign(self.plugin_bytes, self.author_fpr, "author_home")
        sig_path = self.tmp / "plugin.py.asc"
        sig_path.write_bytes(sig)
        verdict = verify_plugin_signature(
            self.plugin_bytes, str(sig_path), [self._anchor(self.author_pub, self.author_fpr)]
        )
        self.assertTrue(verdict.verified)
        self.assertTrue(
            self.author_fpr.endswith(verdict.fingerprint) or verdict.fingerprint == self.author_fpr
        )

    def test_missing_signature_file(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signature import verify_plugin_signature

        verdict = verify_plugin_signature(
            self.plugin_bytes,
            str(self.tmp / "nonexistent.py.asc"),
            [self._anchor(self.author_pub, self.author_fpr)],
        )
        self.assertFalse(verdict.verified)
        self.assertIn("no signature", verdict.reason.lower())

    def test_signature_from_unenrolled_key_rejected(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signature import verify_plugin_signature

        # Impostor signs, but only the author key is enrolled as an anchor.
        sig = self._sign(self.plugin_bytes, self.impostor_fpr, "impostor_home")
        sig_path = self.tmp / "plugin.py.asc"
        sig_path.write_bytes(sig)
        verdict = verify_plugin_signature(
            self.plugin_bytes, str(sig_path), [self._anchor(self.author_pub, self.author_fpr)]
        )
        self.assertFalse(verdict.verified)

    def test_tampered_plugin_bytes_rejected(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signature import verify_plugin_signature

        sig = self._sign(self.plugin_bytes, self.author_fpr, "author_home")
        sig_path = self.tmp / "plugin.py.asc"
        sig_path.write_bytes(sig)
        tampered = self.plugin_bytes + b"\nimport os; os.system('rm -rf ~')\n"
        verdict = verify_plugin_signature(
            tampered, str(sig_path), [self._anchor(self.author_pub, self.author_fpr)]
        )
        self.assertFalse(verdict.verified)

    def test_no_anchors_rejects(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signature import verify_plugin_signature

        sig = self._sign(self.plugin_bytes, self.author_fpr, "author_home")
        sig_path = self.tmp / "plugin.py.asc"
        sig_path.write_bytes(sig)
        verdict = verify_plugin_signature(self.plugin_bytes, str(sig_path), [])
        self.assertFalse(verdict.verified)
        self.assertIn("no trust anchor", verdict.reason.lower())


class TestSignaturePolicy(unittest.TestCase):
    """The policy enum parsing used by the loader/CLI."""

    def test_policy_values(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signature import PluginSignaturePolicy

        self.assertEqual(PluginSignaturePolicy("off"), PluginSignaturePolicy.OFF)
        self.assertEqual(PluginSignaturePolicy("warn"), PluginSignaturePolicy.WARN)
        self.assertEqual(PluginSignaturePolicy("enforce"), PluginSignaturePolicy.ENFORCE)


# A benign, AST-clean plugin usable end-to-end through the loader.
_LOADER_PLUGIN = """
from openssl_encrypt.modules.plugin_system import (
    PluginCapability,
    PluginResult,
    PluginType,
    PreProcessorPlugin,
)


class SignedTestPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("signed_test", "Signed Test Plugin", "1.0.0")

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES}

    def get_description(self):
        return "Signed test plugin"

    def process_file(self, file_path, context):
        return PluginResult.success_result("ok")
"""


class TestLoaderSignaturePolicy(_SigningFixture):
    """End-to-end: the loader honors the signature policy."""

    def setUp(self) -> None:
        super().setUp()
        from openssl_encrypt.modules.plugin_system import PluginManager
        from openssl_encrypt.modules.plugin_system.plugin_config import PluginConfigManager

        self.PluginManager = PluginManager
        self.PluginConfigManager = PluginConfigManager

        # Owner-only plugin dir (so the H8 location check passes) and key store.
        self.plugin_dir = self.tmp / "plugins"
        self.plugin_dir.mkdir(mode=0o700)
        self.plugin_path = self.plugin_dir / "signed_plugin.py"
        self.plugin_path.write_text(_LOADER_PLUGIN)

        self.keys_dir = self.tmp / "trusted_plugin_keys"
        self.keys_dir.mkdir(mode=0o700)
        (self.keys_dir / "author.asc").write_bytes(self.author_pub)

    def _manager(self, policy_str: str):
        from openssl_encrypt.modules.plugin_system.plugin_signature import PluginSignaturePolicy

        return self.PluginManager(
            config_manager=self.PluginConfigManager(),
            strict_security_mode=True,
            signature_policy=PluginSignaturePolicy(policy_str),
            trusted_keys_dir=str(self.keys_dir),
        )

    def _write_signature(self, fpr: str, home_name: str, over: bytes = None) -> None:
        data = self.plugin_path.read_bytes() if over is None else over
        sig = self._sign(data, fpr, home_name)
        (self.plugin_dir / "signed_plugin.py.asc").write_bytes(sig)

    def test_enforce_refuses_unsigned(self) -> None:
        result = self._manager("enforce").load_plugin(str(self.plugin_path))
        self.assertFalse(result.success)

    def test_enforce_accepts_valid_signature(self) -> None:
        self._write_signature(self.author_fpr, "author_home")
        result = self._manager("enforce").load_plugin(str(self.plugin_path))
        self.assertTrue(result.success, result.message)

    def test_enforce_refuses_impostor_signature(self) -> None:
        # Impostor signs; only the author key is enrolled.
        self._write_signature(self.impostor_fpr, "impostor_home")
        result = self._manager("enforce").load_plugin(str(self.plugin_path))
        self.assertFalse(result.success)

    def test_enforce_refuses_signature_over_other_bytes(self) -> None:
        # Valid author signature, but over different bytes than the plugin file.
        self._write_signature(self.author_fpr, "author_home", over=b"different content")
        result = self._manager("enforce").load_plugin(str(self.plugin_path))
        self.assertFalse(result.success)

    def test_default_policy_refuses_unsigned(self) -> None:
        # gitlab#130 regression: with NO explicit signature_policy the loader
        # default is ENFORCE, so an unsigned non-built-in plugin is refused
        # rather than exec'd behind the bypassable AST denylist. Pre-fix the
        # constructor default was WARN and this same plugin loaded successfully.
        from openssl_encrypt.modules.plugin_system.plugin_signature import PluginSignaturePolicy

        manager = self.PluginManager(
            config_manager=self.PluginConfigManager(),
            strict_security_mode=True,
            trusted_keys_dir=str(self.keys_dir),
        )
        self.assertEqual(manager.signature_policy, PluginSignaturePolicy.ENFORCE)
        result = manager.load_plugin(str(self.plugin_path))
        self.assertFalse(
            result.success,
            "default-policy loader must refuse an unsigned non-built-in plugin",
        )

    def test_warn_loads_unsigned(self) -> None:
        result = self._manager("warn").load_plugin(str(self.plugin_path))
        self.assertTrue(result.success, result.message)

    def test_off_loads_unsigned(self) -> None:
        result = self._manager("off").load_plugin(str(self.plugin_path))
        self.assertTrue(result.success, result.message)


class TestSigningCliHelpers(_SigningFixture):
    """Operator-facing sign / enroll / list helpers."""

    def test_sign_plugin_produces_loadable_signature(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signature import (
            TrustAnchor,
            verify_plugin_signature,
        )
        from openssl_encrypt.modules.plugin_system.plugin_signing_cli import sign_plugin

        plugin = self.tmp / "p.py"
        plugin.write_text("VALUE = 1\n")
        sig_path = sign_plugin(str(plugin), self.author_fpr, home=self.tmp / "author_home")
        self.assertTrue(os.path.isfile(sig_path))
        self.assertEqual(sig_path, str(plugin) + ".asc")

        verdict = verify_plugin_signature(
            plugin.read_bytes(),
            sig_path,
            [TrustAnchor(self.author_fpr, self.author_pub, "author")],
        )
        self.assertTrue(verdict.verified)

    def test_enroll_requires_fingerprint_confirmation(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signing_cli import enroll_trust_key

        keyfile = self.tmp / "author.pub"
        keyfile.write_bytes(self.author_pub)
        store = self.tmp / "store"
        with self.assertRaises(ValueError):
            enroll_trust_key(str(keyfile), trusted_keys_dir=str(store))

    def test_enroll_rejects_fingerprint_mismatch(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signing_cli import enroll_trust_key

        keyfile = self.tmp / "author.pub"
        keyfile.write_bytes(self.author_pub)
        store = self.tmp / "store"
        with self.assertRaises(ValueError):
            enroll_trust_key(
                str(keyfile),
                trusted_keys_dir=str(store),
                confirm_fingerprint="DEADBEEF" * 5,
            )

    def test_enroll_rejects_short_key_id_suffix(self) -> None:
        # gitlab#136 (F21): a short key id that is merely a SUFFIX of the full
        # fingerprint used to be accepted (endswith match), letting a crafted
        # colliding key be enrolled. It must now be rejected — only an exact,
        # full-length fingerprint match enrolls.
        from openssl_encrypt.modules.plugin_system.plugin_signing_cli import enroll_trust_key

        keyfile = self.tmp / "author.pub"
        keyfile.write_bytes(self.author_pub)
        store = self.tmp / "store"
        short_id = self.author_fpr[-8:]  # 32-bit short key id (a genuine suffix)
        with self.assertRaises(ValueError):
            enroll_trust_key(
                str(keyfile),
                trusted_keys_dir=str(store),
                confirm_fingerprint=short_id,
            )
        # And a longer-but-still-partial suffix is rejected too.
        with self.assertRaises(ValueError):
            enroll_trust_key(
                str(keyfile),
                trusted_keys_dir=str(store),
                confirm_fingerprint=self.author_fpr[8:],
            )

    def test_enroll_then_list(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signing_cli import (
            enroll_trust_key,
            list_trust_keys,
        )

        keyfile = self.tmp / "author.pub"
        keyfile.write_bytes(self.author_pub)
        store = self.tmp / "store"
        anchor = enroll_trust_key(
            str(keyfile),
            trusted_keys_dir=str(store),
            confirm_fingerprint=self.author_fpr,
        )
        self.assertTrue(self.author_fpr.endswith(anchor.fingerprint))
        # Enrolled file is owner-only.
        dest = store / anchor.label
        self.assertTrue(dest.is_file())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(os.stat(dest).st_mode), 0o600)

        listed = list_trust_keys(trusted_keys_dir=str(store))
        self.assertEqual(len(listed), 1)

    def test_enrolled_key_makes_plugin_loadable(self) -> None:
        """Full loop: enroll author key, sign a plugin, load under enforce."""
        from openssl_encrypt.modules.plugin_system import PluginManager
        from openssl_encrypt.modules.plugin_system.plugin_config import PluginConfigManager
        from openssl_encrypt.modules.plugin_system.plugin_signature import PluginSignaturePolicy
        from openssl_encrypt.modules.plugin_system.plugin_signing_cli import (
            enroll_trust_key,
            sign_plugin,
        )

        plugin_dir = self.tmp / "plugins2"
        plugin_dir.mkdir(mode=0o700)
        plugin_path = plugin_dir / "signed_plugin.py"
        plugin_path.write_text(_LOADER_PLUGIN)

        keyfile = self.tmp / "author.pub"
        keyfile.write_bytes(self.author_pub)
        store = self.tmp / "store2"
        enroll_trust_key(
            str(keyfile),
            trusted_keys_dir=str(store),
            confirm_fingerprint=self.author_fpr,
        )
        sign_plugin(str(plugin_path), self.author_fpr, home=self.tmp / "author_home")

        manager = PluginManager(
            config_manager=PluginConfigManager(),
            signature_policy=PluginSignaturePolicy.ENFORCE,
            trusted_keys_dir=str(store),
        )
        result = manager.load_plugin(str(plugin_path))
        self.assertTrue(result.success, result.message)


if __name__ == "__main__":
    unittest.main()


class TestFactoryPolicyResolution(unittest.TestCase):
    """create_default_plugin_manager resolves the signature policy."""

    def setUp(self) -> None:
        self._saved = os.environ.get("OPENSSL_ENCRYPT_PLUGIN_SIGNATURE_POLICY")
        os.environ.pop("OPENSSL_ENCRYPT_PLUGIN_SIGNATURE_POLICY", None)

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop("OPENSSL_ENCRYPT_PLUGIN_SIGNATURE_POLICY", None)
        else:
            os.environ["OPENSSL_ENCRYPT_PLUGIN_SIGNATURE_POLICY"] = self._saved

    def test_default_is_enforce(self) -> None:
        # gitlab#130: the default policy is ENFORCE (unsigned non-built-in
        # plugins are refused rather than exec'd behind the AST denylist).
        from openssl_encrypt.modules.plugin_system import create_default_plugin_manager
        from openssl_encrypt.modules.plugin_system.plugin_signature import PluginSignaturePolicy

        mgr = create_default_plugin_manager()
        self.assertEqual(mgr.signature_policy, PluginSignaturePolicy.ENFORCE)

    def test_env_can_select_off(self) -> None:
        from openssl_encrypt.modules.plugin_system import create_default_plugin_manager
        from openssl_encrypt.modules.plugin_system.plugin_signature import PluginSignaturePolicy

        os.environ["OPENSSL_ENCRYPT_PLUGIN_SIGNATURE_POLICY"] = "off"
        mgr = create_default_plugin_manager()
        self.assertEqual(mgr.signature_policy, PluginSignaturePolicy.OFF)

    def test_env_var_selects_enforce(self) -> None:
        from openssl_encrypt.modules.plugin_system import create_default_plugin_manager
        from openssl_encrypt.modules.plugin_system.plugin_signature import PluginSignaturePolicy

        os.environ["OPENSSL_ENCRYPT_PLUGIN_SIGNATURE_POLICY"] = "enforce"
        mgr = create_default_plugin_manager()
        self.assertEqual(mgr.signature_policy, PluginSignaturePolicy.ENFORCE)

    def test_explicit_arg_overrides_env(self) -> None:
        from openssl_encrypt.modules.plugin_system import create_default_plugin_manager
        from openssl_encrypt.modules.plugin_system.plugin_signature import PluginSignaturePolicy

        os.environ["OPENSSL_ENCRYPT_PLUGIN_SIGNATURE_POLICY"] = "off"
        mgr = create_default_plugin_manager(signature_policy=PluginSignaturePolicy.WARN)
        self.assertEqual(mgr.signature_policy, PluginSignaturePolicy.WARN)

    def test_invalid_env_falls_back_to_default(self) -> None:
        # An invalid value is a misconfiguration: fail closed to the default
        # (ENFORCE, gitlab#130) rather than silently weakening the policy.
        from openssl_encrypt.modules.plugin_system import create_default_plugin_manager
        from openssl_encrypt.modules.plugin_system.plugin_signature import PluginSignaturePolicy

        os.environ["OPENSSL_ENCRYPT_PLUGIN_SIGNATURE_POLICY"] = "bogus"
        mgr = create_default_plugin_manager()
        self.assertEqual(mgr.signature_policy, PluginSignaturePolicy.ENFORCE)


class TestProjectKeyAnchor(_SigningFixture):
    """The bundled project source-integrity key acts as a default anchor (D2)."""

    def setUp(self) -> None:
        super().setUp()
        # Point the 'project key' helpers at our ephemeral author key so we can
        # exercise the default-anchor path without the real private key.
        self._pub_file = self.tmp / "project.asc"
        self._pub_file.write_bytes(self.author_pub)
        import openssl_encrypt.integrity.verify_cli as vc

        self._patches = [
            unittest.mock.patch.object(vc, "default_pubkey_path", return_value=self._pub_file),
            unittest.mock.patch.object(vc, "default_fingerprint", return_value=self.author_fpr),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self) -> None:
        for p in self._patches:
            p.stop()
        super().tearDown()

    def test_project_trust_anchor_resolves(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signature import project_trust_anchor

        anchor = project_trust_anchor()
        self.assertIsNotNone(anchor)
        self.assertTrue(self.author_fpr.endswith(anchor.fingerprint))

    def _plugin_dir_with_signed_plugin(self):
        pdir = self.tmp / "plugins"
        pdir.mkdir(mode=0o700)
        plugin = pdir / "signed_plugin.py"
        plugin.write_text(_LOADER_PLUGIN)
        sig = self._sign(plugin.read_bytes(), self.author_fpr, "author_home")
        (pdir / "signed_plugin.py.asc").write_bytes(sig)
        return plugin

    def _manager(self, *, include_project_anchor=True):
        from openssl_encrypt.modules.plugin_system import PluginManager
        from openssl_encrypt.modules.plugin_system.plugin_config import PluginConfigManager
        from openssl_encrypt.modules.plugin_system.plugin_signature import PluginSignaturePolicy

        empty_store = self.tmp / "empty_store"
        return PluginManager(
            config_manager=PluginConfigManager(),
            signature_policy=PluginSignaturePolicy.ENFORCE,
            trusted_keys_dir=str(empty_store),
            include_project_anchor=include_project_anchor,
        )

    def test_project_signed_plugin_loads_without_enrollment(self) -> None:
        plugin = self._plugin_dir_with_signed_plugin()
        result = self._manager(include_project_anchor=True).load_plugin(str(plugin))
        self.assertTrue(result.success, result.message)

    def test_disabling_project_anchor_refuses(self) -> None:
        plugin = self._plugin_dir_with_signed_plugin()
        result = self._manager(include_project_anchor=False).load_plugin(str(plugin))
        self.assertFalse(result.success)
