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
        from openssl_encrypt.modules.plugin_system.plugin_signature import (
            verify_plugin_signature,
        )

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
        from openssl_encrypt.modules.plugin_system.plugin_signature import (
            verify_plugin_signature,
        )

        verdict = verify_plugin_signature(
            self.plugin_bytes,
            str(self.tmp / "nonexistent.py.asc"),
            [self._anchor(self.author_pub, self.author_fpr)],
        )
        self.assertFalse(verdict.verified)
        self.assertIn("no signature", verdict.reason.lower())

    def test_signature_from_unenrolled_key_rejected(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signature import (
            verify_plugin_signature,
        )

        # Impostor signs, but only the author key is enrolled as an anchor.
        sig = self._sign(self.plugin_bytes, self.impostor_fpr, "impostor_home")
        sig_path = self.tmp / "plugin.py.asc"
        sig_path.write_bytes(sig)
        verdict = verify_plugin_signature(
            self.plugin_bytes, str(sig_path), [self._anchor(self.author_pub, self.author_fpr)]
        )
        self.assertFalse(verdict.verified)

    def test_tampered_plugin_bytes_rejected(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signature import (
            verify_plugin_signature,
        )

        sig = self._sign(self.plugin_bytes, self.author_fpr, "author_home")
        sig_path = self.tmp / "plugin.py.asc"
        sig_path.write_bytes(sig)
        tampered = self.plugin_bytes + b"\nimport os; os.system('rm -rf ~')\n"
        verdict = verify_plugin_signature(
            tampered, str(sig_path), [self._anchor(self.author_pub, self.author_fpr)]
        )
        self.assertFalse(verdict.verified)

    def test_no_anchors_rejects(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signature import (
            verify_plugin_signature,
        )

        sig = self._sign(self.plugin_bytes, self.author_fpr, "author_home")
        sig_path = self.tmp / "plugin.py.asc"
        sig_path.write_bytes(sig)
        verdict = verify_plugin_signature(self.plugin_bytes, str(sig_path), [])
        self.assertFalse(verdict.verified)
        self.assertIn("no trust anchor", verdict.reason.lower())


class TestSignaturePolicy(unittest.TestCase):
    """The policy enum parsing used by the loader/CLI."""

    def test_policy_values(self) -> None:
        from openssl_encrypt.modules.plugin_system.plugin_signature import (
            PluginSignaturePolicy,
        )

        self.assertEqual(PluginSignaturePolicy("off"), PluginSignaturePolicy.OFF)
        self.assertEqual(PluginSignaturePolicy("warn"), PluginSignaturePolicy.WARN)
        self.assertEqual(PluginSignaturePolicy("enforce"), PluginSignaturePolicy.ENFORCE)


if __name__ == "__main__":
    unittest.main()
