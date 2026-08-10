#!/usr/bin/env python3
"""`identity create --hsm piv` end-to-end (gitlab#218 finding 1).

PIV was declared-but-unreachable on `identity create`: the --hsm choices
excluded 'piv' and cmd_create never read the PIV flags. This wires PIV in and,
crucially, PERSISTS the PIV config (PKCS#11 module path, PIV key slot, biometric
flag) in HSMProtectionConfig so a PIV identity can be UNLOCKED later without the
flags being re-supplied -- otherwise a user could create an identity they could
never open again.

No PIV token or PKCS#11 module exists in CI, so these tests stub the plugin with
a deterministic 32-byte pepper (mirroring test_identity_hsm_type_threading.py's
approach for the Yubikey/OnlyKey plugins) and assert: config persistence, plugin
selection, the relaxed pepper-length acceptance, cmd_create threading, and a full
encrypt->decrypt (create->unlock) private-key round-trip.
"""

import argparse
import contextlib
import hashlib
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

for _mod in ("ykman", "ykman.device", "hid", "yubikit", "yubikit.core", "yubikit.core.otp"):
    sys.modules.setdefault(_mod, mock.MagicMock())


@contextlib.contextmanager
def _allowed_module():
    """A real (empty) .so in a directory trusted via OPENSSL_ENCRYPT_PKCS11_ALLOW.

    The module path is validated (must be a real file in a trusted dir) before
    it is loaded (gitlab#218 finding 2), so tests need a genuine file in an
    allowed directory rather than a bare fake path.
    """
    d = tempfile.mkdtemp()
    path = os.path.join(d, "fake-pkcs11.so")
    with open(path, "wb") as f:
        f.write(b"\x7fELF fake")
    old = os.environ.get("OPENSSL_ENCRYPT_PKCS11_ALLOW")
    os.environ["OPENSSL_ENCRYPT_PKCS11_ALLOW"] = d
    try:
        yield path
    finally:
        if old is None:
            os.environ.pop("OPENSSL_ENCRYPT_PKCS11_ALLOW", None)
        else:
            os.environ["OPENSSL_ENCRYPT_PKCS11_ALLOW"] = old
        os.unlink(path)
        os.rmdir(d)


from openssl_encrypt.modules.identity_protection import (  # noqa: E402
    HSMProtectionConfig,
    IdentityKeyProtectionService,
    IdentityProtection,
    PasswordProtectionConfig,
    ProtectionLevel,
)


class _FakePIVPlugin:
    """A PIV plugin with no hardware: deterministic 32-byte HKDF-style pepper."""

    plugin_id = "piv_card"

    def __init__(self, pkcs11_lib_path=None, slot_index=0, piv_slot=0x9A, biometric=False, **kw):
        self.pkcs11_lib_path = pkcs11_lib_path
        self.slot_index = slot_index
        self.piv_slot = piv_slot
        self.biometric = biometric

    def initialize(self, config):
        return types.SimpleNamespace(success=True, message="ok")

    def get_hsm_pepper(self, salt, context):
        # Deterministic in the challenge, so create and unlock derive the same
        # 32-byte pepper for the same identity.
        pepper = hashlib.sha256(b"fake-piv-pepper:" + bytes(salt)).digest()
        return types.SimpleNamespace(success=True, message="ok", data={"hsm_pepper": pepper})


def _piv_protection(pkcs11_lib_path):
    return IdentityProtection(
        level=ProtectionLevel.PASSWORD_AND_HSM,
        password_config=PasswordProtectionConfig(salt=b"\x00" * 16),
        hsm_config=HSMProtectionConfig(
            hsm_type="piv",
            slot=None,
            challenge_salt=b"\x02" * 32,
            require_touch=False,
            pkcs11_lib_path=pkcs11_lib_path,
            piv_slot=0x9A,
            biometric=False,
        ),
    )


class TestPivConfigPersists(unittest.TestCase):
    def test_piv_fields_round_trip_through_to_dict_from_dict(self):
        cfg = HSMProtectionConfig(
            hsm_type="piv",
            challenge_salt=b"\x01" * 32,
            pkcs11_lib_path="/lib/x.so",
            piv_slot=0x9C,
            biometric=True,
        )
        back = HSMProtectionConfig.from_dict(cfg.to_dict())
        self.assertEqual(back.hsm_type, "piv")
        self.assertEqual(back.pkcs11_lib_path, "/lib/x.so")
        self.assertEqual(back.piv_slot, 0x9C)
        self.assertTrue(back.biometric)

    def test_non_piv_config_keeps_its_on_disk_shape(self):
        # A Yubikey config must not gain PIV keys.
        cfg = HSMProtectionConfig(hsm_type="yubikey", challenge_salt=b"\x01" * 32, slot=1)
        d = cfg.to_dict()
        self.assertNotIn("pkcs11_lib_path", d)
        self.assertNotIn("piv_slot", d)
        self.assertNotIn("biometric", d)


class TestPivPluginSelection(unittest.TestCase):
    def test_hsm_type_piv_resolves_to_the_piv_plugin_with_the_config(self):
        with _allowed_module() as path, mock.patch(
            "openssl_encrypt.plugins.hsm.piv_card.PIVHSMPlugin", _FakePIVPlugin
        ):
            svc = IdentityKeyProtectionService(
                hsm_type="piv", pkcs11_lib_path=path, piv_slot=0x9E, biometric=True
            )
            plugin = svc._get_hsm_plugin()
        self.assertIsInstance(plugin, _FakePIVPlugin)
        self.assertEqual(plugin.pkcs11_lib_path, path)
        self.assertEqual(plugin.piv_slot, 0x9E)
        self.assertTrue(plugin.biometric)


class TestPivPepperLengthAccepted(unittest.TestCase):
    def test_a_32_byte_pepper_is_accepted(self):
        # The old hardcoded len==20 check would reject PIV's 32-byte pepper.
        with _allowed_module() as path, mock.patch(
            "openssl_encrypt.plugins.hsm.piv_card.PIVHSMPlugin", _FakePIVPlugin
        ):
            svc = IdentityKeyProtectionService(hsm_type="piv", pkcs11_lib_path=path)
            pepper = svc._get_hsm_pepper(_piv_protection(path).hsm_config, "alice")
        self.assertEqual(len(pepper), 32)


class TestCreateUnlockRoundTrip(unittest.TestCase):
    """The whole point: a PIV identity created now must open later."""

    def test_private_key_encrypts_and_decrypts_via_persisted_piv_config(self):
        from openssl_encrypt.modules import identity as identity_mod

        secret = b"the-post-quantum-private-key-bytes"
        with _allowed_module() as path, mock.patch(
            "openssl_encrypt.plugins.hsm.piv_card.PIVHSMPlugin", _FakePIVPlugin
        ):
            protection = _piv_protection(path)
            ct = identity_mod._encrypt_private_key(
                private_key=secret,
                passphrase="passphrase123",
                protection=protection,
                identity_name="alice",
            )
            # A fresh protection object rebuilt from the SAME persisted dict --
            # the unlock path only has what was written to disk.
            reloaded = IdentityProtection(
                level=ProtectionLevel.PASSWORD_AND_HSM,
                password_config=protection.password_config,
                hsm_config=HSMProtectionConfig.from_dict(protection.hsm_config.to_dict()),
            )
            pt = identity_mod._decrypt_private_key(
                encrypted_data=ct,
                passphrase="passphrase123",
                protection=reloaded,
                identity_name="alice",
            )
        # decrypt returns a CryptoKey (secure memory); compare the raw bytes.
        self.assertEqual(pt.get_bytes(), secret)


class TestRealPluginThroughIdentityPepperPath(unittest.TestCase):
    """Drive the REAL PIVHSMPlugin (mocked PKCS#11) through the identity
    _get_hsm_pepper path.

    The fake-plugin round-trip above ignores the security context, so it cannot
    catch the real glue: the identity path builds its own context and must NOT
    inject a None CR slot that overrides the plugin's constructed slot_index
    (gitlab#218 review finding 1). This test exercises exactly that handoff.
    """

    def setUp(self):
        import os
        import tempfile

        from openssl_encrypt.unittests import _piv_mocks
        from openssl_encrypt.unittests._piv_mocks import (
            FakeSession,
            FakeToken,
            SessionState,
            TokenFlag,
            make_rsa_key,
        )

        _piv_mocks.reset()
        self.addCleanup(_piv_mocks.reset)
        tmp = tempfile.NamedTemporaryFile(suffix=".so", delete=False)
        tmp.write(b"\x7fELF fake module")
        tmp.close()
        self.path = tmp.name
        self.addCleanup(os.unlink, self.path)
        session = FakeSession(keys=[make_rsa_key(2048)], state=SessionState.RO_USER_FUNCTIONS)
        token = FakeToken(flags=TokenFlag.LOGIN_REQUIRED, session=session)
        _piv_mocks.set_library(_piv_mocks.single_slot_lib(token))

    def _service(self):
        from openssl_encrypt.plugins.hsm.piv_card import PIVHSMPlugin

        plugin = PIVHSMPlugin(
            pkcs11_lib_path=self.path,
            piv_slot=0x9A,
            pin_provider=lambda: bytearray(b"123456"),
        )
        return IdentityKeyProtectionService(hsm_plugin=plugin, hsm_type="piv")

    def test_pepper_derives_and_is_deterministic(self):
        cfg = HSMProtectionConfig(
            hsm_type="piv",
            slot=None,
            challenge_salt=b"\x02" * 32,
            require_touch=False,
            pkcs11_lib_path=self.path,
            piv_slot=0x9A,
        )
        p1 = self._service()._get_hsm_pepper(cfg, "alice")
        p2 = self._service()._get_hsm_pepper(cfg, "alice")
        self.assertEqual(len(p1), 32)
        self.assertEqual(p1, p2)  # same identity+device => same pepper (unlock works)
        # A different identity name must yield a different pepper.
        p3 = self._service()._get_hsm_pepper(cfg, "bob")
        self.assertNotEqual(p1, p3)


class TestCmdCreateThreadsPivConfig(unittest.TestCase):
    def test_piv_flags_reach_generate(self):
        from openssl_encrypt.modules import identity_cli

        args = argparse.Namespace(
            name="alice",
            email=None,
            hsm="piv",
            hsm_slot=None,
            hsm_pkcs11_lib="/lib/opensc-pkcs11.so",
            hsm_piv_slot=0x9A,
            hsm_biometric=False,
            no_touch=False,
            kem_algorithm="ML-KEM-768",
            sig_algorithm="ML-DSA-65",
            identity_store=None,
            overwrite=True,
            quiet=True,
        )
        with mock.patch(
            "openssl_encrypt.modules.identity_cli.IdentityKeyProtectionService"
        ) as svc, mock.patch(
            "openssl_encrypt.modules.identity_cli.Identity.generate"
        ) as gen, mock.patch(
            "openssl_encrypt.modules.identity_cli.prompt_passphrase", return_value="password123"
        ):
            svc.return_value.is_hsm_available.return_value = True
            try:
                identity_cli.cmd_create(args)
            except Exception:
                pass
        self.assertTrue(gen.called)
        kw = gen.call_args.kwargs
        self.assertEqual(kw.get("hsm_type"), "piv")
        self.assertEqual(kw.get("pkcs11_lib_path"), "/lib/opensc-pkcs11.so")
        self.assertEqual(kw.get("piv_slot"), 0x9A)

    def test_piv_without_pkcs11_lib_is_refused(self):
        from openssl_encrypt.modules import identity_cli

        args = argparse.Namespace(
            name="alice",
            email=None,
            hsm="piv",
            hsm_slot=None,
            hsm_pkcs11_lib=None,
            hsm_piv_slot=0x9A,
            hsm_biometric=False,
            no_touch=False,
            kem_algorithm="ML-KEM-768",
            sig_algorithm="ML-DSA-65",
            identity_store=None,
            overwrite=True,
            quiet=True,
        )
        with mock.patch(
            "openssl_encrypt.modules.identity_cli.prompt_passphrase", return_value="password123"
        ):
            rc = identity_cli.cmd_create(args)
        self.assertEqual(rc, 1)


class TestPkcs11ModuleAllowlist(unittest.TestCase):
    """A persisted module path is dlopen'd at unlock, so it must be a real file
    in a trusted directory (gitlab#218 finding 2)."""

    def _validate(self, path):
        from openssl_encrypt.modules.identity_protection import validate_pkcs11_module_path

        validate_pkcs11_module_path(path)

    def test_a_module_in_a_temp_dir_is_refused_by_default(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "evil.so")
        with open(path, "wb") as f:
            f.write(b"\x7fELF")
        try:
            os.environ.pop("OPENSSL_ENCRYPT_PKCS11_ALLOW", None)
            with self.assertRaises(ValueError) as cm:
                self._validate(path)
            self.assertIn("trusted module directories", str(cm.exception))
        finally:
            os.unlink(path)
            os.rmdir(d)

    def test_the_env_override_allows_a_custom_dir(self):
        with _allowed_module() as path:
            self._validate(path)  # must not raise

    def test_a_missing_module_is_refused(self):
        with self.assertRaises(ValueError):
            self._validate("/usr/lib/does-not-exist-12345.so")

    def test_a_relative_path_is_refused(self):
        with self.assertRaises(ValueError):
            self._validate("relative/path.so")

    def test_a_symlink_escaping_the_allowlist_is_refused(self):
        # The realpath (target) must be trusted, not just the link location.
        outside = tempfile.mkdtemp()
        target = os.path.join(outside, "evil.so")
        with open(target, "wb") as f:
            f.write(b"\x7fELF")
        allow = tempfile.mkdtemp()
        link = os.path.join(allow, "link.so")
        os.symlink(target, link)
        old = os.environ.get("OPENSSL_ENCRYPT_PKCS11_ALLOW")
        os.environ["OPENSSL_ENCRYPT_PKCS11_ALLOW"] = allow
        try:
            with self.assertRaises(ValueError):
                self._validate(link)  # link is in allow, but target is not
        finally:
            if old is None:
                os.environ.pop("OPENSSL_ENCRYPT_PKCS11_ALLOW", None)
            else:
                os.environ["OPENSSL_ENCRYPT_PKCS11_ALLOW"] = old
            os.unlink(link)
            os.rmdir(allow)
            os.unlink(target)
            os.rmdir(outside)


if __name__ == "__main__":
    unittest.main()
