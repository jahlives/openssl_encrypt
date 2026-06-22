"""Unit tests for the PIV/PKCS#11 HSM plugin adapter.

Verifies the plugin conforms to the HSMPlugin contract, maps the 16-byte salt
through PIVBackend, never raises (returns PluginResult), and never leaks the PIN
into the result message or data.
"""

import os
import tempfile
import unittest

from openssl_encrypt.modules.plugin_system.plugin_base import (
    PluginCapability,
    PluginSecurityContext,
    PluginType,
)
from openssl_encrypt.plugins.hsm.piv_card import PIVHSMPlugin
from openssl_encrypt.unittests import _piv_mocks
from openssl_encrypt.unittests._piv_mocks import (
    FakeSession,
    FakeToken,
    SessionState,
    TokenFlag,
    make_ed25519_key,
    make_rsa_key,
)

PRESENT = TokenFlag.LOGIN_REQUIRED
SALT16 = b"0123456789abcdef"


class _PluginTestBase(unittest.TestCase):
    def setUp(self):
        _piv_mocks.reset()
        self._tmp = tempfile.NamedTemporaryFile(suffix=".so", delete=False)
        self._tmp.write(b"\x7fELF fake module")
        self._tmp.close()
        self.path = self._tmp.name

    def tearDown(self):
        _piv_mocks.reset()
        os.unlink(self.path)

    def _install(self, key, *, open_error=None, state=SessionState.RO_USER_FUNCTIONS):
        session = FakeSession(keys=[key] if key is not None else [], state=state)
        token = FakeToken(flags=PRESENT, session=session, open_error=open_error)
        _piv_mocks.set_library(_piv_mocks.single_slot_lib(token))

    def _plugin(self, pin=b"123456"):
        calls = {"n": 0}

        def provider():
            calls["n"] += 1
            return bytearray(pin) if pin is not None else bytearray(b"")

        plugin = PIVHSMPlugin(pin_provider=provider)
        plugin._provider_calls = calls
        return plugin

    def _context(self, plugin, **config):
        ctx = PluginSecurityContext(
            plugin_id=plugin.plugin_id,
            capabilities=plugin.get_required_capabilities(),
        )
        ctx.config["pkcs11_lib_path"] = self.path
        ctx.config.update(config)
        return ctx


class TestPluginMetadata(_PluginTestBase):
    def test_plugin_id(self):
        self.assertEqual(PIVHSMPlugin().plugin_id, "piv_hsm")

    def test_plugin_type_is_hsm(self):
        self.assertEqual(PIVHSMPlugin().get_plugin_type(), PluginType.HSM)

    def test_capabilities(self):
        caps = PIVHSMPlugin().get_required_capabilities()
        self.assertIn(PluginCapability.ACCESS_CONFIG, caps)
        self.assertIn(PluginCapability.WRITE_LOGS, caps)

    def test_description_mentions_piv(self):
        desc = PIVHSMPlugin().get_description().lower()
        self.assertIn("piv", desc)
        self.assertIn("pkcs#11", desc)


class TestGetHsmPepper(_PluginTestBase):
    def test_success_returns_pepper(self):
        self._install(make_rsa_key(2048))
        plugin = self._plugin()
        result = plugin.get_hsm_pepper(SALT16, self._context(plugin))
        self.assertTrue(result.success)
        self.assertEqual(len(result.data["hsm_pepper"]), 32)

    def test_ed25519_success(self):
        self._install(make_ed25519_key())
        plugin = self._plugin()
        result = plugin.get_hsm_pepper(SALT16, self._context(plugin))
        self.assertTrue(result.success)

    def test_missing_lib_path_errors(self):
        self._install(make_rsa_key(2048))
        plugin = self._plugin()
        ctx = PluginSecurityContext(
            plugin_id=plugin.plugin_id, capabilities=plugin.get_required_capabilities()
        )
        result = plugin.get_hsm_pepper(SALT16, ctx)
        self.assertFalse(result.success)

    def test_invalid_salt_length_errors(self):
        self._install(make_rsa_key(2048))
        plugin = self._plugin()
        result = plugin.get_hsm_pepper(b"too-short", self._context(plugin))
        self.assertFalse(result.success)

    def test_biometric_config_skips_pin_prompt(self):
        self._install(make_ed25519_key())
        plugin = self._plugin()
        result = plugin.get_hsm_pepper(SALT16, self._context(plugin, biometric=True))
        self.assertTrue(result.success)
        self.assertEqual(plugin._provider_calls["n"], 0)  # PIN never prompted

    def test_pin_prompted_when_not_biometric(self):
        self._install(make_rsa_key(2048))
        plugin = self._plugin()
        plugin.get_hsm_pepper(SALT16, self._context(plugin))
        self.assertEqual(plugin._provider_calls["n"], 1)

    def test_deterministic_across_calls(self):
        self._install(make_rsa_key(2048))
        plugin = self._plugin()
        r1 = plugin.get_hsm_pepper(SALT16, self._context(plugin))
        r2 = plugin.get_hsm_pepper(SALT16, self._context(plugin))
        self.assertEqual(r1.data["hsm_pepper"], r2.data["hsm_pepper"])

    def test_no_key_returns_error_not_raise(self):
        self._install(None)
        plugin = self._plugin()
        result = plugin.get_hsm_pepper(SALT16, self._context(plugin))
        self.assertFalse(result.success)

    def test_custom_piv_slot_config(self):
        self._install(make_rsa_key(2048, key_id=_piv_mocks.PIV_SLOT_ID_9C))
        plugin = self._plugin()
        result = plugin.get_hsm_pepper(SALT16, self._context(plugin, piv_slot=0x9C))
        self.assertTrue(result.success)


class TestPluginPinSecurity(_PluginTestBase):
    def test_pin_not_in_error_message(self):
        from pkcs11.exceptions import PinIncorrect

        self._install(make_rsa_key(2048), open_error=PinIncorrect("bad"))
        plugin = self._plugin(pin=b"myhiddenpin")
        result = plugin.get_hsm_pepper(SALT16, self._context(plugin))
        self.assertFalse(result.success)
        self.assertNotIn("myhiddenpin", result.message)

    def test_result_data_has_no_pin_or_salt(self):
        self._install(make_rsa_key(2048))
        plugin = self._plugin()
        result = plugin.get_hsm_pepper(SALT16, self._context(plugin))
        self.assertNotIn("pin", result.data)
        self.assertNotIn("salt", result.data)


class TestPluginConstructionConfig(_PluginTestBase):
    """Config supplied at construction (used by the encrypt/decrypt CLI path,
    where crypt_core builds its own context without PIV config)."""

    def _bare_ctx(self, plugin):
        return PluginSecurityContext(
            plugin_id=plugin.plugin_id, capabilities=plugin.get_required_capabilities()
        )

    def test_instance_lib_path_used_without_context_config(self):
        self._install(make_rsa_key(2048))
        plugin = PIVHSMPlugin(pkcs11_lib_path=self.path, pin_provider=lambda: bytearray(b"123456"))
        result = plugin.get_hsm_pepper(SALT16, self._bare_ctx(plugin))
        self.assertTrue(result.success)
        self.assertEqual(len(result.data["hsm_pepper"]), 32)

    def test_instance_biometric_skips_prompt(self):
        self._install(make_ed25519_key())
        calls = {"n": 0}

        def provider():
            calls["n"] += 1
            return bytearray(b"x")

        plugin = PIVHSMPlugin(pkcs11_lib_path=self.path, biometric=True, pin_provider=provider)
        result = plugin.get_hsm_pepper(SALT16, self._bare_ctx(plugin))
        self.assertTrue(result.success)
        self.assertEqual(calls["n"], 0)

    def test_instance_piv_slot_used(self):
        self._install(make_rsa_key(2048, key_id=_piv_mocks.PIV_SLOT_ID_9C))
        plugin = PIVHSMPlugin(
            pkcs11_lib_path=self.path, piv_slot=0x9C, pin_provider=lambda: bytearray(b"123456")
        )
        result = plugin.get_hsm_pepper(SALT16, self._bare_ctx(plugin))
        self.assertTrue(result.success)

    def test_context_config_overrides_instance(self):
        # Key is in slot 9a; instance is misconfigured to 9c; context corrects it.
        self._install(make_rsa_key(2048))
        plugin = PIVHSMPlugin(
            pkcs11_lib_path=self.path, piv_slot=0x9C, pin_provider=lambda: bytearray(b"123456")
        )
        ctx = self._bare_ctx(plugin)
        ctx.config["piv_slot"] = 0x9A
        result = plugin.get_hsm_pepper(SALT16, ctx)
        self.assertTrue(result.success)


if __name__ == "__main__":
    unittest.main()
