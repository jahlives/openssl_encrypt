"""
Unit tests for OnlyKey Challenge-Response HSM Plugin.

These tests verify the OnlyKey plugin behavior without requiring physical
hardware. Tests mock the underlying hid / yubikit modules at sys.modules
level so they run in any environment.

OnlyKey speaks the YubiKey HMAC-SHA1 wire protocol — only the USB VID/PID
differs (0x1d50:0x60fc vs Yubico's 0x1050). The plugin reuses
yubikit.yubiotp.YubiOtpSession.calculate_hmac_sha1 over a connection to an
OnlyKey HID device.
"""

import sys
import unittest
from unittest.mock import MagicMock, patch

# Stub hardware libraries at import time so the plugin can be imported
# regardless of whether the real libraries are installed.
sys.modules.setdefault("hid", MagicMock())
sys.modules.setdefault("yubikit", MagicMock())
sys.modules.setdefault("yubikit.core", MagicMock())
sys.modules.setdefault("yubikit.core.otp", MagicMock())
sys.modules.setdefault("yubikit.yubiotp", MagicMock())

from openssl_encrypt.modules.plugin_system.plugin_base import (  # noqa: E402
    PluginCapability,
)
from openssl_encrypt.plugins.hsm.onlykey_challenge_response import (  # noqa: E402
    OnlykeyHSMPlugin,
)


class TestOnlykeyPluginMetadata(unittest.TestCase):
    """Plugin identity, version, and capability advertisement."""

    def setUp(self):
        self.plugin = OnlykeyHSMPlugin()

    def test_plugin_id_is_onlykey_hsm(self):
        self.assertEqual(self.plugin.plugin_id, "onlykey_hsm")

    def test_plugin_name(self):
        self.assertEqual(self.plugin.name, "OnlyKey Challenge-Response HSM")

    def test_plugin_version(self):
        self.assertEqual(self.plugin.version, "1.0.0")

    def test_required_capabilities(self):
        caps = self.plugin.get_required_capabilities()
        self.assertIn(PluginCapability.ACCESS_CONFIG, caps)
        self.assertIn(PluginCapability.WRITE_LOGS, caps)

    def test_description_mentions_onlykey_and_challenge_response(self):
        desc = self.plugin.get_description()
        self.assertIn("OnlyKey", desc)
        self.assertIn("Challenge-Response", desc)
        self.assertIn("hardware-bound", desc.lower())


class TestOnlykeyAvailabilityCheck(unittest.TestCase):
    """The _check_libs_available probe (mirrors YubikeyHSMPlugin pattern)."""

    def test_returns_true_when_libs_importable(self):
        plugin = OnlykeyHSMPlugin()
        # In the test environment the libs are stubbed via sys.modules so
        # imports succeed.
        self.assertTrue(plugin._check_libs_available())

    def test_result_is_cached(self):
        plugin = OnlykeyHSMPlugin()
        first = plugin._check_libs_available()
        second = plugin._check_libs_available()
        self.assertEqual(first, second)
        self.assertIs(plugin._libs_available, first)

    def test_returns_false_when_yubikit_import_fails(self):
        plugin = OnlykeyHSMPlugin()
        # Force the probe to encounter an ImportError by temporarily removing
        # yubikit from sys.modules and blocking re-import.
        import builtins

        real_import = builtins.__import__

        def blocking_import(name, *args, **kwargs):
            if name.startswith("yubikit"):
                raise ImportError(f"blocked: {name}")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=blocking_import):
            self.assertFalse(plugin._check_libs_available())


if __name__ == "__main__":
    unittest.main()
