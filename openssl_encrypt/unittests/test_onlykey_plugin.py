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
from unittest.mock import MagicMock

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


if __name__ == "__main__":
    unittest.main()
