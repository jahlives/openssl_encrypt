"""
Tests for identity-protection wiring of the OnlyKey HSM plugin.

Per the approved plan (Q9), identity protection must support OnlyKey in
addition to YubiKey. The IdentityKeyProtectionService previously hard-
imported YubikeyHSMPlugin; it now selects the plugin based on hsm_type.

These tests use mocks to avoid requiring real hardware; the full
identity create/decrypt roundtrip is exercised through the existing
test_identity.py suite.
"""

import sys
import unittest
from unittest.mock import MagicMock, patch

# Stub hardware libs so plugin imports succeed everywhere.
sys.modules.setdefault("ykman", MagicMock())
sys.modules.setdefault("ykman.device", MagicMock())
sys.modules.setdefault("ykman.hid", MagicMock())
sys.modules.setdefault("ykman.hid.base", MagicMock())
sys.modules.setdefault("ykman.hid.linux", MagicMock())
sys.modules.setdefault("hid", MagicMock())
sys.modules.setdefault("yubikit", MagicMock())
sys.modules.setdefault("yubikit.core", MagicMock())
sys.modules.setdefault("yubikit.core.otp", MagicMock())
sys.modules.setdefault("yubikit.yubiotp", MagicMock())

from openssl_encrypt.modules.identity_protection import IdentityKeyProtectionService  # noqa: E402


class TestIdentityProtectionPluginSelection(unittest.TestCase):
    """The service must select the right plugin based on hsm_type."""

    def test_default_hsm_type_loads_yubikey_plugin(self):
        """Backward-compat: no hsm_type → YubikeyHSMPlugin (existing behavior)."""
        service = IdentityKeyProtectionService()
        plugin = service._get_hsm_plugin()
        self.assertIsNotNone(plugin)
        self.assertEqual(plugin.plugin_id, "yubikey_hsm")

    def test_explicit_yubikey_hsm_type_loads_yubikey_plugin(self):
        service = IdentityKeyProtectionService(hsm_type="yubikey")
        plugin = service._get_hsm_plugin()
        self.assertIsNotNone(plugin)
        self.assertEqual(plugin.plugin_id, "yubikey_hsm")

    def test_onlykey_hsm_type_loads_onlykey_plugin(self):
        service = IdentityKeyProtectionService(hsm_type="onlykey")
        plugin = service._get_hsm_plugin()
        self.assertIsNotNone(plugin)
        self.assertEqual(plugin.plugin_id, "onlykey_hsm")

    def test_unknown_hsm_type_returns_none(self):
        service = IdentityKeyProtectionService(hsm_type="some_unknown_token")
        plugin = service._get_hsm_plugin()
        self.assertIsNone(plugin)

    def test_injected_plugin_overrides_type_selection(self):
        """Explicit plugin injection (for testing) bypasses type lookup."""
        injected = MagicMock()
        injected.plugin_id = "test_injected"
        service = IdentityKeyProtectionService(hsm_plugin=injected, hsm_type="onlykey")
        self.assertIs(service._get_hsm_plugin(), injected)


class TestIdentityProtectionConfigCarriesHsmType(unittest.TestCase):
    """create_protection_config must store the hsm_type in HSMProtectionConfig."""

    def test_create_protection_config_with_onlykey(self):
        from openssl_encrypt.modules.identity_protection import ProtectionLevel

        service = IdentityKeyProtectionService(hsm_type="onlykey")
        # is_hsm_available checks against the OnlyKey plugin
        with patch.object(service, "is_hsm_available", return_value=True), patch.object(
            service, "detect_hsm_slot", return_value=3
        ):
            protection = service.create_protection_config(
                level=ProtectionLevel.PASSWORD_AND_HSM,
                hsm_slot=3,
            )
        self.assertIsNotNone(protection.hsm_config)
        self.assertEqual(protection.hsm_config.hsm_type, "onlykey")
        self.assertEqual(protection.hsm_config.slot, 3)

    def test_create_protection_config_default_remains_yubikey(self):
        from openssl_encrypt.modules.identity_protection import ProtectionLevel

        service = IdentityKeyProtectionService()  # no hsm_type → default
        with patch.object(service, "is_hsm_available", return_value=True), patch.object(
            service, "detect_hsm_slot", return_value=1
        ):
            protection = service.create_protection_config(
                level=ProtectionLevel.PASSWORD_AND_HSM,
                hsm_slot=1,
            )
        self.assertEqual(protection.hsm_config.hsm_type, "yubikey")


class TestIdentityCliAcceptsOnlykey(unittest.TestCase):
    """identity_cli must accept --hsm onlykey and --hsm onlykey-only."""

    def test_identity_cli_recognises_onlykey(self):
        import re

        from openssl_encrypt.modules import identity_cli

        with open(identity_cli.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        # Verify the dispatch checks for "onlykey" and "onlykey-only"
        self.assertRegex(
            src,
            r'hsm_option\s*==\s*["\']onlykey["\']',
            msg="identity_cli must accept --hsm onlykey.",
        )
        self.assertRegex(
            src,
            r'hsm_option\s*==\s*["\']onlykey-only["\']',
            msg="identity_cli must accept --hsm onlykey-only.",
        )

    def test_identity_subparser_lists_onlykey_choices(self):
        import os
        import re

        subparser_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "modules",
            "crypt_cli_subparser.py",
        )
        with open(subparser_path, "r", encoding="utf-8") as f:
            src = f.read()
        # The identity create subcommand has choices=[...] for --hsm
        m = re.search(
            r"create_parser\.add_argument\(\s*[\"']--hsm[\"'],\s*choices=\[(.*?)\]",
            src,
            re.DOTALL,
        )
        self.assertIsNotNone(m, "Could not find identity --hsm choices list")
        choices = m.group(1)
        self.assertIn("onlykey", choices)
        self.assertIn("onlykey-only", choices)


if __name__ == "__main__":
    unittest.main()
