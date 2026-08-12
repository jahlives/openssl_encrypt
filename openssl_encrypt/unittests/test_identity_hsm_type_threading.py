#!/usr/bin/env python3
"""`identity create --hsm onlykey` must bind the identity to the OnlyKey, not
the YubiKey (gitlab#218 finding 3).

`cmd_create` computed `hsm_type="onlykey"` but used it only for a pre-flight
availability check; `Identity.generate()` had no `hsm_type` parameter and built
`IdentityKeyProtectionService()` with the `"yubikey"` default, and the recorded
`hsm_config.hsm_type` was never consulted for plugin selection — both
`_encrypt_private_key` and `_decrypt_private_key` also built the service with
the bare default. So an OnlyKey selection was silently dropped: with both
devices present the identity was YubiKey-bound; with only an OnlyKey, creation
failed with a misleading "no Yubikey available" error.

The HSM challenge-response plugin classes are present, but their hardware
libraries (ykman/yubikit/hid) are not installed here, so these tests stub those
libraries and assert plugin SELECTION -- that the recorded `hsm_type` resolves
to the correct concrete plugin class, and which device the encrypt/decrypt
paths build the service for -- not real pepper derivation on a device.
"""

import sys
import unittest
from unittest import mock

# The HSM challenge-response plugin classes import the YubiKey hardware
# libraries; stub them so plugin SELECTION (which concrete class an hsm_type
# resolves to) is testable without real hardware, mirroring
# test_onlykey_identity_protection.py.
for _mod in (
    "ykman",
    "ykman.device",
    "ykman.hid",
    "ykman.hid.base",
    "ykman.hid.linux",
    "hid",
    "yubikit",
    "yubikit.core",
    "yubikit.core.otp",
    "yubikit.yubiotp",
):
    sys.modules.setdefault(_mod, mock.MagicMock())

from openssl_encrypt.modules.identity import Identity  # noqa: E402
from openssl_encrypt.modules.identity_protection import (  # noqa: E402
    HSMProtectionConfig,
    IdentityProtection,
    PasswordProtectionConfig,
    ProtectionLevel,
)


def _hsm_protection(hsm_type):
    return IdentityProtection(
        level=ProtectionLevel.PASSWORD_AND_HSM,
        password_config=PasswordProtectionConfig(salt=b"\x00" * 16),
        hsm_config=HSMProtectionConfig(
            hsm_type=hsm_type, slot=1, challenge_salt=b"\x01" * 16, require_touch=False
        ),
    )


class TestGenerateRecordsSelectedDevice(unittest.TestCase):
    def _generate(self, **over):
        with mock.patch(
            "openssl_encrypt.modules.identity_protection.IdentityKeyProtectionService.is_hsm_available",
            return_value=True,
        ), mock.patch(
            "openssl_encrypt.modules.identity_protection.IdentityKeyProtectionService.detect_hsm_slot",
            return_value=1,
        ):
            return Identity.generate(
                name="alice",
                passphrase="pw",
                protection_level=ProtectionLevel.PASSWORD_AND_HSM,
                **over,
            )

    def test_onlykey_is_recorded_not_yubikey(self):
        identity = self._generate(hsm_type="onlykey")
        self.assertEqual(identity.protection.hsm_config.hsm_type, "onlykey")

    def test_default_is_yubikey_for_backward_compat(self):
        identity = self._generate()
        self.assertEqual(identity.protection.hsm_config.hsm_type, "yubikey")


class TestKeyPathsSelectTheConfiguredDevice(unittest.TestCase):
    """encrypt/decrypt must build the service for the identity's recorded
    device, not the yubikey default."""

    def test_encrypt_builds_service_for_the_recorded_device(self):
        from openssl_encrypt.modules import identity as identity_mod

        with mock.patch.object(identity_mod, "IdentityKeyProtectionService") as svc:
            svc.return_value.encrypt_private_key.return_value = b"ct"
            identity_mod._encrypt_private_key(
                private_key=b"k",
                passphrase="pw",
                protection=_hsm_protection("onlykey"),
                identity_name="alice",
            )
        _, kwargs = svc.call_args
        self.assertEqual(kwargs.get("hsm_type"), "onlykey")

    def test_decrypt_builds_service_for_the_recorded_device(self):
        from openssl_encrypt.modules import identity as identity_mod

        with mock.patch.object(identity_mod, "IdentityKeyProtectionService") as svc:
            svc.return_value.decrypt_private_key.return_value = b"k"
            identity_mod._decrypt_private_key(
                encrypted_data=b"ct",
                passphrase="pw",
                protection=_hsm_protection("onlykey"),
                identity_name="alice",
            )
        _, kwargs = svc.call_args
        self.assertEqual(kwargs.get("hsm_type"), "onlykey")


class TestCmdCreateThreadsHsmType(unittest.TestCase):
    def test_onlykey_is_passed_to_generate(self):
        from argparse import Namespace

        from openssl_encrypt.modules import identity_cli

        args = Namespace(
            name="alice",
            email=None,
            hsm="onlykey",
            hsm_slot=None,
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
            "openssl_encrypt.modules.identity_cli.prompt_passphrase",
            return_value="password123",
        ):
            svc.return_value.is_hsm_available.return_value = True
            svc.return_value.detect_hsm_slot.return_value = 1
            try:
                identity_cli.cmd_create(args)
            except Exception:
                # We only care that generate() was reached with the right kwarg;
                # downstream save/store is irrelevant to this test.
                pass
        self.assertTrue(gen.called, "Identity.generate was never called")
        self.assertEqual(gen.call_args.kwargs.get("hsm_type"), "onlykey")


class TestRecordedDeviceResolvesToDistinctPlugin(unittest.TestCase):
    """The recorded hsm_type must resolve to the DEVICE-SPECIFIC plugin, not a
    shared/default one.

    OnlyKey and YubiKey share the HMAC-SHA1 challenge-response *protocol* but
    NOT the USB VID/PID: the YubiKey plugin enumerates only Yubico devices, and
    ykman's PID enum rejects OnlyKey's real PID (see
    test_onlykey_pid_masquerade), so the YubiKey plugin genuinely cannot reach
    an OnlyKey -- they are not interchangeable. These pin the concrete classes
    so a "just default to yubikey" refactor cannot silently reintroduce
    gitlab#218.
    """

    def _plugin_for(self, hsm_type):
        from openssl_encrypt.modules.identity_protection import IdentityKeyProtectionService

        return IdentityKeyProtectionService(hsm_type=hsm_type)._get_hsm_plugin()

    def test_onlykey_resolves_to_the_onlykey_plugin(self):
        from openssl_encrypt.plugins.hsm.onlykey_challenge_response import OnlykeyHSMPlugin

        self.assertIsInstance(self._plugin_for("onlykey"), OnlykeyHSMPlugin)

    def test_yubikey_resolves_to_the_yubikey_plugin(self):
        from openssl_encrypt.plugins.hsm.yubikey_challenge_response import YubikeyHSMPlugin

        self.assertIsInstance(self._plugin_for("yubikey"), YubikeyHSMPlugin)

    def test_default_resolves_to_the_yubikey_plugin(self):
        from openssl_encrypt.modules.identity_protection import IdentityKeyProtectionService
        from openssl_encrypt.plugins.hsm.yubikey_challenge_response import YubikeyHSMPlugin

        self.assertIsInstance(IdentityKeyProtectionService()._get_hsm_plugin(), YubikeyHSMPlugin)

    def test_the_two_plugins_are_not_interchangeable(self):
        from openssl_encrypt.plugins.hsm.onlykey_challenge_response import OnlykeyHSMPlugin
        from openssl_encrypt.plugins.hsm.yubikey_challenge_response import YubikeyHSMPlugin

        self.assertIsNot(OnlykeyHSMPlugin, YubikeyHSMPlugin)
        # OnlyKey's non-Yubico PID is exactly why the YubiKey plugin cannot
        # reach it; pin it so the shared-protocol fact cannot be mistaken for
        # device interchangeability.
        self.assertEqual(OnlykeyHSMPlugin.ONLYKEY_PID, 0x60FC)

    def test_a_recorded_onlykey_identity_selects_the_onlykey_plugin_end_to_end(self):
        # The exact service the encrypt/decrypt paths build from a recorded
        # config (IdentityKeyProtectionService(hsm_type=hsm_config.hsm_type))
        # must resolve to the OnlyKey plugin, not the yubikey default.
        from openssl_encrypt.plugins.hsm.onlykey_challenge_response import OnlykeyHSMPlugin

        protection = _hsm_protection("onlykey")
        plugin = self._plugin_for(protection.hsm_config.hsm_type)
        self.assertIsInstance(plugin, OnlykeyHSMPlugin)


if __name__ == "__main__":
    unittest.main()
