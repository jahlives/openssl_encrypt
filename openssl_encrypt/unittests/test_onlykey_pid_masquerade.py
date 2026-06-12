#!/usr/bin/env python3
"""
Regression tests: OnlyKey device construction with non-Yubico USB PID.

ykman's OtpYubiKeyDevice coerces its pid argument through yubikit's PID
IntEnum, which only contains Yubico product IDs. Passing the OnlyKey's
real PID (0x60FC = 24828) raises "24828 is not a valid PID", so the
plugin could never talk to a real device. The plugin must masquerade as
an OTP-only YubiKey (PID.YKS_OTP): yubikit uses the PID solely for USB
interface bookkeeping, the OTP protocol version is negotiated from the
device status, and OTP-only skips ykman's reclaim serial-probe that
OnlyKey does not implement.

Also covers the latent bug right behind it: open_connection(None) trips
ykman's `assert isinstance(connection_type, type)` — the plugin must
request yubikit's OtpConnection explicitly.
"""

import inspect
import sys
import unittest
from unittest.mock import MagicMock, patch

from openssl_encrypt.plugins.hsm.onlykey_challenge_response import OnlykeyHSMPlugin

ONLYKEY_PID = 0x60FC


class TestMakeOtpDeviceMasqueradesPid(unittest.TestCase):
    """_make_otp_device must not pass the raw OnlyKey PID to ykman."""

    def test_constructs_with_yks_otp_not_raw_pid(self):
        fake_base = MagicMock()
        fake_linux = MagicMock()
        fake_core = MagicMock()
        sentinel_pid = object()
        fake_core.PID.YKS_OTP = sentinel_pid

        with patch.dict(
            sys.modules,
            {
                "ykman": MagicMock(),
                "ykman.hid": MagicMock(),
                "ykman.hid.base": fake_base,
                "ykman.hid.linux": fake_linux,
                "yubikit": MagicMock(),
                "yubikit.core": fake_core,
            },
        ):
            plugin = OnlykeyHSMPlugin()
            plugin._make_otp_device("/dev/hidraw7", ONLYKEY_PID)

        fake_base.OtpYubiKeyDevice.assert_called_once()
        args = fake_base.OtpYubiKeyDevice.call_args.args
        self.assertEqual(args[0], "/dev/hidraw7")
        self.assertIs(
            args[1],
            sentinel_pid,
            msg="OtpYubiKeyDevice must be constructed with the PID.YKS_OTP "
            "masquerade — the raw OnlyKey PID is not in yubikit's PID enum "
            "and raises ValueError.",
        )

    def test_masquerade_pid_is_valid_and_otp_only(self):
        """With the real yubikit installed, the masquerade must be a valid
        OTP-only PID so ykman skips the reclaim serial-probe."""
        yubikit_mod = sys.modules.get("yubikit")
        if isinstance(yubikit_mod, MagicMock):
            self.skipTest("real yubikit not installed (sys.modules stubbed)")
        try:
            from yubikit.core import PID, USB_INTERFACE
        except ImportError:
            self.skipTest("real yubikit not installed")

        masquerade = PID.YKS_OTP
        self.assertEqual(masquerade.usb_interfaces, USB_INTERFACE.OTP)
        with self.assertRaises(ValueError):
            PID(ONLYKEY_PID)


class TestOpenConnectionRequestsOtpConnection(unittest.TestCase):
    """open_connection must receive the OtpConnection type, never None."""

    def test_source_never_passes_none(self):
        import openssl_encrypt.plugins.hsm.onlykey_challenge_response as mod

        self.assertNotIn(
            "open_connection(None)",
            inspect.getsource(mod),
            msg="ykman asserts isinstance(connection_type, type); the plugin "
            "must pass yubikit's OtpConnection class.",
        )

    def test_calculate_challenge_response_opens_otp_connection(self):
        fake_otp_mod = MagicMock()
        otp_conn_cls = type("OtpConnection", (), {})
        fake_otp_mod.OtpConnection = otp_conn_cls
        fake_yubiotp = MagicMock()
        session = fake_yubiotp.YubiOtpSession.return_value
        session.calculate_hmac_sha1.return_value = b"\x01" * 20
        device = MagicMock()

        with patch.dict(
            sys.modules,
            {
                "yubikit": MagicMock(),
                "yubikit.core": MagicMock(),
                "yubikit.core.otp": fake_otp_mod,
                "yubikit.yubiotp": fake_yubiotp,
            },
        ):
            plugin = OnlykeyHSMPlugin()
            plugin._libs_available = True
            with patch.object(plugin, "_list_onlykey_devices", return_value=[device]):
                response = plugin._calculate_challenge_response(b"\x00" * 16, 1)

        device.open_connection.assert_called_once_with(otp_conn_cls)
        self.assertEqual(response, b"\x01" * 20)


if __name__ == "__main__":
    unittest.main()
