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
    PluginSecurityContext,
)
from openssl_encrypt.plugins.hsm.onlykey_challenge_response import OnlykeyHSMPlugin  # noqa: E402


def _make_context(plugin: OnlykeyHSMPlugin, slot=None) -> PluginSecurityContext:
    """Build a PluginSecurityContext with the given slot in config."""
    ctx = PluginSecurityContext(
        plugin_id=plugin.plugin_id,
        capabilities=plugin.get_required_capabilities(),
    )
    if slot is not None:
        ctx.config["slot"] = slot
    return ctx


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


class TestOnlykeyDeviceEnumeration(unittest.TestCase):
    """Discovering OnlyKey HID devices on the host."""

    def test_constants_match_onlykey_usb_spec(self):
        """VID 0x1D50 (OpenMoko), PID 0x60FC (OnlyKey-allocated)."""
        plugin = OnlykeyHSMPlugin()
        self.assertEqual(plugin.ONLYKEY_VID, 0x1D50)
        self.assertEqual(plugin.ONLYKEY_PID, 0x60FC)

    def test_list_devices_returns_empty_when_no_hidraw_matches(self):
        plugin = OnlykeyHSMPlugin()
        with patch.object(plugin, "_enumerate_hidraw", return_value=[]):
            self.assertEqual(plugin._list_onlykey_devices(), [])

    def test_list_devices_filters_to_only_onlykey_vid_pid(self):
        plugin = OnlykeyHSMPlugin()
        # Mixed enumeration: OnlyKey, YubiKey, random USB HID
        synthetic = [
            ("/dev/hidraw0", 0x1050, 0x0407),  # YubiKey OTP — excluded
            ("/dev/hidraw1", plugin.ONLYKEY_VID, plugin.ONLYKEY_PID),  # OnlyKey
            ("/dev/hidraw2", 0x046D, 0xC52B),  # Logitech receiver — excluded
        ]
        sentinel_device = object()
        with patch.object(plugin, "_enumerate_hidraw", return_value=synthetic), patch.object(
            plugin, "_make_otp_device", return_value=sentinel_device
        ) as make_dev:
            devices = plugin._list_onlykey_devices()
        self.assertEqual(devices, [sentinel_device])
        make_dev.assert_called_once_with("/dev/hidraw1", plugin.ONLYKEY_PID)

    def test_list_devices_returns_multiple_when_fleet_attached(self):
        plugin = OnlykeyHSMPlugin()
        synthetic = [
            ("/dev/hidraw1", plugin.ONLYKEY_VID, plugin.ONLYKEY_PID),
            ("/dev/hidraw2", plugin.ONLYKEY_VID, plugin.ONLYKEY_PID),
            ("/dev/hidraw3", plugin.ONLYKEY_VID, plugin.ONLYKEY_PID),
        ]
        with patch.object(plugin, "_enumerate_hidraw", return_value=synthetic), patch.object(
            plugin, "_make_otp_device", side_effect=lambda path, pid: (path, pid)
        ):
            devices = plugin._list_onlykey_devices()
        self.assertEqual(len(devices), 3)


def _make_mock_device():
    """Build a device-like object whose open_connection yields a ctx manager."""
    device = MagicMock()
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=MagicMock())
    ctx.__exit__ = MagicMock(return_value=False)
    device.open_connection.return_value = ctx
    return device


class TestCalculateChallengeResponse(unittest.TestCase):
    """The low-level HMAC-SHA1 call against an OnlyKey via YubiOtpSession."""

    def test_returns_session_response_bytes(self):
        plugin = OnlykeyHSMPlugin()
        device = _make_mock_device()
        expected = b"\xab" * 20

        mock_session = MagicMock()
        mock_session.calculate_hmac_sha1.return_value = expected

        with patch.object(plugin, "_list_onlykey_devices", return_value=[device]), patch(
            "yubikit.yubiotp.YubiOtpSession", return_value=mock_session
        ):
            result = plugin._calculate_challenge_response(b"\x00" * 16, slot=1)

        self.assertEqual(result, expected)
        mock_session.calculate_hmac_sha1.assert_called_once_with(1, b"\x00" * 16)

    def test_no_device_raises_runtime_error(self):
        plugin = OnlykeyHSMPlugin()
        with patch.object(plugin, "_list_onlykey_devices", return_value=[]):
            with self.assertRaises(RuntimeError) as cm:
                plugin._calculate_challenge_response(b"\x00" * 16, slot=1)
        self.assertIn("OnlyKey", str(cm.exception))

    def test_session_exception_wraps_into_runtime_error(self):
        plugin = OnlykeyHSMPlugin()
        device = _make_mock_device()
        mock_session = MagicMock()
        mock_session.calculate_hmac_sha1.side_effect = RuntimeError("device timeout")

        with patch.object(plugin, "_list_onlykey_devices", return_value=[device]), patch(
            "yubikit.yubiotp.YubiOtpSession", return_value=mock_session
        ):
            with self.assertRaises(RuntimeError) as cm:
                plugin._calculate_challenge_response(b"\x00" * 16, slot=1)
        self.assertIn("OnlyKey Challenge-Response failed", str(cm.exception))

    def test_uses_first_device_when_fleet_attached(self):
        plugin = OnlykeyHSMPlugin()
        d1, d2, d3 = _make_mock_device(), _make_mock_device(), _make_mock_device()
        mock_session = MagicMock()
        mock_session.calculate_hmac_sha1.return_value = b"\xcc" * 20

        with patch.object(plugin, "_list_onlykey_devices", return_value=[d1, d2, d3]), patch(
            "yubikit.yubiotp.YubiOtpSession", return_value=mock_session
        ):
            plugin._calculate_challenge_response(b"\x00" * 16, slot=2)

        # Only the first device should be opened
        d1.open_connection.assert_called_once()
        d2.open_connection.assert_not_called()
        d3.open_connection.assert_not_called()


class TestFindChallengeResponseSlot(unittest.TestCase):
    """Auto-detection across OnlyKey's slot range (1..12)."""

    def test_no_devices_returns_none(self):
        plugin = OnlykeyHSMPlugin()
        with patch.object(plugin, "_list_onlykey_devices", return_value=[]):
            self.assertIsNone(plugin._find_challenge_response_slot())

    def test_slot_1_responds_returns_1(self):
        plugin = OnlykeyHSMPlugin()
        device = _make_mock_device()
        mock_session = MagicMock()
        # Only slot 1 returns; all others raise
        mock_session.calculate_hmac_sha1.side_effect = (
            lambda slot, challenge: b"\x00" * 20
            if slot == 1
            else (_ for _ in ()).throw(RuntimeError("slot not configured"))
        )
        with patch.object(plugin, "_list_onlykey_devices", return_value=[device]), patch(
            "yubikit.yubiotp.YubiOtpSession", return_value=mock_session
        ):
            self.assertEqual(plugin._find_challenge_response_slot(), 1)

    def test_slot_5_only_returns_5(self):
        """Probe finds slot beyond YubiKey's 1..2 range (OnlyKey has 12)."""
        plugin = OnlykeyHSMPlugin()
        device = _make_mock_device()
        mock_session = MagicMock()
        mock_session.calculate_hmac_sha1.side_effect = (
            lambda slot, challenge: b"\x55" * 20
            if slot == 5
            else (_ for _ in ()).throw(RuntimeError("not configured"))
        )
        with patch.object(plugin, "_list_onlykey_devices", return_value=[device]), patch(
            "yubikit.yubiotp.YubiOtpSession", return_value=mock_session
        ):
            self.assertEqual(plugin._find_challenge_response_slot(), 5)

    def test_no_slot_configured_returns_none(self):
        plugin = OnlykeyHSMPlugin()
        device = _make_mock_device()
        mock_session = MagicMock()
        mock_session.calculate_hmac_sha1.side_effect = RuntimeError("slot not configured")
        with patch.object(plugin, "_list_onlykey_devices", return_value=[device]), patch(
            "yubikit.yubiotp.YubiOtpSession", return_value=mock_session
        ):
            self.assertIsNone(plugin._find_challenge_response_slot())

    def test_button_press_required_recognised_as_configured(self):
        """If a slot times out waiting for OnlyKey button press, it IS CR."""
        plugin = OnlykeyHSMPlugin()
        device = _make_mock_device()
        mock_session = MagicMock()
        mock_session.calculate_hmac_sha1.side_effect = (
            lambda slot, challenge: (_ for _ in ()).throw(
                RuntimeError("timeout waiting for button press")
            )
            if slot == 3
            else (_ for _ in ()).throw(RuntimeError("not configured"))
        )
        with patch.object(plugin, "_list_onlykey_devices", return_value=[device]), patch(
            "yubikit.yubiotp.YubiOtpSession", return_value=mock_session
        ):
            self.assertEqual(plugin._find_challenge_response_slot(), 3)

    def test_enumeration_exception_returns_none(self):
        plugin = OnlykeyHSMPlugin()
        with patch.object(
            plugin,
            "_list_onlykey_devices",
            side_effect=RuntimeError("USB error"),
        ):
            self.assertIsNone(plugin._find_challenge_response_slot())


class TestGetHsmPepper(unittest.TestCase):
    """The plugin's primary public entrypoint."""

    def test_happy_path_with_explicit_slot(self):
        plugin = OnlykeyHSMPlugin()
        expected_response = b"\x42" * 20
        ctx = _make_context(plugin, slot=1)

        with patch.object(
            plugin, "_calculate_challenge_response", return_value=expected_response
        ) as calc:
            result = plugin.get_hsm_pepper(b"\x00" * 16, ctx)

        self.assertTrue(result.success)
        self.assertEqual(result.data.get("hsm_pepper"), expected_response)
        self.assertEqual(result.data.get("slot"), 1)
        calc.assert_called_once_with(b"\x00" * 16, 1)

    def test_happy_path_with_high_slot(self):
        """OnlyKey accepts slots up to 12, unlike YubiKey's 2-slot max."""
        plugin = OnlykeyHSMPlugin()
        expected = b"\x77" * 20
        ctx = _make_context(plugin, slot=10)

        with patch.object(plugin, "_calculate_challenge_response", return_value=expected):
            result = plugin.get_hsm_pepper(b"\x00" * 16, ctx)

        self.assertTrue(result.success)
        self.assertEqual(result.data.get("slot"), 10)

    def test_invalid_salt_none_returns_error(self):
        plugin = OnlykeyHSMPlugin()
        ctx = _make_context(plugin)
        result = plugin.get_hsm_pepper(None, ctx)
        self.assertFalse(result.success)
        self.assertIn("salt", result.message.lower())

    def test_invalid_salt_wrong_length_returns_error(self):
        plugin = OnlykeyHSMPlugin()
        ctx = _make_context(plugin)
        result = plugin.get_hsm_pepper(b"\x00" * 8, ctx)
        self.assertFalse(result.success)
        self.assertIn("salt", result.message.lower())

    def test_invalid_slot_13_returns_error(self):
        """Slot above OnlyKey's max (12) is rejected."""
        plugin = OnlykeyHSMPlugin()
        ctx = _make_context(plugin, slot=13)
        result = plugin.get_hsm_pepper(b"\x00" * 16, ctx)
        self.assertFalse(result.success)
        self.assertIn("slot", result.message.lower())

    def test_auto_detect_when_no_slot_specified(self):
        plugin = OnlykeyHSMPlugin()
        ctx = _make_context(plugin)  # no slot
        expected = b"\x99" * 20

        with patch.object(plugin, "_find_challenge_response_slot", return_value=4), patch.object(
            plugin, "_calculate_challenge_response", return_value=expected
        ):
            result = plugin.get_hsm_pepper(b"\x00" * 16, ctx)

        self.assertTrue(result.success)
        self.assertEqual(result.data.get("slot"), 4)

    def test_auto_detect_failure_returns_error(self):
        plugin = OnlykeyHSMPlugin()
        ctx = _make_context(plugin)
        with patch.object(plugin, "_find_challenge_response_slot", return_value=None):
            result = plugin.get_hsm_pepper(b"\x00" * 16, ctx)
        self.assertFalse(result.success)
        self.assertIn("OnlyKey", result.message)

    def test_cached_slot_used_on_second_call(self):
        plugin = OnlykeyHSMPlugin()
        plugin._cached_slot = 7  # simulate prior auto-detection
        expected = b"\x55" * 20
        ctx = _make_context(plugin)  # no slot

        with patch.object(plugin, "_find_challenge_response_slot") as find, patch.object(
            plugin, "_calculate_challenge_response", return_value=expected
        ):
            result = plugin.get_hsm_pepper(b"\x00" * 16, ctx)

        self.assertTrue(result.success)
        self.assertEqual(result.data.get("slot"), 7)
        # Auto-detect must NOT be re-invoked when a slot is already cached
        find.assert_not_called()


class TestPluginInitialize(unittest.TestCase):
    """The initialize() lifecycle method."""

    def test_initialize_success(self):
        plugin = OnlykeyHSMPlugin()
        result = plugin.initialize({})
        self.assertTrue(result.success)
        self.assertIn("initialized", result.message.lower())


class TestEdgeCaseLockedDevice(unittest.TestCase):
    """OnlyKey locked-device handling (PIN must be entered on device buttons)."""

    def test_locked_device_error_surfaces_unlock_hint(self):
        plugin = OnlykeyHSMPlugin()
        device = _make_mock_device()
        mock_session = MagicMock()
        mock_session.calculate_hmac_sha1.side_effect = RuntimeError(
            "OnlyKey is locked, enter PIN to unlock"
        )

        ctx = _make_context(plugin, slot=1)
        with patch.object(plugin, "_list_onlykey_devices", return_value=[device]), patch(
            "yubikit.yubiotp.YubiOtpSession", return_value=mock_session
        ):
            result = plugin.get_hsm_pepper(b"\x00" * 16, ctx)

        self.assertFalse(result.success)
        # The user-facing message must tell them to unlock on device buttons.
        msg = result.message.lower()
        self.assertIn("locked", msg)
        self.assertIn("pin", msg)
        self.assertIn("button", msg)


class TestEdgeCaseChallengeSizes(unittest.TestCase):
    """
    The low-level _calculate_challenge_response must pass any byte sequence
    through to the device unchanged. Salt-shape validation is enforced at
    get_hsm_pepper, but the lower-level API is general-purpose and used by
    the RFC 2202 cross-backend determinism test.
    """

    def test_empty_challenge_passed_through(self):
        plugin = OnlykeyHSMPlugin()
        device = _make_mock_device()
        mock_session = MagicMock()
        mock_session.calculate_hmac_sha1.return_value = b"\x11" * 20

        with patch.object(plugin, "_list_onlykey_devices", return_value=[device]), patch(
            "yubikit.yubiotp.YubiOtpSession", return_value=mock_session
        ):
            response = plugin._calculate_challenge_response(b"", slot=1)

        self.assertEqual(response, b"\x11" * 20)
        mock_session.calculate_hmac_sha1.assert_called_once_with(1, b"")

    def test_64_byte_challenge_passed_through(self):
        plugin = OnlykeyHSMPlugin()
        device = _make_mock_device()
        mock_session = MagicMock()
        expected = b"\x22" * 20
        mock_session.calculate_hmac_sha1.return_value = expected
        challenge = bytes(range(64))

        with patch.object(plugin, "_list_onlykey_devices", return_value=[device]), patch(
            "yubikit.yubiotp.YubiOtpSession", return_value=mock_session
        ):
            response = plugin._calculate_challenge_response(challenge, slot=2)

        self.assertEqual(response, expected)
        mock_session.calculate_hmac_sha1.assert_called_once_with(2, challenge)

    def test_challenge_with_null_bytes_passed_through(self):
        plugin = OnlykeyHSMPlugin()
        device = _make_mock_device()
        mock_session = MagicMock()
        mock_session.calculate_hmac_sha1.return_value = b"\x33" * 20
        challenge = b"\x00" * 8 + b"abcd" + b"\x00" * 4  # embedded nulls

        with patch.object(plugin, "_list_onlykey_devices", return_value=[device]), patch(
            "yubikit.yubiotp.YubiOtpSession", return_value=mock_session
        ):
            response = plugin._calculate_challenge_response(challenge, slot=1)

        self.assertEqual(response, b"\x33" * 20)
        mock_session.calculate_hmac_sha1.assert_called_once_with(1, challenge)


class TestEdgeCaseDeviceDisconnect(unittest.TestCase):
    """Device unplugged mid-operation surfaces a clear error, not a crash."""

    def test_disconnect_during_session_open(self):
        """USB disconnect at connection open → user-facing error result."""
        plugin = OnlykeyHSMPlugin()
        device = MagicMock()
        # open_connection raises (device gone between enumeration and open)
        device.open_connection.side_effect = OSError("Errno 19: No such device")

        ctx = _make_context(plugin, slot=1)
        with patch.object(plugin, "_list_onlykey_devices", return_value=[device]):
            result = plugin.get_hsm_pepper(b"\x00" * 16, ctx)

        self.assertFalse(result.success)
        self.assertIn("OnlyKey", result.message)

    def test_disconnect_mid_hmac_call(self):
        """USB disconnect during HMAC call → user-facing error result."""
        plugin = OnlykeyHSMPlugin()
        device = _make_mock_device()
        mock_session = MagicMock()
        mock_session.calculate_hmac_sha1.side_effect = IOError(
            "device disconnected during transfer"
        )

        ctx = _make_context(plugin, slot=1)
        with patch.object(plugin, "_list_onlykey_devices", return_value=[device]), patch(
            "yubikit.yubiotp.YubiOtpSession", return_value=mock_session
        ):
            result = plugin.get_hsm_pepper(b"\x00" * 16, ctx)

        self.assertFalse(result.success)
        # Generic CR-failed wrapper covers it (not a special-cased message)
        self.assertIn("Challenge-Response", result.message)

    def test_disconnect_between_enumerate_and_use(self):
        """Race: device listed, then unplugged before HMAC call."""
        plugin = OnlykeyHSMPlugin()
        # First call lists one device; that device's open_connection then fails.
        device = MagicMock()
        device.open_connection.side_effect = RuntimeError("device removed")

        ctx = _make_context(plugin, slot=1)
        with patch.object(plugin, "_list_onlykey_devices", return_value=[device]):
            result = plugin.get_hsm_pepper(b"\x00" * 16, ctx)

        self.assertFalse(result.success)


if __name__ == "__main__":
    unittest.main()
