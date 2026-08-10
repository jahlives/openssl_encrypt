"""
Unit tests for Yubikey Challenge-Response HSM Plugin.

Regression baseline for the existing YubikeyHSMPlugin behavior, captured prior
to introducing the OnlyKey Challenge-Response backend. These tests must
continue to pass unchanged after the OnlyKey work lands, proving that no
existing YubiKey behavior was altered.

Tests mock ykman / yubikit at sys.modules level so they run without the real
hardware libraries (which require pyscard, hidapi, etc. — environment-specific).
"""

import sys
import unittest
from unittest.mock import MagicMock, patch

# Stub ykman / yubikit at import time so the plugin can import them
# regardless of whether the real libraries are installed in this environment.
sys.modules.setdefault("ykman", MagicMock())
sys.modules.setdefault("ykman.device", MagicMock())
sys.modules.setdefault("yubikit", MagicMock())
sys.modules.setdefault("yubikit.core", MagicMock())
sys.modules.setdefault("yubikit.core.otp", MagicMock())
sys.modules.setdefault("yubikit.yubiotp", MagicMock())

from openssl_encrypt.modules.plugin_system.plugin_base import (  # noqa: E402
    PluginCapability,
    PluginSecurityContext,
)
from openssl_encrypt.plugins.hsm.yubikey_challenge_response import (  # noqa: E402
    YubikeyHSMPlugin,
)


def _make_context(plugin: YubikeyHSMPlugin, slot=None) -> PluginSecurityContext:
    """Build a PluginSecurityContext with the given slot in config."""
    ctx = PluginSecurityContext(
        plugin_id=plugin.plugin_id,
        capabilities=plugin.get_required_capabilities(),
    )
    if slot is not None:
        ctx.config["slot"] = slot
    return ctx


class TestYubikeyPluginMetadata(unittest.TestCase):
    """Plugin identity, version, and capability advertisement."""

    def setUp(self):
        self.plugin = YubikeyHSMPlugin()

    def test_plugin_id_is_yubikey_hsm(self):
        self.assertEqual(self.plugin.plugin_id, "yubikey_hsm")

    def test_plugin_name(self):
        self.assertEqual(self.plugin.name, "Yubikey Challenge-Response HSM")

    def test_plugin_version(self):
        self.assertEqual(self.plugin.version, "1.0.0")

    def test_required_capabilities(self):
        caps = self.plugin.get_required_capabilities()
        self.assertIn(PluginCapability.ACCESS_CONFIG, caps)
        self.assertIn(PluginCapability.WRITE_LOGS, caps)

    def test_description_mentions_yubikey_and_challenge_response(self):
        desc = self.plugin.get_description()
        self.assertIn("Yubikey", desc)
        self.assertIn("Challenge-Response", desc)
        self.assertIn("hardware-bound", desc.lower())


class TestYubikeyAvailabilityCheck(unittest.TestCase):
    """The _check_ykman_available probe."""

    def test_check_ykman_available_returns_true_when_no_import_error(self):
        plugin = YubikeyHSMPlugin()
        # Current implementation memoizes True on first call (empty try body).
        self.assertTrue(plugin._check_ykman_available())

    def test_check_ykman_available_is_cached(self):
        plugin = YubikeyHSMPlugin()
        first = plugin._check_ykman_available()
        second = plugin._check_ykman_available()
        self.assertEqual(first, second)
        self.assertIs(plugin._ykman_available, first)


class TestFindChallengeResponseSlot(unittest.TestCase):
    """Auto-detection of which slot has Challenge-Response configured."""

    def _build_mocks(self, *, devices, slot_responses):
        """
        Build (list_all_devices, OtpConnection, YubiOtpSession) mocks.

        devices: list of device-like objects to return from list_all_devices()
        slot_responses: dict {slot_number: response_or_exception}
            response_or_exception: bytes -> returned; Exception -> raised
        """
        mock_list_all_devices = MagicMock(return_value=devices)

        mock_session = MagicMock()
        mock_session.get_config_state.return_value.is_configured.side_effect = (
            lambda slot: slot in slot_responses
        )

        def calculate_hmac_sha1(slot, challenge):
            value = slot_responses[slot]
            if isinstance(value, Exception):
                raise value
            return value

        mock_session.calculate_hmac_sha1.side_effect = calculate_hmac_sha1

        mock_session_cls = MagicMock(return_value=mock_session)
        mock_otp_connection_cls = MagicMock()
        return mock_list_all_devices, mock_otp_connection_cls, mock_session_cls

    def _patch_plugin_lookups(self, list_all_devices, OtpConnection, YubiOtpSession):
        return patch.multiple(
            "openssl_encrypt.plugins.hsm.yubikey_challenge_response",
            __dict__={},  # no-op; we patch via sys.modules below
        )

    def _make_device(self):
        """A device-like object whose open_connection returns a context manager."""
        device = MagicMock()
        # open_connection(OtpConnection) -> ctx manager yielding a connection
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=MagicMock())
        ctx.__exit__ = MagicMock(return_value=False)
        device.open_connection.return_value = ctx
        return device

    def test_no_devices_returns_none(self):
        plugin = YubikeyHSMPlugin()
        with patch("ykman.device.list_all_devices", return_value=[]), patch(
            "yubikit.core.otp.OtpConnection"
        ), patch("yubikit.yubiotp.YubiOtpSession"):
            result = plugin._find_challenge_response_slot()
        self.assertIsNone(result)

    def test_slot_1_configured_and_responds_returns_1(self):
        plugin = YubikeyHSMPlugin()
        device = self._make_device()
        list_all, _, session_cls = self._build_mocks(
            devices=[device],
            slot_responses={1: b"\x00" * 20},
        )
        with patch("ykman.device.list_all_devices", list_all), patch(
            "yubikit.core.otp.OtpConnection"
        ), patch("yubikit.yubiotp.YubiOtpSession", session_cls):
            result = plugin._find_challenge_response_slot()
        self.assertEqual(result, 1)

    def test_slot_2_only_returns_2(self):
        plugin = YubikeyHSMPlugin()
        device = self._make_device()
        list_all, _, session_cls = self._build_mocks(
            devices=[device],
            slot_responses={2: b"\xff" * 20},
        )
        with patch("ykman.device.list_all_devices", list_all), patch(
            "yubikit.core.otp.OtpConnection"
        ), patch("yubikit.yubiotp.YubiOtpSession", session_cls):
            result = plugin._find_challenge_response_slot()
        self.assertEqual(result, 2)

    def test_slot_with_touch_timeout_is_recognised_as_challenge_response(self):
        """If a slot times out waiting for touch, that proves it IS CR."""
        plugin = YubikeyHSMPlugin()
        device = self._make_device()
        list_all, _, session_cls = self._build_mocks(
            devices=[device],
            slot_responses={1: Exception("operation timeout waiting for touch")},
        )
        with patch("ykman.device.list_all_devices", list_all), patch(
            "yubikit.core.otp.OtpConnection"
        ), patch("yubikit.yubiotp.YubiOtpSession", session_cls):
            result = plugin._find_challenge_response_slot()
        self.assertEqual(result, 1)

    def test_enumeration_exception_returns_none(self):
        plugin = YubikeyHSMPlugin()
        with patch("ykman.device.list_all_devices", side_effect=RuntimeError("USB error")):
            result = plugin._find_challenge_response_slot()
        self.assertIsNone(result)

    def test_tuple_device_entry_unpacked(self):
        """Older ykman returns (list, state); newer returns just list."""
        plugin = YubikeyHSMPlugin()
        device = self._make_device()
        list_all, _, session_cls = self._build_mocks(
            devices=([(device, MagicMock())], MagicMock()),  # old API shape
            slot_responses={1: b"\x00" * 20},
        )
        # Build_mocks already wraps in a return_value; for the tuple-shape test
        # we override:
        list_all = MagicMock(return_value=([(device, MagicMock())], MagicMock()))
        with patch("ykman.device.list_all_devices", list_all), patch(
            "yubikit.core.otp.OtpConnection"
        ), patch("yubikit.yubiotp.YubiOtpSession", session_cls):
            result = plugin._find_challenge_response_slot()
        self.assertEqual(result, 1)


class TestCalculateChallengeResponse(unittest.TestCase):
    """The low-level HMAC-SHA1 call."""

    def _make_device(self):
        device = MagicMock()
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=MagicMock())
        ctx.__exit__ = MagicMock(return_value=False)
        device.open_connection.return_value = ctx
        return device

    def test_returns_session_response_bytes(self):
        plugin = YubikeyHSMPlugin()
        device = self._make_device()
        expected = b"\xaa" * 20

        mock_session = MagicMock()
        mock_session.calculate_hmac_sha1.return_value = expected

        with patch("ykman.device.list_all_devices", return_value=[device]), patch(
            "yubikit.core.otp.OtpConnection"
        ), patch("yubikit.yubiotp.YubiOtpSession", return_value=mock_session):
            result = plugin._calculate_challenge_response(b"\x00" * 16, slot=1)

        self.assertEqual(result, expected)
        mock_session.calculate_hmac_sha1.assert_called_once_with(1, b"\x00" * 16)

    def test_no_device_raises_runtime_error(self):
        plugin = YubikeyHSMPlugin()
        with patch("ykman.device.list_all_devices", return_value=[]), patch(
            "yubikit.core.otp.OtpConnection"
        ), patch("yubikit.yubiotp.YubiOtpSession"):
            with self.assertRaises(RuntimeError) as cm:
                plugin._calculate_challenge_response(b"\x00" * 16, slot=1)
        self.assertIn("No Yubikey", str(cm.exception))

    def test_session_exception_wraps_into_runtime_error(self):
        plugin = YubikeyHSMPlugin()
        device = self._make_device()
        mock_session = MagicMock()
        mock_session.calculate_hmac_sha1.side_effect = RuntimeError("touch timeout")

        with patch("ykman.device.list_all_devices", return_value=[device]), patch(
            "yubikit.core.otp.OtpConnection"
        ), patch("yubikit.yubiotp.YubiOtpSession", return_value=mock_session):
            with self.assertRaises(RuntimeError) as cm:
                plugin._calculate_challenge_response(b"\x00" * 16, slot=1)
        self.assertIn("Yubikey Challenge-Response failed", str(cm.exception))


class TestGetHsmPepper(unittest.TestCase):
    """The plugin's primary public entrypoint."""

    def _make_device(self):
        device = MagicMock()
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=MagicMock())
        ctx.__exit__ = MagicMock(return_value=False)
        device.open_connection.return_value = ctx
        return device

    def test_invalid_salt_none_returns_error(self):
        plugin = YubikeyHSMPlugin()
        ctx = _make_context(plugin)
        result = plugin.get_hsm_pepper(None, ctx)
        self.assertFalse(result.success)
        self.assertIn("salt", result.message.lower())

    def test_invalid_salt_wrong_length_returns_error(self):
        plugin = YubikeyHSMPlugin()
        ctx = _make_context(plugin)
        result = plugin.get_hsm_pepper(b"\x00" * 8, ctx)  # too short
        self.assertFalse(result.success)
        self.assertIn("salt", result.message.lower())

    def test_invalid_slot_three_returns_error(self):
        plugin = YubikeyHSMPlugin()
        ctx = _make_context(plugin, slot=3)
        result = plugin.get_hsm_pepper(b"\x00" * 16, ctx)
        self.assertFalse(result.success)
        self.assertIn("slot", result.message.lower())

    def test_happy_path_with_explicit_slot(self):
        plugin = YubikeyHSMPlugin()
        device = self._make_device()
        expected_response = b"\x42" * 20

        mock_session = MagicMock()
        mock_session.calculate_hmac_sha1.return_value = expected_response

        ctx = _make_context(plugin, slot=1)
        with patch("ykman.device.list_all_devices", return_value=[device]), patch(
            "yubikit.core.otp.OtpConnection"
        ), patch("yubikit.yubiotp.YubiOtpSession", return_value=mock_session):
            result = plugin.get_hsm_pepper(b"\x00" * 16, ctx)

        self.assertTrue(result.success)
        self.assertEqual(result.data.get("hsm_pepper"), expected_response)
        self.assertEqual(result.data.get("slot"), 1)

    def test_auto_detect_when_no_slot_specified(self):
        plugin = YubikeyHSMPlugin()
        device = self._make_device()
        expected_response = b"\x99" * 20

        mock_session = MagicMock()
        mock_session.get_config_state.return_value.is_configured.side_effect = lambda s: s == 2
        mock_session.calculate_hmac_sha1.return_value = expected_response

        ctx = _make_context(plugin)  # no slot
        with patch("ykman.device.list_all_devices", return_value=[device]), patch(
            "yubikit.core.otp.OtpConnection"
        ), patch("yubikit.yubiotp.YubiOtpSession", return_value=mock_session):
            result = plugin.get_hsm_pepper(b"\x00" * 16, ctx)

        self.assertTrue(result.success)
        self.assertEqual(result.data.get("slot"), 2)

    def test_auto_detect_failure_returns_error(self):
        plugin = YubikeyHSMPlugin()
        ctx = _make_context(plugin)
        with patch("ykman.device.list_all_devices", return_value=[]), patch(
            "yubikit.core.otp.OtpConnection"
        ), patch("yubikit.yubiotp.YubiOtpSession"):
            result = plugin.get_hsm_pepper(b"\x00" * 16, ctx)
        self.assertFalse(result.success)
        self.assertIn("Yubikey", result.message)

    def test_cached_slot_used_on_second_call(self):
        plugin = YubikeyHSMPlugin()
        plugin._cached_slot = 2  # simulate prior auto-detection
        device = self._make_device()
        expected_response = b"\x77" * 20

        mock_session = MagicMock()
        mock_session.calculate_hmac_sha1.return_value = expected_response

        ctx = _make_context(plugin)  # no slot
        with patch("ykman.device.list_all_devices", return_value=[device]), patch(
            "yubikit.core.otp.OtpConnection"
        ), patch("yubikit.yubiotp.YubiOtpSession", return_value=mock_session):
            result = plugin.get_hsm_pepper(b"\x00" * 16, ctx)

        self.assertTrue(result.success)
        self.assertEqual(result.data.get("slot"), 2)
        # session.get_config_state must NOT be called when cached slot is used
        mock_session.get_config_state.assert_not_called()


class TestPluginInitialize(unittest.TestCase):
    """The initialize() lifecycle method."""

    def test_initialize_success(self):
        plugin = YubikeyHSMPlugin()
        result = plugin.initialize({})
        self.assertTrue(result.success)
        self.assertIn("initialized", result.message.lower())


if __name__ == "__main__":
    unittest.main()
