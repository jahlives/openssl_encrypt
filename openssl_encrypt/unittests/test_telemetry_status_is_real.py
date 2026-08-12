#!/usr/bin/env python3
"""
`telemetry status` must report the real state, not a constant (gitlab#166,
part 5).

`TelemetryPlugin.get_status()` returned a hardcoded `"enabled": True`. So
the one command a user runs to check whether telemetry is on answered "yes"
regardless -- including immediately after `telemetry opt-out`, and on an
install where telemetry was never enabled at all (it is opt-in, default
off).

Enablement is actually decided per run by `_is_telemetry_enabled()`:
runtime flag, then `OPENSSL_ENCRYPT_TELEMETRY=1`, then the config file,
defaulting to off. That is the value `status` has to show.

This is a privacy control misreporting itself, which is the same class as
`enable-plugin` claiming success while persisting nothing (gitlab#199) --
the user's belief about what the tool is doing diverges from what it does,
and nothing signals the gap.
"""

import os
import unittest
from unittest import mock


class _StatusTestCase(unittest.TestCase):
    def setUp(self):
        try:
            from openssl_encrypt.plugins.telemetry.telemetry_plugin import (
                OpenSSLEncryptTelemetryPlugin as TelemetryPlugin,
            )
        except ImportError:  # pragma: no cover - plugin always present here
            self.skipTest("telemetry plugin unavailable")
        self.TelemetryPlugin = TelemetryPlugin

    def _status(self):
        plugin = self.TelemetryPlugin.__new__(self.TelemetryPlugin)
        # Only the members get_status reads.
        plugin.buffer = mock.Mock(get_pending_count=mock.Mock(return_value=0))
        plugin.telemetry_config = mock.Mock(server_url="https://x.test", upload_interval=60)
        plugin.key_manager = mock.Mock(has_valid_key=mock.Mock(return_value=False))
        plugin._upload_thread = None
        return plugin.get_status()


class TestStatusReflectsTheRealSetting(_StatusTestCase):
    def test_disabled_by_default(self):
        """Telemetry is opt-in. A fresh install must not report "enabled"."""
        with mock.patch(
            "openssl_encrypt.modules.crypt_core._is_telemetry_enabled", return_value=False
        ):
            self.assertFalse(
                self._status()["enabled"],
                "status reported enabled on an install where telemetry is off",
            )

    def test_enabled_when_the_setting_says_so(self):
        """The negative arm: it must not become a constant False either."""
        with mock.patch(
            "openssl_encrypt.modules.crypt_core._is_telemetry_enabled", return_value=True
        ):
            self.assertTrue(self._status()["enabled"])

    def test_the_environment_variable_is_honoured(self):
        """Driven through the real resolver rather than a patch, so the
        wiring itself is covered and not just the plumbing."""
        with mock.patch.dict(os.environ, {"OPENSSL_ENCRYPT_TELEMETRY": "1"}):
            self.assertTrue(self._status()["enabled"])

        # And the reverse: with the variable absent and no config saying
        # otherwise, the default is off. The runtime flag is cleared too --
        # it is module state and a previous test could have set it.
        from openssl_encrypt.modules import crypt_core

        environment = dict(os.environ)
        environment.pop("OPENSSL_ENCRYPT_TELEMETRY", None)
        previous = crypt_core._telemetry_enabled
        self.addCleanup(setattr, crypt_core, "_telemetry_enabled", previous)
        crypt_core._telemetry_enabled = False
        with mock.patch.dict(os.environ, environment, clear=True):
            self.assertFalse(self._status()["enabled"])

    def test_the_other_fields_are_unchanged(self):
        """Only `enabled` was a constant; the rest were already real."""
        with mock.patch(
            "openssl_encrypt.modules.crypt_core._is_telemetry_enabled", return_value=False
        ):
            status = self._status()
        self.assertEqual(status["pending_events"], 0)
        self.assertEqual(status["server_url"], "https://x.test")
        self.assertFalse(status["has_api_key"])
        self.assertFalse(status["upload_thread_alive"])

    def test_a_failure_to_resolve_reports_disabled(self):
        """Fail closed: if the setting cannot be read, the honest answer for
        a privacy control is "not on", not "on"."""
        with mock.patch(
            "openssl_encrypt.modules.crypt_core._is_telemetry_enabled",
            side_effect=RuntimeError("config unreadable"),
        ):
            self.assertFalse(self._status()["enabled"])


if __name__ == "__main__":
    unittest.main()
