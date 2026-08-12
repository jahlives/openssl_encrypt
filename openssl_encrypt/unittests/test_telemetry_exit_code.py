#!/usr/bin/env python3
"""
Tests that the telemetry command reports failure through its exit code
(gitlab#166 / github#84).

`handle_telemetry_command` reported every failure by printing to stderr and
returning, and the dispatcher ended in an unconditional `sys.exit(0)`. A caller
therefore could not distinguish a successful opt-out from one that never
happened — and opt-out is destructive: it deletes pending events and the API
key. A GUI checking the exit code would tell the user their telemetry data was
gone when it was not.
"""

import argparse
import unittest
from unittest import mock

from openssl_encrypt.modules.crypt_cli import handle_telemetry_command


def _ns(action, **kw):
    base = dict(telemetry_action=action, force=True, json=False, limit=100)
    base.update(kw)
    return argparse.Namespace(**base)


class TelemetryExitCodeBase(unittest.TestCase):
    """The handler returns a process exit status: 0 success, non-zero failure."""

    def assertFailureStatus(self, status):
        """Assert a real non-zero exit status.

        Not just `!= 0`: the pre-fix code returned None, which satisfies that
        and would let the test pass without the fix.
        """
        self.assertIsInstance(status, int, "must return an exit status, not None")
        self.assertNotEqual(status, 0)


class TestOptOutFailureIsReported(TelemetryExitCodeBase):
    def test_failed_opt_out_returns_non_zero(self):
        """A refused opt-out must not look like a completed one."""
        plugin = mock.MagicMock()
        plugin.opt_out.return_value = mock.Mock(
            success=False, message="could not delete the API key"
        )
        with mock.patch(
            "openssl_encrypt.plugins.telemetry.OpenSSLEncryptTelemetryPlugin",
            return_value=plugin,
        ):
            self.assertFailureStatus(handle_telemetry_command(_ns("opt-out")))

    def test_successful_opt_out_returns_zero(self):
        plugin = mock.MagicMock()
        plugin.opt_out.return_value = mock.Mock(success=True, message="done")
        with mock.patch(
            "openssl_encrypt.plugins.telemetry.OpenSSLEncryptTelemetryPlugin",
            return_value=plugin,
        ):
            self.assertEqual(handle_telemetry_command(_ns("opt-out")), 0)


class TestPluginUnavailableIsReported(TelemetryExitCodeBase):
    def test_failed_plugin_construction_returns_non_zero(self):
        """A plugin that cannot start has deleted nothing."""
        with mock.patch(
            "openssl_encrypt.plugins.telemetry.OpenSSLEncryptTelemetryPlugin",
            side_effect=RuntimeError("no telemetry backend"),
        ):
            self.assertFailureStatus(handle_telemetry_command(_ns("opt-out")))


class TestFlushFailureIsReported(TelemetryExitCodeBase):
    def test_failed_flush_returns_non_zero(self):
        """A wrapper may clear local state believing the upload succeeded."""
        plugin = mock.MagicMock()
        plugin.flush.return_value = mock.Mock(success=False, message="upload refused")
        with mock.patch(
            "openssl_encrypt.plugins.telemetry.OpenSSLEncryptTelemetryPlugin",
            return_value=plugin,
        ):
            self.assertFailureStatus(handle_telemetry_command(_ns("flush")))


class TestCancellationIsDistinct(TelemetryExitCodeBase):
    def test_declining_the_prompt_is_neither_success_nor_failure(self):
        """ "No" must not read as a completed destructive action."""
        plugin = mock.MagicMock()
        with mock.patch(
            "openssl_encrypt.plugins.telemetry.OpenSSLEncryptTelemetryPlugin",
            return_value=plugin,
        ), mock.patch("builtins.input", return_value="n"):
            status = handle_telemetry_command(_ns("opt-out", force=False))
        self.assertEqual(status, 3, "a decline needs its own status")
        plugin.opt_out.assert_not_called()


class TestClearCancellationIsDistinct(TelemetryExitCodeBase):
    def test_declining_clear_does_not_delete(self):
        plugin = mock.MagicMock()
        plugin.buffer.get_pending_count.return_value = 5
        with mock.patch(
            "openssl_encrypt.plugins.telemetry.OpenSSLEncryptTelemetryPlugin",
            return_value=plugin,
        ), mock.patch("builtins.input", return_value="n"):
            status = handle_telemetry_command(_ns("clear", force=False))
        self.assertEqual(status, 3)
        plugin.buffer.clear_all.assert_not_called()


class TestClosedStdinIsNotATraceback(TelemetryExitCodeBase):
    def test_no_stdin_declines_rather_than_crashing(self):
        """A GUI or CI caller has no stdin; that must land on the contract."""
        plugin = mock.MagicMock()
        with mock.patch(
            "openssl_encrypt.plugins.telemetry.OpenSSLEncryptTelemetryPlugin",
            return_value=plugin,
        ), mock.patch("builtins.input", side_effect=EOFError):
            status = handle_telemetry_command(_ns("opt-out", force=False))
        self.assertEqual(status, 3)
        plugin.opt_out.assert_not_called()


class TestUnknownActionIsReported(TelemetryExitCodeBase):
    def test_unknown_action_returns_non_zero(self):
        plugin = mock.MagicMock()
        with mock.patch(
            "openssl_encrypt.plugins.telemetry.OpenSSLEncryptTelemetryPlugin",
            return_value=plugin,
        ):
            self.assertFailureStatus(handle_telemetry_command(_ns("no-such-action")))


if __name__ == "__main__":
    unittest.main()
