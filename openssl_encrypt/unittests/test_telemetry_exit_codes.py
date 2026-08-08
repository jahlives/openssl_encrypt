#!/usr/bin/env python3
"""
`telemetry` must exit non-zero when it fails (gitlab#166, part 1).

`main_with_args` ran `handle_telemetry_command(args)` and then `sys.exit(0)`
unconditionally, while every failure inside the handler only `eprint`ed and
returned: plugin import failure, plugin init failure, and `result.success ==
False` from `flush()` or `opt_out()`.

So a caller checking the exit code could not detect that a **destructive
privacy action had failed**. A GUI would tell the user their telemetry data
was deleted when it was not -- the same shape as gitlab#199, where
`disable-plugin` reported success and persisted nothing.

The distinction that matters here, and the reason a blanket "non-zero on
anything unusual" would be wrong: **declining the confirmation is not a
failure.** The user was asked and said no; the tool did exactly what was
asked. Only an opt-out that was attempted and did not complete is an error.
"""

import unittest
from unittest import mock


class _HandlerTestCase(unittest.TestCase):
    def _run(self, action, plugin=None, force=True):
        import argparse

        from openssl_encrypt.modules import crypt_cli

        args = argparse.Namespace(
            telemetry_action=action, force=force, json=False, quiet=True, limit=10
        )
        if plugin is None:
            return crypt_cli.handle_telemetry_command(args)

        with mock.patch(
            "openssl_encrypt.plugins.telemetry.OpenSSLEncryptTelemetryPlugin",
            return_value=plugin,
        ):
            return crypt_cli.handle_telemetry_command(args)

    def _plugin(self, **overrides):
        plugin = mock.Mock()
        plugin.buffer.get_pending_count.return_value = 0
        plugin.get_status.return_value = {
            "enabled": False,
            "pending_events": 0,
            "server_url": "https://x.test",
            "has_api_key": False,
            "upload_interval": 60,
            "upload_thread_alive": False,
        }
        for key, value in overrides.items():
            setattr(plugin, key, value)
        return plugin


class TestAFailedActionExitsNonZero(_HandlerTestCase):
    def test_a_failed_opt_out_is_an_error(self):
        """The one that matters: a destructive privacy action that did not
        complete must not look like success."""
        plugin = self._plugin(
            opt_out=mock.Mock(return_value=mock.Mock(success=False, message="backend refused"))
        )
        self.assertEqual(self._run("opt-out", plugin), 1)

    def test_a_failed_flush_is_an_error(self):
        plugin = self._plugin(
            flush=mock.Mock(return_value=mock.Mock(success=False, message="upload failed"))
        )
        self.assertEqual(self._run("flush", plugin), 1)

    def test_an_unknown_action_is_an_error(self):
        self.assertEqual(self._run("no-such-action", self._plugin()), 1)


class TestSuccessAndRefusalAreNotErrors(_HandlerTestCase):
    """The negative arms. A blanket non-zero would be just as wrong."""

    def test_a_successful_opt_out_exits_zero(self):
        plugin = self._plugin(
            opt_out=mock.Mock(return_value=mock.Mock(success=True, message="done"))
        )
        self.assertIn(self._run("opt-out", plugin), (0, None))

    def test_a_successful_flush_exits_zero(self):
        plugin = self._plugin(
            flush=mock.Mock(return_value=mock.Mock(success=True, message="uploaded"))
        )
        self.assertIn(self._run("flush", plugin), (0, None))

    def test_status_exits_zero(self):
        self.assertIn(self._run("status", self._plugin()), (0, None))

    def test_declining_the_confirmation_is_not_a_failure(self):
        """The user was asked and said no. The tool did what was asked, so
        this is success -- distinguishing it from an opt-out that was
        attempted and failed is the whole point.
        """
        plugin = self._plugin(
            opt_out=mock.Mock(return_value=mock.Mock(success=True, message="done"))
        )
        with mock.patch("openssl_encrypt.modules.crypt_cli.prompt_and_read", return_value="no"):
            self.assertIn(self._run("opt-out", plugin, force=False), (0, None))
        plugin.opt_out.assert_not_called()


class TestTheExitCodeReachesTheProcess(unittest.TestCase):
    """Returning a code is useless if the caller discards it."""

    def test_main_propagates_the_handlers_status(self):
        import inspect

        from openssl_encrypt.modules import crypt_cli

        source = inspect.getsource(crypt_cli.main_with_args)
        self.assertNotIn(
            "handle_telemetry_command(args)\n        sys.exit(0)",
            source,
            "main_with_args still exits 0 regardless of what the handler returned",
        )


if __name__ == "__main__":
    unittest.main()
