#!/usr/bin/env python3
"""`telemetry opt-out` must persist (gitlab#166 part 5).

opt_out() stopped uploads, cleared the buffer and deleted the API key, but wrote
no persistent disable -- so a stale OPENSSL_ENCRYPT_TELEMETRY=1 (or a
config-enabled install) silently re-enabled collection and registered a new key
on the next run. opt_out now writes a persistent marker that
`_is_telemetry_enabled` honours before the env/config sources.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def _marker(home):
    return Path(home) / ".openssl_encrypt" / "telemetry" / "opted_out"


class TestOptOutMarkerOverridesEnv(unittest.TestCase):
    def test_marker_disables_even_when_env_enables(self):
        from openssl_encrypt.modules.crypt_core import _is_telemetry_enabled, set_telemetry_enabled

        with tempfile.TemporaryDirectory() as home, mock.patch(
            "pathlib.Path.home", return_value=Path(home)
        ), mock.patch.dict(os.environ, {"OPENSSL_ENCRYPT_TELEMETRY": "1"}):
            set_telemetry_enabled(False)  # clear the runtime flag
            # No marker yet: the env var enables telemetry.
            self.assertTrue(_is_telemetry_enabled())
            # An explicit opt-out marker overrides the env var.
            m = _marker(home)
            m.parent.mkdir(parents=True, exist_ok=True)
            m.write_text("opted out\n")
            self.assertFalse(_is_telemetry_enabled())

    def test_no_marker_leaves_env_in_control(self):
        from openssl_encrypt.modules.crypt_core import _is_telemetry_enabled, set_telemetry_enabled

        with tempfile.TemporaryDirectory() as home, mock.patch(
            "pathlib.Path.home", return_value=Path(home)
        ), mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPENSSL_ENCRYPT_TELEMETRY", None)
            set_telemetry_enabled(False)
            self.assertFalse(_is_telemetry_enabled())  # default opt-in: off


class TestOptOutWritesTheMarker(unittest.TestCase):
    def test_opt_out_persists_the_marker(self):
        from openssl_encrypt.plugins.telemetry.telemetry_plugin import OpenSSLEncryptTelemetryPlugin

        with tempfile.TemporaryDirectory() as home, mock.patch(
            "pathlib.Path.home", return_value=Path(home)
        ):
            # Bypass __init__ (needs real buffer/key files) and stub the parts
            # opt_out touches.
            plugin = OpenSSLEncryptTelemetryPlugin.__new__(OpenSSLEncryptTelemetryPlugin)
            plugin.stop = mock.MagicMock()
            plugin.buffer = mock.MagicMock()
            plugin.buffer.clear_all.return_value = 3
            plugin.key_manager = mock.MagicMock()

            result = plugin.opt_out()

            self.assertTrue(result.success)
            self.assertTrue(_marker(home).exists(), "opt-out marker was not written")
            self.assertIn("persistently disabled", result.message)

    def test_opt_out_does_not_claim_persistence_when_marker_write_fails(self):
        from openssl_encrypt.plugins.telemetry.telemetry_plugin import OpenSSLEncryptTelemetryPlugin

        with tempfile.TemporaryDirectory() as home, mock.patch(
            "pathlib.Path.home", return_value=Path(home)
        ), mock.patch("pathlib.Path.write_text", side_effect=OSError("read-only")):
            plugin = OpenSSLEncryptTelemetryPlugin.__new__(OpenSSLEncryptTelemetryPlugin)
            plugin.stop = mock.MagicMock()
            plugin.buffer = mock.MagicMock()
            plugin.buffer.clear_all.return_value = 3
            plugin.key_manager = mock.MagicMock()

            result = plugin.opt_out()

            # The key/buffer were still cleared, so the op "succeeds", but the
            # message must NOT falsely promise persistent disablement (gitlab#166
            # part 5 security review finding).
            self.assertTrue(result.success)
            self.assertFalse(_marker(home).exists())
            self.assertNotIn("persistently disabled", result.message)
            self.assertIn("WARNING", result.message)


if __name__ == "__main__":
    unittest.main()
