#!/usr/bin/env python3
"""`telemetry status --json` machine-readable output (gitlab#162).

A GUI toggle needs the *current* telemetry state; scraping the unversioned
human report means the toggle can show the wrong state. `telemetry status`
now emits the status dict as JSON on stdout (human report stays on stderr),
matching the convention `analyze-config`/`check-password`/`show-pending` use.
"""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from openssl_encrypt.modules.crypt_cli_subparser import build_subparser

_STATUS = {
    "enabled": False,
    "pending_events": 0,
    "server_url": "https://telemetry.example.com",
    "has_api_key": False,
    "upload_interval": 3600,
    "upload_thread_alive": False,
}


def _run(argv):
    args = build_subparser().parse_args(argv)
    out, err = io.StringIO(), io.StringIO()
    plugin = mock.MagicMock()
    plugin.get_status.return_value = dict(_STATUS)
    with mock.patch(
        "openssl_encrypt.plugins.telemetry.OpenSSLEncryptTelemetryPlugin",
        return_value=plugin,
    ), redirect_stdout(out), redirect_stderr(err):
        from openssl_encrypt.modules.crypt_cli import handle_telemetry_command

        handle_telemetry_command(args)
    return out.getvalue(), err.getvalue()


class TestTelemetryStatusJson(unittest.TestCase):
    def test_json_flag_emits_status_document_on_stdout(self):
        out, err = _run(["telemetry", "status", "--json"])
        parsed = json.loads(out)  # stdout must be valid JSON on its own
        self.assertEqual(parsed, _STATUS)
        # The human report must NOT contaminate stdout.
        self.assertNotIn("TELEMETRY STATUS", out)

    def test_json_flag_keeps_stdout_free_of_human_report(self):
        out, _ = _run(["telemetry", "status", "--json"])
        # Every line of stdout parses as one JSON document -> nothing else leaked.
        self.assertTrue(out.strip().startswith("{"))
        self.assertTrue(out.strip().endswith("}"))

    def test_default_is_human_readable_on_stderr_not_stdout(self):
        out, err = _run(["telemetry", "status"])
        self.assertEqual(out, "")  # no machine output without --json
        self.assertIn("TELEMETRY STATUS", err)


if __name__ == "__main__":
    unittest.main()
