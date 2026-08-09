"""Tests for the `plugin pepper` management CLI (gitlab#193).

Drives pepper_cli.main() with argparse-style namespaces and a stubbed
PepperPlugin, so it exercises dispatch, output shape, exit codes, and secret
handling without a server. Also parses real argv through the plugin subparser
to confirm the surface matches the GUI's contract.
"""

import io
import json
import unittest
from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from openssl_encrypt.modules.crypt_cli_subparser import build_subparser
from openssl_encrypt.modules.plugin_system import pepper_cli


class _StubPlugin:
    def __init__(self):
        self.calls = []

    def get_profile(self):
        self.calls.append(("get_profile",))
        return {"client_id": "c1"}

    def list_peppers(self):
        self.calls.append(("list_peppers",))
        return [{"name": "p1", "created_at": "2026-01-01", "access_count": 3}]

    def setup_totp(self):
        self.calls.append(("setup_totp",))
        return {"secret": "S3CRET", "qr_svg": "<svg/>", "uri": "otpauth://x", "message": "scan me"}

    def verify_totp(self, code):
        self.calls.append(("verify_totp", code))
        return {"message": "ok", "backup_codes": ["bc1", "bc2"]}

    def configure_deadman(self, interval, grace_period, enabled=True):
        self.calls.append(("configure_deadman", interval, grace_period, enabled))
        return {"enabled": enabled}

    def disable_deadman(self):
        self.calls.append(("disable_deadman",))
        return {"enabled": False}


def _enabled_config(**over):
    cfg = mock.Mock()
    cfg.enabled = over.get("enabled", True)
    return cfg


class TestPepperCliDispatch(unittest.TestCase):
    def setUp(self):
        self.stub = _StubPlugin()
        # list/setup-totp/verify-totp/configure-deadman go through from_file.
        self._cfg = mock.patch(
            "openssl_encrypt.plugins.pepper.config.PepperConfig.from_file",
            return_value=_enabled_config(),
        )
        self._plugin = mock.patch(
            "openssl_encrypt.plugins.pepper.pepper_plugin.PepperPlugin",
            return_value=self.stub,
        )
        self._cfg.start()
        self._plugin.start()
        self.addCleanup(self._cfg.stop)
        self.addCleanup(self._plugin.stop)

    def _run(self, ns):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = pepper_cli.main(ns)
        return rc, out.getvalue(), err.getvalue()

    def test_list_emits_peppers_json(self):
        rc, out, _ = self._run(Namespace(pepper_action="list"))
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["peppers"][0]["name"], "p1")

    def test_setup_totp_emits_secret_and_qr_on_stdout_only(self):
        rc, out, err = self._run(Namespace(pepper_action="setup-totp"))
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        self.assertEqual(doc["secret"], "S3CRET")
        # GUI reads qr_code; qr_svg kept for precise consumers; same value.
        self.assertEqual(doc["qr_code"], "<svg/>")
        self.assertEqual(doc["qr_svg"], "<svg/>")
        # The secret must NOT appear on stderr (which the GUI logs).
        self.assertNotIn("S3CRET", err)

    def test_setup_totp_registers_the_secret_with_the_redactor(self):
        with mock.patch(
            "openssl_encrypt.modules.plugin_system.pepper_cli.register_consumed_secret"
        ) as reg:
            self._run(Namespace(pepper_action="setup-totp"))
        reg.assert_any_call("pepper_totp_secret", "S3CRET")

    def test_verify_totp_requires_code(self):
        rc, _, err = self._run(Namespace(pepper_action="verify-totp", code=None))
        self.assertEqual(rc, 2)
        self.assertIn("--code", err)

    def test_verify_totp_delivers_backup_codes_and_registers_them(self):
        with mock.patch(
            "openssl_encrypt.modules.plugin_system.pepper_cli.register_consumed_secret"
        ) as reg:
            rc, out, _ = self._run(Namespace(pepper_action="verify-totp", code="123456"))
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        self.assertTrue(doc["verified"])
        self.assertEqual(doc["backup_codes"], ["bc1", "bc2"])
        reg.assert_any_call("pepper_backup_code_0", "bc1")
        reg.assert_any_call("pepper_backup_code_1", "bc2")

    def test_configure_deadman_enable_converts_days_to_duration(self):
        rc, _, _ = self._run(
            Namespace(
                pepper_action="configure-deadman",
                enable=True,
                disable=False,
                interval=7,
                grace_period=2,
            )
        )
        self.assertEqual(rc, 0)
        self.assertIn(("configure_deadman", "7d", "2d", True), self.stub.calls)

    def test_configure_deadman_disable(self):
        rc, _, _ = self._run(
            Namespace(
                pepper_action="configure-deadman",
                enable=False,
                disable=True,
                interval=None,
                grace_period=None,
            )
        )
        self.assertEqual(rc, 0)
        self.assertIn(("disable_deadman",), self.stub.calls)

    def test_configure_deadman_rejects_both(self):
        rc, _, _ = self._run(
            Namespace(
                pepper_action="configure-deadman",
                enable=True,
                disable=True,
                interval=None,
                grace_period=None,
            )
        )
        self.assertEqual(rc, 2)

    def test_configure_deadman_rejects_non_positive_interval(self):
        # Arms an auto-wipe switch: 0/negative could set an already-past
        # deadline. Must fail closed without calling configure_deadman.
        rc, _, err = self._run(
            Namespace(
                pepper_action="configure-deadman",
                enable=True,
                disable=False,
                interval=0,
                grace_period=1,
            )
        )
        self.assertEqual(rc, 2)
        self.assertIn("at least 1 day", err)
        self.assertNotIn(("configure_deadman", "0d", "1d", True), self.stub.calls)

    def test_unknown_action(self):
        rc, _, err = self._run(Namespace(pepper_action="bogus"))
        self.assertEqual(rc, 2)
        self.assertIn("Unknown or missing", err)


class TestPepperCliDisabled(unittest.TestCase):
    def test_list_fails_closed_when_pepper_disabled(self):
        cfg = mock.Mock()
        cfg.enabled = False
        with mock.patch(
            "openssl_encrypt.plugins.pepper.config.PepperConfig.from_file",
            return_value=cfg,
        ):
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = pepper_cli.main(Namespace(pepper_action="list"))
        self.assertEqual(rc, 1)
        self.assertIn("not enabled", err.getvalue())


class TestPepperArgvParses(unittest.TestCase):
    """The GUI emits these exact argv; they must parse against the real tree."""

    def setUp(self):
        self.parser = build_subparser()

    def _parse(self, argv):
        return self.parser.parse_args(argv)

    def test_list(self):
        ns = self._parse(["plugin", "pepper", "list"])
        self.assertEqual(ns.pepper_action, "list")

    def test_test_with_certs(self):
        ns = self._parse(
            [
                "plugin",
                "pepper",
                "test",
                "--url",
                "https://x",
                "--client-cert",
                "/c",
                "--client-key",
                "/k",
                "--ca-cert",
                "/ca",
            ]
        )
        self.assertEqual(ns.pepper_action, "test")
        self.assertEqual(ns.url, "https://x")

    def test_verify_totp(self):
        ns = self._parse(["plugin", "pepper", "verify-totp", "--code", "123456"])
        self.assertEqual(ns.code, "123456")

    def test_configure_deadman_enable(self):
        ns = self._parse(
            [
                "plugin",
                "pepper",
                "configure-deadman",
                "--enable",
                "--interval",
                "7",
                "--grace-period",
                "2",
            ]
        )
        self.assertTrue(ns.enable)
        self.assertEqual(ns.interval, 7)
        self.assertEqual(ns.grace_period, 2)


if __name__ == "__main__":
    unittest.main()
