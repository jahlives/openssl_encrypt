"""Tests for the `plugin integrity` management CLI (gitlab#194).

The crux is the four-outcome verify contract: match / mismatch / not_found /
unreachable must be distinguishable, and not_found or unreachable must NEVER
read as a tamper alarm. Drives integrity_cli.main() with stubbed plugin.
"""

import io
import json
import unittest
from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from openssl_encrypt.modules.crypt_cli_subparser import build_subparser
from openssl_encrypt.modules.plugin_system import integrity_cli


class _StubPlugin:
    """Context-manager stub matching IntegrityPlugin's usage."""

    def __init__(self, verify_result=None, verify_raises=None, stats=None):
        self._verify_result = verify_result
        self._verify_raises = verify_raises
        self._stats = stats or {"total_verifications": 5}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get_profile(self):
        return {"client_id": "c1"}

    def get_stats(self):
        return self._stats

    def verify(self, file_id, metadata_hash):
        if self._verify_raises:
            raise self._verify_raises
        return self._verify_result


def _enabled():
    cfg = mock.Mock()
    cfg.enabled = True
    return cfg


class TestIntegrityVerifyOutcomes(unittest.TestCase):
    def _run_verify(self, stub):
        with mock.patch(
            "openssl_encrypt.plugins.integrity.config.IntegrityConfig.from_file",
            return_value=_enabled(),
        ), mock.patch(
            "openssl_encrypt.plugins.integrity.integrity_plugin.IntegrityPlugin",
            return_value=stub,
        ):
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = integrity_cli.main(
                    Namespace(integrity_action="verify", file_id="f1", metadata_hash="a" * 64)
                )
            return rc, out.getvalue(), err.getvalue()

    def test_match_is_exit_0(self):
        rc, out, err = self._run_verify(_StubPlugin(verify_result=(True, {"stored": "x"})))
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["outcome"], "match")
        self.assertIn("confirmed", err.lower())

    def test_mismatch_is_exit_1_and_alarms(self):
        rc, out, err = self._run_verify(
            _StubPlugin(verify_result=(False, {"warning": "hash differs"}))
        )
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out)["outcome"], "mismatch")
        self.assertIn("VIOLATION", err)

    def test_not_found_is_exit_3_and_NOT_an_alarm(self):
        # match False, no warning => never registered. Must not read as tamper.
        rc, out, err = self._run_verify(_StubPlugin(verify_result=(False, {})))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(out)["outcome"], "not_found")
        # Never a tamper alarm, but honest rather than falsely reassuring.
        self.assertNotIn("VIOLATION", err)
        self.assertIn("not a confirmed tamper alarm", err)
        self.assertIn("out of band", err)

    def test_unreachable_is_exit_4_and_NOT_an_alarm(self):
        rc, out, err = self._run_verify(
            _StubPlugin(verify_raises=RuntimeError("connection refused"))
        )
        self.assertEqual(rc, 4)
        self.assertEqual(json.loads(out)["outcome"], "unreachable")
        self.assertNotIn("VIOLATION", err)


class TestIntegrityStatsAndDispatch(unittest.TestCase):
    def test_stats_emits_json(self):
        with mock.patch(
            "openssl_encrypt.plugins.integrity.config.IntegrityConfig.from_file",
            return_value=_enabled(),
        ), mock.patch(
            "openssl_encrypt.plugins.integrity.integrity_plugin.IntegrityPlugin",
            return_value=_StubPlugin(stats={"total_verifications": 9}),
        ):
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                rc = integrity_cli.main(Namespace(integrity_action="stats"))
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out.getvalue())["total_verifications"], 9)

    def test_verify_requires_args(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = integrity_cli.main(
                Namespace(integrity_action="verify", file_id=None, metadata_hash=None)
            )
        self.assertEqual(rc, 2)

    def test_disabled_fails_closed_without_alarm(self):
        cfg = mock.Mock()
        cfg.enabled = False
        with mock.patch(
            "openssl_encrypt.plugins.integrity.config.IntegrityConfig.from_file",
            return_value=cfg,
        ):
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = integrity_cli.main(
                    Namespace(integrity_action="verify", file_id="f", metadata_hash="a" * 64)
                )
        # Not enabled is unreachable-ish (exit 4), never a violation, and emits
        # a uniform JSON outcome document.
        self.assertEqual(rc, 4)
        self.assertNotIn("VIOLATION", err.getvalue())
        self.assertEqual(json.loads(out.getvalue())["outcome"], "unreachable")

    def test_unknown_action(self):
        err = io.StringIO()
        with redirect_stderr(err), redirect_stdout(io.StringIO()):
            rc = integrity_cli.main(Namespace(integrity_action="bogus"))
        self.assertEqual(rc, 2)


class TestIntegrityArgvParses(unittest.TestCase):
    def setUp(self):
        self.parser = build_subparser()

    def test_stats(self):
        ns = self.parser.parse_args(["plugin", "integrity", "stats"])
        self.assertEqual(ns.integrity_action, "stats")

    def test_verify(self):
        ns = self.parser.parse_args(
            ["plugin", "integrity", "verify", "--file-id", "f1", "--metadata-hash", "a" * 64]
        )
        self.assertEqual(ns.file_id, "f1")
        self.assertEqual(ns.metadata_hash, "a" * 64)

    def test_test_with_certs(self):
        ns = self.parser.parse_args(
            [
                "plugin",
                "integrity",
                "test",
                "--url",
                "https://x",
                "--client-cert",
                "/c",
                "--client-key",
                "/k",
            ]
        )
        self.assertEqual(ns.integrity_action, "test")
        self.assertEqual(ns.url, "https://x")


if __name__ == "__main__":
    unittest.main()
