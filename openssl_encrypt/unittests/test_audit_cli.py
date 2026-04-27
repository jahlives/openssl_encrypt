#!/usr/bin/env python3
"""
Tests for the standalone audit_cli (verify / status).

Drives ``audit_cli.main`` directly with synthetic chains laid down via the
chained ``SecurityAuditLogger`` so we exercise the same data path the CLI
will see in production.
"""

import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


def _reset_singleton():
    from openssl_encrypt.modules import security_logger as sl

    sl.SecurityAuditLogger._instance = None
    sl._security_logger = None


class _ChainEnv:
    _VARS = (
        "OPENSSL_ENCRYPT_AUDIT_CHAIN",
        "OPENSSL_ENCRYPT_AUDIT_SEED_FILE",
        "OPENSSL_ENCRYPT_DISABLE_AUDIT_LOG",
    )

    def __init__(self, **overrides):
        self.overrides = overrides
        self.saved = {}

    def __enter__(self):
        for var in self._VARS:
            self.saved[var] = os.environ.pop(var, None)
        for var, value in self.overrides.items():
            os.environ[var] = value
        return self

    def __exit__(self, *args):
        for var in self._VARS:
            os.environ.pop(var, None)
        for var, value in self.saved.items():
            if value is not None:
                os.environ[var] = value


class _CLITestBase(unittest.TestCase):
    def setUp(self):
        _reset_singleton()
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        _reset_singleton()
        shutil.rmtree(self.dir, ignore_errors=True)

    def _emit(self, count):
        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        with _ChainEnv(OPENSSL_ENCRYPT_AUDIT_CHAIN="1"):
            logger = SecurityAuditLogger(log_dir=str(self.dir), enabled=True)
            for i in range(count):
                logger.log_event(f"e{i}", "info", {"i": i})
        _reset_singleton()

    def _argv_for(self, *cli_args):
        return [
            *cli_args,
            "--log",
            str(self.dir / "security-audit.log"),
            "--seed",
            str(self.dir / "audit-seed.bin"),
            "--state",
            str(self.dir / "audit-state.json"),
        ]

    def _run(self, *argv):
        from openssl_encrypt.modules.audit_cli import main

        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()


class TestAuditVerifyCLI(_CLITestBase):
    def test_verify_intact_chain_returns_zero(self):
        self._emit(10)
        code, out, _ = self._run(*self._argv_for("verify"))
        self.assertEqual(code, 0, msg=out)
        self.assertIn("INTACT", out)
        self.assertIn("10", out)

    def test_verify_intact_chain_json(self):
        self._emit(7)
        code, out, _ = self._run(*self._argv_for("verify", "--json"))
        self.assertEqual(code, 0)
        report = json.loads(out)
        self.assertTrue(report["intact"])
        self.assertEqual(report["records_verified"], 7)
        self.assertEqual(report["last_seq"], 6)

    def test_verify_tampered_chain_returns_two_with_seq(self):
        self._emit(10)
        # Tamper with seq=4.
        log_path = self.dir / "security-audit.log"
        lines = log_path.read_text(encoding="utf-8").splitlines()
        evt = json.loads(lines[4])
        evt["details"]["i"] = 9999
        lines[4] = json.dumps(evt)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        code, out, _ = self._run(*self._argv_for("verify"))
        self.assertEqual(code, 2)
        self.assertIn("BROKEN", out)
        self.assertIn("seq=4", out)

    def test_verify_tampered_chain_json_reports_failure(self):
        self._emit(5)
        log_path = self.dir / "security-audit.log"
        lines = log_path.read_text(encoding="utf-8").splitlines()
        evt = json.loads(lines[2])
        evt["event_type"] = "tampered"
        lines[2] = json.dumps(evt)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        code, out, _ = self._run(*self._argv_for("verify", "--json"))
        self.assertEqual(code, 2)
        report = json.loads(out)
        self.assertFalse(report["intact"])
        self.assertEqual(report["failures"][0]["seq"], 2)
        self.assertEqual(report["failures"][0]["reason"], "mac_mismatch")

    def test_verify_missing_seed_returns_three(self):
        self._emit(3)
        # Remove the seed.
        (self.dir / "audit-seed.bin").unlink()
        code, _out, _ = self._run(*self._argv_for("verify"))
        self.assertEqual(code, 3)

    def test_verify_missing_log_returns_one(self):
        self._emit(3)
        (self.dir / "security-audit.log").unlink()
        code, _out, _ = self._run(*self._argv_for("verify"))
        self.assertEqual(code, 1)

    def test_verify_detects_tail_truncation_via_state(self):
        self._emit(10)
        # Truncate the log to 7 records but leave state pointing at 10.
        log_path = self.dir / "security-audit.log"
        lines = log_path.read_text(encoding="utf-8").splitlines()
        log_path.write_text("\n".join(lines[:7]) + "\n", encoding="utf-8")

        code, _out, _ = self._run(*self._argv_for("verify", "--json"))
        self.assertEqual(code, 2)


class TestAuditStatusCLI(_CLITestBase):
    def test_status_reports_current_seq(self):
        self._emit(5)
        code, out, _ = self._run(
            "status",
            "--log-dir",
            str(self.dir),
        )
        self.assertEqual(code, 0)
        self.assertIn("current_seq: 5", out)
        self.assertIn("seed_present: True", out)
        self.assertIn("state_present: True", out)

    def test_status_json(self):
        self._emit(3)
        code, out, _ = self._run(
            "status",
            "--log-dir",
            str(self.dir),
            "--json",
        )
        self.assertEqual(code, 0)
        info = json.loads(out)
        self.assertEqual(info["current_seq"], 3)
        self.assertTrue(info["seed_present"])
        self.assertTrue(info["state_present"])
        self.assertGreater(info["log_size_bytes"], 0)

    def test_status_on_unconfigured_dir(self):
        empty = Path(tempfile.mkdtemp())
        try:
            code, out, _ = self._run("status", "--log-dir", str(empty), "--json")
            self.assertEqual(code, 0)
            info = json.loads(out)
            self.assertFalse(info["seed_present"])
            self.assertFalse(info["state_present"])
            self.assertFalse(info["log_present"])
        finally:
            shutil.rmtree(empty, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
