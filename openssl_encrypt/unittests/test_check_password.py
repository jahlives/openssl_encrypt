#!/usr/bin/env python3
"""
Tests for the check-password reporting core and CLI command.

The pure functions ``build_strength_report`` / ``format_strength_report`` are
unit-tested directly; the ``check-password`` subcommand is exercised end-to-end
via a subprocess (password supplied through the CRYPT_PASSWORD env var so it
never lands in argv).
"""

import json
import os
import subprocess
import sys
import unittest

from openssl_encrypt.modules.password_policy import build_strength_report, format_strength_report

STRONG = "Xk9$mQ2vLp8@Wn4!zR"
SEQ_HIGH_RAW = "Abcdefghijk1!"  # clears raw standard gate (~85 bits) but a sequence

_REQUIRED_KEYS = {
    "length",
    "raw_bits",
    "bits",
    "category",
    "warnings",
    "source",
    "policy_level",
    "strict_strength",
    "valid",
    "failures",
}


class TestBuildStrengthReport(unittest.TestCase):
    def test_report_shape_is_json_serialisable(self):
        report = build_strength_report(STRONG, policy_level="standard")
        self.assertEqual(set(report), _REQUIRED_KEYS)
        # Must round-trip through JSON (the --json path depends on this).
        self.assertEqual(json.loads(json.dumps(report))["category"], report["category"])

    def test_strong_password_passes_standard(self):
        report = build_strength_report(STRONG, policy_level="standard")
        self.assertTrue(report["valid"], report["failures"])
        self.assertIn(report["category"], ("STRONG", "VERY STRONG"))

    def test_advisory_accepts_but_flags_sequence(self):
        report = build_strength_report(SEQ_HIGH_RAW, policy_level="standard")
        self.assertTrue(report["valid"], report["failures"])  # advisory: raw gate
        self.assertTrue(report["warnings"])  # but flagged as weak
        self.assertLess(report["bits"], report["raw_bits"])

    def test_strict_rejects_sequence(self):
        report = build_strength_report(SEQ_HIGH_RAW, policy_level="standard", strict_strength=True)
        self.assertFalse(report["valid"])
        self.assertTrue(any("entropy" in f.lower() for f in report["failures"]))

    def test_policy_none_skips_gate(self):
        report = build_strength_report(SEQ_HIGH_RAW, policy_level="none")
        self.assertTrue(report["valid"])
        self.assertEqual(report["failures"], [])


class TestFormatStrengthReport(unittest.TestCase):
    def test_human_output_contains_category_and_status(self):
        text = format_strength_report(
            build_strength_report(SEQ_HIGH_RAW, policy_level="standard", strict_strength=True)
        )
        self.assertIn("Password strength:", text)
        self.assertIn("FAIL", text)
        self.assertIn("Weakness:", text)

    def test_none_policy_omits_policy_line(self):
        text = format_strength_report(build_strength_report(STRONG, policy_level="none"))
        self.assertNotIn("Policy", text)


class TestCheckPasswordCli(unittest.TestCase):
    """End-to-end subcommand behaviour (password via CRYPT_PASSWORD env)."""

    def _run(self, password, *extra):
        env = dict(os.environ, CRYPT_PASSWORD=password)
        return subprocess.run(
            [sys.executable, "-m", "openssl_encrypt.crypt", "check-password", *extra],
            capture_output=True,
            text=True,
            env=env,
        )

    def test_json_output_on_stdout(self):
        proc = self._run(STRONG, "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertIn(data["category"], ("STRONG", "VERY STRONG"))
        self.assertTrue(data["valid"])

    def test_strict_flag_fails_weak_password(self):
        proc = self._run(SEQ_HIGH_RAW, "--strict-strength")
        self.assertEqual(proc.returncode, 1)
        # Human report goes to stderr, not stdout.
        self.assertIn("FAIL", proc.stderr)
        self.assertEqual(proc.stdout.strip(), "")

    def test_advisory_passes_weak_password(self):
        proc = self._run(SEQ_HIGH_RAW)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Weakness:", proc.stderr)

    def _run_no_env(self, *args):
        # Run with -p and no CRYPT_PASSWORD, stdin closed so it can't fall back.
        env = {k: v for k, v in os.environ.items() if k != "CRYPT_PASSWORD"}
        return subprocess.run(
            [sys.executable, "-m", "openssl_encrypt.crypt", "check-password", *args],
            capture_output=True,
            text=True,
            env=env,
            stdin=subprocess.DEVNULL,
        )

    def test_password_flag_reports_and_warns(self):
        proc = self._run_no_env("-p", STRONG, "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(json.loads(proc.stdout)["valid"])
        # The insecure -p source must emit a warning to stderr.
        self.assertIn("Warning", proc.stderr)

    def test_password_flag_takes_precedence_over_env(self):
        # -p wins over CRYPT_PASSWORD: a strong -p passes even if env is weak.
        env = dict(os.environ, CRYPT_PASSWORD="weak")
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt.crypt",
                "check-password",
                "-p",
                STRONG,
                "--json",
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["length"], len(STRONG))


if __name__ == "__main__":
    unittest.main()
