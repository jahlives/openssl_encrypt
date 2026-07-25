#!/usr/bin/env python3
"""
Tests that a configuration without post-quantum protection is not reported as
having it (gitlab#166 / github#84).

`--pqc-algorithm` defaults to the *string* "none", and `_extract_pqc_info`
guarded with `if not pqc_algorithm`, which "none" satisfies. The analysis then
reported post_quantum_enabled: true for a configuration with PQC off, and
suppressed the recommendation to turn it on — telling the user they had a
protection they did not have, and withholding the advice that would give it to
them.
"""

import argparse
import io
import unittest
from contextlib import redirect_stdout

from openssl_encrypt.modules.config_analyzer import ConfigurationAnalyzer


class TestTheCommandActuallyRuns(unittest.TestCase):
    """Drive the command, not the analyzer.

    Every other test here passes a dict literal, so `config.get("use_case", "")`
    returns the default. The real CLI sets `use_case = None` (argparse declares
    it with choices and no default), which is a different value entirely — and
    the report-level tests below cannot see the difference.
    """

    def _args(self, *argv):
        from openssl_encrypt.modules.crypt_cli_subparser import (
            setup_analyze_config_parser,
        )

        parser = argparse.ArgumentParser()
        setup_analyze_config_parser(parser)
        return parser.parse_args(list(argv))

    def test_default_invocation_produces_a_report(self):
        """`analyze-config` with no options must not crash."""
        from openssl_encrypt.modules.crypt_cli import run_config_analyzer

        args = self._args("--output-format", "json")
        self.assertIsNone(getattr(args, "use_case", "unset"),
                          "argparse is expected to leave use_case as None")
        buf = io.StringIO()
        with redirect_stdout(buf):
            run_config_analyzer(args)
        self.assertTrue(buf.getvalue().strip(), "no report was produced")

    def test_default_invocation_does_not_claim_quantum_resistance(self):
        from openssl_encrypt.modules.crypt_cli import run_config_analyzer

        buf = io.StringIO()
        with redirect_stdout(buf):
            run_config_analyzer(self._args("--output-format", "json"))
        self.assertNotIn("quantum-resistant", buf.getvalue())


class TestReportDoesNotClaimQuantumResistance(unittest.TestCase):
    """Assert the REPORT, not the helper.

    The first version of these tests only exercised _extract_pqc_info, so it
    passed while every field the user actually reads still said post-quantum
    was enabled. The helper is not the product; the report is.
    """

    def setUp(self):
        self.analysis = ConfigurationAnalyzer().analyze_configuration(
            {"pqc_algorithm": "none"}
        )

    def test_summary_does_not_report_post_quantum_enabled(self):
        self.assertFalse(self.analysis.configuration_summary["post_quantum_enabled"])

    def test_future_proofing_does_not_report_quantum_ready(self):
        self.assertFalse(self.analysis.future_proofing["post_quantum_ready"])

    def test_longevity_estimate_does_not_claim_quantum_resistance(self):
        self.assertNotIn(
            "quantum-resistant",
            str(self.analysis.future_proofing.get("estimated_secure_years", "")),
        )

    def test_the_recommendation_to_enable_it_is_not_suppressed(self):
        text = " ".join(str(r) for r in (self.analysis.recommendations or []))
        self.assertIn("post-quantum", text.lower())


class TestPqcNoneIsNotEnabled(unittest.TestCase):
    def setUp(self):
        self.analyzer = ConfigurationAnalyzer()

    def test_the_string_none_is_treated_as_absent(self):
        self.assertIsNone(self.analyzer._extract_pqc_info({"pqc_algorithm": "none"}))

    def test_an_absent_key_is_still_absent(self):
        self.assertIsNone(self.analyzer._extract_pqc_info({}))

    def test_case_and_padding_do_not_smuggle_it_through(self):
        """argparse gives 'none', but a config file need not be so tidy."""
        for value in ("None", "NONE", " none ", ""):
            with self.subTest(value=value):
                self.assertIsNone(
                    self.analyzer._extract_pqc_info({"pqc_algorithm": value})
                )

    def test_a_real_algorithm_is_still_reported(self):
        info = self.analyzer._extract_pqc_info({"pqc_algorithm": "kyber768-hybrid"})
        self.assertIsNotNone(info)
        self.assertTrue(info["enabled"])
        self.assertTrue(info["hybrid"])


if __name__ == "__main__":
    unittest.main()
