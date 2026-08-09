#!/usr/bin/env python3
"""Machine-readable output for analyze-security and smart-recommendations (gitlab#162).

A GUI that renders a *misparsed* security readout is worse than one that renders
none. These commands now emit a structured JSON document on stdout (human report
stays on stderr), matching the convention analyze-config already uses. 1.4.x only
(the analyze/recommendations subsystem does not exist on 1.5.x).
"""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from openssl_encrypt.modules.crypt_cli_subparser import build_subparser


def _parse(argv):
    return build_subparser().parse_args(argv)


class TestAnalyzeSecurityJson(unittest.TestCase):
    def _run(self, argv):
        from openssl_encrypt.modules.crypt_cli import analyze_current_security_configuration

        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            analyze_current_security_configuration(_parse(argv))
        return out.getvalue(), err.getvalue()

    def test_json_emits_analysis_document_on_stdout(self):
        out, err = self._run(
            ["analyze-security", "--sha256-rounds", "100000", "--output-format", "json"]
        )
        doc = json.loads(out)  # stdout is a single valid JSON document
        self.assertIn("overall", doc)
        # The SecurityLevel enum is serialised as its name, not "SecurityLevel.X".
        self.assertIsInstance(doc["overall"]["level"], str)
        self.assertNotIn("SecurityLevel.", doc["overall"]["level"])
        self.assertIn("hash_analysis", doc)
        # No human header leaked onto stdout.
        self.assertNotIn("SECURITY CONFIGURATION ANALYSIS", out)

    def test_text_mode_writes_to_stderr_not_stdout(self):
        out, err = self._run(["analyze-security", "--sha256-rounds", "100000"])
        self.assertEqual(out, "")
        self.assertIn("SECURITY CONFIGURATION ANALYSIS", err)

    def test_json_scoring_failure_emits_error_document_and_exits_nonzero(self):
        # A scoring failure in json mode must not yield empty stdout + exit 0:
        # a GUI/script has to be able to tell failure from an empty success.
        from openssl_encrypt.modules.crypt_cli import analyze_current_security_configuration

        out, err = io.StringIO(), io.StringIO()
        with mock.patch(
            "openssl_encrypt.modules.crypt_cli.SecurityScorer",
            side_effect=RuntimeError("boom"),
        ), redirect_stdout(out), redirect_stderr(err):
            with self.assertRaises(SystemExit) as cm:
                analyze_current_security_configuration(
                    _parse(
                        ["analyze-security", "--sha256-rounds", "100000", "--output-format", "json"]
                    )
                )
        self.assertNotEqual(cm.exception.code, 0)
        self.assertEqual(json.loads(out.getvalue()), {"error": "boom"})


class TestSmartRecommendationsJson(unittest.TestCase):
    def _real_recommendation(self):
        from openssl_encrypt.modules.smart_recommendations import (
            ConfidenceLevel,
            RecommendationCategory,
            RecommendationPriority,
            SmartRecommendation,
        )

        return SmartRecommendation(
            id="rec-1",
            category=list(RecommendationCategory)[0],
            priority=list(RecommendationPriority)[0],
            confidence=list(ConfidenceLevel)[0],
            title="Use Argon2id",
            description="d",
            action="a",
            reasoning="r",
            evidence=["e1"],
            trade_offs={"speed": "slower"},
            implementation_difficulty="easy",
            estimated_impact="high",
            applicable_contexts=["personal"],
        )

    def test_get_json_lists_recommendations_on_stdout(self):
        from openssl_encrypt.modules.crypt_cli import _handle_recommendations_get

        engine = mock.MagicMock()
        engine.load_user_context.return_value = None
        engine.generate_recommendations.return_value = [self._real_recommendation()]

        args = _parse(["smart-recommendations", "get", "--output-format", "json"])
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            _handle_recommendations_get(engine, args)

        doc = json.loads(out.getvalue())
        self.assertEqual(len(doc["recommendations"]), 1)
        rec = doc["recommendations"][0]
        self.assertEqual(rec["id"], "rec-1")
        # enum fields are serialised as scalars, not "Category.X"
        self.assertNotIn("Category.", str(rec["category"]))
        self.assertNotIn("SMART RECOMMENDATIONS", out.getvalue())
        engine.save_user_context.assert_called_once()

    def test_quick_json_has_use_case_and_list(self):
        from openssl_encrypt.modules.crypt_cli import _handle_recommendations_quick

        engine = mock.MagicMock()
        engine.get_quick_recommendations.return_value = ["do X", "do Y"]

        args = _parse(["smart-recommendations", "quick", "personal", "--output-format", "json"])
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            _handle_recommendations_quick(engine, args)

        doc = json.loads(out.getvalue())
        self.assertEqual(doc["use_case"], "personal")
        self.assertEqual(doc["recommendations"], ["do X", "do Y"])
        self.assertNotIn("QUICK RECOMMENDATIONS", out.getvalue())

    def test_quick_text_mode_stays_on_stderr(self):
        from openssl_encrypt.modules.crypt_cli import _handle_recommendations_quick

        engine = mock.MagicMock()
        engine.get_quick_recommendations.return_value = ["do X"]

        args = _parse(["smart-recommendations", "quick", "personal"])
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            _handle_recommendations_quick(engine, args)

        self.assertEqual(out.getvalue(), "")
        self.assertIn("QUICK RECOMMENDATIONS", err.getvalue())


if __name__ == "__main__":
    unittest.main()
