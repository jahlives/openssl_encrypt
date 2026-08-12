#!/usr/bin/env python3
"""`template compare --format json` must emit a JSON document (gitlab#167).

`template compare` declared `--format {table,json}` but `_handle_template_compare`
never read it: it printed the human `🔄 TEMPLATE COMPARISON …` report to stderr
and emitted nothing on stdout, so a caller (the GUI's read-only template view,
P32) could ask for JSON, get exit 0, and receive nothing. `template list
--format json` was already fixed; this is the remaining `compare` half.

Follows the list handler's gitlab#169 discipline: every template-declared
string comes from a file any local process can drop in, so each is coerced and
bounded, and the self-asserted `security_score`/`security_level` are NOT
published (publishing an untrusted number as an authoritative rating is the
wrong direction) — the derived verdicts answer the comparison instead.
"""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout


def _compare(t1="quick", t2="paranoid", fmt="json"):
    from openssl_encrypt.modules.crypt_cli import run_template_manager
    from openssl_encrypt.modules.crypt_cli_subparser import build_subparser

    parser = build_subparser()
    args = parser.parse_args(["template", "compare", t1, t2, "--format", fmt])
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        status = run_template_manager(args)
    return status, out.getvalue(), err.getvalue()


class TestTemplateCompareJson(unittest.TestCase):
    def test_json_document_is_emitted_on_stdout(self):
        _, out, _ = _compare()
        doc = json.loads(out)  # valid JSON, and the only thing on stdout
        self.assertIn("template1", doc)
        self.assertIn("template2", doc)
        self.assertIn("security_comparison", doc)

    def test_human_report_does_not_reach_stdout_in_json_mode(self):
        _, out, _ = _compare()
        self.assertNotIn("TEMPLATE COMPARISON", out)

    def test_self_asserted_security_score_is_not_published(self):
        # gitlab#169: the raw file-declared score must not be handed to an
        # automated consumer as an authoritative rating.
        _, out, _ = _compare()
        self.assertNotIn("security_score", out)

    def test_verdicts_are_labelled_with_their_trust_basis(self):
        # gitlab#169: a machine consumer must be able to tell the self-asserted
        # (file-declared) security verdict from the analyzer-computed one.
        _, out, _ = _compare()
        doc = json.loads(out)
        self.assertEqual(doc["security_comparison"]["basis"], "template_declared")
        self.assertEqual(doc["performance_comparison"]["basis"], "analyzer_computed")

    def test_table_mode_still_prints_the_human_report(self):
        _, out, err = _compare(fmt="table")
        self.assertEqual(out, "")
        self.assertIn("TEMPLATE COMPARISON", err)


if __name__ == "__main__":
    unittest.main()
