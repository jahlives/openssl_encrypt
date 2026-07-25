#!/usr/bin/env python3
"""
Tests that `template list --format json` actually emits JSON (gitlab#167 /
github#85).

`--format {table,json}` was declared on the list parser and then never read:
the handler emitted human text via eprint unconditionally, so a caller could
request JSON, receive exit 0, and get nothing on stdout. Third
accepted-then-discarded flag found in this plan, after --hsm-piv-slot and the
analyse/telemetry defects.

The payload deliberately omits security_score/security_level: for the
metadata-bearing template format they are taken verbatim from the file and
never recomputed, and list_templates() sorts by that value (gitlab#169).
"""

import argparse
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest import mock

from openssl_encrypt.modules.crypt_cli import (
    _handle_template_list,
    run_template_manager,
)
from openssl_encrypt.modules.template_manager import TemplateManager


def _ns(**kw):
    base = dict(category=None, use_case=None, format="table", verbose=False)
    base.update(kw)
    return argparse.Namespace(**base)


class TestTemplateListJson(unittest.TestCase):
    def setUp(self):
        self.mgr = TemplateManager()

    def _run(self, args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            _handle_template_list(self.mgr, args)
        return buf.getvalue()

    def test_json_format_emits_a_document_on_stdout(self):
        doc = json.loads(self._run(_ns(format="json")))
        self.assertIn("templates", doc)
        self.assertIsInstance(doc["templates"], list)

    def test_each_entry_carries_the_fields_the_human_view_shows(self):
        doc = json.loads(self._run(_ns(format="json")))
        if not doc["templates"]:
            self.skipTest("no templates available in this environment")
        entry = doc["templates"][0]
        for field in ("name", "description", "use_cases", "tags", "built_in"):
            self.assertIn(field, entry)

    def test_the_file_supplied_security_rating_is_not_published(self):
        """It is never recomputed and is the sort key — not ours to assert."""
        doc = json.loads(self._run(_ns(format="json")))
        for entry in doc["templates"]:
            self.assertNotIn("security_score", entry)
            self.assertNotIn("security_level", entry)

    def test_untrusted_fields_are_bounded_and_type_coerced(self):
        """A template file is any .json a local process can drop in."""
        bad = mock.Mock()
        bad.metadata.name = "x" * 5000
        bad.metadata.description = "y" * 50000
        bad.metadata.use_cases = "business"       # a string, not a list
        bad.metadata.tags = 42                     # not a list at all
        bad.is_built_in = False
        with mock.patch.object(self.mgr, "list_templates", return_value=[bad]):
            entry = json.loads(self._run(_ns(format="json")))["templates"][0]
        self.assertLessEqual(len(entry["name"]), 256)
        self.assertLessEqual(len(entry["description"]), 1024)
        self.assertEqual(entry["use_cases"], [])
        self.assertEqual(entry["tags"], [])

    def test_table_format_writes_nothing_to_stdout(self):
        """stdout carries the machine-readable document only."""
        self.assertEqual(self._run(_ns(format="table")), "")

    def test_an_empty_result_is_still_valid_json(self):
        """A consumer must not have to special-case "no templates"."""
        with mock.patch.object(self.mgr, "list_templates", return_value=[]):
            doc = json.loads(self._run(_ns(format="json")))
        self.assertEqual(doc["templates"], [])


class TestTemplateExitStatus(unittest.TestCase):
    """An unrecognised subcommand must not report success.

    `template` was dispatched with an unconditional sys.exit(0), so a caller
    could not tell a valid run from a mistyped subcommand — the same defect
    fixed for telemetry under gitlab#166.
    """

    def test_invalid_subcommand_returns_non_zero(self):
        status = run_template_manager(argparse.Namespace(template_action="nope"))
        self.assertIsInstance(status, int, "must return a status, not None")
        self.assertNotEqual(status, 0)

    def test_a_valid_subcommand_returns_zero(self):
        args = _ns(format="json", template_action="list")
        buf = io.StringIO()
        with redirect_stdout(buf):
            status = run_template_manager(args)
        self.assertEqual(status, 0)


if __name__ == "__main__":
    unittest.main()
