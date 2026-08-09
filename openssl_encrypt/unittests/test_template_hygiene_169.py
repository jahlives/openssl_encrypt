#!/usr/bin/env python3
"""Template subsystem hygiene (gitlab#169 parts 3, 4, 6), 1.4.x only.

Part 4: `template create`/`analyze`/`delete` read `args.template_name` while the
parser defines positionals `name`/`template`/`template`, so every one exited 1;
and `template list --use-case` read an undefined `args.category`, so the filter
was silently ignored. Part 3: `create_template_from_args` did `config = vars(args)`
and `save_template` wrote a bare, umask-mode file (a secret-to-disk sink if a
richer namespace ever reached it). Part 6: `load_template` tried the raw
caller-supplied path first, so an absolute path outside the template dir was read.
"""

import os
import stat
import tempfile
import unittest
from argparse import Namespace
from unittest import mock

from openssl_encrypt.modules.crypt_cli import (
    _handle_template_analyze,
    _handle_template_create,
    _handle_template_delete,
    _handle_template_list,
)
from openssl_encrypt.modules.crypt_cli_subparser import build_subparser
from openssl_encrypt.modules.template_manager import (
    EnhancedTemplate,
    TemplateFormat,
    TemplateManager,
    TemplateMetadata,
)


def _template_args(*argv):
    return build_subparser().parse_args(["template", *argv])


class TestDeadSubcommandsReadTheRightDest(unittest.TestCase):
    """Part 4: the handler must read the positional the parser actually sets."""

    def test_create_reads_name_and_reaches_the_manager(self):
        args = _template_args("create", "mytemplate")
        self.assertEqual(args.name, "mytemplate")
        mgr = mock.MagicMock()
        try:
            _handle_template_create(mgr, args)
        except (SystemExit, Exception):
            pass
        mgr.create_template_from_args.assert_called_once()
        self.assertEqual(mgr.create_template_from_args.call_args.args[1], "mytemplate")

    def test_analyze_reads_template_and_reaches_the_manager(self):
        args = _template_args("analyze", "sometemplate")
        self.assertEqual(args.template, "sometemplate")
        mgr = mock.MagicMock()
        try:
            _handle_template_analyze(mgr, args)
        except (SystemExit, Exception):
            pass
        mgr.get_template_by_name.assert_called_once_with("sometemplate")

    def test_delete_reads_template_and_reaches_the_manager(self):
        args = _template_args("delete", "sometemplate")
        self.assertEqual(args.template, "sometemplate")
        mgr = mock.MagicMock()
        with mock.patch("builtins.input", return_value="n"):
            try:
                _handle_template_delete(mgr, args)
            except (SystemExit, Exception):
                pass
        mgr.get_template_by_name.assert_called_once_with("sometemplate")


class TestListUseCaseFilterWorks(unittest.TestCase):
    """Part 4: --use-case now filters by the template's declared use-cases."""

    def _mgr_with(self, *use_case_lists):
        mgr = mock.MagicMock()
        templates = []
        for i, ucs in enumerate(use_case_lists):
            templates.append(
                EnhancedTemplate(
                    metadata=TemplateMetadata(name=f"t{i}", use_cases=list(ucs)),
                    config={"hash_config": {}},
                )
            )
        mgr.list_templates.return_value = templates
        return mgr

    def test_filter_keeps_only_matching_use_cases(self):
        mgr = self._mgr_with(["personal"], ["business"], ["personal", "archival"])
        args = Namespace(use_case="personal", format="json", verbose=False)
        import io
        from contextlib import redirect_stdout

        out = io.StringIO()
        with redirect_stdout(out):
            _handle_template_list(mgr, args)
        # list_templates() called with no category arg; filtering happens after.
        mgr.list_templates.assert_called_once_with()
        self.assertIn("t0", out.getvalue())
        self.assertIn("t2", out.getvalue())
        self.assertNotIn('"name": "t1"', out.getvalue())


class TestSaveTemplateIsPrivateAndAtomic(unittest.TestCase):
    """Part 3: a saved template is 0600, not umask-mode."""

    def test_saved_file_is_0600(self):
        with tempfile.TemporaryDirectory() as d:
            mgr = TemplateManager(template_dir=d)
            tmpl = EnhancedTemplate(
                metadata=TemplateMetadata(name="private"),
                config={"hash_config": {"pbkdf2_iterations": 600000}},
            )
            path = mgr.save_template(tmpl, format=TemplateFormat.JSON)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)


class TestCreateFromArgsExcludesSecrets(unittest.TestCase):
    """Part 3: secret-named args never reach the saved config."""

    def test_password_like_keys_are_dropped(self):
        with tempfile.TemporaryDirectory() as d:
            mgr = TemplateManager(template_dir=d)
            args = Namespace(
                password="hunter2",
                keystore_password="k",
                signer_passphrase="p",
                code="123456",  # exact-dest blocklist (substring heuristic misses it)
                sha256_rounds=1000,
            )
            with mock.patch(
                "openssl_encrypt.modules.template_manager.analyze_configuration_from_args"
            ) as an:
                an.return_value = mock.MagicMock(overall_score=5.0)
                an.return_value.security_level.name = "MODERATE"
                tmpl = mgr.create_template_from_args(args, "t")
            flat = str(tmpl.config)
            self.assertNotIn("hunter2", flat)
            self.assertNotIn("password", flat)
            self.assertNotIn("passphrase", flat)
            self.assertNotIn("123456", flat)  # the `code` dest is dropped
            self.assertIn("sha256_rounds", flat)


class TestLoadTemplateRejectsOutsidePaths(unittest.TestCase):
    """Part 6: an absolute path outside the template dir is not read."""

    def test_absolute_path_outside_dir_is_not_loaded(self):
        with tempfile.TemporaryDirectory() as d:
            mgr = TemplateManager(template_dir=d)
            # A real file outside the template dir must not be read as a template.
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as outside:
                outside.write('{"hash_config": {}}')
                outside_path = outside.name
            try:
                self.assertIsNone(mgr.load_template(outside_path))
            finally:
                os.unlink(outside_path)

    def test_a_template_saved_and_loaded_by_returned_path_still_works(self):
        with tempfile.TemporaryDirectory() as d:
            mgr = TemplateManager(template_dir=d)
            tmpl = EnhancedTemplate(
                metadata=TemplateMetadata(name="roundtrip"),
                config={"hash_config": {"pbkdf2_iterations": 600000}},
            )
            path = mgr.save_template(tmpl)  # absolute path INSIDE template_dir
            loaded = mgr.load_template(path)
            self.assertIsNotNone(loaded)


if __name__ == "__main__":
    unittest.main()
