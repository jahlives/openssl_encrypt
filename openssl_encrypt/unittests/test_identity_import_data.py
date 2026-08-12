#!/usr/bin/env python3
"""
Tests for `identity import --data-stdin` and `--alias` (gitlab#164 / github#82).

The desktop GUI has always emitted a contact document plus an optional alias,
neither of which the parser accepted: it took only `--file`. Every contact
import from the GUI therefore died at argparse with exit 2, so the feature has
never worked.

The document arrives on **stdin**, not argv. /proc/PID/cmdline is world-readable,
so an argv channel would publish the contact metadata to every local process,
and would irreversibly expose anything pasted into the GUI's free-text field by
mistake -- a private key or passphrase is leaked at execve, before the handler
can reject it.
"""

import argparse
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock

from openssl_encrypt.modules.crypt_cli_subparser import setup_identity_parser
from openssl_encrypt.modules.identity import Identity
from openssl_encrypt.modules.pqc_signing import LIBOQS_AVAILABLE


def _parse(*argv):
    parser = argparse.ArgumentParser()
    setup_identity_parser(parser)
    return parser.parse_args(list(argv))


class TestImportParserAcceptsStdin(unittest.TestCase):
    def test_data_stdin_is_accepted(self):
        self.assertTrue(_parse("import", "--data-stdin").data_stdin)

    def test_file_is_still_accepted(self):
        self.assertEqual(_parse("import", "--file", "alice.json").file, "alice.json")

    def test_alias_is_accepted(self):
        args = _parse("import", "--data-stdin", "--alias", "alice-work")
        self.assertEqual(args.alias, "alice-work")

    def test_the_document_cannot_be_passed_on_argv(self):
        """argv is world-readable; there must be no inline flag at all.

        Note argparse abbreviation resolves `--data` to `--data-stdin`, so the
        rejection comes from the document being an unrecognised positional
        rather than from `--data` being unknown. The outcome is what matters --
        no invocation accepts the document as an argv value -- but the
        mechanism is worth stating so this is not misread as proving that
        `--data` does not parse.
        """
        with self.assertRaises(SystemExit):
            _parse("import", "--data", '{"name": "alice"}')

    def test_no_option_takes_the_document_as_a_value(self):
        """The real property: no import option accepts an inline document."""
        parser = argparse.ArgumentParser()
        setup_identity_parser(parser)
        subparsers = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
        import_parser = subparsers[0].choices["import"]
        value_taking = [
            opt
            for action in import_parser._actions
            for opt in action.option_strings
            if action.nargs != 0 and action.option_strings
        ]
        self.assertNotIn("--data", value_taking)

    def test_one_source_is_required(self):
        with self.assertRaises(SystemExit):
            _parse("import")

    def test_the_two_sources_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            _parse("import", "--file", "a.json", "--data-stdin")


class TestImportHandlerReadsStdin(unittest.TestCase):
    """The flag must be consumed, not merely accepted.

    Several flags in this plan were accepted by argparse and silently
    discarded, so presence in the parser is not evidence of anything.
    """

    def setUp(self):
        self.document = {"name": "alice", "fingerprint": "AA:BB"}

    def _run(self, args, stdin=""):
        from openssl_encrypt.modules.identity_cli import cmd_import

        identity = mock.Mock()
        identity.name = "alice"
        identity.email = None
        with mock.patch(
            "openssl_encrypt.modules.identity.Identity.import_public",
            return_value=identity,
        ) as imported, mock.patch(
            "openssl_encrypt.modules.identity_cli.get_identity_store"
        ) as store, mock.patch(
            "sys.stdin", io.StringIO(stdin)
        ):
            status = cmd_import(args)
        return status, imported, identity, store

    def _args(self, **kw):
        base = dict(
            data_stdin=False,
            file=None,
            alias=None,
            overwrite=False,
            allow_key_change=False,
            identity_store=None,
        )
        base.update(kw)
        return argparse.Namespace(**base)

    def test_stdin_reaches_import_public(self):
        status, imported, _identity, _store = self._run(
            self._args(data_stdin=True), stdin=json.dumps(self.document)
        )
        self.assertEqual(status, 0)
        imported.assert_called_once()
        self.assertEqual(imported.call_args[0][0], self.document)

    def test_malformed_input_is_refused_rather_than_ignored(self):
        status, imported, _i, _s = self._run(self._args(data_stdin=True), stdin="{not json")
        self.assertNotEqual(status, 0)
        imported.assert_not_called()

    def test_a_non_object_document_is_refused(self):
        """json.loads returns lists and scalars too."""
        for raw in ('["a"]', '"alice"', "42", "null"):
            with self.subTest(raw=raw):
                status, imported, _i, _s = self._run(self._args(data_stdin=True), stdin=raw)
                self.assertNotEqual(status, 0)
                imported.assert_not_called()

    def test_alias_renames_the_stored_contact(self):
        status, _imported, identity, _store = self._run(
            self._args(data_stdin=True, alias="alice-work"),
            stdin=json.dumps(self.document),
        )
        self.assertEqual(status, 0)
        self.assertEqual(identity.name, "alice-work")

    def test_a_traversal_alias_is_refused(self):
        """The name becomes a directory name under the identity store.

        `validate_identity_name` guards the document's own name at
        identity.py:538; an alias that skipped it would be a traversal sink
        the file path never had.
        """
        for alias in ("../../etc/passwd", "/absolute", "..", ".hidden", "a/b", ""):
            with self.subTest(alias=alias):
                status, _imported, _identity, store = self._run(
                    self._args(data_stdin=True, alias=alias),
                    stdin=json.dumps(self.document),
                )
                self.assertNotEqual(status, 0, f"{alias!r} was accepted")
                store.return_value.add_identity.assert_not_called()

    def test_a_deeply_nested_document_is_refused_before_parsing(self):
        """SecureJSONValidator's pre-parse depth scan (#94) must apply here.

        json.loads recurses; a hostile document must not reach it.
        """
        status, imported, _i, _s = self._run(
            self._args(data_stdin=True), stdin="[" * 5000 + "]" * 5000
        )
        self.assertNotEqual(status, 0)
        imported.assert_not_called()

    def test_an_oversized_document_is_refused(self):
        from openssl_encrypt.modules.identity_cli import (
            MAX_IDENTITY_DOCUMENT_BYTES,
        )

        status, imported, _i, _s = self._run(
            self._args(data_stdin=True),
            stdin='{"name": "' + "a" * MAX_IDENTITY_DOCUMENT_BYTES + '"}',
        )
        self.assertNotEqual(status, 0)
        imported.assert_not_called()

    def test_a_non_boolean_data_stdin_does_not_select_the_stdin_path(self):
        """Only a real True counts.

        argparse leaves the unused source falsy, but programmatic callers need
        not -- test_identity.py::test_cmd_import passes a MagicMock, whose
        every attribute is truthy, and must still import from its file.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "alice.json")
            with open(path, "w") as f:
                json.dump(self.document, f)
            args = mock.MagicMock()
            args.file = path
            args.overwrite = False
            args.identity_store = None
            status, imported, _identity, _store = self._run(args)
        self.assertEqual(status, 0)
        self.assertEqual(imported.call_args[0][0], self.document)

    def test_a_file_still_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "alice.json")
            with open(path, "w") as f:
                json.dump(self.document, f)
            status, imported, _identity, _store = self._run(self._args(file=path))
        self.assertEqual(status, 0)
        self.assertEqual(imported.call_args[0][0], self.document)


@unittest.skipUnless(LIBOQS_AVAILABLE, "liboqs required to generate identities")
class TestAliasDoesNotEvadeKeyPinning(unittest.TestCase):
    """The alias must not become a way around TOFU key pinning.

    The rename happens before `store.add_identity`, which looks up
    `get_by_name(identity.name)` -- so the pin check keys on the name actually
    stored. Asserted end to end against a real store, with nothing mocked:
    the ordering argument this feature rests on is worth more than a comment.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store_path = os.path.join(self.tmp.name, "store")

    def _import(self, document, alias=None, allow_key_change=False, isatty=False):
        from openssl_encrypt.modules.identity_cli import cmd_import

        args = argparse.Namespace(
            data_stdin=True,
            file=None,
            alias=alias,
            overwrite=True,
            allow_key_change=allow_key_change,
            identity_store=self.store_path,
        )
        # isatty is set on the STREAM, not patched onto the real sys.stdin:
        # sys.stdin is rebound wholesale below, so patching its attribute
        # would silently do nothing and the test would pass vacuously.
        stdin = io.StringIO(json.dumps(document))
        stdin.isatty = lambda: isatty
        buf = io.StringIO()
        with mock.patch("sys.stdin", stdin), redirect_stderr(buf):
            status = cmd_import(args)
        self._stderr = buf.getvalue()
        return status

    def _stored(self, name):
        from openssl_encrypt.modules.identity_cli import get_identity_store

        return get_identity_store(self.store_path).get_by_name(name, None, load_private_keys=False)

    def test_a_substituted_key_under_the_same_alias_is_still_caught(self):
        alice = Identity.generate("alice", "alice@example.com", "pw")
        mallory = Identity.generate("mallory", "m@example.com", "pw")

        self.assertEqual(self._import(alice.export_public(), alias="contact"), 0)

        # Same local label, different keys: this is exactly the substitution
        # the pin exists to catch, and the alias must not hide it.
        status = self._import(mallory.export_public(), alias="contact")
        self.assertNotEqual(status, 0, "key substitution was accepted silently")

        # Assert the REASON, so an unrelated failure cannot masquerade as the
        # pin firing -- and the POST-CONDITION, so an implementation that
        # refused only after writing the new keys would not pass.
        self.assertIn("CHANGED", self._stderr)
        self.assertEqual(
            self._stored("contact").fingerprint,
            alice.fingerprint,
            "the pinned key was replaced despite the refusal",
        )

    def test_the_control_case_re_importing_the_same_key_is_accepted(self):
        """Without this, "refuses everything" would pass the test above.

        The claim is that a *changed* key is refused, not that a second import
        is refused; only the pair of tests distinguishes the two.
        """
        alice = Identity.generate("alice", "alice@example.com", "pw")
        self.assertEqual(self._import(alice.export_public(), alias="contact"), 0)
        self.assertEqual(
            self._import(alice.export_public(), alias="contact"),
            0,
            "re-importing an unchanged key was refused",
        )

    def test_the_alias_is_what_gets_stored(self):
        alice = Identity.generate("alice", "alice@example.com", "pw")
        self.assertEqual(self._import(alice.export_public(), alias="alice-work"), 0)

        from openssl_encrypt.modules.identity_cli import get_identity_store

        store = get_identity_store(self.store_path)
        stored = store.get_by_name("alice-work", None, load_private_keys=False)
        self.assertIsNotNone(stored, "the alias was not used as the store key")
        self.assertEqual(stored.fingerprint, alice.fingerprint)

    def test_a_stdin_document_never_gets_the_confirmation_prompt(self):
        """The bundle and the confirmation must not share one channel.

        A pty EOF is soft, so `{...}<^D>yes` would leave isatty() True and let
        whoever supplied the untrusted bundle also supply the confirmation
        that it is trustworthy. The refusal therefore keys on the document's
        source, not only on isatty().
        """
        alice = Identity.generate("alice", "alice@example.com", "pw")
        mallory = Identity.generate("mallory", "m@example.com", "pw")
        self.assertEqual(self._import(alice.export_public(), alias="contact"), 0)

        # isatty() True -- the pty case -- and input() would answer "yes" if
        # it were ever reached.
        with mock.patch("builtins.input", return_value="yes") as prompt:
            status = self._import(mallory.export_public(), alias="contact", isatty=True)

        prompt.assert_not_called()
        self.assertNotEqual(status, 0)
        self.assertEqual(self._stored("contact").fingerprint, alice.fingerprint)

    def test_the_alias_does_not_change_the_fingerprint(self):
        """Renaming must not alter the identity's cryptographic binding."""
        alice = Identity.generate("alice", "alice@example.com", "pw")
        self.assertEqual(self._import(alice.export_public(), alias="nickname"), 0)

        from openssl_encrypt.modules.identity_cli import get_identity_store

        stored = get_identity_store(self.store_path).get_by_name(
            "nickname", None, load_private_keys=False
        )
        self.assertEqual(stored.fingerprint, alice.fingerprint)
        self.assertTrue(stored.check_fingerprint_consistency())


if __name__ == "__main__":
    unittest.main()
