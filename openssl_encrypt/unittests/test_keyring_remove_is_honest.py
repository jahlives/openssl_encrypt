#!/usr/bin/env python3
"""
`--keyring-remove` must delete only when asked, and must say so truthfully
(follow-up security review of gitlab#177).

Three defects in one credential-removal control:

  * **It fired from a position argparse would not honour.** The pre-scan
    walk stopped at `--` and at the command token but did not skip an
    option's *value*, so `crypt --identity-store --keyring-remove encrypt
    -i f` -- a "forgot the path" typo -- deleted the keyring entry named
    `encrypt` and exited 0. argparse would have failed with
    `argument --identity-store: expected one argument` and deleted nothing.

  * **It was a no-op in two reachable spellings.** Nothing anywhere reads
    `args.keyring_remove`; the option exists only through the raw-argv
    pre-scan. So an abbreviation (`--keyring-rem`), which argparse binds
    happily, silently did nothing -- and the option was also declared on
    encrypt/decrypt and two other subcommands, where it was advertised in
    `--help` and did nothing at all. That is a false assurance on a
    credential-removal control, the same class the project treated as a
    Security entry for enable/disable-plugin.

  * **A failed deletion was reported as success.** A locked backend, a DBus
    failure or a permission error was reported as "No password found",
    exit 0 -- so a script that removes a credential and checks `$?` could
    not tell "deleted" from "still there". The telemetry opt-out three
    functions up rejects exactly this, returning 1 because "a caller that
    cannot tell a refusal from a completed deletion may tell the user their
    data is gone when it is not".
"""

import unittest
from unittest import mock


class _PrescanTestCase(unittest.TestCase):
    def _run(self, argv, delete=None):
        """Drive main()'s pre-scan, capturing the deletion. Returns
        (label_or_None, exit_code)."""
        from openssl_encrypt.modules import crypt_cli

        deleted = []

        class _FakeKeyring:
            errors = type("errors", (), {"PasswordDeleteError": type("PDE", (Exception,), {})})

            @staticmethod
            def delete_password(service, label):
                deleted.append(label)
                if delete is not None:
                    raise delete

        code = None
        with mock.patch.dict("sys.modules", {"keyring": _FakeKeyring}):
            with mock.patch.object(crypt_cli.sys, "argv", list(argv)):
                try:
                    crypt_cli.main()
                except SystemExit as exit_error:
                    code = exit_error.code
                except Exception:
                    pass
        return (deleted[0] if deleted else None), code


class TestItFiresOnlyFromAnOptionPosition(_PrescanTestCase):
    def test_a_value_of_another_option_is_not_a_request(self):
        label, _code = self._run(
            ["crypt", "--identity-store", "--keyring-remove", "encrypt", "-i", "f"]
        )
        self.assertIsNone(
            label,
            "a keyring entry was deleted because --keyring-remove was the "
            "VALUE of --identity-store, which argparse would have rejected",
        )

    def test_a_label_that_looks_like_a_flag_is_refused(self):
        """`crypt --keyring-remove --debug` means the user forgot the label."""
        label, _code = self._run(["crypt", "--keyring-remove", "--debug"])
        self.assertIsNone(label)

    def test_an_empty_label_is_refused(self):
        label, _code = self._run(["crypt", "--keyring-remove="])
        self.assertIsNone(label)

    def test_the_last_occurrence_wins_like_argparse(self):
        label, _code = self._run(["crypt", "--keyring-remove", "a", "--keyring-remove", "b"])
        self.assertEqual(label, "b", "the first occurrence was used; argparse binds the last")

    def test_an_abbreviation_is_honoured(self):
        """argparse binds --keyring-rem, so the pre-scan must too -- or the
        option silently does nothing."""
        label, _code = self._run(["crypt", "--keyring-rem", "my-label"])
        self.assertEqual(label, "my-label")

    def test_the_plain_form_still_works(self):
        label, code = self._run(["crypt", "--keyring-remove", "my-label"])
        self.assertEqual(label, "my-label")
        self.assertEqual(code, 0)


class TestItReportsFailureAsFailure(_PrescanTestCase):
    def test_a_backend_error_exits_non_zero(self):
        _label, code = self._run(
            ["crypt", "--keyring-remove", "my-label"], delete=RuntimeError("dbus unavailable")
        )
        self.assertNotEqual(
            code,
            0,
            "a failed deletion exited 0, so a caller cannot tell 'removed' "
            "from 'backend unavailable, still there'",
        )

    def test_a_missing_entry_is_not_an_error(self):
        """Not-found is the ordinary case and stays exit 0: the credential is
        not there, which is what the user asked for. Distinguished from a
        backend failure by the exception type the library raises."""
        from openssl_encrypt.modules import crypt_cli

        class _NotFound(Exception):
            pass

        class _FakeKeyring:
            errors = type("errors", (), {"PasswordDeleteError": _NotFound})

            @staticmethod
            def delete_password(service, label):
                raise _NotFound("no such password")

        code = None
        with mock.patch.dict("sys.modules", {"keyring": _FakeKeyring}):
            with mock.patch.object(crypt_cli.sys, "argv", ["crypt", "--keyring-remove", "gone"]):
                try:
                    crypt_cli.main()
                except SystemExit as exit_error:
                    code = exit_error.code
        self.assertEqual(code, 0, "a missing entry was reported as a failure")

    def test_the_success_path_exits_zero(self):
        _label, code = self._run(["crypt", "--keyring-remove", "my-label"])
        self.assertEqual(code, 0)


class TestTheSubcommandDeclarationIsGone(unittest.TestCase):
    """It was advertised on encrypt/decrypt and did nothing there."""

    def test_encrypt_does_not_advertise_it(self):
        from openssl_encrypt.modules.crypt_cli_subparser import build_subparser
        import argparse

        parser = build_subparser()
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                encrypt = action.choices.get("encrypt")
                break
        else:
            self.skipTest("no subparsers found")

        options = {opt for act in encrypt._actions for opt in act.option_strings}
        self.assertNotIn(
            "--keyring-remove",
            options,
            "encrypt still advertises --keyring-remove, which does nothing there",
        )

    def test_the_top_level_still_declares_it(self):
        """It is a real top-level option; only the subcommand copies were
        dead surface."""
        from openssl_encrypt.modules.crypt_cli_subparser import build_subparser

        options = {opt for act in build_subparser()._actions for opt in act.option_strings}
        self.assertIn("--keyring-remove", options)


if __name__ == "__main__":
    unittest.main()
