#!/usr/bin/env python3
"""
The command scan must understand every option form argparse accepts
(security review of gitlab#177).

`_first_command_token` classifies each leading option as boolean or
value-taking so it knows whether the next token is the command or somebody
else's value. It did that by exact membership in two sets read off the
parser -- which cannot express two forms argparse does accept, so the
command got swallowed and the invocation failed:

    crypt -qy install-dependencies    ->  invalid choice: 'install-dependencies'
    crypt -q -y install-dependencies  ->  works
    crypt --deb identity list         ->  invalid choice: 'identity'
    crypt --debug identity list       ->  works

`-qy` is the natural spelling for the one command `--yes` exists for, and
no parser here sets `allow_abbrev=False`, so `--deb` is a valid unambiguous
prefix of `--debug`.

A third form went the other way: a bare `--` returned None, but POSIX and
argparse both take the *next* token as the command, so `crypt -- identity
list` routed to the wrong parser and failed.

All three fail closed -- argparse errors, nothing silently changes meaning.
Confirmed separately that the parser switch does not alter KDF defaults:
`--argon2-time`, `--argon2-memory` and `--password-policy` are identical in
both parsers.
"""

import unittest


class _ScanTestCase(unittest.TestCase):
    def scan(self, *argv):
        from openssl_encrypt.modules.crypt_cli import _first_command_token

        return _first_command_token(["crypt", *argv])


class TestCombinedShortOptions(_ScanTestCase):
    """`-qy` is one token containing two boolean flags."""

    def test_two_booleans_do_not_swallow_the_command(self):
        self.assertEqual(self.scan("-qy", "install-dependencies"), "install-dependencies")

    def test_either_order(self):
        self.assertEqual(self.scan("-yq", "identity"), "identity")

    def test_a_bundle_ending_in_a_value_flag_still_consumes_the_value(self):
        """`-qw 4` would be -q plus --kdf-workers' short form if it had one.

        No global value flag has a short form today, so the meaningful case
        is that an unknown letter in the bundle falls back to "takes a
        value" rather than being assumed boolean -- fail closed, not open.
        """
        self.assertIsNone(self.scan("-qZ", "encrypt"))

    def test_a_lone_dash_is_not_an_option(self):
        self.assertIsNone(self.scan("-"))


class TestAbbreviatedLongOptions(_ScanTestCase):
    """argparse accepts unambiguous prefixes unless allow_abbrev=False."""

    def test_an_abbreviated_boolean_does_not_swallow_the_command(self):
        for form in ("--deb", "--debu", "--verb", "--quie"):
            with self.subTest(form=form):
                self.assertEqual(self.scan(form, "identity"), "identity")

    def test_an_abbreviated_value_flag_still_consumes_its_value(self):
        self.assertEqual(self.scan("--kdf-work", "4", "encrypt"), "encrypt")

    def test_an_ambiguous_prefix_is_treated_as_unknown(self):
        """`--k` matches --kdf-workers and --keyring-remove, so argparse
        would reject it. Falling back to "takes a value" is the fail-closed
        choice."""
        self.assertIsNone(self.scan("--k", "encrypt"))

    def test_the_equals_form_of_an_abbreviation_is_self_contained(self):
        self.assertEqual(self.scan("--kdf-work=4", "encrypt"), "encrypt")


class TestTheSeparatorBeforeTheCommand(_ScanTestCase):
    """POSIX and argparse both take the token after `--` as the positional."""

    def test_the_command_after_the_separator_is_found(self):
        self.assertEqual(self.scan("--", "identity"), "identity")

    def test_a_non_command_after_the_separator_is_still_none(self):
        self.assertIsNone(self.scan("--", "not-a-command"))

    def test_a_flag_name_after_the_separator_is_not_a_command(self):
        """Data, not a flag -- and not a command either."""
        self.assertIsNone(self.scan("--", "--quiet"))

    def test_only_the_first_separator_counts(self):
        self.assertEqual(self.scan("--", "encrypt", "--", "--quiet"), "encrypt")

    def test_a_leading_separator_is_stripped_for_argparse(self):
        """Finding the command is not enough: argparse does NOT strip `--`
        before a subparser -- it reports `invalid choice: '--'`. Verified
        directly against argparse, contradicting the review's premise. So a
        separator that precedes the command has to be removed, or the
        invocation still fails."""
        from openssl_encrypt.modules.crypt_cli import preprocess_global_args

        self.assertEqual(
            preprocess_global_args(["crypt", "--", "identity", "list"]),
            ["crypt", "identity", "list"],
        )

    def test_a_separator_after_the_command_is_kept(self):
        """The gitlab#177 case: there it protects the data that follows."""
        from openssl_encrypt.modules.crypt_cli import preprocess_global_args

        argv = ["crypt", "shred", "--", "--quiet"]
        self.assertEqual(preprocess_global_args(list(argv)), argv)

    def test_a_global_flag_before_a_leading_separator_still_moves(self):
        from openssl_encrypt.modules.crypt_cli import preprocess_global_args

        self.assertEqual(
            preprocess_global_args(["crypt", "--debug", "--", "identity", "list"]),
            ["crypt", "--debug", "identity", "list"],
        )


class TestTheFallbackSetsAreConsistent(_ScanTestCase):
    """The hardcoded fallback fires only if the parser cannot be built.

    It listed `--kdf-workers` as boolean, because it was built from
    TRULY_GLOBAL_FLAGS which contains it -- so in that path the flag would
    not consume its value and the scan would read "4" as the command. That
    is verbatim the gitlab#171 bug the surrounding comment says was fixed.
    """

    def test_the_fallback_does_not_call_a_value_flag_boolean(self):
        from openssl_encrypt.modules import crypt_cli

        original = crypt_cli._TOP_LEVEL_FLAGS
        self.addCleanup(setattr, crypt_cli, "_TOP_LEVEL_FLAGS", original)
        crypt_cli._TOP_LEVEL_FLAGS = None

        import openssl_encrypt.modules.crypt_cli_subparser as subparser_module
        from unittest import mock

        def explode():
            raise RuntimeError("parser construction failed")

        with mock.patch.object(subparser_module, "build_subparser", explode):
            value_flags, boolean_flags = crypt_cli._top_level_flags()

        self.assertIn("--kdf-workers", value_flags)
        self.assertNotIn(
            "--kdf-workers",
            boolean_flags,
            "the fallback classifies the one value-carrying global flag as "
            "boolean, so its value would be read as the command",
        )

    def test_the_scan_still_works_on_the_fallback_path(self):
        from unittest import mock

        from openssl_encrypt.modules import crypt_cli
        import openssl_encrypt.modules.crypt_cli_subparser as subparser_module

        original = crypt_cli._TOP_LEVEL_FLAGS
        self.addCleanup(setattr, crypt_cli, "_TOP_LEVEL_FLAGS", original)
        crypt_cli._TOP_LEVEL_FLAGS = None

        def explode():
            raise RuntimeError("parser construction failed")

        with mock.patch.object(subparser_module, "build_subparser", explode):
            self.assertEqual(
                crypt_cli._first_command_token(["crypt", "--kdf-workers", "4", "encrypt"]),
                "encrypt",
            )


class TestNoTopLevelOptionHasVariableArity(unittest.TestCase):
    """The scan consumes exactly one token after a value-taking option.

    A top-level `nargs='?'` spelled without its value would swallow the
    command; `nargs='+'`/`'*'` would under-consume. Neither exists today,
    and both patterns are already common one level down -- so this fails
    the moment such an option is promoted, rather than the next time
    someone debugs a mis-routed command line.
    """

    def test_every_top_level_option_takes_zero_or_one_value(self):
        import argparse

        from openssl_encrypt.modules.crypt_cli_subparser import build_subparser

        offenders = []
        for action in build_subparser()._actions:
            if not action.option_strings:
                continue
            if isinstance(action, argparse._SubParsersAction):
                continue
            if action.nargs not in (None, 0):
                offenders.append(f"{action.option_strings}: nargs={action.nargs!r}")

        self.assertFalse(
            offenders,
            "top-level options with variable arity; _first_command_token "
            "consumes exactly one token after a value-taking option:\n" + "\n".join(offenders),
        )


if __name__ == "__main__":
    unittest.main()
