#!/usr/bin/env python3
"""
Global-flag relocation must respect `--` and must not treat an option value
as the command (gitlab#177).

`preprocess_global_args` hoists the truly-global flags to the front so they
work after a subcommand (gitlab#171). Two things it got wrong:

  * **It did not stop at a bare `--`.** Everything after `--` is data by
    POSIX convention, so a file literally named `--quiet` was hoisted away
    from its subcommand and read as a flag:

        ['crypt', 'shred', '--', '--quiet']
        -> ['crypt', '--quiet', 'shred', '--']

  * **It found the command anywhere, including option values.** gitlab#171
    widened the command set from 20 names to 42, which added common
    barewords -- `test`, `version`, `sign`, `recover`, `template`,
    `identity`, `plugin`, `hsm`, `armor`. So a *value* that happens to equal
    one opened the relocation gate on an invocation with no subcommand at
    all:

        ['crypt', '--alias', 'telemetry', '--debug']
        -> ['crypt', '--debug', '--alias', 'telemetry']

Impact is low and this file says so rather than overclaiming: relocation
moves only exact global-flag tokens and preserves relative order otherwise,
so no positional is ever read as a password. What it costs is predictability
in exactly the place a user reaches for `--` to get predictability.

The corresponding scan in `main()` shares both properties and is covered
here too, because fixing one and not the other just moves the surprise.
"""

import unittest

from openssl_encrypt.modules.crypt_cli import preprocess_global_args


class TestTheDoubleDashIsRespected(unittest.TestCase):
    """`--` means "everything after this is data"."""

    def test_a_file_named_like_a_global_flag_is_left_alone(self):
        argv = ["crypt", "shred", "--", "--quiet"]
        self.assertEqual(
            preprocess_global_args(list(argv)),
            argv,
            "a file literally named --quiet was hoisted out of the argument "
            "list and read as a flag",
        )

    def test_a_short_flag_name_after_the_separator_is_left_alone(self):
        argv = ["crypt", "template", "analyze", "--", "-q"]
        self.assertEqual(preprocess_global_args(list(argv)), argv)

    def test_a_real_global_flag_before_the_separator_still_moves(self):
        """The separator must not disable relocation for what precedes it."""
        result = preprocess_global_args(["crypt", "shred", "--debug", "--", "--quiet"])
        self.assertEqual(result, ["crypt", "--debug", "shred", "--", "--quiet"])

    def test_a_value_that_is_a_flag_name_after_the_separator_survives(self):
        """keyserver set-token <token>, where the token starts with a dash."""
        argv = ["crypt", "keyserver", "set-token", "--", "--verbose"]
        self.assertEqual(preprocess_global_args(list(argv)), argv)


class TestTheCommandIsFoundAmongCommandsOnly(unittest.TestCase):
    """An option's value is not the command, however it is spelled."""

    def test_a_value_equal_to_a_command_name_does_not_open_the_gate(self):
        argv = ["crypt", "--alias", "telemetry", "--debug"]
        self.assertEqual(
            preprocess_global_args(list(argv)),
            argv,
            "the value of --alias was treated as the command, so --debug was "
            "relocated on an invocation that has no subcommand",
        )

    def test_the_same_for_a_bareword_command_name_as_a_value(self):
        """The names gitlab#171 added are ordinary words: test, version,
        sign, recover, template, identity, plugin, hsm, armor."""
        for name in ("test", "version", "sign", "recover", "identity", "armor"):
            with self.subTest(name=name):
                argv = ["crypt", "--alias", name, "--debug"]
                self.assertEqual(preprocess_global_args(list(argv)), argv)

    def test_a_real_command_after_an_option_value_is_still_found(self):
        """The load-bearing negative arm.

        Skipping option values must not skip the command itself, or
        gitlab#171 comes straight back.
        """
        result = preprocess_global_args(["crypt", "--identity-store", "/tmp/x", "sign", "--debug"])
        self.assertEqual(result[1], "--debug", f"the command was no longer found: {result}")


class TestTheOrdinaryCasesStillWork(unittest.TestCase):
    """gitlab#171 is what this preprocessing exists for; none of it may
    regress."""

    def test_a_flag_after_the_command_is_relocated(self):
        self.assertEqual(
            preprocess_global_args(["crypt", "encrypt", "-i", "f", "--debug"]),
            ["crypt", "--debug", "encrypt", "-i", "f"],
        )

    def test_a_flag_already_in_front_stays(self):
        self.assertEqual(
            preprocess_global_args(["crypt", "--debug", "encrypt", "-i", "f"]),
            ["crypt", "--debug", "encrypt", "-i", "f"],
        )

    def test_an_unknown_command_is_left_alone(self):
        argv = ["crypt", "not-a-command", "--debug"]
        self.assertEqual(preprocess_global_args(list(argv)), argv)

    def test_the_value_carrying_flag_moves_with_its_value(self):
        result = preprocess_global_args(["crypt", "encrypt", "-i", "f", "--kdf-workers", "4"])
        self.assertEqual(result[1:3], ["--kdf-workers", "4"])


class TestMainsScanAgrees(unittest.TestCase):
    """`main()` runs the same two-part scan to pick the parser.

    Fixing relocation but not routing just moves the surprise: the flags
    would stay put and then the wrong parser would reject them.
    """

    def _first_command(self, argv):
        from openssl_encrypt.modules.crypt_cli import _first_command_token

        return _first_command_token(argv)

    def test_the_command_may_follow_the_separator(self):
        """This asserted `is None` when gitlab#177 landed, and that was
        wrong: POSIX reads `crypt -- encrypt` as "encrypt is a positional",
        so returning None routed it to the wrong parser. Corrected by the
        security review of that change (finding 6). The separator itself is
        then stripped, because argparse does NOT remove it before a
        subparser -- it reports `invalid choice: '--'`.
        """
        self.assertEqual(self._first_command(["crypt", "--", "encrypt"]), "encrypt")

    def test_a_non_command_after_the_separator_is_still_none(self):
        self.assertIsNone(self._first_command(["crypt", "--", "some-file.txt"]))

    def test_an_option_value_is_not_the_command(self):
        self.assertIsNone(self._first_command(["crypt", "--alias", "telemetry"]))

    def test_a_real_command_is_still_found(self):
        self.assertEqual(self._first_command(["crypt", "encrypt", "-i", "f"]), "encrypt")

    def test_a_real_command_after_a_global_flag_is_still_found(self):
        self.assertEqual(self._first_command(["crypt", "--debug", "decrypt", "-i", "f"]), "decrypt")

    def test_a_top_level_boolean_does_not_swallow_the_command(self):
        """-h/--help is a top-level boolean that is not in
        TRULY_GLOBAL_FLAGS, so keying "does this option take a value" off
        that set alone made `crypt -h encrypt` treat `encrypt` as its value
        and find no command at all. Caught in testing; the scan reads both
        the value-taking and boolean sets off the real parser instead.

        --yes/-y was in the same position when this was written and has
        since joined TRULY_GLOBAL_FLAGS (gitlab#176). It stays in this list
        deliberately: the property under test is that a BOOLEAN does not
        swallow the command, and that must hold whether or not the flag also
        happens to be relocatable.
        """
        for flag in ("--yes", "-y", "-h", "--help"):
            with self.subTest(flag=flag):
                self.assertEqual(self._first_command(["crypt", flag, "encrypt"]), "encrypt")

    def test_a_value_carrying_top_level_flag_consumes_its_value(self):
        for flag in ("--kdf-workers", "--identity-store", "--keyring-remove"):
            with self.subTest(flag=flag):
                self.assertEqual(self._first_command(["crypt", flag, "x", "encrypt"]), "encrypt")


if __name__ == "__main__":
    unittest.main()
