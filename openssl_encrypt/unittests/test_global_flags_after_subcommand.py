#!/usr/bin/env python3
"""
Tests that global flags work after a subcommand (gitlab#171 / github#89).

`--debug`, `--verbose`, `--quiet` and friends are declared on the top-level
parser, so argparse rejects them once a subcommand has been seen.
`preprocess_global_args` exists to relocate them to the front -- but only for
commands it recognises, and its `commands` set had drifted to roughly half of
the real subcommand list. For the missing ones (`identity`, `keyserver`,
`telemetry`, `plugin`, `hsm`, `test`, ...) argv was returned unchanged and the
subparser rejected the flag with exit 2.

The desktop GUI appends `--debug` after the subcommand at 19 call sites in
cli_service.dart, so with its debug toggle on, every one of those commands
failed before doing anything.

The fix is one shared constant rather than a second hand-maintained list: the
drift is the bug, so a test that merely checked today's missing names would
let the next divergence through.
"""

import sys
import unittest
from unittest import mock

from openssl_encrypt.modules.crypt_cli import (
    SUBPARSER_COMMANDS,
    preprocess_global_args,
)


class TestTheTwoCommandListsCannotDrift(unittest.TestCase):
    """The root cause was two lists of the same thing, maintained separately."""

    def test_the_preprocessor_covers_every_subcommand(self):
        for command in SUBPARSER_COMMANDS:
            with self.subTest(command=command):
                argv = ["crypt", command, "--debug"]
                self.assertEqual(
                    preprocess_global_args(argv)[1],
                    "--debug",
                    f"--debug was not relocated for '{command}'",
                )

    def test_the_command_is_preserved_after_relocation(self):
        for command in SUBPARSER_COMMANDS:
            with self.subTest(command=command):
                result = preprocess_global_args(["crypt", command, "--debug"])
                self.assertIn(command, result)
                self.assertEqual(len(result), 3)


class TestPreviouslyBrokenCommands(unittest.TestCase):
    """The commands the GUI actually calls, named explicitly.

    Each of these was verified failing against the real CLI with
    `unrecognized arguments: --debug` before the fix.
    """

    def test_identity_accepts_a_trailing_debug(self):
        self.assertEqual(
            preprocess_global_args(["crypt", "identity", "list", "--debug"]),
            ["crypt", "--debug", "identity", "list"],
        )

    def test_keyserver_accepts_a_trailing_debug(self):
        self.assertEqual(
            preprocess_global_args(["crypt", "keyserver", "search", "x", "--debug"]),
            ["crypt", "--debug", "keyserver", "search", "x"],
        )

    def test_telemetry_accepts_a_trailing_debug(self):
        self.assertEqual(
            preprocess_global_args(["crypt", "telemetry", "status", "--debug"]),
            ["crypt", "--debug", "telemetry", "status"],
        )


class TestRelocationDoesNotDisturbSubcommandArguments(unittest.TestCase):
    """Relocation must move global flags only -- never a subcommand's own."""

    def test_a_subcommand_option_and_its_value_stay_put(self):
        result = preprocess_global_args(
            ["crypt", "identity", "import", "--file", "a.json", "--debug"]
        )
        self.assertEqual(
            result, ["crypt", "--debug", "identity", "import", "--file", "a.json"]
        )

    def test_a_later_value_matching_a_command_name_does_not_move_the_anchor(self):
        """The command position is the FIRST match, so a later value is inert.

        Note this does not test that option values are excluded from the scan
        generally -- they are not. `preprocess_global_args(["crypt", "--alias",
        "telemetry", "--debug"])` does treat "telemetry" as the command
        position. That is a real (pre-existing) wart, tracked separately;
        asserting the stronger property here would be asserting something
        false.
        """
        result = preprocess_global_args(
            ["crypt", "identity", "import", "--alias", "telemetry", "--debug"]
        )
        self.assertEqual(
            result,
            ["crypt", "--debug", "identity", "import", "--alias", "telemetry"],
        )

    def test_an_unknown_command_is_left_alone(self):
        argv = ["crypt", "no-such-command", "--debug"]
        self.assertEqual(preprocess_global_args(argv), argv)

    def test_a_flag_already_at_the_front_is_not_duplicated(self):
        result = preprocess_global_args(["crypt", "--debug", "identity", "list"])
        self.assertEqual(result.count("--debug"), 1)


class TestValueCarryingGlobalFlag(unittest.TestCase):
    """--kdf-workers is the only global flag that takes a value."""

    def test_the_value_moves_with_the_flag(self):
        self.assertEqual(
            preprocess_global_args(
                ["crypt", "identity", "list", "--kdf-workers", "4"]
            ),
            ["crypt", "--kdf-workers", "4", "identity", "list"],
        )

    def test_the_equals_form_is_relocated_too(self):
        """`--kdf-workers=4` is one token, so an exact match misses it."""
        self.assertEqual(
            preprocess_global_args(["crypt", "identity", "list", "--kdf-workers=4"]),
            ["crypt", "--kdf-workers=4", "identity", "list"],
        )

    def test_the_value_is_not_mistaken_for_the_command(self):
        """main()'s scan must skip the value, not treat "4" as the command.

        Both branches of that skip used to `continue`, so the value was never
        skipped -- harmless while the flag was rarely relocated, but every
        subcommand is relocated now.
        """
        from openssl_encrypt.modules.crypt_cli import SUBPARSER_COMMANDS

        argv = preprocess_global_args(
            ["crypt", "identity", "list", "--kdf-workers", "4"]
        )
        first_command = None
        skip_next = False
        for i in range(1, len(argv)):
            if skip_next:
                skip_next = False
                continue
            arg = argv[i]
            if arg == "--kdf-workers":
                skip_next = True
                continue
            if not arg.startswith("-"):
                first_command = arg
                break
        self.assertEqual(first_command, "identity")
        self.assertIn(first_command, SUBPARSER_COMMANDS)


class TestTemplateIsNotRelocated(unittest.TestCase):
    """-t/--template is a subcommand option, not a global flag.

    It selects KDF/hash parameters. If it were relocated, the encrypt
    subparser's own `template=None` default would overwrite the top-level
    value and the file would be encrypted at default KDF cost instead of the
    requested one -- a silent downgrade.
    """

    def test_template_stays_with_the_subcommand(self):
        argv = ["crypt", "encrypt", "-i", "a", "-o", "b", "-t", "hardened"]
        self.assertEqual(preprocess_global_args(argv), argv)

    def test_template_is_not_a_global_flag(self):
        from openssl_encrypt.modules.crypt_cli import TRULY_GLOBAL_FLAGS

        self.assertNotIn("--template", TRULY_GLOBAL_FLAGS)
        self.assertNotIn("-t", TRULY_GLOBAL_FLAGS)


class TestTheFlagSurvivesParsing(unittest.TestCase):
    """Relocation is worthless if the subparser then discards the value.

    The first version of these tests only exercised preprocess_global_args, so
    they could not see that five subparsers declare their own `--quiet` whose
    default overwrites the relocated one: argparse parses a subcommand into a
    fresh namespace and copies every key back over the parent's
    (cpython argparse `_SubParsersAction.__call__`). Relocating the flag and
    then having it silently dropped is worse than rejecting it, so the
    end-to-end property is what must be asserted.
    """

    def _parse(self, argv):
        """Parse through the real parser, the way the CLI does.

        create_subparser_main() reads sys.argv itself and returns
        (parser, args) -- it is not a parser factory -- so sys.argv is what
        must be patched. Getting this wrong is how the first attempt at these
        tests produced four bogus failures.
        """
        from openssl_encrypt.modules.crypt_cli_subparser import create_subparser_main

        relocated = preprocess_global_args(["crypt"] + argv)
        with mock.patch.object(sys, "argv", relocated):
            result = create_subparser_main()
        self.assertNotEqual(result, 1, f"parser construction failed for {argv}")
        _parser, args = result
        return args

    # The five commands whose subparser declares its own --quiet.
    QUIET_OWNERS = [
        ["recover", "--input", "a.enc", "--output", "b", "--quiet"],
        ["add-recovery", "-i", "a.enc", "-o", "b.enc", "--add-code", "--quiet"],
        ["remove-recovery", "-i", "a.enc", "-o", "b.enc", "--slot-id", "1", "--quiet"],
        ["verify-integrity", "--quiet"],
        ["test", "all", "--quiet"],
    ]

    def test_quiet_survives_for_commands_that_declare_their_own(self):
        for argv in self.QUIET_OWNERS:
            with self.subTest(command=argv[0]):
                try:
                    args = self._parse(argv)
                except SystemExit:
                    self.fail(f"'{argv[0]} --quiet' was rejected by the parser")
                self.assertTrue(
                    getattr(args, "quiet", False),
                    f"--quiet was silently dropped for '{argv[0]}'",
                )

    def test_quiet_still_works_when_given_directly_to_the_subparser(self):
        """The other direction: no relocation, flag passed after the command.

        With default=SUPPRESS the subparser's own declaration is now the only
        thing setting the attribute on this path, so it needs its own test --
        every case above goes through preprocess_global_args, which moves the
        flag to the front and never exercises the subparser declaration.
        """
        from openssl_encrypt.modules.crypt_cli_subparser import create_subparser_main

        argv = ["crypt", "recover", "-i", "a.enc", "-o", "b", "--quiet"]
        with mock.patch.object(sys, "argv", argv):
            result = create_subparser_main()
        self.assertNotEqual(result, 1)
        _parser, args = result
        self.assertTrue(args.quiet)

    def test_debug_survives_parsing_for_the_previously_broken_commands(self):
        for argv in (
            ["identity", "list", "--debug"],
            ["telemetry", "status", "--debug"],
            ["keyserver", "status", "--debug"],
            ["template", "list", "--debug"],
        ):
            with self.subTest(command=argv[0]):
                try:
                    args = self._parse(argv)
                except SystemExit:
                    self.fail(f"'{' '.join(argv)}' was rejected by the parser")
                self.assertTrue(
                    getattr(args, "debug", False),
                    f"--debug was silently dropped for '{argv[0]}'",
                )


if __name__ == "__main__":
    unittest.main()
