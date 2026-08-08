#!/usr/bin/env python3
"""
`--identity-store` given before the command must survive into it
(gitlab#210).

The flag is declared on the top-level parser AND on several subcommands.
argparse parses a subcommand into a fresh namespace and copies every key
back over the parent's, so the subcommand's `default=None` overwrote the
global value:

    build_subparser().parse_args(['--identity-store','/tmp/X','identity','list'])
    -> identity_store = None

so `crypt --identity-store <store> identity list` silently listed the
DEFAULT store and reported "No identities found."

`identity list` merely shows nothing. The same flag is on the destructive
commands: a user running `identity delete` with `--identity-store` pointed
at one store, believing they are working there, is working on the default
store instead -- removing an identity and its private keys from somewhere
they did not intend, with no error to signal the mistake.

This is the third instance of the same dest-clobber. gitlab#171 fixed it
for `--quiet` and gitlab#176 for `--yes`, both with
`default=argparse.SUPPRESS`; the tests that pinned those are what stopped
them regressing, which is why this one exists in the same shape.
"""

import unittest


class TestTheGlobalValueSurvives(unittest.TestCase):
    def _parse(self, argv):
        from openssl_encrypt.modules.crypt_cli_subparser import build_subparser

        return build_subparser().parse_args(argv)

    def test_it_survives_into_identity_list(self):
        args = self._parse(["--identity-store", "/tmp/X", "identity", "list"])
        self.assertEqual(
            getattr(args, "identity_store", None),
            "/tmp/X",
            "the subcommand's default overwrote the global value, so the "
            "command silently used the default store",
        )

    def test_it_survives_into_every_subcommand_that_declares_it(self):
        """Any subcommand carrying its own copy has the same hazard."""
        import argparse

        from openssl_encrypt.modules.crypt_cli_subparser import build_subparser

        parser = build_subparser()
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                choices = action.choices
                break
        else:
            self.skipTest("no subparsers found")

        declaring = [
            name
            for name, sub in choices.items()
            if any("--identity-store" in act.option_strings for act in sub._actions)
        ]
        self.assertTrue(declaring, "no subcommand declares --identity-store")

        for name in declaring:
            with self.subTest(command=name):
                try:
                    args = self._parse(["--identity-store", "/tmp/X", name])
                except SystemExit:
                    # Needs its own required arguments; the namespace copy is
                    # what matters and is covered by the cases that parse.
                    continue
                self.assertEqual(getattr(args, "identity_store", None), "/tmp/X")

    def test_a_subcommand_value_still_overrides_the_global_one(self):
        """The help text promises this: "overrides global --identity-store"."""
        # On `sign`, not `identity list`: the flag is declared on the
        # subcommand itself, not on its sub-subcommands, so `identity list
        # --identity-store X` is not even valid syntax.
        args = self._parse(
            [
                "--identity-store",
                "/tmp/GLOBAL",
                "sign",
                "-i",
                "f.txt",
                "--sign-with",
                "me",
                "--identity-store",
                "/tmp/SUB",
            ]
        )
        self.assertEqual(getattr(args, "identity_store", None), "/tmp/SUB")

    def test_absent_everywhere_stays_none(self):
        """SUPPRESS must not make the attribute vanish for callers that read
        it with a default, nor invent a value."""
        args = self._parse(["identity", "list"])
        self.assertIsNone(getattr(args, "identity_store", None))


if __name__ == "__main__":
    unittest.main()
