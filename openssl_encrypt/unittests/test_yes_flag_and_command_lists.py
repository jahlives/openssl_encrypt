#!/usr/bin/env python3
"""
`--yes` must work for the command it was written for, and the command lists
must not drift again (gitlab#176).

`--yes`/`-y` is declared on the top-level parser with the help text
"Automatic yes to prompts (for install-dependencies command)", and it was
recognised by the routing scan -- but it was not in `TRULY_GLOBAL_FLAGS`, so
it was never relocated, and the `install-dependencies` subparser declares no
arguments at all. So `install-dependencies --yes` exited 2 with
`unrecognized arguments: --yes`: exactly the gitlab#171 failure mode, for
the one command the flag exists for.

It was left out of gitlab#171 deliberately, because another subparser
(`hsm fido2-unregister`) declares its own `--yes`, and argparse parses a
subcommand into a fresh namespace and copies every key back over the
parent's -- so that subparser's `False` default would overwrite a relocated
`--yes`. That is the same dest-clobber gitlab#171 had to fix for `--quiet`,
and it takes the same `default=argparse.SUPPRESS` treatment.

The second half of this issue -- `main()`'s routing skip-set being a
hand-maintained duplicate -- was closed by gitlab#177, which replaced it
with the shared `_first_command_token()` scan. What remains here is the
list nobody consolidated: the monolithic parser's `action` positional
`choices`.
"""

import argparse
import os
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _run(*argv):
    return subprocess.run(
        [sys.executable, "-m", "openssl_encrypt.crypt", *argv],
        capture_output=True,
        text=True,
        cwd=REPO,
        timeout=120,
    )


class TestYesIsRelocatedLikeTheOtherGlobals(unittest.TestCase):
    def test_yes_is_a_truly_global_flag(self):
        from openssl_encrypt.modules.crypt_cli import TRULY_GLOBAL_FLAGS

        self.assertIn("--yes", TRULY_GLOBAL_FLAGS)
        self.assertIn("-y", TRULY_GLOBAL_FLAGS)

    def test_it_is_relocated_after_a_subcommand(self):
        from openssl_encrypt.modules.crypt_cli import preprocess_global_args

        self.assertEqual(
            preprocess_global_args(["crypt", "install-dependencies", "--yes"]),
            ["crypt", "--yes", "install-dependencies"],
        )

    def test_install_dependencies_accepts_it(self):
        """The user-visible half: it has to PARSE, not just be relocated.

        Parse-level rather than a subprocess, deliberately -- `--help` would
        short-circuit before argparse ever rejected the flag, so that version
        of this test passed while the command still exited 2, and running it
        for real would install packages.

        Relocation alone is not enough: that is exactly what happened to
        --quiet in gitlab#171, where the subparser's own default then
        discarded the relocated value.
        """
        from openssl_encrypt.modules.crypt_cli import preprocess_global_args
        from openssl_encrypt.modules.crypt_cli_subparser import build_subparser

        argv = preprocess_global_args(["crypt", "install-dependencies", "--yes"])
        try:
            args = build_subparser().parse_args(argv[1:])
        except SystemExit as exit_error:
            self.fail(f"install-dependencies --yes still exits {exit_error.code}")
        self.assertTrue(getattr(args, "yes", False), "the relocated --yes was discarded")


class TestTheOtherYesIsNotClobbered(unittest.TestCase):
    """`hsm fido2-unregister` declares its own `--yes`.

    argparse parses a subcommand into a fresh namespace and copies every key
    back over the parent's, so a plain `False` default there silently
    overwrites a relocated one. SUPPRESS leaves the key absent unless the
    flag is actually passed to that subcommand.
    """

    def _namespace(self, argv):
        from openssl_encrypt.modules.crypt_cli import preprocess_global_args
        from openssl_encrypt.modules.crypt_cli_subparser import build_subparser

        return build_subparser().parse_args(preprocess_global_args(["crypt"] + argv)[1:])

    def test_a_relocated_yes_survives_that_subcommand(self):
        args = self._namespace(["hsm", "fido2-unregister", "--yes"])
        self.assertTrue(getattr(args, "yes", False))

    def test_the_subcommands_own_yes_still_works(self):
        args = self._namespace(["hsm", "fido2-unregister", "--yes"])
        self.assertTrue(getattr(args, "yes", False))

    def test_not_passing_it_leaves_it_false(self):
        """The negative arm: SUPPRESS must not make the flag look set."""
        args = self._namespace(["hsm", "fido2-unregister"])
        self.assertFalse(getattr(args, "yes", False))


class TestTheCommandListsDoNotDrift(unittest.TestCase):
    """The remaining hand-maintained duplicate.

    The monolithic parser's `action` positional carries its own `choices`
    list. It is smaller than KNOWN_COMMANDS and separately maintained, which
    is the same shape as the drift that produced gitlab#171 and gitlab#179.
    A command declared there but absent from KNOWN_COMMANDS never gets its
    global flags relocated.
    """

    def _monolithic_choices(self):
        """The `choices` of the monolithic parser's `action` positional.

        Read structurally from the AST rather than by running the parser:
        the monolithic parser is built partway through main_with_args, after
        work that needs a real namespace, so there is no clean seam to build
        it in isolation. AST, not a text search -- the GUI lints in this
        suite learned that the hard way.
        """
        import ast

        from openssl_encrypt.modules import crypt_cli

        tree = ast.parse(open(crypt_cli.__file__, encoding="utf-8").read())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not (isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument"):
                continue
            if not (
                node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "action"
            ):
                continue
            for keyword in node.keywords:
                if keyword.arg == "choices" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                    values = [
                        element.value
                        for element in keyword.value.elts
                        if isinstance(element, ast.Constant)
                    ]
                    if values:
                        return set(values)
        return None

    def test_every_monolithic_choice_is_a_known_command(self):
        from openssl_encrypt.modules.crypt_cli import KNOWN_COMMANDS

        choices = self._monolithic_choices()
        if choices is None:
            self.skipTest("the monolithic parser's action choices were not reached")
        missing = sorted(choices - set(KNOWN_COMMANDS))
        self.assertFalse(
            missing,
            "the monolithic parser accepts commands that KNOWN_COMMANDS does "
            f"not list, so their global flags are never relocated: {missing}",
        )


if __name__ == "__main__":
    unittest.main()
