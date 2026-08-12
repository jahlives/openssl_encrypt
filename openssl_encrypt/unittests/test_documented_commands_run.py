#!/usr/bin/env python3
"""
Every command the CLI advertises must actually dispatch (gitlab#179).

`main()` routes a command to the subparser when it appears in
`SUBPARSER_COMMANDS`. Seven commands were listed there and had no
`setup_*_parser` function, so routing on them reached `invalid choice` --
they were documented, listed in `--help`, and could not run:

    create-usb  verify-usb  list-plugins  plugin-info
    enable-plugin  disable-plugin  reload-plugin

Their argument definitions and handlers live on the monolithic parser inside
`main_with_args`, so the fix is to stop routing them to a subparser that was
never written, rather than to reimplement seven argument sets.

The invariant this pins is the one that broke: **every name in
SUBPARSER_COMMANDS must have a subparser**, and every command the CLI offers
must dispatch. Those are checked separately because they fail differently --
the first is a wiring mistake, the second is a user-visible dead command.
"""

import argparse
import os
import subprocess
import sys
import unittest
import unittest.mock

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The seven from gitlab#179. Named explicitly so a regression that drops one
# back into SUBPARSER_COMMANDS is reported against the issue.
PREVIOUSLY_DEAD = (
    "create-usb",
    "verify-usb",
    "list-plugins",
    "plugin-info",
    "enable-plugin",
    "disable-plugin",
    "reload-plugin",
)


def _run(*argv):
    return subprocess.run(
        [sys.executable, "-m", "openssl_encrypt.crypt", *argv],
        capture_output=True,
        text=True,
        cwd=REPO,
    )


def _registered_choices():
    """The subparser's real choices.

    build_subparser(), not create_subparser_main(): the latter calls
    parse_args() on the live sys.argv.
    """
    from openssl_encrypt.modules.crypt_cli_subparser import build_subparser

    choices = set()
    for action in build_subparser()._actions:
        if isinstance(action, argparse._SubParsersAction):
            choices |= set(action.choices)
    return choices


class TestTheRoutingSetIsDerived(unittest.TestCase):
    """The routing set must be read off the parser, not kept beside it.

    A hand-maintained copy is the actual defect here: the list said these
    seven route to the subparser, the subparser had never heard of them, and
    nothing connected the two claims. Deriving it makes "routed but
    unregistered" unrepresentable -- these tests fail if someone reverts to
    a literal list.
    """

    def test_no_routed_command_is_missing_its_parser(self):
        from openssl_encrypt.modules.crypt_cli import _subparser_choices

        missing = sorted(set(_subparser_choices()) - _registered_choices())
        self.assertFalse(
            missing,
            f"these route to the subparser, which does not define them: {missing}. "
            "They will exit 2 with 'invalid choice' (gitlab#179).",
        )

    def test_the_routing_set_is_exactly_what_is_registered(self):
        """Both directions: a registered command must also be reachable.

        Without this, dropping a name from the routing set would silently
        send a command with a perfectly good subparser to the monolithic
        parser instead.
        """
        from openssl_encrypt.modules.crypt_cli import _subparser_choices

        self.assertEqual(set(_subparser_choices()), _registered_choices())

    def test_the_known_command_list_still_covers_the_subparser(self):
        """KNOWN_COMMANDS answers a different question -- "is this token a
        command", for global-flag relocation -- so it must remain a superset.
        A registered command missing from it is gitlab#171 again: the flags
        after it are never relocated.
        """
        from openssl_encrypt.modules.crypt_cli import KNOWN_COMMANDS

        missing = sorted(_registered_choices() - set(KNOWN_COMMANDS))
        self.assertFalse(missing, f"registered commands absent from KNOWN_COMMANDS: {missing}")

    def test_the_previously_dead_seven_are_not_routed(self):
        """They are handled by the monolithic parser, which declares them."""
        from openssl_encrypt.modules.crypt_cli import KNOWN_COMMANDS, _subparser_choices

        for command in PREVIOUSLY_DEAD:
            self.assertIn(command, KNOWN_COMMANDS, f"{command} is no longer a known command")
            self.assertNotIn(
                command,
                _subparser_choices(),
                f"{command} is routed to the subparser again; if a subparser was "
                "written for it, delete it from PREVIOUSLY_DEAD instead",
            )


class TestTheRoutingSetIsRobust(unittest.TestCase):
    """Deriving the set moved a module import onto the unconditional path.

    Both of these came out of the security review of this change: the cache
    was handed out mutable, and a build failure would have taken down every
    command rather than the subparser-routed ones.
    """

    def test_the_cache_cannot_be_mutated_by_a_caller(self):
        from openssl_encrypt.modules.crypt_cli import _subparser_choices

        choices = _subparser_choices()
        with self.assertRaises(AttributeError):
            choices.add("bogus-command")
        with self.assertRaises(AttributeError):
            choices.clear()
        self.assertIn("encrypt", _subparser_choices())

    def test_a_build_failure_falls_back_to_the_monolithic_parser(self):
        """An empty set routes everything to the parser that declares
        everything. The alternative -- an exception on the unconditional path
        -- would break every command including encrypt and decrypt.
        """
        from openssl_encrypt.modules import crypt_cli

        original = crypt_cli._SUBPARSER_CHOICES
        self.addCleanup(setattr, crypt_cli, "_SUBPARSER_CHOICES", original)
        crypt_cli._SUBPARSER_CHOICES = None
        # The built parser is shared between the two caches, so it has to be
        # cleared as well or this reads a parser built before the patch.
        original_parser = crypt_cli._BUILT_SUBPARSER
        self.addCleanup(setattr, crypt_cli, "_BUILT_SUBPARSER", original_parser)
        crypt_cli._BUILT_SUBPARSER = None

        import openssl_encrypt.modules.crypt_cli_subparser as subparser_module

        def explode():
            raise RuntimeError("subparser construction failed")

        with unittest.mock.patch.object(subparser_module, "build_subparser", explode):
            self.assertEqual(crypt_cli._subparser_choices(), frozenset())


class TestPreviouslyDeadCommandsDispatch(unittest.TestCase):
    """The user-visible half: they have to actually run."""

    def test_each_one_reaches_its_handler(self):
        broken = []
        for command in PREVIOUSLY_DEAD:
            result = _run(command, "--help")
            combined = (result.stdout or "") + (result.stderr or "")
            if "invalid choice" in combined:
                broken.append(f"  {command}: invalid choice")
            elif result.returncode not in (0, 1):
                broken.append(f"  {command}: exit {result.returncode}")

        self.assertFalse(
            broken,
            "documented commands that do not dispatch:\n" + "\n".join(broken),
        )

    def test_a_real_invocation_is_not_an_argparse_failure(self):
        """`--help` alone would pass if the command were merely declared.

        list-plugins takes no required arguments, so it is the one that can
        be run for real without side effects; if dispatch were still broken
        it would exit 2.
        """
        result = _run("list-plugins")
        combined = (result.stdout or "") + (result.stderr or "")
        self.assertNotIn("invalid choice", combined)
        self.assertNotEqual(result.returncode, 2, combined[-400:])


if __name__ == "__main__":
    unittest.main()
