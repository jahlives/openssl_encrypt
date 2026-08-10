#!/usr/bin/env python3
"""combine-secrets/split-secret/verify must not have a dead subparser (gitlab#208).

Each of the three used to have a registered subparser that nothing ever routed
to -- they are handled by the monolithic parser -- so there were two argument
definitions per command and only one was live, the exact drift that produced
gitlab#164/#183. The dead subparser definitions were removed; this guards that
they do not come back (which would re-open the divergence) while confirming the
commands still dispatch through the monolithic parser.
"""

import argparse
import unittest


def _subparser_choices():
    from openssl_encrypt.modules.crypt_cli_subparser import build_subparser

    choices = set()
    for action in build_subparser()._actions:
        if isinstance(action, argparse._SubParsersAction):
            choices |= set(action.choices)
    return choices


class TestNoDeadSubparsers(unittest.TestCase):
    def test_the_three_are_not_registered_as_subparsers(self):
        choices = _subparser_choices()
        for cmd in ("verify", "split-secret", "combine-secrets"):
            self.assertNotIn(cmd, choices, f"{cmd} regained a dead subparser (gitlab#208)")

    def test_the_real_signing_commands_keep_their_subparsers(self):
        # Guard the fix did not overreach: sign / verify-signature are live
        # subparser commands and must stay registered.
        choices = _subparser_choices()
        for cmd in ("sign", "verify-signature"):
            self.assertIn(cmd, choices)

    def test_the_three_still_dispatch_via_the_monolithic_parser(self):
        # They remain known, runnable commands (their handlers live on the
        # monolithic path); --help must succeed, not error with "invalid choice".
        import subprocess
        import sys

        for cmd in ("verify", "split-secret", "combine-secrets"):
            proc = subprocess.run(
                [sys.executable, "-m", "openssl_encrypt.crypt", cmd, "--help"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, f"{cmd} --help failed: {proc.stderr[:200]}")
            self.assertNotIn("invalid choice", proc.stderr)


if __name__ == "__main__":
    unittest.main()
