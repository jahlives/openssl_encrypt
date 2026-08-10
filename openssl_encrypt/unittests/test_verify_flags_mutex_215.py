#!/usr/bin/env python3
"""--verify-from and --no-verify are mutually exclusive (gitlab#215 item 1).

Naming a sender to verify and skipping verification contradict each other;
the CLI used to accept the pair and silently prefer --no-verify (the GUI's
CLIService already refused to emit both). The decrypt parser now rejects the
pair structurally.
"""

import argparse
import unittest

from openssl_encrypt.modules.crypt_cli_subparser import setup_decrypt_parser


def _parser():
    parser = argparse.ArgumentParser()
    setup_decrypt_parser(parser)
    return parser


class TestVerifyFlagsMutex(unittest.TestCase):
    def test_the_pair_is_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            _parser().parse_args(["-i", "a.enc", "--verify-from", "alice", "--no-verify"])
        self.assertEqual(ctx.exception.code, 2)

    def test_verify_from_alone_is_accepted(self):
        args = _parser().parse_args(["-i", "a.enc", "--verify-from", "alice"])
        self.assertEqual(args.verify_from, "alice")
        self.assertFalse(args.skip_verification)

    def test_no_verify_alone_is_accepted(self):
        args = _parser().parse_args(["-i", "a.enc", "--no-verify"])
        self.assertTrue(args.skip_verification)
        self.assertIsNone(args.verify_from)


if __name__ == "__main__":
    unittest.main()
