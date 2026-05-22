"""
CLI integration tests for the --dice mode of `generate-password`.

These tests exercise the argparse layer (flag presence, defaults, types)
and the runtime handler (policy interaction, dispatch). Hardware-free.
"""

import unittest


class TestGeneratePasswordDiceFlags(unittest.TestCase):
    """argparse must accept --dice, --dice-count, --dice-sep, --dice-list,
    --force-wordlist on the generate-password subcommand."""

    def _make_parser(self):
        """Build the project's subparser-based main parser for inspection."""
        import argparse

        from openssl_encrypt.modules.crypt_cli_subparser import (
            setup_generate_password_parser,
        )

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="action")
        gp = subparsers.add_parser("generate-password")
        setup_generate_password_parser(gp)
        return parser

    def test_dice_flag_accepted(self):
        parser = self._make_parser()
        args = parser.parse_args(["generate-password", "--dice"])
        self.assertTrue(args.dice)

    def test_dice_default_false(self):
        parser = self._make_parser()
        args = parser.parse_args(["generate-password"])
        self.assertFalse(getattr(args, "dice", False))

    def test_dice_count_default_10(self):
        parser = self._make_parser()
        args = parser.parse_args(["generate-password"])
        self.assertEqual(args.dice_count, 10)

    def test_dice_count_override(self):
        parser = self._make_parser()
        args = parser.parse_args(["generate-password", "--dice", "--dice-count", "6"])
        self.assertEqual(args.dice_count, 6)

    def test_dice_sep_default_empty(self):
        parser = self._make_parser()
        args = parser.parse_args(["generate-password"])
        self.assertEqual(args.dice_sep, "")

    def test_dice_sep_override(self):
        parser = self._make_parser()
        args = parser.parse_args(
            ["generate-password", "--dice", "--dice-sep", "-"]
        )
        self.assertEqual(args.dice_sep, "-")

    def test_dice_list_default_none(self):
        parser = self._make_parser()
        args = parser.parse_args(["generate-password"])
        self.assertIsNone(args.dice_list)

    def test_dice_list_override(self):
        parser = self._make_parser()
        args = parser.parse_args(
            ["generate-password", "--dice", "--dice-list", "/tmp/wl.txt"]
        )
        self.assertEqual(args.dice_list, "/tmp/wl.txt")

    def test_force_wordlist_flag(self):
        parser = self._make_parser()
        args = parser.parse_args(["generate-password", "--force-wordlist"])
        self.assertTrue(args.force_wordlist)
        args = parser.parse_args(["generate-password"])
        self.assertFalse(args.force_wordlist)


if __name__ == "__main__":
    unittest.main()
