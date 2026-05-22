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


class TestGeneratePasswordRuntimeValidation(unittest.TestCase):
    """
    The handler must reject:
    1. --dice combined with any character-class flag (mutually exclusive)
    2. --dice-count / --dice-sep / --dice-list / --force-wordlist used
       without --dice (those flags have no meaning otherwise)
    """

    def test_dice_combined_with_use_lowercase_errors(self):
        """The handler validator (not argparse) rejects this combination."""
        from openssl_encrypt.modules.crypt_cli import _validate_generate_password_args

        with self.assertRaises(ValueError) as cm:
            _validate_generate_password_args(
                dice=True,
                use_lowercase=True,
                use_uppercase=False,
                use_digits=False,
                use_special=False,
                dice_count=10,
                dice_sep="",
                dice_list=None,
                force_wordlist=False,
            )
        msg = str(cm.exception).lower()
        self.assertIn("--dice", msg)
        self.assertIn("--use-lowercase", msg)

    def test_dice_combined_with_use_special_errors(self):
        from openssl_encrypt.modules.crypt_cli import _validate_generate_password_args

        with self.assertRaises(ValueError):
            _validate_generate_password_args(
                dice=True,
                use_lowercase=False,
                use_uppercase=False,
                use_digits=False,
                use_special=True,
                dice_count=10,
                dice_sep="",
                dice_list=None,
                force_wordlist=False,
            )

    def test_dice_alone_ok(self):
        from openssl_encrypt.modules.crypt_cli import _validate_generate_password_args

        # No exception expected.
        _validate_generate_password_args(
            dice=True,
            use_lowercase=False,
            use_uppercase=False,
            use_digits=False,
            use_special=False,
            dice_count=10,
            dice_sep="",
            dice_list=None,
            force_wordlist=False,
        )

    def test_dice_count_without_dice_errors(self):
        from openssl_encrypt.modules.crypt_cli import _validate_generate_password_args

        with self.assertRaises(ValueError) as cm:
            _validate_generate_password_args(
                dice=False,
                use_lowercase=False,
                use_uppercase=False,
                use_digits=False,
                use_special=False,
                dice_count=6,  # non-default
                dice_sep="",
                dice_list=None,
                force_wordlist=False,
            )
        self.assertIn("--dice-count", str(cm.exception))
        self.assertIn("--dice", str(cm.exception))

    def test_dice_sep_non_default_without_dice_errors(self):
        from openssl_encrypt.modules.crypt_cli import _validate_generate_password_args

        with self.assertRaises(ValueError):
            _validate_generate_password_args(
                dice=False,
                use_lowercase=False,
                use_uppercase=False,
                use_digits=False,
                use_special=False,
                dice_count=10,
                dice_sep="-",  # non-default
                dice_list=None,
                force_wordlist=False,
            )

    def test_dice_list_without_dice_errors(self):
        from openssl_encrypt.modules.crypt_cli import _validate_generate_password_args

        with self.assertRaises(ValueError):
            _validate_generate_password_args(
                dice=False,
                use_lowercase=False,
                use_uppercase=False,
                use_digits=False,
                use_special=False,
                dice_count=10,
                dice_sep="",
                dice_list="/tmp/wl.txt",
                force_wordlist=False,
            )

    def test_force_wordlist_without_dice_errors(self):
        from openssl_encrypt.modules.crypt_cli import _validate_generate_password_args

        with self.assertRaises(ValueError):
            _validate_generate_password_args(
                dice=False,
                use_lowercase=False,
                use_uppercase=False,
                use_digits=False,
                use_special=False,
                dice_count=10,
                dice_sep="",
                dice_list=None,
                force_wordlist=True,
            )

    def test_default_args_no_dice_no_char_flag_ok(self):
        """Bare `generate-password` (no flags) must validate cleanly."""
        from openssl_encrypt.modules.crypt_cli import _validate_generate_password_args

        _validate_generate_password_args(
            dice=False,
            use_lowercase=False,
            use_uppercase=False,
            use_digits=False,
            use_special=False,
            dice_count=10,
            dice_sep="",
            dice_list=None,
            force_wordlist=False,
        )


if __name__ == "__main__":
    unittest.main()
