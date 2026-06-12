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

        from openssl_encrypt.modules.crypt_cli_subparser import setup_generate_password_parser

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
        args = parser.parse_args(["generate-password", "--dice", "--dice-sep", "-"])
        self.assertEqual(args.dice_sep, "-")

    def test_dice_list_default_none(self):
        parser = self._make_parser()
        args = parser.parse_args(["generate-password"])
        self.assertIsNone(args.dice_list)

    def test_dice_list_override(self):
        parser = self._make_parser()
        args = parser.parse_args(["generate-password", "--dice", "--dice-list", "/tmp/wl.txt"])
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


class TestRunDiceGeneration(unittest.TestCase):
    """The _run_dice_generation helper that ties the diceware module to the CLI."""

    def _make_args(self, **overrides):
        """Build a SimpleNamespace mimicking parsed CLI args."""
        from types import SimpleNamespace

        defaults = dict(
            dice_list=None,
            dice_count=10,
            dice_sep="",
            force_wordlist=False,
        )
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def test_returns_passphrase_and_entropy(self):
        from openssl_encrypt.modules.crypt_cli import _run_dice_generation

        phrase, bits = _run_dice_generation(self._make_args())
        self.assertIsInstance(phrase, str)
        self.assertIsInstance(bits, float)

    def test_default_uses_bundled_eff_list(self):
        from openssl_encrypt.modules.crypt_cli import _run_dice_generation
        from openssl_encrypt.modules.diceware import load_wordlist

        bundled = set(load_wordlist())
        phrase, bits = _run_dice_generation(self._make_args(dice_count=10, dice_sep=" "))
        for w in phrase.split(" "):
            self.assertIn(w, bundled)
        # 10 words × log2(7776) ≈ 129.2 bits
        self.assertAlmostEqual(bits, 129.2, places=1)

    def test_custom_wordlist_used(self):
        import tempfile

        from openssl_encrypt.modules.crypt_cli import _run_dice_generation

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for i in range(2000):
                f.write(f"customword{i:04d}\n")
            tmp = f.name
        try:
            phrase, bits = _run_dice_generation(
                self._make_args(dice_list=tmp, dice_count=5, dice_sep=" ")
            )
            for w in phrase.split(" "):
                self.assertTrue(w.startswith("customword"))
            # Custom 2000-word list → 5 * log2(2000) ≈ 54.83 bits
            import math

            self.assertAlmostEqual(bits, 5 * math.log2(2000), places=3)
        finally:
            import os

            os.unlink(tmp)

    def test_force_wordlist_passed_to_loader(self):
        """A small custom list must work with --force-wordlist."""
        import tempfile

        from openssl_encrypt.modules.crypt_cli import _run_dice_generation

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for i in range(100):
                f.write(f"tiny{i:03d}\n")
            tmp = f.name
        try:
            # Without force_wordlist, this would raise WordlistValidationError
            phrase, _bits = _run_dice_generation(
                self._make_args(dice_list=tmp, dice_count=3, force_wordlist=True)
            )
            self.assertTrue(phrase.startswith("tiny"))
        finally:
            import os

            os.unlink(tmp)

    def test_dice_count_one_produces_one_word_no_separator(self):
        from openssl_encrypt.modules.crypt_cli import _run_dice_generation

        phrase, _bits = _run_dice_generation(self._make_args(dice_count=1, dice_sep="-"))
        self.assertNotIn("-", phrase)


class TestGeneratePasswordDiceHandlerIntegration(unittest.TestCase):
    """
    End-to-end-ish: invoke the generate-password handler with --dice
    and confirm it dispatches to the dice path, prints the entropy
    line on stderr, and exits 0.
    """

    def _run_main_with(self, argv_after_action):
        """Invoke main_with_args via subprocess capturing stderr/stdout."""
        import os
        import subprocess
        import sys

        env = os.environ.copy()
        env["PYTHONPATH"] = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        cmd = [
            sys.executable,
            "-c",
            "from openssl_encrypt.modules.crypt_cli import main_with_args; " "main_with_args()",
            "generate-password",
        ] + argv_after_action
        return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=30)

    def test_dice_smoke_runs_and_prints_entropy(self):
        """--dice mode runs to completion and emits entropy line on stderr."""
        # Use 3 words with sep="-" so the output is easy to inspect.
        result = self._run_main_with(["--dice", "--dice-count", "3", "--dice-sep", "-"])
        self.assertEqual(
            result.returncode,
            0,
            f"unexpected exit: rc={result.returncode}\nstderr={result.stderr}",
        )
        self.assertIn("Passphrase entropy:", result.stderr)
        self.assertIn("3 words", result.stderr)

    def test_dice_combined_with_use_lowercase_exits_nonzero(self):
        result = self._run_main_with(["--dice", "--use-lowercase"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--dice", result.stderr)
        self.assertIn("--use-lowercase", result.stderr)

    def test_dice_count_without_dice_exits_nonzero(self):
        result = self._run_main_with(["--dice-count", "6"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("require --dice", result.stderr)


if __name__ == "__main__":
    unittest.main()
