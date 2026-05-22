"""
Unit tests for Diceware passphrase generation.

This module is built up incrementally. The first test simply verifies that
the bundled EFF Large Wordlist is present and loadable via the same
importlib.resources pattern the existing common_passwords.txt uses
(see password_policy.py:294).
"""

import importlib.resources
import unittest


class TestEffWordlistBundled(unittest.TestCase):
    """The EFF Large Wordlist must be packaged at openssl_encrypt/data/eff_large_wordlist.txt."""

    def test_wordlist_file_is_present(self):
        path = importlib.resources.files("openssl_encrypt").joinpath(
            "data/eff_large_wordlist.txt"
        )
        self.assertTrue(path.is_file(), f"expected wordlist at {path}")

    def test_wordlist_has_7776_lines(self):
        """EFF Large Wordlist has exactly 7776 entries (6^5 = full 5-die mapping)."""
        path = importlib.resources.files("openssl_encrypt").joinpath(
            "data/eff_large_wordlist.txt"
        )
        with path.open("r", encoding="utf-8") as f:
            line_count = sum(1 for _ in f)
        self.assertEqual(line_count, 7776)

    def test_wordlist_lines_have_eff_format(self):
        """Each line is '<5-digit-dice><TAB><word>' (raw EFF format)."""
        path = importlib.resources.files("openssl_encrypt").joinpath(
            "data/eff_large_wordlist.txt"
        )
        with path.open("r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.rstrip("\n")
                parts = line.split("\t")
                self.assertEqual(
                    len(parts),
                    2,
                    f"line {i + 1}: expected '<dice>\\t<word>', got {line!r}",
                )
                dice, word = parts
                self.assertTrue(
                    dice.isdigit() and len(dice) == 5,
                    f"line {i + 1}: dice prefix must be 5 digits, got {dice!r}",
                )
                self.assertTrue(
                    word and not any(c.isspace() for c in word),
                    f"line {i + 1}: word must be non-empty and whitespace-free, got {word!r}",
                )


class TestEffWordlistLicensePresent(unittest.TestCase):
    """CC BY 3.0 US attribution must accompany the bundled wordlist."""

    def test_license_file_is_present(self):
        path = importlib.resources.files("openssl_encrypt").joinpath(
            "data/EFF_WORDLIST_LICENSE.txt"
        )
        self.assertTrue(path.is_file(), f"expected license at {path}")

    def test_license_file_credits_eff_and_cc_by(self):
        path = importlib.resources.files("openssl_encrypt").joinpath(
            "data/EFF_WORDLIST_LICENSE.txt"
        )
        text = path.read_text(encoding="utf-8")
        self.assertIn("Electronic Frontier Foundation", text)
        self.assertIn("Creative Commons Attribution 3.0 United States", text)
        self.assertIn("CC BY 3.0 US", text)


if __name__ == "__main__":
    unittest.main()
