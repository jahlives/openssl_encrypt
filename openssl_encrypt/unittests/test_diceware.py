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


class TestLoadWordlist(unittest.TestCase):
    """The load_wordlist() function: auto-detect EFF vs plain text format."""

    def test_default_path_loads_bundled_eff_wordlist(self):
        """load_wordlist() with no arguments returns the bundled EFF list."""
        from openssl_encrypt.modules.diceware import load_wordlist

        words = load_wordlist()
        self.assertEqual(len(words), 7776)
        # First and last words from EFF Large Wordlist
        self.assertEqual(words[0], "abacus")
        self.assertEqual(words[-1], "zoom")

    def test_load_eff_format_strips_dice_prefix(self):
        """EFF format '<5-digit>\\t<word>' yields just the word."""
        import tempfile
        from pathlib import Path

        from openssl_encrypt.modules.diceware import load_wordlist

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("11111\talpha\n11112\tbravo\n11113\tcharlie\n")
            tmp = Path(f.name)
        try:
            words = load_wordlist(tmp)
            self.assertEqual(words, ["alpha", "bravo", "charlie"])
        finally:
            tmp.unlink()

    def test_load_plain_format(self):
        """Plain text: one word per line, no prefix."""
        import tempfile
        from pathlib import Path

        from openssl_encrypt.modules.diceware import load_wordlist

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("alpha\nbravo\ncharlie\n")
            tmp = Path(f.name)
        try:
            words = load_wordlist(tmp)
            self.assertEqual(words, ["alpha", "bravo", "charlie"])
        finally:
            tmp.unlink()

    def test_load_skips_blank_lines_and_strips_whitespace(self):
        """Blank lines ignored; trailing whitespace stripped."""
        import tempfile
        from pathlib import Path

        from openssl_encrypt.modules.diceware import load_wordlist

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("\nalpha  \n\nbravo\n   \ncharlie\n\n")
            tmp = Path(f.name)
        try:
            words = load_wordlist(tmp)
            self.assertEqual(words, ["alpha", "bravo", "charlie"])
        finally:
            tmp.unlink()

    def test_load_accepts_str_path(self):
        """Path can be str, not just Path object."""
        import tempfile

        from openssl_encrypt.modules.diceware import load_wordlist

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("apple\nbanana\n")
            tmp_str = f.name
        try:
            words = load_wordlist(tmp_str)
            self.assertEqual(words, ["apple", "banana"])
        finally:
            import os

            os.unlink(tmp_str)

    def test_load_nonexistent_path_raises(self):
        """Clear error on missing file."""
        from openssl_encrypt.modules.diceware import load_wordlist

        with self.assertRaises((FileNotFoundError, OSError)):
            load_wordlist("/nonexistent/path/that/does/not/exist.txt")


if __name__ == "__main__":
    unittest.main()
