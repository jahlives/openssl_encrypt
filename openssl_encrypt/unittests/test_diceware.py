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
            words = load_wordlist(tmp, force_small=True)
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
            words = load_wordlist(tmp, force_small=True)
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
            words = load_wordlist(tmp, force_small=True)
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
            words = load_wordlist(tmp_str, force_small=True)
            self.assertEqual(words, ["apple", "banana"])
        finally:
            import os

            os.unlink(tmp_str)

    def test_load_nonexistent_path_raises(self):
        """Clear error on missing file."""
        from openssl_encrypt.modules.diceware import load_wordlist

        with self.assertRaises((FileNotFoundError, OSError)):
            load_wordlist("/nonexistent/path/that/does/not/exist.txt")


class TestWordlistValidation(unittest.TestCase):
    """
    Per Q10: duplicates and whitespace-containing words must be rejected
    outright. Silent dedup would mislead users about effective entropy;
    embedded whitespace would break --dice-sep boundary semantics.
    """

    def _write(self, content: str):
        import tempfile
        from pathlib import Path

        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        )
        f.write(content)
        f.close()
        return Path(f.name)

    def test_duplicate_words_raise(self):
        from openssl_encrypt.modules.diceware import (
            WordlistValidationError,
            load_wordlist,
        )

        tmp = self._write("alpha\nbravo\nalpha\ncharlie\n")
        try:
            with self.assertRaises(WordlistValidationError) as cm:
                load_wordlist(tmp)
            self.assertIn("duplicate", str(cm.exception).lower())
            self.assertIn("alpha", str(cm.exception))
        finally:
            tmp.unlink()

    def test_duplicate_in_eff_format_raises(self):
        from openssl_encrypt.modules.diceware import (
            WordlistValidationError,
            load_wordlist,
        )

        tmp = self._write("11111\talpha\n11112\tbravo\n11113\talpha\n")
        try:
            with self.assertRaises(WordlistValidationError):
                load_wordlist(tmp)
        finally:
            tmp.unlink()

    def test_word_with_embedded_space_raises(self):
        from openssl_encrypt.modules.diceware import (
            WordlistValidationError,
            load_wordlist,
        )

        # Plain-format file with a multi-word entry.
        tmp = self._write("alpha\nfoo bar\ncharlie\n")
        try:
            with self.assertRaises(WordlistValidationError) as cm:
                load_wordlist(tmp)
            self.assertIn("whitespace", str(cm.exception).lower())
        finally:
            tmp.unlink()

    def test_word_with_embedded_tab_raises(self):
        from openssl_encrypt.modules.diceware import (
            WordlistValidationError,
            load_wordlist,
        )

        # A plain-format file where one "word" contains an embedded tab.
        # We need this to not be misdetected as EFF format: first line is
        # plain, then the bad line has the tab.
        tmp = self._write("alpha\nfoo\tbar\ncharlie\n")
        try:
            with self.assertRaises(WordlistValidationError):
                load_wordlist(tmp)
        finally:
            tmp.unlink()

    def test_bundled_eff_wordlist_passes_validation(self):
        """Sanity: the bundled EFF list has no dups and no whitespace-words."""
        from openssl_encrypt.modules.diceware import load_wordlist

        words = load_wordlist()
        self.assertEqual(len(words), len(set(words)), "EFF list has duplicates?")
        for w in words:
            self.assertFalse(any(c.isspace() for c in w))


class TestSmallWordlistThreshold(unittest.TestCase):
    """
    Per Q10: small wordlists (< 1024 words = < 10 bits/word) are rejected
    by default; user must pass force_small=True to override (the CLI
    layer exposes this as --force-wordlist).
    """

    def _write_small(self, n_words: int):
        import tempfile
        from pathlib import Path

        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        )
        for i in range(n_words):
            f.write(f"word{i:05d}\n")
        f.close()
        return Path(f.name)

    def test_small_wordlist_raises_by_default(self):
        from openssl_encrypt.modules.diceware import (
            WordlistValidationError,
            load_wordlist,
        )

        tmp = self._write_small(100)
        try:
            with self.assertRaises(WordlistValidationError) as cm:
                load_wordlist(tmp)
            msg = str(cm.exception).lower()
            self.assertIn("small", msg)
            self.assertIn("100", str(cm.exception))
            self.assertIn("force_small", msg)
        finally:
            tmp.unlink()

    def test_small_wordlist_warns_with_force_small(self):
        """With force_small=True the load proceeds but emits a UserWarning."""
        import warnings

        from openssl_encrypt.modules.diceware import load_wordlist

        tmp = self._write_small(100)
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                words = load_wordlist(tmp, force_small=True)
            self.assertEqual(len(words), 100)
            # Exactly one warning about the small list size.
            small_warnings = [
                w for w in caught if "small" in str(w.message).lower()
            ]
            self.assertEqual(len(small_warnings), 1)
        finally:
            tmp.unlink()

    def test_threshold_boundary_exactly_1024_words_ok(self):
        """1024 words = log2(1024) = 10 bits/word — at the threshold, allow."""
        from openssl_encrypt.modules.diceware import load_wordlist

        tmp = self._write_small(1024)
        try:
            words = load_wordlist(tmp)
            self.assertEqual(len(words), 1024)
        finally:
            tmp.unlink()

    def test_threshold_just_below_1023_words_raises(self):
        from openssl_encrypt.modules.diceware import (
            WordlistValidationError,
            load_wordlist,
        )

        tmp = self._write_small(1023)
        try:
            with self.assertRaises(WordlistValidationError):
                load_wordlist(tmp)
        finally:
            tmp.unlink()

    def test_bundled_eff_does_not_warn_or_raise(self):
        import warnings

        from openssl_encrypt.modules.diceware import load_wordlist

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            words = load_wordlist()
        self.assertEqual(len(words), 7776)
        self.assertEqual(
            [w for w in caught if "small" in str(w.message).lower()],
            [],
            "the bundled 7776-word EFF list should NOT trigger small-list warning",
        )


class TestGeneratePassphrase(unittest.TestCase):
    """Diceware passphrase generation against the EFF wordlist."""

    def test_returns_string(self):
        from openssl_encrypt.modules.diceware import generate_passphrase

        self.assertIsInstance(generate_passphrase(count=6), str)

    def test_count_words_with_separator(self):
        from openssl_encrypt.modules.diceware import generate_passphrase

        phrase = generate_passphrase(count=10, sep=" ")
        self.assertEqual(len(phrase.split(" ")), 10)

    def test_count_words_with_empty_separator_via_supplied_wordlist(self):
        """With empty separator, count is verifiable by intersecting words."""
        from openssl_encrypt.modules.diceware import generate_passphrase

        # Fixed wordlist of equal-length distinct words so we can chunk
        # and recover the count even with sep="".
        wl = [f"word{i:04d}" for i in range(2000)]
        phrase = generate_passphrase(count=5, sep="", wordlist=wl)
        # Each word is 8 chars; phrase total length = 40.
        self.assertEqual(len(phrase), 40)

    def test_separator_is_applied_between_words_only(self):
        from openssl_encrypt.modules.diceware import generate_passphrase

        # 4 words → 3 separators in between (no leading/trailing).
        phrase = generate_passphrase(count=4, sep="-")
        self.assertEqual(phrase.count("-"), 3)
        self.assertFalse(phrase.startswith("-"))
        self.assertFalse(phrase.endswith("-"))

    def test_uses_provided_wordlist_exclusively(self):
        from openssl_encrypt.modules.diceware import generate_passphrase

        wl = [f"only{i:04d}" for i in range(2000)]
        phrase = generate_passphrase(count=8, sep=" ", wordlist=wl)
        for w in phrase.split(" "):
            self.assertIn(w, wl)

    def test_uses_default_wordlist_when_none_supplied(self):
        from openssl_encrypt.modules.diceware import generate_passphrase, load_wordlist

        eff_words = set(load_wordlist())
        phrase = generate_passphrase(count=10, sep=" ")
        for w in phrase.split(" "):
            self.assertIn(w, eff_words)

    def test_invalid_count_raises_value_error(self):
        from openssl_encrypt.modules.diceware import generate_passphrase

        with self.assertRaises(ValueError):
            generate_passphrase(count=0)
        with self.assertRaises(ValueError):
            generate_passphrase(count=-1)

    def test_two_calls_produce_different_passphrases(self):
        """Trivially unlikely otherwise (12.92 × 10 = 129 bits of entropy)."""
        from openssl_encrypt.modules.diceware import generate_passphrase

        a = generate_passphrase(count=10, sep=" ")
        b = generate_passphrase(count=10, sep=" ")
        self.assertNotEqual(a, b)

    def test_uses_secrets_systemrandom_not_random_random(self):
        """
        Guard against any future refactor switching to non-CSPRNG.
        Patch secrets.SystemRandom and assert the patched object is used.
        """
        from unittest.mock import MagicMock, patch

        from openssl_encrypt.modules.diceware import generate_passphrase

        wl = [f"w{i}" for i in range(1024)]
        mock_rng = MagicMock()
        mock_rng.choice.side_effect = lambda seq: seq[0]

        with patch(
            "openssl_encrypt.modules.diceware.secrets.SystemRandom",
            return_value=mock_rng,
        ):
            phrase = generate_passphrase(count=3, sep="-", wordlist=wl)

        # All-zero indices → first word ("w0") three times.
        self.assertEqual(phrase, "w0-w0-w0")
        self.assertEqual(mock_rng.choice.call_count, 3)


class TestPassphraseEntropy(unittest.TestCase):
    """Entropy = count * log2(len(wordlist))."""

    def test_eff_wordlist_default_count_entropy(self):
        """7776 words, count=10 → 10 * log2(7776) ≈ 129.2 bits."""
        from openssl_encrypt.modules.diceware import passphrase_entropy

        bits = passphrase_entropy(count=10, wordlist_size=7776)
        self.assertAlmostEqual(bits, 129.2, places=1)

    def test_six_word_passphrase_entropy(self):
        """EFF's recommended minimum: 6 words × ~12.92 bits ≈ 77.5."""
        from openssl_encrypt.modules.diceware import passphrase_entropy

        bits = passphrase_entropy(count=6, wordlist_size=7776)
        self.assertAlmostEqual(bits, 77.5, places=1)

    def test_threshold_wordlist_10_bits_per_word(self):
        """A 1024-word wordlist gives exactly 10 bits per word."""
        from openssl_encrypt.modules.diceware import passphrase_entropy

        bits = passphrase_entropy(count=1, wordlist_size=1024)
        self.assertAlmostEqual(bits, 10.0, places=6)

    def test_scales_linearly_with_count(self):
        from openssl_encrypt.modules.diceware import passphrase_entropy

        b1 = passphrase_entropy(count=1, wordlist_size=4096)
        b10 = passphrase_entropy(count=10, wordlist_size=4096)
        self.assertAlmostEqual(b10, b1 * 10, places=6)

    def test_invalid_inputs_raise(self):
        from openssl_encrypt.modules.diceware import passphrase_entropy

        with self.assertRaises(ValueError):
            passphrase_entropy(count=0, wordlist_size=7776)
        with self.assertRaises(ValueError):
            passphrase_entropy(count=-1, wordlist_size=7776)
        with self.assertRaises(ValueError):
            passphrase_entropy(count=10, wordlist_size=0)
        with self.assertRaises(ValueError):
            passphrase_entropy(count=10, wordlist_size=1)  # log2(1) = 0


if __name__ == "__main__":
    unittest.main()
