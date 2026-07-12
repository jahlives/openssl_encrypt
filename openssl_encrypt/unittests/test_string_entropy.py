#!/usr/bin/env python3
"""
Test suite for the ``string_entropy`` password-entropy estimator.

These tests pin the character-pool (search-space) behaviour for ASCII
passwords and act as regression tests for the Unicode handling fix, where
non-ASCII characters were previously dropped from the unique-character count
and could score a password at 0.0 bits.
"""

import math
import unittest

from openssl_encrypt.modules.crypt_core import string_entropy


class TestStringEntropyAscii(unittest.TestCase):
    """ASCII behaviour must remain stable (regression pins)."""

    def test_empty_password_is_zero(self):
        self.assertEqual(string_entropy(""), 0.0)

    def test_mixed_ascii_password_pin(self):
        # lower+upper+digit+symbol -> pool 94, 9 unique chars
        expected = math.log2(94) * 9
        self.assertAlmostEqual(string_entropy("Password1!"), expected, places=6)

    def test_single_class_repetition_pin(self):
        # 20 'a's -> pool 26 (lowercase only), 1 unique char
        self.assertAlmostEqual(string_entropy("a" * 20), math.log2(26), places=6)

    def test_repetition_does_not_add_entropy(self):
        # unique-character model: repeating a block adds no entropy
        self.assertAlmostEqual(string_entropy("abcabcabc"), string_entropy("abc"), places=6)


class TestStringEntropyUnicode(unittest.TestCase):
    """Non-ASCII characters must contribute, not zero the score."""

    def test_emoji_only_is_nonzero(self):
        # Regression: previously 0.0 because non-ASCII was excluded from the
        # unique-character count.
        self.assertGreater(string_entropy("\U0001f600\U0001f680\U0001f60e"), 0.0)

    def test_distinct_unicode_beats_repeated_unicode(self):
        distinct = string_entropy("αβγ")  # αβγ
        repeated = string_entropy("ααα")  # ααα
        self.assertGreater(distinct, repeated)

    def test_accented_char_counts_toward_uniqueness(self):
        # "café" has one more unique character than "caf".
        self.assertGreater(string_entropy("café"), string_entropy("caf"))

    def test_non_ascii_unique_chars_are_counted(self):
        # Four distinct non-ASCII codepoints must yield strictly more entropy
        # than one, i.e. the unique count reaches beyond the ASCII range.
        one = string_entropy("é")
        four = string_entropy("éüñà")
        self.assertGreater(four, one)


if __name__ == "__main__":
    unittest.main()
