#!/usr/bin/env python3
"""
Test suite for pattern-aware password strength estimation.

Covers the unified strength bucketer, the ``estimate_strength`` estimator on
both the zxcvbn and heuristic-fallback code paths, and the advisory-by-default
vs opt-in strict ``min_entropy`` gate in ``PasswordPolicy``.

Design under test:
- ``string_entropy`` remains the raw search-space measure (unchanged).
- ``estimate_strength`` never exceeds the raw measure and is pulled down when a
  named pattern (dictionary / sequence / repeat / date / keyboard) is detected.
- Standard policy gates on the raw measure (backward compatible); ``paranoid``
  and ``strict_strength=True`` gate on the pattern-aware measure.
"""

import unittest
from unittest.mock import patch

from openssl_encrypt.modules.crypt_core import string_entropy
from openssl_encrypt.modules.password_policy import (
    _HAVE_ZXCVBN,
    PasswordPolicy,
    StrengthResult,
    estimate_strength,
    get_password_strength,
    get_pattern_strength,
    strength_category,
)

# A structureless, high-entropy password (no dictionary/sequence content).
STRONG = "Xk9$mQ2vLp8@Wn4!zR"
# High raw entropy (~85 bits, clears the standard gate) but a pure a-k run.
SEQ_HIGH_RAW = "Abcdefghijk1!"
# Obvious weak patterns.
SEQ_LOW = "abcdefghijklmnop"
LEET_COMMON = "P@ssw0rd"


class TestStrengthCategory(unittest.TestCase):
    """The single source of truth for entropy -> label bucketing."""

    def test_boundaries(self):
        self.assertEqual(strength_category(34.9), "VERY WEAK")
        self.assertEqual(strength_category(35.0), "WEAK")
        self.assertEqual(strength_category(59.9), "WEAK")
        self.assertEqual(strength_category(60.0), "MODERATE")
        self.assertEqual(strength_category(79.9), "MODERATE")
        self.assertEqual(strength_category(80.0), "STRONG")
        self.assertEqual(strength_category(99.9), "STRONG")
        self.assertEqual(strength_category(100.0), "VERY STRONG")


class _EstimatorContract:
    """Assertions that must hold on either estimator backend."""

    def test_strong_password_not_penalized(self):
        est = estimate_strength(STRONG)
        self.assertIsInstance(est, StrengthResult)
        # No named pattern -> full search-space credit, top buckets.
        self.assertIn(est.category, ("STRONG", "VERY STRONG"))
        self.assertGreaterEqual(est.bits, 80.0)

    def test_never_exceeds_raw(self):
        for pw in (STRONG, SEQ_HIGH_RAW, SEQ_LOW, LEET_COMMON, "hunter2"):
            self.assertLessEqual(estimate_strength(pw).bits, string_entropy(pw) + 1e-6)

    def test_high_raw_sequence_is_pulled_down(self):
        # ~85 raw bits, but a pure alphabetical run must not read as STRONG.
        est = estimate_strength(SEQ_HIGH_RAW)
        self.assertLess(est.bits, string_entropy(SEQ_HIGH_RAW))
        self.assertLess(est.bits, 80.0)
        self.assertTrue(est.warnings, "expected a pattern warning")

    def test_obvious_sequence_is_weak(self):
        est = estimate_strength(SEQ_LOW)
        self.assertLess(est.bits, 60.0)
        self.assertIn(est.category, ("VERY WEAK", "WEAK"))

    def test_leet_common_is_weak(self):
        est = estimate_strength(LEET_COMMON)
        self.assertLess(est.bits, 60.0)
        self.assertTrue(est.warnings)


class TestEstimatorHeuristic(_EstimatorContract, unittest.TestCase):
    """Force the hand-rolled fallback regardless of whether zxcvbn is installed."""

    def setUp(self):
        self._patcher = patch("openssl_encrypt.modules.password_policy._HAVE_ZXCVBN", False)
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()

    def test_source_is_heuristic(self):
        self.assertEqual(estimate_strength(STRONG).source, "heuristic")


@unittest.skipUnless(_HAVE_ZXCVBN, "zxcvbn not installed")
class TestEstimatorZxcvbn(_EstimatorContract, unittest.TestCase):
    """Exercise the zxcvbn-backed path when the optional dep is present."""

    def test_source_is_zxcvbn(self):
        self.assertEqual(estimate_strength(STRONG).source, "zxcvbn")


class TestGateAdvisoryVsStrict(unittest.TestCase):
    """Advisory by default; strict gate is opt-in."""

    def test_standard_accepts_high_raw_sequence(self):
        # raw entropy clears the standard (MODERATE=80) gate -> still accepted.
        policy = PasswordPolicy(policy_level="standard")
        valid, msgs = policy.validate_password(SEQ_HIGH_RAW, quiet=True)
        self.assertTrue(valid, msgs)

    def test_strict_rejects_high_raw_sequence(self):
        policy = PasswordPolicy(policy_level="standard", strict_strength=True)
        valid, msgs = policy.validate_password(SEQ_HIGH_RAW, quiet=True)
        self.assertFalse(valid)
        self.assertTrue(any("entropy" in m.lower() for m in msgs))

    def test_paranoid_enables_strict_by_default(self):
        policy = PasswordPolicy(policy_level="paranoid")
        self.assertTrue(policy.strict_strength)

    def test_strong_password_passes_strict(self):
        policy = PasswordPolicy(policy_level="standard", strict_strength=True)
        valid, msgs = policy.validate_password(STRONG, quiet=True)
        self.assertTrue(valid, msgs)


class TestPublicApiBackCompat(unittest.TestCase):
    """get_password_strength stays byte-compatible; add pattern-aware sibling."""

    def test_get_password_strength_returns_raw(self):
        bits, category = get_password_strength(STRONG)
        self.assertAlmostEqual(bits, string_entropy(STRONG), places=6)
        self.assertEqual(category, strength_category(string_entropy(STRONG)))

    def test_get_pattern_strength_returns_result(self):
        res = get_pattern_strength(SEQ_HIGH_RAW)
        self.assertIsInstance(res, StrengthResult)
        self.assertLess(res.bits, res.raw_bits)


if __name__ == "__main__":
    unittest.main()
