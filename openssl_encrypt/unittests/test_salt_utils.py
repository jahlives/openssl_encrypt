#!/usr/bin/env python3
"""
Unit tests for salt derivation utility functions.

Tests the deprecated and secure salt derivation methods.
All code in English as per project requirements.
"""

import warnings

import pytest

from openssl_encrypt.modules.registry.utils import (
    derive_salt_chained,
    derive_salt_for_round,
)


class TestDeprecatedSaltDerivation:
    """Tests for deprecated derive_salt_for_round()."""

    def test_deprecated_warning(self):
        """Test that derive_salt_for_round() emits DeprecationWarning."""
        base_salt = b"test_salt_value"

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            derive_salt_for_round(base_salt, 1)

            # Check that a warning was issued
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "deprecated and insecure" in str(w[0].message)
            assert "chained salt derivation" in str(w[0].message)

    def test_different_rounds_different_salts(self):
        """Test that different rounds produce different salts."""
        base_salt = b"base_salt_value"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            salt0 = derive_salt_for_round(base_salt, 0)
            salt1 = derive_salt_for_round(base_salt, 1)
            salt2 = derive_salt_for_round(base_salt, 2)

        assert salt0 != salt1
        assert salt1 != salt2
        assert salt0 != salt2

    def test_deterministic(self):
        """Test that same inputs produce same outputs."""
        base_salt = b"base_salt_value"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            salt1 = derive_salt_for_round(base_salt, 5)
            salt2 = derive_salt_for_round(base_salt, 5)

        assert salt1 == salt2

    def test_salt_length(self):
        """Test that derived salt is always 16 bytes."""
        base_salt = b"test"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for round_num in range(10):
                salt = derive_salt_for_round(base_salt, round_num)
                assert len(salt) == 16


class TestChainedSaltDerivation:
    """Tests for secure derive_salt_chained()."""

    def test_chained_derivation(self):
        """Test basic chained salt derivation."""
        # Simulate output from previous round
        previous_output = b"0123456789ABCDEF0123456789ABCDEF"  # 32 bytes

        # Derive salt from previous output
        salt = derive_salt_chained(previous_output)

        # Should return first 16 bytes
        assert salt == b"0123456789ABCDEF"
        assert len(salt) == 16

    def test_chained_custom_length(self):
        """Test chained derivation with custom length."""
        previous_output = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"

        # Request different lengths
        salt8 = derive_salt_chained(previous_output, length=8)
        salt16 = derive_salt_chained(previous_output, length=16)
        salt24 = derive_salt_chained(previous_output, length=24)

        assert len(salt8) == 8
        assert len(salt16) == 16
        assert len(salt24) == 24

        assert salt8 == b"ABCDEFGH"
        assert salt16 == b"ABCDEFGHIJKLMNOP"
        assert salt24 == b"ABCDEFGHIJKLMNOPQRSTUVWX"

    def test_chained_deterministic(self):
        """Test that chained derivation is deterministic."""
        previous_output = b"deterministic_test_data_here"

        salt1 = derive_salt_chained(previous_output)
        salt2 = derive_salt_chained(previous_output)

        assert salt1 == salt2

    def test_chained_insufficient_length(self):
        """Test error handling when previous_output is too short."""
        short_output = b"short"  # Only 5 bytes

        # Requesting 16 bytes should raise ValueError
        with pytest.raises(ValueError, match="Previous output too short"):
            derive_salt_chained(short_output, length=16)

        # Requesting 10 bytes should also raise ValueError
        with pytest.raises(ValueError, match="too short"):
            derive_salt_chained(short_output, length=10)

    def test_chained_exact_length(self):
        """Test chained derivation when output is exactly the requested length."""
        exact_output = b"exactly16bytes!!"  # Exactly 16 bytes

        salt = derive_salt_chained(exact_output, length=16)
        assert salt == exact_output
        assert len(salt) == 16

    def test_chained_prevents_precomputation(self):
        """Test that chained derivation creates dependency on previous round."""
        # Simulate multi-round KDF with chained salts
        base_salt = b"initial_salt_val"

        # Round 0: Use base salt (simulated output)
        round_0_output = b"round_0_output_data_here_32bytes"

        # Round 1: Derive salt from round 0 output
        round_1_salt = derive_salt_chained(round_0_output)

        # Round 1: Simulated output depends on round_1_salt
        round_1_output = b"round_1_output_different_32bytes"

        # Round 2: Derive salt from round 1 output
        round_2_salt = derive_salt_chained(round_1_output)

        # Verify that each salt is different and depends on previous output
        assert round_1_salt != base_salt
        assert round_2_salt != round_1_salt
        assert round_2_salt != base_salt

        # Verify salts are derived from corresponding outputs
        assert round_1_salt == round_0_output[:16]
        assert round_2_salt == round_1_output[:16]


class TestSaltDerivationComparison:
    """Tests comparing deprecated vs secure salt derivation methods."""

    def test_v8_v9_produce_different_salts(self):
        """Test that v8 (deprecated) and v9 (chained) produce different salts."""
        base_salt = b"comparison_test"

        # v8 method: derive from base_salt
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            v8_salt_round_1 = derive_salt_for_round(base_salt, 1)

        # v9 method: would use previous round's output
        # Simulate a 32-byte output from round 0
        simulated_round_0_output = b"simulated_kdf_output_32bytes_lng"
        v9_salt_round_1 = derive_salt_chained(simulated_round_0_output)

        # These should be different
        assert v8_salt_round_1 != v9_salt_round_1

    def test_chained_creates_dependency_chain(self):
        """Test that chained derivation creates cryptographic dependency."""
        base_salt = b"base_dependency_test"

        # In v8, all salts can be derived from base_salt independently
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            v8_salt_1 = derive_salt_for_round(base_salt, 1)
            v8_salt_2 = derive_salt_for_round(base_salt, 2)
            v8_salt_3 = derive_salt_for_round(base_salt, 3)

        # All v8 salts are independent (precomputable from base_salt alone)
        # This is the security vulnerability

        # In v9, each salt depends on the previous round's output
        output_0 = b"00000000000000000000000000000000"  # 32 bytes
        salt_1 = derive_salt_chained(output_0)

        output_1 = b"11111111111111111111111111111111"  # 32 bytes
        salt_2 = derive_salt_chained(output_1)

        output_2 = b"22222222222222222222222222222222"  # 32 bytes
        salt_3 = derive_salt_chained(output_2)

        # v9 salts form a dependency chain
        assert salt_1 == output_0[:16]
        assert salt_2 == output_1[:16]
        assert salt_3 == output_2[:16]

        # Each salt is different and depends on different output
        assert salt_1 != salt_2 != salt_3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
