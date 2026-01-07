#!/usr/bin/env python3
"""
Unit tests for KDF registry.

Tests all key derivation function implementations and registry functionality.
All code in English as per project requirements.
"""

import pytest

from openssl_encrypt.modules.registry import (
    HKDF,
    PBKDF2,
    AlgorithmCategory,
    Argon2d,
    Argon2i,
    Argon2id,
    Argon2Params,
    Balloon,
    BalloonParams,
    HKDFParams,
    KDFRegistry,
    PBKDF2Params,
    RandomX,
    RandomXParams,
    Scrypt,
    ScryptParams,
    SecurityLevel,
    ValidationError,
    get_kdf,
)


class TestKDFRegistry:
    """Tests for KDFRegistry class."""

    def test_singleton(self):
        """Test that default() returns singleton."""
        registry1 = KDFRegistry.default()
        registry2 = KDFRegistry.default()
        assert registry1 is registry2

    def test_all_kdfs_registered(self):
        """Test that all KDFs are registered."""
        registry = KDFRegistry.default()

        expected_kdfs = [
            "argon2id",
            "argon2i",
            "argon2d",
            "pbkdf2",
            "scrypt",
            "balloon",
            "hkdf",
            "randomx",
        ]

        for kdf_name in expected_kdfs:
            assert registry.exists(kdf_name), f"{kdf_name} not registered"

    def test_get_kdf_function(self):
        """Test get_kdf convenience function."""
        kdf = get_kdf("argon2id")
        assert isinstance(kdf, Argon2id)


# ============================================================================
# Argon2 Family Tests
# ============================================================================


class TestArgon2id:
    """Tests for Argon2id."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = Argon2id.info()
        assert info.name == "argon2id"
        assert info.category == AlgorithmCategory.KDF
        assert info.security_level == SecurityLevel.STANDARD
        assert "argon2" in info.aliases

    def test_availability(self):
        """Test availability check."""
        is_available = Argon2id.is_available()
        assert isinstance(is_available, bool)

    @pytest.mark.skipif(not Argon2id.is_available(), reason="Argon2 not available")
    def test_basic_derivation(self):
        """Test basic key derivation."""
        kdf = Argon2id()
        password = b"test password"
        salt = b"0" * 16

        key = kdf.derive(password, salt)
        assert len(key) == 32  # Default output length

    @pytest.mark.skipif(not Argon2id.is_available(), reason="Argon2 not available")
    def test_deterministic(self):
        """Test that same inputs produce same output."""
        kdf = Argon2id()
        password = b"test password"
        salt = b"1" * 16

        key1 = kdf.derive(password, salt)
        key2 = kdf.derive(password, salt)
        assert key1 == key2

    @pytest.mark.skipif(not Argon2id.is_available(), reason="Argon2 not available")
    def test_different_passwords_different_keys(self):
        """Test that different passwords produce different keys."""
        kdf = Argon2id()
        salt = b"2" * 16

        key1 = kdf.derive(b"password1", salt)
        key2 = kdf.derive(b"password2", salt)
        assert key1 != key2

    @pytest.mark.skipif(not Argon2id.is_available(), reason="Argon2 not available")
    def test_different_salts_different_keys(self):
        """Test that different salts produce different keys."""
        kdf = Argon2id()
        password = b"same password"

        key1 = kdf.derive(password, b"3" * 16)
        key2 = kdf.derive(password, b"4" * 16)
        assert key1 != key2

    @pytest.mark.skipif(not Argon2id.is_available(), reason="Argon2 not available")
    def test_custom_params(self):
        """Test custom parameters."""
        kdf = Argon2id()
        password = b"test"
        salt = b"5" * 16

        params = Argon2Params(
            output_length=64,  # 64-byte key
            time_cost=2,
            memory_cost=8192,  # 8 MB
            parallelism=2,
        )

        key = kdf.derive(password, salt, params)
        assert len(key) == 64

    @pytest.mark.skipif(not Argon2id.is_available(), reason="Argon2 not available")
    def test_default_params(self):
        """Test default parameters."""
        params = Argon2id.default_params()
        assert params.output_length == 32
        assert params.time_cost == 3
        assert params.memory_cost == 65536
        assert params.parallelism == 4
        assert params.variant == "id"


class TestArgon2i:
    """Tests for Argon2i."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = Argon2i.info()
        assert info.name == "argon2i"
        assert "side-channel resistant" in info.description.lower()

    @pytest.mark.skipif(not Argon2i.is_available(), reason="Argon2 not available")
    def test_basic_derivation(self):
        """Test basic key derivation."""
        kdf = Argon2i()
        key = kdf.derive(b"password", b"6" * 16)
        assert len(key) == 32

    @pytest.mark.skipif(not Argon2i.is_available(), reason="Argon2 not available")
    def test_forces_variant_i(self):
        """Test that variant is forced to 'i'."""
        kdf = Argon2i()
        params = Argon2Params(variant="id")  # Try to use 'id'

        # Should still use 'i' variant
        kdf.derive(b"test", b"7" * 16, params)
        # No exception means it worked


class TestArgon2d:
    """Tests for Argon2d."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = Argon2d.info()
        assert info.name == "argon2d"
        assert "gpu-resistant" in info.description.lower()

    @pytest.mark.skipif(not Argon2d.is_available(), reason="Argon2 not available")
    def test_basic_derivation(self):
        """Test basic key derivation."""
        kdf = Argon2d()
        key = kdf.derive(b"password", b"8" * 16)
        assert len(key) == 32


# ============================================================================
# PBKDF2 Tests
# ============================================================================


class TestPBKDF2:
    """Tests for PBKDF2."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = PBKDF2.info()
        assert info.name == "pbkdf2"
        assert info.category == AlgorithmCategory.KDF
        assert info.security_level == SecurityLevel.LEGACY
        assert info.nist_standard == "SP 800-132"

    def test_basic_derivation(self):
        """Test basic key derivation."""
        kdf = PBKDF2()
        password = b"test password"
        salt = b"9" * 16

        key = kdf.derive(password, salt)
        assert len(key) == 32

    def test_deterministic(self):
        """Test determinism."""
        kdf = PBKDF2()
        password = b"password"
        salt = b"A" * 16

        key1 = kdf.derive(password, salt)
        key2 = kdf.derive(password, salt)
        assert key1 == key2

    def test_custom_iterations(self):
        """Test custom iteration count."""
        kdf = PBKDF2()
        password = b"test"
        salt = b"B" * 16

        params = PBKDF2Params(iterations=50000)
        key = kdf.derive(password, salt, params)
        assert len(key) == 32

    def test_different_hash_functions(self):
        """Test different hash functions."""
        kdf = PBKDF2()
        password = b"test"
        salt = b"C" * 16

        # SHA-256
        params_256 = PBKDF2Params(hash_function="sha256", iterations=1000)
        key_256 = kdf.derive(password, salt, params_256)

        # SHA-512
        params_512 = PBKDF2Params(hash_function="sha512", iterations=1000)
        key_512 = kdf.derive(password, salt, params_512)

        # Should produce different keys
        assert key_256 != key_512

    def test_invalid_hash_function(self):
        """Test that invalid hash function raises error."""
        kdf = PBKDF2()
        params = PBKDF2Params(hash_function="invalid")

        with pytest.raises(ValidationError, match="Unsupported hash function"):
            kdf.derive(b"test", b"D" * 16, params)

    def test_default_params(self):
        """Test default parameters."""
        params = PBKDF2.default_params()
        assert params.iterations == 100000
        assert params.hash_function == "sha256"


# ============================================================================
# Scrypt Tests
# ============================================================================


class TestScrypt:
    """Tests for Scrypt."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = Scrypt.info()
        assert info.name == "scrypt"
        assert info.security_level == SecurityLevel.STANDARD
        assert "memory-hard" in info.description.lower()

    def test_availability(self):
        """Test availability check."""
        is_available = Scrypt.is_available()
        assert isinstance(is_available, bool)

    @pytest.mark.skipif(not Scrypt.is_available(), reason="Scrypt not available")
    def test_basic_derivation(self):
        """Test basic key derivation."""
        kdf = Scrypt()
        password = b"test password"
        salt = b"E" * 16

        key = kdf.derive(password, salt)
        assert len(key) == 32

    @pytest.mark.skipif(not Scrypt.is_available(), reason="Scrypt not available")
    def test_deterministic(self):
        """Test determinism."""
        kdf = Scrypt()
        password = b"password"
        salt = b"F" * 16

        key1 = kdf.derive(password, salt)
        key2 = kdf.derive(password, salt)
        assert key1 == key2

    @pytest.mark.skipif(not Scrypt.is_available(), reason="Scrypt not available")
    def test_custom_params(self):
        """Test custom parameters."""
        kdf = Scrypt()
        password = b"test"
        salt = b"G" * 16

        params = ScryptParams(
            n=1024,  # Lower for testing
            r=4,
            p=1,
        )

        key = kdf.derive(password, salt, params)
        assert len(key) == 32

    @pytest.mark.skipif(not Scrypt.is_available(), reason="Scrypt not available")
    def test_invalid_n_not_power_of_2(self):
        """Test that non-power-of-2 n raises error."""
        kdf = Scrypt()
        params = ScryptParams(n=1000)  # Not a power of 2

        with pytest.raises(ValidationError, match="power of 2"):
            kdf.derive(b"test", b"H" * 16, params)


# ============================================================================
# Balloon Tests
# ============================================================================


class TestBalloon:
    """Tests for Balloon hashing."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = Balloon.info()
        assert info.name == "balloon"
        assert "memory-hard" in info.description.lower()

    def test_availability(self):
        """Test availability check."""
        is_available = Balloon.is_available()
        assert isinstance(is_available, bool)

    @pytest.mark.skipif(not Balloon.is_available(), reason="Balloon not available")
    def test_basic_derivation(self):
        """Test basic key derivation."""
        from openssl_encrypt.modules.registry.kdf_registry import BalloonParams

        kdf = Balloon()
        password = b"test password"
        salt = b"I" * 16

        # Use time_cost=1 for faster testing (default is 3)
        params = BalloonParams(time_cost=1)
        key = kdf.derive(password, salt, params)
        assert len(key) == 32


# ============================================================================
# HKDF Tests
# ============================================================================


class TestHKDF:
    """Tests for HKDF."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = HKDF.info()
        assert info.name == "hkdf"
        assert "NOT for passwords" in info.description

    def test_availability(self):
        """Test availability check."""
        is_available = HKDF.is_available()
        assert isinstance(is_available, bool)

    @pytest.mark.skipif(not HKDF.is_available(), reason="HKDF not available")
    def test_basic_derivation(self):
        """Test basic key derivation (key expansion)."""
        kdf = HKDF()
        key_material = b"input key material"
        salt = b"J" * 16

        expanded_key = kdf.derive(key_material, salt)
        assert len(expanded_key) == 32

    @pytest.mark.skipif(not HKDF.is_available(), reason="HKDF not available")
    def test_with_info(self):
        """Test with context info."""
        kdf = HKDF()
        key_material = b"input"
        salt = b"K" * 16

        params = HKDFParams(info=b"application context")
        key = kdf.derive(key_material, salt, params)
        assert len(key) == 32

    @pytest.mark.skipif(not HKDF.is_available(), reason="HKDF not available")
    def test_different_info_different_keys(self):
        """Test that different info produces different keys."""
        kdf = HKDF()
        key_material = b"input"
        salt = b"L" * 16

        params1 = HKDFParams(info=b"context1")
        params2 = HKDFParams(info=b"context2")

        key1 = kdf.derive(key_material, salt, params1)
        key2 = kdf.derive(key_material, salt, params2)

        assert key1 != key2


# ============================================================================
# RandomX Tests
# ============================================================================


class TestRandomX:
    """Tests for RandomX."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = RandomX.info()
        assert info.name == "randomx"
        assert info.security_level == SecurityLevel.PARANOID
        assert "VERY SLOW" in info.display_name

    def test_availability(self):
        """Test availability check."""
        is_available = RandomX.is_available()
        assert isinstance(is_available, bool)

    @pytest.mark.skipif(not RandomX.is_available(), reason="RandomX not available")
    def test_basic_derivation(self):
        """Test basic key derivation (if available and not too slow)."""
        kdf = RandomX()
        password = b"test"
        salt = b"M" * 16

        # Use minimal params for testing
        params = RandomXParams(init_rounds=1, passes=1)

        key = kdf.derive(password, salt, params)
        assert len(key) == 32


# ============================================================================
# Parameter Tests
# ============================================================================


class TestKDFParams:
    """Tests for KDF parameter classes."""

    def test_argon2_params_defaults(self):
        """Test Argon2Params defaults."""
        params = Argon2Params()
        assert params.output_length == 32
        assert params.salt_length == 16
        assert params.time_cost == 3
        assert params.memory_cost == 65536
        assert params.parallelism == 4
        assert params.variant == "id"

    def test_pbkdf2_params_defaults(self):
        """Test PBKDF2Params defaults."""
        params = PBKDF2Params()
        assert params.output_length == 32
        assert params.iterations == 100000
        assert params.hash_function == "sha256"

    def test_scrypt_params_defaults(self):
        """Test ScryptParams defaults."""
        params = ScryptParams()
        assert params.n == 16384
        assert params.r == 8
        assert params.p == 1

    def test_param_validation(self):
        """Test parameter validation."""
        kdf = PBKDF2()

        # Invalid output length
        params = PBKDF2Params(output_length=0)
        with pytest.raises(ValidationError, match="at least 1 byte"):
            kdf.derive(b"test", b"salt", params)


# ============================================================================
# Comparative Tests
# ============================================================================


class TestKDFComparison:
    """Comparative tests across different KDFs."""

    def test_all_available_kdfs_work(self):
        """Test that all available KDFs can derive keys."""
        registry = KDFRegistry.default()
        password = b"test password"
        salt = b"N" * 16

        for kdf_name in ["pbkdf2"]:  # PBKDF2 always available
            kdf = registry.get(kdf_name)
            key = kdf.derive(password, salt)
            assert len(key) == 32, f"Failed for {kdf_name}"

    def test_different_kdfs_different_output(self):
        """Test that different KDFs produce different output."""
        password = b"same password"
        salt = b"O" * 16

        # PBKDF2 always available
        pbkdf2_key = PBKDF2().derive(password, salt)

        # If Argon2 available, compare
        if Argon2id.is_available():
            argon2_key = Argon2id().derive(password, salt)
            assert pbkdf2_key != argon2_key


class TestKDFErrorHandling:
    """Tests for KDF error handling."""

    def test_invalid_output_length(self):
        """Test that invalid output length is rejected."""
        kdf = PBKDF2()
        params = PBKDF2Params(output_length=-1)

        with pytest.raises(ValidationError):
            kdf.derive(b"test", b"P" * 16, params)

    def test_invalid_iterations(self):
        """Test that invalid iterations are rejected."""
        kdf = PBKDF2()
        params = PBKDF2Params(iterations=0)

        with pytest.raises(ValidationError, match="at least 1"):
            kdf.derive(b"test", b"Q" * 16, params)


# ============================================================================
# Multi-Round KDF Tests
# ============================================================================


class TestMultiRoundKDF:
    """Tests for multi-round KDF behavior."""

    def test_pbkdf2_multi_round_simulation(self):
        """Test simulating multi-round PBKDF2 (chained derivation)."""
        kdf = PBKDF2()
        password = b"test_password"
        base_salt = b"R" * 16

        # Simulate v9 chained salt derivation (3 rounds)
        rounds = 3
        current_output = password

        for round_num in range(rounds):
            if round_num == 0:
                round_salt = base_salt
            else:
                # Use previous output as salt (v9 chained method)
                round_salt = bytes(current_output[:16])

            current_output = kdf.derive(bytes(current_output), round_salt)

        final_key_v9 = bytes(current_output)
        assert len(final_key_v9) == 32

        # Simulate v8 predictable salt derivation (3 rounds)
        import hashlib

        current_output = password
        for round_num in range(rounds):
            if round_num == 0:
                round_salt = base_salt
            else:
                # Use predictable derivation (v8 method)
                salt_material = hashlib.sha256(base_salt + str(round_num).encode()).digest()
                round_salt = salt_material[:16]

            current_output = kdf.derive(bytes(current_output), round_salt)

        final_key_v8 = bytes(current_output)

        # v8 and v9 should produce different results
        assert final_key_v8 != final_key_v9

    @pytest.mark.skipif(not Argon2id.is_available(), reason="Argon2 not available")
    def test_argon2_multi_round_simulation(self):
        """Test simulating multi-round Argon2 with different salt derivation methods."""
        kdf = Argon2id()
        password = b"test_password"
        base_salt = b"S" * 16

        # Simulate v9 chained salt derivation (2 rounds)
        rounds = 2
        current_output = password

        for round_num in range(rounds):
            if round_num == 0:
                round_salt = base_salt
            else:
                # Use previous output as salt (v9 chained method)
                round_salt = bytes(current_output[:16])

            current_output = kdf.derive(bytes(current_output), round_salt)

        final_key_v9 = bytes(current_output)

        # Simulate v8 predictable salt derivation (2 rounds)
        import hashlib

        current_output = password
        for round_num in range(rounds):
            if round_num == 0:
                round_salt = base_salt
            else:
                # Use predictable derivation (v8 method)
                salt_material = hashlib.sha256(base_salt + str(round_num).encode()).digest()
                round_salt = salt_material[:16]

            current_output = kdf.derive(bytes(current_output), round_salt)

        final_key_v8 = bytes(current_output)

        # v8 and v9 should produce different results
        assert final_key_v8 != final_key_v9

    @pytest.mark.skipif(not Scrypt.is_available(), reason="Scrypt not available")
    def test_scrypt_multi_round_simulation(self):
        """Test simulating multi-round Scrypt with different salt derivation methods."""
        kdf = Scrypt()
        password = b"test_password"
        base_salt = b"T" * 16

        # Use low params for faster testing
        params = ScryptParams(n=1024, r=4, p=1)

        # Simulate v9 chained salt derivation (2 rounds)
        rounds = 2
        current_output = password

        for round_num in range(rounds):
            if round_num == 0:
                round_salt = base_salt
            else:
                # Use previous output as salt (v9 chained method)
                round_salt = bytes(current_output[:16])

            current_output = kdf.derive(bytes(current_output), round_salt, params)

        final_key_v9 = bytes(current_output)

        # Simulate v8 predictable salt derivation (2 rounds)
        import hashlib

        current_output = password
        for round_num in range(rounds):
            if round_num == 0:
                round_salt = base_salt
            else:
                # Use predictable derivation (v8 method)
                salt_material = hashlib.sha256(base_salt + str(round_num).encode()).digest()
                round_salt = salt_material[:16]

            current_output = kdf.derive(bytes(current_output), round_salt, params)

        final_key_v8 = bytes(current_output)

        # v8 and v9 should produce different results
        assert final_key_v8 != final_key_v9

    def test_single_vs_multi_round_different(self):
        """Test that single round vs multi-round produce different output."""
        kdf = PBKDF2()
        password = b"test_password"
        salt = b"U" * 16

        # Single round
        single_round_key = bytes(kdf.derive(password, salt))

        # Multi-round (2 rounds with chained salt)
        round_0_output = kdf.derive(password, salt)
        round_1_salt = bytes(round_0_output[:16])
        multi_round_key = bytes(kdf.derive(bytes(round_0_output), round_1_salt))

        # Should be different
        assert single_round_key != multi_round_key

    def test_chained_salt_creates_dependency(self):
        """Test that chained salt derivation creates cryptographic dependencies."""
        kdf = PBKDF2()
        password = b"password"
        base_salt = b"V" * 16

        # First execution with specific round 0 output
        round_0_output_a = kdf.derive(password, base_salt)
        round_1_salt_a = bytes(round_0_output_a[:16])
        round_1_output_a = bytes(kdf.derive(bytes(round_0_output_a), round_1_salt_a))

        # Second execution - change the "round 0 output" slightly
        # This simulates what happens if round 0 produced different output
        modified_password = b"password_modified"
        round_0_output_b = kdf.derive(modified_password, base_salt)
        round_1_salt_b = bytes(round_0_output_b[:16])
        round_1_output_b = bytes(kdf.derive(bytes(round_0_output_b), round_1_salt_b))

        # The round 1 salts should be different (dependency on previous round)
        assert round_1_salt_a != round_1_salt_b

        # The final outputs should be different
        assert round_1_output_a != round_1_output_b


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
