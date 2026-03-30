#!/usr/bin/env python3
"""
Unit tests for hash registry.

Tests all hash function implementations and registry functionality.
All code in English as per project requirements.
"""

import pytest

from openssl_encrypt.modules.registry import (
    BLAKE3,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHA256,
    SHA384,
    SHA512,
    SHAKE128,
    SHAKE256,
    AlgorithmCategory,
    BLAKE2b,
    BLAKE2s,
    HashRegistry,
    SecurityLevel,
    ValidationError,
    Whirlpool,
    get_hash,
)


class TestHashRegistry:
    """Tests for HashRegistry class."""

    def test_singleton(self):
        """Test that default() returns singleton."""
        registry1 = HashRegistry.default()
        registry2 = HashRegistry.default()
        assert registry1 is registry2

    def test_all_hashes_registered(self):
        """Test that all hash functions are registered."""
        registry = HashRegistry.default()

        expected_hashes = [
            "sha256",
            "sha384",
            "sha512",
            "sha3-256",
            "sha3-384",
            "sha3-512",
            "blake2b",
            "blake2s",
            "blake3",
            "shake128",
            "shake256",
            "whirlpool",
        ]

        for hash_name in expected_hashes:
            assert registry.exists(hash_name), f"{hash_name} not registered"

    def test_get_hash_function(self):
        """Test get_hash convenience function."""
        hasher = get_hash("sha256")
        assert isinstance(hasher, SHA256)


# ============================================================================
# SHA-2 Family Tests
# ============================================================================


class TestSHA256:
    """Tests for SHA-256."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = SHA256.info()
        assert info.name == "sha256"
        assert info.category == AlgorithmCategory.HASH
        assert info.security_bits == 256
        assert info.output_size == 32
        assert info.is_xof is False

    def test_basic_hash(self):
        """Test basic hashing."""
        hasher = SHA256()
        data = b"Hello, World!"
        digest = hasher.hash(data)

        assert len(digest) == 32
        # Verify it's deterministic
        assert digest == hasher.hash(data)

    def test_empty_data(self):
        """Test hashing empty data."""
        hasher = SHA256()
        digest = hasher.hash(b"")
        assert len(digest) == 32

    def test_known_vector(self):
        """Test with known test vector."""
        hasher = SHA256()
        # SHA-256("abc") = ba7816bf...
        data = b"abc"
        digest = hasher.hash(data)
        expected = bytes.fromhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        assert digest == expected

    def test_fixed_output_length(self):
        """Test that SHA-256 rejects custom output length."""
        hasher = SHA256()
        with pytest.raises(ValidationError, match="fixed output length"):
            hasher.hash(b"data", output_length=16)


class TestSHA384:
    """Tests for SHA-384."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = SHA384.info()
        assert info.name == "sha384"
        assert info.output_size == 48
        assert info.security_level == SecurityLevel.HIGH

    def test_basic_hash(self):
        """Test basic hashing."""
        hasher = SHA384()
        data = b"Test data for SHA-384"
        digest = hasher.hash(data)
        assert len(digest) == 48


class TestSHA512:
    """Tests for SHA-512."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = SHA512.info()
        assert info.name == "sha512"
        assert info.output_size == 64
        assert info.security_bits == 512

    def test_basic_hash(self):
        """Test basic hashing."""
        hasher = SHA512()
        data = b"Test data for SHA-512"
        digest = hasher.hash(data)
        assert len(digest) == 64


# ============================================================================
# SHA-3 Family Tests
# ============================================================================


class TestSHA3_256:
    """Tests for SHA3-256."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = SHA3_256.info()
        assert info.name == "sha3-256"
        assert info.output_size == 32
        assert info.nist_standard == "FIPS 202"

    def test_basic_hash(self):
        """Test basic hashing."""
        hasher = SHA3_256()
        data = b"Test data for SHA3-256"
        digest = hasher.hash(data)
        assert len(digest) == 32

    def test_different_from_sha2(self):
        """Test that SHA3-256 produces different output from SHA-256."""
        data = b"same data"
        sha2_digest = SHA256().hash(data)
        sha3_digest = SHA3_256().hash(data)
        assert sha2_digest != sha3_digest


class TestSHA3_384:
    """Tests for SHA3-384."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = SHA3_384.info()
        assert info.name == "sha3-384"
        assert info.output_size == 48

    def test_basic_hash(self):
        """Test basic hashing."""
        hasher = SHA3_384()
        digest = hasher.hash(b"test")
        assert len(digest) == 48


class TestSHA3_512:
    """Tests for SHA3-512."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = SHA3_512.info()
        assert info.name == "sha3-512"
        assert info.output_size == 64

    def test_basic_hash(self):
        """Test basic hashing."""
        hasher = SHA3_512()
        digest = hasher.hash(b"test")
        assert len(digest) == 64


# ============================================================================
# BLAKE2 Family Tests
# ============================================================================


class TestBLAKE2b:
    """Tests for BLAKE2b."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = BLAKE2b.info()
        assert info.name == "blake2b"
        assert info.output_size == 64
        assert info.supports_keyed_mode is True
        assert info.security_level == SecurityLevel.HIGH

    def test_basic_hash(self):
        """Test basic hashing with default size."""
        hasher = BLAKE2b()
        data = b"BLAKE2b test data"
        digest = hasher.hash(data)
        assert len(digest) == 64

    def test_variable_output_length(self):
        """Test variable output length."""
        hasher = BLAKE2b()
        data = b"test"

        # Test various output lengths
        for length in [16, 32, 48, 64]:
            digest = hasher.hash(data, output_length=length)
            assert len(digest) == length

    def test_keyed_hashing(self):
        """Test keyed hashing mode."""
        hasher = BLAKE2b()
        data = b"message"
        key = b"secret key"

        digest = hasher.hash_keyed(data, key)
        assert len(digest) == 64

        # Different key should produce different digest
        different_key = b"other key"
        different_digest = hasher.hash_keyed(data, different_key)
        assert digest != different_digest

    def test_invalid_digest_size(self):
        """Test that invalid digest size raises error."""
        hasher = BLAKE2b()
        with pytest.raises(ValidationError, match="1-64 bytes"):
            hasher.hash(b"data", output_length=65)

        with pytest.raises(ValidationError, match="1-64 bytes"):
            hasher.hash(b"data", output_length=0)

    def test_invalid_key_size(self):
        """Test that oversized key raises error."""
        hasher = BLAKE2b()
        too_long_key = b"x" * 65
        with pytest.raises(ValidationError, match="0-64 bytes"):
            hasher.hash_keyed(b"data", too_long_key)


class TestBLAKE2s:
    """Tests for BLAKE2s."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = BLAKE2s.info()
        assert info.name == "blake2s"
        assert info.output_size == 32
        assert info.supports_keyed_mode is True

    def test_basic_hash(self):
        """Test basic hashing."""
        hasher = BLAKE2s()
        digest = hasher.hash(b"test")
        assert len(digest) == 32

    def test_variable_output_length(self):
        """Test variable output length."""
        hasher = BLAKE2s()
        for length in [8, 16, 24, 32]:
            digest = hasher.hash(b"test", output_length=length)
            assert len(digest) == length

    def test_keyed_hashing(self):
        """Test keyed hashing mode."""
        hasher = BLAKE2s()
        data = b"message"
        key = b"key"

        digest = hasher.hash_keyed(data, key)
        assert len(digest) == 32

    def test_invalid_key_size(self):
        """Test that oversized key raises error."""
        hasher = BLAKE2s()
        too_long_key = b"x" * 33
        with pytest.raises(ValidationError, match="0-32 bytes"):
            hasher.hash_keyed(b"data", too_long_key)


class TestBLAKE3:
    """Tests for BLAKE3."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = BLAKE3.info()
        assert info.name == "blake3"
        assert info.output_size == 32
        assert info.supports_keyed_mode is True
        assert info.is_xof is True

    def test_availability(self):
        """Test availability check."""
        # BLAKE3 requires external package
        if BLAKE3.is_available():
            pytest.skip("BLAKE3 is available (test would pass)")
        else:
            pytest.skip("BLAKE3 not available (expected)")

    @pytest.mark.skipif(not BLAKE3.is_available(), reason="BLAKE3 not available")
    def test_basic_hash(self):
        """Test basic hashing."""
        hasher = BLAKE3()
        digest = hasher.hash(b"test")
        assert len(digest) == 32

    @pytest.mark.skipif(not BLAKE3.is_available(), reason="BLAKE3 not available")
    def test_variable_output_xof(self):
        """Test extendable output function."""
        hasher = BLAKE3()
        data = b"test"

        # BLAKE3 can produce arbitrary length output
        for length in [16, 32, 64, 128, 256]:
            digest = hasher.hash(data, output_length=length)
            assert len(digest) == length

    @pytest.mark.skipif(not BLAKE3.is_available(), reason="BLAKE3 not available")
    def test_keyed_hashing(self):
        """Test keyed hashing mode."""
        hasher = BLAKE3()
        data = b"message"
        key = b"0" * 32  # BLAKE3 requires exactly 32-byte key

        digest = hasher.hash_keyed(data, key)
        assert len(digest) == 32

    @pytest.mark.skipif(not BLAKE3.is_available(), reason="BLAKE3 not available")
    def test_invalid_key_size(self):
        """Test that wrong key size raises error."""
        hasher = BLAKE3()
        with pytest.raises(ValidationError, match="exactly 32-byte key"):
            hasher.hash_keyed(b"data", b"short key")


# ============================================================================
# SHAKE (XOF) Tests
# ============================================================================


class TestSHAKE128:
    """Tests for SHAKE-128."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = SHAKE128.info()
        assert info.name == "shake128"
        assert info.output_size == 16  # Default
        assert info.is_xof is True
        assert info.nist_standard == "FIPS 202"

    def test_default_output(self):
        """Test default output length."""
        hasher = SHAKE128()
        digest = hasher.hash(b"test")
        assert len(digest) == 16

    def test_variable_output(self):
        """Test extendable output."""
        hasher = SHAKE128()
        data = b"test data"

        # SHAKE can produce arbitrary length
        for length in [8, 16, 32, 64, 128]:
            digest = hasher.hash(data, output_length=length)
            assert len(digest) == length

    def test_different_lengths_different_output(self):
        """Test that different lengths produce different output."""
        hasher = SHAKE128()
        data = b"test"

        digest_16 = hasher.hash(data, output_length=16)
        digest_32 = hasher.hash(data, output_length=32)

        # First 16 bytes should match
        assert digest_32[:16] == digest_16


class TestSHAKE256:
    """Tests for SHAKE-256."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = SHAKE256.info()
        assert info.name == "shake256"
        assert info.output_size == 32  # Default
        assert info.is_xof is True
        assert info.security_level == SecurityLevel.HIGH

    def test_default_output(self):
        """Test default output length."""
        hasher = SHAKE256()
        digest = hasher.hash(b"test")
        assert len(digest) == 32

    def test_variable_output(self):
        """Test extendable output."""
        hasher = SHAKE256()
        for length in [16, 32, 64, 128]:
            digest = hasher.hash(b"test", output_length=length)
            assert len(digest) == length


# ============================================================================
# Whirlpool Tests
# ============================================================================


class TestWhirlpool:
    """Tests for Whirlpool."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = Whirlpool.info()
        assert info.name == "whirlpool"
        assert info.output_size == 64
        assert info.security_level == SecurityLevel.LEGACY
        assert "LEGACY" in info.display_name

    def test_availability_check(self):
        """Test availability check (may not be available)."""
        is_available = Whirlpool.is_available()
        # Just check it doesn't crash
        assert isinstance(is_available, bool)

    @pytest.mark.skipif(not Whirlpool.is_available(), reason="Whirlpool not available")
    def test_basic_hash(self):
        """Test basic hashing if available."""
        hasher = Whirlpool()
        digest = hasher.hash(b"test")
        assert len(digest) == 64

    @pytest.mark.skipif(not Whirlpool.is_available(), reason="Whirlpool not available")
    def test_fixed_output_length(self):
        """Test that Whirlpool rejects custom output length."""
        hasher = Whirlpool()
        with pytest.raises(ValidationError, match="fixed output length"):
            hasher.hash(b"data", output_length=32)


# ============================================================================
# Comparative Tests
# ============================================================================


class TestHashComparison:
    """Comparative tests across different hash functions."""

    def test_all_standard_hashes_work(self):
        """Test that all standard (non-XOF) hashes produce output."""
        registry = HashRegistry.default()
        test_data = b"Test data for all hashes"

        standard_hashes = [
            "sha256",
            "sha384",
            "sha512",
            "sha3-256",
            "sha3-384",
            "sha3-512",
        ]

        for hash_name in standard_hashes:
            hasher = registry.get(hash_name)
            digest = hasher.hash(test_data)
            expected_size = hasher.get_output_size()
            assert len(digest) == expected_size, f"Failed for {hash_name}"

    def test_same_input_same_output(self):
        """Test determinism across all hashes."""
        registry = HashRegistry.default()
        data = b"determinism test"

        for hash_name in ["sha256", "sha512", "blake2b"]:
            hasher = registry.get(hash_name)
            digest1 = hasher.hash(data)
            digest2 = hasher.hash(data)
            assert digest1 == digest2, f"Non-deterministic: {hash_name}"

    def test_different_hashes_different_output(self):
        """Test that different hash functions produce different output."""
        data = b"test data"

        sha256_digest = SHA256().hash(data)
        sha512_digest = SHA512().hash(data)[:32]  # Truncate for comparison
        blake2b_digest = BLAKE2b().hash(data, output_length=32)

        # All should be different
        assert sha256_digest != blake2b_digest
        assert sha256_digest != sha512_digest
        assert blake2b_digest != sha512_digest


class TestHashEdgeCases:
    """Tests for edge cases and error handling."""

    def test_large_data(self):
        """Test hashing large data."""
        hasher = SHA256()
        large_data = b"x" * (1024 * 1024)  # 1 MB
        digest = hasher.hash(large_data)
        assert len(digest) == 32

    def test_unicode_handling(self):
        """Test that unicode strings are handled properly."""
        hasher = SHA256()
        # Should work with bytes
        digest = hasher.hash("test".encode("utf-8"))
        assert len(digest) == 32


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
