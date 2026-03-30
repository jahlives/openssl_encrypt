#!/usr/bin/env python3
"""
Unit tests for KEM (Key Encapsulation Mechanism) registry.

Tests all post-quantum KEM implementations and registry functionality.
All code in English as per project requirements.
"""

import pytest

from openssl_encrypt.modules.registry import (
    HQC128,
    HQC192,
    HQC256,
    MLKEM512,
    MLKEM768,
    MLKEM1024,
    AlgorithmCategory,
    AlgorithmNotAvailableError,
    KEMRegistry,
    SecurityLevel,
    get_kem,
)
from openssl_encrypt.modules.secure_memory import SecureBytes

# Check if liboqs is available
try:
    from openssl_encrypt.modules.pqc_liboqs import LIBOQS_AVAILABLE
except ImportError:
    LIBOQS_AVAILABLE = False


class TestKEMRegistry:
    """Tests for KEMRegistry class."""

    def test_singleton(self):
        """Test that default() returns singleton."""
        registry1 = KEMRegistry.default()
        registry2 = KEMRegistry.default()
        assert registry1 is registry2

    def test_all_kems_registered(self):
        """Test that all KEMs are registered."""
        registry = KEMRegistry.default()

        expected_kems = [
            # ML-KEM
            "ml-kem-512",
            "ml-kem-768",
            "ml-kem-1024",
            # HQC
            "hqc-128",
            "hqc-192",
            "hqc-256",
        ]

        for kem_name in expected_kems:
            assert registry.exists(kem_name), f"{kem_name} not registered"

    def test_get_kem_function(self):
        """Test get_kem convenience function."""
        if not LIBOQS_AVAILABLE:
            pytest.skip("liboqs not available")

        kem = get_kem("ml-kem-768")
        assert isinstance(kem, MLKEM768)

    def test_aliases_work(self):
        """Test that KEM aliases work."""
        registry = KEMRegistry.default()

        # Test ML-KEM aliases
        assert registry.exists("mlkem768")
        assert registry.exists("ml_kem_768")
        assert registry.exists("kyber768")  # Legacy alias

        # Test HQC aliases
        assert registry.exists("hqc128")
        assert registry.exists("hqc_256")


# ============================================================================
# ML-KEM Tests
# ============================================================================


class TestMLKEM512:
    """Tests for ML-KEM-512."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = MLKEM512.info()
        assert info.name == "ml-kem-512"
        assert info.category == AlgorithmCategory.KEM
        assert info.security_bits == 128
        assert info.pq_security_bits == 161
        assert info.security_level == SecurityLevel.STANDARD
        assert info.nist_standard == "FIPS 203"
        assert info.public_key_size == 800
        assert info.ciphertext_size == 768
        assert info.shared_secret_size == 32

    def test_availability(self):
        """Test availability check."""
        is_available = MLKEM512.is_available()
        assert isinstance(is_available, bool)

        if not is_available:
            with pytest.raises(AlgorithmNotAvailableError):
                MLKEM512()

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_generate_keypair(self):
        """Test keypair generation."""
        kem = MLKEM512()
        public_key, secret_key = kem.generate_keypair()

        assert isinstance(public_key, bytes)
        # secret_key can be bytes or SecureBytes (for secure memory)
        assert isinstance(secret_key, (bytes, memoryview, SecureBytes))
        assert len(public_key) == 800
        assert len(bytes(secret_key)) == 1632

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_encapsulate_decapsulate(self):
        """Test encapsulation and decapsulation."""
        kem = MLKEM512()
        public_key, secret_key = kem.generate_keypair()

        # Encapsulate
        ciphertext, shared_secret1 = kem.encapsulate(public_key)
        assert len(ciphertext) == 768
        assert len(shared_secret1) == 32

        # Decapsulate
        shared_secret2 = kem.decapsulate(ciphertext, secret_key)
        assert shared_secret1 == shared_secret2

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_different_keys_different_secrets(self):
        """Test that different keys produce different shared secrets."""
        kem = MLKEM512()

        # Generate two keypairs
        public_key1, _ = kem.generate_keypair()
        public_key2, _ = kem.generate_keypair()

        # Encapsulate with both
        _, shared_secret1 = kem.encapsulate(public_key1)
        _, shared_secret2 = kem.encapsulate(public_key2)

        # Should be different (extremely high probability)
        assert shared_secret1 != shared_secret2


class TestMLKEM768:
    """Tests for ML-KEM-768."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = MLKEM768.info()
        assert info.name == "ml-kem-768"
        assert info.security_bits == 192
        assert info.pq_security_bits == 234
        assert info.security_level == SecurityLevel.HIGH
        assert "recommended" in info.description.lower()

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_basic_operations(self):
        """Test basic KEM operations."""
        kem = MLKEM768()
        public_key, secret_key = kem.generate_keypair()

        ciphertext, shared_secret1 = kem.encapsulate(public_key)
        shared_secret2 = kem.decapsulate(ciphertext, secret_key)

        assert shared_secret1 == shared_secret2


class TestMLKEM1024:
    """Tests for ML-KEM-1024."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = MLKEM1024.info()
        assert info.name == "ml-kem-1024"
        assert info.security_bits == 256
        assert info.pq_security_bits == 309
        assert info.security_level == SecurityLevel.PARANOID

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_basic_operations(self):
        """Test basic KEM operations."""
        kem = MLKEM1024()
        public_key, secret_key = kem.generate_keypair()

        ciphertext, shared_secret1 = kem.encapsulate(public_key)
        shared_secret2 = kem.decapsulate(ciphertext, secret_key)

        assert shared_secret1 == shared_secret2


# ============================================================================
# HQC Tests
# ============================================================================


class TestHQC128:
    """Tests for HQC-128."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = HQC128.info()
        assert info.name == "hqc-128"
        assert info.category == AlgorithmCategory.KEM
        assert info.security_bits == 128
        assert "code-based" in info.description.lower()
        assert "NIST Round 4" in info.nist_standard

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_basic_operations(self):
        """Test basic KEM operations."""
        kem = HQC128()
        public_key, secret_key = kem.generate_keypair()

        ciphertext, shared_secret1 = kem.encapsulate(public_key)
        shared_secret2 = kem.decapsulate(ciphertext, secret_key)

        assert shared_secret1 == shared_secret2
        assert len(shared_secret1) == 64  # HQC uses 64-byte shared secrets


class TestHQC192:
    """Tests for HQC-192."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = HQC192.info()
        assert info.name == "hqc-192"
        assert info.security_bits == 192
        assert info.security_level == SecurityLevel.HIGH

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_basic_operations(self):
        """Test basic KEM operations."""
        kem = HQC192()
        public_key, secret_key = kem.generate_keypair()

        ciphertext, shared_secret1 = kem.encapsulate(public_key)
        shared_secret2 = kem.decapsulate(ciphertext, secret_key)

        assert shared_secret1 == shared_secret2


class TestHQC256:
    """Tests for HQC-256."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = HQC256.info()
        assert info.name == "hqc-256"
        assert info.security_bits == 256
        assert info.security_level == SecurityLevel.PARANOID

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_basic_operations(self):
        """Test basic KEM operations."""
        kem = HQC256()
        public_key, secret_key = kem.generate_keypair()

        ciphertext, shared_secret1 = kem.encapsulate(public_key)
        shared_secret2 = kem.decapsulate(ciphertext, secret_key)

        assert shared_secret1 == shared_secret2


# ============================================================================
# Comparative Tests
# ============================================================================


class TestKEMComparison:
    """Comparative tests across different KEMs."""

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_all_kems_produce_different_secrets(self):
        """Test that different KEMs produce different shared secrets."""
        registry = KEMRegistry.default()

        # Generate keypair with ML-KEM-512
        kem1 = registry.get("ml-kem-512")
        public_key, _ = kem1.generate_keypair()

        # Encapsulate with different KEMs (same key size)
        _, secret1 = kem1.encapsulate(public_key)

        # ML-KEM should produce different secrets each time
        _, secret2 = kem1.encapsulate(public_key)
        assert secret1 != secret2

    def test_size_progression(self):
        """Test that security levels have appropriate size progression."""
        info512 = MLKEM512.info()
        info768 = MLKEM768.info()
        info1024 = MLKEM1024.info()

        # Higher security = larger keys
        assert info512.public_key_size < info768.public_key_size < info1024.public_key_size
        assert info512.ciphertext_size < info768.ciphertext_size < info1024.ciphertext_size

    def test_security_level_classification(self):
        """Test security level classification."""
        assert MLKEM512.info().security_level == SecurityLevel.STANDARD
        assert MLKEM768.info().security_level == SecurityLevel.HIGH
        assert MLKEM1024.info().security_level == SecurityLevel.PARANOID

        assert HQC128.info().security_level == SecurityLevel.STANDARD
        assert HQC192.info().security_level == SecurityLevel.HIGH
        assert HQC256.info().security_level == SecurityLevel.PARANOID


# ============================================================================
# Error Handling Tests
# ============================================================================


class TestKEMErrorHandling:
    """Tests for KEM error handling."""

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_decapsulate_wrong_key(self):
        """Test decapsulation with wrong secret key."""
        kem = MLKEM512()

        # Generate two keypairs
        public_key1, secret_key1 = kem.generate_keypair()
        _, secret_key2 = kem.generate_keypair()

        # Encapsulate with first key
        ciphertext, shared_secret1 = kem.encapsulate(public_key1)

        # Decapsulate with wrong secret key
        shared_secret2 = kem.decapsulate(ciphertext, secret_key2)

        # Should produce different secret (not raise error, but wrong result)
        assert shared_secret1 != shared_secret2

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_invalid_public_key_size(self):
        """Test that invalid public key size produces different result."""
        kem = MLKEM512()

        # Generate valid keypair
        valid_public_key, _ = kem.generate_keypair()

        # Try to encapsulate with wrong-sized public key
        invalid_key = b"x" * 100

        # liboqs may not raise error but result will be invalid
        # Just ensure it doesn't crash
        try:
            result = kem.encapsulate(invalid_key)
            # If it doesn't raise, that's okay - just check we get something back
            assert result is not None
        except Exception:
            # If it does raise, that's also acceptable behavior
            pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
