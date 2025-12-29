#!/usr/bin/env python3
"""
Unit tests for post-quantum signature registry.

Tests all post-quantum signature implementations and registry functionality.
All code in English as per project requirements.
"""

import pytest

from openssl_encrypt.modules.registry import (
    CROSS128,
    CROSS192,
    CROSS256,
    FNDSA512,
    FNDSA1024,
    MAYO1,
    MAYO3,
    MAYO5,
    MLDSA44,
    MLDSA65,
    MLDSA87,
    SLHDSASHA2128F,
    SLHDSASHA2192F,
    SLHDSASHA2256F,
    AlgorithmCategory,
    AlgorithmNotAvailableError,
    SecurityLevel,
    SignatureRegistry,
    get_signature,
)
from openssl_encrypt.modules.secure_memory import SecureBytes

# Check if liboqs is available
try:
    from openssl_encrypt.modules.pqc_liboqs import LIBOQS_AVAILABLE
except ImportError:
    LIBOQS_AVAILABLE = False


class TestSignatureRegistry:
    """Tests for SignatureRegistry class."""

    def test_singleton(self):
        """Test that default() returns singleton."""
        registry1 = SignatureRegistry.default()
        registry2 = SignatureRegistry.default()
        assert registry1 is registry2

    def test_all_signatures_registered(self):
        """Test that all signature algorithms are registered."""
        registry = SignatureRegistry.default()

        expected_sigs = [
            # ML-DSA
            "ml-dsa-44",
            "ml-dsa-65",
            "ml-dsa-87",
            # SLH-DSA
            "slh-dsa-sha2-128f",
            "slh-dsa-sha2-192f",
            "slh-dsa-sha2-256f",
            # FN-DSA
            "fn-dsa-512",
            "fn-dsa-1024",
            # MAYO
            "mayo-1",
            "mayo-3",
            "mayo-5",
            # CROSS
            "cross-128",
            "cross-192",
            "cross-256",
        ]

        for sig_name in expected_sigs:
            assert registry.exists(sig_name), f"{sig_name} not registered"

    def test_get_signature_function(self):
        """Test get_signature convenience function."""
        if not LIBOQS_AVAILABLE:
            pytest.skip("liboqs not available")

        sig = get_signature("ml-dsa-65")
        assert isinstance(sig, MLDSA65)

    def test_aliases_work(self):
        """Test that signature aliases work."""
        registry = SignatureRegistry.default()

        # Test ML-DSA aliases
        assert registry.exists("mldsa65")
        assert registry.exists("ml_dsa_65")
        assert registry.exists("dilithium3")  # Legacy alias

        # Test FN-DSA aliases
        assert registry.exists("falcon512")
        assert registry.exists("fndsa-512")

        # Test SLH-DSA aliases
        assert registry.exists("sphincs-sha2-128f")


# ============================================================================
# ML-DSA Tests
# ============================================================================


class TestMLDSA44:
    """Tests for ML-DSA-44."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = MLDSA44.info()
        assert info.name == "ml-dsa-44"
        assert info.category == AlgorithmCategory.SIGNATURE
        assert info.security_bits == 128
        assert info.security_level == SecurityLevel.STANDARD
        assert info.nist_standard == "FIPS 204"
        assert info.public_key_size == 1312
        assert info.signature_size == 2420

    def test_availability(self):
        """Test availability check."""
        is_available = MLDSA44.is_available()
        assert isinstance(is_available, bool)

        if not is_available:
            with pytest.raises(AlgorithmNotAvailableError):
                MLDSA44()

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_generate_keypair(self):
        """Test keypair generation."""
        sig = MLDSA44()
        public_key, secret_key = sig.generate_keypair()

        assert isinstance(public_key, bytes)
        # secret_key can be bytes or SecureBytes (for secure memory)
        assert isinstance(secret_key, (bytes, memoryview, SecureBytes))
        assert len(public_key) == 1312
        assert len(bytes(secret_key)) == 2560

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_sign_verify(self):
        """Test signing and verification."""
        sig = MLDSA44()
        public_key, secret_key = sig.generate_keypair()

        message = b"Test message for ML-DSA-44"

        # Sign
        signature = sig.sign(message, secret_key)
        assert isinstance(signature, bytes)
        assert len(signature) == 2420

        # Verify
        is_valid = sig.verify(message, signature, public_key)
        assert is_valid is True

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_verify_wrong_message(self):
        """Test that verification fails with wrong message."""
        sig = MLDSA44()
        public_key, secret_key = sig.generate_keypair()

        message1 = b"Original message"
        message2 = b"Different message"

        signature = sig.sign(message1, secret_key)

        # Verify with wrong message should fail
        is_valid = sig.verify(message2, signature, public_key)
        assert is_valid is False

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_verify_wrong_key(self):
        """Test that verification fails with wrong public key."""
        sig = MLDSA44()
        public_key1, secret_key1 = sig.generate_keypair()
        public_key2, _ = sig.generate_keypair()

        message = b"Test message"
        signature = sig.sign(message, secret_key1)

        # Verify with wrong public key should fail
        is_valid = sig.verify(message, signature, public_key2)
        assert is_valid is False


class TestMLDSA65:
    """Tests for ML-DSA-65."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = MLDSA65.info()
        assert info.name == "ml-dsa-65"
        assert info.security_bits == 192
        assert info.security_level == SecurityLevel.HIGH
        assert "recommended" in info.description.lower()

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_basic_operations(self):
        """Test basic signature operations."""
        sig = MLDSA65()
        public_key, secret_key = sig.generate_keypair()

        message = b"Test message"
        signature = sig.sign(message, secret_key)

        is_valid = sig.verify(message, signature, public_key)
        assert is_valid is True


class TestMLDSA87:
    """Tests for ML-DSA-87."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = MLDSA87.info()
        assert info.name == "ml-dsa-87"
        assert info.security_bits == 256
        assert info.security_level == SecurityLevel.PARANOID

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_basic_operations(self):
        """Test basic signature operations."""
        sig = MLDSA87()
        public_key, secret_key = sig.generate_keypair()

        message = b"Test message"
        signature = sig.sign(message, secret_key)

        is_valid = sig.verify(message, signature, public_key)
        assert is_valid is True


# ============================================================================
# SLH-DSA Tests
# ============================================================================


class TestSLHDSASHA2128F:
    """Tests for SLH-DSA-SHA2-128F."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = SLHDSASHA2128F.info()
        assert info.name == "slh-dsa-sha2-128f"
        assert info.category == AlgorithmCategory.SIGNATURE
        assert info.nist_standard == "FIPS 205"
        assert "stateless hash-based" in info.description.lower()
        # SLH-DSA has small keys but large signatures
        assert info.public_key_size == 32
        assert info.signature_size == 17088

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_basic_operations(self):
        """Test basic signature operations."""
        sig = SLHDSASHA2128F()
        public_key, secret_key = sig.generate_keypair()

        message = b"Test message"
        signature = sig.sign(message, secret_key)

        # SLH-DSA signatures are large
        assert len(signature) == 17088

        is_valid = sig.verify(message, signature, public_key)
        assert is_valid is True


class TestSLHDSASHA2192F:
    """Tests for SLH-DSA-SHA2-192F."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = SLHDSASHA2192F.info()
        assert info.name == "slh-dsa-sha2-192f"
        assert info.security_level == SecurityLevel.HIGH
        assert info.signature_size == 35664  # Even larger signature

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_basic_operations(self):
        """Test basic signature operations."""
        sig = SLHDSASHA2192F()
        public_key, secret_key = sig.generate_keypair()

        message = b"Test message"
        signature = sig.sign(message, secret_key)

        is_valid = sig.verify(message, signature, public_key)
        assert is_valid is True


class TestSLHDSASHA2256F:
    """Tests for SLH-DSA-SHA2-256F."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = SLHDSASHA2256F.info()
        assert info.name == "slh-dsa-sha2-256f"
        assert info.security_level == SecurityLevel.PARANOID
        assert info.signature_size == 49856  # Largest signature

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_basic_operations(self):
        """Test basic signature operations."""
        sig = SLHDSASHA2256F()
        public_key, secret_key = sig.generate_keypair()

        message = b"Test message"
        signature = sig.sign(message, secret_key)

        is_valid = sig.verify(message, signature, public_key)
        assert is_valid is True


# ============================================================================
# FN-DSA Tests
# ============================================================================


class TestFNDSA512:
    """Tests for FN-DSA-512."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = FNDSA512.info()
        assert info.name == "fn-dsa-512"
        assert info.nist_standard == "FIPS 206 (forthcoming)"
        assert "compact signatures" in info.description.lower()
        # Falcon has smallest signatures
        assert info.signature_size == 666

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_basic_operations(self):
        """Test basic signature operations."""
        sig = FNDSA512()
        public_key, secret_key = sig.generate_keypair()

        message = b"Test message"
        signature = sig.sign(message, secret_key)

        is_valid = sig.verify(message, signature, public_key)
        assert is_valid is True


class TestFNDSA1024:
    """Tests for FN-DSA-1024."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = FNDSA1024.info()
        assert info.name == "fn-dsa-1024"
        assert info.security_level == SecurityLevel.PARANOID
        assert info.signature_size == 1280

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_basic_operations(self):
        """Test basic signature operations."""
        sig = FNDSA1024()
        public_key, secret_key = sig.generate_keypair()

        message = b"Test message"
        signature = sig.sign(message, secret_key)

        is_valid = sig.verify(message, signature, public_key)
        assert is_valid is True


# ============================================================================
# MAYO Tests
# ============================================================================


class TestMAYO1:
    """Tests for MAYO-1."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = MAYO1.info()
        assert info.name == "mayo-1"
        assert "multivariate" in info.description.lower()
        assert "NIST Round 2" in info.nist_standard
        # MAYO has very small secret keys
        assert info.secret_key_size == 24
        assert info.signature_size == 321

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_basic_operations(self):
        """Test basic signature operations."""
        sig = MAYO1()
        public_key, secret_key = sig.generate_keypair()

        message = b"Test message"
        signature = sig.sign(message, secret_key)

        is_valid = sig.verify(message, signature, public_key)
        assert is_valid is True


class TestMAYO3:
    """Tests for MAYO-3."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = MAYO3.info()
        assert info.name == "mayo-3"
        assert info.security_level == SecurityLevel.HIGH

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_basic_operations(self):
        """Test basic signature operations."""
        sig = MAYO3()
        public_key, secret_key = sig.generate_keypair()

        message = b"Test message"
        signature = sig.sign(message, secret_key)

        is_valid = sig.verify(message, signature, public_key)
        assert is_valid is True


class TestMAYO5:
    """Tests for MAYO-5."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = MAYO5.info()
        assert info.name == "mayo-5"
        assert info.security_level == SecurityLevel.PARANOID

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_basic_operations(self):
        """Test basic signature operations."""
        sig = MAYO5()
        public_key, secret_key = sig.generate_keypair()

        message = b"Test message"
        signature = sig.sign(message, secret_key)

        is_valid = sig.verify(message, signature, public_key)
        assert is_valid is True


# ============================================================================
# CROSS Tests
# ============================================================================


class TestCROSS128:
    """Tests for CROSS-128."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = CROSS128.info()
        assert info.name == "cross-128"
        assert "code-based" in info.description.lower()
        # CROSS has small keys but large signatures
        assert info.public_key_size == 77
        assert info.secret_key_size == 32
        assert info.signature_size == 12852

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_basic_operations(self):
        """Test basic signature operations."""
        sig = CROSS128()
        public_key, secret_key = sig.generate_keypair()

        message = b"Test message"
        signature = sig.sign(message, secret_key)

        is_valid = sig.verify(message, signature, public_key)
        assert is_valid is True


class TestCROSS192:
    """Tests for CROSS-192."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = CROSS192.info()
        assert info.name == "cross-192"
        assert info.security_level == SecurityLevel.HIGH

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_basic_operations(self):
        """Test basic signature operations."""
        sig = CROSS192()
        public_key, secret_key = sig.generate_keypair()

        message = b"Test message"
        signature = sig.sign(message, secret_key)

        is_valid = sig.verify(message, signature, public_key)
        assert is_valid is True


class TestCROSS256:
    """Tests for CROSS-256."""

    def test_metadata(self):
        """Test algorithm metadata."""
        info = CROSS256.info()
        assert info.name == "cross-256"
        assert info.security_level == SecurityLevel.PARANOID

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_basic_operations(self):
        """Test basic signature operations."""
        sig = CROSS256()
        public_key, secret_key = sig.generate_keypair()

        message = b"Test message"
        signature = sig.sign(message, secret_key)

        is_valid = sig.verify(message, signature, public_key)
        assert is_valid is True


# ============================================================================
# Comparative Tests
# ============================================================================


class TestSignatureComparison:
    """Comparative tests across different signature algorithms."""

    def test_size_tradeoffs(self):
        """Test size tradeoffs across algorithms."""
        # ML-DSA: balanced
        mldsa = MLDSA65.info()

        # SLH-DSA: small keys, large signatures
        slhdsa = SLHDSASHA2128F.info()

        # FN-DSA: compact signatures
        fndsa = FNDSA512.info()

        # MAYO: very small secret keys
        mayo = MAYO1.info()

        # Verify tradeoffs
        assert slhdsa.public_key_size < mldsa.public_key_size
        assert slhdsa.signature_size > mldsa.signature_size

        assert fndsa.signature_size < mldsa.signature_size

        assert mayo.secret_key_size < mldsa.secret_key_size

    def test_security_level_classification(self):
        """Test security level classification."""
        # Level 1 (128-bit)
        assert MLDSA44.info().security_level == SecurityLevel.STANDARD
        assert SLHDSASHA2128F.info().security_level == SecurityLevel.STANDARD
        assert FNDSA512.info().security_level == SecurityLevel.STANDARD

        # Level 3 (192-bit)
        assert MLDSA65.info().security_level == SecurityLevel.HIGH
        assert MAYO3.info().security_level == SecurityLevel.HIGH

        # Level 5 (256-bit)
        assert MLDSA87.info().security_level == SecurityLevel.PARANOID
        assert FNDSA1024.info().security_level == SecurityLevel.PARANOID

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_randomized_signatures(self):
        """Test that signatures are randomized (different each time)."""
        sig = MLDSA44()
        public_key, secret_key = sig.generate_keypair()

        message = b"Randomization test"

        signature1 = sig.sign(message, secret_key)
        signature2 = sig.sign(message, secret_key)

        # ML-DSA signatures are randomized (not deterministic)
        assert signature1 != signature2

        # But both signatures should verify correctly
        assert sig.verify(message, signature1, public_key)
        assert sig.verify(message, signature2, public_key)


# ============================================================================
# Error Handling Tests
# ============================================================================


class TestSignatureErrorHandling:
    """Tests for signature error handling."""

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_tampered_signature(self):
        """Test that tampered signature fails verification."""
        sig = MLDSA44()
        public_key, secret_key = sig.generate_keypair()

        message = b"Test message"
        signature = sig.sign(message, secret_key)

        # Tamper with signature
        tampered = bytearray(signature)
        tampered[0] ^= 0xFF
        tampered_signature = bytes(tampered)

        # Verification should fail
        is_valid = sig.verify(message, tampered_signature, public_key)
        assert is_valid is False

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not available")
    def test_empty_message(self):
        """Test signing empty message."""
        sig = MLDSA44()
        public_key, secret_key = sig.generate_keypair()

        message = b""
        signature = sig.sign(message, secret_key)

        is_valid = sig.verify(message, signature, public_key)
        assert is_valid is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
