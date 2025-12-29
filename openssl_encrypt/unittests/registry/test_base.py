#!/usr/bin/env python3
"""
Unit tests for registry base classes.

Tests AlgorithmBase, AlgorithmInfo, RegistryBase, and related functionality.
All code in English as per project requirements.
"""

import pytest

from openssl_encrypt.modules.registry.base import (
    AlgorithmBase,
    AlgorithmCategory,
    AlgorithmError,
    AlgorithmInfo,
    AlgorithmNotAvailableError,
    AlgorithmNotFoundError,
    RegistryBase,
    SecurityLevel,
    ValidationError,
)


class TestAlgorithmInfo:
    """Tests for AlgorithmInfo dataclass."""

    def test_basic_creation(self):
        """Test creating a basic AlgorithmInfo."""
        info = AlgorithmInfo(
            name="test-algo",
            display_name="Test Algorithm",
            category=AlgorithmCategory.CIPHER,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="A test algorithm",
        )

        assert info.name == "test-algo"
        assert info.display_name == "Test Algorithm"
        assert info.category == AlgorithmCategory.CIPHER
        assert info.security_bits == 256
        assert info.pq_security_bits == 128
        assert info.security_level == SecurityLevel.STANDARD

    def test_cipher_specific_fields(self):
        """Test cipher-specific fields."""
        info = AlgorithmInfo(
            name="aes-256-gcm",
            display_name="AES-256-GCM",
            category=AlgorithmCategory.CIPHER,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="AES-256 in GCM mode",
            key_size=32,
            nonce_size=12,
            tag_size=16,
            block_size=16,
        )

        assert info.key_size == 32
        assert info.nonce_size == 12
        assert info.tag_size == 16
        assert info.block_size == 16

    def test_hash_specific_fields(self):
        """Test hash-specific fields."""
        info = AlgorithmInfo(
            name="blake3",
            display_name="BLAKE3",
            category=AlgorithmCategory.HASH,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.HIGH,
            description="BLAKE3 hash function",
            output_size=64,
            supports_keyed_mode=True,
            is_xof=True,
        )

        assert info.output_size == 64
        assert info.supports_keyed_mode is True
        assert info.is_xof is True

    def test_kem_specific_fields(self):
        """Test KEM-specific fields."""
        info = AlgorithmInfo(
            name="ml-kem-768",
            display_name="ML-KEM-768",
            category=AlgorithmCategory.KEM,
            security_bits=192,
            pq_security_bits=128,
            security_level=SecurityLevel.HIGH,
            description="ML-KEM-768 post-quantum KEM",
            public_key_size=1184,
            secret_key_size=2400,
            ciphertext_size=1088,
            shared_secret_size=32,
        )

        assert info.public_key_size == 1184
        assert info.secret_key_size == 2400
        assert info.ciphertext_size == 1088
        assert info.shared_secret_size == 32

    def test_aliases_and_references(self):
        """Test aliases and references."""
        info = AlgorithmInfo(
            name="aes-256-gcm",
            display_name="AES-256-GCM",
            category=AlgorithmCategory.CIPHER,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="AES-256 in GCM mode",
            aliases=("aes-gcm", "aes256", "aes"),
            references=("NIST SP 800-38D", "RFC 5116"),
            nist_standard="SP 800-38D",
        )

        assert "aes-gcm" in info.aliases
        assert "aes256" in info.aliases
        assert len(info.references) == 2
        assert info.nist_standard == "SP 800-38D"

    def test_immutability(self):
        """Test that AlgorithmInfo is immutable (frozen)."""
        info = AlgorithmInfo(
            name="test",
            display_name="Test",
            category=AlgorithmCategory.CIPHER,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="Test",
        )

        with pytest.raises(AttributeError):
            info.name = "modified"

    def test_negative_security_bits_validation(self):
        """Test validation of negative security bits."""
        with pytest.raises(ValueError, match="security_bits must be non-negative"):
            AlgorithmInfo(
                name="test",
                display_name="Test",
                category=AlgorithmCategory.CIPHER,
                security_bits=-1,
                pq_security_bits=128,
                security_level=SecurityLevel.STANDARD,
                description="Test",
            )


class DummyAlgorithm(AlgorithmBase):
    """Dummy algorithm for testing."""

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="dummy",
            display_name="Dummy Algorithm",
            category=AlgorithmCategory.CIPHER,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="A dummy algorithm for testing",
            aliases=("dummy-algo", "test-algo"),
        )


class UnavailableAlgorithm(AlgorithmBase):
    """Algorithm that is not available."""

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="unavailable",
            display_name="Unavailable Algorithm",
            category=AlgorithmCategory.CIPHER,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="An unavailable algorithm",
        )

    @classmethod
    def is_available(cls) -> bool:
        return False


class TestAlgorithmBase:
    """Tests for AlgorithmBase abstract class."""

    def test_info_method(self):
        """Test that info() returns correct metadata."""
        info = DummyAlgorithm.info()
        assert info.name == "dummy"
        assert info.display_name == "Dummy Algorithm"

    def test_is_available_default(self):
        """Test that is_available() defaults to True."""
        assert DummyAlgorithm.is_available() is True

    def test_is_available_override(self):
        """Test overriding is_available()."""
        assert UnavailableAlgorithm.is_available() is False

    def test_check_available_success(self):
        """Test check_available() with available algorithm."""
        DummyAlgorithm.check_available()  # Should not raise

    def test_check_available_failure(self):
        """Test check_available() with unavailable algorithm."""
        with pytest.raises(AlgorithmNotAvailableError, match="not available"):
            UnavailableAlgorithm.check_available()

    def test_get_all_names(self):
        """Test get_all_names() returns canonical name and aliases."""
        names = DummyAlgorithm.get_all_names()
        assert "dummy" in names
        assert "dummy-algo" in names
        assert "test-algo" in names
        assert len(names) == 3


class TestRegistryBase:
    """Tests for RegistryBase generic registry class."""

    def test_register_algorithm(self):
        """Test registering an algorithm."""
        registry = RegistryBase[AlgorithmBase]()
        registry.register(DummyAlgorithm)

        assert registry.exists("dummy")
        assert registry.exists("dummy-algo")  # Alias

    def test_register_duplicate_name(self):
        """Test that registering duplicate name raises error."""
        registry = RegistryBase[AlgorithmBase]()
        registry.register(DummyAlgorithm)

        with pytest.raises(ValueError, match="already registered"):
            registry.register(DummyAlgorithm)

    def test_get_algorithm(self):
        """Test getting an algorithm instance."""
        registry = RegistryBase[AlgorithmBase]()
        registry.register(DummyAlgorithm)

        algo = registry.get("dummy")
        assert isinstance(algo, DummyAlgorithm)

    def test_get_by_alias(self):
        """Test getting algorithm by alias."""
        registry = RegistryBase[AlgorithmBase]()
        registry.register(DummyAlgorithm)

        algo = registry.get("dummy-algo")
        assert isinstance(algo, DummyAlgorithm)

    def test_get_case_insensitive(self):
        """Test that get() is case-insensitive."""
        registry = RegistryBase[AlgorithmBase]()
        registry.register(DummyAlgorithm)

        algo1 = registry.get("DUMMY")
        algo2 = registry.get("Dummy")
        algo3 = registry.get("dummy")

        assert all(isinstance(a, DummyAlgorithm) for a in [algo1, algo2, algo3])

    def test_get_not_found(self):
        """Test getting non-existent algorithm."""
        registry = RegistryBase[AlgorithmBase]()
        registry.register(DummyAlgorithm)

        with pytest.raises(AlgorithmNotFoundError, match="not found"):
            registry.get("nonexistent")

    def test_get_unavailable(self):
        """Test getting unavailable algorithm."""
        registry = RegistryBase[AlgorithmBase]()
        registry.register(UnavailableAlgorithm)

        with pytest.raises(AlgorithmNotAvailableError, match="not available"):
            registry.get("unavailable")

    def test_get_class(self):
        """Test getting algorithm class without instantiation."""
        registry = RegistryBase[AlgorithmBase]()
        registry.register(DummyAlgorithm)

        algo_class = registry.get_class("dummy")
        assert algo_class is DummyAlgorithm

    def test_get_info(self):
        """Test getting algorithm info."""
        registry = RegistryBase[AlgorithmBase]()
        registry.register(DummyAlgorithm)

        info = registry.get_info("dummy")
        assert info.name == "dummy"
        assert info.display_name == "Dummy Algorithm"

    def test_exists(self):
        """Test exists() method."""
        registry = RegistryBase[AlgorithmBase]()
        registry.register(DummyAlgorithm)

        assert registry.exists("dummy")
        assert registry.exists("dummy-algo")
        assert not registry.exists("nonexistent")

    def test_is_available(self):
        """Test is_available() method."""
        registry = RegistryBase[AlgorithmBase]()
        registry.register(DummyAlgorithm)
        registry.register(UnavailableAlgorithm)

        assert registry.is_available("dummy") is True
        assert registry.is_available("unavailable") is False
        assert registry.is_available("nonexistent") is False

    def test_list_names(self):
        """Test list_names() without aliases."""
        registry = RegistryBase[AlgorithmBase]()
        registry.register(DummyAlgorithm)

        names = registry.list_names(include_aliases=False)
        assert "dummy" in names
        assert "dummy-algo" not in names

    def test_list_names_with_aliases(self):
        """Test list_names() with aliases."""
        registry = RegistryBase[AlgorithmBase]()
        registry.register(DummyAlgorithm)

        names = registry.list_names(include_aliases=True)
        assert "dummy" in names
        assert "dummy-algo" in names
        assert "test-algo" in names

    def test_list_available(self):
        """Test list_available() returns only available algorithms."""
        registry = RegistryBase[AlgorithmBase]()
        registry.register(DummyAlgorithm)
        registry.register(UnavailableAlgorithm)

        available = registry.list_available()
        assert "dummy" in available
        assert "unavailable" not in available

    def test_list_all(self):
        """Test list_all() returns all algorithms with availability."""
        registry = RegistryBase[AlgorithmBase]()
        registry.register(DummyAlgorithm)
        registry.register(UnavailableAlgorithm)

        all_algos = registry.list_all()
        assert "dummy" in all_algos
        assert "unavailable" in all_algos

        dummy_info, dummy_available = all_algos["dummy"]
        assert dummy_available is True

        unavail_info, unavail_available = all_algos["unavailable"]
        assert unavail_available is False

    def test_allowed_values(self):
        """Test allowed_values() for validation."""
        registry = RegistryBase[AlgorithmBase]()
        registry.register(DummyAlgorithm)

        allowed = registry.allowed_values()
        assert "dummy" in allowed
        assert "dummy-algo" in allowed
        assert "test-algo" in allowed

    def test_by_security_level(self):
        """Test filtering by security level."""
        registry = RegistryBase[AlgorithmBase]()
        registry.register(DummyAlgorithm)

        standard_algos = registry.by_security_level(SecurityLevel.STANDARD)
        assert len(standard_algos) == 1
        assert standard_algos[0].name == "dummy"

        high_algos = registry.by_security_level(SecurityLevel.HIGH)
        assert len(high_algos) == 0

    def test_by_category(self):
        """Test filtering by category."""
        registry = RegistryBase[AlgorithmBase]()
        registry.register(DummyAlgorithm)

        cipher_algos = registry.by_category(AlgorithmCategory.CIPHER)
        assert len(cipher_algos) == 1
        assert cipher_algos[0].name == "dummy"

        hash_algos = registry.by_category(AlgorithmCategory.HASH)
        assert len(hash_algos) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
