#!/usr/bin/env python3
"""
Base classes for the Algorithm Registry System.

This module defines the common interfaces and data structures for all
cryptographic algorithms (Cipher, Hash, KDF, KEM, Signature, Hybrid).

All code in English as per project requirements.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, ClassVar, Dict, Generic, List, Optional, Tuple, Type, TypeVar


class AlgorithmCategory(Enum):
    """Category of cryptographic algorithm."""

    CIPHER = auto()  # Symmetric encryption (AES, ChaCha20)
    HASH = auto()  # Hash functions (SHA, BLAKE)
    KDF = auto()  # Key derivation functions (Argon2, PBKDF2)
    KEM = auto()  # Key encapsulation mechanisms (ML-KEM, HQC)
    SIGNATURE = auto()  # Digital signatures (ML-DSA, FN-DSA)
    HYBRID = auto()  # Hybrid encryption (KEM + Symmetric)


class SecurityLevel(Enum):
    """Security level classification for algorithms."""

    LEGACY = "legacy"  # Not recommended, compatibility only
    STANDARD = "standard"  # Recommended for normal use
    HIGH = "high"  # Enhanced security
    PARANOID = "paranoid"  # Maximum security (e.g., PQ-256)


@dataclass(frozen=True)
class AlgorithmInfo:
    """
    Metadata about a cryptographic algorithm.

    This is a frozen dataclass for immutability and hashability.
    Supports all algorithm types with category-specific fields.

    Attributes:
        # Common identification
        name: Canonical name (e.g., 'aes-256-gcm', 'ml-kem-768')
        display_name: Human-readable name (e.g., 'AES-256-GCM', 'ML-KEM-768')
        category: Algorithm category (CIPHER, HASH, KDF, KEM, SIGNATURE, HYBRID)

        # Security classification
        security_bits: Classical security level in bits
        pq_security_bits: Post-quantum security in bits (after Grover's algorithm)
        security_level: Recommended security level classification

        # Description
        description: Brief description of the algorithm

        # Cipher-specific fields
        key_size: Key size in bytes (for symmetric ciphers)
        nonce_size: Nonce/IV size in bytes (for AEAD ciphers)
        tag_size: Authentication tag size in bytes (for AEAD ciphers)
        block_size: Block size in bytes (for block ciphers)

        # Hash-specific fields
        output_size: Hash output size in bytes
        supports_keyed_mode: Whether hash supports keyed hashing (BLAKE2, BLAKE3)
        is_xof: Whether this is an extendable output function (SHAKE, BLAKE3)

        # KEM-specific fields
        public_key_size: Public key size in bytes (for KEMs)
        secret_key_size: Secret key size in bytes (for KEMs)
        ciphertext_size: KEM ciphertext size in bytes
        shared_secret_size: Shared secret size in bytes (for KEMs)

        # Signature-specific fields
        signature_size: Signature size in bytes

        # Hybrid-specific fields
        base_kem_algorithm: Base KEM algorithm name (for hybrid modes)
        symmetric_algorithm: Symmetric cipher name (for hybrid modes)

        # Additional metadata
        aliases: Alternative names for the algorithm
        references: Standards, RFCs, papers, etc.
        nist_standard: NIST standard designation (e.g., "FIPS 203")
    """

    # Common identification
    name: str
    display_name: str
    category: AlgorithmCategory

    # Security classification
    security_bits: int
    pq_security_bits: int
    security_level: SecurityLevel

    # Description
    description: str

    # Cipher-specific (optional)
    key_size: Optional[int] = None
    nonce_size: Optional[int] = None
    tag_size: Optional[int] = None
    block_size: Optional[int] = None

    # Hash-specific (optional)
    output_size: Optional[int] = None
    supports_keyed_mode: bool = False
    is_xof: bool = False

    # KEM-specific (optional)
    public_key_size: Optional[int] = None
    secret_key_size: Optional[int] = None
    ciphertext_size: Optional[int] = None
    shared_secret_size: Optional[int] = None

    # Signature-specific (optional)
    signature_size: Optional[int] = None

    # Hybrid-specific (optional)
    base_kem_algorithm: Optional[str] = None
    symmetric_algorithm: Optional[str] = None

    # Additional metadata
    aliases: Tuple[str, ...] = field(default_factory=tuple)
    references: Tuple[str, ...] = field(default_factory=tuple)
    nist_standard: Optional[str] = None

    def __post_init__(self):
        """Validation after initialization."""
        if self.security_bits < 0:
            raise ValueError("security_bits must be non-negative")
        if self.pq_security_bits < 0:
            raise ValueError("pq_security_bits must be non-negative")


class AlgorithmError(Exception):
    """Base exception for algorithm errors."""

    pass


class AlgorithmNotAvailableError(AlgorithmError):
    """Algorithm is not available (missing dependency)."""

    pass


class AlgorithmNotFoundError(AlgorithmError):
    """Algorithm was not found in registry."""

    pass


class ValidationError(AlgorithmError):
    """Parameter validation failed."""

    pass


class AuthenticationError(AlgorithmError):
    """Authentication failed (for AEAD ciphers)."""

    pass


class AlgorithmBase(ABC):
    """
    Abstract base class for all cryptographic algorithms.

    Each concrete algorithm inherits from this class and implements
    the abstract methods. Provides common functionality for availability
    checking, validation, and metadata access.
    """

    # Class-level cache for availability check
    _available: ClassVar[Optional[bool]] = None

    @classmethod
    @abstractmethod
    def info(cls) -> AlgorithmInfo:
        """
        Returns the algorithm metadata.

        Returns:
            AlgorithmInfo with all relevant information about this algorithm
        """
        pass

    @classmethod
    def is_available(cls) -> bool:
        """
        Checks if the algorithm is available on this system.

        Can be overridden for algorithms with optional dependencies
        (e.g., Threefish, RandomX, Whirlpool).

        Returns:
            True if the algorithm can be used, False otherwise
        """
        return True

    @classmethod
    def check_available(cls) -> None:
        """
        Checks availability and raises exception if not available.

        Raises:
            AlgorithmNotAvailableError: If the algorithm is not available
        """
        if not cls.is_available():
            info = cls.info()
            raise AlgorithmNotAvailableError(
                f"Algorithm '{info.name}' is not available. " f"Install required dependencies."
            )

    @classmethod
    def get_all_names(cls) -> List[str]:
        """
        Returns all names for this algorithm (canonical + aliases).

        Returns:
            List of all valid names for this algorithm
        """
        info = cls.info()
        return [info.name] + list(info.aliases)


# Type variable for generic registry
T = TypeVar("T", bound=AlgorithmBase)


class RegistryBase(Generic[T]):
    """
    Generic base class for algorithm registries.

    Manages registration and lookup of algorithms with support for
    aliases, availability checking, and filtering.
    """

    def __init__(self):
        """Initialize empty registry."""
        self._algorithms: Dict[str, Type[T]] = {}
        self._aliases: Dict[str, str] = {}  # alias -> canonical name

    def register(self, algorithm_class: Type[T]) -> None:
        """
        Registers an algorithm class.

        Args:
            algorithm_class: The algorithm class to register

        Raises:
            ValueError: If name or alias already registered
        """
        info = algorithm_class.info()

        # Register canonical name
        if info.name in self._algorithms:
            raise ValueError(f"Algorithm '{info.name}' already registered")
        self._algorithms[info.name] = algorithm_class

        # Register aliases
        for alias in info.aliases:
            if alias in self._aliases or alias in self._algorithms:
                raise ValueError(f"Alias '{alias}' already registered")
            self._aliases[alias] = info.name

    def get(self, name: str) -> T:
        """
        Returns an instance of the requested algorithm.

        Args:
            name: Algorithm name or alias (case-insensitive)

        Returns:
            Instance of the algorithm

        Raises:
            AlgorithmNotFoundError: If algorithm not found
            AlgorithmNotAvailableError: If algorithm not available
        """
        algorithm_class = self.get_class(name)
        algorithm_class.check_available()
        return algorithm_class()

    def get_class(self, name: str) -> Type[T]:
        """
        Returns the algorithm class without instantiation.

        Args:
            name: Algorithm name or alias (case-insensitive)

        Returns:
            Algorithm class

        Raises:
            AlgorithmNotFoundError: If algorithm not found
        """
        name_lower = name.lower().strip()

        # Direct registration?
        if name_lower in self._algorithms:
            return self._algorithms[name_lower]

        # Alias?
        if name_lower in self._aliases:
            canonical = self._aliases[name_lower]
            return self._algorithms[canonical]

        # Not found
        available = self.list_names()
        raise AlgorithmNotFoundError(
            f"Algorithm '{name}' not found. Available: {', '.join(available)}"
        )

    def get_info(self, name: str) -> AlgorithmInfo:
        """
        Returns only the metadata (without availability check).

        Args:
            name: Algorithm name or alias

        Returns:
            AlgorithmInfo

        Raises:
            AlgorithmNotFoundError: If algorithm not found
        """
        return self.get_class(name).info()

    def exists(self, name: str) -> bool:
        """
        Checks if an algorithm is registered.

        Args:
            name: Algorithm name or alias

        Returns:
            True if the algorithm is registered
        """
        name_lower = name.lower().strip()
        return name_lower in self._algorithms or name_lower in self._aliases

    def is_available(self, name: str) -> bool:
        """
        Checks if an algorithm is available on this system.

        Args:
            name: Algorithm name or alias

        Returns:
            True if the algorithm is available
        """
        try:
            return self.get_class(name).is_available()
        except AlgorithmNotFoundError:
            return False

    def list_names(self, include_aliases: bool = False) -> List[str]:
        """
        Lists all registered algorithm names.

        Args:
            include_aliases: Whether to include aliases in the list

        Returns:
            Sorted list of algorithm names
        """
        names = list(self._algorithms.keys())
        if include_aliases:
            names.extend(self._aliases.keys())
        return sorted(names)

    def list_available(self) -> Dict[str, AlgorithmInfo]:
        """
        Lists all available algorithms with their metadata.

        Returns:
            Dictionary mapping algorithm name to AlgorithmInfo
        """
        result = {}
        for name, algo_class in self._algorithms.items():
            if algo_class.is_available():
                result[name] = algo_class.info()
        return result

    def list_all(self) -> Dict[str, Tuple[AlgorithmInfo, bool]]:
        """
        Lists all algorithms including unavailable ones.

        Returns:
            Dictionary mapping name to (AlgorithmInfo, is_available)
        """
        result = {}
        for name, algo_class in self._algorithms.items():
            result[name] = (algo_class.info(), algo_class.is_available())
        return result

    def allowed_values(self) -> List[str]:
        """
        Returns list of all allowed values for validation.

        Useful for telemetry filters and configuration validation.

        Returns:
            List of all names and aliases
        """
        return self.list_names(include_aliases=True)

    def by_security_level(
        self, level: SecurityLevel, only_available: bool = True
    ) -> List[AlgorithmInfo]:
        """
        Filters algorithms by security level.

        Args:
            level: Desired security level
            only_available: Whether to return only available algorithms

        Returns:
            List of AlgorithmInfo matching the criteria
        """
        result = []
        for name, algo_class in self._algorithms.items():
            info = algo_class.info()
            if info.security_level == level:
                if only_available and not algo_class.is_available():
                    continue
                result.append(info)
        return result

    def by_category(
        self, category: AlgorithmCategory, only_available: bool = True
    ) -> List[AlgorithmInfo]:
        """
        Filters algorithms by category.

        Args:
            category: Desired algorithm category
            only_available: Whether to return only available algorithms

        Returns:
            List of AlgorithmInfo matching the criteria
        """
        result = []
        for name, algo_class in self._algorithms.items():
            info = algo_class.info()
            if info.category == category:
                if only_available and not algo_class.is_available():
                    continue
                result.append(info)
        return result
