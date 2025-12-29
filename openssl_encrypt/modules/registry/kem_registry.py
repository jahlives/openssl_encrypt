#!/usr/bin/env python3
"""
KEM (Key Encapsulation Mechanism) Registry.

Unified management of post-quantum KEMs with support for:
- ML-KEM (NIST FIPS 203 standard, formerly Kyber)
- HQC (NIST Round 4 candidate)

All code in English as per project requirements.
"""

from abc import abstractmethod
from dataclasses import dataclass
from typing import Optional, Tuple, Union

from .base import (
    AlgorithmBase,
    AlgorithmCategory,
    AlgorithmInfo,
    AlgorithmNotAvailableError,
    RegistryBase,
    SecurityLevel,
)

# Import secure memory handling
try:
    from ..secure_memory import SecureBytes, secure_memzero

    SECURE_MEMORY_AVAILABLE = True
except ImportError:
    SecureBytes = bytes
    SECURE_MEMORY_AVAILABLE = False

    def secure_memzero(data):
        """Fallback no-op."""
        pass


# Import existing PQC implementation
try:
    # Import oqs directly to avoid incorrect mapping in PQEncapsulator
    import oqs

    from ..pqc_liboqs import LIBOQS_AVAILABLE, PQAlgorithm, check_liboqs_support
except ImportError:
    LIBOQS_AVAILABLE = False
    PQAlgorithm = None
    check_liboqs_support = None
    oqs = None


class KEMBase(AlgorithmBase):
    """
    Base class for Key Encapsulation Mechanisms (KEMs).

    KEMs are used in hybrid post-quantum encryption to encapsulate
    a shared secret that is then used with symmetric encryption.
    """

    @abstractmethod
    def generate_keypair(self) -> Tuple[bytes, "SecureBytes"]:
        """
        Generate a KEM keypair.

        Returns:
            tuple: (public_key, secret_key)
                - public_key: Public key (bytes - meant to be shared)
                - secret_key: Secret key (SecureBytes - MUST be zeroed after use)

        Security:
            - Returns secret key as SecureBytes for automatic cleanup
            - Caller MUST explicitly zero the secret key after use
        """
        pass

    @abstractmethod
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, "SecureBytes"]:
        """
        Encapsulate a shared secret using a public key.

        Args:
            public_key: The recipient's public key

        Returns:
            tuple: (ciphertext, shared_secret)
                - ciphertext: Encapsulated shared secret to send (bytes)
                - shared_secret: The shared secret (SecureBytes - MUST be zeroed after use)

        Security:
            - Returns shared secret as SecureBytes for automatic cleanup
            - Caller MUST explicitly zero the shared secret after use
        """
        pass

    @abstractmethod
    def decapsulate(
        self, ciphertext: bytes, secret_key: Union[bytes, "SecureBytes"]
    ) -> "SecureBytes":
        """
        Decapsulate the shared secret using the secret key.

        Args:
            ciphertext: The encapsulated shared secret
            secret_key: The recipient's secret key (bytes or SecureBytes)

        Returns:
            SecureBytes: The decapsulated shared secret (MUST be zeroed after use)

        Security:
            - Accepts secret key as bytes or SecureBytes
            - Returns shared secret as SecureBytes for automatic cleanup
            - Secret key copy is zeroed after use
        """
        pass

    def get_public_key_size(self) -> int:
        """Get the KEM public key size in bytes."""
        info = self.info()
        return info.public_key_size or 0

    def get_secret_key_size(self) -> int:
        """Get the KEM secret key size in bytes."""
        info = self.info()
        return info.secret_key_size or 0

    def get_ciphertext_size(self) -> int:
        """Get the KEM ciphertext size in bytes."""
        info = self.info()
        return info.ciphertext_size or 0

    def get_shared_secret_size(self) -> int:
        """Get the shared secret size in bytes."""
        info = self.info()
        return info.shared_secret_size or 0


# ============================================================================
# ML-KEM (NIST FIPS 203) - formerly Kyber
# ============================================================================


class MLKEM512(KEMBase):
    """
    ML-KEM-512 (NIST FIPS 203).

    Security Level 1 (128-bit classical, 161-bit quantum).
    Smallest keys and ciphertext, fastest performance.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="ml-kem-512",
            display_name="ML-KEM-512 (NIST FIPS 203)",
            category=AlgorithmCategory.KEM,
            security_bits=128,
            pq_security_bits=161,
            security_level=SecurityLevel.STANDARD,
            description="NIST standard post-quantum KEM (Level 1)",
            nist_standard="FIPS 203",
            public_key_size=800,
            secret_key_size=1632,
            ciphertext_size=768,
            shared_secret_size=32,
            aliases=("ml_kem_512", "mlkem512", "mlkem-512", "kyber512", "kyber-512"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "ML-KEM-512 requires liboqs-python. Install with: pip install liboqs"
            )
        # Use oqs library directly (PQEncapsulator has incorrect name mappings)
        self._kem = oqs.KeyEncapsulation("ML-KEM-512")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._kem.generate_keypair()
        secret_key = self._kem.export_secret_key()
        return public_key, SecureBytes(secret_key)

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, SecureBytes]:
        ciphertext, shared_secret = self._kem.encap_secret(public_key)
        return ciphertext, SecureBytes(shared_secret)

    def decapsulate(self, ciphertext: bytes, secret_key: Union[bytes, SecureBytes]) -> SecureBytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            # Load secret key and decapsulate
            kem = oqs.KeyEncapsulation("ML-KEM-512", secret_key_bytes)
            shared_secret = kem.decap_secret(ciphertext)
            return SecureBytes(shared_secret)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))


class MLKEM768(KEMBase):
    """
    ML-KEM-768 (NIST FIPS 203).

    Security Level 3 (192-bit classical, 234-bit quantum).
    Recommended for most applications.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="ml-kem-768",
            display_name="ML-KEM-768 (NIST FIPS 203)",
            category=AlgorithmCategory.KEM,
            security_bits=192,
            pq_security_bits=234,
            security_level=SecurityLevel.HIGH,
            description="NIST standard post-quantum KEM (Level 3, recommended)",
            nist_standard="FIPS 203",
            public_key_size=1184,
            secret_key_size=2400,
            ciphertext_size=1088,
            shared_secret_size=32,
            aliases=("ml_kem_768", "mlkem768", "mlkem-768", "kyber768", "kyber-768"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "ML-KEM-768 requires liboqs-python. Install with: pip install liboqs"
            )
        self._kem = oqs.KeyEncapsulation("ML-KEM-768")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._kem.generate_keypair()
        secret_key = self._kem.export_secret_key()
        return public_key, SecureBytes(secret_key)

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, SecureBytes]:
        ciphertext, shared_secret = self._kem.encap_secret(public_key)
        return ciphertext, SecureBytes(shared_secret)

    def decapsulate(self, ciphertext: bytes, secret_key: Union[bytes, SecureBytes]) -> SecureBytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            # Load secret key and decapsulate
            kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key_bytes)
            shared_secret = kem.decap_secret(ciphertext)
            return SecureBytes(shared_secret)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))


class MLKEM1024(KEMBase):
    """
    ML-KEM-1024 (NIST FIPS 203).

    Security Level 5 (256-bit classical, 309-bit quantum).
    Highest security, larger keys and ciphertext.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="ml-kem-1024",
            display_name="ML-KEM-1024 (NIST FIPS 203)",
            category=AlgorithmCategory.KEM,
            security_bits=256,
            pq_security_bits=309,
            security_level=SecurityLevel.PARANOID,
            description="NIST standard post-quantum KEM (Level 5)",
            nist_standard="FIPS 203",
            public_key_size=1568,
            secret_key_size=3168,
            ciphertext_size=1568,
            shared_secret_size=32,
            aliases=("ml_kem_1024", "mlkem1024", "mlkem-1024", "kyber1024", "kyber-1024"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "ML-KEM-1024 requires liboqs-python. Install with: pip install liboqs"
            )
        self._kem = oqs.KeyEncapsulation("ML-KEM-1024")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._kem.generate_keypair()
        secret_key = self._kem.export_secret_key()
        return public_key, SecureBytes(secret_key)

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, SecureBytes]:
        ciphertext, shared_secret = self._kem.encap_secret(public_key)
        return ciphertext, SecureBytes(shared_secret)

    def decapsulate(self, ciphertext: bytes, secret_key: Union[bytes, SecureBytes]) -> SecureBytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            # Load secret key and decapsulate
            kem = oqs.KeyEncapsulation("ML-KEM-1024", secret_key_bytes)
            shared_secret = kem.decap_secret(ciphertext)
            return SecureBytes(shared_secret)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))


# ============================================================================
# HQC (NIST Round 4 Candidate)
# ============================================================================


class HQC128(KEMBase):
    """
    HQC-128 (Hamming Quasi-Cyclic).

    Security Level 1 (128-bit classical).
    Code-based post-quantum KEM with small keys.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="hqc-128",
            display_name="HQC-128",
            category=AlgorithmCategory.KEM,
            security_bits=128,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="Code-based post-quantum KEM (Level 1)",
            nist_standard="NIST Round 4 candidate",
            public_key_size=2249,
            secret_key_size=2289,
            ciphertext_size=4481,
            shared_secret_size=64,
            aliases=("hqc_128", "hqc128"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "HQC-128 requires liboqs-python. Install with: pip install liboqs"
            )
        self._kem = oqs.KeyEncapsulation("HQC-128")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._kem.generate_keypair()
        secret_key = self._kem.export_secret_key()
        return public_key, SecureBytes(secret_key)

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, SecureBytes]:
        ciphertext, shared_secret = self._kem.encap_secret(public_key)
        return ciphertext, SecureBytes(shared_secret)

    def decapsulate(self, ciphertext: bytes, secret_key: Union[bytes, SecureBytes]) -> SecureBytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            # Load secret key and decapsulate
            kem = oqs.KeyEncapsulation("HQC-128", secret_key_bytes)
            shared_secret = kem.decap_secret(ciphertext)
            return SecureBytes(shared_secret)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))


class HQC192(KEMBase):
    """
    HQC-192 (Hamming Quasi-Cyclic).

    Security Level 3 (192-bit classical).
    Code-based post-quantum KEM.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="hqc-192",
            display_name="HQC-192",
            category=AlgorithmCategory.KEM,
            security_bits=192,
            pq_security_bits=192,
            security_level=SecurityLevel.HIGH,
            description="Code-based post-quantum KEM (Level 3)",
            nist_standard="NIST Round 4 candidate",
            public_key_size=4522,
            secret_key_size=4562,
            ciphertext_size=9026,
            shared_secret_size=64,
            aliases=("hqc_192", "hqc192"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "HQC-192 requires liboqs-python. Install with: pip install liboqs"
            )
        self._kem = oqs.KeyEncapsulation("HQC-192")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._kem.generate_keypair()
        secret_key = self._kem.export_secret_key()
        return public_key, SecureBytes(secret_key)

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, SecureBytes]:
        ciphertext, shared_secret = self._kem.encap_secret(public_key)
        return ciphertext, SecureBytes(shared_secret)

    def decapsulate(self, ciphertext: bytes, secret_key: Union[bytes, SecureBytes]) -> SecureBytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            # Load secret key and decapsulate
            kem = oqs.KeyEncapsulation("HQC-192", secret_key_bytes)
            shared_secret = kem.decap_secret(ciphertext)
            return SecureBytes(shared_secret)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))


class HQC256(KEMBase):
    """
    HQC-256 (Hamming Quasi-Cyclic).

    Security Level 5 (256-bit classical).
    Code-based post-quantum KEM with highest security.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="hqc-256",
            display_name="HQC-256",
            category=AlgorithmCategory.KEM,
            security_bits=256,
            pq_security_bits=256,
            security_level=SecurityLevel.PARANOID,
            description="Code-based post-quantum KEM (Level 5)",
            nist_standard="NIST Round 4 candidate",
            public_key_size=7245,
            secret_key_size=7285,
            ciphertext_size=14469,
            shared_secret_size=64,
            aliases=("hqc_256", "hqc256"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "HQC-256 requires liboqs-python. Install with: pip install liboqs"
            )
        self._kem = oqs.KeyEncapsulation("HQC-256")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._kem.generate_keypair()
        secret_key = self._kem.export_secret_key()
        return public_key, SecureBytes(secret_key)

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, SecureBytes]:
        ciphertext, shared_secret = self._kem.encap_secret(public_key)
        return ciphertext, SecureBytes(shared_secret)

    def decapsulate(self, ciphertext: bytes, secret_key: Union[bytes, SecureBytes]) -> SecureBytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            # Load secret key and decapsulate
            kem = oqs.KeyEncapsulation("HQC-256", secret_key_bytes)
            shared_secret = kem.decap_secret(ciphertext)
            return SecureBytes(shared_secret)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))


# ============================================================================
# KEM Registry
# ============================================================================


class KEMRegistry(RegistryBase[KEMBase]):
    """
    Registry for Key Encapsulation Mechanisms (KEMs).

    Manages post-quantum KEMs including ML-KEM and HQC.

    Usage:
        registry = KEMRegistry.default()
        kem = registry.get("ml-kem-768")
        public_key, secret_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encapsulate(public_key)
    """

    _instance: Optional["KEMRegistry"] = None

    def __init__(self):
        super().__init__()
        self._register_all()

    def _register_all(self):
        """Register all KEM implementations."""
        # ML-KEM (NIST FIPS 203)
        self.register(MLKEM512)
        self.register(MLKEM768)
        self.register(MLKEM1024)

        # HQC (NIST Round 4)
        self.register(HQC128)
        self.register(HQC192)
        self.register(HQC256)

    @classmethod
    def default(cls) -> "KEMRegistry":
        """Get the default singleton registry instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance


# Convenience function
def get_kem(name: str) -> KEMBase:
    """
    Get a KEM instance by name.

    Args:
        name: KEM algorithm name (e.g., "ml-kem-768", "hqc-256")

    Returns:
        KEMBase: A KEM instance

    Example:
        kem = get_kem("ml-kem-768")
        public_key, secret_key = kem.generate_keypair()
    """
    return KEMRegistry.default().get(name)
