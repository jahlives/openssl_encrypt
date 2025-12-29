#!/usr/bin/env python3
"""
Post-Quantum Signature Registry.

Unified management of post-quantum digital signatures with support for:
- ML-DSA (NIST FIPS 204, formerly Dilithium)
- SLH-DSA (NIST FIPS 205, formerly SPHINCS+)
- FN-DSA (NIST FIPS 206 forthcoming, formerly Falcon)
- MAYO (NIST Round 2 candidate)
- CROSS (NIST Round 2 candidate)

All code in English as per project requirements.
"""

from abc import abstractmethod
from typing import Optional, Tuple, Union

from .base import (
    AlgorithmBase,
    AlgorithmCategory,
    AlgorithmInfo,
    AlgorithmNotAvailableError,
    RegistryBase,
    SecurityLevel,
)

# Import SecureBytes for secure memory handling of secret keys
try:
    from ..secure_memory import SecureBytes, secure_memzero

    SECURE_MEMORY_AVAILABLE = True
except ImportError:
    # Fallback if secure_memory module not available
    SecureBytes = bytes
    SECURE_MEMORY_AVAILABLE = False

    def secure_memzero(data):
        """Fallback no-op if secure_memory not available."""
        pass


# Import existing PQC implementation
try:
    # Import oqs directly to avoid incorrect mapping in PQSigner
    import oqs

    from ..pqc_liboqs import LIBOQS_AVAILABLE, PQAlgorithm, check_liboqs_support
except ImportError:
    LIBOQS_AVAILABLE = False
    PQAlgorithm = None
    check_liboqs_support = None
    oqs = None


class SignatureBase(AlgorithmBase):
    """
    Base class for post-quantum digital signature algorithms.

    Provides sign and verify operations for post-quantum security.
    """

    @abstractmethod
    def generate_keypair(self) -> Tuple[bytes, "SecureBytes"]:
        """
        Generate a signature keypair.

        Returns:
            tuple: (public_key, secret_key)
                - public_key: Public key (bytes - meant to be shared)
                - secret_key: Secret key (SecureBytes - MUST be zeroed after use)

        Security:
            - Secret key is returned as SecureBytes for automatic cleanup
            - Caller must ensure secret key is zeroed when no longer needed
        """
        pass

    @abstractmethod
    def sign(self, message: bytes, secret_key: Union[bytes, "SecureBytes"]) -> bytes:
        """
        Sign a message using the secret key.

        Args:
            message: The message to sign
            secret_key: The signer's secret key (bytes or SecureBytes)

        Returns:
            bytes: The signature

        Security:
            - If secret_key is SecureBytes, a temporary copy is made and zeroed
            - The original secret_key is never modified
        """
        pass

    @abstractmethod
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a signature using the public key.

        Args:
            message: The original message
            signature: The signature to verify
            public_key: The signer's public key

        Returns:
            bool: True if signature is valid, False otherwise
        """
        pass

    def get_public_key_size(self) -> int:
        """Get the signature public key size in bytes."""
        info = self.info()
        return info.public_key_size or 0

    def get_secret_key_size(self) -> int:
        """Get the signature secret key size in bytes."""
        info = self.info()
        return info.secret_key_size or 0

    def get_signature_size(self) -> int:
        """Get the signature size in bytes."""
        info = self.info()
        return info.signature_size or 0


# ============================================================================
# ML-DSA (NIST FIPS 204) - formerly Dilithium
# ============================================================================


class MLDSA44(SignatureBase):
    """
    ML-DSA-44 (NIST FIPS 204).

    Security Level 1 (128-bit classical).
    Smallest keys and signatures, fastest performance.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="ml-dsa-44",
            display_name="ML-DSA-44 (NIST FIPS 204)",
            category=AlgorithmCategory.SIGNATURE,
            security_bits=128,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="NIST standard post-quantum signature (Level 1)",
            nist_standard="FIPS 204",
            public_key_size=1312,
            secret_key_size=2560,
            signature_size=2420,
            aliases=("ml_dsa_44", "mldsa44", "mldsa-44", "dilithium2"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "ML-DSA-44 requires liboqs-python. Install with: pip install liboqs"
            )
        # Use oqs library directly
        self._signer = oqs.Signature("ML-DSA-44")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._signer.generate_keypair()
        secret_key = self._signer.export_secret_key()
        # Wrap secret key in SecureBytes for automatic cleanup
        return public_key, SecureBytes(secret_key)

    def sign(self, message: bytes, secret_key: Union[bytes, SecureBytes]) -> bytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            signer = oqs.Signature("ML-DSA-44", secret_key_bytes)
            return signer.sign(message)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return self._signer.verify(message, signature, public_key)


class MLDSA65(SignatureBase):
    """
    ML-DSA-65 (NIST FIPS 204).

    Security Level 3 (192-bit classical).
    Recommended for most applications.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="ml-dsa-65",
            display_name="ML-DSA-65 (NIST FIPS 204)",
            category=AlgorithmCategory.SIGNATURE,
            security_bits=192,
            pq_security_bits=192,
            security_level=SecurityLevel.HIGH,
            description="NIST standard post-quantum signature (Level 3, recommended)",
            nist_standard="FIPS 204",
            public_key_size=1952,
            secret_key_size=4032,
            signature_size=3309,
            aliases=("ml_dsa_65", "mldsa65", "mldsa-65", "dilithium3"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "ML-DSA-65 requires liboqs-python. Install with: pip install liboqs"
            )
        self._signer = oqs.Signature("ML-DSA-65")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._signer.generate_keypair()
        secret_key = self._signer.export_secret_key()
        # Wrap secret key in SecureBytes for automatic cleanup
        return public_key, SecureBytes(secret_key)

    def sign(self, message: bytes, secret_key: Union[bytes, SecureBytes]) -> bytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            signer = oqs.Signature("ML-DSA-65", secret_key_bytes)
            return signer.sign(message)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return self._signer.verify(message, signature, public_key)


class MLDSA87(SignatureBase):
    """
    ML-DSA-87 (NIST FIPS 204).

    Security Level 5 (256-bit classical).
    Highest security, larger keys and signatures.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="ml-dsa-87",
            display_name="ML-DSA-87 (NIST FIPS 204)",
            category=AlgorithmCategory.SIGNATURE,
            security_bits=256,
            pq_security_bits=256,
            security_level=SecurityLevel.PARANOID,
            description="NIST standard post-quantum signature (Level 5)",
            nist_standard="FIPS 204",
            public_key_size=2592,
            secret_key_size=4896,
            signature_size=4627,
            aliases=("ml_dsa_87", "mldsa87", "mldsa-87", "dilithium5"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "ML-DSA-87 requires liboqs-python. Install with: pip install liboqs"
            )
        self._signer = oqs.Signature("ML-DSA-87")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._signer.generate_keypair()
        secret_key = self._signer.export_secret_key()
        # Wrap secret key in SecureBytes for automatic cleanup
        return public_key, SecureBytes(secret_key)

    def sign(self, message: bytes, secret_key: Union[bytes, SecureBytes]) -> bytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            signer = oqs.Signature("ML-DSA-87", secret_key_bytes)
            return signer.sign(message)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return self._signer.verify(message, signature, public_key)


# ============================================================================
# SLH-DSA (NIST FIPS 205) - formerly SPHINCS+
# ============================================================================


class SLHDSASHA2128F(SignatureBase):
    """
    SLH-DSA-SHA2-128F (NIST FIPS 205).

    Security Level 1 (128-bit classical).
    Stateless hash-based signature (fast variant).
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="slh-dsa-sha2-128f",
            display_name="SLH-DSA-SHA2-128F (NIST FIPS 205)",
            category=AlgorithmCategory.SIGNATURE,
            security_bits=128,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="Stateless hash-based signature (Level 1, fast)",
            nist_standard="FIPS 205",
            public_key_size=32,
            secret_key_size=64,
            signature_size=17088,
            aliases=("slh_dsa_sha2_128f", "slhdsasha2-128f", "sphincs-sha2-128f"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "SLH-DSA-SHA2-128F requires liboqs-python. Install with: pip install liboqs"
            )
        self._signer = oqs.Signature("SPHINCS+-SHA2-128f-simple")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._signer.generate_keypair()
        secret_key = self._signer.export_secret_key()
        # Wrap secret key in SecureBytes for automatic cleanup
        return public_key, SecureBytes(secret_key)

    def sign(self, message: bytes, secret_key: Union[bytes, SecureBytes]) -> bytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            signer = oqs.Signature("SPHINCS+-SHA2-128f-simple", secret_key_bytes)
            return signer.sign(message)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return self._signer.verify(message, signature, public_key)


class SLHDSASHA2192F(SignatureBase):
    """
    SLH-DSA-SHA2-192F (NIST FIPS 205).

    Security Level 3 (192-bit classical).
    Stateless hash-based signature (fast variant).
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="slh-dsa-sha2-192f",
            display_name="SLH-DSA-SHA2-192F (NIST FIPS 205)",
            category=AlgorithmCategory.SIGNATURE,
            security_bits=192,
            pq_security_bits=192,
            security_level=SecurityLevel.HIGH,
            description="Stateless hash-based signature (Level 3, fast)",
            nist_standard="FIPS 205",
            public_key_size=48,
            secret_key_size=96,
            signature_size=35664,
            aliases=("slh_dsa_sha2_192f", "slhdsasha2-192f", "sphincs-sha2-192f"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "SLH-DSA-SHA2-192F requires liboqs-python. Install with: pip install liboqs"
            )
        self._signer = oqs.Signature("SPHINCS+-SHA2-192f-simple")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._signer.generate_keypair()
        secret_key = self._signer.export_secret_key()
        # Wrap secret key in SecureBytes for automatic cleanup
        return public_key, SecureBytes(secret_key)

    def sign(self, message: bytes, secret_key: Union[bytes, SecureBytes]) -> bytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            signer = oqs.Signature("SPHINCS+-SHA2-192f-simple", secret_key_bytes)
            return signer.sign(message)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return self._signer.verify(message, signature, public_key)


class SLHDSASHA2256F(SignatureBase):
    """
    SLH-DSA-SHA2-256F (NIST FIPS 205).

    Security Level 5 (256-bit classical).
    Stateless hash-based signature (fast variant).
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="slh-dsa-sha2-256f",
            display_name="SLH-DSA-SHA2-256F (NIST FIPS 205)",
            category=AlgorithmCategory.SIGNATURE,
            security_bits=256,
            pq_security_bits=256,
            security_level=SecurityLevel.PARANOID,
            description="Stateless hash-based signature (Level 5, fast)",
            nist_standard="FIPS 205",
            public_key_size=64,
            secret_key_size=128,
            signature_size=49856,
            aliases=("slh_dsa_sha2_256f", "slhdsasha2-256f", "sphincs-sha2-256f"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "SLH-DSA-SHA2-256F requires liboqs-python. Install with: pip install liboqs"
            )
        self._signer = oqs.Signature("SPHINCS+-SHA2-256f-simple")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._signer.generate_keypair()
        secret_key = self._signer.export_secret_key()
        # Wrap secret key in SecureBytes for automatic cleanup
        return public_key, SecureBytes(secret_key)

    def sign(self, message: bytes, secret_key: Union[bytes, SecureBytes]) -> bytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            signer = oqs.Signature("SPHINCS+-SHA2-256f-simple", secret_key_bytes)
            return signer.sign(message)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return self._signer.verify(message, signature, public_key)


# ============================================================================
# FN-DSA (NIST FIPS 206 forthcoming) - formerly Falcon
# ============================================================================


class FNDSA512(SignatureBase):
    """
    FN-DSA-512 (NIST FIPS 206 forthcoming).

    Security Level 1 (128-bit classical).
    Lattice-based signature with smallest signature size.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="fn-dsa-512",
            display_name="FN-DSA-512 (NIST FIPS 206)",
            category=AlgorithmCategory.SIGNATURE,
            security_bits=128,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="Lattice-based signature with compact signatures (Level 1)",
            nist_standard="FIPS 206 (forthcoming)",
            public_key_size=897,
            secret_key_size=1281,
            signature_size=666,
            aliases=("fn_dsa_512", "fndsa512", "fndsa-512", "falcon512", "falcon-512"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "FN-DSA-512 requires liboqs-python. Install with: pip install liboqs"
            )
        self._signer = oqs.Signature("Falcon-512")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._signer.generate_keypair()
        secret_key = self._signer.export_secret_key()
        # Wrap secret key in SecureBytes for automatic cleanup
        return public_key, SecureBytes(secret_key)

    def sign(self, message: bytes, secret_key: Union[bytes, SecureBytes]) -> bytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            signer = oqs.Signature("Falcon-512", secret_key_bytes)
            return signer.sign(message)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return self._signer.verify(message, signature, public_key)


class FNDSA1024(SignatureBase):
    """
    FN-DSA-1024 (NIST FIPS 206 forthcoming).

    Security Level 5 (256-bit classical).
    Lattice-based signature with compact signatures.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="fn-dsa-1024",
            display_name="FN-DSA-1024 (NIST FIPS 206)",
            category=AlgorithmCategory.SIGNATURE,
            security_bits=256,
            pq_security_bits=256,
            security_level=SecurityLevel.PARANOID,
            description="Lattice-based signature with compact signatures (Level 5)",
            nist_standard="FIPS 206 (forthcoming)",
            public_key_size=1793,
            secret_key_size=2305,
            signature_size=1280,
            aliases=("fn_dsa_1024", "fndsa1024", "fndsa-1024", "falcon1024", "falcon-1024"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "FN-DSA-1024 requires liboqs-python. Install with: pip install liboqs"
            )
        self._signer = oqs.Signature("Falcon-1024")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._signer.generate_keypair()
        secret_key = self._signer.export_secret_key()
        # Wrap secret key in SecureBytes for automatic cleanup
        return public_key, SecureBytes(secret_key)

    def sign(self, message: bytes, secret_key: Union[bytes, SecureBytes]) -> bytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            signer = oqs.Signature("Falcon-1024", secret_key_bytes)
            return signer.sign(message)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return self._signer.verify(message, signature, public_key)


# ============================================================================
# MAYO (NIST Round 2 Candidate)
# ============================================================================


class MAYO1(SignatureBase):
    """
    MAYO-1 (NIST Round 2).

    Security Level 1 (128-bit classical).
    Multivariate Oil-and-Vinegar signature scheme.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="mayo-1",
            display_name="MAYO-1",
            category=AlgorithmCategory.SIGNATURE,
            security_bits=128,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="Multivariate signature scheme (Level 1)",
            nist_standard="NIST Round 2 candidate",
            public_key_size=1168,
            secret_key_size=24,
            signature_size=321,
            aliases=("mayo_1", "mayo1"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "MAYO-1 requires liboqs-python. Install with: pip install liboqs"
            )
        self._signer = oqs.Signature("MAYO-1")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._signer.generate_keypair()
        secret_key = self._signer.export_secret_key()
        # Wrap secret key in SecureBytes for automatic cleanup
        return public_key, SecureBytes(secret_key)

    def sign(self, message: bytes, secret_key: Union[bytes, SecureBytes]) -> bytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            signer = oqs.Signature("MAYO-1", secret_key_bytes)
            return signer.sign(message)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return self._signer.verify(message, signature, public_key)


class MAYO3(SignatureBase):
    """
    MAYO-3 (NIST Round 2).

    Security Level 3 (192-bit classical).
    Multivariate Oil-and-Vinegar signature scheme.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="mayo-3",
            display_name="MAYO-3",
            category=AlgorithmCategory.SIGNATURE,
            security_bits=192,
            pq_security_bits=192,
            security_level=SecurityLevel.HIGH,
            description="Multivariate signature scheme (Level 3)",
            nist_standard="NIST Round 2 candidate",
            public_key_size=2656,
            secret_key_size=32,
            signature_size=577,
            aliases=("mayo_3", "mayo3"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "MAYO-3 requires liboqs-python. Install with: pip install liboqs"
            )
        self._signer = oqs.Signature("MAYO-3")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._signer.generate_keypair()
        secret_key = self._signer.export_secret_key()
        # Wrap secret key in SecureBytes for automatic cleanup
        return public_key, SecureBytes(secret_key)

    def sign(self, message: bytes, secret_key: Union[bytes, SecureBytes]) -> bytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            signer = oqs.Signature("MAYO-3", secret_key_bytes)
            return signer.sign(message)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return self._signer.verify(message, signature, public_key)


class MAYO5(SignatureBase):
    """
    MAYO-5 (NIST Round 2).

    Security Level 5 (256-bit classical).
    Multivariate Oil-and-Vinegar signature scheme.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="mayo-5",
            display_name="MAYO-5",
            category=AlgorithmCategory.SIGNATURE,
            security_bits=256,
            pq_security_bits=256,
            security_level=SecurityLevel.PARANOID,
            description="Multivariate signature scheme (Level 5)",
            nist_standard="NIST Round 2 candidate",
            public_key_size=5488,
            secret_key_size=40,
            signature_size=838,
            aliases=("mayo_5", "mayo5"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "MAYO-5 requires liboqs-python. Install with: pip install liboqs"
            )
        self._signer = oqs.Signature("MAYO-5")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._signer.generate_keypair()
        secret_key = self._signer.export_secret_key()
        # Wrap secret key in SecureBytes for automatic cleanup
        return public_key, SecureBytes(secret_key)

    def sign(self, message: bytes, secret_key: Union[bytes, SecureBytes]) -> bytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            signer = oqs.Signature("MAYO-5", secret_key_bytes)
            return signer.sign(message)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return self._signer.verify(message, signature, public_key)


# ============================================================================
# CROSS (NIST Round 2 Candidate)
# ============================================================================


class CROSS128(SignatureBase):
    """
    CROSS-128 (NIST Round 2).

    Security Level 1 (128-bit classical).
    Codes and Restricted Objects Signature Scheme.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="cross-128",
            display_name="CROSS-128",
            category=AlgorithmCategory.SIGNATURE,
            security_bits=128,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="Code-based signature scheme (Level 1)",
            nist_standard="NIST Round 2 candidate",
            public_key_size=77,
            secret_key_size=32,
            signature_size=12852,
            aliases=("cross_128", "cross128"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "CROSS-128 requires liboqs-python. Install with: pip install liboqs"
            )
        self._signer = oqs.Signature("cross-rsdp-128-balanced")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._signer.generate_keypair()
        secret_key = self._signer.export_secret_key()
        # Wrap secret key in SecureBytes for automatic cleanup
        return public_key, SecureBytes(secret_key)

    def sign(self, message: bytes, secret_key: Union[bytes, SecureBytes]) -> bytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            signer = oqs.Signature("cross-rsdp-128-balanced", secret_key_bytes)
            return signer.sign(message)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return self._signer.verify(message, signature, public_key)


class CROSS192(SignatureBase):
    """
    CROSS-192 (NIST Round 2).

    Security Level 3 (192-bit classical).
    Codes and Restricted Objects Signature Scheme.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="cross-192",
            display_name="CROSS-192",
            category=AlgorithmCategory.SIGNATURE,
            security_bits=192,
            pq_security_bits=192,
            security_level=SecurityLevel.HIGH,
            description="Code-based signature scheme (Level 3)",
            nist_standard="NIST Round 2 candidate",
            public_key_size=115,
            secret_key_size=48,
            signature_size=28036,
            aliases=("cross_192", "cross192"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "CROSS-192 requires liboqs-python. Install with: pip install liboqs"
            )
        self._signer = oqs.Signature("cross-rsdp-192-balanced")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._signer.generate_keypair()
        secret_key = self._signer.export_secret_key()
        # Wrap secret key in SecureBytes for automatic cleanup
        return public_key, SecureBytes(secret_key)

    def sign(self, message: bytes, secret_key: Union[bytes, SecureBytes]) -> bytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            signer = oqs.Signature("cross-rsdp-192-balanced", secret_key_bytes)
            return signer.sign(message)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return self._signer.verify(message, signature, public_key)


class CROSS256(SignatureBase):
    """
    CROSS-256 (NIST Round 2).

    Security Level 5 (256-bit classical).
    Codes and Restricted Objects Signature Scheme.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="cross-256",
            display_name="CROSS-256",
            category=AlgorithmCategory.SIGNATURE,
            security_bits=256,
            pq_security_bits=256,
            security_level=SecurityLevel.PARANOID,
            description="Code-based signature scheme (Level 5)",
            nist_standard="NIST Round 2 candidate",
            public_key_size=153,
            secret_key_size=64,
            signature_size=51044,
            aliases=("cross_256", "cross256"),
        )

    @classmethod
    def is_available(cls) -> bool:
        return LIBOQS_AVAILABLE

    def __init__(self):
        if not self.is_available():
            raise AlgorithmNotAvailableError(
                "CROSS-256 requires liboqs-python. Install with: pip install liboqs"
            )
        self._signer = oqs.Signature("cross-rsdp-256-balanced")

    def generate_keypair(self) -> Tuple[bytes, SecureBytes]:
        public_key = self._signer.generate_keypair()
        secret_key = self._signer.export_secret_key()
        # Wrap secret key in SecureBytes for automatic cleanup
        return public_key, SecureBytes(secret_key)

    def sign(self, message: bytes, secret_key: Union[bytes, SecureBytes]) -> bytes:
        # Convert SecureBytes to bytes for library
        secret_key_bytes = bytes(secret_key) if isinstance(secret_key, SecureBytes) else secret_key

        try:
            signer = oqs.Signature("cross-rsdp-256-balanced", secret_key_bytes)
            return signer.sign(message)
        finally:
            # Zero secret key copy if original was SecureBytes
            if isinstance(secret_key, SecureBytes) and secret_key_bytes != secret_key:
                secure_memzero(bytearray(secret_key_bytes))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return self._signer.verify(message, signature, public_key)


# ============================================================================
# Signature Registry
# ============================================================================


class SignatureRegistry(RegistryBase[SignatureBase]):
    """
    Registry for post-quantum digital signature algorithms.

    Manages post-quantum signatures including ML-DSA, SLH-DSA, FN-DSA,
    MAYO, and CROSS.

    Usage:
        registry = SignatureRegistry.default()
        sig = registry.get("ml-dsa-65")
        public_key, secret_key = sig.generate_keypair()
        signature = sig.sign(message, secret_key)
        is_valid = sig.verify(message, signature, public_key)
    """

    _instance: Optional["SignatureRegistry"] = None

    def __init__(self):
        super().__init__()
        self._register_all()

    def _register_all(self):
        """Register all signature implementations."""
        # ML-DSA (NIST FIPS 204)
        self.register(MLDSA44)
        self.register(MLDSA65)
        self.register(MLDSA87)

        # SLH-DSA (NIST FIPS 205)
        self.register(SLHDSASHA2128F)
        self.register(SLHDSASHA2192F)
        self.register(SLHDSASHA2256F)

        # FN-DSA (NIST FIPS 206)
        self.register(FNDSA512)
        self.register(FNDSA1024)

        # MAYO (NIST Round 2)
        self.register(MAYO1)
        self.register(MAYO3)
        self.register(MAYO5)

        # CROSS (NIST Round 2)
        self.register(CROSS128)
        self.register(CROSS192)
        self.register(CROSS256)

    @classmethod
    def default(cls) -> "SignatureRegistry":
        """Get the default singleton registry instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance


# Convenience function
def get_signature(name: str) -> SignatureBase:
    """
    Get a signature instance by name.

    Args:
        name: Signature algorithm name (e.g., "ml-dsa-65", "fn-dsa-512")

    Returns:
        SignatureBase: A signature instance

    Example:
        sig = get_signature("ml-dsa-65")
        public_key, secret_key = sig.generate_keypair()
        signature = sig.sign(message, secret_key)
    """
    return SignatureRegistry.default().get(name)
