#!/usr/bin/env python3
"""
Hash Function Registry.

Implements cryptographic hash functions with unified interface.
Supports: SHA-2, SHA-3, BLAKE2, BLAKE3, SHAKE (XOF), and Whirlpool (legacy).

All code in English as per project requirements.
"""

import hashlib
from abc import abstractmethod
from typing import ClassVar, Optional

from .base import (
    AlgorithmBase,
    AlgorithmCategory,
    AlgorithmInfo,
    RegistryBase,
    SecurityLevel,
    ValidationError,
)


class HashBase(AlgorithmBase):
    """
    Abstract base class for cryptographic hash functions.

    Provides unified interface for both regular hashes and
    extendable output functions (XOFs).
    """

    @abstractmethod
    def hash(self, data: bytes, output_length: Optional[int] = None) -> bytes:
        """
        Computes the hash of data.

        Args:
            data: Data to hash
            output_length: Output length in bytes (for XOFs, None = default)

        Returns:
            Hash digest

        Raises:
            ValidationError: If parameters are invalid
        """
        pass

    @classmethod
    def get_output_size(cls) -> int:
        """
        Returns the default output size in bytes.

        Returns:
            Output size in bytes
        """
        return cls.info().output_size

    @classmethod
    def supports_variable_output(cls) -> bool:
        """
        Returns whether this hash supports variable output length.

        Returns:
            True if this is an XOF (extendable output function)
        """
        return cls.info().is_xof


# ============================================================================
# SHA-2 Family (FIPS 180-4)
# ============================================================================


class SHA256(HashBase):
    """SHA-256 - 256-bit SHA-2 hash function."""

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="sha256",
            display_name="SHA-256",
            category=AlgorithmCategory.HASH,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="SHA-256 - Widely used 256-bit hash from SHA-2 family",
            output_size=32,
            block_size=64,
            aliases=("sha-256", "sha2-256"),
            references=("NIST FIPS 180-4", "RFC 6234"),
            nist_standard="FIPS 180-4",
        )

    def hash(self, data: bytes, output_length: Optional[int] = None) -> bytes:
        if output_length is not None:
            raise ValidationError("SHA-256 has fixed output length")
        return hashlib.sha256(data).digest()


class SHA384(HashBase):
    """SHA-384 - 384-bit SHA-2 hash function."""

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="sha384",
            display_name="SHA-384",
            category=AlgorithmCategory.HASH,
            security_bits=384,
            pq_security_bits=192,
            security_level=SecurityLevel.HIGH,
            description="SHA-384 - 384-bit hash from SHA-2 family",
            output_size=48,
            block_size=128,
            aliases=("sha-384", "sha2-384"),
            references=("NIST FIPS 180-4", "RFC 6234"),
            nist_standard="FIPS 180-4",
        )

    def hash(self, data: bytes, output_length: Optional[int] = None) -> bytes:
        if output_length is not None:
            raise ValidationError("SHA-384 has fixed output length")
        return hashlib.sha384(data).digest()


class SHA512(HashBase):
    """SHA-512 - 512-bit SHA-2 hash function."""

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="sha512",
            display_name="SHA-512",
            category=AlgorithmCategory.HASH,
            security_bits=512,
            pq_security_bits=256,
            security_level=SecurityLevel.HIGH,
            description="SHA-512 - 512-bit hash from SHA-2 family",
            output_size=64,
            block_size=128,
            aliases=("sha-512", "sha2-512"),
            references=("NIST FIPS 180-4", "RFC 6234"),
            nist_standard="FIPS 180-4",
        )

    def hash(self, data: bytes, output_length: Optional[int] = None) -> bytes:
        if output_length is not None:
            raise ValidationError("SHA-512 has fixed output length")
        return hashlib.sha512(data).digest()


# ============================================================================
# SHA-3 Family (FIPS 202)
# ============================================================================


class SHA3_256(HashBase):
    """SHA3-256 - 256-bit Keccak-based hash function."""

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="sha3-256",
            display_name="SHA3-256",
            category=AlgorithmCategory.HASH,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="SHA3-256 - Keccak-based hash, resistant to length-extension",
            output_size=32,
            block_size=136,
            aliases=("sha3_256",),
            references=("NIST FIPS 202",),
            nist_standard="FIPS 202",
        )

    def hash(self, data: bytes, output_length: Optional[int] = None) -> bytes:
        if output_length is not None:
            raise ValidationError("SHA3-256 has fixed output length")
        return hashlib.sha3_256(data).digest()


class SHA3_384(HashBase):
    """SHA3-384 - 384-bit Keccak-based hash function."""

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="sha3-384",
            display_name="SHA3-384",
            category=AlgorithmCategory.HASH,
            security_bits=384,
            pq_security_bits=192,
            security_level=SecurityLevel.HIGH,
            description="SHA3-384 - Keccak-based hash with 384-bit output",
            output_size=48,
            block_size=104,
            aliases=("sha3_384",),
            references=("NIST FIPS 202",),
            nist_standard="FIPS 202",
        )

    def hash(self, data: bytes, output_length: Optional[int] = None) -> bytes:
        if output_length is not None:
            raise ValidationError("SHA3-384 has fixed output length")
        return hashlib.sha3_384(data).digest()


class SHA3_512(HashBase):
    """SHA3-512 - 512-bit Keccak-based hash function."""

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="sha3-512",
            display_name="SHA3-512",
            category=AlgorithmCategory.HASH,
            security_bits=512,
            pq_security_bits=256,
            security_level=SecurityLevel.HIGH,
            description="SHA3-512 - Keccak-based hash with 512-bit output",
            output_size=64,
            block_size=72,
            aliases=("sha3_512",),
            references=("NIST FIPS 202",),
            nist_standard="FIPS 202",
        )

    def hash(self, data: bytes, output_length: Optional[int] = None) -> bytes:
        if output_length is not None:
            raise ValidationError("SHA3-512 has fixed output length")
        return hashlib.sha3_512(data).digest()


# ============================================================================
# BLAKE2 Family (RFC 7693)
# ============================================================================


class BLAKE2b(HashBase):
    """
    BLAKE2b - Fast cryptographic hash optimized for 64-bit platforms.

    Supports variable output length (1-64 bytes) and optional keyed hashing.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="blake2b",
            display_name="BLAKE2b",
            category=AlgorithmCategory.HASH,
            security_bits=512,
            pq_security_bits=256,
            security_level=SecurityLevel.HIGH,
            description="BLAKE2b - Fast hash with keyed mode support (64-bit optimized)",
            output_size=64,  # Default, but variable
            block_size=128,
            supports_keyed_mode=True,
            is_xof=False,  # Variable but not XOF in the strict sense
            aliases=("blake2b-512",),
            references=("RFC 7693",),
        )

    def hash(self, data: bytes, output_length: Optional[int] = None) -> bytes:
        digest_size = output_length if output_length is not None else 64

        if digest_size < 1 or digest_size > 64:
            raise ValidationError("BLAKE2b digest size must be 1-64 bytes")

        return hashlib.blake2b(data, digest_size=digest_size).digest()

    def hash_keyed(self, data: bytes, key: bytes, output_length: Optional[int] = None) -> bytes:
        """
        Computes keyed hash using BLAKE2b.

        Args:
            data: Data to hash
            key: Key for keyed hashing (0-64 bytes)
            output_length: Output length in bytes (1-64, default 64)

        Returns:
            Keyed hash digest
        """
        if len(key) > 64:
            raise ValidationError("BLAKE2b key must be 0-64 bytes")

        digest_size = output_length if output_length is not None else 64

        if digest_size < 1 or digest_size > 64:
            raise ValidationError("BLAKE2b digest size must be 1-64 bytes")

        return hashlib.blake2b(data, digest_size=digest_size, key=key).digest()


class BLAKE2s(HashBase):
    """
    BLAKE2s - Fast cryptographic hash optimized for 32-bit platforms.

    Supports variable output length (1-32 bytes) and optional keyed hashing.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="blake2s",
            display_name="BLAKE2s",
            category=AlgorithmCategory.HASH,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="BLAKE2s - Fast hash with keyed mode support (32-bit optimized)",
            output_size=32,  # Default, but variable
            block_size=64,
            supports_keyed_mode=True,
            is_xof=False,
            aliases=("blake2s-256",),
            references=("RFC 7693",),
        )

    def hash(self, data: bytes, output_length: Optional[int] = None) -> bytes:
        digest_size = output_length if output_length is not None else 32

        if digest_size < 1 or digest_size > 32:
            raise ValidationError("BLAKE2s digest size must be 1-32 bytes")

        return hashlib.blake2s(data, digest_size=digest_size).digest()

    def hash_keyed(self, data: bytes, key: bytes, output_length: Optional[int] = None) -> bytes:
        """
        Computes keyed hash using BLAKE2s.

        Args:
            data: Data to hash
            key: Key for keyed hashing (0-32 bytes)
            output_length: Output length in bytes (1-32, default 32)

        Returns:
            Keyed hash digest
        """
        if len(key) > 32:
            raise ValidationError("BLAKE2s key must be 0-32 bytes")

        digest_size = output_length if output_length is not None else 32

        if digest_size < 1 or digest_size > 32:
            raise ValidationError("BLAKE2s digest size must be 1-32 bytes")

        return hashlib.blake2s(data, digest_size=digest_size, key=key).digest()


class BLAKE3(HashBase):
    """
    BLAKE3 - High-performance cryptographic hash with XOF support.

    Supports arbitrary output length and optional keyed hashing.
    Much faster than BLAKE2 with better parallelism.
    """

    _available: ClassVar[Optional[bool]] = None

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="blake3",
            display_name="BLAKE3",
            category=AlgorithmCategory.HASH,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.HIGH,
            description="BLAKE3 - Very fast XOF with keyed hashing and parallelism",
            output_size=32,  # Default
            block_size=64,
            supports_keyed_mode=True,
            is_xof=True,  # Arbitrary output length
            references=("https://github.com/BLAKE3-team/BLAKE3",),
        )

    @classmethod
    def is_available(cls) -> bool:
        if cls._available is None:
            try:
                import blake3

                cls._available = True
            except ImportError:
                cls._available = False
        return cls._available

    def hash(self, data: bytes, output_length: Optional[int] = None) -> bytes:
        self.check_available()

        import blake3

        output_len = output_length if output_length is not None else 32

        if output_len < 1:
            raise ValidationError("BLAKE3 output length must be at least 1 byte")

        return blake3.blake3(data).digest(output_len)

    def hash_keyed(self, data: bytes, key: bytes, output_length: Optional[int] = None) -> bytes:
        """
        Computes keyed hash using BLAKE3.

        Args:
            data: Data to hash
            key: Key for keyed hashing (must be exactly 32 bytes)
            output_length: Output length in bytes (default 32)

        Returns:
            Keyed hash digest
        """
        self.check_available()

        import blake3

        if len(key) != 32:
            raise ValidationError("BLAKE3 keyed hashing requires exactly 32-byte key")

        output_len = output_length if output_length is not None else 32

        if output_len < 1:
            raise ValidationError("BLAKE3 output length must be at least 1 byte")

        return blake3.blake3(data, key=key).digest(output_len)


# ============================================================================
# SHAKE Family - Extendable Output Functions (FIPS 202)
# ============================================================================


class SHAKE128(HashBase):
    """
    SHAKE-128 - Extendable output function with 128-bit security.

    Based on Keccak, can produce arbitrary-length output.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="shake128",
            display_name="SHAKE-128",
            category=AlgorithmCategory.HASH,
            security_bits=128,
            pq_security_bits=64,
            security_level=SecurityLevel.STANDARD,
            description="SHAKE-128 - XOF with 128-bit security and arbitrary output",
            output_size=16,  # Default (128 bits)
            block_size=168,
            is_xof=True,
            aliases=("shake-128",),
            references=("NIST FIPS 202",),
            nist_standard="FIPS 202",
        )

    def hash(self, data: bytes, output_length: Optional[int] = None) -> bytes:
        output_len = output_length if output_length is not None else 16

        if output_len < 1:
            raise ValidationError("SHAKE-128 output length must be at least 1 byte")

        return hashlib.shake_128(data).digest(output_len)


class SHAKE256(HashBase):
    """
    SHAKE-256 - Extendable output function with 256-bit security.

    Based on Keccak, can produce arbitrary-length output.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="shake256",
            display_name="SHAKE-256",
            category=AlgorithmCategory.HASH,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.HIGH,
            description="SHAKE-256 - XOF with 256-bit security and arbitrary output",
            output_size=32,  # Default (256 bits)
            block_size=136,
            is_xof=True,
            aliases=("shake-256",),
            references=("NIST FIPS 202",),
            nist_standard="FIPS 202",
        )

    def hash(self, data: bytes, output_length: Optional[int] = None) -> bytes:
        output_len = output_length if output_length is not None else 32

        if output_len < 1:
            raise ValidationError("SHAKE-256 output length must be at least 1 byte")

        return hashlib.shake_256(data).digest(output_len)


# ============================================================================
# Legacy Hash Functions
# ============================================================================


class Whirlpool(HashBase):
    """
    Whirlpool - 512-bit hash function (LEGACY).

    Includes special handling for Python 3.13+ compatibility.
    Limited adoption, provided for backward compatibility only.
    """

    _available: ClassVar[Optional[bool]] = None

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="whirlpool",
            display_name="Whirlpool (LEGACY)",
            category=AlgorithmCategory.HASH,
            security_bits=512,
            pq_security_bits=256,
            security_level=SecurityLevel.LEGACY,
            description="Whirlpool - 512-bit hash (legacy, limited adoption)",
            output_size=64,
            block_size=64,
            references=("ISO/IEC 10118-3",),
        )

    @classmethod
    def is_available(cls) -> bool:
        """
        Checks Whirlpool availability with Python 3.13+ compatibility.

        Tries multiple import strategies:
        1. Modern 'whirlpool' package
        2. Legacy 'pywhirlpool' package
        3. Python 3.13+ special loading
        """
        if cls._available is None:
            # Try modern whirlpool package
            try:
                import whirlpool

                cls._available = True
                return True
            except ImportError:
                pass

            # Try legacy pywhirlpool package
            try:
                import pywhirlpool

                cls._available = True
                return True
            except ImportError:
                pass

            # Python 3.13+ special handling
            try:
                import sys

                python_version = sys.version_info

                if python_version.major == 3 and python_version.minor >= 13:
                    import glob
                    import importlib.util
                    import site
                    from importlib.machinery import ExtensionFileLoader

                    # Look for whirlpool in site-packages
                    for site_pkg in site.getsitepackages():
                        pattern = os.path.join(site_pkg, "whirlpool*py313*.so")
                        py313_modules = glob.glob(pattern)

                        if py313_modules:
                            module_path = py313_modules[0]
                            loader = ExtensionFileLoader("whirlpool", module_path)
                            spec = importlib.util.spec_from_file_location(
                                "whirlpool", module_path, loader=loader
                            )
                            whirlpool_module = importlib.util.module_from_spec(spec)
                            spec.loader.exec_module(whirlpool_module)
                            cls._available = True
                            return True
            except Exception:
                pass

            cls._available = False

        return cls._available

    def hash(self, data: bytes, output_length: Optional[int] = None) -> bytes:
        self.check_available()

        if output_length is not None:
            raise ValidationError("Whirlpool has fixed output length")

        # Try whirlpool package
        try:
            import whirlpool

            return whirlpool.new(data).digest()
        except ImportError:
            pass

        # Try pywhirlpool package
        try:
            import pywhirlpool

            return pywhirlpool.whirlpool(data).digest()
        except ImportError:
            pass

        # This shouldn't happen if is_available() returned True
        raise ImportError("Whirlpool module not available")


# ============================================================================
# Registry and convenience functions
# ============================================================================


class HashRegistry(RegistryBase[HashBase]):
    """Registry for cryptographic hash functions."""

    _default_instance: ClassVar[Optional["HashRegistry"]] = None

    def __init__(self):
        super().__init__()
        # Register all hash implementations
        # SHA-2 family
        self.register(SHA256)
        self.register(SHA384)
        self.register(SHA512)

        # SHA-3 family
        self.register(SHA3_256)
        self.register(SHA3_384)
        self.register(SHA3_512)

        # BLAKE family
        self.register(BLAKE2b)
        self.register(BLAKE2s)
        self.register(BLAKE3)

        # SHAKE (XOF)
        self.register(SHAKE128)
        self.register(SHAKE256)

        # Legacy
        self.register(Whirlpool)

    @classmethod
    def default(cls) -> "HashRegistry":
        """Returns the default singleton registry instance."""
        if cls._default_instance is None:
            cls._default_instance = cls()
        return cls._default_instance


def get_hash(name: str) -> HashBase:
    """
    Convenience function to get a hash function instance.

    Args:
        name: Hash function name or alias

    Returns:
        Hash function instance

    Example:
        >>> hasher = get_hash("sha256")
        >>> digest = hasher.hash(b"data")
    """
    return HashRegistry.default().get(name)


# Import os for Whirlpool Python 3.13+ handling
import os
