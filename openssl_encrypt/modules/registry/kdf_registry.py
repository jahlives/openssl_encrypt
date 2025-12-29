#!/usr/bin/env python3
"""
Key Derivation Function (KDF) Registry.

Implements password-based key derivation functions with unified interface.
Supports: Argon2 family, PBKDF2, Scrypt, Balloon, HKDF, and RandomX.

All code in English as per project requirements.
"""

import subprocess
import sys
from abc import abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar, Optional, Union

from .base import (
    AlgorithmBase,
    AlgorithmCategory,
    AlgorithmInfo,
    RegistryBase,
    SecurityLevel,
    ValidationError,
)

# Import secure memory handling
try:
    from ..secure_memory import SecureBytes, secure_memzero

    SECURE_MEMORY_AVAILABLE = True
except ImportError:
    # Fallback if secure_memory not available
    SecureBytes = bytes
    SECURE_MEMORY_AVAILABLE = False

    def secure_memzero(data):
        """Fallback no-op."""
        pass


class Argon2Type(Enum):
    """Argon2 variant types."""

    ARGON2D = 0  # Data-dependent (GPU-resistant)
    ARGON2I = 1  # Data-independent (side-channel resistant)
    ARGON2ID = 2  # Hybrid (recommended)


@dataclass
class KDFParams:
    """Base class for KDF parameters."""

    output_length: int = 32  # Default key length in bytes
    salt_length: int = 16  # Default salt length in bytes


@dataclass
class Argon2Params(KDFParams):
    """
    Parameters for Argon2 key derivation.

    Attributes:
        output_length: Desired key length in bytes (default: 32)
        salt_length: Salt length in bytes (default: 16)
        time_cost: Number of iterations (default: 3)
        memory_cost: Memory usage in KiB (default: 65536 = 64 MB)
        parallelism: Number of parallel threads (default: 4)
        variant: Argon2 variant (id/i/d, default: id)
    """

    time_cost: int = 3
    memory_cost: int = 65536  # 64 MB in KiB
    parallelism: int = 4
    variant: str = "id"  # "id", "i", or "d"


@dataclass
class PBKDF2Params(KDFParams):
    """
    Parameters for PBKDF2 key derivation.

    Attributes:
        output_length: Desired key length in bytes (default: 32)
        salt_length: Salt length in bytes (default: 16)
        iterations: Number of iterations (default: 100000)
        hash_function: Hash function name (default: "sha256")
    """

    iterations: int = 100000
    hash_function: str = "sha256"  # "sha256", "sha512", etc.


@dataclass
class ScryptParams(KDFParams):
    """
    Parameters for Scrypt key derivation.

    Attributes:
        output_length: Desired key length in bytes (default: 32)
        salt_length: Salt length in bytes (default: 16)
        n: CPU/memory cost factor (power of 2, default: 16384)
        r: Block size (default: 8)
        p: Parallelization factor (default: 1)
    """

    n: int = 16384  # CPU/memory cost
    r: int = 8  # Block size
    p: int = 1  # Parallelization


@dataclass
class BalloonParams(KDFParams):
    """
    Parameters for Balloon hashing.

    Attributes:
        output_length: Desired key length in bytes (default: 32)
        salt_length: Salt length in bytes (default: 16)
        time_cost: Number of rounds (default: 3)
        space_cost: Memory usage (default: 65536)
        parallelism: Parallel cost (default: 4)
    """

    time_cost: int = 3
    space_cost: int = 65536
    parallelism: int = 4


@dataclass
class HKDFParams(KDFParams):
    """
    Parameters for HKDF key expansion.

    Note: HKDF is NOT for passwords - use for key expansion only.

    Attributes:
        output_length: Desired key length in bytes (default: 32)
        salt_length: Salt length in bytes (default: 16, None = no salt)
        hash_function: Hash function name (default: "sha256")
        info: Context-specific info bytes (default: b"")
    """

    hash_function: str = "sha256"
    info: bytes = b""


@dataclass
class RandomXParams(KDFParams):
    """
    Parameters for RandomX PoW-based KDF.

    WARNING: Very slow, meant for extreme security.

    Attributes:
        output_length: Desired key length in bytes (default: 32)
        salt_length: Salt length in bytes (default: 16)
        hash: Initial hash function (default: "sha256")
        init_rounds: Number of initialization rounds (default: 1)
        passes: Number of RandomX passes (default: 1)
    """

    hash: str = "sha256"
    init_rounds: int = 1
    passes: int = 1


class KDFBase(AlgorithmBase):
    """
    Abstract base class for key derivation functions.

    Provides unified interface for password-based key derivation.
    """

    @abstractmethod
    def derive(
        self, password: Union[bytes, "SecureBytes"], salt: bytes, params: Optional[KDFParams] = None
    ) -> "SecureBytes":
        """
        Derives a key from a password and salt.

        Args:
            password: Password to derive key from (bytes or SecureBytes)
            salt: Random salt
            params: KDF-specific parameters (None = use defaults)

        Returns:
            Derived key as SecureBytes (MUST be zeroed after use)

        Raises:
            ValidationError: If parameters are invalid

        Security:
            - Accepts both bytes and SecureBytes for backward compatibility
            - Returns SecureBytes which will be zeroed when deleted
            - Caller MUST explicitly zero the returned key after use:
              >>> key = kdf.derive(password, salt)
              >>> try:
              >>>     # Use key...
              >>> finally:
              >>>     secure_memzero(key)
              >>>     del key
        """
        pass

    @classmethod
    @abstractmethod
    def default_params(cls) -> KDFParams:
        """
        Returns default parameters for this KDF.

        Returns:
            Default KDFParams instance
        """
        pass

    @classmethod
    def validate_params(cls, params: KDFParams) -> None:
        """
        Validates KDF parameters.

        Args:
            params: Parameters to validate

        Raises:
            ValidationError: If parameters are invalid
        """
        if params.output_length < 1:
            raise ValidationError("Output length must be at least 1 byte")
        if params.salt_length < 1:
            raise ValidationError("Salt length must be at least 1 byte")


# ============================================================================
# Argon2 Family
# ============================================================================


class Argon2id(KDFBase):
    """
    Argon2id - Hybrid Argon2 variant (recommended).

    Combines resistance to both side-channel and GPU attacks.
    Winner of the Password Hashing Competition (2015).
    """

    _available: ClassVar[Optional[bool]] = None

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="argon2id",
            display_name="Argon2id",
            category=AlgorithmCategory.KDF,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="Argon2id - Recommended hybrid variant (side-channel + GPU resistant)",
            aliases=("argon2",),
            references=("RFC 9106",),
        )

    @classmethod
    def is_available(cls) -> bool:
        if cls._available is None:
            try:
                import argon2

                cls._available = True
            except ImportError:
                cls._available = False
        return cls._available

    @classmethod
    def default_params(cls) -> Argon2Params:
        return Argon2Params(
            output_length=32,
            salt_length=16,
            time_cost=3,
            memory_cost=65536,  # 64 MB
            parallelism=4,
            variant="id",
        )

    def derive(
        self,
        password: Union[bytes, SecureBytes],
        salt: bytes,
        params: Optional[Argon2Params] = None,
    ) -> SecureBytes:
        self.check_available()

        if params is None:
            params = self.default_params()

        self.validate_params(params)

        import argon2
        from argon2.low_level import Type

        # Convert password to bytes if needed (SecureBytes is a bytearray subclass)
        password_bytes = bytes(password) if isinstance(password, SecureBytes) else password

        # Map variant string to Type enum
        type_map = {
            "id": Type.ID,
            "i": Type.I,
            "d": Type.D,
        }

        if params.variant not in type_map:
            raise ValidationError(f"Invalid Argon2 variant: {params.variant}")

        argon2_type = type_map[params.variant]

        try:
            derived_key = argon2.low_level.hash_secret_raw(
                secret=password_bytes,
                salt=salt,
                time_cost=params.time_cost,
                memory_cost=params.memory_cost,
                parallelism=params.parallelism,
                hash_len=params.output_length,
                type=argon2_type,
            )
            # Wrap result in SecureBytes for automatic cleanup
            return SecureBytes(derived_key)
        finally:
            # Zero out password_bytes if we created a copy
            if isinstance(password, SecureBytes) and password_bytes != password:
                secure_memzero(bytearray(password_bytes))


class Argon2i(KDFBase):
    """
    Argon2i - Data-independent variant (side-channel resistant).

    Use when side-channel attacks are a concern. Slower than Argon2id.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="argon2i",
            display_name="Argon2i",
            category=AlgorithmCategory.KDF,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="Argon2i - Side-channel resistant variant",
            references=("RFC 9106",),
        )

    @classmethod
    def is_available(cls) -> bool:
        return Argon2id.is_available()

    @classmethod
    def default_params(cls) -> Argon2Params:
        params = Argon2id.default_params()
        params.variant = "i"
        return params

    def derive(
        self,
        password: Union[bytes, SecureBytes],
        salt: bytes,
        params: Optional[Argon2Params] = None,
    ) -> SecureBytes:
        if params is None:
            params = self.default_params()
        else:
            # Force variant to 'i'
            params.variant = "i"

        # Delegate to Argon2id with forced variant (already returns SecureBytes)
        return Argon2id().derive(password, salt, params)


class Argon2d(KDFBase):
    """
    Argon2d - Data-dependent variant (GPU-resistant).

    Faster but vulnerable to side-channel attacks. Use Argon2id instead.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="argon2d",
            display_name="Argon2d",
            category=AlgorithmCategory.KDF,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="Argon2d - GPU-resistant but vulnerable to side-channels",
            references=("RFC 9106",),
        )

    @classmethod
    def is_available(cls) -> bool:
        return Argon2id.is_available()

    @classmethod
    def default_params(cls) -> Argon2Params:
        params = Argon2id.default_params()
        params.variant = "d"
        return params

    def derive(
        self,
        password: Union[bytes, SecureBytes],
        salt: bytes,
        params: Optional[Argon2Params] = None,
    ) -> SecureBytes:
        if params is None:
            params = self.default_params()
        else:
            # Force variant to 'd'
            params.variant = "d"

        # Delegate to Argon2id with forced variant (already returns SecureBytes)
        return Argon2id().derive(password, salt, params)


# ============================================================================
# PBKDF2
# ============================================================================


class PBKDF2(KDFBase):
    """
    PBKDF2 - Password-Based Key Derivation Function 2 (NIST SP 800-132).

    Legacy KDF, not memory-hard. Use Argon2 for new applications.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="pbkdf2",
            display_name="PBKDF2",
            category=AlgorithmCategory.KDF,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.LEGACY,
            description="PBKDF2 - Legacy KDF (not memory-hard, use Argon2 instead)",
            aliases=("pbkdf2-hmac", "pbkdf2-sha256"),
            references=("NIST SP 800-132", "RFC 2898"),
            nist_standard="SP 800-132",
        )

    @classmethod
    def default_params(cls) -> PBKDF2Params:
        return PBKDF2Params(
            output_length=32,
            salt_length=16,
            iterations=100000,
            hash_function="sha256",
        )

    def derive(
        self,
        password: Union[bytes, SecureBytes],
        salt: bytes,
        params: Optional[PBKDF2Params] = None,
    ) -> SecureBytes:
        if params is None:
            params = self.default_params()

        self.validate_params(params)

        if params.iterations < 1:
            raise ValidationError("PBKDF2 iterations must be at least 1")

        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        # Convert password to bytes if needed
        password_bytes = bytes(password) if isinstance(password, SecureBytes) else password

        # Map hash function name to cryptography hash algorithm
        hash_map = {
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(),
            "sha224": hashes.SHA224(),
        }

        if params.hash_function not in hash_map:
            raise ValidationError(f"Unsupported hash function: {params.hash_function}")

        kdf = PBKDF2HMAC(
            algorithm=hash_map[params.hash_function],
            length=params.output_length,
            salt=salt,
            iterations=params.iterations,
            backend=default_backend(),
        )

        try:
            derived_key = kdf.derive(password_bytes)
            return SecureBytes(derived_key)
        finally:
            if isinstance(password, SecureBytes) and password_bytes != password:
                secure_memzero(bytearray(password_bytes))


# ============================================================================
# Scrypt
# ============================================================================


class Scrypt(KDFBase):
    """
    Scrypt - Memory-hard KDF (RFC 7914).

    Good balance of memory-hardness and performance.
    """

    _available: ClassVar[Optional[bool]] = None

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="scrypt",
            display_name="Scrypt",
            category=AlgorithmCategory.KDF,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="Scrypt - Memory-hard KDF with good properties",
            references=("RFC 7914",),
        )

    @classmethod
    def is_available(cls) -> bool:
        if cls._available is None:
            try:
                from cryptography.hazmat.primitives.kdf.scrypt import Scrypt as CryptoScrypt

                cls._available = True
            except ImportError:
                cls._available = False
        return cls._available

    @classmethod
    def default_params(cls) -> ScryptParams:
        return ScryptParams(
            output_length=32,
            salt_length=16,
            n=16384,  # CPU/memory cost
            r=8,  # Block size
            p=1,  # Parallelization
        )

    def derive(
        self,
        password: Union[bytes, SecureBytes],
        salt: bytes,
        params: Optional[ScryptParams] = None,
    ) -> SecureBytes:
        self.check_available()

        if params is None:
            params = self.default_params()

        self.validate_params(params)

        # Validate scrypt parameters
        if params.n < 2 or (params.n & (params.n - 1)) != 0:
            raise ValidationError("Scrypt n must be a power of 2")
        if params.r < 1:
            raise ValidationError("Scrypt r must be at least 1")
        if params.p < 1:
            raise ValidationError("Scrypt p must be at least 1")

        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt as CryptoScrypt

        # Convert password to bytes if needed
        password_bytes = bytes(password) if isinstance(password, SecureBytes) else password

        kdf = CryptoScrypt(
            salt=salt,
            length=params.output_length,
            n=params.n,
            r=params.r,
            p=params.p,
            backend=default_backend(),
        )

        try:
            derived_key = kdf.derive(password_bytes)
            return SecureBytes(derived_key)
        finally:
            if isinstance(password, SecureBytes) and password_bytes != password:
                secure_memzero(bytearray(password_bytes))


# ============================================================================
# Balloon Hashing
# ============================================================================


class Balloon(KDFBase):
    """
    Balloon Hashing - Memory-hard KDF.

    Alternative to Argon2 with different construction.
    """

    _available: ClassVar[Optional[bool]] = None

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="balloon",
            display_name="Balloon Hashing",
            category=AlgorithmCategory.KDF,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="Balloon - Memory-hard KDF alternative to Argon2",
            references=("https://eprint.iacr.org/2016/027",),
        )

    @classmethod
    def is_available(cls) -> bool:
        if cls._available is None:
            try:
                from openssl_encrypt.modules.balloon import balloon_m

                cls._available = True
            except ImportError:
                cls._available = False
        return cls._available

    @classmethod
    def default_params(cls) -> BalloonParams:
        return BalloonParams(
            output_length=32,
            salt_length=16,
            time_cost=3,
            space_cost=65536,
            parallelism=4,
        )

    def derive(
        self,
        password: Union[bytes, SecureBytes],
        salt: bytes,
        params: Optional[BalloonParams] = None,
    ) -> SecureBytes:
        self.check_available()

        if params is None:
            params = self.default_params()

        self.validate_params(params)

        from openssl_encrypt.modules.balloon import balloon_m

        # Convert password to bytes if needed
        password_bytes = bytes(password) if isinstance(password, SecureBytes) else password

        try:
            # Balloon expects salt as string
            result = balloon_m(
                password=password_bytes,
                salt=str(salt.hex()),  # Convert to hex string
                time_cost=params.time_cost,
                space_cost=params.space_cost,
                parallel_cost=params.parallelism,
            )

            # Truncate or pad to desired length
            if len(result) >= params.output_length:
                return SecureBytes(result[: params.output_length])
            else:
                # Pad with additional hashing if needed
                import hashlib

                padded = result
                while len(padded) < params.output_length:
                    padded += hashlib.sha256(padded).digest()
                return SecureBytes(padded[: params.output_length])
        finally:
            if isinstance(password, SecureBytes) and password_bytes != password:
                secure_memzero(bytearray(password_bytes))


# ============================================================================
# HKDF
# ============================================================================


class HKDF(KDFBase):
    """
    HKDF - HMAC-based Key Derivation Function (RFC 5869).

    For key expansion, NOT for passwords. Use Argon2 for passwords.
    """

    _available: ClassVar[Optional[bool]] = None

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="hkdf",
            display_name="HKDF",
            category=AlgorithmCategory.KDF,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="HKDF - Key expansion (NOT for passwords!)",
            references=("RFC 5869",),
        )

    @classmethod
    def is_available(cls) -> bool:
        if cls._available is None:
            try:
                from cryptography.hazmat.primitives.kdf.hkdf import HKDF as CryptoHKDF

                cls._available = True
            except ImportError:
                cls._available = False
        return cls._available

    @classmethod
    def default_params(cls) -> HKDFParams:
        return HKDFParams(
            output_length=32,
            salt_length=16,
            hash_function="sha256",
            info=b"",
        )

    def derive(
        self, password: Union[bytes, SecureBytes], salt: bytes, params: Optional[HKDFParams] = None
    ) -> SecureBytes:
        self.check_available()

        if params is None:
            params = self.default_params()

        self.validate_params(params)

        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF as CryptoHKDF

        # Convert password to bytes if needed
        password_bytes = bytes(password) if isinstance(password, SecureBytes) else password

        # Map hash function name
        hash_map = {
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(),
        }

        if params.hash_function not in hash_map:
            raise ValidationError(f"Unsupported hash function: {params.hash_function}")

        kdf = CryptoHKDF(
            algorithm=hash_map[params.hash_function],
            length=params.output_length,
            salt=salt,
            info=params.info,
            backend=default_backend(),
        )

        try:
            derived_key = kdf.derive(password_bytes)
            return SecureBytes(derived_key)
        finally:
            if isinstance(password, SecureBytes) and password_bytes != password:
                secure_memzero(bytearray(password_bytes))


# ============================================================================
# RandomX
# ============================================================================


class RandomX(KDFBase):
    """
    RandomX - Proof-of-Work based KDF (VERY SLOW).

    Extremely secure but very slow. Only for paranoid security requirements.
    """

    _available: ClassVar[Optional[bool]] = None

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="randomx",
            display_name="RandomX (VERY SLOW)",
            category=AlgorithmCategory.KDF,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.PARANOID,
            description="RandomX - PoW-based KDF (VERY slow, extreme security)",
            references=("https://github.com/tevador/RandomX",),
        )

    @classmethod
    def is_available(cls) -> bool:
        if cls._available is None:
            # Use subprocess to test import - randomx may cause SIGILL on unsupported CPUs
            try:
                result = subprocess.run(
                    [sys.executable, "-c", "import randomx"],
                    capture_output=True,
                    timeout=2,
                    check=False,
                )
                cls._available = result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                cls._available = False
        return cls._available

    @classmethod
    def default_params(cls) -> RandomXParams:
        return RandomXParams(
            output_length=32,
            salt_length=16,
            hash="sha256",
            init_rounds=1,
            passes=1,
        )

    def derive(
        self,
        password: Union[bytes, SecureBytes],
        salt: bytes,
        params: Optional[RandomXParams] = None,
    ) -> SecureBytes:
        self.check_available()

        if params is None:
            params = self.default_params()

        self.validate_params(params)

        import hashlib

        import randomx

        # Convert password to bytes if needed
        password_bytes = bytes(password) if isinstance(password, SecureBytes) else password

        try:
            # Initial hash with salt
            hash_func = getattr(hashlib, params.hash)
            initial = hash_func(password_bytes + salt).digest()

            # Apply RandomX hashing
            # Use initial hash as the RandomX key
            vm = randomx.RandomX(initial[:32])  # RandomX key (32 bytes)

            # Apply multiple passes for increased security
            derived = initial
            for _ in range(params.passes):
                derived = vm.calculate_hash(derived)

            # Ensure correct output length
            if len(derived) >= params.output_length:
                return SecureBytes(derived[: params.output_length])
            else:
                # Expand with hashing if needed
                expanded = derived
                while len(expanded) < params.output_length:
                    expanded += hashlib.sha256(expanded).digest()
                return SecureBytes(expanded[: params.output_length])
        finally:
            if isinstance(password, SecureBytes) and password_bytes != password:
                secure_memzero(bytearray(password_bytes))


# ============================================================================
# Registry and convenience functions
# ============================================================================


class KDFRegistry(RegistryBase[KDFBase]):
    """Registry for key derivation functions."""

    _default_instance: ClassVar[Optional["KDFRegistry"]] = None

    def __init__(self):
        super().__init__()
        # Register all KDF implementations
        # Argon2 family
        self.register(Argon2id)
        self.register(Argon2i)
        self.register(Argon2d)

        # Standard KDFs
        self.register(PBKDF2)
        self.register(Scrypt)
        self.register(Balloon)
        self.register(HKDF)

        # Extreme security
        self.register(RandomX)

    @classmethod
    def default(cls) -> "KDFRegistry":
        """Returns the default singleton registry instance."""
        if cls._default_instance is None:
            cls._default_instance = cls()
        return cls._default_instance


def get_kdf(name: str) -> KDFBase:
    """
    Convenience function to get a KDF instance.

    Args:
        name: KDF name or alias

    Returns:
        KDF instance

    Example:
        >>> kdf = get_kdf("argon2id")
        >>> key = kdf.derive(password, salt)
    """
    return KDFRegistry.default().get(name)
