#!/usr/bin/env python3
"""
Symmetric Cipher Registry.

Implements symmetric encryption algorithms (AEAD ciphers) with a unified interface.
Supports: AES-GCM, AES-GCM-SIV, AES-SIV, AES-OCB3, ChaCha20-Poly1305,
XChaCha20-Poly1305, Fernet, and legacy Camellia.

All code in English as per project requirements.
"""

from abc import abstractmethod
from dataclasses import dataclass
from typing import Optional, ClassVar, Dict, Union

from .base import (
    AlgorithmBase,
    AlgorithmInfo,
    AlgorithmCategory,
    SecurityLevel,
    RegistryBase,
    AlgorithmNotAvailableError,
    ValidationError,
    AuthenticationError,
)
from .utils import generate_random_bytes

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


# Helper functions for secure memory handling
def _convert_to_bytes(data: Union[bytes, 'SecureBytes']) -> bytes:
    """Convert SecureBytes to bytes for library calls."""
    return bytes(data) if isinstance(data, SecureBytes) else data


def _secure_cleanup(original, copy):
    """Securely zero a copy if original was SecureBytes."""
    if isinstance(original, SecureBytes) and copy != original:
        secure_memzero(bytearray(copy))


@dataclass
class CipherParams:
    """
    Parameters for symmetric cipher operations.

    Attributes:
        nonce_size: Nonce/IV size in bytes (None = algorithm default)
        tag_size: Authentication tag size in bytes (None = algorithm default)
        associated_data: Additional authenticated data (AEAD only)
    """
    nonce_size: Optional[int] = None
    tag_size: Optional[int] = None
    associated_data: Optional[bytes] = None


class CipherBase(AlgorithmBase):
    """
    Abstract base class for symmetric encryption algorithms.

    Provides a unified interface for AEAD ciphers with support for
    encryption, decryption, and nonce generation.
    """

    @abstractmethod
    def encrypt(
        self,
        key: Union[bytes, 'SecureBytes'],
        plaintext: Union[bytes, 'SecureBytes'],
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Encrypts plaintext with authenticated encryption.

        Args:
            key: Encryption key (bytes or SecureBytes)
            plaintext: Data to encrypt (bytes or SecureBytes)
            nonce: Nonce/IV (None = auto-generate)
            associated_data: Additional data to authenticate (AEAD only)

        Returns:
            Nonce + ciphertext + tag (format may vary by algorithm)
            Note: Ciphertext is not returned as SecureBytes since it's meant
            to be stored/transmitted

        Raises:
            ValidationError: If parameters are invalid

        Security:
            - Accepts SecureBytes for key and plaintext (auto-zeroed)
            - Key and plaintext copies are zeroed after use
            - Ciphertext is NOT SecureBytes (meant for storage)
        """
        pass

    @abstractmethod
    def decrypt(
        self,
        key: Union[bytes, 'SecureBytes'],
        ciphertext: bytes,
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
    ) -> 'SecureBytes':
        """
        Decrypts ciphertext and verifies authentication.

        Args:
            key: Decryption key (bytes or SecureBytes)
            ciphertext: Encrypted data (may include nonce + tag)
            nonce: Nonce/IV (None = extract from ciphertext)
            associated_data: Additional authenticated data

        Returns:
            Decrypted plaintext as SecureBytes (MUST be zeroed after use)

        Raises:
            AuthenticationError: If authentication tag verification fails
            ValidationError: If parameters are invalid

        Security:
            - Returns SecureBytes which will be zeroed when deleted
            - Caller MUST explicitly zero the returned plaintext after use
        """
        pass

    @abstractmethod
    def generate_nonce(self) -> bytes:
        """
        Generates a random nonce of appropriate size.

        Returns:
            Random nonce bytes
        """
        pass

    @classmethod
    @abstractmethod
    def get_key_size(cls) -> int:
        """
        Returns the required key size in bytes.

        Returns:
            Key size in bytes
        """
        pass


# ============================================================================
# AES Family
# ============================================================================

class AES256GCM(CipherBase):
    """
    AES-256-GCM - Advanced Encryption Standard in Galois/Counter Mode.

    Recommended for general-purpose authenticated encryption with
    hardware acceleration (AES-NI).
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="aes-256-gcm",
            display_name="AES-256-GCM",
            category=AlgorithmCategory.CIPHER,
            security_bits=256,
            pq_security_bits=128,  # Grover's algorithm impact
            security_level=SecurityLevel.STANDARD,
            description="AES-256 in Galois/Counter Mode - NIST approved AEAD cipher",
            key_size=32,
            nonce_size=12,
            tag_size=16,
            block_size=16,
            aliases=("aes-gcm", "aes256-gcm", "aesgcm"),
            references=("NIST SP 800-38D", "RFC 5116"),
            nist_standard="SP 800-38D",
        )

    @classmethod
    def get_key_size(cls) -> int:
        return 32

    def generate_nonce(self) -> bytes:
        """Generates a 12-byte nonce (96 bits, recommended for GCM)."""
        return generate_random_bytes(12)

    def encrypt(
        self,
        key: Union[bytes, SecureBytes],
        plaintext: Union[bytes, SecureBytes],
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Encrypts with AES-256-GCM.

        Returns:
            nonce (12 bytes) + ciphertext + tag (16 bytes)
        """
        self.check_available()

        # Convert SecureBytes to bytes for library
        key_bytes = _convert_to_bytes(key)
        plaintext_bytes = _convert_to_bytes(plaintext)

        try:
            # Validate key
            if len(key_bytes) != 32:
                raise ValidationError(f"AES-256-GCM requires 32-byte key, got {len(key_bytes)}")

            # Generate nonce if not provided
            if nonce is None:
                nonce = self.generate_nonce()

            if len(nonce) != 12:
                raise ValidationError(f"AES-GCM nonce must be 12 bytes, got {len(nonce)}")

            # Import here to allow optional dependency
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            cipher = AESGCM(key_bytes)
            encrypted = cipher.encrypt(nonce, plaintext_bytes, associated_data)

            # Return nonce + ciphertext+tag
            return nonce + encrypted
        finally:
            # Zero copies if originals were SecureBytes
            _secure_cleanup(key, key_bytes)
            _secure_cleanup(plaintext, plaintext_bytes)

    def decrypt(
        self,
        key: Union[bytes, SecureBytes],
        ciphertext: bytes,
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
    ) -> SecureBytes:
        """
        Decrypts AES-256-GCM ciphertext.

        Args:
            ciphertext: nonce (12 bytes) + encrypted_data + tag (16 bytes)
        """
        self.check_available()

        # Convert SecureBytes to bytes for library
        key_bytes = _convert_to_bytes(key)

        try:
            # Validate key
            if len(key_bytes) != 32:
                raise ValidationError(f"AES-256-GCM requires 32-byte key, got {len(key_bytes)}")

            # Extract nonce if not provided separately
            if nonce is None:
                if len(ciphertext) < 12 + 16:  # nonce + minimum tag
                    raise ValidationError("Ciphertext too short")
                nonce = ciphertext[:12]
                ciphertext = ciphertext[12:]

            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            import cryptography.exceptions

            cipher = AESGCM(key_bytes)
            try:
                plaintext = cipher.decrypt(nonce, ciphertext, associated_data)
                return SecureBytes(plaintext)
            except cryptography.exceptions.InvalidTag:
                raise AuthenticationError("Authentication tag verification failed")
        finally:
            # Zero key copy if original was SecureBytes
            _secure_cleanup(key, key_bytes)


class AESGCMSIV(CipherBase):
    """
    AES-256-GCM-SIV - AES-GCM with Synthetic IV (nonce-misuse resistant).

    Recommended when nonce reuse is a concern. Slightly slower than GCM
    but provides additional security if nonces are accidentally repeated.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="aes-256-gcm-siv",
            display_name="AES-256-GCM-SIV",
            category=AlgorithmCategory.CIPHER,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.HIGH,
            description="AES-256-GCM-SIV - Nonce-misuse resistant AEAD",
            key_size=32,
            nonce_size=12,
            tag_size=16,
            block_size=16,
            aliases=("aes-gcm-siv", "aesgcmsiv"),
            references=("RFC 8452",),
        )

    @classmethod
    def get_key_size(cls) -> int:
        return 32

    def generate_nonce(self) -> bytes:
        return generate_random_bytes(12)

    def encrypt(self, key: Union[bytes, SecureBytes], plaintext: Union[bytes, SecureBytes],
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        self.check_available()

        if len(key) != 32:
            raise ValidationError(f"AES-256-GCM-SIV requires 32-byte key, got {len(key)}")

        if nonce is None:
            nonce = self.generate_nonce()

        if len(nonce) != 12:
            raise ValidationError(f"AES-GCM-SIV nonce must be 12 bytes, got {len(nonce)}")

        from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

        cipher = AESGCMSIV(key)
        encrypted = cipher.encrypt(nonce, plaintext, associated_data)

        return nonce + encrypted

    def decrypt(self, key: Union[bytes, SecureBytes], ciphertext: bytes,
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        self.check_available()

        if len(key) != 32:
            raise ValidationError(f"AES-256-GCM-SIV requires 32-byte key, got {len(key)}")

        if nonce is None:
            if len(ciphertext) < 12 + 16:
                raise ValidationError("Ciphertext too short")
            nonce = ciphertext[:12]
            ciphertext = ciphertext[12:]

        from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
        import cryptography.exceptions

        cipher = AESGCMSIV(key)
        try:
            return cipher.decrypt(nonce, ciphertext, associated_data)
        except cryptography.exceptions.InvalidTag:
            raise AuthenticationError("Authentication tag verification failed")


class AESSIV(CipherBase):
    """
    AES-256-SIV - AES with Synthetic IV (deterministic AEAD).

    Recommended for key-wrapping and scenarios requiring deterministic
    encryption. Does not use a separate nonce (IV is derived from plaintext).
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="aes-256-siv",
            display_name="AES-256-SIV",
            category=AlgorithmCategory.CIPHER,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.HIGH,
            description="AES-256-SIV - Deterministic AEAD for key wrapping",
            key_size=64,  # SIV mode requires 2 keys
            nonce_size=0,  # No explicit nonce (deterministic)
            tag_size=16,
            block_size=16,
            aliases=("aes-siv", "aessiv"),
            references=("RFC 5297",),
        )

    @classmethod
    def get_key_size(cls) -> int:
        return 64  # SIV uses 2 keys (64 bytes total for AES-256)

    def generate_nonce(self) -> SecureBytes:
        """SIV is deterministic, no nonce needed."""
        return b""

    def encrypt(self, key: Union[bytes, SecureBytes], plaintext: Union[bytes, SecureBytes],
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        self.check_available()

        if len(key) != 64:
            raise ValidationError(f"AES-256-SIV requires 64-byte key, got {len(key)}")

        from cryptography.hazmat.primitives.ciphers.aead import AESSIV

        cipher = AESSIV(key)
        # SIV takes AAD as a list
        aad_list = [associated_data] if associated_data else None
        return cipher.encrypt(plaintext, aad_list)

    def decrypt(self, key: Union[bytes, SecureBytes], ciphertext: bytes,
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        self.check_available()

        if len(key) != 64:
            raise ValidationError(f"AES-256-SIV requires 64-byte key, got {len(key)}")

        from cryptography.hazmat.primitives.ciphers.aead import AESSIV
        import cryptography.exceptions

        cipher = AESSIV(key)
        aad_list = [associated_data] if associated_data else None

        try:
            return cipher.decrypt(ciphertext, aad_list)
        except cryptography.exceptions.InvalidTag:
            raise AuthenticationError("Authentication tag verification failed")


class AESOCB3(CipherBase):
    """
    AES-256-OCB3 - Offset Codebook Mode v3 (DEPRECATED).

    ⚠️ DEPRECATED: Security concerns with short nonces.
    Use AES-GCM or AES-GCM-SIV instead.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="aes-256-ocb3",
            display_name="AES-256-OCB3 (DEPRECATED)",
            category=AlgorithmCategory.CIPHER,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.LEGACY,  # Deprecated
            description="AES-256-OCB3 - DEPRECATED due to security concerns with short nonces",
            key_size=32,
            nonce_size=12,
            tag_size=16,
            block_size=16,
            aliases=("aes-ocb3", "aesocb3"),
            references=("RFC 7253",),
        )

    @classmethod
    def get_key_size(cls) -> int:
        return 32

    def generate_nonce(self) -> bytes:
        return generate_random_bytes(12)

    def encrypt(self, key: Union[bytes, SecureBytes], plaintext: Union[bytes, SecureBytes],
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        self.check_available()

        # Issue deprecation warning
        import warnings
        warnings.warn(
            "AES-OCB3 is deprecated due to security concerns. Use AES-GCM instead.",
            DeprecationWarning,
            stacklevel=2
        )

        if len(key) != 32:
            raise ValidationError(f"AES-256-OCB3 requires 32-byte key, got {len(key)}")

        if nonce is None:
            nonce = self.generate_nonce()

        if len(nonce) != 12:
            raise ValidationError(f"AES-OCB3 nonce must be 12 bytes, got {len(nonce)}")

        from cryptography.hazmat.primitives.ciphers.aead import AESOCB3

        cipher = AESOCB3(key)
        encrypted = cipher.encrypt(nonce, plaintext, associated_data)

        return nonce + encrypted

    def decrypt(self, key: Union[bytes, SecureBytes], ciphertext: bytes,
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        self.check_available()

        if len(key) != 32:
            raise ValidationError(f"AES-256-OCB3 requires 32-byte key, got {len(key)}")

        if nonce is None:
            if len(ciphertext) < 12 + 16:
                raise ValidationError("Ciphertext too short")
            nonce = ciphertext[:12]
            ciphertext = ciphertext[12:]

        from cryptography.hazmat.primitives.ciphers.aead import AESOCB3
        import cryptography.exceptions

        cipher = AESOCB3(key)
        try:
            return cipher.decrypt(nonce, ciphertext, associated_data)
        except cryptography.exceptions.InvalidTag:
            raise AuthenticationError("Authentication tag verification failed")


# ============================================================================
# ChaCha20 Family
# ============================================================================

class ChaCha20Poly1305(CipherBase):
    """
    ChaCha20-Poly1305 - Stream cipher with Poly1305 MAC.

    Recommended for software-only implementations without AES hardware
    acceleration. Fast in software, constant-time.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="chacha20-poly1305",
            display_name="ChaCha20-Poly1305",
            category=AlgorithmCategory.CIPHER,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="ChaCha20-Poly1305 - Fast software AEAD cipher",
            key_size=32,
            nonce_size=12,
            tag_size=16,
            block_size=64,
            aliases=("chacha20", "chacha20poly1305"),
            references=("RFC 7539",),
        )

    @classmethod
    def get_key_size(cls) -> int:
        return 32

    def generate_nonce(self) -> bytes:
        return generate_random_bytes(12)

    def encrypt(self, key: Union[bytes, SecureBytes], plaintext: Union[bytes, SecureBytes],
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        self.check_available()

        if len(key) != 32:
            raise ValidationError(f"ChaCha20-Poly1305 requires 32-byte key, got {len(key)}")

        if nonce is None:
            nonce = self.generate_nonce()

        if len(nonce) != 12:
            raise ValidationError(f"ChaCha20-Poly1305 nonce must be 12 bytes, got {len(nonce)}")

        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as CryptoChaChaCipher

        cipher = CryptoChaChaCipher(key)
        encrypted = cipher.encrypt(nonce, plaintext, associated_data)

        return nonce + encrypted

    def decrypt(self, key: Union[bytes, SecureBytes], ciphertext: bytes,
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        self.check_available()

        if len(key) != 32:
            raise ValidationError(f"ChaCha20-Poly1305 requires 32-byte key, got {len(key)}")

        if nonce is None:
            if len(ciphertext) < 12 + 16:
                raise ValidationError("Ciphertext too short")
            nonce = ciphertext[:12]
            ciphertext = ciphertext[12:]

        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as CryptoChaChaCipher
        import cryptography.exceptions

        cipher = CryptoChaChaCipher(key)
        try:
            return cipher.decrypt(nonce, ciphertext, associated_data)
        except cryptography.exceptions.InvalidTag:
            raise AuthenticationError("Authentication tag verification failed")


class XChaCha20Poly1305(CipherBase):
    """
    XChaCha20-Poly1305 - Extended nonce ChaCha20-Poly1305.

    Recommended for long-lived keys where nonce space exhaustion is
    a concern. Uses 24-byte nonces (vs 12-byte for standard ChaCha20).

    Note: Uses HKDF to derive 12-byte nonce from 24-byte input for
    compatibility with cryptography library.
    """

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="xchacha20-poly1305",
            display_name="XChaCha20-Poly1305",
            category=AlgorithmCategory.CIPHER,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.HIGH,
            description="XChaCha20-Poly1305 - Extended nonce space for long-lived keys",
            key_size=32,
            nonce_size=24,  # Extended nonce
            tag_size=16,
            block_size=64,
            aliases=("xchacha20", "xchacha20poly1305"),
            references=("https://tools.ietf.org/id/draft-arciszewski-xchacha-03.html",),
        )

    @classmethod
    def get_key_size(cls) -> int:
        return 32

    def generate_nonce(self) -> bytes:
        return generate_random_bytes(24)

    def _process_nonce(self, key: bytes, nonce: bytes) -> SecureBytes:
        """
        Process 24-byte XChaCha20 nonce to 12-byte ChaCha20 nonce.

        Uses HKDF with SHA256 for secure nonce derivation.
        """
        if len(nonce) == 24:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            from cryptography.hazmat.backends import default_backend

            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=12,
                salt=nonce[:16],
                info=nonce[16:],
                backend=default_backend(),
            )
            return hkdf.derive(key)
        elif len(nonce) == 12:
            # Already correct size
            return nonce
        else:
            raise ValidationError(
                f"XChaCha20 nonce must be 24 bytes (or 12 for compat), got {len(nonce)}"
            )

    def encrypt(self, key: Union[bytes, SecureBytes], plaintext: Union[bytes, SecureBytes],
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        self.check_available()

        if len(key) != 32:
            raise ValidationError(f"XChaCha20-Poly1305 requires 32-byte key, got {len(key)}")

        if nonce is None:
            nonce = self.generate_nonce()

        # Store original nonce in output
        original_nonce = nonce
        processed_nonce = self._process_nonce(key, nonce)

        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        cipher = ChaCha20Poly1305(key)
        encrypted = cipher.encrypt(processed_nonce, plaintext, associated_data)

        # Return original nonce (24 bytes) + ciphertext+tag
        return original_nonce + encrypted

    def decrypt(self, key: Union[bytes, SecureBytes], ciphertext: bytes,
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        self.check_available()

        if len(key) != 32:
            raise ValidationError(f"XChaCha20-Poly1305 requires 32-byte key, got {len(key)}")

        # Extract nonce if not provided
        if nonce is None:
            if len(ciphertext) < 24 + 16:
                raise ValidationError("Ciphertext too short")
            nonce = ciphertext[:24]
            ciphertext = ciphertext[24:]

        processed_nonce = self._process_nonce(key, nonce)

        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        import cryptography.exceptions

        cipher = ChaCha20Poly1305(key)
        try:
            return cipher.decrypt(processed_nonce, ciphertext, associated_data)
        except cryptography.exceptions.InvalidTag:
            raise AuthenticationError("Authentication tag verification failed")


# ============================================================================
# Registry and convenience functions
# ============================================================================

class CipherRegistry(RegistryBase[CipherBase]):
    """Registry for symmetric cipher algorithms."""

    _default_instance: ClassVar[Optional['CipherRegistry']] = None

    def __init__(self):
        super().__init__()
        # Register all cipher implementations
        self.register(AES256GCM)
        self.register(AESGCMSIV)
        self.register(AESSIV)
        self.register(AESOCB3)
        self.register(ChaCha20Poly1305)
        self.register(XChaCha20Poly1305)

    @classmethod
    def default(cls) -> 'CipherRegistry':
        """Returns the default singleton registry instance."""
        if cls._default_instance is None:
            cls._default_instance = cls()
        return cls._default_instance


def get_cipher(name: str) -> CipherBase:
    """
    Convenience function to get a cipher instance.

    Args:
        name: Cipher name or alias

    Returns:
        Cipher instance

    Example:
        >>> cipher = get_cipher("aes-256-gcm")
        >>> ciphertext = cipher.encrypt(key, plaintext)
    """
    return CipherRegistry.default().get(name)
