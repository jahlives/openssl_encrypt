"""Cascade Encryption Module.

This module implements cascade encryption (multi-layer encryption) with chained
HKDF key derivation. Each layer encrypts the output of the previous layer using
a different cipher, with keys derived sequentially where each layer's key includes
entropy from the previous layer.

The chaining ensures that:
1. An attacker must break ALL ciphers to decrypt the data
2. Key derivation is sequential and cannot be parallelized
3. Each layer adds entropy to the next layer's key derivation

Example usage:
    from openssl_encrypt.modules.cascade import (
        CascadeConfig,
        CascadeEncryption,
        cascade_encrypt,
        cascade_decrypt
    )

    # Using the convenience functions
    plaintext = b"Secret message"
    master_key = secrets.token_bytes(32)
    cipher_names = ["aes-256-gcm", "chacha20-poly1305"]

    ciphertext, metadata = cascade_encrypt(
        plaintext, master_key, cipher_names, cascade_hash="sha256"
    )

    decrypted = cascade_decrypt(ciphertext, master_key, metadata)
    assert decrypted == plaintext
"""

import base64
import secrets
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .registry import get_cipher

# Domain separation prefixes for HKDF
KEY_INFO_PREFIX = b"cascade:key:"
NONCE_INFO_PREFIX = b"cascade:nonce:"
CHAIN_PREFIX_LENGTH = 16  # 128 bits from previous layer


class CascadeError(Exception):
    """Base exception for cascade encryption errors."""

    pass


class CascadeConfigError(CascadeError):
    """Exception raised for invalid cascade configuration."""

    pass


class AuthenticationError(CascadeError):
    """Exception raised when authentication fails during decryption."""

    pass


@dataclass
class CascadeConfig:
    """Configuration for cascade encryption.

    Attributes:
        cipher_names: List of cipher names in execution order (minimum 2)
        hkdf_hash: Hash function name for HKDF key derivation (default: "sha256")

    Raises:
        CascadeConfigError: If less than 2 ciphers are specified
    """

    cipher_names: List[str]
    hkdf_hash: str = "sha256"

    def __post_init__(self):
        """Validate the configuration after initialization."""
        if len(self.cipher_names) < 2:
            raise CascadeConfigError(
                f"Cascade requires at least 2 ciphers, got {len(self.cipher_names)}"
            )

    @property
    def layer_count(self) -> int:
        """Return the number of encryption layers."""
        return len(self.cipher_names)


class CascadeKeyDerivation:
    """Chained HKDF key derivation for cascade encryption.

    This class derives keys sequentially for each layer, where each layer's
    key derivation includes 128 bits from the previous layer's key. This
    creates a chain of dependencies that prevents parallel key derivation
    and adds entropy from each layer to the next.

    Key derivation schema:
        key_1 = HKDF(master_key, salt, info=b"cascade:key:aes-256-gcm")
        key_2 = HKDF(master_key, salt, info=b"cascade:key:chacha20:" || key_1[:16])
        key_3 = HKDF(master_key, salt, info=b"cascade:key:threefish:" || key_2[:16])
    """

    def __init__(self, config: CascadeConfig):
        """Initialize key derivation with the cascade configuration.

        Args:
            config: Cascade configuration with cipher names and hash function
        """
        self.config = config
        self.hash_algorithm = self._get_hash_algorithm(config.hkdf_hash)

    def _get_hash_algorithm(self, hash_name: str):
        """Get the cryptography hash algorithm object.

        Args:
            hash_name: Name of the hash function (sha256, sha384, sha512, etc.)

        Returns:
            Hash algorithm instance

        Raises:
            CascadeConfigError: If hash algorithm is not supported
        """
        hash_map = {
            "sha256": lambda: hashes.SHA256(),
            "sha384": lambda: hashes.SHA384(),
            "sha512": lambda: hashes.SHA512(),
            "sha3-256": lambda: hashes.SHA3_256(),
            "sha3-384": lambda: hashes.SHA3_384(),
            "sha3-512": lambda: hashes.SHA3_512(),
            "blake2b": lambda: hashes.BLAKE2b(64),  # 64 bytes = 512 bits
            "blake2s": lambda: hashes.BLAKE2s(32),  # 32 bytes = 256 bits
        }

        if hash_name.lower() not in hash_map:
            raise CascadeConfigError(
                f"Unsupported hash algorithm '{hash_name}'. "
                f"Supported: {', '.join(hash_map.keys())}"
            )

        return hash_map[hash_name.lower()]()

    def derive_layer_keys(
        self,
        master_key: bytes,
        salt: bytes,
    ) -> List[Tuple[bytes, bytes]]:
        """Derive keys and nonces for all layers using chained HKDF.

        Each layer's key derivation includes 128 bits from the previous layer's
        key in the info parameter, creating a chain of dependencies.

        Args:
            master_key: Master key material (e.g., from password derivation)
            salt: Salt for HKDF (should be random and unique per encryption)

        Returns:
            List of (key, nonce) tuples for each layer in order
        """
        layers = []
        previous_key_prefix = b""  # Empty for first layer

        for cipher_name in self.config.cipher_names:
            # Get cipher info to determine key and nonce sizes
            cipher = get_cipher(cipher_name)
            cipher_info = cipher.info()

            # Construct info parameter with chain prefix
            key_info = KEY_INFO_PREFIX + cipher_name.encode("utf-8") + previous_key_prefix
            nonce_info = NONCE_INFO_PREFIX + cipher_name.encode("utf-8") + previous_key_prefix

            # Derive key
            kdf_key = HKDF(
                algorithm=self.hash_algorithm,
                length=cipher_info.key_size,
                salt=salt,
                info=key_info,
                backend=default_backend(),
            )
            key = kdf_key.derive(master_key)

            # Derive nonce
            kdf_nonce = HKDF(
                algorithm=self.hash_algorithm,
                length=cipher_info.nonce_size,
                salt=salt,
                info=nonce_info,
                backend=default_backend(),
            )
            nonce = kdf_nonce.derive(master_key)

            layers.append((key, nonce))

            # Update chain prefix for next layer (first 128 bits of current key)
            previous_key_prefix = key[:CHAIN_PREFIX_LENGTH]

        return layers


class CascadeEncryption:
    """Cascade encryption implementation.

    Encrypts plaintext through multiple cipher layers sequentially. Each layer
    encrypts the output of the previous layer using a different cipher with
    independently derived keys.

    The encryption flow:
        plaintext → [Cipher 1] → [Cipher 2] → [Cipher 3] → ciphertext

    Decryption flow:
        ciphertext → [Cipher 3⁻¹] → [Cipher 2⁻¹] → [Cipher 1⁻¹] → plaintext

    Example:
        config = CascadeConfig(
            cipher_names=["aes-256-gcm", "chacha20-poly1305"],
            hkdf_hash="sha256"
        )
        cascade = CascadeEncryption(config)

        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)

        ciphertext = cascade.encrypt(plaintext, master_key, salt)
        decrypted = cascade.decrypt(ciphertext, master_key, salt)
    """

    def __init__(self, config: CascadeConfig):
        """Initialize cascade encryption with the given configuration.

        Args:
            config: Cascade configuration

        Raises:
            CascadeConfigError: If any cipher is not available
        """
        self.config = config
        self.key_derivation = CascadeKeyDerivation(config)

        # Validate all ciphers are available
        self.ciphers = []
        for cipher_name in config.cipher_names:
            try:
                cipher = get_cipher(cipher_name)
                self.ciphers.append(cipher)
            except Exception as e:
                raise CascadeConfigError(f"Cipher '{cipher_name}' is not available: {e}")

    def encrypt(
        self,
        plaintext: bytes,
        master_key: bytes,
        salt: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Encrypt plaintext through all cascade layers.

        Args:
            plaintext: Data to encrypt
            master_key: Master key material
            salt: Salt for key derivation
            associated_data: Optional additional authenticated data (AAD)

        Returns:
            Ciphertext from the final layer

        Raises:
            CascadeError: If encryption fails
        """
        # Derive keys for all layers
        layer_keys = self.key_derivation.derive_layer_keys(master_key, salt)

        # Encrypt through each layer sequentially
        data = plaintext
        for i, (cipher, (key, nonce)) in enumerate(zip(self.ciphers, layer_keys)):
            try:
                # Only the first layer uses AAD
                aad = associated_data if i == 0 else None
                data = cipher.encrypt(key, data, nonce=nonce, associated_data=aad)
            except Exception as e:
                raise CascadeError(
                    f"Encryption failed at layer {i + 1} ({self.config.cipher_names[i]}): {e}"
                )

        return data

    def decrypt(
        self,
        ciphertext: bytes,
        master_key: bytes,
        salt: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt ciphertext through all cascade layers in reverse.

        Args:
            ciphertext: Data to decrypt
            master_key: Master key material
            salt: Salt for key derivation
            associated_data: Optional additional authenticated data (AAD)

        Returns:
            Decrypted plaintext

        Raises:
            AuthenticationError: If authentication fails at any layer
            CascadeError: If decryption fails
        """
        # Derive keys for all layers
        layer_keys = self.key_derivation.derive_layer_keys(master_key, salt)

        # Decrypt through layers in reverse order
        data = ciphertext
        for i in range(len(self.ciphers) - 1, -1, -1):
            cipher = self.ciphers[i]
            key, nonce = layer_keys[i]

            try:
                # Only the first layer (last in decryption) uses AAD
                aad = associated_data if i == 0 else None
                # Don't pass nonce - let cipher extract it from ciphertext
                # (The nonce was prepended during encryption)
                data = cipher.decrypt(key, data, nonce=None, associated_data=aad)
            except Exception as e:
                # Check if it's an authentication error
                if "authentication" in str(e).lower() or "tag" in str(e).lower():
                    raise AuthenticationError(
                        f"Authentication failed at layer {i + 1} ({self.config.cipher_names[i]})"
                    )
                raise CascadeError(
                    f"Decryption failed at layer {i + 1} ({self.config.cipher_names[i]}): {e}"
                )

        return data

    def get_total_overhead(self) -> int:
        """Calculate total authentication tag overhead for all layers.

        Returns:
            Total size in bytes of all authentication tags
        """
        total = 0
        for cipher in self.ciphers:
            total += cipher.info().tag_size
        return total

    def get_security_info(self) -> Dict[str, Any]:
        """Get security information about the cascade configuration.

        Returns:
            Dictionary with security metrics:
                - layer_count: Number of encryption layers
                - ciphers: List of cipher names
                - min_security_bits: Minimum security level across all ciphers
                - pq_security_bits: Post-quantum security level (minimum across ciphers)
                - total_key_size: Sum of all key sizes
                - total_overhead: Sum of all authentication tags
        """
        min_security = min(cipher.info().security_bits for cipher in self.ciphers)
        pq_security = min(cipher.info().pq_security_bits for cipher in self.ciphers)
        total_key_size = sum(cipher.info().key_size for cipher in self.ciphers)

        return {
            "layer_count": len(self.ciphers),
            "ciphers": self.config.cipher_names,
            "min_security_bits": min_security,
            "pq_security_bits": pq_security,
            "total_key_size": total_key_size,
            "total_overhead": self.get_total_overhead(),
            "hkdf_hash": self.config.hkdf_hash,
        }


# Convenience functions


def cascade_encrypt(
    plaintext: bytes,
    master_key: bytes,
    cipher_names: List[str],
    cascade_hash: str = "sha256",
    associated_data: Optional[bytes] = None,
) -> Tuple[bytes, Dict[str, Any]]:
    """Convenience function for cascade encryption.

    Args:
        plaintext: Data to encrypt
        master_key: Master key material
        cipher_names: List of cipher names for cascade
        cascade_hash: Hash function for HKDF (default: sha256)
        associated_data: Optional AAD

    Returns:
        Tuple of (ciphertext, metadata_dict)

    Example:
        ciphertext, metadata = cascade_encrypt(
            b"secret",
            master_key,
            ["aes-256-gcm", "chacha20-poly1305"]
        )
    """
    # Generate random salt
    salt = secrets.token_bytes(32)

    # Create configuration
    config = CascadeConfig(cipher_names=cipher_names, hkdf_hash=cascade_hash)

    # Encrypt
    cascade = CascadeEncryption(config)
    ciphertext = cascade.encrypt(plaintext, master_key, salt, associated_data)

    # Build metadata
    security_info = cascade.get_security_info()
    layer_info = []
    for cipher in cascade.ciphers:
        info = cipher.info()
        layer_info.append(
            {
                "cipher": info.name,
                "key_size": info.key_size,
                "tag_size": info.tag_size,
            }
        )

    metadata = {
        "cascade": True,
        "cipher_chain": cipher_names,
        "hkdf_hash": cascade_hash,
        "cascade_salt": base64.b64encode(salt).decode("ascii"),
        "layer_info": layer_info,
        "total_overhead": security_info["total_overhead"],
        "pq_security_bits": security_info["pq_security_bits"],
    }

    return ciphertext, metadata


def cascade_decrypt(
    ciphertext: bytes,
    master_key: bytes,
    metadata: Dict[str, Any],
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Convenience function for cascade decryption.

    Args:
        ciphertext: Data to decrypt
        master_key: Master key material
        metadata: Metadata dictionary from cascade_encrypt
        associated_data: Optional AAD (must match encryption)

    Returns:
        Decrypted plaintext

    Example:
        plaintext = cascade_decrypt(ciphertext, master_key, metadata)
    """
    # Extract configuration from metadata
    cipher_names = metadata["cipher_chain"]
    cascade_hash = metadata.get("hkdf_hash", "sha256")
    salt = base64.b64decode(metadata["cascade_salt"])

    # Create configuration
    config = CascadeConfig(cipher_names=cipher_names, hkdf_hash=cascade_hash)

    # Decrypt
    cascade = CascadeEncryption(config)
    plaintext = cascade.decrypt(ciphertext, master_key, salt, associated_data)

    return plaintext
