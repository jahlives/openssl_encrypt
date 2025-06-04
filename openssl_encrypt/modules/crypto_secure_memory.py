#!/usr/bin/env python3
"""
Cryptographic Secure Memory Module

This module provides cryptographic-specific secure memory utilities that use
the secure allocator to protect sensitive data like keys, IVs, passwords,
and other cryptographic material. It offers a high-level API for common
cryptographic memory operations with enhanced security protections.
"""

import contextlib
import os
import secrets
import sys
from typing import Any, BinaryIO, Callable, Dict, List, Optional, Tuple, Union

# Import secure error handling
from .crypt_errors import KeyDerivationError
from .crypt_errors import MemoryError as SecureMemoryError
from .crypt_errors import secure_key_derivation_error_handler, secure_memory_error_handler

# Import from secure_allocator module
from .secure_allocator import (
    SecureBytes,
    allocate_secure_crypto_buffer,
    check_all_crypto_buffer_integrity,
    free_secure_crypto_buffer,
)


class CryptoSecureBuffer:
    """
    A secure buffer specifically designed for cryptographic material.

    This class provides a secure memory container with specific protections
    for cryptographic material like keys, IVs, and passwords. It includes
    functionality for common cryptographic operations.
    """

    @secure_memory_error_handler
    def __init__(
        self, size: Optional[int] = None, data: Optional[Union[bytes, bytearray, str]] = None
    ):
        """
        Initialize a secure cryptographic buffer.

        Args:
            size: Size in bytes to allocate (ignored if data is provided)
            data: Initial data to store (if provided, size is determined from data)

        Either size or data must be provided, but not both.
        """
        if size is not None and data is not None:
            raise SecureMemoryError(
                "Cannot specify both size and data", "Size and data both provided"
            )

        if data is not None:
            # Determine size from data
            if isinstance(data, str):
                byte_data = data.encode("utf-8")
                size = len(byte_data)
            elif isinstance(data, (bytes, bytearray)):
                byte_data = data
                size = len(byte_data)
            else:
                raise SecureMemoryError(
                    "Invalid data type", f"Data must be bytes, bytearray, or str, got {type(data)}"
                )
        else:
            if size is None:
                raise SecureMemoryError(
                    "Missing required parameter", "Either size or data must be provided"
                )
            byte_data = None

        # Allocate the secure buffer
        self.block_id, self.buffer = allocate_secure_crypto_buffer(size, zero=(data is None))

        # If data was provided, copy it to the buffer
        if byte_data is not None:
            self.buffer[:] = byte_data

    def __del__(self):
        """Ensure the buffer is properly freed when the object is destroyed."""
        try:
            self.clear()
        except (TypeError, AttributeError):
            # Silence errors during garbage collection
            pass

    def clear(self):
        """Explicitly clear and free the buffer."""
        if hasattr(self, "block_id") and hasattr(self, "buffer") and self.buffer is not None:
            try:
                # Clear the buffer data
                for i in range(len(self.buffer)):
                    self.buffer[i] = 0

                # Free the block
                free_secure_crypto_buffer(self.block_id)
            except (TypeError, AttributeError):
                # Handle any errors during cleanup
                pass
            finally:
                # Remove attributes to prevent accidental use after clearing
                self.block_id = None
                self.buffer = None

    @secure_memory_error_handler
    def get_bytes(self) -> bytes:
        """Get a copy of the buffer contents as bytes (use with caution)."""
        if self.buffer is None:
            raise SecureMemoryError("Buffer not available", "Buffer has been cleared")
        return bytes(self.buffer)

    @secure_memory_error_handler
    def get_bytearray(self) -> bytearray:
        """Get a copy of the buffer contents as bytearray (use with caution)."""
        if self.buffer is None:
            raise SecureMemoryError("Buffer not available", "Buffer has been cleared")
        return bytearray(self.buffer)

    @secure_memory_error_handler
    def get_as_str(self) -> str:
        """Get the buffer contents as a string, assuming UTF-8 encoding (use with caution)."""
        if self.buffer is None:
            raise SecureMemoryError("Buffer not available", "Buffer has been cleared")
        return self.buffer.decode("utf-8")

    def check_integrity(self) -> bool:
        """
        Check if the buffer's memory integrity is intact.

        Returns:
            bool: True if integrity check passed, False otherwise
        """
        if not hasattr(self, "buffer") or self.buffer is None:
            return False
        return self.buffer.check_integrity()

    def __enter__(self):
        """Support for use as a context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up when exiting context."""
        self.clear()
        # Don't suppress exceptions
        return False

    def __len__(self):
        """Get the length of the buffer in bytes."""
        if self.buffer is None:
            return 0
        return len(self.buffer)


class CryptoKey(CryptoSecureBuffer):
    """
    A secure container specifically for cryptographic keys.

    This class extends CryptoSecureBuffer with key-specific functionality
    and enhanced protection mechanisms appropriate for key material.
    """

    def __init__(
        self,
        key_data: Optional[Union[bytes, bytearray, str]] = None,
        key_size: Optional[int] = None,
    ):
        """
        Initialize a secure cryptographic key.

        Args:
            key_data: The key material, or None to generate a random key
            key_size: Size of the key in bytes (required if key_data is None)
        """
        if key_data is None and key_size is None:
            raise ValueError("Either key_data or key_size must be provided")

        if key_data is None:
            # Generate a random key of the specified size
            super().__init__(size=key_size)
            self._fill_random()
        else:
            # Use the provided key data
            super().__init__(data=key_data)

    def _fill_random(self):
        """Fill the buffer with cryptographically secure random bytes."""
        random_data = secrets.token_bytes(len(self.buffer))
        for i in range(len(self.buffer)):
            self.buffer[i] = random_data[i]

        # Clear the temporary random data to avoid leaving traces
        random_data = None

    def derive_subkey(self, info: bytes, length: int) -> "CryptoKey":
        """
        Derive a subkey from this key using HKDF-like approach.

        Args:
            info: Context and application specific information
            length: Length of the derived key in bytes

        Returns:
            CryptoKey: A new key derived from this key
        """
        try:
            # Import HKDF from cryptography if available
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF

            # Get the current key material (temporarily)
            key_material = self.get_bytes()

            # Derive the new key
            hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
            derived_key = hkdf.derive(key_material)

            # Clear the temporary copy of the key material
            key_material = None

            # Create a new key with the derived material
            result = CryptoKey(key_data=derived_key)

            # Clear the derived key bytes (which are immutable)
            derived_key = None

            return result

        finally:
            # Ensure cleanup in case of exception
            if "key_material" in locals() and key_material is not None:
                # Try to clear if still exists - use secure_memzero if possible
                try:
                    from ..modules.secure_memory import secure_memzero

                    if isinstance(key_material, bytearray):
                        secure_memzero(key_material)
                except:
                    key_material = None
                finally:
                    key_material = None

            if "derived_key" in locals() and derived_key is not None:
                # Since bytes are immutable, we just remove the reference
                derived_key = None


class CryptoIV(CryptoSecureBuffer):
    """
    A secure container specifically for initialization vectors and nonces.

    This class extends CryptoSecureBuffer with IV/nonce-specific functionality.
    """

    def __init__(self, iv_size: int, random: bool = True):
        """
        Initialize a secure cryptographic IV or nonce.

        Args:
            iv_size: Size of the IV/nonce in bytes
            random: Whether to fill with random bytes (True) or zeros (False)
        """
        super().__init__(size=iv_size)

        if random:
            self._fill_random()

    def _fill_random(self):
        """Fill the buffer with cryptographically secure random bytes."""
        random_data = secrets.token_bytes(len(self.buffer))
        for i in range(len(self.buffer)):
            self.buffer[i] = random_data[i]

        # Clear the temporary random data
        random_data = None


@contextlib.contextmanager
def secure_crypto_buffer(size: int) -> CryptoSecureBuffer:
    """
    Context manager for a secure cryptographic buffer.

    Args:
        size: Size of the buffer in bytes

    Yields:
        CryptoSecureBuffer: A secure buffer that will be automatically cleared
    """
    buffer = CryptoSecureBuffer(size=size)
    try:
        yield buffer
    finally:
        buffer.clear()


@contextlib.contextmanager
def secure_crypto_key(
    key_data: Optional[Union[bytes, bytearray, str]] = None, key_size: Optional[int] = None
) -> CryptoKey:
    """
    Context manager for a secure cryptographic key.

    Args:
        key_data: The key material, or None to generate a random key
        key_size: Size of the key in bytes (required if key_data is None)

    Yields:
        CryptoKey: A secure key that will be automatically cleared
    """
    key = CryptoKey(key_data=key_data, key_size=key_size)
    try:
        yield key
    finally:
        key.clear()


@contextlib.contextmanager
def secure_crypto_iv(iv_size: int, random: bool = True) -> CryptoIV:
    """
    Context manager for a secure cryptographic IV or nonce.

    Args:
        iv_size: Size of the IV/nonce in bytes
        random: Whether to fill with random bytes (True) or zeros (False)

    Yields:
        CryptoIV: A secure IV that will be automatically cleared
    """
    iv = CryptoIV(iv_size=iv_size, random=random)
    try:
        yield iv
    finally:
        iv.clear()


@secure_memory_error_handler
def generate_secure_key(key_size: int) -> CryptoKey:
    """
    Generate a new secure random key of the specified size.

    Args:
        key_size: Size of the key in bytes

    Returns:
        CryptoKey: A new secure random key
    """
    return CryptoKey(key_size=key_size)


@secure_key_derivation_error_handler
def create_key_from_password(
    password: Union[str, bytes, bytearray],
    salt: bytes,
    key_size: int,
    hash_iterations: int = 100000,
) -> CryptoKey:
    """
    Create a secure key from a password using a key derivation function.

    Args:
        password: The password to derive the key from
        salt: Salt value for the KDF
        key_size: Size of the derived key in bytes
        hash_iterations: Number of iterations for the KDF

    Returns:
        CryptoKey: A secure key derived from the password
    """
    try:
        # Import key derivation function
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        # Convert password to bytes if needed
        if isinstance(password, str):
            password_bytes = password.encode("utf-8")
        else:
            password_bytes = password

        # Derive the key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=salt,
            iterations=hash_iterations,
        )
        derived_key = kdf.derive(password_bytes)

        # Create a secure key from the derived material
        result = CryptoKey(key_data=derived_key)

        # Clear the derived key bytes (which are immutable)
        derived_key = None

        return result

    finally:
        # Clean up sensitive data
        if "password_bytes" in locals() and password_bytes is not None:
            # For strings, just remove the reference
            password_bytes = None

        if "derived_key" in locals() and derived_key is not None:
            # Since bytes are immutable, we just remove the reference
            derived_key = None


@secure_memory_error_handler
def validate_crypto_memory_integrity() -> bool:
    """
    Validate the integrity of all cryptographic memory allocations.

    This function performs a comprehensive check of all secure memory
    allocations used for cryptographic operations to detect any
    tampering or memory corruption.

    Returns:
        bool: True if all memory integrity checks pass, False otherwise
    """
    return check_all_crypto_buffer_integrity()
