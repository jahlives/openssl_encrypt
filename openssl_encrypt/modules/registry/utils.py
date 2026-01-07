#!/usr/bin/env python3
"""
Shared utilities for the Algorithm Registry System.

Common cryptographic utilities used across different registry types.
All code in English as per project requirements.
"""

import secrets
from typing import Optional


def generate_random_bytes(length: int) -> bytes:
    """
    Generates cryptographically secure random bytes.

    Args:
        length: Number of bytes to generate

    Returns:
        Random bytes of specified length

    Raises:
        ValueError: If length is negative
    """
    if length < 0:
        raise ValueError("Length must be non-negative")
    return secrets.token_bytes(length)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Performs constant-time comparison of two byte strings.

    This prevents timing attacks when comparing sensitive values
    like authentication tags or password hashes.

    Args:
        a: First byte string
        b: Second byte string

    Returns:
        True if the byte strings are equal, False otherwise
    """
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def pad_pkcs7(data: bytes, block_size: int) -> bytes:
    """
    Adds PKCS#7 padding to data.

    Args:
        data: Data to pad
        block_size: Block size in bytes (typically 16 for AES)

    Returns:
        Padded data

    Raises:
        ValueError: If block_size is invalid
    """
    if block_size < 1 or block_size > 255:
        raise ValueError("Block size must be between 1 and 255")

    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def unpad_pkcs7(data: bytes) -> bytes:
    """
    Removes PKCS#7 padding from data.

    Args:
        data: Padded data

    Returns:
        Unpadded data

    Raises:
        ValueError: If padding is invalid
    """
    if not data:
        raise ValueError("Cannot unpad empty data")

    padding_length = data[-1]

    if padding_length == 0 or padding_length > len(data):
        raise ValueError("Invalid padding length")

    # Verify all padding bytes are correct
    for i in range(padding_length):
        if data[-(i + 1)] != padding_length:
            raise ValueError("Invalid padding bytes")

    return data[:-padding_length]


def derive_salt_for_round(base_salt: bytes, round_number: int) -> bytes:
    """
    DEPRECATED: This function implements predictable salt derivation.

    WARNING: This method is deprecated due to security concerns.
    It allows attackers to precompute all round salts from the base salt.
    Use chained salt derivation (derive_salt_chained) instead.

    This function is maintained only for backward compatibility with
    format versions <= 8. It will be removed in version 2.0.

    For new code, use the previous round's output as the next round's salt
    to create a cryptographic dependency chain that prevents precomputation.

    Args:
        base_salt: Base salt value
        round_number: Round number (0-indexed)

    Returns:
        Derived salt (16 bytes)
    """
    import warnings

    warnings.warn(
        "derive_salt_for_round() is deprecated and insecure. "
        "Use chained salt derivation instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    import hashlib

    salt_material = hashlib.sha256(base_salt + str(round_number).encode()).digest()
    return salt_material[:16]


def derive_salt_chained(previous_output: bytes, length: int = 16) -> bytes:
    """
    Derives salt from previous round output (chained derivation).

    This is the SECURE method for multi-round salt derivation introduced in format version 9.
    Each round uses the first `length` bytes of the previous round's output as its salt,
    creating a cryptographic dependency chain that prevents precomputation attacks.

    Unlike derive_salt_for_round(), this method makes it impossible for attackers to
    precompute round salts without first computing all previous rounds, significantly
    strengthening security in multi-round KDF operations.

    Args:
        previous_output: Output from previous cryptographic operation
        length: Desired salt length in bytes (default: 16)

    Returns:
        Derived salt (first `length` bytes of previous_output)

    Raises:
        ValueError: If previous_output is shorter than the requested length

    Example:
        >>> # Round 0 uses base_salt
        >>> round_0_output = kdf(password, base_salt)
        >>> # Round 1 uses first 16 bytes of round 0 output as salt
        >>> round_1_salt = derive_salt_chained(round_0_output)
        >>> round_1_output = kdf(round_0_output, round_1_salt)
    """
    if len(previous_output) < length:
        raise ValueError(
            f"Previous output too short: {len(previous_output)} bytes < {length} bytes required"
        )
    return previous_output[:length]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XORs two byte strings of equal length.

    Args:
        a: First byte string
        b: Second byte string

    Returns:
        XORed result

    Raises:
        ValueError: If lengths don't match
    """
    if len(a) != len(b):
        raise ValueError(f"Length mismatch: {len(a)} != {len(b)}")

    return bytes(x ^ y for x, y in zip(a, b))


def split_buffer(data: bytes, *sizes: int) -> tuple:
    """
    Splits a byte buffer into multiple parts of specified sizes.

    Args:
        data: Data to split
        *sizes: Sizes of each part in bytes

    Returns:
        Tuple of byte strings

    Raises:
        ValueError: If total size exceeds data length

    Example:
        >>> data = b'0123456789'
        >>> nonce, key, tag = split_buffer(data, 4, 4, 2)
        >>> nonce
        b'0123'
        >>> key
        b'4567'
        >>> tag
        b'89'
    """
    total_size = sum(sizes)
    if total_size > len(data):
        raise ValueError(f"Total size {total_size} exceeds data length {len(data)}")

    result = []
    offset = 0
    for size in sizes:
        result.append(data[offset : offset + size])
        offset += size

    return tuple(result)


def format_bytes_hex(data: bytes, max_length: Optional[int] = 32) -> str:
    """
    Formats bytes as hex string with optional truncation.

    Useful for logging and debugging without exposing full sensitive values.

    Args:
        data: Bytes to format
        max_length: Maximum number of bytes to show (None for all)

    Returns:
        Hex string representation

    Example:
        >>> format_bytes_hex(b'0123456789', max_length=4)
        '30313233...'
    """
    if max_length is not None and len(data) > max_length:
        return data[:max_length].hex() + "..."
    return data.hex()


def safe_memzero(data: bytearray) -> None:
    """
    Safely zeros out memory containing sensitive data.

    Note: This is a best-effort attempt. For true secure memory
    handling, use the secure_memory module's SecureBytes.

    Args:
        data: Bytearray to zero out
    """
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
