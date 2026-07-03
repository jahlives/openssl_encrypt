#!/usr/bin/env python3
"""
Secure Cryptographic Operations Module

This module provides centralized and standardized implementations of security-critical
operations to ensure that they're implemented correctly and consistently throughout
the codebase. These include constant-time comparison, secure memory handling, and
other operations that need to be resilient against side-channel attacks.
"""

import secrets
import threading
import time
from typing import Any, Optional, Union

# Import from local modules
from .crypt_errors import add_timing_jitter
from .secure_ops_core import (
    constant_time_bytes_eq,
    constant_time_compare_core,
    constant_time_mac_verify,
    is_zeroed_constant_time,
    secure_value_wipe,
)


def constant_time_compare(
    a: Union[bytes, bytearray, memoryview, str], b: Union[bytes, bytearray, memoryview, str]
) -> bool:
    """
    Perform a constant-time comparison of two byte sequences.

    This function ensures that the comparison takes exactly the same amount
    of time regardless of how similar the sequences are, to prevent timing
    side-channel attacks.

    Args:
        a: First sequence (bytes, bytearray, memoryview, or str)
        b: Second sequence (bytes, bytearray, memoryview, or str)

    Returns:
        bool: True if the sequences match, False otherwise
    """
    # Add a small random delay to mask timing differences
    add_timing_jitter(1, 3)  # 1-3ms

    # Handle None values securely
    if a is None and b is None:
        return True
    if a is None or b is None:
        # Still perform a comparison to maintain timing consistency
        # but ensure False return if only one input is None
        a = b"" if a is None else a
        b = b"" if b is None else b

    # Convert to bytes if not already
    if isinstance(a, str):
        a_bytes = a.encode("utf-8")
    else:
        a_bytes = bytes(a)

    if isinstance(b, str):
        b_bytes = b.encode("utf-8")
    else:
        b_bytes = bytes(b)

    # Use our optimized core implementation
    result = constant_time_compare_core(a_bytes, b_bytes)

    # Add another small delay to mask the processing time
    add_timing_jitter(1, 3)  # 1-3ms

    return result


def constant_time_pkcs7_unpad(padded_data: bytes, block_size: int = 16) -> tuple:
    """
    Perform PKCS#7 unpadding in constant time to prevent padding oracle attacks.

    This function ensures that the unpadding operation takes the same amount
    of time regardless of whether the padding is valid or not, to prevent
    timing side-channel attacks that could be used in padding oracle attacks.

    Args:
        padded_data: The padded data to unpad
        block_size: The block size used for padding (default is 16 bytes)

    Returns:
        tuple: (unpadded_data, is_valid_padding)

    Note:
        Unlike standard PKCS#7 unpadding which raises exceptions for invalid
        padding, this function returns a tuple with the potentially unpadded
        data and a boolean indicating if the padding was valid.
    """
    # Add a small random delay to further mask timing differences
    add_timing_jitter(1, 5)  # 1-5ms

    # Handle None or empty input data (public information — the length of
    # the ciphertext is not secret, so branching on it is fine)
    if padded_data is None or len(padded_data) == 0:
        return b"", False

    # Convert to bytes if needed
    if not isinstance(padded_data, bytes):
        padded_data = bytes(padded_data)

    data_len = len(padded_data)
    last_byte = padded_data[-1]

    # Branchless validity (#90): every secret-derived condition is folded
    # into 0/1 integers and applied as arithmetic masks — no Python if/else
    # keyed on padding bytes. (CPython can never be strictly constant-time;
    # this removes the data-dependent control flow the old code had.)
    #
    # in_range also requires last_byte <= data_len: the old code skipped
    # padding verification entirely when the claimed padding length
    # exceeded the data length, accepting invalid padding as valid.
    in_range = int(last_byte >= 1) & int(last_byte <= block_size) & int(last_byte <= data_len)
    padding_len = last_byte * in_range

    # Verify the trailing padding bytes over a FIXED number of iterations
    # (block_size), masking out positions that are not padding.
    mismatch = 0
    for i in range(block_size):
        idx = data_len - 1 - i
        idx_valid = int(idx >= 0)
        # Clamp the index so every iteration performs a lookup; masked-out
        # iterations read byte 0 and contribute nothing.
        safe_idx = idx * idx_valid
        byte = padded_data[safe_idx]
        is_padding_pos = int(i < padding_len) & idx_valid
        # -is_padding_pos is 0 or -1 (all ones): a full mask for the XOR
        mismatch |= (byte ^ last_byte) & -is_padding_pos

    is_valid_int = in_range & int(mismatch == 0)

    # Arithmetic mask instead of a conditional for the unpadded length
    unpadded_len = data_len - padding_len * is_valid_int
    unpadded_data = padded_data[:unpadded_len]

    # Add another small delay to mask the processing time
    add_timing_jitter(1, 5)  # 1-5ms

    return unpadded_data, bool(is_valid_int)


def secure_memzero(data: bytearray) -> None:
    """
    Securely wipe data from memory.

    This function attempts to securely wipe sensitive data from memory
    to prevent it from remaining in memory dumps or swap files.

    Args:
        data: The bytearray to zero out

    Note:
        Due to garbage collection and memory management optimizations in Python,
        this cannot guarantee complete removal from all memory. However, it
        significantly reduces the risk by ensuring immediate overwriting.
    """
    # Check if input is empty or None
    if data is None or len(data) == 0:
        return

    # Use our optimized core implementation for better performance
    secure_value_wipe(data)

    # Additionally, we can force garbage collection to help ensure
    # that our wiped data is not hanging around in memory
    import gc

    gc.collect()


def verify_mac(
    expected_mac: Union[bytes, bytearray, memoryview],
    received_mac: Union[bytes, bytearray, memoryview],
) -> bool:
    """
    Verify a message authentication code (MAC) in constant time.

    This function provides a secure way to verify MACs with protection
    against timing attacks. It should be used for all HMAC and authenticated
    encryption tag verifications.

    Any associated data must be bound into the MAC computation by the
    caller (e.g. included in the HMAC input); this function only compares
    the two MAC values.

    Args:
        expected_mac: The expected MAC value (computed)
        received_mac: The received MAC value (to verify)

    Returns:
        bool: True if the MACs match, False otherwise
    """
    # Add small timing jitter
    add_timing_jitter(1, 3)  # 1-3ms

    # Handle None values securely
    if expected_mac is None and received_mac is None:
        return True
    elif expected_mac is None or received_mac is None:
        return False

    # Convert to bytes if needed
    expected_bytes = bytes(expected_mac)
    received_bytes = bytes(received_mac)

    # Always use constant-time comparison to prevent timing attacks
    result = constant_time_mac_verify(expected_bytes, received_bytes)

    # Add final timing jitter
    add_timing_jitter(1, 3)  # 1-3ms

    return result


class SecureContainer:
    """
    Secure container for sensitive data like passwords and keys.

    This class provides a way to store sensitive data in memory with
    extra protection. It automatically wipes the data when it's no longer needed.
    It supports various data types and implements basic context manager protocol.
    """

    def __init__(self, data: Optional[Union[bytes, bytearray, str, int, list, dict]] = None):
        """
        Initialize a secure container for sensitive data.

        Args:
            data: Initial data to store in the container. Supports various types including:
                 bytes, bytearray, str, int, list, and dict.
        """
        self._data = bytearray()
        if data is not None:
            self.set(data)

    def __del__(self):
        """Securely wipe data when object is garbage collected."""
        self.clear()

    def __enter__(self):
        """Support for context manager protocol."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Securely wipe data when exiting context."""
        self.clear()
        return False  # Don't suppress exceptions

    def clear(self) -> None:
        """Securely wipe the contained data."""
        secure_memzero(self._data)
        # Reinitialize to empty bytearray after zeroing
        self._data = bytearray()

    def get(self) -> bytes:
        """Get the stored data as bytes."""
        return bytes(self._data)

    def get_as_str(self) -> str:
        """Get the stored data as a string, assuming UTF-8 encoding."""
        return self._data.decode("utf-8")

    def get_as_int(self) -> int:
        """Get the stored data as an integer."""
        return int.from_bytes(self._data, byteorder="big")

    def get_as_object(self):
        """Get the stored data as a Python object, assuming JSON encoding."""
        import json

        return json.loads(self.get_as_str())

    def set(self, data: Union[bytes, bytearray, str, int, list, dict]) -> None:
        """
        Set new data, securely wiping the old data.

        Args:
            data: New data to store. Supports various types including:
                 bytes, bytearray, str, int, list, and dict.
        """
        # Clear existing data
        self.clear()

        # Handle different data types
        if isinstance(data, (bytes, bytearray)):
            self._data = bytearray(data)
        elif isinstance(data, str):
            self._data = bytearray(data.encode("utf-8"))
        elif isinstance(data, int):
            # Store integers as big-endian bytes
            byte_length = max(1, (data.bit_length() + 7) // 8)
            self._data = bytearray(data.to_bytes(byte_length, byteorder="big"))
        elif isinstance(data, (list, dict)):
            # Convert more complex objects to JSON
            import json

            json_str = json.dumps(data)
            self._data = bytearray(json_str.encode("utf-8"))
        elif data is None:
            # Initialize as empty
            self._data = bytearray()
        else:
            raise TypeError(f"Unsupported data type: {type(data)}")

    def append(self, data: Union[bytes, bytearray, str, int]) -> None:
        """
        Append data to the existing container content.

        Args:
            data: Data to append. Supports bytes, bytearray, str, and int.
        """
        if isinstance(data, (bytes, bytearray)):
            self._data.extend(data)
        elif isinstance(data, str):
            self._data.extend(data.encode("utf-8"))
        elif isinstance(data, int):
            # Single integer value gets appended as a byte
            self._data.append(data & 0xFF)
        else:
            raise TypeError(f"Cannot append data of type: {type(data)}")

    def __len__(self) -> int:
        """Get the length of the stored data in bytes."""
        return len(self._data)

    def __bool__(self) -> bool:
        """Return True if the container has data, False otherwise."""
        return len(self._data) > 0

    def __eq__(self, other) -> bool:
        """Compare this container's contents with another value in constant time."""
        if isinstance(other, SecureContainer):
            return constant_time_compare(self._data, other._data)
        elif isinstance(other, (bytes, bytearray)):
            return constant_time_compare(self._data, other)
        elif isinstance(other, str):
            return constant_time_compare(self._data, other.encode("utf-8"))
        return False
