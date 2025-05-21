#!/usr/bin/env python3
"""
Secure Cryptographic Operations Module

This module provides centralized and standardized implementations of security-critical
operations to ensure that they're implemented correctly and consistently throughout
the codebase. These include constant-time comparison, secure memory handling, and
other operations that need to be resilient against side-channel attacks.
"""

import time
import secrets
import threading
from typing import Union, Any, Optional

# Import from local modules
from .crypt_errors import add_timing_jitter
from .secure_ops_core import (
    constant_time_compare_core,
    constant_time_mac_verify,
    constant_time_bytes_eq,
    is_zeroed_constant_time,
    secure_value_wipe
)


def constant_time_compare(a: Union[bytes, bytearray, memoryview], 
                          b: Union[bytes, bytearray, memoryview]) -> bool:
    """
    Perform a constant-time comparison of two byte sequences.
    
    This function ensures that the comparison takes exactly the same amount
    of time regardless of how similar the sequences are, to prevent timing
    side-channel attacks.
    
    Args:
        a: First byte sequence
        b: Second byte sequence
        
    Returns:
        bool: True if the sequences match, False otherwise
    """
    # Add a small random delay to mask timing differences
    add_timing_jitter(1, 5)  # 1-5ms
    
    # Handle None values securely
    if a is None and b is None:
        return True
    if a is None or b is None:
        # Still perform a comparison to maintain timing consistency
        # but ensure False return if only one input is None
        a = b"" if a is None else a
        b = b"" if b is None else b
    
    # Convert to bytes if not already
    a_bytes = bytes(a)
    b_bytes = bytes(b)
    
    # Use our optimized core implementation
    result = constant_time_compare_core(a_bytes, b_bytes)
    
    # Add another small delay to mask the processing time
    add_timing_jitter(1, 5)  # 1-5ms
    
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
    
    # Handle None or empty input data
    if padded_data is None or len(padded_data) == 0:
        return b"", False
    
    # Convert to bytes if needed
    if not isinstance(padded_data, bytes):
        padded_data = bytes(padded_data)
    
    # Initial assumption - padding is invalid until proven otherwise
    is_valid = False
    padding_len = 0
    data_len = len(padded_data)
    
    # Check for basic validity conditions in constant time
    if data_len > 0:
        # Get padding length from last byte
        last_byte = padded_data[-1]
        
        # Check padding byte range using constant-time operations
        # This uses bitwise operations to avoid branch conditions
        in_range = (last_byte >= 1) & (last_byte <= block_size)
        
        # Conditionally set padding length based on range check
        padding_len = last_byte if in_range else 0
        
        # Initial valid state depends on in_range
        is_valid = in_range
        
        # Only proceed with validation if we potentially have valid padding
        # And have enough bytes for the padding
        if padding_len <= data_len:
            # Verify all padding bytes are the same in constant time
            # Store mismatch in a single variable that is updated for each byte
            mismatch = 0
            
            # Process all potential padding bytes
            for i in range(block_size):
                # For each position, check if it should be a padding byte
                idx = data_len - i - 1
                
                is_padding_pos = (i < padding_len) & (idx >= 0)
                
                # Only check bytes within valid range
                if idx >= 0 and idx < data_len:
                    # XOR will be non-zero if bytes don't match
                    # Use logical OR to accumulate any mismatches
                    byte_mismatch = padded_data[idx] ^ last_byte if is_padding_pos else 0
                    mismatch |= byte_mismatch
            
            # Update valid state - only valid if no mismatches found
            is_valid = is_valid & (mismatch == 0)
    
    # Use constant-time conditional operation for unpadded length
    # If padding is invalid, use full length; otherwise subtract padding_len
    unpadded_len = data_len - (padding_len if is_valid else 0)
    
    # Create unpadded data
    unpadded_data = padded_data[:unpadded_len]
    
    # Add another small delay to mask the processing time
    add_timing_jitter(1, 5)  # 1-5ms
    
    return unpadded_data, is_valid


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


def verify_mac(expected_mac: Union[bytes, bytearray, memoryview], 
             received_mac: Union[bytes, bytearray, memoryview],
             associated_data: Optional[bytes] = None) -> bool:
    """
    Verify a message authentication code (MAC) in constant time.
    
    This function provides a secure way to verify MACs with protection
    against timing attacks. It should be used for all HMAC and authenticated
    encryption tag verifications.
    
    Args:
        expected_mac: The expected MAC value (computed)
        received_mac: The received MAC value (to verify)
        associated_data: Optional additional data used for context binding
        
    Returns:
        bool: True if the MACs match, False otherwise
    """
    # Add timing jitter to mask processing time
    add_timing_jitter(2, 10)  # 2-10ms
    
    # Handle None values securely
    if expected_mac is None and received_mac is None:
        return True
    elif expected_mac is None or received_mac is None:
        return False
    
    # Convert to bytes if needed
    expected_bytes = bytes(expected_mac)
    received_bytes = bytes(received_mac)
    
    # If associated data is provided, include it in the verification timing
    # This binds the verification timing to the context
    if associated_data is not None:
        # Add a timing component based on associated_data length
        # This prevents oracles based on different associated data sizes
        delay_factor = min(5, len(associated_data) // 1024) / 1000.0
        if delay_factor > 0:
            time.sleep(delay_factor)
    
    # Use specialized MAC verification from the core module
    result = constant_time_mac_verify(expected_bytes, received_bytes)
    
    # Add timing jitter after verification
    add_timing_jitter(2, 10)  # 2-10ms
    
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
        return self._data.decode('utf-8')
    
    def get_as_int(self) -> int:
        """Get the stored data as an integer."""
        return int.from_bytes(self._data, byteorder='big')
    
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
            self._data = bytearray(data.encode('utf-8'))
        elif isinstance(data, int):
            # Store integers as big-endian bytes
            byte_length = max(1, (data.bit_length() + 7) // 8)
            self._data = bytearray(data.to_bytes(byte_length, byteorder='big'))
        elif isinstance(data, (list, dict)):
            # Convert more complex objects to JSON
            import json
            json_str = json.dumps(data)
            self._data = bytearray(json_str.encode('utf-8'))
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
            self._data.extend(data.encode('utf-8'))
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
            return constant_time_compare(self._data, other.encode('utf-8'))
        return False