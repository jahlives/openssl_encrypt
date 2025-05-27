#!/usr/bin/env python3
"""
Secure Cryptographic Core Operations Module

This module provides optimized and performance-critical constant-time operations
that are essential for cryptographic security. These implementations focus on
maximum performance while maintaining security against timing side-channels.

The operations in this module avoid branching on sensitive data, variable-time
operations, and other potential sources of timing leaks. This is a specialized
module that should not be used directly; instead use the secure_ops.py module
which provides a more comprehensive and easy-to-use API with proper validation.
"""

import hmac
import secrets
import time
from typing import Union, Any, Optional


def constant_time_compare_core(a: bytes, b: bytes) -> bool:
    """
    Perform a raw constant-time comparison of two byte sequences.
    
    This is a performance-critical internal implementation that assumes
    inputs are already validated. For general use, use the constant_time_compare
    function in secure_ops.py instead.
    
    Args:
        a: First byte sequence (must be bytes, not bytearray or memoryview)
        b: Second byte sequence (must be bytes, not bytearray or memoryview)
        
    Returns:
        bool: True if the sequences match, False otherwise
        
    Warning:
        This function assumes inputs are already validated to be of the correct type.
        Using improper inputs could lead to security vulnerabilities.
    """
    # Prefer native implementation when available for best performance
    # hmac.compare_digest is implemented in C and highly optimized
    try:
        return hmac.compare_digest(a, b)
    except (ImportError, AttributeError):
        # If native implementation is not available, use our own
        if len(a) != len(b):
            return False
        
        # Use integer arithmetic to avoid any potential timing variations
        # This ensures the operation completes in constant time regardless
        # of how many bytes match or differ between the sequences
        result = 0
        for x, y in zip(a, b):
            # XOR will be zero only when bits match
            result |= x ^ y
            
        # Only return true if all bytes matched (result is still 0)
        return result == 0


def constant_time_mac_verify(expected_mac: bytes, received_mac: bytes) -> bool:
    """
    Verify a message authentication code (MAC) in constant time.
    
    This function is specifically optimized for MAC verification and
    includes additional protections against advanced timing attacks.
    
    Args:
        expected_mac: The expected MAC value (computed)
        received_mac: The received MAC value (to verify)
        
    Returns:
        bool: True if the MACs match, False otherwise
    """
    # Validate inputs to ensure correct types
    if not isinstance(expected_mac, bytes) or not isinstance(received_mac, bytes):
        # Convert to bytes if needed to ensure consistent operation
        expected_mac = bytes(expected_mac) if expected_mac is not None else b''
        received_mac = bytes(received_mac) if received_mac is not None else b''
    
    # Add a small variable delay before verification to mask timing differences
    # This uses a cryptographically secure random number to prevent patterns
    time.sleep(secrets.randbelow(5) / 1000.0)  # 0-4ms delay
    
    # Compare MACs using the core constant-time comparison
    result = constant_time_compare_core(expected_mac, received_mac)
    
    # Add another small delay after verification to mask timing differences
    # The delay after comparison is essential to prevent timing analysis of the return path
    time.sleep(secrets.randbelow(5) / 1000.0)  # 0-4ms delay
    
    return result


def constant_time_bytes_eq(a: bytes, b: bytes) -> bool:
    """
    A faster constant-time equality check for bytes.
    
    This function provides a streamlined comparison for situations
    where both inputs are known to be bytes and of the same length.
    It is used internally for performance-critical operations.
    
    Args:
        a: First byte sequence
        b: Second byte sequence
        
    Returns:
        bool: True if sequences are equal, False otherwise
    """
    # For optimum performance, directly use the core implementation
    # when we already know the input types are correct
    return constant_time_compare_core(a, b)


def is_zeroed_constant_time(data: bytes, full_check: bool = True) -> bool:
    """
    Check if all bytes in a buffer are zero in constant time.
    
    This is useful for verifying that sensitive memory has been properly
    zeroed without leaking timing information about which bytes may
    still contain data.
    
    Args:
        data: The bytes to check
        full_check: Whether to check the entire buffer (True) or use sampling (False)
        
    Returns:
        bool: True if all checked bytes are zero, False otherwise
    """
    if not data:
        return True
        
    # For smaller buffers, always do a full check in constant time
    if len(data) <= 1024 or full_check:
        # Accumulate all bytes in a way that only returns True if all are zero
        result = 0
        for byte in data:
            # Once result becomes non-zero, it stays non-zero
            result |= byte
        return result == 0
    else:
        # For very large buffers, sampling can be used as a trade-off
        # This is still done in a timing-resistant way
        result = 0
        
        # Always check beginning and end of buffer
        result |= data[0]
        result |= data[-1]
        
        # Sample bytes throughout the buffer
        step = max(1, len(data) // 32)
        for i in range(0, len(data), step):
            result |= data[i]
            
        return result == 0


def secure_value_wipe(buffer: bytearray) -> None:
    """
    Low-level secure wiping of a buffer.
    
    This function writes random data to the buffer first,
    then zeroes it out to minimize data recovery possibilities.
    
    Args:
        buffer: The bytearray to securely wipe
    """
    if not buffer:
        return
        
    # Get buffer length for efficiency
    length = len(buffer)
    
    # First overwrite with random data to disturb any potential
    # residual magnetic/electric state in memory
    for i in range(length):
        buffer[i] = secrets.randbits(8)
        
    # Then overwrite with zeros in reverse order to prevent
    # compiler optimization from removing the operation
    for i in range(length - 1, -1, -1):
        buffer[i] = 0