#!/usr/bin/env python3
"""
Memory Security Helper Functions

Functions to securely handle sensitive data in memory by overwriting it
before deletion to prevent data leakage through memory dumps.
"""

import ctypes
import sys
import secrets
import array


def secure_overwrite_string(string_var):
    """
    Securely overwrite a string in memory before it's garbage collected.
    
    This helps prevent sensitive data from being recovered from memory dumps.
    Note that this is best-effort as Python strings are immutable and
    this can't guarantee complete removal from all memory locations.
    
    Args:
        string_var (str): The string variable to overwrite
    """
    if string_var is None or not isinstance(string_var, str):
        return
    
    # Get memory address and size of the string
    try:
        # Create a mutable buffer at the string's memory location
        # Convert the string to a ctypes char array to access its memory
        length = len(string_var)
        if length == 0:
            return
            
        # Fill with random data several times to ensure overwrite
        for _ in range(3):
            # Generate random data to overwrite with
            random_data = secrets.token_bytes(length)
            
            # Use a ctypes array as a mutable buffer
            buffer = ctypes.create_string_buffer(random_data)
            
            # We can't directly modify string_var (it's immutable)
            # but this might overwrite memory if the original string hasn't been moved
            # This is a best-effort approach with Python's limitations
            try:
                ctypes.memmove(id(string_var), buffer, length)
            except:
                # Fallback approach - fill the string variable with a different value
                # This creates a new string but might help in some cases
                new_value = '*' * length
                string_var_ref = string_var  # Keep a reference to prevent GC during operation
                string_var = new_value
                del string_var_ref
                break
    except Exception:
        # Silently handle errors as this is a security best-effort
        pass


def secure_overwrite_bytearray(byte_array):
    """
    Securely overwrite a bytearray in memory before it's garbage collected.
    
    This is more effective than string overwriting since bytearrays are mutable.
    
    Args:
        byte_array (bytearray): The bytearray to overwrite
    """
    if byte_array is None or not isinstance(byte_array, bytearray):
        return
        
    length = len(byte_array)
    if length == 0:
        return
        
    # Overwrite with random data multiple times
    for _ in range(3):
        random_data = secrets.token_bytes(length)
        for i in range(length):
            byte_array[i] = random_data[i]
            
    # Final overwrite with zeros
    for i in range(length):
        byte_array[i] = 0


def secure_overwrite_bytes(bytes_var):
    """
    Securely handle bytes objects by converting to bytearray, overwriting, then discarding.
    
    Args:
        bytes_var (bytes): The bytes object to handle securely
    """
    if bytes_var is None or not isinstance(bytes_var, bytes):
        return
        
    # Convert to bytearray which is mutable
    byte_array = bytearray(bytes_var)
    
    # Overwrite the bytearray
    secure_overwrite_bytearray(byte_array)
    
    # bytes objects themselves are immutable, so we can't modify directly
    del byte_array


class SecureString:
    """
    Class for securely handling sensitive strings in memory.
    
    Uses a mutable char array internally instead of Python's immutable strings.
    """
    
    def __init__(self, value=None):
        """Initialize with a string value or empty"""
        if value is None:
            self._buffer = array.array('u')
        else:
            self._buffer = array.array('u', value)
            # Try to overwrite original value in memory
            secure_overwrite_string(value)
    
    def __del__(self):
        """Securely clear memory when object is destroyed"""
        length = len(self._buffer)
        for i in range(length):
            self._buffer[i] = '\0'  # Overwrite with null character
    
    def get_value(self):
        """Get the string value (use cautiously as it creates a new string)"""
        return self._buffer.tounicode()
    
    def clear(self):
        """Explicitly clear the contents"""
        length = len(self._buffer)
        for i in range(length):
            self._buffer[i] = '\0'
        self._buffer = array.array('u')
    
    def __len__(self):
        """Return the length of the string"""
        return len(self._buffer)
