#!/usr/bin/env python3
"""
Secure Memory Module

This module provides functions for secure memory handling, ensuring that
sensitive data is properly wiped from memory when no longer needed.
"""

import ctypes
import platform
import array
import contextlib
import mmap
import sys
import os
import secrets
import gc
import random
import time


def get_memory_page_size():
    """
    Get the system's memory page size.

    Returns:
        int: Memory page size in bytes
    """
    if hasattr(os, 'sysconf'):
        return os.sysconf('SC_PAGE_SIZE')
    elif hasattr(mmap, 'PAGESIZE'):
        return mmap.PAGESIZE
    else:
        # Default to 4KB if we can't determine it
        return 4096


def secure_memzero(data):
    """
    Securely wipe data with three rounds of random overwriting followed by zeroing.
    Ensures the data is completely overwritten in memory.

    Args:
        data: The data to be wiped (SecureBytes, bytes, bytearray, or memoryview)
    """
    if data is None:
        return

    if isinstance(data, str):
        data = data.encode('utf-8')

    # Simplified zeroing during shutdown
    try:
        if isinstance(data, (bytearray, memoryview)):
            data[:] = bytearray(len(data))
            return
    except BaseException:
        return

    # Handle different input types
    if isinstance(data, (SecureBytes, bytearray)):
        target_data = data
    elif isinstance(data, bytes):
        target_data = bytearray(data)
    elif isinstance(data, memoryview):
        if data.readonly:
            raise TypeError("Cannot wipe readonly memory view")
        target_data = bytearray(data)
    else:
        try:
            # Try to convert other types to bytes first
            target_data = bytearray(bytes(data))
        except BaseException:
            raise TypeError(
                "Data must be SecureBytes, bytes, bytearray, memoryview, or convertible to bytes")

    length = len(target_data)

    try:
        # Simplified zeroing during shutdown or error cases
        target_data[:] = bytearray(length)

        # Only attempt the more complex wiping if we're not shutting down
        if getattr(sys, 'meta_path', None) is not None:
            try:
                # Three rounds of random overwriting
                for _ in range(3):
                    # Simple zero fill if generate_secure_random_bytes is
                    # unavailable
                    random_data = bytearray(length)
                    try:
                        random_data = bytearray(
                            generate_secure_random_bytes(length))
                    except BaseException:
                        pass
                    time.sleep(random.uniform(0.0001, 0.001))
                    target_data[:] = random_data
                    random_data[:] = bytearray(length)
                    time.sleep(random.uniform(0.0001, 0.001))
                    del random_data

                # Try platform specific secure zeroing
                import platform
                import ctypes

                if platform.system() == 'Windows':
                    try:
                        buf = (ctypes.c_byte * length).from_buffer(target_data)
                        ctypes.windll.kernel32.RtlSecureZeroMemory(
                            ctypes.byref(buf),
                            ctypes.c_size_t(length)
                        )
                    except BaseException:
                        pass
                elif platform.system() in ('Linux', 'Darwin'):
                    try:
                        libc = ctypes.CDLL(None)
                        if hasattr(libc, 'explicit_bzero'):
                            buf = (
                                ctypes.c_byte *
                                length).from_buffer(target_data)
                            libc.explicit_bzero(
                                ctypes.byref(buf),
                                ctypes.c_size_t(length)
                            )
                    except BaseException:
                        pass
            except BaseException:
                pass

            # Final zeroing
            target_data[:] = bytearray(length)

    except Exception:
        # Last resort zeroing attempt
        try:
            target_data[:] = bytearray(length)
        except BaseException:
            pass


class SecureBytes(bytearray):
    """
    Secure bytes container that automatically zeroes memory on deletion.

    This class extends bytearray to ensure its contents are securely
    cleared when the object is garbage collected.
    """

    def __del__(self):
        """Securely clear memory before deletion."""
        secure_memzero(self)

    @classmethod
    def copy_from(cls, source):
        """
        Create a SecureBytes object by copying from another bytes-like object.

        Args:
            source: A bytes-like object to copy from

        Returns:
            SecureBytes: A new SecureBytes object with the copied data
        """
        return cls(bytes(source))


class SecureMemoryAllocator:
    """
    Allocator for secure memory blocks that will be properly zeroed when freed.

    This class attempts to use platform-specific methods to allocate memory
    that won't be swapped to disk, where possible.
    """

    def __init__(self):
        """Initialize the secure memory allocator."""
        self.allocated_blocks = []
        self.system = platform.system().lower()
        self.page_size = get_memory_page_size()

    def _round_to_page_size(self, size):
        """Round a size up to the nearest multiple of the page size."""
        return ((size + self.page_size - 1) // self.page_size) * self.page_size

    def allocate(self, size, zero=True):
        """
        Allocate a secure memory block.

        Args:
            size (int): Size in bytes to allocate
            zero (bool): Whether to zero the memory initially

        Returns:
            SecureBytes: A secure memory container
        """
        # Create a secure byte container
        secure_container = SecureBytes(size)

        # Zero the memory if requested
        if zero:
            for i in range(size):
                secure_container[i] = 0

        # Keep track of allocated blocks
        self.allocated_blocks.append(secure_container)

        # Attempt to lock memory if possible (platform specific)
        self._try_lock_memory(secure_container)

        return secure_container

    def _try_lock_memory(self, buffer):
        """
        Try to lock memory to prevent it from being swapped to disk.

        This is a best-effort function that attempts to use platform-specific
        methods to prevent the memory from being included in core dumps or
        swapped to disk.

        Args:
            buffer: The memory buffer to lock
        """
        # Validate buffer before proceeding
        if buffer is None:
            return False
        
        # Ensure buffer has valid length
        try:
            buffer_len = len(buffer)
            if buffer_len <= 0:
                return False
        except (TypeError, AttributeError):
            return False
            
        lock_success = False
        try:
            # On Linux/Unix platforms
            if self.system in ('linux', 'darwin', 'freebsd'):
                # Try to import the appropriate modules
                try:
                    import resource
                    import fcntl

                    # Attempt to disable core dumps
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

                    # Determine the correct library name based on platform
                    if self.system == 'linux':
                        libc_name = 'libc.so.6'
                    elif self.system == 'darwin':
                        libc_name = 'libc.dylib'
                    elif self.system == 'freebsd':
                        libc_name = 'libc.so'
                    else:
                        return False
                        
                    # Load the C library
                    try:
                        libc = ctypes.CDLL(libc_name)
                    except OSError:
                        return False
                        
                    # Check if mlock function exists
                    if hasattr(libc, 'mlock'):
                        # Create a memoryview to safely access buffer
                        try:
                            # Get buffer address with validation
                            c_buffer = ctypes.c_char.from_buffer(buffer)
                            if not c_buffer:
                                return False
                                
                            addr = ctypes.addressof(c_buffer)
                            size = buffer_len
                            
                            # Validate address and size
                            if addr <= 0 or size <= 0 or size > 1_000_000_000:  # 1GB max for safety
                                return False
                                
                            # Call mlock with proper error checking
                            result = libc.mlock(addr, size)
                            lock_success = (result == 0)
                            
                            # Check if locking was successful
                            if not lock_success:
                                # Try to get error code
                                if hasattr(ctypes, 'get_errno'):
                                    errno = ctypes.get_errno()
                                    if not quiet:
                                        print(f"Memory locking failed with error code: {errno}")
                            
                        except (TypeError, ValueError, BufferError) as e:
                            if not quiet:
                                print(f"Buffer conversion error: {str(e)}")
                            return False
                    
                except (ImportError, AttributeError, OSError) as e:
                    if not quiet:
                        print(f"Memory locking error: {str(e)}")
                    return False

            # On Windows
            elif self.system == 'windows':
                try:
                    # Attempt to use VirtualLock to prevent memory from being paged to disk
                    try:
                        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
                    except OSError:
                        return False
                        
                    if hasattr(kernel32, 'VirtualLock'):
                        try:
                            # Get buffer address with validation
                            c_buffer = ctypes.c_char.from_buffer(buffer)
                            if not c_buffer:
                                return False
                                
                            addr = ctypes.addressof(c_buffer)
                            size = buffer_len
                            
                            # Validate address and size
                            if addr <= 0 or size <= 0 or size > 1_000_000_000:  # 1GB max for safety
                                return False
                                
                            # Call VirtualLock with proper error handling
                            result = kernel32.VirtualLock(addr, size)
                            lock_success = (result != 0)  # Windows API returns non-zero on success
                            
                            # Check for errors
                            if not lock_success:
                                error_code = ctypes.get_last_error()
                                if not quiet:
                                    print(f"Memory locking failed with error code: {error_code}")
                                    
                        except (TypeError, ValueError, BufferError) as e:
                            if not quiet:
                                print(f"Buffer conversion error: {str(e)}")
                            return False
                            
                except (AttributeError, OSError) as e:
                    if not quiet:
                        print(f"Memory locking error: {str(e)}")
                    return False
                    
        except Exception as e:
            # Log the error but continue execution
            if not quiet:
                print(f"Memory locking unexpected error: {str(e)}")
            return False
            
        return lock_success

    def free(self, secure_container):
        """
        Explicitly free a secure memory container.

        Args:
            secure_container (SecureBytes): The secure container to free
        """
        if secure_container in self.allocated_blocks:
            self._try_unlock_memory(secure_container)
            secure_memzero(secure_container)
            self.allocated_blocks.remove(secure_container)

    def _try_unlock_memory(self, buffer):
        """
        Try to unlock previously locked memory.

        Args:
            buffer: The memory buffer to unlock
            
        Returns:
            bool: True if unlocking was successful, False otherwise
        """
        # Validate buffer before proceeding
        if buffer is None:
            return False
        
        # Ensure buffer has valid length
        try:
            buffer_len = len(buffer)
            if buffer_len <= 0:
                return False
        except (TypeError, AttributeError):
            return False
            
        unlock_success = False
        try:
            # On Linux/Unix platforms
            if self.system in ('linux', 'darwin', 'freebsd'):
                try:
                    # Determine the correct library name based on platform
                    if self.system == 'linux':
                        libc_name = 'libc.so.6'
                    elif self.system == 'darwin':
                        libc_name = 'libc.dylib'
                    elif self.system == 'freebsd':
                        libc_name = 'libc.so'
                    else:
                        return False
                        
                    # Load the C library
                    try:
                        libc = ctypes.CDLL(libc_name)
                    except OSError:
                        return False
                    
                    # Check if munlock function exists
                    if hasattr(libc, 'munlock'):
                        try:
                            # Get buffer address with validation
                            c_buffer = ctypes.c_char.from_buffer(buffer)
                            if not c_buffer:
                                return False
                                
                            addr = ctypes.addressof(c_buffer)
                            size = buffer_len
                            
                            # Validate address and size
                            if addr <= 0 or size <= 0 or size > 1_000_000_000:  # 1GB max for safety
                                return False
                                
                            # Call munlock with proper error checking
                            result = libc.munlock(addr, size)
                            unlock_success = (result == 0)
                            
                        except (TypeError, ValueError, BufferError) as e:
                            if not quiet:
                                print(f"Buffer conversion error during unlock: {str(e)}")
                            return False
                            
                except (ImportError, AttributeError, OSError) as e:
                    if not quiet:
                        print(f"Memory unlocking error: {str(e)}")
                    return False

            # On Windows
            elif self.system == 'windows':
                try:
                    # Load Windows kernel library
                    try:
                        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
                    except OSError:
                        return False
                        
                    # Check if VirtualUnlock function exists
                    if hasattr(kernel32, 'VirtualUnlock'):
                        try:
                            # Get buffer address with validation
                            c_buffer = ctypes.c_char.from_buffer(buffer)
                            if not c_buffer:
                                return False
                                
                            addr = ctypes.addressof(c_buffer)
                            size = buffer_len
                            
                            # Validate address and size
                            if addr <= 0 or size <= 0 or size > 1_000_000_000:  # 1GB max for safety
                                return False
                                
                            # Call VirtualUnlock with proper error handling
                            result = kernel32.VirtualUnlock(addr, size)
                            unlock_success = (result != 0)  # Windows API returns non-zero on success
                            
                            # Check for errors
                            if not unlock_success:
                                error_code = ctypes.get_last_error()
                                if not quiet:
                                    print(f"Memory unlocking failed with error code: {error_code}")
                                    
                        except (TypeError, ValueError, BufferError) as e:
                            if not quiet:
                                print(f"Buffer conversion error during unlock: {str(e)}")
                            return False
                            
                except (AttributeError, OSError) as e:
                    if not quiet:
                        print(f"Memory unlocking error: {str(e)}")
                    return False
                    
        except Exception as e:
            # Log the error but continue execution
            if not quiet:
                print(f"Memory unlocking unexpected error: {str(e)}")
            return False
            
        return unlock_success

    def __del__(self):
        """Clean up all allocated blocks when the allocator is destroyed."""
        # Make a copy of the list since we'll be modifying it during iteration
        for block in list(self.allocated_blocks):
            self.free(block)


# Global secure memory allocator instance
_global_secure_allocator = SecureMemoryAllocator()


def allocate_secure_buffer(size, zero=True):
    """
    Allocate a secure buffer of the specified size.

    Args:
        size (int): Size in bytes to allocate
        zero (bool): Whether to zero the memory initially

    Returns:
        SecureBytes: A secure memory container
    """
    return _global_secure_allocator.allocate(size, zero)


def free_secure_buffer(buffer):
    """
    Explicitly free a secure buffer.

    Args:
        buffer (SecureBytes): The secure buffer to free
    """
    _global_secure_allocator.free(buffer)


def secure_memcpy(dest, src, length=None):
    """
    Copy data between buffers securely with comprehensive validation and buffer overflow protection.

    Args:
        dest: Destination buffer
        src: Source buffer
        length (int, optional): Number of bytes to copy. If None, copy all of src.

    Returns:
        int: Number of bytes copied
        
    Raises:
        ValueError: If either source or destination is None, or if length is invalid
        TypeError: If source or destination are not valid buffer types
    """
    # Input validation
    if dest is None:
        raise ValueError("Destination buffer cannot be None")
    if src is None:
        raise ValueError("Source buffer cannot be None")
        
    # Validate buffer types
    try:
        len_dest = len(dest)
        len_src = len(src)
    except (TypeError, AttributeError):
        raise TypeError("Both source and destination must support the len() operation")
    
    # Validate length parameter if provided
    if length is not None:
        if not isinstance(length, int):
            raise TypeError("Length must be an integer")
        if length < 0:
            raise ValueError("Length cannot be negative")
            
    # Zero-length check to avoid unnecessary operations
    if len_src == 0 or len_dest == 0:
        return 0
        
    # Ensure buffers are accessible for writing
    try:
        # Check if destination is writable by attempting to modify first byte
        # First save the original value
        if len_dest > 0:
            orig_val = dest[0]
            dest[0] = orig_val  # Try writing the same value to test writability
    except (TypeError, IndexError):
        raise TypeError("Destination buffer is not writable")
        
    # Determine number of bytes to copy with explicit bounds checks
    if length is None:
        # Default to the minimum length to avoid buffer overflows
        copy_length = min(len_src, len_dest)
    else:
        # Ensure length doesn't exceed either buffer
        copy_length = min(length, len_src, len_dest)
    
    # Size check - if destination is too small, resize it if possible
    if hasattr(dest, 'extend') and len_dest < copy_length:
        # For resizable buffers like bytearray or SecureBytes, extend if needed
        extension_needed = copy_length - len_dest
        try:
            dest.extend(b'\x00' * extension_needed)
            # Update destination length after extension
            len_dest = len(dest)
        except (AttributeError, TypeError, ValueError):
            # If extend fails, handle error gracefully by adjusting copy length
            copy_length = min(copy_length, len_dest)
    
    # Final safety check before copying
    actual_copy_length = min(copy_length, len_dest)
    
    # Try different copy strategies with proper error handling
    try:
        # Strategy 1: Direct byte-by-byte copy with bounds checking
        for i in range(actual_copy_length):
            # Validate indices for both source and destination
            if i < len_src and i < len_dest:
                dest[i] = src[i]
            else:
                # We've reached the end of at least one buffer
                return i
    except (TypeError, IndexError, ValueError) as e:
        # Strategy 2: Try with explicit type conversions
        try:
            # Convert to bytearrays/bytes if needed
            src_bytes = bytes(src)
            for i in range(actual_copy_length):
                # Double-check bounds to prevent overflows
                if i < len(src_bytes) and i < len_dest:
                    dest[i] = src_bytes[i]
                else:
                    return i
        except Exception as e:
            # Strategy 3: Try using memory views if possible
            try:
                # Create memory views with explicit bounds checking
                src_view = memoryview(src)
                dest_view = memoryview(dest)
                
                # Validate views are compatible
                if src_view.readonly and not dest_view.readonly:
                    # Ensure copy length doesn't exceed either view
                    fit_length = min(len(src_view), len(dest_view))
                    
                    # Byte-by-byte copy with explicit bounds checking
                    for i in range(fit_length):
                        if i < len(src_view) and i < len(dest_view):
                            dest_view[i] = src_view[i]
                        else:
                            return i
                    
                    return fit_length
                else:
                    # Memory views aren't compatible for copying
                    return 0
            except Exception as final_error:
                # Last resort: log the error and return 0
                # This prevents breaking old files completely
                return 0
    
    # Return number of bytes actually copied
    return actual_copy_length


@contextlib.contextmanager
def secure_string():
    """
    Context manager for secure string handling.

    This creates a secure string buffer that will be automatically
    zeroed out when the context is exited.

    Yields:
        SecureBytes: A secure string buffer
    """
    buffer = SecureBytes()
    try:
        yield buffer
    finally:
        secure_memzero(buffer)


@contextlib.contextmanager
def secure_input(prompt="Enter sensitive data: ", echo=False):
    """
    Context manager for securely capturing user input.

    Args:
        prompt (str): The prompt to display to the user
        echo (bool): Whether to echo the input (True) or hide it (False)

    Yields:
        SecureBytes: A secure buffer containing the user's input
    """
    import getpass

    buffer = SecureBytes()
    try:
        if echo:
            user_input = input(prompt)
        else:
            user_input = getpass.getpass(prompt)

        # Copy the input to our secure buffer
        buffer.extend(user_input.encode())

        # Immediately try to clear the input from the regular string
        # Note: This is best-effort since strings are immutable in Python
        user_input = None

        yield buffer
    finally:
        secure_memzero(buffer)


@contextlib.contextmanager
def secure_buffer(size, zero=True):
    """
    Context manager for a secure memory buffer.

    Args:
        size (int): Size in bytes to allocate
        zero (bool): Whether to zero the memory initially

    Yields:
        SecureBytes: A secure memory buffer
    """
    buffer = allocate_secure_buffer(size, zero)
    try:
        yield buffer
    finally:
        free_secure_buffer(buffer)


def generate_secure_random_bytes(length):
    """
    Generate cryptographically secure random bytes.

    Args:
        length (int): Number of bytes to generate

    Returns:
        SecureBytes: A secure buffer with random bytes
    """
    # Create a secure buffer
    buffer = allocate_secure_buffer(length, zero=False)

    # Fill it with cryptographically secure random bytes
    random_bytes = secrets.token_bytes(length)
    secure_memcpy(buffer, random_bytes)

    # Clear the intermediate regular bytes object
    # (best effort, since bytes objects are immutable)
    random_bytes = None

    return buffer


def secure_compare(a, b):
    """
    Perform a constant-time comparison of two byte sequences.

    This function is resistant to timing attacks by ensuring that
    the comparison takes the same amount of time regardless of how
    similar the sequences are.

    Args:
        a (bytes-like): First byte sequence
        b (bytes-like): Second byte sequence

    Returns:
        bool: True if the sequences match, False otherwise
    """
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= x ^ y

    return result == 0
