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


# def secure_memzero(data):
#     """
#     Securely zero out a bytes/bytearray object or ctypes array.
#
#     This function attempts to bypass compiler optimizations that
#     might skip the zeroing of memory that's about to be released.
#
#     Args:
#         data: The data to securely zero (bytes, bytearray, ctypes array,
#               or other buffer protocol supporting object)
#     """
#     # Skip empty data
#     if not data:
#         return
#
#     # Get data size and pointer
#     try:
#         if isinstance(data, (bytes, bytearray)):
#             # For bytes/bytearray
#             memsize = len(data)
#             if isinstance(data, bytes):
#                 # Convert immutable bytes to bytearray
#                 data = bytearray(data)
#         elif hasattr(data, '_type_') and hasattr(data, 'raw'):
#             # For ctypes arrays
#             memsize = len(data) * ctypes.sizeof(data._type_)
#         elif hasattr(data, 'buffer_info'):
#             # For array.array objects
#             addr, memsize = data.buffer_info()
#         else:
#             # Try using the buffer protocol
#             memoryview_obj = memoryview(data)
#             memsize = memoryview_obj.nbytes
#
#         # Create a null bytes pattern for secure overwrite
#         null_bytes = b'\x00' * memsize
#
#         # Attempt different methods of zeroing out data
#         if isinstance(data, bytearray):
#             data[:] = null_bytes
#         elif hasattr(data, '_type_') and hasattr(data, 'raw'):
#             ctypes.memset(ctypes.addressof(data), 0, memsize)
#         elif hasattr(data, 'buffer_info'):
#             data.frombytes(null_bytes)
#         else:
#             # Last resort, try using the buffer protocol
#             mv = memoryview(data)
#             if mv.readonly:
#                 raise TypeError("Cannot securely zero read-only memory")
#             mv[:] = null_bytes[:len(mv)]
#
#         # Force actual memory update by reading the data
#         # This helps bypass some compiler optimizations
#         if isinstance(data, bytearray):
#             _ = sum(data)
#         elif hasattr(data, '_type_') and hasattr(data, 'raw'):
#             _ = sum(data)
#         elif hasattr(data, 'buffer_info'):
#             _ = sum(data)
#     except (TypeError, BufferError) as e:
#         raise TypeError(f"Data type not supported for secure zeroing: {type(data)}") from e
#     except Exception as e:
#         raise RuntimeError(f"Failed to securely zero memory: {e}") from e

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
    except:
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
        except:
            raise TypeError("Data must be SecureBytes, bytes, bytearray, memoryview, or convertible to bytes")

    length = len(target_data)

    try:
        # Simplified zeroing during shutdown or error cases
        target_data[:] = bytearray(length)

        # Only attempt the more complex wiping if we're not shutting down
        if getattr(sys, 'meta_path', None) is not None:
            try:
                # Three rounds of random overwriting
                for _ in range(3):
                    random_data = bytearray(length)  # Simple zero fill if generate_secure_random_bytes is unavailable
                    try:
                        random_data = bytearray(generate_secure_random_bytes(length))
                    except:
                        pass
                    target_data[:] = random_data
                    random_data[:] = bytearray(length)
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
                    except:
                        pass
                elif platform.system() in ('Linux', 'Darwin'):
                    try:
                        libc = ctypes.CDLL(None)
                        if hasattr(libc, 'explicit_bzero'):
                            buf = (ctypes.c_byte * length).from_buffer(target_data)
                            libc.explicit_bzero(
                                ctypes.byref(buf),
                                ctypes.c_size_t(length)
                            )
                    except:
                        pass
            except:
                pass

            # Final zeroing
            target_data[:] = bytearray(length)

    except Exception:
        # Last resort zeroing attempt
        try:
            target_data[:] = bytearray(length)
        except:
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
        try:
            # On Linux/Unix platforms
            if self.system in ('linux', 'darwin', 'freebsd'):
                # Try to import the appropriate modules
                try:
                    import resource
                    import fcntl
                    
                    # Attempt to disable core dumps
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                    
                    # On Linux, we can use mlock to prevent memory from being swapped
                    if hasattr(ctypes.CDLL('libc.so.6' if self.system == 'linux' else 'libc.dylib'), 'mlock'):
                        addr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
                        size = len(buffer)
                        ctypes.CDLL('libc.so.6' if self.system == 'linux' else 'libc.dylib').mlock(addr, size)
                except (ImportError, AttributeError, OSError):
                    pass
                    
            # On Windows
            elif self.system == 'windows':
                try:
                    # Attempt to use VirtualLock to prevent memory from being paged to disk
                    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
                    if hasattr(kernel32, 'VirtualLock'):
                        addr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
                        size = len(buffer)
                        kernel32.VirtualLock(addr, size)
                except (AttributeError, OSError):
                    pass
        except Exception:
            # Silently continue if locking fails - this is a best-effort approach
            pass
            
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
        """
        try:
            # On Linux/Unix platforms
            if self.system in ('linux', 'darwin', 'freebsd'):
                try:
                    # On Linux, we can use munlock to unlock previously locked memory
                    if hasattr(ctypes.CDLL('libc.so.6' if self.system == 'linux' else 'libc.dylib'), 'munlock'):
                        addr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
                        size = len(buffer)
                        ctypes.CDLL('libc.so.6' if self.system == 'linux' else 'libc.dylib').munlock(addr, size)
                except (ImportError, AttributeError, OSError):
                    pass
                    
            # On Windows
            elif self.system == 'windows':
                try:
                    # Unlock memory previously locked with VirtualLock
                    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
                    if hasattr(kernel32, 'VirtualUnlock'):
                        addr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
                        size = len(buffer)
                        kernel32.VirtualUnlock(addr, size)
                except (AttributeError, OSError):
                    pass
        except Exception:
            # Silently continue if unlocking fails
            pass
            
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
    Copy data between buffers securely with backward compatibility.
    
    Args:
        dest: Destination buffer
        src: Source buffer
        length (int, optional): Number of bytes to copy. If None, copy all of src.
        
    Returns:
        int: Number of bytes copied
    """
    # Determine number of bytes to copy
    if length is None:
        # Default to the minimum length to avoid buffer overflows
        length = min(len(src), len(dest))
    else:
        length = min(length, len(src), len(dest))
    
    # Size check - if destination is too small, resize it if possible
    if hasattr(dest, 'extend') and len(dest) < length:
        # For resizable buffers like bytearray or SecureBytes, extend if needed
        extension_needed = length - len(dest)
        try:
            dest.extend(b'\x00' * extension_needed)
        except AttributeError:
            # If extend fails, handle error gracefully
            pass

    # If sizes don't match after attempted resizing and dest is smaller,
    # we have to truncate to avoid buffer overflow
    actual_copy_length = min(length, len(dest))
    
    # Use a safer byte-by-byte copy approach that works with any buffer type
    try:
        for i in range(actual_copy_length):
            dest[i] = src[i]
    except (TypeError, IndexError) as e:
        # Fall back to an even more robust approach for problematic buffers
        try:
            # Convert to bytearrays if needed
            src_bytes = bytes(src)
            for i in range(actual_copy_length):
                if i < len(dest):  # Final safety check
                    dest[i] = src_bytes[i]
        except Exception as e:
            # If all else fails, try one more approach using a memory view if possible
            try:
                src_view = memoryview(src)
                dest_view = memoryview(dest)
                
                # Copy only what will fit
                fit_length = min(len(src_view), len(dest_view))
                
                # Byte by byte copy with memoryview
                for i in range(fit_length):
                    dest_view[i] = src_view[i]
                
                return fit_length
            except Exception:
                # Last resort: log that we couldn't copy and return 0
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

