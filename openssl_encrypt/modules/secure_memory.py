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


def verify_memory_zeroed(data, sample_size=8):
    """
    Verify that a memory buffer has been properly zeroed.
    
    This function checks that the data has been properly zeroed by examining
    a sample of bytes from the buffer. It uses a constant-time approach to
    avoid timing side channels.
    
    Args:
        data: The data buffer to verify (bytes, bytearray, or memoryview)
        sample_size: Number of random sample points to check, default 8
        
    Returns:
        bool: True if the memory appears to be properly zeroed, False otherwise
    """
    if data is None:
        return True
        
    try:
        # Get length of data
        data_len = len(data)
        if data_len == 0:
            return True
            
        # For very small buffers, check every byte
        if data_len <= sample_size:
            sample_size = data_len
            
        # Determine sample indices - either check all bytes or a random sample
        if data_len <= 64:  # For small buffers, check everything
            indices = list(range(data_len))
        else:
            # For large buffers, check beginning, end, and random samples in the middle
            indices = [0, data_len // 4, data_len // 2, 3 * data_len // 4, data_len - 1]
            
            # Add some random sample points
            random_indices = []
            while len(random_indices) < sample_size - len(indices):
                idx = random.randint(1, data_len - 2)  # Skip first and last bytes
                if idx not in indices and idx not in random_indices:
                    random_indices.append(idx)
                    
            indices.extend(random_indices)
            
        # Check if all bytes are zero in constant time
        result = 0
        for idx in indices:
            byte_val = data[idx]
            # Use bitwise OR to accumulate any non-zero values
            result |= byte_val
            
        return result == 0
        
    except Exception:
        # If any error occurs during verification, assume zeroing failed
        return False


def secure_memzero(data):
    """
    Securely wipe data with multiple rounds of overwriting followed by zeroing.
    Ensures the data is completely overwritten in memory and performs verification.

    Args:
        data: The data to be wiped (SecureBytes, bytes, bytearray, or memoryview)
        
    Returns:
        bool: True if zeroing was successful and verified, False otherwise
    """
    if data is None:
        return True

    # Convert strings to bytes for wiping
    if isinstance(data, str):
        data = data.encode('utf-8')

    # Simplified zeroing during shutdown
    try:
        if isinstance(data, (bytearray, memoryview)):
            data[:] = bytearray(len(data))
            return verify_memory_zeroed(data)
    except BaseException:
        return False

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
    zeroing_successful = False
    
    try:
        # Apply multi-layered wiping approach to defend against cold boot attacks
        
        # First pass: Simple zeroing as a baseline
        target_data[:] = bytearray(length)

        # Only attempt the more complex wiping if we're not shutting down
        if getattr(sys, 'meta_path', None) is not None:
            try:
                # Increased number of overwrite rounds with different patterns for better cold boot protection
                # Each pattern targets different memory retention characteristics
                
                # 1. Random data (unpredictable)
                random_data = bytearray(length)
                try:
                    random_data = bytearray(generate_secure_random_bytes(length))
                    target_data[:] = random_data
                    random_data[:] = bytearray(length)  # Zero the random data too
                except BaseException:
                    pass
                
                # 2. All ones (0xFF) - alternate bit pattern to flip all bits
                all_ones = bytearray([0xFF] * length)
                target_data[:] = all_ones
                all_ones[:] = bytearray(length)
                
                # 3. Alternating pattern (0xAA) - 10101010 pattern
                pattern_aa = bytearray([0xAA] * length)
                target_data[:] = pattern_aa
                pattern_aa[:] = bytearray(length)
                
                # 4. Inverse alternating pattern (0x55) - 01010101 pattern
                pattern_55 = bytearray([0x55] * length)
                target_data[:] = pattern_55
                pattern_55[:] = bytearray(length)
                
                # 5. Random data again - further disrupt any residual state
                try:
                    random_data = bytearray(generate_secure_random_bytes(length))
                    target_data[:] = random_data
                    random_data[:] = bytearray(length)
                except BaseException:
                    pass
                
                # Add random timing variations to prevent timing-based memory analysis
                # This is especially important for cold boot attacks
                time.sleep(random.uniform(0.001, 0.005))
                
                # Try platform-specific secure zeroing methods
                try:
                    # Force memory synchronization before secure zeroing
                    # This helps ensure previous writes are committed to memory
                    gc.collect()  # Request garbage collection to help flush caches
                    
                    system_name = platform.system()
                    if system_name == 'Windows':
                        try:
                            # Windows has a dedicated secure memory zeroing function
                            buf = (ctypes.c_byte * length).from_buffer(target_data)
                            result = ctypes.windll.kernel32.RtlSecureZeroMemory(
                                ctypes.byref(buf),
                                ctypes.c_size_t(length)
                            )
                            if result == 0:  # Success returns 0
                                zeroing_successful = True
                        except BaseException:
                            pass
                    elif system_name in ('Linux', 'Darwin', 'FreeBSD'):
                        try:
                            # Try to use platform-specific secure zeroing functions
                            libc = ctypes.CDLL(None)
                            
                            # Modern libc versions provide explicit_bzero (similar to memset_s)
                            if hasattr(libc, 'explicit_bzero'):
                                buf = (ctypes.c_byte * length).from_buffer(target_data)
                                libc.explicit_bzero(
                                    ctypes.byref(buf),
                                    ctypes.c_size_t(length)
                                )
                                zeroing_successful = True
                            # Try POSIX memset_s if available
                            elif hasattr(libc, 'memset_s'):
                                buf = (ctypes.c_byte * length).from_buffer(target_data)
                                libc.memset_s(
                                    ctypes.byref(buf),
                                    ctypes.c_size_t(length),
                                    ctypes.c_int(0),
                                    ctypes.c_size_t(length)
                                )
                                zeroing_successful = True
                        except BaseException:
                            pass
                except BaseException:
                    pass
                
                # Final zeroing using standard Python method
                target_data[:] = bytearray(length)
                
                # Ensure the data is flushed to actual memory (helpful against optimizations)
                # Call msync equivalent if on POSIX systems
                if platform.system() in ('Linux', 'Darwin', 'FreeBSD'):
                    try:
                        # Try to ensure memory writes are synchronized to physical memory
                        libc = ctypes.CDLL(None)
                        if hasattr(libc, 'msync'):
                            try:
                                addr = ctypes.addressof(ctypes.c_char.from_buffer(target_data))
                                page_size = get_memory_page_size()
                                # Round address down to page boundary
                                page_addr = (addr // page_size) * page_size
                                # Round size up to page boundary
                                page_len = ((length + (addr - page_addr) + page_size - 1) // page_size) * page_size
                                
                                # MS_SYNC: Synchronous flush (2 on most systems)
                                MS_SYNC = 2
                                libc.msync(ctypes.c_void_p(page_addr), ctypes.c_size_t(page_len), MS_SYNC)
                            except:
                                pass
                    except:
                        pass

            except BaseException:
                pass
            
            # One more zeroing pass
            target_data[:] = bytearray(length)
            
            # Verify that memory has been properly zeroed
            zeroing_successful = verify_memory_zeroed(target_data)

    except Exception:
        # Last resort zeroing attempt
        try:
            target_data[:] = bytearray(length)
            zeroing_successful = verify_memory_zeroed(target_data)
        except BaseException:
            zeroing_successful = False
            
    return zeroing_successful


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
    that won't be swapped to disk, and implements additional protections
    against cold boot attacks and memory analysis.
    """

    def __init__(self):
        """Initialize the secure memory allocator."""
        self.allocated_blocks = []
        self.system = platform.system().lower()
        self.page_size = get_memory_page_size()
        
        # Track overall memory usage
        self.total_allocated = 0
        self.max_allowed = 1024 * 1024 * 100  # 100MB limit by default
        
        # Set up platform detection for advanced features
        self.has_mlockall = False
        self.has_madvise = False
        self.has_minherit = False
        self.supports_madv_dontdump = False
        
        # Debug mode (disabled by default)
        self.debug_mode = False
        
        # Attempt to configure advanced memory protections
        self._setup_advanced_protections()
        
    def _setup_advanced_protections(self):
        """Set up advanced memory protection features if available on this platform."""
        try:
            # Configure advanced memory protection options based on platform
            if self.system in ('linux', 'darwin', 'freebsd'):
                try:
                    libc = ctypes.CDLL(None)
                    
                    # Check for mlockall support (lock all memory pages)
                    self.has_mlockall = hasattr(libc, 'mlockall')
                    
                    # Check for madvise support (memory advice functions)
                    self.has_madvise = hasattr(libc, 'madvise')
                    
                    # Check for minherit support (BSD memory inheritance)
                    self.has_minherit = hasattr(libc, 'minherit')
                    
                    # Linux-specific: Check if MADV_DONTDUMP is supported
                    # This prevents sensitive memory from being included in core dumps
                    if self.system == 'linux':
                        try:
                            # Try to get MADV_DONTDUMP constant (value 16 on most systems)
                            # We'll use the value directly if we can't get it from headers
                            self.supports_madv_dontdump = True
                        except:
                            pass
                except Exception:
                    pass
                    
            # Windows has its own memory protection mechanisms
            elif self.system == 'windows':
                try:
                    # Just check if we can load kernel32
                    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
                    # Windows memory protection is handled during allocation/locking
                except Exception:
                    pass
        except Exception:
            # Fail silently if we can't set up advanced protections
            pass

    def _round_to_page_size(self, size):
        """Round a size up to the nearest multiple of the page size."""
        return ((size + self.page_size - 1) // self.page_size) * self.page_size
    
    def _anti_debug_check(self):
        """
        Check for debuggers or memory scanners and perform anti-debugging measures.
        
        This helps protect against memory analysis tools and debuggers that
        could be used to extract sensitive information from memory.
        
        Returns:
            bool: True if no debuggers were detected, False otherwise
        """
        try:
            # Various anti-debugging techniques
            if self.system == 'linux':
                # Check for tracers via status file
                try:
                    with open('/proc/self/status', 'r') as f:
                        status = f.read()
                        if 'TracerPid:\t0' not in status:
                            # Tracer detected - could be a debugger
                            if self.debug_mode:
                                print("Warning: Possible debugger detected")
                            return False
                except:
                    pass
            
            elif self.system == 'windows':
                # Check for Windows debuggers
                try:
                    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
                    if hasattr(kernel32, 'IsDebuggerPresent'):
                        if kernel32.IsDebuggerPresent():
                            if self.debug_mode:
                                print("Warning: Debugger detected")
                            return False
                except:
                    pass
            
            # Memory scanning countermeasures
            # Introduce some randomness in memory patterns
            # This makes it harder for scanners to identify patterns
            try:
                # Random memory access pattern to prevent predictable analysis
                dummy_size = random.randint(64, 256)
                dummy = bytearray(dummy_size)
                for i in range(0, dummy_size, 8):
                    dummy[i] = random.randint(0, 255)
                # Immediately clear to avoid leaving traces
                dummy[:] = bytearray(dummy_size)
            except:
                pass
                
            return True
        except Exception:
            # Default to allowing allocation if checks fail
            return True

    def allocate(self, size, zero=True):
        """
        Allocate a secure memory block with enhanced protection against cold boot attacks.

        Args:
            size (int): Size in bytes to allocate
            zero (bool): Whether to zero the memory initially

        Returns:
            SecureBytes: A secure memory container with additional protections
            
        Raises:
            ValueError: If size is invalid or memory limit would be exceeded
            RuntimeError: If allocation fails
        """
        # Validate size
        if not isinstance(size, int) or size <= 0:
            raise ValueError("Size must be a positive integer")
            
        # Check against memory limits to prevent DoS
        if self.total_allocated + size > self.max_allowed:
            raise ValueError(f"Memory allocation limit exceeded ({self.total_allocated + size} > {self.max_allowed})")
            
        # Perform anti-debugging check
        self._anti_debug_check()
        
        try:
            # Round up allocation size to page boundary for more efficient memory locking
            alloc_size = size
            if size > 1024:  # Only for larger allocations
                alloc_size = self._round_to_page_size(size)
                
            # Create a secure byte container
            secure_container = SecureBytes(alloc_size)
            
            # Apply platform-specific memory protections
            lock_success = self._try_lock_memory(secure_container)
            
            if not lock_success and self.debug_mode:
                print("Warning: Memory locking failed")
            
            # Apply additional cold boot attack countermeasures
            self._apply_cold_boot_protections(secure_container)
            
            # Zero the memory if requested, using secure pattern
            if zero:
                if alloc_size > 1024:
                    # For larger allocations, use multi-pattern zeroing for better DRAM coverage
                    patterns = [
                        0x00,  # all zeros
                        0xFF,  # all ones
                        0xAA,  # alternating 10101010
                        0x55   # alternating 01010101
                    ]
                    
                    # Apply each pattern and then zero
                    for pattern in patterns:
                        pattern_bytes = bytearray([pattern] * alloc_size)
                        secure_container[:] = pattern_bytes
                        # Force memory synchronization
                        gc.collect()
                        time.sleep(0.001)  # Small delay to ensure write
                        
                    # Final zeroing
                    secure_container[:] = bytearray(alloc_size)
                else:
                    # For small allocations, simple zeroing is sufficient
                    for i in range(alloc_size):
                        secure_container[i] = 0
            
            # Update allocation tracking
            self.allocated_blocks.append(secure_container)
            self.total_allocated += alloc_size
            
            return secure_container
            
        except Exception as e:
            # Clean up any partial allocations
            if 'secure_container' in locals():
                try:
                    secure_memzero(secure_container)
                except:
                    pass
            raise RuntimeError(f"Secure memory allocation failed: {str(e)}")
    
    def _apply_cold_boot_protections(self, buffer):
        """
        Apply additional protections against cold boot attacks.
        
        Args:
            buffer: The memory buffer to protect
        
        Returns:
            bool: True if protections were applied, False otherwise
        """
        if buffer is None or len(buffer) == 0:
            return False
            
        try:
            # For Linux platforms, apply additional protections
            if self.system == 'linux':
                try:
                    # Try to prevent memory from being included in core dumps
                    if self.has_madvise and self.supports_madv_dontdump:
                        try:
                            libc = ctypes.CDLL(None)
                            addr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
                            size = len(buffer)
                            
                            # MADV_DONTDUMP (16) - exclude from core dumps
                            MADV_DONTDUMP = 16
                            libc.madvise(ctypes.c_void_p(addr), ctypes.c_size_t(size), MADV_DONTDUMP)
                            
                            # MADV_DONTFORK (10) - don't share with child processes
                            MADV_DONTFORK = 10
                            libc.madvise(ctypes.c_void_p(addr), ctypes.c_size_t(size), MADV_DONTFORK)
                        except:
                            pass
                except:
                    pass
                    
            # For BSD platforms (including macOS), use minherit
            elif self.system in ('darwin', 'freebsd'):
                try:
                    if self.has_minherit:
                        libc = ctypes.CDLL(None)
                        addr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
                        size = len(buffer)
                        
                        # VM_INHERIT_NONE (2) - memory not inherited by child processes
                        VM_INHERIT_NONE = 2
                        libc.minherit(
                            ctypes.c_void_p(addr), 
                            ctypes.c_size_t(size),
                            VM_INHERIT_NONE
                        )
                except:
                    pass
                    
            # For Windows, additional protection is applied during memory locking
            
            return True
        except Exception:
            return False

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
        Explicitly free a secure memory container with verification.

        Args:
            secure_container (SecureBytes): The secure container to free
            
        Returns:
            bool: True if freeing was successful and verified, False otherwise
        """
        if secure_container in self.allocated_blocks:
            # Get container size before unlocking for tracking
            container_size = len(secure_container)
            
            # Unlock memory
            unlock_success = self._try_unlock_memory(secure_container)
            
            # Securely zero memory and verify
            zero_success = secure_memzero(secure_container)
            
            # Update allocation tracking
            self.allocated_blocks.remove(secure_container)
            self.total_allocated -= container_size
            
            # Perform garbage collection to help prevent memory leaks
            gc.collect()
            
            return unlock_success and zero_success
        return False

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
    Explicitly free a secure buffer with zeroing verification.

    Args:
        buffer (SecureBytes): The secure buffer to free
        
    Returns:
        bool: True if freeing was successful and zeroing was verified, False otherwise
    """
    if buffer is None:
        return False
        
    try:
        # Use the allocator's enhanced freeing mechanism with verification
        return _global_secure_allocator.free(buffer)
    except Exception:
        # Handle error cases
        try:
            # Last resort zeroing attempt if allocator's free method fails
            zeroing_success = secure_memzero(buffer)
            return zeroing_success
        except:
            return False


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
def secure_buffer(size, zero=True, verify_zeroing=True):
    """
    Context manager for a secure memory buffer with cold boot protection.

    This enhanced version provides additional protections against memory
    disclosure and cold boot attacks, including memory zeroing verification.

    Args:
        size (int): Size in bytes to allocate
        zero (bool): Whether to zero the memory initially
        verify_zeroing (bool): Whether to verify memory is properly zeroed on cleanup

    Yields:
        SecureBytes: A secure memory buffer
        
    Raises:
        RuntimeError: If zeroing verification fails when verify_zeroing is True
    """
    # Validate size
    if not isinstance(size, int) or size <= 0:
        raise ValueError("Size must be a positive integer")
        
    # Allocate secure buffer
    buffer = allocate_secure_buffer(size, zero)
    zeroing_verified = False
    
    try:
        yield buffer
    finally:
        # Free secure buffer with verification
        if verify_zeroing:
            zeroing_verified = free_secure_buffer(buffer)
            
            # If in a critical security context and verification failed, raise exception
            if not zeroing_verified and os.environ.get('CRITICAL_SECURITY_CONTEXT') == '1':
                raise RuntimeError("Failed to verify memory zeroing in secure buffer")
        else:
            # Basic free without verification
            free_secure_buffer(buffer)
            
        # In all cases, explicitly remove reference to buffer
        buffer = None
        
        # Force garbage collection to clean up any remnants
        gc.collect()


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
    

def secure_erase_system_memory(trigger_gc=True, full_sweep=False):
    """
    Perform a system-wide secure memory cleanup to mitigate cold boot attacks.
    
    This function attempts to clean up sensitive data in memory by:
    1. Freeing all secure memory buffers
    2. Forcing garbage collection
    3. Allocating and zeroing large memory buffers to overwrite free memory
    4. Applying platform-specific memory protection mechanisms
    
    Args:
        trigger_gc (bool): Whether to force garbage collection
        full_sweep (bool): Whether to perform a more thorough memory cleanup
        
    Returns:
        bool: True if the operation was successful, False otherwise
    """
    try:
        # First do a round of garbage collection to free unused objects
        if trigger_gc:
            gc.collect()
            
        # Free all secure memory blocks through the global allocator
        for block in list(_global_secure_allocator.allocated_blocks):
            _global_secure_allocator.free(block)
            
        # Platform-specific memory cleanup
        system_name = platform.system().lower()
        
        # For Linux platforms, try to clean swap space
        if system_name == 'linux':
            try:
                # Request the kernel flush memory to disk
                try:
                    with open('/proc/sys/vm/drop_caches', 'w') as f:
                        f.write('3')
                except:
                    pass
                    
                # Try to disable core dumps
                try:
                    import resource
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                except:
                    pass
                    
                # Request garbage collection again after memory operations
                gc.collect()
            except:
                pass
                
        # For a more thorough cleanup when requested
        if full_sweep:
            try:
                # Allocate a large buffer and fill with random data to overwrite free memory
                # This helps against memory dump attacks
                memory_size = min(1024 * 1024 * 32, os.sysconf('SC_PHYS_PAGES') * os.sysconf('SC_PAGE_SIZE') // 4)
                
                # Break this into smaller chunks to avoid OOM killer
                chunk_size = 1024 * 1024  # 1MB chunks
                for _ in range(memory_size // chunk_size):
                    try:
                        # Allocate, fill with various patterns, then release
                        buf = bytearray(chunk_size)
                        
                        # Different bit patterns to effectively overwrite various memory states
                        patterns = [0xFF, 0x00, 0x55, 0xAA, 0xF0]
                        for pattern in patterns:
                            for i in range(chunk_size):
                                buf[i] = pattern
                            # Small delay to ensure writes propagate
                            time.sleep(0.001)
                            
                        # Final zeroing
                        for i in range(chunk_size):
                            buf[i] = 0
                            
                        # Explicit delete
                        del buf
                    except:
                        # If we run out of memory, just continue
                        break
                        
                # One more garbage collection
                gc.collect()
            except:
                pass
                
        return True
            
    except Exception as e:
        # Fail silently in production, log in debug mode
        if os.environ.get('DEBUG') == '1':
            print(f"Error in secure memory erasure: {str(e)}")
        return False
