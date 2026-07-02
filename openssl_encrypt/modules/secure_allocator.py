#!/usr/bin/env python3
"""
Secure Memory Allocator Module

This module provides a specialized memory allocator for sensitive cryptographic data,
which helps protect against various types of memory-based attacks. It offers:

1. Protection against memory disclosure attacks
2. Memory locking to prevent swapping to disk
3. Secure memory zeroing when freeing memory
4. Anti-debugging protection
5. Memory isolation for sensitive data
6. Protections against cold boot attacks

The allocator ensures proper cleanup of sensitive data with verification and
implements platform-specific memory protections where available.
"""

import atexit
import ctypes
import gc
import logging
import mmap
import os
import platform
import random
import secrets
import sys
import threading
import time
import weakref
from typing import Any, Dict, List, Optional, Tuple, Union

# Import secure error handling
from .crypt_errors import MemoryError as SecureMemoryError
from .crypt_errors import secure_memory_error_handler
from .crypt_utils import eprint

# Import secure memory utility functions
from .secure_memory import SecureBytes as BaseSecureBytes
from .secure_memory import get_memory_page_size, secure_memzero, verify_memory_zeroed

logger = logging.getLogger(__name__)

# Linux madvise() advice value for excluding a range from core dumps.
_MADV_DONTDUMP = 16


def _buffer_address(buffer) -> Optional[int]:
    """Return the address of a writable buffer, or None if unavailable."""
    try:
        return ctypes.addressof(ctypes.c_char.from_buffer(buffer))
    except (TypeError, ValueError, BufferError):
        return None


def _lock_and_protect_buffer(buffer) -> bool:
    """Best-effort mlock() + madvise(MADV_DONTDUMP) of a buffer's memory.

    Returns True if the memory was locked. Prototypes are declared so ctypes does
    not truncate the 64-bit address to a C int (the same class of bug fixed in
    secure_memory, #61); failures are non-fatal (best-effort, #63).
    """
    if platform.system().lower() not in ("linux", "darwin", "freebsd"):
        return False
    size = len(buffer)
    if size <= 0:
        return False
    addr = _buffer_address(buffer)
    if not addr:
        return False
    try:
        libc_name = {"linux": "libc.so.6", "darwin": "libc.dylib", "freebsd": "libc.so"}[
            platform.system().lower()
        ]
        libc = ctypes.CDLL(libc_name, use_errno=True)
    except (OSError, KeyError):
        return False
    if not hasattr(libc, "mlock"):
        return False
    libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.mlock.restype = ctypes.c_int
    locked = libc.mlock(addr, size) == 0
    # madvise(MADV_DONTDUMP) to keep keys out of core dumps (Linux; best-effort).
    if platform.system().lower() == "linux" and hasattr(libc, "madvise"):
        libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        libc.madvise.restype = ctypes.c_int
        try:
            libc.madvise(addr, size, _MADV_DONTDUMP)
        except Exception:
            pass
    return locked


def _unlock_buffer(buffer) -> None:
    """Best-effort munlock() of a buffer's memory."""
    if platform.system().lower() not in ("linux", "darwin", "freebsd"):
        return
    size = len(buffer)
    if size <= 0:
        return
    addr = _buffer_address(buffer)
    if not addr:
        return
    try:
        libc_name = {"linux": "libc.so.6", "darwin": "libc.dylib", "freebsd": "libc.so"}[
            platform.system().lower()
        ]
        libc = ctypes.CDLL(libc_name, use_errno=True)
        if hasattr(libc, "munlock"):
            libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libc.munlock.restype = ctypes.c_int
            libc.munlock(addr, size)
    except (OSError, KeyError):
        pass


class SecureHeapBlock:
    """
    A single block in the secure heap with enhanced protection mechanisms.

    This class represents a memory block with additional metadata and
    protection features to ensure that sensitive data is properly isolated
    and securely erased when no longer needed.
    """

    def __init__(self, size: int, canary_size: int = 16):
        """
        Initialize a secure heap block with canaries and metadata.

        Args:
            size: The requested size in bytes for the usable portion
            canary_size: Size of canary values in bytes for overflow detection

        The block structure:
        [header canary][metadata][front canary][usable memory][end canary]
        """
        self.block_id = secrets.token_hex(8)
        self.requested_size = size
        self.canary_size = canary_size

        # Calculate total size with canaries and metadata
        self.total_size = size + (canary_size * 3)  # Three canaries: header, front, end

        # Generate random canary values (different for each canary)
        self.header_canary = secrets.token_bytes(canary_size)
        self.front_canary = secrets.token_bytes(canary_size)
        self.end_canary = secrets.token_bytes(canary_size)

        # Allocate the entire buffer
        self.buffer = bytearray(self.total_size)

        # Set up canaries
        # Header canary (beginning of block)
        self.buffer[:canary_size] = self.header_canary
        # Front canary (before user data)
        front_canary_pos = canary_size
        self.buffer[front_canary_pos : front_canary_pos + canary_size] = self.front_canary
        # End canary (after user data)
        end_canary_pos = canary_size + canary_size + size
        self.buffer[end_canary_pos:] = self.end_canary

        # The usable memory area starts after the front canary
        self.data_offset = canary_size + canary_size

        # Lock this block's memory against swapping and exclude it from core
        # dumps so the key material it holds cannot leak to disk (#63).
        self.locked = _lock_and_protect_buffer(self.buffer)

        # Track when this block was allocated for detection of memory leaks
        self.allocation_time = time.time()
        self.last_access_time = self.allocation_time

        # Reference to stack trace for debugging (if enabled)
        self.allocation_traceback = None
        if os.environ.get("DEBUG_SECURE_ALLOCATOR") == "1":
            import traceback

            self.allocation_traceback = traceback.extract_stack()

    @property
    def data(self) -> memoryview:
        """Get a memoryview of just the usable portion of the block."""
        return memoryview(self.buffer)[self.data_offset : self.data_offset + self.requested_size]

    def check_canaries(self) -> bool:
        """
        Check all canaries to detect buffer overflows or memory corruption.

        Returns:
            bool: True if all canaries are intact, False if any have been modified
        """
        # Check header canary
        if bytes(self.buffer[: self.canary_size]) != self.header_canary:
            return False

        # Check front canary (before user data)
        front_canary_pos = self.canary_size
        if (
            bytes(self.buffer[front_canary_pos : front_canary_pos + self.canary_size])
            != self.front_canary
        ):
            return False

        # Check end canary (after user data)
        end_canary_pos = self.canary_size + self.canary_size + self.requested_size
        if bytes(self.buffer[end_canary_pos:]) != self.end_canary:
            return False

        return True

    def wipe(self, verification_level: int = 2) -> bool:
        """
        Securely wipe the entire block, including canaries and data.

        Args:
            verification_level: Level of verification (0=none, 1=sample, 2=full)

        Returns:
            bool: True if wiping was successful and verified, False otherwise
        """
        # Update last access time
        self.last_access_time = time.time()

        # First check canaries to detect any overflow before wiping
        canaries_intact = self.check_canaries()
        if not canaries_intact and os.environ.get("DEBUG_SECURE_ALLOCATOR") == "1":
            eprint(f"WARNING: Canary violation detected in block {self.block_id} before wiping")
            # Still continue with wiping to clean up what we can

        # Securely wipe the entire buffer, then release the memory lock.
        result = secure_memzero(self.buffer, full_verification=(verification_level == 2))
        if self.locked:
            _unlock_buffer(self.buffer)
            self.locked = False
        return result

    def __del__(self):
        """Ensure memory is wiped when the block is garbage collected."""
        try:
            self.wipe()
            # Remove references to potentially sensitive data
            self.header_canary = None
            self.front_canary = None
            self.end_canary = None
            self.buffer = None
        except Exception:
            # Fail silently in __del__ to avoid exceptions during garbage collection
            pass


class SecureBytes(BaseSecureBytes):
    """
    Enhanced secure bytes container with memory protection for cryptographic operations.

    This class extends the base SecureBytes with additional memory protections
    specifically designed for cryptographic operations, including canary
    protection, overflow detection, and anti-debugging measures.
    """

    def __init__(self, data=None, block=None):
        """
        Initialize a secure bytes container with enhanced protection.

        Args:
            data: Initial data (bytes, bytearray, str) or None
            block: SecureHeapBlock to use, or None to create a new one
        """
        super().__init__()

        # Store reference to the secure block if provided
        self._secure_block = block

        # Set data if provided
        if data is not None:
            if isinstance(data, str):
                self.extend(data.encode())
            elif isinstance(data, (bytes, bytearray)):
                self.extend(data)

    def check_integrity(self) -> bool:
        """
        Verify the integrity of the memory by checking canaries.

        Returns:
            bool: True if memory is intact, False if tampering is detected
        """
        if self._secure_block:
            return self._secure_block.check_canaries()
        return True

    def __enter__(self):
        """Enter the context manager - return self."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the context manager - securely clear memory."""
        try:
            secure_memzero(self)
        except Exception:
            pass  # Fail silently to avoid masking original exceptions
        return False  # Don't suppress exceptions

    def __del__(self):
        """Ensure memory is securely wiped before deletion."""
        try:
            # Wipe our own data
            secure_memzero(self)

            # If we have a secure block, let it handle its own cleanup
            # in its __del__ method
            self._secure_block = None
        except Exception:
            # Fail silently in __del__ to avoid exceptions during garbage collection
            pass


class SecureHeap:
    """
    A secure heap implementation for sensitive cryptographic data.

    This class provides a protected region of memory for allocating
    sensitive data like encryption keys, passwords, and other
    cryptographic material. It implements multiple layers of
    protection against memory disclosure attacks.
    """

    def __init__(self, max_size: int = 10 * 1024 * 1024):
        """
        Initialize the secure heap with a maximum size limit.

        Args:
            max_size: Maximum total size of the heap in bytes (default 10MB)
        """
        self.max_size = max_size
        self.current_size = 0
        self.blocks: Dict[str, SecureHeapBlock] = {}
        self.lock = threading.RLock()

        # Track if we're shutting down
        self.shutting_down = False

        # Platform detection for platform-specific features
        self.system = platform.system().lower()
        self.page_size = get_memory_page_size()

        # Register cleanup function to run at exit
        atexit.register(self.cleanup)

        # Optionally enable debug logging
        self.debug_mode = os.environ.get("DEBUG_SECURE_ALLOCATOR") == "1"
        self.quiet = not self.debug_mode

        # Setup prevention of core dumps if possible
        self._setup_core_dump_prevention()

    def _setup_core_dump_prevention(self):
        """Set up protections against core dumps if supported by platform."""
        try:
            # Try to disable core dumps on Unix platforms
            if self.system in ("linux", "darwin", "freebsd"):
                try:
                    import resource

                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                except ImportError:
                    pass
        except Exception:
            if self.debug_mode:
                eprint("Failed to set up core dump prevention")

    def _detect_debugger(self) -> bool:
        """
        Detect if a debugger is attached to the process.

        Returns:
            bool: True if a debugger is detected, False otherwise
        """
        if self.system == "linux":
            try:
                with open("/proc/self/status", "r") as f:
                    status = f.read()
                    if "TracerPid:\t0" not in status:
                        return True
            except Exception:
                pass
        elif self.system == "windows":
            try:
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                if hasattr(kernel32, "IsDebuggerPresent"):
                    if kernel32.IsDebuggerPresent():
                        return True
            except Exception:
                pass

        return False

    def allocate(self, size: int) -> Tuple[str, memoryview]:
        """
        Allocate a secure memory block of the specified size.

        Args:
            size: Size in bytes to allocate

        Returns:
            Tuple of (block_id, memoryview) where the memoryview points to the
            usable memory area of the allocated block

        Raises:
            SecureMemoryError: If the size is invalid or exceeds limits or if allocation fails
        """
        if not isinstance(size, int) or size <= 0:
            raise SecureMemoryError(
                "Invalid memory allocation size",
                f"Size must be a positive integer, got {size} of type {type(size)}",
            )

        # Apply size limits to prevent DoS
        if size > self.max_size // 10:
            raise SecureMemoryError(
                "Memory allocation size exceeds limits",
                f"Requested size {size} exceeds maximum allowed block size "
                f"{self.max_size // 10}",
            )

        # Check if adding this block would exceed the heap size limit
        if self.current_size + size > self.max_size:
            raise SecureMemoryError(
                "Memory allocation would exceed heap limit",
                f"Allocation would exceed secure heap size limit "
                f"({self.current_size + size} > {self.max_size})",
            )

        # Security check: Detect debugger
        if self._detect_debugger() and not self.quiet:
            eprint("Warning: Debugger detected during secure memory allocation")

        with self.lock:
            # Create a new secure block
            block = SecureHeapBlock(size)

            # Store block by ID
            self.blocks[block.block_id] = block

            # Update current size
            self.current_size += block.total_size

            return block.block_id, block.data

    def allocate_bytes(self, size: int, zero: bool = True) -> Tuple[str, memoryview]:
        """
        Allocate secure storage of the specified size.

        Returns a writable memoryview into the block's canary-guarded, mlock'd
        usable region, so data written through it physically resides in the
        protected memory (#60). The backing bytearray is zero-initialised, so the
        region is already zeroed regardless of ``zero``.

        Args:
            size: Size in bytes to allocate
            zero: Retained for API compatibility (the region is always zeroed)

        Returns:
            Tuple of (block_id, memoryview) into the protected usable region

        Raises:
            SecureMemoryError: If the size is invalid or exceeds limits or if allocation fails
        """
        # allocate() already returns block.data, a memoryview into the usable
        # (canary-guarded) region of the freshly zero-initialised block buffer.
        return self.allocate(size)

    def free(self, block_id: str, verification_level: int = 2) -> bool:
        """
        Explicitly free a secure memory block with verification.

        Args:
            block_id: The ID of the block to free
            verification_level: Level of verification (0=none, 1=sample, 2=full)

        Returns:
            bool: True if freeing was successful and verified, False otherwise
        """
        with self.lock:
            # Get the block
            block = self.blocks.get(block_id)
            if not block:
                # Raise a secure error for non-existent blocks
                if not isinstance(block_id, str):
                    raise SecureMemoryError(
                        "Invalid block ID type",
                        f"Block ID must be a string, got {type(block_id)}",
                    )
                raise SecureMemoryError("Block not found", f"No block with ID {block_id} exists")

            # Check canaries before wiping
            if not block.check_canaries() and not self.quiet:
                eprint(f"Warning: Canary violation detected in block {block_id} during free")

            # Wipe the block
            success = block.wipe(verification_level)

            # Update current size
            self.current_size -= block.total_size

            # Remove from blocks
            del self.blocks[block_id]

            return success

    def check_integrity(self) -> Dict[str, bool]:
        """
        Check the integrity of all blocks by verifying their canaries.

        Returns:
            Dict mapping block IDs to integrity status (True = intact, False = violated)
        """
        result = {}
        with self.lock:
            for block_id, block in self.blocks.items():
                result[block_id] = block.check_canaries()
        return result

    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the secure heap.

        Returns:
            Dict with statistics about heap usage and blocks
        """
        with self.lock:
            # Count blocks and sizes
            block_count = len(self.blocks)
            total_requested = sum(block.requested_size for block in self.blocks.values())
            total_overhead = self.current_size - total_requested

            # Calculate average time since allocation to detect potential leaks
            now = time.time()
            block_ages = [(now - block.allocation_time) for block in self.blocks.values()]
            avg_age = sum(block_ages) / len(block_ages) if block_ages else 0

            return {
                "block_count": block_count,
                "current_size": self.current_size,
                "max_size": self.max_size,
                "utilization_percent": (
                    (self.current_size / self.max_size) * 100 if self.max_size > 0 else 0
                ),
                "total_requested": total_requested,
                "total_overhead": total_overhead,
                "overhead_percent": (
                    (total_overhead / self.current_size) * 100 if self.current_size > 0 else 0
                ),
                "average_block_age_seconds": avg_age,
            }

    def cleanup(self):
        """
        Clean up all allocated blocks, called automatically at program exit.
        """
        with self.lock:
            # Mark that we're shutting down
            self.shutting_down = True

            # Make a copy of the keys since we'll be modifying the dictionary
            block_ids = list(self.blocks.keys())

            # Free all blocks
            for block_id in block_ids:
                self.free(block_id)

            # Reset state
            self.blocks = {}
            self.current_size = 0

    def __del__(self):
        """Ensure all blocks are freed when the heap is destroyed."""
        try:
            self.cleanup()
        except Exception:
            # Fail silently in __del__ to avoid exceptions during garbage collection
            pass


# Global secure heap instance
_global_secure_heap = SecureHeap()


# Module-level allocation functions that use the global secure heap
@secure_memory_error_handler
def allocate_secure_memory(size: int) -> Tuple[str, memoryview]:
    """
    Allocate secure memory for cryptographic operations.

    Args:
        size: Size in bytes to allocate

    Returns:
        Tuple of (block_id, memoryview) for accessing the memory
    """
    return _global_secure_heap.allocate(size)


@secure_memory_error_handler
def allocate_secure_crypto_buffer(size: int, zero: bool = True) -> Tuple[str, memoryview]:
    """
    Allocate a secure buffer specifically for cryptographic operations.

    This function allocates memory with additional protections specifically
    designed for cryptographic keys, IVs, and other sensitive material.

    Args:
        size: Size in bytes to allocate
        zero: Whether to zero-initialize the memory

    Returns:
        Tuple of (block_id, SecureBytes) containing the allocated secure bytes
    """
    return _global_secure_heap.allocate_bytes(size, zero)


def crypto_buffer_integrity(block_id: str) -> bool:
    """Return True if the block's canaries are intact (guarding the real data)."""
    block = _global_secure_heap.blocks.get(block_id)
    if block is None:
        return False
    return block.check_canaries()


@secure_memory_error_handler
def free_secure_crypto_buffer(block_id: str, verification_level: int = 2) -> bool:
    """
    Explicitly free a secure cryptographic buffer with zeroing verification.

    Args:
        block_id: The ID of the secure block to free
        verification_level: Level of verification (0=none, 1=sample, 2=full)

    Returns:
        bool: True if freeing was successful and verified, False otherwise
    """
    return _global_secure_heap.free(block_id, verification_level)


@secure_memory_error_handler
def check_all_crypto_buffer_integrity() -> bool:
    """
    Check the integrity of all allocated cryptographic buffers.

    Returns:
        bool: True if all buffers are intact, False if any are compromised
    """
    integrity_map = _global_secure_heap.check_integrity()
    return all(integrity_map.values())


@secure_memory_error_handler
def get_crypto_heap_stats() -> Dict[str, Any]:
    """
    Get statistics about the secure cryptographic heap.

    Returns:
        Dict with statistics about heap usage and buffers
    """
    return _global_secure_heap.get_stats()


@secure_memory_error_handler
def cleanup_secure_heap():
    """
    Force cleanup of all secure heap allocations.

    This function should be called explicitly in security-critical
    situations where immediate cleanup is required, such as when
    shutting down a security module or when detecting potential
    security breaches.
    """
    _global_secure_heap.cleanup()


# Register cleanup function to ensure memory is wiped at program exit
atexit.register(cleanup_secure_heap)
