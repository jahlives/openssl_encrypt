#!/usr/bin/env python3
"""
Test suite for secure memory management functionality.

This module contains comprehensive tests for:
- Secure heap block allocation
- Secure heap management
- SecureBytes class
- CryptoSecureMemory
- Thread safety
- Error handling
"""

import os
import random
import secrets
import shutil
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

import pytest

# Import secure memory modules
from openssl_encrypt.modules.crypt_errors import ErrorCategory
from openssl_encrypt.modules.crypt_errors import MemoryError as SecureMemoryError
from openssl_encrypt.modules.crypt_errors import SecureError
from openssl_encrypt.modules.crypto_secure_memory import (
    CryptoKey,
    CryptoSecureBuffer,
    create_key_from_password,
    generate_secure_key,
    validate_crypto_memory_integrity,
)
from openssl_encrypt.modules.secure_allocator import (
    SecureBytes,
    SecureHeap,
    SecureHeapBlock,
    allocate_secure_crypto_buffer,
    allocate_secure_memory,
    free_secure_crypto_buffer,
)
from openssl_encrypt.modules.secure_memory import secure_memzero, verify_memory_zeroed


class TestSecureHeapBlock(unittest.TestCase):
    """Tests for the SecureHeapBlock class."""

    def test_create_secure_heap_block(self):
        """Test creating a secure heap block."""
        block = SecureHeapBlock(64)

        # Verify the block was created successfully
        self.assertEqual(block.requested_size, 64)
        self.assertIsNotNone(block.buffer)
        self.assertGreater(len(block.buffer), 64)  # Should include canaries

        # Verify canaries are in place
        self.assertTrue(block.check_canaries())

        # Clean up
        block.wipe()

    def test_secure_heap_block_data_access(self):
        """Test accessing data in a secure heap block."""
        block = SecureHeapBlock(64)

        # Get a view of the data
        data = block.data

        # Verify the data view has the correct size
        self.assertEqual(len(data), 64)

        # Write some data and verify it was written correctly
        for i in range(64):
            data[i] = i % 256

        # Verify the data can be read back correctly
        for i in range(64):
            self.assertEqual(data[i], i % 256)

        # Verify canaries are still intact
        self.assertTrue(block.check_canaries())

        # Clean up
        block.wipe()

    def test_secure_heap_block_clearing(self):
        """Test clearing a secure heap block."""
        block = SecureHeapBlock(64)

        # Write some data
        for i in range(64):
            block.data[i] = i % 256

        # Wipe the block
        block.wipe()

        # Verify data has been zeroed (is all zeros)
        all_zeros = True
        for i in range(64):
            if block.data[i] != 0:
                all_zeros = False
                break
        self.assertTrue(all_zeros)


class TestSecureHeap(unittest.TestCase):
    """Tests for the SecureHeap class."""

    def test_secure_heap_allocation(self):
        """Test allocating memory from the secure heap."""
        heap = SecureHeap()

        # Allocate some blocks
        block_id1, memview1 = heap.allocate(64)
        block_id2, memview2 = heap.allocate(128)

        # Verify blocks were allocated correctly
        self.assertIsInstance(block_id1, str)
        self.assertIsInstance(block_id2, str)
        self.assertEqual(len(memview1), 64)
        self.assertEqual(len(memview2), 128)

        # Verify both blocks have intact canaries using the integrity check
        integrity = heap.check_integrity()
        self.assertTrue(integrity[block_id1])
        self.assertTrue(integrity[block_id2])

        # Clean up
        heap.free(block_id1)
        heap.free(block_id2)
        heap.cleanup()

    def test_secure_heap_free(self):
        """Test freeing memory from the secure heap."""
        heap = SecureHeap()

        # Allocate and free a block
        block_id, _ = heap.allocate(64)
        result = heap.free(block_id)

        # Verify the block was freed successfully
        self.assertTrue(result)

        # Clean up
        heap.cleanup()

    def test_secure_heap_stats(self):
        """Test getting statistics from the secure heap."""
        heap = SecureHeap()

        # Allocate some blocks
        block_ids = [heap.allocate(64)[0] for _ in range(5)]

        # Get heap statistics
        stats = heap.get_stats()

        # Verify statistics
        self.assertEqual(stats["block_count"], 5)
        self.assertEqual(stats["total_requested"], 5 * 64)

        # Clean up
        for block_id in block_ids:
            heap.free(block_id)
        heap.cleanup()


class TestSecureBytes(unittest.TestCase):
    """Tests for the SecureBytes class."""

    def test_secure_bytes_creation(self):
        """Test creating a SecureBytes object."""
        # Import necessary functions
        from openssl_encrypt.modules.secure_allocator import (
            SecureBytes,
            allocate_secure_crypto_buffer,
            free_secure_crypto_buffer,
        )
        from openssl_encrypt.modules.secure_memory import SecureBytes as BaseSecureBytes

        # Create directly using the BaseSecureBytes class from secure_memory
        test_data = bytes([i % 256 for i in range(64)])
        base_secure_bytes = BaseSecureBytes()
        base_secure_bytes.extend(test_data)
        self.assertEqual(bytes(base_secure_bytes), test_data)

        # Create using the allocate_secure_crypto_buffer function
        block_id, secure_bytes = allocate_secure_crypto_buffer(64, zero=True)

        # Fill it with some data
        test_buffer = bytearray(secure_bytes)
        test_buffer[:] = bytes([0xAA] * 64)

        # Verify length and cleanup
        self.assertEqual(len(test_buffer), 64)
        free_secure_crypto_buffer(block_id)

    def test_secure_bytes_operations(self):
        """Test various operations on SecureBytes objects."""
        # Import necessary functions
        from openssl_encrypt.modules.secure_allocator import (
            allocate_secure_crypto_buffer,
            free_secure_crypto_buffer,
        )
        from openssl_encrypt.modules.secure_memory import SecureBytes

        # Create a SecureBytes object directly
        secure_bytes = SecureBytes()

        # Fill with test data
        test_data = bytes([i % 256 for i in range(64)])
        secure_bytes.extend(test_data)

        # Test conversion to bytes
        self.assertEqual(bytes(secure_bytes), test_data)

        # Test length
        self.assertEqual(len(secure_bytes), 64)

        # Test slicing
        self.assertEqual(bytes(secure_bytes[10:20]), test_data[10:20])

        # Test allocation through buffer allocation
        block_id, allocated_bytes = allocate_secure_crypto_buffer(32, zero=True)

        # Fill allocated bytes with data
        test_data2 = bytes([0xBB] * 32)
        buffer = bytearray(allocated_bytes)
        buffer[:] = test_data2

        # Verify contents
        self.assertEqual(bytes(buffer), test_data2)

        # Clean up
        free_secure_crypto_buffer(block_id)


class TestCryptoSecureMemory(unittest.TestCase):
    """Tests for crypto secure memory utilities."""

    def test_crypto_secure_buffer(self):
        """Test the CryptoSecureBuffer class."""
        # Create a buffer with size
        buffer_size = CryptoSecureBuffer(size=32)
        self.assertEqual(len(buffer_size), 32)

        # Create a buffer with data
        test_data = bytes([i % 256 for i in range(32)])
        buffer_data = CryptoSecureBuffer(data=test_data)
        self.assertEqual(buffer_data.get_bytes(), test_data)

        # Test clearing
        buffer_data.clear()
        with self.assertRaises(SecureMemoryError):
            buffer_data.get_bytes()  # Should raise after clearing

    def test_crypto_keys(self):
        """Test cryptographic key containers."""
        # Import from crypto_secure_memory module
        from openssl_encrypt.modules.crypto_secure_memory import (
            CryptoKey,
            create_key_from_password,
            generate_secure_key,
        )

        # Generate a random key
        key = generate_secure_key(32)
        self.assertEqual(len(key), 32)

        # Create a key from a password
        password_key = create_key_from_password("test password", b"salt", 32)
        self.assertEqual(len(password_key), 32)

        # Create a specific key container
        key_container = CryptoKey(key_data=key.get_bytes())
        self.assertEqual(len(key_container), 32)

        # Clean up
        key.clear()  # Using clear() as implemented in CryptoKey
        password_key.clear()
        key_container.clear()


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of secure memory operations."""

    def test_concurrent_allocations(self):
        """Test allocating memory concurrently from multiple threads."""
        # Number of allocations per thread
        allocs_per_thread = 10
        num_threads = 5

        # List to track allocated blocks for cleanup
        blocks = []
        blocks_lock = threading.Lock()

        # Function to allocate memory in a thread
        def allocate_memory():
            for _ in range(allocs_per_thread):
                try:
                    block_id, block = allocate_secure_crypto_buffer(random.randint(16, 64))
                    with blocks_lock:
                        blocks.append(block_id)
                except Exception as e:
                    self.fail(f"Exception during concurrent allocation: {e}")

        # Start multiple threads
        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=allocate_memory)
            thread.start()
            threads.append(thread)

        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=10.0)
            self.assertFalse(thread.is_alive(), "Thread timed out")

        # Verify the expected number of blocks were allocated
        self.assertEqual(len(blocks), num_threads * allocs_per_thread)

        # Clean up
        for block_id in blocks:
            free_secure_crypto_buffer(block_id)


class TestSecureMemoryErrorHandling(unittest.TestCase):
    """Test error handling in secure memory operations."""

    def test_invalid_allocation_size(self):
        """Test allocating memory with invalid size."""
        # Negative size
        with self.assertRaises(SecureError) as context:
            allocate_secure_memory(-10)
        self.assertEqual(context.exception.category, ErrorCategory.MEMORY)

        # Zero size
        with self.assertRaises(SecureError) as context:
            allocate_secure_memory(0)
        self.assertEqual(context.exception.category, ErrorCategory.MEMORY)

        # Non-integer size
        with self.assertRaises(SecureError) as context:
            allocate_secure_memory("not a number")
        self.assertEqual(context.exception.category, ErrorCategory.MEMORY)

    def test_invalid_block_free(self):
        """Test freeing invalid blocks."""
        # Nonexistent block ID
        with self.assertRaises(SecureError) as context:
            free_secure_crypto_buffer("nonexistent_block_id")
        self.assertEqual(context.exception.category, ErrorCategory.MEMORY)

        # Invalid block ID type
        with self.assertRaises(SecureError) as context:
            free_secure_crypto_buffer(123)  # Not a string
        self.assertEqual(context.exception.category, ErrorCategory.MEMORY)

    def test_double_free(self):
        """Test freeing a block twice."""
        # Allocate a block
        block_id, _ = allocate_secure_crypto_buffer(64)

        # Free it once (should succeed)
        self.assertTrue(free_secure_crypto_buffer(block_id))

        # Free it again (should raise an error)
        with self.assertRaises(SecureError) as context:
            free_secure_crypto_buffer(block_id)
        self.assertEqual(context.exception.category, ErrorCategory.MEMORY)


class TestCryptoSecureMemoryErrorHandling(unittest.TestCase):
    """Test error handling in cryptographic secure memory operations."""

    def test_invalid_crypto_buffer_creation(self):
        """Test creating crypto buffers with invalid parameters."""
        # Neither size nor data provided
        with self.assertRaises(SecureError) as context:
            CryptoSecureBuffer()
        self.assertEqual(context.exception.category, ErrorCategory.MEMORY)

        # Both size and data provided
        with self.assertRaises(SecureError) as context:
            CryptoSecureBuffer(size=10, data=b"data")
        self.assertEqual(context.exception.category, ErrorCategory.MEMORY)

        # Invalid data type
        with self.assertRaises(SecureError) as context:
            CryptoSecureBuffer(data=123)  # Not bytes-like
        self.assertEqual(context.exception.category, ErrorCategory.MEMORY)

    def test_using_cleared_buffer(self):
        """Test using a buffer after it has been cleared."""
        # Create and clear a buffer
        buffer = CryptoSecureBuffer(size=10)
        buffer.clear()

        # Attempt to get data from cleared buffer
        with self.assertRaises(SecureError) as context:
            buffer.get_bytes()
        self.assertEqual(context.exception.category, ErrorCategory.MEMORY)

    def test_key_derivation_errors(self):
        """Test error handling in key derivation."""
        # Test with invalid salt
        with self.assertRaises(SecureError) as context:
            create_key_from_password("password", None, 32)
        self.assertEqual(context.exception.category, ErrorCategory.KEY_DERIVATION)

        # Test with invalid key size
        with self.assertRaises(SecureError) as context:
            create_key_from_password("password", b"salt", -1)
        self.assertEqual(context.exception.category, ErrorCategory.KEY_DERIVATION)

        # Test with invalid hash iterations
        with self.assertRaises(SecureError) as context:
            create_key_from_password("password", b"salt", 32, "not a number")
        self.assertEqual(context.exception.category, ErrorCategory.KEY_DERIVATION)


class TestThreadedErrorHandling(unittest.TestCase):
    """Test error handling in multi-threaded environments."""

    def test_parallel_allocation_errors(self):
        """Test handling errors when allocating memory in parallel."""
        # Create a heap with a very small size limit
        test_heap = SecureHeap(max_size=1024)  # 1KB max

        # Use a thread-safe list to track errors
        errors = []
        lock = threading.Lock()

        def allocate_with_errors():
            """Allocate memory with potential errors."""
            try:
                # Try to allocate a block larger than the limit
                test_heap.allocate(2048)
                # If we get here, no error was raised
                with lock:
                    errors.append("Expected SecureMemoryError was not raised")
            except SecureMemoryError:
                # This is expected - success case
                pass
            except Exception as e:
                # Unexpected exception type
                with lock:
                    errors.append(f"Unexpected exception type: {type(e).__name__}, {str(e)}")

        # Start multiple threads to allocate memory
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=allocate_with_errors)
            # Mark as daemon to avoid hanging if there's an issue
            thread.daemon = True
            thread.start()
            threads.append(thread)

        # Wait for all threads to complete with a timeout
        for thread in threads:
            thread.join(timeout=5.0)

        # Clean up
        test_heap.cleanup()

        # Check if any errors were reported
        self.assertEqual(errors, [], f"Errors occurred during parallel allocation: {errors}")
