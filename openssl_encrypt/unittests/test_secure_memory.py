#!/usr/bin/env python3
"""
Test suite for secure memory functionality.

This module contains tests for the secure memory allocator and cryptographic
secure memory utilities, verifying that memory protection mechanisms work
as expected and sensitive data is properly protected.
"""

import os
import sys
import tempfile
import shutil
import unittest
import threading
import time
import random
import gc
from concurrent.futures import ThreadPoolExecutor

# Add the parent directory to path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import modules to test
from modules.secure_allocator import (
    SecureHeapBlock, SecureHeap, SecureBytes,
    allocate_secure_memory, allocate_secure_crypto_buffer,
    free_secure_crypto_buffer, check_all_crypto_buffer_integrity,
    get_crypto_heap_stats, cleanup_secure_heap
)
from modules.crypto_secure_memory import (
    CryptoSecureBuffer, CryptoKey, CryptoIV,
    secure_crypto_buffer, secure_crypto_key, secure_crypto_iv,
    generate_secure_key, create_key_from_password,
    validate_crypto_memory_integrity
)
from modules.secure_memory import (
    verify_memory_zeroed, secure_memzero
)
from modules.crypt_errors import (
    MemoryError as SecureMemoryError
)


class TestSecureHeapBlock(unittest.TestCase):
    """Test cases for the SecureHeapBlock class."""
    
    def test_creation_and_data_access(self):
        """Test creating a heap block and accessing its data."""
        # Create a block with a specific size
        block_size = 1024
        block = SecureHeapBlock(block_size)
        
        # Verify block properties
        self.assertEqual(block.requested_size, block_size)
        self.assertTrue(block.total_size > block_size)  # Should include canaries
        
        # Verify we can access the data area
        data_view = block.data
        self.assertEqual(len(data_view), block_size)
        
        # Write some data and read it back
        test_data = b"Test data for secure heap block"
        data_view[:len(test_data)] = test_data
        self.assertEqual(bytes(data_view[:len(test_data)]), test_data)
    
    def test_canary_protection(self):
        """Test canary protection against buffer overflows."""
        block = SecureHeapBlock(100)
        
        # Initially, canaries should be intact
        self.assertTrue(block.check_canaries())
        
        # Simulate a buffer overflow by modifying the end canary
        end_canary_pos = block.canary_size + block.canary_size + block.requested_size
        block.buffer[end_canary_pos] = (block.buffer[end_canary_pos] + 1) % 256
        
        # Canary check should now fail
        self.assertFalse(block.check_canaries())
    
    def test_secure_wiping(self):
        """Test secure wiping of heap block data."""
        block = SecureHeapBlock(256)
        
        # Fill with test pattern
        pattern = bytearray([0xA5] * 256)
        data_view = block.data
        data_view[:] = pattern
        
        # Verify data was written
        self.assertEqual(bytes(data_view), bytes(pattern))
        
        # Wipe the block
        self.assertTrue(block.wipe(verification_level=2))
        
        # Verify the data area has been zeroed
        self.assertTrue(verify_memory_zeroed(data_view))


class TestSecureHeap(unittest.TestCase):
    """Test cases for the SecureHeap class."""
    
    def setUp(self):
        """Set up test environment."""
        # Create a separate test heap with smaller limits for testing
        self.test_heap = SecureHeap(max_size=1024 * 1024)  # 1MB max
    
    def tearDown(self):
        """Clean up test environment."""
        # Ensure test heap is cleaned up
        self.test_heap.cleanup()
    
    def test_allocation_and_freeing(self):
        """Test allocating and freeing memory blocks."""
        # Allocate a block
        block_id, mem_view = self.test_heap.allocate(1024)
        
        # Block should be tracked in the heap
        self.assertIn(block_id, self.test_heap.blocks)
        
        # Memory view should be usable
        test_data = bytearray([i % 256 for i in range(100)])
        mem_view[:100] = test_data
        self.assertEqual(bytes(mem_view[:100]), bytes(test_data))
        
        # Free the block
        self.assertTrue(self.test_heap.free(block_id))
        
        # Block should no longer be tracked
        self.assertNotIn(block_id, self.test_heap.blocks)
    
    def test_secure_bytes_allocation(self):
        """Test allocating SecureBytes objects through the heap."""
        # Allocate secure bytes
        block_id, secure_bytes = self.test_heap.allocate_bytes(512, zero=True)
        
        # Block should be tracked in the heap
        self.assertIn(block_id, self.test_heap.blocks)
        
        # Secure bytes should be zeroed
        self.assertEqual(bytes(secure_bytes), bytes(bytearray(512)))
        
        # We should be able to modify the bytes
        test_data = b"Test data"
        secure_bytes[:len(test_data)] = test_data
        self.assertEqual(bytes(secure_bytes[:len(test_data)]), test_data)
        
        # Free the block
        self.assertTrue(self.test_heap.free(block_id))
    
    def test_heap_size_limits(self):
        """Test enforcement of heap size limits."""
        # Try to allocate a block larger than the heap max size
        with self.assertRaises(SecureMemoryError):
            self.test_heap.allocate(2 * 1024 * 1024)  # 2MB > 1MB
        
        # Allocate blocks up to the limit
        blocks = []
        try:
            # Allocate 100KB blocks until we hit the limit
            block_size = 100 * 1024
            while True:
                block_id, _ = self.test_heap.allocate(block_size)
                blocks.append(block_id)
        except SecureMemoryError:
            # We expect a SecureMemoryError when we hit the limit
            pass
        
        # Should have allocated at least a few blocks
        self.assertGreater(len(blocks), 0)
        
        # Free all blocks
        for block_id in blocks:
            self.test_heap.free(block_id)
    
    def test_integrity_checking(self):
        """Test integrity checking of all heap blocks."""
        # Allocate some blocks
        block_ids = []
        for _ in range(5):
            block_id, _ = self.test_heap.allocate(64)
            block_ids.append(block_id)
        
        # Initially all blocks should pass integrity check
        integrity = self.test_heap.check_integrity()
        for block_id in block_ids:
            self.assertTrue(integrity[block_id])
        
        # Simulate tampering with one block's canary
        tampered_block_id = block_ids[2]
        block = self.test_heap.blocks[tampered_block_id]
        end_canary_pos = block.canary_size + block.canary_size + block.requested_size
        block.buffer[end_canary_pos] = (block.buffer[end_canary_pos] + 1) % 256
        
        # Check integrity again
        integrity = self.test_heap.check_integrity()
        for i, block_id in enumerate(block_ids):
            if i == 2:
                self.assertFalse(integrity[block_id])
            else:
                self.assertTrue(integrity[block_id])
        
        # Free all blocks
        for block_id in block_ids:
            self.test_heap.free(block_id)
    
    def test_heap_statistics(self):
        """Test getting statistics about heap usage."""
        # Get initial stats
        stats = self.test_heap.get_stats()
        initial_block_count = stats['block_count']
        
        # Allocate some blocks
        block_ids = []
        for size in [128, 256, 512]:
            block_id, _ = self.test_heap.allocate(size)
            block_ids.append(block_id)
        
        # Get updated stats
        stats = self.test_heap.get_stats()
        
        # Check stats are updated correctly
        self.assertEqual(stats['block_count'], initial_block_count + 3)
        self.assertGreaterEqual(stats['current_size'], 128 + 256 + 512)
        self.assertLess(stats['utilization_percent'], 100)
        
        # Free all blocks
        for block_id in block_ids:
            self.test_heap.free(block_id)


class TestSecureBytes(unittest.TestCase):
    """Test cases for the enhanced SecureBytes class."""
    
    def test_creation_and_modification(self):
        """Test creating and modifying SecureBytes."""
        # Create a SecureBytes object with initial data
        secure_bytes = SecureBytes(b"Initial test data")
        
        # Check data access
        self.assertEqual(bytes(secure_bytes), b"Initial test data")
        
        # Modify the data
        secure_bytes[:7] = b"Updated"
        self.assertEqual(bytes(secure_bytes), b"Updated test data")
    
    def test_integrity_checking(self):
        """Test integrity checking for SecureBytes."""
        # Create SecureBytes with heap block
        block = SecureHeapBlock(100)
        secure_bytes = SecureBytes(block=block)
        
        # Fill with test data
        secure_bytes.extend(b"Test data")
        
        # Initially integrity should be good
        self.assertTrue(secure_bytes.check_integrity())
        
        # Simulate memory tampering
        end_canary_pos = block.canary_size + block.canary_size + block.requested_size
        block.buffer[end_canary_pos] = (block.buffer[end_canary_pos] + 1) % 256
        
        # Integrity check should now fail
        self.assertFalse(secure_bytes.check_integrity())


class TestCryptoSecureMemory(unittest.TestCase):
    """Test cases for cryptographic secure memory utilities."""
    
    def test_crypto_secure_buffer(self):
        """Test CryptoSecureBuffer functionality."""
        # Create a buffer with size
        buffer = CryptoSecureBuffer(size=256)
        
        # Should be initially zeroed
        self.assertEqual(bytes(buffer.get_bytes()), bytes(bytearray(256)))
        
        # Create a buffer with data
        test_data = b"Test cryptographic data"
        buffer2 = CryptoSecureBuffer(data=test_data)
        
        # Data should match
        self.assertEqual(buffer2.get_bytes(), test_data)
        
        # Clear the buffer
        buffer2.clear()
        
        # Should raise exception after clearing
        with self.assertRaises(SecureMemoryError):
            buffer2.get_bytes()
    
    def test_crypto_key(self):
        """Test CryptoKey functionality."""
        # Create a random key
        key = CryptoKey(key_size=32)
        
        # Key should have the right size
        self.assertEqual(len(key), 32)
        
        # Create a key with specific data
        key_data = bytes([i % 256 for i in range(16)])
        key2 = CryptoKey(key_data=key_data)
        self.assertEqual(key2.get_bytes(), key_data)
        
        # Derive a subkey
        info = b"context info"
        subkey = key2.derive_subkey(info, 32)
        
        # Subkey should have the requested length
        self.assertEqual(len(subkey), 32)
        
        # Subkey should be different from original key
        self.assertNotEqual(subkey.get_bytes()[:16], key_data)
    
    def test_crypto_iv(self):
        """Test CryptoIV functionality."""
        # Create a random IV
        iv = CryptoIV(iv_size=16, random=True)
        
        # IV should have the right size
        self.assertEqual(len(iv), 16)
        
        # IV should not be all zeros
        self.assertNotEqual(iv.get_bytes(), bytes(16))
        
        # Create a zero IV
        zero_iv = CryptoIV(iv_size=16, random=False)
        
        # Should be all zeros
        self.assertEqual(zero_iv.get_bytes(), bytes(16))
    
    def test_context_managers(self):
        """Test context manager functionality."""
        # Test secure_crypto_buffer context manager
        data = None
        with secure_crypto_buffer(64) as buffer:
            # Fill with data
            for i in range(64):
                buffer.buffer[i] = i % 256
            
            # Save a copy for comparison
            data = buffer.get_bytes()
        
        # Outside the context, buffer should be cleared
        # We can't directly check buffer.buffer, but we can verify
        # the global heap state is clean
        stats = get_crypto_heap_stats()
        self.assertEqual(stats['block_count'], 0)
        
        # Test secure_crypto_key context manager
        with secure_crypto_key(key_size=32) as key:
            # Key should have data
            key_data = key.get_bytes()
            self.assertEqual(len(key_data), 32)
        
        # Test secure_crypto_iv context manager
        with secure_crypto_iv(iv_size=16) as iv:
            # IV should have data
            iv_data = iv.get_bytes()
            self.assertEqual(len(iv_data), 16)
    
    def test_key_derivation(self):
        """Test key derivation from password."""
        # Create a key from a password
        password = "test password"
        salt = b"test salt"
        key = create_key_from_password(password, salt, 32)
        
        # Key should have the right size
        self.assertEqual(len(key), 32)
        
        # Creating a key with the same password and salt should yield the same key
        key2 = create_key_from_password(password, salt, 32)
        self.assertEqual(key.get_bytes(), key2.get_bytes())
        
        # Different salt should yield different key
        key3 = create_key_from_password(password, b"different salt", 32)
        self.assertNotEqual(key.get_bytes(), key3.get_bytes())
    
    def test_integrity_validation(self):
        """Test cryptographic memory integrity validation."""
        # Initially, no allocations so validation should pass
        self.assertTrue(validate_crypto_memory_integrity())
        
        # Allocate some buffers
        buffers = []
        for _ in range(3):
            buffers.append(CryptoSecureBuffer(size=64))
        
        # Validation should still pass
        self.assertTrue(validate_crypto_memory_integrity())
        
        # Clean up
        for buffer in buffers:
            buffer.clear()


class TestThreadSafety(unittest.TestCase):
    """Test cases for thread safety of secure memory operations."""
    
    def test_concurrent_allocations(self):
        """Test concurrent allocations from multiple threads."""
        # Number of threads and allocations per thread
        num_threads = 10
        allocs_per_thread = 50
        
        # Track allocation results
        results = []
        lock = threading.Lock()
        
        def allocate_buffers():
            thread_results = []
            for _ in range(allocs_per_thread):
                # Allocate a buffer
                buffer = CryptoSecureBuffer(size=random.randint(16, 256))
                
                # Fill with recognizable data
                thread_id_bytes = threading.get_ident().to_bytes(8, byteorder='big')
                buffer.buffer[:8] = thread_id_bytes
                
                # Store the buffer
                thread_results.append(buffer)
                
                # Small delay to increase thread interleaving
                time.sleep(0.001)
            
            # Add results to the global list
            with lock:
                results.extend(thread_results)
        
        # Start threads
        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=allocate_buffers)
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify results
        self.assertEqual(len(results), num_threads * allocs_per_thread)
        
        # Check that all buffers have valid data
        for buffer in results:
            self.assertTrue(buffer.check_integrity())
        
        # Clean up
        for buffer in results:
            buffer.clear()
    
    def test_concurrent_mixed_operations(self):
        """Test concurrent mixed allocations and deallocations."""
        # Create a thread pool
        with ThreadPoolExecutor(max_workers=8) as executor:
            # Track allocation results and operations count
            buffers = []
            alloc_count = 0
            free_count = 0
            lock = threading.Lock()
            
            def random_operation():
                nonlocal alloc_count, free_count
                
                # Randomly allocate or free
                op = random.randint(0, 1)
                
                if op == 0 or not buffers:
                    # Allocate a new buffer
                    buffer = CryptoSecureBuffer(size=random.randint(16, 256))
                    with lock:
                        buffers.append(buffer)
                        alloc_count += 1
                else:
                    # Free a random buffer
                    with lock:
                        if buffers:
                            idx = random.randint(0, len(buffers) - 1)
                            buffer = buffers.pop(idx)
                            buffer.clear()
                            free_count += 1
            
            # Submit a large number of random operations
            futures = [executor.submit(random_operation) for _ in range(500)]
            
            # Wait for all operations to complete
            for future in futures:
                future.result()
            
            # Clean up any remaining buffers
            for buffer in buffers:
                buffer.clear()
            
            # Verify operations completed
            self.assertGreater(alloc_count, 0)
            self.assertGreater(free_count, 0)


if __name__ == "__main__":
    unittest.main()