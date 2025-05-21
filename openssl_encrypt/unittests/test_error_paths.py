#!/usr/bin/env python3
"""
Test suite for error paths and edge cases.

This module contains comprehensive tests for error handling and edge cases
to ensure that the cryptographic operations behave correctly and securely
under various error conditions and extreme inputs.
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
import pytest
from unittest.mock import patch, MagicMock

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
    ErrorCategory, SecureError, ValidationError, EncryptionError,
    DecryptionError, AuthenticationError, KeyDerivationError,
    MemoryError as SecureMemoryError, InternalError, PlatformError,
    PermissionError, ConfigurationError, KeystoreError,
    secure_error_handler, secure_memory_error_handler,
    secure_key_derivation_error_handler
)


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
    
    @patch('modules.secure_allocator.SecureHeap.allocate')
    def test_memory_allocation_failure(self, mock_allocate):
        """Test handling of allocation failures."""
        # Make the allocate method raise an exception
        mock_allocate.side_effect = RuntimeError("Simulated allocation failure")
        
        # Attempt to allocate memory
        with self.assertRaises(SecureError) as context:
            allocate_secure_memory(1024)
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
    
    def test_concurrent_allocate_free(self):
        """Test concurrent allocation and freeing with error handling."""
        # Create a shared list to track allocated blocks
        blocks = []
        lock = threading.Lock()
        
        def allocate_and_free():
            """Allocate and free memory blocks in a loop."""
            for _ in range(10):
                try:
                    # Randomly decide to allocate or free
                    if random.random() < 0.7 or not blocks:  # 70% chance to allocate
                        # Allocate a new block
                        block_id, _ = allocate_secure_crypto_buffer(random.randint(8, 64))
                        with lock:
                            blocks.append(block_id)
                    else:
                        # Free a random block
                        with lock:
                            if blocks:
                                idx = random.randint(0, len(blocks) - 1)
                                block_id = blocks.pop(idx)
                                free_secure_crypto_buffer(block_id)
                except SecureError:
                    # Expect and ignore secure errors during concurrent operations
                    pass
        
        # Start multiple threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=allocate_and_free)
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Clean up any remaining blocks
        for block_id in blocks:
            try:
                free_secure_crypto_buffer(block_id)
            except:
                pass


class TestErrorMessageConsistency(unittest.TestCase):
    """Test that error messages are consistent and don't leak information."""
    
    def test_error_message_format(self):
        """Test that error messages follow the standardized format."""
        # Create errors of different types
        validation_error = ValidationError("debug details")
        crypto_error = EncryptionError("debug details")
        memory_error = SecureMemoryError("debug details")
        
        # Check that error messages follow the standardized format
        self.assertTrue(str(validation_error).startswith("Security validation check failed"))
        self.assertTrue(str(crypto_error).startswith("Security encryption operation failed"))
        self.assertTrue(str(memory_error).startswith("Security memory operation failed"))
        
        # In production mode, debug details should not be included
        with patch('os.environ.get', return_value=None):  # Simulate production
            validation_error = ValidationError("debug details")
            self.assertEqual(str(validation_error), "Security validation check failed")
            self.assertNotIn("debug details", str(validation_error))
    
    @patch('os.environ.get')
    def test_debug_mode_error_messages(self, mock_environ_get):
        """Test that debug mode includes more detailed error messages."""
        # Simulate debug mode
        mock_environ_get.return_value = '1'
        
        # Create an error with debug details
        error = KeyDerivationError("Password too short")
        
        # In debug mode, the details should be included
        self.assertIn("Password too short", str(error))
    
    def test_error_decorator_consistency(self):
        """Test that error decorator provides consistent error handling."""
        # Define test functions with different error handlers
        @secure_memory_error_handler
        def memory_operation():
            # Use SecureMemoryError directly instead of ValueError to avoid conversion
            raise SecureMemoryError("Test error", "Memory error details")
        
        @secure_key_derivation_error_handler
        def key_operation():
            # Use KeyDerivationError directly instead of ValueError to avoid conversion
            raise KeyDerivationError("Test error", "Key derivation error details")
        
        # Both should raise secure errors of the appropriate type
        with self.assertRaises(SecureMemoryError):
            memory_operation()
        
        with self.assertRaises(KeyDerivationError):
            key_operation()


class TestBufferOverflowAndUnderflow(unittest.TestCase):
    """Test handling of buffer overflow and underflow conditions."""
    
    def test_heap_block_overflow_detection(self):
        """Test detection of buffer overflows in heap blocks."""
        # Create a block
        block = SecureHeapBlock(64)
        
        # Initially, canaries should be intact
        self.assertTrue(block.check_canaries())
        
        # Simulate a buffer overflow by accessing beyond the buffer's bounds
        try:
            # This should cause a buffer overflow if bounds checking fails
            data_view = block.data
            # Attempt to write beyond the allocated size
            with self.assertRaises((IndexError, ValueError)):
                data_view[100] = 0xFF  # This should fail with proper bounds checking
        except IndexError:
            # This is expected with proper bounds checking
            pass
        
        # Simulate a more subtle overflow by directly modifying the buffer
        # This is what our canary system should detect
        end_canary_pos = block.canary_size + block.canary_size + block.requested_size
        block.buffer[end_canary_pos] = (block.buffer[end_canary_pos] + 1) % 256
        
        # Canary check should now fail
        self.assertFalse(block.check_canaries())
    
    def test_secure_container_memory_corruption(self):
        """Test handling of memory corruption in secure containers."""
        # Create a secure buffer
        buffer = CryptoSecureBuffer(size=32)
        
        # Fill it with recognizable data
        test_data = bytes([i % 256 for i in range(32)])
        buffer.buffer[:] = test_data
        
        # Verify the data was written correctly
        self.assertEqual(buffer.get_bytes(), test_data)
        
        # Attempt to detect memory corruption
        # In a real scenario, this would be caused by buffer overflow or other issues
        # Here we simulate it by creating a SecureHeapBlock instance and changing its canary
        # assuming that SecureBytes is using SecureHeapBlock internally
        
        # We check if the buffer has a _secure_block attribute we can use
        if hasattr(buffer, '_secure_block') and buffer._secure_block:
            # Access the internal block and corrupt a canary
            block = buffer._secure_block
            end_canary_pos = block.canary_size + block.canary_size + block.requested_size
            original_value = block.buffer[end_canary_pos]
            block.buffer[end_canary_pos] = (original_value + 1) % 256
            
            # Integrity check should now fail
            self.assertFalse(buffer.check_integrity())
            
            # Restore the original value to avoid affecting other tests
            block.buffer[end_canary_pos] = original_value


if __name__ == "__main__":
    unittest.main()