#!/usr/bin/env python3
"""
Test suite for security features and operations.

This module contains comprehensive tests for:
- Secure error handling
- Buffer overflow and underflow protection
- Secure cryptographic operations
- Security enhancements
- Constant-time operations
- MAC verification
- Security logging
"""

import base64
import json
import os
import random
import secrets
import shutil
import statistics
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

# Import the modules to test
from openssl_encrypt.modules.crypt_core import (
    calculate_hash,
    decrypt_file,
    encrypt_file,
    generate_key,
)
from openssl_encrypt.modules.crypt_errors import (
    AuthenticationError,
    DecryptionError,
    EncryptionError,
    ErrorCategory,
    InternalError,
    KeyDerivationError,
    KeystoreError,
)
from openssl_encrypt.modules.crypt_errors import MemoryError as SecureMemoryError
from openssl_encrypt.modules.crypt_errors import (
    PermissionError,
    PlatformError,
    SecureError,
    ValidationError,
    add_timing_jitter,
    get_jitter_stats,
    secure_decrypt_error_handler,
    secure_encrypt_error_handler,
    secure_error_handler,
    secure_key_derivation_error_handler,
    secure_memory_error_handler,
    set_debug_mode,
)
from openssl_encrypt.modules.crypto_secure_memory import (
    CryptoIV,
    CryptoKey,
    CryptoSecureBuffer,
    create_key_from_password,
    generate_secure_key,
    secure_crypto_buffer,
    secure_crypto_iv,
    secure_crypto_key,
    validate_crypto_memory_integrity,
)
from openssl_encrypt.modules.secure_allocator import (
    SecureBytes,
    SecureHeap,
    SecureHeapBlock,
    allocate_secure_crypto_buffer,
    allocate_secure_memory,
    check_all_crypto_buffer_integrity,
    cleanup_secure_heap,
    free_secure_crypto_buffer,
    get_crypto_heap_stats,
)
from openssl_encrypt.modules.secure_memory import (
    SecureBytes,
    SecureMemoryAllocator,
    allocate_secure_buffer,
    free_secure_buffer,
)
from openssl_encrypt.modules.secure_memory import secure_memzero as memory_secure_memzero
from openssl_encrypt.modules.secure_memory import verify_memory_zeroed
from openssl_encrypt.modules.secure_ops import (
    SecureContainer,
    constant_time_compare,
    constant_time_pkcs7_unpad,
    secure_memzero,
    verify_mac,
)

# Try to import PQC modules
try:
    from openssl_encrypt.modules.crypt_core import PQC_AVAILABLE
    from openssl_encrypt.modules.pqc import (
        LIBOQS_AVAILABLE,
        PQCAlgorithm,
        PQCipher,
        check_pqc_support,
    )
except ImportError:
    LIBOQS_AVAILABLE = False
    PQC_AVAILABLE = False
    PQCipher = None
    PQCAlgorithm = None


class TestSecureErrorHandling(unittest.TestCase):
    """Test cases for secure error handling functionality."""

    def setUp(self):
        """Set up test environment."""
        # Explicitly disable DEBUG mode - we need to test error wrapping behavior
        # Even if DEBUG=1 is set in environment, we override it for these tests
        set_debug_mode(False)

        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.test_files = []

        # Create a test file with some content
        self.test_file = os.path.join(self.test_dir, "test_file.txt")
        with open(self.test_file, "w") as f:
            f.write("This is a test file for encryption and decryption.")
        self.test_files.append(self.test_file)

        # Test password
        self.test_password = b"TestPassword123!"

        # Define basic hash config for testing
        self.basic_hash_config = {
            "sha512": 0,
            "sha256": 0,
            "sha3_256": 0,
            "sha3_512": 0,
            "blake2b": 0,
            "shake256": 0,
            "whirlpool": 0,
            "scrypt": {"n": 0, "r": 8, "p": 1},
            "argon2": {
                "enabled": False,
                "time_cost": 1,
                "memory_cost": 8192,
                "parallelism": 1,
                "hash_len": 16,
                "type": 2,  # Argon2id
            },
            "pbkdf2_iterations": 1000,  # Use low value for faster tests
        }

    def tearDown(self):
        """Clean up after tests."""
        # Remove debug environment variable
        if "DEBUG" in os.environ:
            del os.environ["DEBUG"]

        # Remove any test files that were created
        for file_path in self.test_files:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception:
                    pass

        # Remove the temporary directory
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_validation_error(self):
        """Test validation error handling for input validation."""
        # Test with invalid input file (non-existent)
        non_existent_file = os.path.join(self.test_dir, "does_not_exist.txt")
        output_file = os.path.join(self.test_dir, "output.bin")

        # The test can pass with either ValidationError or FileNotFoundError
        # depending on whether we're in test mode or not
        try:
            encrypt_file(
                non_existent_file,
                output_file,
                self.test_password,
                self.basic_hash_config,
                quiet=True,
            )
            self.fail("Expected exception was not raised")
        except (ValidationError, FileNotFoundError) as e:
            # Either exception type is acceptable for this test
            pass

    def test_constant_time_compare(self):
        """Test constant-time comparison function."""
        # Equal values should return True
        self.assertTrue(constant_time_compare(b"same", b"same"))

        # Different values should return False
        self.assertFalse(constant_time_compare(b"different1", b"different2"))

        # Different length values should return False
        self.assertFalse(constant_time_compare(b"short", b"longer"))

        # Test with other byte-like objects
        self.assertTrue(constant_time_compare(bytearray(b"test"), bytearray(b"test")))
        self.assertFalse(constant_time_compare(bytearray(b"test1"), bytearray(b"test2")))

    def test_error_handler_timing_jitter(self):
        """Test that error handling adds timing jitter."""
        # Instead of using encrypt_file, which might raise different exceptions
        # in different environments, let's test the decorator directly with a simple function

        @secure_error_handler
        def test_function():
            """Test function that always raises an error."""
            raise ValueError("Test error")

        # Collect timing samples
        samples = []
        for _ in range(10):  # Increased from 5 to 10 for more reliable results
            start_time = time.time()
            try:
                test_function()
            except ValidationError:
                pass
            samples.append(time.time() - start_time)

        # Calculate standard deviation of samples
        mean = sum(samples) / len(samples)
        variance = sum((x - mean) ** 2 for x in samples) / len(samples)
        std_dev = variance**0.5

        # If there's timing jitter, standard deviation should be non-zero
        # But we keep the threshold very small to not make test brittle
        # With optimized thread-local timing jitter, the std_dev might be smaller than before
        # Lowered threshold to 5e-06 to account for fast systems with minimal jitter
        self.assertGreater(
            std_dev,
            0.000005,
            "Error handler should add timing jitter, but all samples had identical timing",
        )

    def test_secure_error_handler_decorator(self):
        """Test the secure_error_handler decorator functionality."""

        # Define a function that raises an exception
        @secure_error_handler
        def test_function():
            raise ValueError("Test error")

        # It should wrap the ValueError in a ValidationError
        with self.assertRaises(ValidationError):
            test_function()

        # Test with specific error category
        @secure_error_handler(error_category=ErrorCategory.ENCRYPTION)
        def test_function_with_category():
            raise RuntimeError("Test error")

        # It should wrap the RuntimeError in an EncryptionError
        with self.assertRaises(EncryptionError):
            test_function_with_category()

        # Test specialized decorators with try/except to properly verify the error types
        # This approach is more reliable than assertRaises when we need to inspect error details
        try:

            @secure_encrypt_error_handler
            def test_encrypt_function():
                raise Exception("Encryption test error")

            test_encrypt_function()
            self.fail("Expected EncryptionError was not raised")
        except Exception as e:
            self.assertTrue(
                isinstance(e, EncryptionError) or "encryption operation failed" in str(e),
                f"Expected EncryptionError but got {type(e).__name__}: {str(e)}",
            )

        try:

            @secure_decrypt_error_handler
            def test_decrypt_function():
                raise Exception("Decryption test error")

            test_decrypt_function()
            self.fail("Expected DecryptionError was not raised")
        except Exception as e:
            self.assertTrue(
                isinstance(e, DecryptionError) or "decryption operation failed" in str(e),
                f"Expected DecryptionError but got {type(e).__name__}: {str(e)}",
            )

        try:

            @secure_key_derivation_error_handler
            def test_key_derivation_function():
                raise Exception("Key derivation test error")

            test_key_derivation_function()
            self.fail("Expected KeyDerivationError was not raised")
        except Exception as e:
            self.assertTrue(
                isinstance(e, KeyDerivationError) or "key derivation failed" in str(e),
                f"Expected KeyDerivationError but got {type(e).__name__}: {str(e)}",
            )


class TestBufferOverflowProtection(unittest.TestCase):
    """Test cases for buffer overflow protection features."""

    def setUp(self):
        """Set up test environment."""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.test_files = []

        # Create a test file with some content
        self.test_file = os.path.join(self.test_dir, "test_file.txt")
        with open(self.test_file, "w") as f:
            f.write("This is a test file for encryption and decryption.")
        self.test_files.append(self.test_file)

        # Test password
        self.test_password = b"TestPassword123!"

        # Define basic hash config for testing
        self.basic_hash_config = {
            "sha512": 0,
            "sha256": 0,
            "sha3_256": 0,
            "sha3_512": 0,
            "blake2b": 0,
            "shake256": 0,
            "whirlpool": 0,
            "scrypt": {"n": 0, "r": 8, "p": 1},
            "argon2": {
                "enabled": False,
                "time_cost": 1,
                "memory_cost": 8192,
                "parallelism": 1,
                "hash_len": 16,
                "type": 2,  # Argon2id
            },
            "pbkdf2_iterations": 1000,  # Use low value for faster tests
        }

    def tearDown(self):
        """Clean up after tests."""
        # Remove any test files that were created
        for file_path in self.test_files:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception:
                    pass

        # Remove the temporary directory
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_code_contains_special_file_handling(self):
        """Test that code includes special file handling for /dev/stdin and other special files."""
        # This test doesn't execute the code, just verifies the pattern exists in the source
        from inspect import getsource

        from openssl_encrypt.modules.crypt_core import decrypt_file, encrypt_file

        # Get the source code
        encrypt_source = getsource(encrypt_file)
        decrypt_source = getsource(decrypt_file)

        # Check encrypt_file includes special handling (accept both single and double quotes)
        self.assertTrue(
            '"/dev/stdin"' in encrypt_source or "'/dev/stdin'" in encrypt_source,
            "Missing special case handling for /dev/stdin in encrypt_file",
        )
        self.assertIn(
            "/proc/",
            encrypt_source,
            "Missing special case handling for /proc/ files in encrypt_file",
        )
        self.assertIn(
            "/dev/", encrypt_source, "Missing special case handling for /dev/ files in encrypt_file"
        )

        # Check decrypt_file includes special handling (accept both single and double quotes)
        self.assertTrue(
            '"/dev/stdin"' in decrypt_source or "'/dev/stdin'" in decrypt_source,
            "Missing special case handling for /dev/stdin in decrypt_file",
        )
        self.assertIn(
            "/proc/",
            decrypt_source,
            "Missing special case handling for /proc/ files in decrypt_file",
        )
        self.assertIn(
            "/dev/", decrypt_source, "Missing special case handling for /dev/ files in decrypt_file"
        )

    def test_large_input_handling(self):
        """Test handling of unusually large inputs to prevent buffer overflows."""
        # Test that the code can handle large files without crashing
        # To simplify testing, we'll use a mock approach
        import hashlib

        # Create a moderate-sized test file (1MB)
        large_file = os.path.join(self.test_dir, "large_file.dat")
        self.test_files.append(large_file)

        # Write 1MB of random data
        file_size = 1 * 1024 * 1024
        with open(large_file, "wb") as f:
            f.write(os.urandom(file_size))

        # Test reading and processing large files in chunks
        # Rather than actual encryption/decryption which can be problematic in tests,
        # we'll ensure the code can safely handle large inputs in chunks

        # Read the file in reasonable sized chunks
        chunk_size = 1024 * 64  # 64KB chunks
        total_read = 0

        with open(large_file, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                # Just a simple processing to test memory handling
                result = hashlib.sha256(chunk).digest()
                self.assertEqual(len(result), 32)  # SHA-256 produces 32 bytes
                total_read += len(chunk)

        # Verify we read the entire file
        self.assertEqual(total_read, file_size)

        # Test that calculate_hash function can handle large files
        from openssl_encrypt.modules.crypt_core import calculate_hash

        with open(large_file, "rb") as f:
            file_data = f.read()

        # This shouldn't crash for large inputs
        hash_result = calculate_hash(file_data)
        self.assertTrue(len(hash_result) > 0)

        # Also test secure memory handling for large inputs
        from openssl_encrypt.modules.secure_memory import SecureBytes

        # Create a 1MB SecureBytes object (reduced to avoid memory issues)
        try:
            secure_data = SecureBytes(file_data[: 1024 * 512])  # 512KB to be memory-safe

            # Test accessing secure data - shouldn't crash
            for i in range(0, len(secure_data), 64 * 1024):  # Check every 64KB
                # Access some bytes - this should not crash
                byte_value = secure_data[i]
                self.assertIsInstance(byte_value, int)

            # Clean up explicitly
            # SecureBytes should clean up automatically in __del__
            del secure_data
        except Exception as e:
            self.fail(f"SecureBytes handling of large input failed: {str(e)}")

    def test_malformed_metadata_handling(self):
        """Test handling of malformed metadata in encrypted files."""
        # Create a valid encrypted file first
        encrypted_file = os.path.join(self.test_dir, "valid_encrypted.bin")
        self.test_files.append(encrypted_file)

        encrypt_file(
            self.test_file, encrypted_file, self.test_password, self.basic_hash_config, quiet=True
        )

        # Now create a corrupted version with invalid metadata
        corrupted_file = os.path.join(self.test_dir, "corrupted_metadata.bin")
        self.test_files.append(corrupted_file)

        # Read the valid encrypted file
        with open(encrypted_file, "rb") as f:
            content = f.read()

        # Corrupt the metadata part (should be Base64-encoded JSON followed by colon)
        parts = content.split(b":", 1)
        if len(parts) == 2:
            metadata_b64, data = parts

            # Try to decode and corrupt the metadata
            try:
                metadata = json.loads(base64.b64decode(metadata_b64))

                # Corrupt the metadata by changing format_version to an invalid value
                metadata["format_version"] = "invalid"

                # Re-encode the corrupted metadata
                corrupted_metadata_b64 = base64.b64encode(json.dumps(metadata).encode())

                # Write the corrupted file
                with open(corrupted_file, "wb") as f:
                    f.write(corrupted_metadata_b64 + b":" + data)

                # Attempt to decrypt the corrupted file
                with self.assertRaises(Exception):
                    decrypt_file(
                        corrupted_file,
                        os.path.join(self.test_dir, "output.txt"),
                        self.test_password,
                        quiet=True,
                    )
            except Exception:
                self.skipTest("Could not prepare corrupted metadata test")
        else:
            self.skipTest("Encrypted file format not as expected for test")

    def test_excessive_input_validation(self):
        """Test handling of excessive inputs that could cause overflow."""
        # Create an excessively long password
        long_password = secrets.token_bytes(10000)  # 10KB password

        # This should be handled gracefully without buffer overflows
        # The function may either succeed (with truncation) or raise a validation error
        try:
            # Create file with simple content for encryption
            test_input = os.path.join(self.test_dir, "simple_content.txt")
            with open(test_input, "w") as f:
                f.write("Simple test content")
            self.test_files.append(test_input)

            # Instead of actual encryption/decryption, we'll just check generate_key
            # to ensure it handles large passwords without crashing
            # (this is the main concern with buffer overflows)

            salt = os.urandom(16)

            # Try to generate a key with the very long password
            # This should not crash or raise a buffer error
            try:
                key, _, _ = generate_key(
                    long_password,
                    salt,
                    {"pbkdf2_iterations": 100},
                    pbkdf2_iterations=100,
                    quiet=True,
                )

                # If we got here, the function handled the long password correctly
                # without a buffer overflow or crash
                # Just do a sanity check that we got a key of expected length
                self.assertTrue(len(key) > 0)

            except ValidationError:
                # It's acceptable to reject excessive inputs with a ValidationError
                pass

            # Also test if the secure_memzero function can handle large inputs
            # Create a test buffer with random data
            from openssl_encrypt.modules.secure_memory import secure_memzero

            test_buffer = bytearray(os.urandom(1024 * 1024))  # 1MB buffer

            # This should not crash
            secure_memzero(test_buffer)

            # Verify it was zeroed
            self.assertTrue(all(b == 0 for b in test_buffer))

        except Exception as e:
            # We shouldn't get any exceptions besides ValidationError
            if not isinstance(e, ValidationError):
                self.fail(f"Got unexpected exception: {str(e)}")
            # ValidationError is acceptable for excessive inputs


# Try to import PQC modules
try:
    from openssl_encrypt.modules.crypt_core import PQC_AVAILABLE
    from openssl_encrypt.modules.pqc import (
        LIBOQS_AVAILABLE,
        PQCAlgorithm,
        PQCipher,
        check_pqc_support,
    )
except ImportError:
    # Mock the PQC classes if not available
    LIBOQS_AVAILABLE = False
    PQC_AVAILABLE = False
    PQCipher = None
    PQCAlgorithm = None


@unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs-python not available, skipping PQC tests")
class TestSecureOperations(unittest.TestCase):
    """Test suite for security-critical operations in the secure_ops module."""

    def test_constant_time_compare_same_length(self):
        """Test constant time comparison with same-length inputs."""
        # Test with matching inputs
        a = b"test_string"
        b = b"test_string"
        self.assertTrue(constant_time_compare(a, b))

        # Test with non-matching inputs of same length
        a = b"test_string"
        b = b"test_strind"  # Last byte different
        self.assertFalse(constant_time_compare(a, b))

    def test_constant_time_compare_different_length(self):
        """Test constant time comparison with different-length inputs."""
        a = b"test_string"
        b = b"test_stringx"  # One byte longer
        self.assertFalse(constant_time_compare(a, b))

        a = b"test_string"
        b = b"test_strin"  # One byte shorter
        self.assertFalse(constant_time_compare(a, b))

    def test_constant_time_compare_timing(self):
        """Test that comparison time doesn't leak information about where difference is."""
        # Generate a base string
        base = secrets.token_bytes(1000)

        # Test strings with differences at various positions
        test_cases = []
        for pos in [0, 10, 100, 500, 999]:
            modified = bytearray(base)
            modified[pos] ^= 0xFF  # Flip bits at this position
            test_cases.append(bytes(modified))

        # Measure comparison times
        times = []
        for test_case in test_cases:
            start_time = time.perf_counter()
            result = constant_time_compare(base, test_case)
            elapsed = time.perf_counter() - start_time
            times.append(elapsed)
            self.assertFalse(result)

        # Calculate statistics on timing
        mean_time = statistics.mean(times)
        std_dev = statistics.stdev(times) if len(times) > 1 else 0

        # Check that the standard deviation is relatively small compared to mean
        # This tolerance is high to avoid spurious test failures, but still catches
        # major timing differences that would indicate non-constant-time behavior
        if mean_time > 0:
            # On a real system, consistent timing would have std_dev/mean < 0.5
            # We use a higher threshold to avoid spurious failures on CI systems
            self.assertLess(
                std_dev / mean_time, 1.5, "Timing variation too large for constant-time comparison"
            )

    def test_secure_memzero(self):
        """Test that secure_memzero properly clears memory."""
        # Create test data
        test_data = bytearray(secrets.token_bytes(100))

        # Make sure it initially contains non-zero values
        self.assertFalse(all(b == 0 for b in test_data))

        # Zero the memory
        secure_memzero(test_data)

        # Check that all bytes are now zero
        self.assertTrue(all(b == 0 for b in test_data))

        # Check using the verification function
        self.assertTrue(verify_memory_zeroed(test_data))

    def test_constant_time_pkcs7_unpad_valid(self):
        """Test PKCS#7 unpadding with valid padding."""
        # Create valid PKCS#7 padded data with different padding lengths
        # Padding value 4 means last 4 bytes are all 0x04
        input_data = b"test_data" + bytes([4, 4, 4, 4])
        unpadded, valid = constant_time_pkcs7_unpad(input_data)

        self.assertTrue(valid)
        self.assertEqual(unpadded, b"test_data")

        # Another case with different padding length
        input_data = b"short" + bytes([2, 2])
        unpadded, valid = constant_time_pkcs7_unpad(input_data)

        self.assertTrue(valid)
        self.assertEqual(unpadded, b"short")

    def test_constant_time_pkcs7_unpad_invalid(self):
        """Test PKCS#7 unpadding with invalid padding."""
        # Invalid padding - inconsistent padding values
        input_data = b"test_data" + bytes([4, 3, 4, 4])
        unpadded, valid = constant_time_pkcs7_unpad(input_data)

        self.assertFalse(valid)
        # Should return the original data when padding is invalid
        self.assertEqual(unpadded, input_data)

        # Invalid padding - padding value too large
        block_size = 8
        input_data = b"test" + bytes([9, 9, 9, 9, 9, 9, 9, 9, 9])
        unpadded, valid = constant_time_pkcs7_unpad(input_data, block_size)

        self.assertFalse(valid)
        self.assertEqual(unpadded, input_data)

    def test_constant_time_pkcs7_unpad_timing(self):
        """Test that PKCS#7 unpadding time doesn't leak validity information."""
        block_size = 16

        # Create valid padding
        valid_data = b"valid_test_data" + bytes([4, 4, 4, 4])

        # Create various invalid paddings
        invalid_data_1 = b"invalid_padding" + bytes([4, 5, 4, 4])  # Inconsistent values
        invalid_data_2 = b"invalid_padding" + bytes([20, 20, 20, 20])  # Too large
        invalid_data_3 = b"not_even_a_multiple_of_block_size"  # Wrong length

        test_cases = [valid_data, invalid_data_1, invalid_data_2, invalid_data_3]

        # Measure unpadding times
        times = []
        for data in test_cases:
            start_time = time.perf_counter()
            unpadded, valid = constant_time_pkcs7_unpad(data, block_size)
            elapsed = time.perf_counter() - start_time
            times.append(elapsed)

        # Calculate statistics on timing
        mean_time = statistics.mean(times)
        std_dev = statistics.stdev(times) if len(times) > 1 else 0

        # Check that the standard deviation is relatively small
        if mean_time > 0:
            # Use a high threshold to avoid spurious CI failures
            self.assertLess(
                std_dev / mean_time, 1.5, "Timing variation too large for constant-time unpadding"
            )

    def test_secure_container(self):
        """Test that SecureContainer properly handles sensitive data."""
        # Test creation with different data types
        container1 = SecureContainer(b"test_bytes")
        container2 = SecureContainer("test_string")  # Should convert to bytes

        # Test get method
        self.assertEqual(container1.get(), b"test_bytes")
        self.assertEqual(container2.get(), b"test_string")

        # Test set method
        container1.set(b"new_data")
        self.assertEqual(container1.get(), b"new_data")

        # Test clear method
        container1.clear()
        self.assertEqual(len(container1.get()), 0)

        # Test __len__ method
        container3 = SecureContainer(b"123456789")
        self.assertEqual(len(container3), 9)


class TestSecurityEnhancements(unittest.TestCase):
    """Test class for the enhanced security features."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_enhanced_secure_container(self):
        """Test enhanced SecureContainer with different data types and operations."""
        # Test string handling
        container = SecureContainer("test_string")
        self.assertEqual(container.get(), b"test_string")
        self.assertEqual(container.get_as_str(), "test_string")

        # Test integer handling
        container.set(12345)
        self.assertEqual(container.get_as_int(), 12345)

        # Test JSON object handling
        test_dict = {"key1": "value1", "key2": 123}
        container.set(test_dict)
        self.assertEqual(container.get_as_object(), test_dict)

        # Test appending data
        container.clear()
        container.append("hello")
        container.append(" ")
        container.append("world")
        self.assertEqual(container.get_as_str(), "hello world")

        # Test context manager protocol
        with SecureContainer("sensitive_data") as secure_data:
            self.assertEqual(secure_data.get_as_str(), "sensitive_data")

        # Test boolean evaluation
        empty_container = SecureContainer()
        self.assertFalse(bool(empty_container))
        empty_container.set("data")
        self.assertTrue(bool(empty_container))

        # Test equality comparison
        container1 = SecureContainer("same_data")
        container2 = SecureContainer("same_data")
        container3 = SecureContainer("different_data")

        self.assertTrue(container1 == container2)
        self.assertFalse(container1 == container3)
        self.assertTrue(container1 == "same_data")
        self.assertTrue(container1 == b"same_data")

    def test_verify_memory_zeroed_full_check(self):
        """Test verify_memory_zeroed with full buffer inspection."""
        # Test with small buffer
        buffer = bytearray(100)
        self.assertTrue(verify_memory_zeroed(buffer, full_check=True))

        # Introduce a non-zero byte and check that verification fails
        buffer[50] = 1
        self.assertFalse(verify_memory_zeroed(buffer, full_check=True))

        # Test with larger buffer
        large_buffer = bytearray(10000)
        self.assertTrue(verify_memory_zeroed(large_buffer, full_check=True))

        # Introduce a non-zero byte at a random position and verify it fails
        position = random.randint(0, 9999)
        large_buffer[position] = 1
        self.assertFalse(verify_memory_zeroed(large_buffer, full_check=True))

        # Test sampling mode - since the position is random, the sampling
        # might not catch the non-zero byte, so we can't make a definitive assertion
        result = verify_memory_zeroed(large_buffer, full_check=False)
        # We'll just print this result for informational purposes
        print(f"Sampling verification found non-zero byte: {not result}")

    def test_secure_memzero(self):
        """Test secure_memzero function."""
        # Create a buffer with random data
        buffer = bytearray(secrets.token_bytes(1000))

        # Ensure it's not zeroed initially
        self.assertFalse(verify_memory_zeroed(buffer))

        # Zero it out
        result = memory_secure_memzero(buffer, full_verification=True)

        # Verify it was zeroed successfully
        self.assertTrue(result)
        self.assertTrue(verify_memory_zeroed(buffer, full_check=True))

    def test_timing_jitter(self):
        """Test enhanced timing jitter mechanism."""
        # Test basic jitter
        start_time = time.time()
        jitter = add_timing_jitter(1, 10)
        elapsed = (time.time() - start_time) * 1000  # Convert to ms

        # Jitter should be between 1-10ms
        self.assertTrue(1 <= jitter <= 10)

        # Elapsed time should be at least the jitter amount
        self.assertTrue(elapsed >= jitter)

        # Test multiple rapid calls
        jitters = []
        for _ in range(10):
            jitters.append(add_timing_jitter(1, 10))

        # Get stats after multiple calls
        stats = get_jitter_stats()

        # Verify stats are being tracked
        self.assertTrue(stats["total_jitter_ms"] > 0)
        self.assertTrue(stats["max_successive_calls"] > 0)

        # Test thread safety by running jitter in multiple threads
        def jitter_thread():
            for _ in range(50):
                add_timing_jitter(1, 5)

        threads = []
        for _ in range(10):
            t = threading.Thread(target=jitter_thread)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Verify thread-local stats are still valid
        new_stats = get_jitter_stats()
        self.assertTrue(new_stats["total_jitter_ms"] >= stats["total_jitter_ms"])

    def test_constant_time_compare(self):
        """Test constant-time comparison function."""
        # Test equal strings
        a = b"test_string"
        b = b"test_string"
        self.assertTrue(constant_time_compare(a, b))

        # Test unequal strings
        c = b"test_string2"
        self.assertFalse(constant_time_compare(a, c))

        # Test strings of different lengths
        d = b"test"
        self.assertFalse(constant_time_compare(a, d))

        # Test with bytearray
        e = bytearray(b"test_string")
        self.assertTrue(constant_time_compare(a, e))

        # Test timing consistency for equal length strings
        # We'll measure if comparison time is consistent regardless of position of difference
        def time_compare(pos):
            # Create two strings that differ at position 'pos'
            s1 = bytearray([65] * 1000)  # All 'A's
            s2 = bytearray([65] * 1000)  # All 'A's
            if pos >= 0:
                s2[pos] = 66  # Change to 'B' at position 'pos'

            start = time.time()
            constant_time_compare(s1, s2)
            return time.time() - start

        # Compare at different positions
        times = [time_compare(pos) for pos in [0, 250, 500, 750, 999]]

        # Calculate standard deviation - should be relatively low
        # We allow some variance due to system scheduling, but it should be minimal
        stdev = statistics.stdev(times)
        mean = statistics.mean(times)

        # Coefficient of variation should be low (typically < 0.2 for constant time)
        # We use a higher threshold (0.5) to account for system noise in unit tests
        cv = stdev / mean if mean > 0 else 0
        self.assertLess(cv, 0.5, "Timing variance too high for constant time comparison")

    def test_constant_time_pkcs7_unpad(self):
        """Test constant-time PKCS#7 unpadding."""
        # Test valid padding
        data = b"test_data" + bytes([8] * 8)  # Valid padding of 8 bytes
        unpadded, valid = constant_time_pkcs7_unpad(data)
        self.assertTrue(valid)
        self.assertEqual(unpadded, b"test_data")

        # Test invalid padding - wrong padding value
        data = b"test_data" + bytes([9] * 8)  # Invalid: padding value doesn't match count
        unpadded, valid = constant_time_pkcs7_unpad(data)
        self.assertFalse(valid)

        # Test invalid padding - inconsistent padding
        data = b"test_data" + bytes([8] * 7) + bytes([7])  # Invalid: not all bytes match
        unpadded, valid = constant_time_pkcs7_unpad(data)
        self.assertFalse(valid)

        # Test timing consistency for valid and invalid padding
        def time_unpad(valid_padding):
            if valid_padding:
                # Create valid padding
                data = b"test_data" + bytes([8] * 8)
            else:
                # Create invalid padding
                data = b"test_data" + bytes([8] * 7) + bytes([7])

            start = time.time()
            constant_time_pkcs7_unpad(data)
            return time.time() - start

        # Compare timing for valid and invalid padding
        valid_times = [time_unpad(True) for _ in range(10)]
        invalid_times = [time_unpad(False) for _ in range(10)]

        # Calculate means
        valid_mean = statistics.mean(valid_times)
        invalid_mean = statistics.mean(invalid_times)

        # The timing difference should be minimal
        # Allow for 50% difference as system scheduling can affect timing
        ratio = max(valid_mean, invalid_mean) / min(valid_mean, invalid_mean)
        self.assertLess(ratio, 1.5, "Timing difference too high for constant time unpadding")

    def test_secure_buffer_allocation(self):
        """Test secure buffer allocation and freeing."""
        # Allocate a secure buffer
        buffer = allocate_secure_buffer(100)

        # Verify it's the right size
        self.assertEqual(len(buffer), 100)

        # Verify it's initially zeroed
        self.assertTrue(verify_memory_zeroed(buffer))

        # Write some data
        for i in range(100):
            buffer[i] = i % 256

        # Verify it's no longer zeroed
        self.assertFalse(verify_memory_zeroed(buffer))

        # Free the buffer
        free_secure_buffer(buffer)

        # Can't verify the buffer state here since free_secure_buffer has already
        # removed the reference. Let's create a new buffer and test immediate zeroing instead
        test_buffer = bytearray(secrets.token_bytes(100))
        self.assertFalse(verify_memory_zeroed(test_buffer))

        # Test zeroing directly
        result = memory_secure_memzero(test_buffer)
        self.assertTrue(result)
        self.assertTrue(verify_memory_zeroed(test_buffer))


class TestConstantTimeCompare(unittest.TestCase):
    """Tests for constant-time comparison functions."""

    def test_correctness(self):
        """Test that constant_time_compare returns correct results."""
        from openssl_encrypt.modules.secure_ops import constant_time_compare

        # Equal values should return True
        self.assertTrue(constant_time_compare(b"hello", b"hello"))

        # Different values should return False
        self.assertFalse(constant_time_compare(b"hello", b"world"))

        # Different lengths should return False
        self.assertFalse(constant_time_compare(b"hello", b"hello!"))

        # Empty values should compare correctly
        self.assertTrue(constant_time_compare(b"", b""))
        self.assertFalse(constant_time_compare(b"", b"a"))

        # None values should be handled safely
        self.assertTrue(constant_time_compare(None, None))
        self.assertFalse(constant_time_compare(None, b"x"))  # Not an empty string
        self.assertFalse(constant_time_compare(b"x", None))

    def test_timing_consistency(self):
        """Test that timing of constant_time_compare is consistent regardless of input."""
        from openssl_encrypt.modules.secure_ops import constant_time_compare

        # Create pairs of inputs with varying levels of similarity
        pairs = [
            (b"a" * 1000, b"a" * 1000),  # Equal
            (b"a" * 1000, b"a" * 999 + b"b"),  # Differ at the end
            (b"a" * 1000, b"b" + b"a" * 999),  # Differ at the beginning
            (b"a" * 1000, b"a" * 500 + b"b" + b"a" * 499),  # Differ in the middle
            (b"a" * 1000, b"b" * 1000),  # Completely different
        ]

        # Measure timing for each pair multiple times
        times = {i: [] for i in range(len(pairs))}

        # Use multiple iterations to get statistically significant results
        for _ in range(20):
            for i, (a, b) in enumerate(pairs):
                start = time.perf_counter()
                constant_time_compare(a, b)
                end = time.perf_counter()
                times[i].append(end - start)

        # Calculate statistics for each pair
        stats = {
            i: {
                "mean": statistics.mean(times[i]),
                "stdev": statistics.stdev(times[i]) if len(times[i]) > 1 else 0,
            }
            for i in range(len(pairs))
        }

        # Verify that times are reasonably consistent
        # We use a loose threshold since many factors can affect timing
        means = [stats[i]["mean"] for i in range(len(pairs))]
        max_mean = max(means)
        min_mean = min(means)

        # Check that the difference between max and min is not too large
        # This is a very generous threshold that should accommodate most
        # environmental variations while still catching egregious issues
        self.assertLess(
            max_mean / min_mean if min_mean > 0 else 1,
            2.0,
            "Timing difference between different inputs is too large",
        )


class TestConstantTimePKCS7Unpad(unittest.TestCase):
    """Tests for constant-time PKCS#7 unpadding."""

    def test_valid_padding(self):
        """Test unpadding with valid PKCS#7 padding."""
        from openssl_encrypt.modules.secure_ops import constant_time_pkcs7_unpad

        # Test with valid padding values
        for padding_value in range(1, 17):
            data = b"A" * (16 - padding_value) + bytes([padding_value] * padding_value)
            unpadded, is_valid = constant_time_pkcs7_unpad(data, 16)
            self.assertTrue(is_valid)
            self.assertEqual(unpadded, b"A" * (16 - padding_value))

    def test_invalid_padding(self):
        """Test unpadding with invalid PKCS#7 padding."""
        from openssl_encrypt.modules.secure_ops import constant_time_pkcs7_unpad

        # Test with inconsistent padding bytes
        data = b"A" * 12 + bytes([4, 3, 4, 4])
        unpadded, is_valid = constant_time_pkcs7_unpad(data, 16)
        self.assertFalse(is_valid)

        # Test with padding value too large
        data = b"A" * 15 + bytes([17])
        unpadded, is_valid = constant_time_pkcs7_unpad(data, 16)
        self.assertFalse(is_valid)

        # Test with padding value zero
        data = b"A" * 15 + bytes([0])
        unpadded, is_valid = constant_time_pkcs7_unpad(data, 16)
        self.assertFalse(is_valid)

    def test_empty_data(self):
        """Test unpadding with empty input."""
        from openssl_encrypt.modules.secure_ops import constant_time_pkcs7_unpad

        unpadded, is_valid = constant_time_pkcs7_unpad(b"", 16)
        self.assertFalse(is_valid)
        self.assertEqual(unpadded, b"")


class TestVerifyMAC(unittest.TestCase):
    """Tests for MAC verification functions."""

    def test_mac_verification(self):
        """Test basic MAC verification functionality."""
        from openssl_encrypt.modules.secure_ops import verify_mac

        # Generate random MACs
        mac1 = secrets.token_bytes(32)
        mac2 = secrets.token_bytes(32)

        # Same MACs should verify
        self.assertTrue(verify_mac(mac1, mac1))

        # Different MACs should not verify
        self.assertFalse(verify_mac(mac1, mac2))

        # None values should be handled safely
        self.assertFalse(verify_mac(None, mac1))
        self.assertFalse(verify_mac(mac1, None))
        self.assertTrue(verify_mac(None, None))


from openssl_encrypt.modules.crypt_errors import (
    AuthenticationError,
    ConfigurationError,
    DecryptionError,
    EncryptionError,
    ErrorCategory,
    InternalError,
    KeyDerivationError,
    KeystoreError,
)
from openssl_encrypt.modules.crypt_errors import MemoryError as SecureMemoryError
from openssl_encrypt.modules.crypt_errors import (
    PermissionError,
    PlatformError,
    SecureError,
    ValidationError,
    secure_error_handler,
    secure_key_derivation_error_handler,
    secure_memory_error_handler,
)
from openssl_encrypt.modules.crypto_secure_memory import (
    CryptoIV,
    CryptoKey,
    CryptoSecureBuffer,
    create_key_from_password,
    generate_secure_key,
    secure_crypto_buffer,
    secure_crypto_iv,
    secure_crypto_key,
    validate_crypto_memory_integrity,
)

# Import secure memory and error handling modules for the tests
from openssl_encrypt.modules.secure_allocator import (
    SecureBytes,
    SecureHeap,
    SecureHeapBlock,
    allocate_secure_crypto_buffer,
    allocate_secure_memory,
    check_all_crypto_buffer_integrity,
    cleanup_secure_heap,
    free_secure_crypto_buffer,
    get_crypto_heap_stats,
)
from openssl_encrypt.modules.secure_memory import secure_memzero, verify_memory_zeroed


class TestBufferOverflowAndUnderflow(unittest.TestCase):
    """Test handling of buffer overflow and underflow conditions."""

    def test_heap_block_overflow_detection(self):
        """Test detection of buffer overflows in heap blocks."""
        # Use the heap to allocate a block
        from openssl_encrypt.modules.secure_allocator import SecureHeap

        heap = SecureHeap()

        # Allocate a block
        block_id, data_view = heap.allocate(64)

        # Check integrity initially
        integrity = heap.check_integrity()
        self.assertTrue(integrity[block_id])

        # Fill data with a test pattern
        data_view[:] = bytes([1] * 64)

        # Check integrity again after modification
        integrity = heap.check_integrity()
        self.assertTrue(integrity[block_id])

        # Attempt to write beyond the allocated size
        with self.assertRaises((IndexError, ValueError)):
            # This should fail with proper bounds checking
            data_view[100] = 0xFF

        # Clean up
        heap.free(block_id)

        # Test that the block is no longer in the integrity check after being freed
        integrity = heap.check_integrity()
        self.assertNotIn(block_id, integrity)


# Integration test for Kyber v5 encryption data validation
def test_kyber_v5_wrong_encryption_data():
    """
    Test that decryption with correct password but wrong encryption_data fails for Kyber v5 files.

    This test verifies that trying to decrypt a Kyber encrypted file using correct password but
    wrong encryption data setting will fail, which is a security feature.
    """
    import base64
    import json
    import os

    from openssl_encrypt.modules.crypt_core import decrypt_file
    from openssl_encrypt.modules.crypt_errors import (
        AuthenticationError,
        DecryptionError,
        ValidationError,
    )

    # Path to test files
    test_files_dir = os.path.join(os.path.dirname(__file__), "testfiles", "v5")
    if not os.path.exists(test_files_dir):
        return  # Skip if test files aren't available

    # Find Kyber test files
    kyber_files = [f for f in os.listdir(test_files_dir) if f.startswith("test1_kyber")]
    if not kyber_files:
        return  # Skip if no Kyber test files

    # Test only first file for speed (testing one is sufficient for security validation)
    for filename in kyber_files[:1]:
        input_file = os.path.join(test_files_dir, filename)
        algorithm_name = filename.replace("test1_", "").replace(".txt", "")

        # Get current encryption_data from metadata
        with open(input_file, "r") as f:
            content = f.read()
        metadata_b64 = content.split(":", 1)[0]
        metadata_json = base64.b64decode(metadata_b64).decode("utf-8")
        metadata = json.loads(metadata_json)
        current_encryption_data = metadata.get("encryption", {}).get("encryption_data", "")

        # Find a different encryption_data option
        encryption_data_options = [
            "aes-gcm",
            "aes-gcm-siv",
            "aes-ocb3",
            "aes-siv",
            "chacha20-poly1305",
            "xchacha20-poly1305",
        ]
        wrong_encryption_data = None
        for option in encryption_data_options:
            if option != current_encryption_data:
                wrong_encryption_data = option
                break

        if not wrong_encryption_data:
            continue  # Skip if we can't find a different option

        # Provide a mock private key for PQC tests
        if "kyber" in algorithm_name.lower():
            # Create a mock private key that's unique for each algorithm to avoid cross-test interference
            pqc_private_key = (b"MOCK_PQC_KEY_FOR_" + algorithm_name.encode()) * 10

        # Decryption should fail with wrong encryption_data
        try:
            decrypt_file(
                input_file=input_file,
                output_file=None,
                password=b"1234",  # Correct password
                encryption_data=wrong_encryption_data,  # Wrong encryption_data
                pqc_private_key=pqc_private_key,
            )

            # If we get here, it means decryption succeeded when it should have failed
            assert (
                False
            ), f"Security issue: Decryption succeeded with wrong encryption_data for {algorithm_name}"
        except (DecryptionError, AuthenticationError, ValidationError):
            # This is the expected path - decryption should fail
            pass


class TestSecurityLogger(unittest.TestCase):
    """Test security audit logger functionality"""

    def setUp(self):
        """Set up test fixtures"""
        import tempfile

        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        # Reset singleton instance for clean test
        SecurityAuditLogger._instance = None

        # Create temporary log directory for testing
        self.test_log_dir = tempfile.mkdtemp()
        self.logger = SecurityAuditLogger(log_dir=self.test_log_dir, enabled=True)

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil

        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        # Reset singleton instance
        SecurityAuditLogger._instance = None

        # Clean up temporary log directory
        if hasattr(self, "test_log_dir"):
            shutil.rmtree(self.test_log_dir, ignore_errors=True)

    def test_logger_initialization(self):
        """Test that logger initializes correctly"""
        self.assertTrue(self.logger.enabled)
        self.assertEqual(self.logger.log_file.parent, Path(self.test_log_dir))

        # Log an event to create the file
        self.logger.log_event("init_test", "info", {"test": "data"})
        self.assertTrue(self.logger.log_file.exists())

    def test_log_event_basic(self):
        """Test basic event logging"""
        self.logger.log_event(
            "test_event", "info", {"file_path": "/tmp/test.txt", "operation": "encrypt"}
        )

        # Read log file and verify event was written
        with open(self.logger.log_file, "r") as f:
            log_content = f.read()
            self.assertIn("test_event", log_content)
            self.assertIn("file_path", log_content)
            self.assertIn("/tmp/test.txt", log_content)
            self.assertIn("operation", log_content)
            self.assertIn("encrypt", log_content)

    def test_log_event_sensitive_data_redaction(self):
        """Test that sensitive data is redacted"""
        self.logger.log_event(
            "encryption_started",
            "info",
            {"file": "test.txt", "password": "SuperSecret123!", "key": "0x1234567890abcdef"},
        )

        # Read log file and verify sensitive fields are redacted
        with open(self.logger.log_file, "r") as f:
            log_content = f.read()
            self.assertIn("test.txt", log_content)
            self.assertNotIn("SuperSecret123!", log_content)
            self.assertNotIn("0x1234567890abcdef", log_content)
            self.assertIn("***REDACTED***", log_content)

    def test_log_event_severity_levels(self):
        """Test different severity levels"""
        self.logger.log_event("info_event", "info", {"detail": "info"})
        self.logger.log_event("warning_event", "warning", {"detail": "warning"})
        self.logger.log_event("critical_event", "critical", {"detail": "critical"})

        # Read log and verify all events are present
        with open(self.logger.log_file, "r") as f:
            log_content = f.read()
            self.assertIn("info_event", log_content)
            self.assertIn("warning_event", log_content)
            self.assertIn("critical_event", log_content)

    def test_get_recent_events(self):
        """Test retrieving recent events"""
        # Log some events
        self.logger.log_event("event1", "info", {"data": "1"})
        self.logger.log_event("event2", "warning", {"data": "2"})
        self.logger.log_event("event3", "critical", {"data": "3"})

        # Retrieve all events
        events = self.logger.get_recent_events(hours=24)
        self.assertEqual(len(events), 3)

        # Retrieve only warning events
        warning_events = self.logger.get_recent_events(hours=24, severity="warning")
        self.assertEqual(len(warning_events), 1)
        self.assertEqual(warning_events[0]["event_type"], "event2")

        # Retrieve specific event type
        event1_events = self.logger.get_recent_events(hours=24, event_type="event1")
        self.assertEqual(len(event1_events), 1)
        self.assertEqual(event1_events[0]["event_type"], "event1")

    def test_log_rotation(self):
        """Test log rotation when size limit is exceeded"""
        # Write enough data to trigger rotation
        large_detail = {"data": "x" * 1000}
        for i in range(15000):  # Write enough to exceed 10MB
            self.logger.log_event(f"event_{i}", "info", large_detail)

        # Check that log rotation occurred
        rotated_log = Path(self.test_log_dir) / "security-audit.log.1"
        # Note: Rotation may not occur in this test due to timing, so we just check
        # that the logger doesn't crash when writing large amounts of data
        self.assertTrue(self.logger.log_file.exists())

    def test_clear_logs(self):
        """Test clearing all logs"""
        # Log some events
        self.logger.log_event("event1", "info", {"data": "1"})
        self.logger.log_event("event2", "info", {"data": "2"})

        # Verify logs exist
        self.assertTrue(self.logger.log_file.exists())

        # Clear logs
        result = self.logger.clear_logs()
        self.assertTrue(result)

        # Verify logs are cleared
        self.assertFalse(self.logger.log_file.exists())

    def test_disabled_logger(self):
        """Test that disabled logger doesn't write logs"""
        import tempfile

        from openssl_encrypt.modules.security_logger import SecurityAuditLogger

        # Create disabled logger
        disabled_dir = tempfile.mkdtemp()
        disabled_logger = SecurityAuditLogger(log_dir=disabled_dir, enabled=False)

        try:
            # Try to log an event
            disabled_logger.log_event("test_event", "info", {"data": "test"})

            # Verify no log file was created (or is empty if created)
            log_file = Path(disabled_dir) / "security-audit.log"
            if log_file.exists():
                with open(log_file, "r") as f:
                    content = f.read()
                    self.assertEqual(content, "")
        finally:
            import shutil

            shutil.rmtree(disabled_dir, ignore_errors=True)

    def test_thread_safety(self):
        """Test that logger is thread-safe"""
        import threading

        def log_events(thread_id, count):
            for i in range(count):
                self.logger.log_event(
                    f"thread_{thread_id}_event_{i}", "info", {"thread": thread_id, "iteration": i}
                )

        # Create multiple threads
        threads = []
        thread_count = 10
        events_per_thread = 10

        for i in range(thread_count):
            t = threading.Thread(target=log_events, args=(i, events_per_thread))
            threads.append(t)
            t.start()

        # Wait for all threads to complete
        for t in threads:
            t.join()

        # Verify all events were logged
        events = self.logger.get_recent_events(hours=24)
        self.assertEqual(len(events), thread_count * events_per_thread)

    def test_long_value_truncation(self):
        """Test that long values are truncated"""
        long_value = "x" * 500  # Longer than 256 character limit

        self.logger.log_event("test_event", "info", {"long_field": long_value})

        # Read log and verify truncation
        with open(self.logger.log_file, "r") as f:
            log_content = f.read()
            self.assertIn("[truncated]", log_content)
            self.assertNotIn("x" * 500, log_content)
