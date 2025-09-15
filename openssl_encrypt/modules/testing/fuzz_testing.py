"""
Fuzzing Test Suite for OpenSSL Encrypt Library.

Provides comprehensive fuzzing capabilities to test input boundary conditions,
edge cases, and resilience against malformed inputs.
"""

import os
import random
import string
import tempfile
from typing import List, Dict, Any, Callable, Optional, Tuple
from dataclasses import dataclass
import struct
import json

from .base_test import BaseSecurityTest, TestResult, TestResultLevel, TestConfig
from ..crypt_core import encrypt_file, decrypt_file


@dataclass 
class FuzzInput:
    """Represents a fuzz test input."""
    data: bytes
    description: str
    expected_behavior: str = "should_handle_gracefully"  # should_handle_gracefully, should_fail, should_succeed


class InputGenerator:
    """Generates various types of inputs for fuzzing."""
    
    def __init__(self, seed: Optional[int] = None):
        if seed is not None:
            random.seed(seed)
    
    def generate_random_bytes(self, size: int) -> bytes:
        """Generate random byte data."""
        return bytes(random.randint(0, 255) for _ in range(size))
    
    def generate_boundary_sizes(self) -> List[int]:
        """Generate boundary size values for testing."""
        return [
            0,           # Empty
            1,           # Single byte
            15, 16, 17,  # Around AES block size
            31, 32, 33,  # Around common buffer sizes
            63, 64, 65,  # Around cache line size
            255, 256, 257,  # Around byte boundary
            1023, 1024, 1025,  # Around KB boundary
            4095, 4096, 4097,  # Around page size
            65535, 65536, 65537,  # Around 64KB boundary
            1048575, 1048576, 1048577,  # Around MB boundary
        ]
    
    def generate_special_patterns(self) -> List[Tuple[bytes, str]]:
        """Generate special byte patterns for testing."""
        patterns = []
        
        # All zeros
        patterns.append((b'\x00' * 1024, "all_zeros"))
        
        # All ones
        patterns.append((b'\xff' * 1024, "all_ones"))
        
        # Alternating pattern
        patterns.append((b'\xaa' * 512 + b'\x55' * 512, "alternating_pattern"))
        
        # Incremental pattern
        patterns.append((bytes(i % 256 for i in range(1024)), "incremental_pattern"))
        
        # Random pattern
        patterns.append((self.generate_random_bytes(1024), "random_pattern"))
        
        # ASCII text
        ascii_text = "".join(random.choices(string.ascii_letters + string.digits + " \n\t", k=1024))
        patterns.append((ascii_text.encode('utf-8'), "ascii_text"))
        
        # Unicode text
        unicode_text = "Hello 世界 🔒 Test" * 50
        patterns.append((unicode_text.encode('utf-8'), "unicode_text"))
        
        # Binary data with embedded nulls
        binary_with_nulls = b"DATA\x00\x00NULL\x00DATA" * 50
        patterns.append((binary_with_nulls, "binary_with_nulls"))
        
        return patterns
    
    def generate_malformed_configs(self) -> List[Dict[str, Any]]:
        """Generate malformed configuration dictionaries."""
        configs = []
        
        # Empty config
        configs.append({})
        
        # Invalid algorithm
        configs.append({"algorithm": "invalid_algorithm"})
        
        # Invalid hash algorithm
        configs.append({"hash_algorithm": "invalid_hash"})
        
        # Invalid KDF
        configs.append({"kdf": "invalid_kdf"})
        
        # Negative values
        configs.append({"argon2_time_cost": -1})
        configs.append({"argon2_memory_cost": -1})
        configs.append({"balloon_space_cost": -1})
        
        # Extremely large values
        configs.append({"argon2_memory_cost": 2**32})
        configs.append({"balloon_time_cost": 2**16})
        
        # Wrong types
        configs.append({"algorithm": 123})
        configs.append({"hash_algorithm": []})
        configs.append({"argon2_time_cost": "invalid"})
        
        # Missing required fields
        configs.append({"hash_algorithm": "SHA256"})  # No algorithm
        
        return configs


class FuzzTestSuite(BaseSecurityTest):
    """Comprehensive fuzzing test suite."""
    
    def __init__(self):
        super().__init__(
            "FuzzTestSuite", 
            "Comprehensive fuzzing tests for input validation and error handling"
        )
        self.input_generator = InputGenerator()
        self.temp_dir = None
    
    def setup_temp_directory(self) -> str:
        """Set up temporary directory for test files."""
        if not self.temp_dir:
            self.temp_dir = tempfile.mkdtemp(prefix="fuzz_test_")
        return self.temp_dir
    
    def cleanup_temp_directory(self) -> None:
        """Clean up temporary directory."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir = None
    
    def run_tests(self, **kwargs) -> List[TestResult]:
        """Run all fuzzing tests."""
        self.clear_results()
        config = TestConfig(**kwargs)
        
        try:
            self.setup_temp_directory()
            
            # Run different categories of fuzz tests
            self._test_boundary_sizes(config)
            self._test_special_patterns(config)
            self._test_malformed_configs(config)
            self._test_file_boundary_conditions(config)
            self._test_password_fuzzing(config)
            self._test_concurrent_access(config)
            
        finally:
            self.cleanup_temp_directory()
        
        return self.get_results()
    
    def _test_boundary_sizes(self, config: TestConfig) -> None:
        """Test various boundary sizes for file encryption."""
        sizes = self.input_generator.generate_boundary_sizes()
        
        for size in sizes:
            result = self.run_single_test(
                self._test_encrypt_decrypt_size,
                f"boundary_size_{size}",
                size,
                config
            )
            self.add_result(result)
    
    def _test_encrypt_decrypt_size(self, size: int, config: TestConfig) -> TestResult:
        """Test encryption/decryption with specific data size."""
        try:
            # Generate test data
            test_data = self.input_generator.generate_random_bytes(size)
            
            # Create temporary files
            input_file = os.path.join(self.temp_dir, f"input_{size}.bin")
            encrypted_file = os.path.join(self.temp_dir, f"encrypted_{size}.bin")
            decrypted_file = os.path.join(self.temp_dir, f"decrypted_{size}.bin")
            
            # Write test data
            with open(input_file, 'wb') as f:
                f.write(test_data)
            
            # Test encryption
            encrypt_config = {
                "algorithm": config.get("algorithm", "fernet"),
                "hash_algorithm": config.get("hash_algorithm", "SHA256"),
                "kdf": config.get("kdf", "pbkdf2")
            }
            
            password = "test_password_123"
            
            # Encrypt file
            encrypt_file(input_file, encrypted_file, password, hash_config=encrypt_config)
            
            if not os.path.exists(encrypted_file):
                return TestResult(
                    f"boundary_size_{size}",
                    TestResultLevel.ERROR,
                    f"Encryption failed for size {size} - no output file created"
                )
            
            # Decrypt file
            decrypt_file(encrypted_file, decrypted_file, password)
            
            if not os.path.exists(decrypted_file):
                return TestResult(
                    f"boundary_size_{size}",
                    TestResultLevel.ERROR,
                    f"Decryption failed for size {size} - no output file created"
                )
            
            # Verify data integrity
            with open(decrypted_file, 'rb') as f:
                decrypted_data = f.read()
            
            if decrypted_data != test_data:
                return TestResult(
                    f"boundary_size_{size}",
                    TestResultLevel.ERROR,
                    f"Data corruption detected for size {size}",
                    details={
                        "original_size": len(test_data),
                        "decrypted_size": len(decrypted_data),
                        "data_match": False
                    }
                )
            
            return TestResult(
                f"boundary_size_{size}",
                TestResultLevel.PASS,
                f"Successfully handled {size} bytes",
                details={
                    "data_size": size,
                    "encrypted_size": os.path.getsize(encrypted_file),
                    "data_integrity": True
                }
            )
            
        except Exception as e:
            return TestResult(
                f"boundary_size_{size}",
                TestResultLevel.ERROR,
                f"Exception during size {size} test: {str(e)}",
                exception=e
            )
    
    def _test_special_patterns(self, config: TestConfig) -> None:
        """Test encryption with special data patterns."""
        patterns = self.input_generator.generate_special_patterns()
        
        for pattern_data, pattern_name in patterns:
            result = self.run_single_test(
                self._test_encrypt_decrypt_pattern,
                f"special_pattern_{pattern_name}",
                pattern_data,
                pattern_name,
                config
            )
            self.add_result(result)
    
    def _test_encrypt_decrypt_pattern(self, data: bytes, pattern_name: str, config: TestConfig) -> TestResult:
        """Test encryption/decryption with specific data pattern."""
        try:
            # Create temporary files
            input_file = os.path.join(self.temp_dir, f"pattern_{pattern_name}.bin")
            encrypted_file = os.path.join(self.temp_dir, f"pattern_{pattern_name}_enc.bin")
            decrypted_file = os.path.join(self.temp_dir, f"pattern_{pattern_name}_dec.bin")
            
            # Write test data
            with open(input_file, 'wb') as f:
                f.write(data)
            
            # Test encryption/decryption
            encrypt_config = {
                "algorithm": config.get("algorithm", "fernet"),
                "hash_algorithm": config.get("hash_algorithm", "SHA256")
            }
            
            password = "pattern_test_password"
            
            encrypt_file(input_file, encrypted_file, password, hash_config=encrypt_config)
            decrypt_file(encrypted_file, decrypted_file, password)
            
            # Verify integrity
            with open(decrypted_file, 'rb') as f:
                decrypted_data = f.read()
            
            if decrypted_data != data:
                return TestResult(
                    f"special_pattern_{pattern_name}",
                    TestResultLevel.ERROR,
                    f"Data corruption in pattern {pattern_name}"
                )
            
            return TestResult(
                f"special_pattern_{pattern_name}",
                TestResultLevel.PASS,
                f"Successfully handled {pattern_name} pattern",
                details={"pattern": pattern_name, "size": len(data)}
            )
            
        except Exception as e:
            return TestResult(
                f"special_pattern_{pattern_name}",
                TestResultLevel.ERROR,
                f"Exception with pattern {pattern_name}: {str(e)}",
                exception=e
            )
    
    def _test_malformed_configs(self, config: TestConfig) -> None:
        """Test handling of malformed configuration dictionaries."""
        malformed_configs = self.input_generator.generate_malformed_configs()
        
        for i, bad_config in enumerate(malformed_configs):
            result = self.run_single_test(
                self._test_bad_config,
                f"malformed_config_{i}",
                bad_config
            )
            self.add_result(result)
    
    def _test_bad_config(self, bad_config: Dict[str, Any]) -> TestResult:
        """Test that malformed configs are handled gracefully."""
        try:
            # Create test files
            input_file = os.path.join(self.temp_dir, "config_test.txt")
            encrypted_file = os.path.join(self.temp_dir, "config_test_enc.bin")
            
            # Write small test data
            with open(input_file, 'w') as f:
                f.write("test data for config validation")
            
            # This should either succeed with defaults or fail gracefully
            try:
                encrypt_file(input_file, encrypted_file, "test_password", hash_config=bad_config)
                
                # If it succeeds, that's okay (library uses defaults)
                return TestResult(
                    f"malformed_config",
                    TestResultLevel.PASS,
                    "Malformed config handled gracefully (used defaults)",
                    details={"config": bad_config}
                )
                
            except (ValueError, TypeError, KeyError) as expected_error:
                # Expected behavior - library should reject invalid configs
                return TestResult(
                    f"malformed_config",
                    TestResultLevel.PASS,
                    f"Malformed config properly rejected: {str(expected_error)}",
                    details={"config": bad_config, "error": str(expected_error)}
                )
            
        except Exception as unexpected_error:
            # Unexpected errors indicate problems
            return TestResult(
                f"malformed_config",
                TestResultLevel.ERROR,
                f"Unexpected error with malformed config: {str(unexpected_error)}",
                details={"config": bad_config},
                exception=unexpected_error
            )
    
    def _test_file_boundary_conditions(self, config: TestConfig) -> None:
        """Test various file-related boundary conditions."""
        test_cases = [
            ("empty_file", b""),
            ("large_file", self.input_generator.generate_random_bytes(10 * 1024 * 1024)),  # 10MB
            ("file_with_nulls", b"\x00" * 1000 + b"data" + b"\x00" * 1000),
        ]
        
        for test_name, test_data in test_cases:
            result = self.run_single_test(
                self._test_file_condition,
                f"file_boundary_{test_name}",
                test_data,
                test_name
            )
            self.add_result(result)
    
    def _test_file_condition(self, data: bytes, condition_name: str) -> TestResult:
        """Test specific file boundary condition."""
        try:
            input_file = os.path.join(self.temp_dir, f"{condition_name}_input.bin")
            encrypted_file = os.path.join(self.temp_dir, f"{condition_name}_encrypted.bin")
            decrypted_file = os.path.join(self.temp_dir, f"{condition_name}_decrypted.bin")
            
            with open(input_file, 'wb') as f:
                f.write(data)
            
            config_dict = {
                "algorithm": "fernet",
                "hash_algorithm": "SHA256"
            }
            
            encrypt_file(input_file, encrypted_file, "boundary_password", hash_config=config_dict)
            decrypt_file(encrypted_file, decrypted_file, "boundary_password")
            
            with open(decrypted_file, 'rb') as f:
                decrypted_data = f.read()
            
            if decrypted_data != data:
                return TestResult(
                    f"file_boundary_{condition_name}",
                    TestResultLevel.ERROR,
                    f"Data integrity failed for {condition_name}"
                )
            
            return TestResult(
                f"file_boundary_{condition_name}",
                TestResultLevel.PASS,
                f"Successfully handled {condition_name}",
                details={"data_size": len(data)}
            )
            
        except Exception as e:
            return TestResult(
                f"file_boundary_{condition_name}",
                TestResultLevel.ERROR,
                f"Exception in {condition_name}: {str(e)}",
                exception=e
            )
    
    def _test_password_fuzzing(self, config: TestConfig) -> None:
        """Test various password edge cases."""
        password_cases = [
            ("empty_password", ""),
            ("single_char", "a"),
            ("very_long", "a" * 10000),
            ("unicode", "🔒password世界"),
            ("special_chars", "!@#$%^&*()_+-=[]{}|;:,.<>?"),
            ("with_nulls", "pass\x00word\x00test"),
            ("binary", "\x01\x02\x03\x04\x05"),
        ]
        
        for password_name, password in password_cases:
            result = self.run_single_test(
                self._test_password_case,
                f"password_fuzz_{password_name}",
                password
            )
            self.add_result(result)
    
    def _test_password_case(self, password: str) -> TestResult:
        """Test specific password case."""
        try:
            input_file = os.path.join(self.temp_dir, "password_test.txt")
            encrypted_file = os.path.join(self.temp_dir, "password_test_enc.bin")
            decrypted_file = os.path.join(self.temp_dir, "password_test_dec.txt")
            
            test_data = "Password test data"
            with open(input_file, 'w') as f:
                f.write(test_data)
            
            config_dict = {"algorithm": "fernet", "hash_algorithm": "SHA256"}
            
            encrypt_file(input_file, encrypted_file, password, hash_config=config_dict)
            decrypt_file(encrypted_file, decrypted_file, password)
            
            with open(decrypted_file, 'r', encoding='utf-8') as f:
                decrypted_data = f.read()
            
            if decrypted_data != test_data:
                return TestResult(
                    f"password_fuzz",
                    TestResultLevel.ERROR,
                    f"Password case failed data integrity check"
                )
            
            return TestResult(
                f"password_fuzz",
                TestResultLevel.PASS,
                "Password case handled successfully",
                details={"password_length": len(password)}
            )
            
        except Exception as e:
            return TestResult(
                f"password_fuzz",
                TestResultLevel.ERROR,
                f"Password case failed: {str(e)}",
                exception=e
            )
    
    def _test_concurrent_access(self, config: TestConfig) -> None:
        """Test concurrent file access scenarios."""
        import threading
        import time
        
        def encrypt_worker(worker_id: int, results: List):
            try:
                input_file = os.path.join(self.temp_dir, f"concurrent_{worker_id}.txt")
                encrypted_file = os.path.join(self.temp_dir, f"concurrent_{worker_id}_enc.bin")
                
                with open(input_file, 'w') as f:
                    f.write(f"Concurrent test data {worker_id}")
                
                config_dict = {"algorithm": "fernet", "hash_algorithm": "SHA256"}
                encrypt_file(input_file, encrypted_file, f"password_{worker_id}", hash_config=config_dict)
                
                results.append(("success", worker_id, None))
            except Exception as e:
                results.append(("error", worker_id, e))
        
        # Run concurrent encryption operations
        threads = []
        results = []
        
        for i in range(5):  # 5 concurrent operations
            thread = threading.Thread(target=encrypt_worker, args=(i, results))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Analyze results
        success_count = sum(1 for status, _, _ in results if status == "success")
        error_count = len(results) - success_count
        
        if error_count == 0:
            test_result = TestResult(
                "concurrent_access",
                TestResultLevel.PASS,
                f"All {success_count} concurrent operations succeeded",
                details={"concurrent_operations": len(results), "success_count": success_count}
            )
        else:
            test_result = TestResult(
                "concurrent_access",
                TestResultLevel.WARNING,
                f"{success_count} succeeded, {error_count} failed in concurrent test",
                details={"total": len(results), "success": success_count, "errors": error_count}
            )
        
        self.add_result(test_result)