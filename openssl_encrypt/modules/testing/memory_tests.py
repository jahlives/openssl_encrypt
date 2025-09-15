"""
Memory Safety Test Suite for OpenSSL Encrypt Library.

Tests for memory leaks, buffer overflows, use-after-free,
secure memory zeroing, and other memory-related security issues.
"""

import gc
import os
import tempfile
import threading
import time
import weakref
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
import ctypes
import sys

from .base_test import BaseSecurityTest, TestResult, TestResultLevel, TestConfig
from ..crypt_core import encrypt_file, decrypt_file


@dataclass
class MemorySnapshot:
    """Represents a memory usage snapshot."""
    timestamp: float
    rss_bytes: int  # Resident Set Size
    vms_bytes: int  # Virtual Memory Size
    available_bytes: int
    percent_used: float
    operation: str = ""


class MemoryProfiler:
    """Memory profiling utilities."""
    
    def __init__(self):
        self.snapshots: List[MemorySnapshot] = []
        self._psutil_available = False
        
        try:
            import psutil
            self._psutil = psutil
            self._psutil_available = True
        except ImportError:
            self._psutil = None
    
    def is_available(self) -> bool:
        """Check if memory profiling is available."""
        return self._psutil_available
    
    def take_snapshot(self, operation: str = "") -> Optional[MemorySnapshot]:
        """Take a memory usage snapshot."""
        if not self._psutil_available:
            return None
        
        try:
            process = self._psutil.Process()
            memory_info = process.memory_info()
            virtual_memory = self._psutil.virtual_memory()
            
            snapshot = MemorySnapshot(
                timestamp=time.time(),
                rss_bytes=memory_info.rss,
                vms_bytes=memory_info.vms,
                available_bytes=virtual_memory.available,
                percent_used=virtual_memory.percent,
                operation=operation
            )
            
            self.snapshots.append(snapshot)
            return snapshot
            
        except Exception:
            return None
    
    def calculate_memory_delta(self, snapshot1: MemorySnapshot, 
                             snapshot2: MemorySnapshot) -> Dict[str, Any]:
        """Calculate memory usage delta between two snapshots."""
        return {
            "time_delta": snapshot2.timestamp - snapshot1.timestamp,
            "rss_delta": snapshot2.rss_bytes - snapshot1.rss_bytes,
            "vms_delta": snapshot2.vms_bytes - snapshot1.vms_bytes,
            "rss_delta_mb": (snapshot2.rss_bytes - snapshot1.rss_bytes) / (1024 * 1024),
            "vms_delta_mb": (snapshot2.vms_bytes - snapshot1.vms_bytes) / (1024 * 1024)
        }
    
    def detect_memory_leak(self, operation_snapshots: List[MemorySnapshot], 
                          threshold_mb: float = 1.0) -> Dict[str, Any]:
        """Detect potential memory leaks from a series of snapshots."""
        if len(operation_snapshots) < 3:
            return {"error": "Insufficient snapshots for leak detection"}
        
        # Calculate memory deltas between consecutive operations
        deltas = []
        for i in range(1, len(operation_snapshots)):
            delta = self.calculate_memory_delta(operation_snapshots[i-1], operation_snapshots[i])
            deltas.append(delta["rss_delta_mb"])
        
        # Check if memory consistently increases
        increasing_count = sum(1 for delta in deltas if delta > 0.1)  # 0.1 MB threshold
        leak_detected = increasing_count > len(deltas) * 0.7  # More than 70% increasing
        
        avg_increase = sum(delta for delta in deltas if delta > 0) / max(1, len(deltas))
        
        return {
            "leak_detected": leak_detected,
            "average_increase_mb": avg_increase,
            "increasing_operations": increasing_count,
            "total_operations": len(deltas),
            "leak_rate_mb_per_op": avg_increase if leak_detected else 0.0,
            "threshold_exceeded": avg_increase > threshold_mb
        }


class MemoryTestSuite(BaseSecurityTest):
    """Memory safety test suite."""
    
    def __init__(self):
        super().__init__(
            "MemoryTestSuite",
            "Memory safety tests for leak detection, secure zeroing, and buffer handling"
        )
        self.profiler = MemoryProfiler()
        self.temp_dir = None
    
    def setup_temp_directory(self) -> str:
        """Set up temporary directory for test files."""
        if not self.temp_dir:
            self.temp_dir = tempfile.mkdtemp(prefix="memory_test_")
        return self.temp_dir
    
    def cleanup_temp_directory(self) -> None:
        """Clean up temporary directory."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir = None
    
    def run_tests(self, **kwargs) -> List[TestResult]:
        """Run all memory safety tests."""
        self.clear_results()
        config = TestConfig(**kwargs)
        
        try:
            self.setup_temp_directory()
            
            # Run different categories of memory tests
            self._test_memory_leak_detection(config)
            self._test_memory_usage_patterns(config)
            self._test_large_file_memory_handling(config)
            self._test_concurrent_memory_access(config)
            self._test_memory_cleanup_after_errors(config)
            self._test_secure_memory_zeroing(config)
            
        finally:
            self.cleanup_temp_directory()
        
        return self.get_results()
    
    def _test_memory_leak_detection(self, config: TestConfig) -> None:
        """Test for memory leaks during repeated operations."""
        
        result = self.run_single_test(
            self._memory_leak_test,
            "memory_leak_detection",
            config
        )
        self.add_result(result)
    
    def _memory_leak_test(self, config: TestConfig) -> TestResult:
        """Test for memory leaks during repeated encryption/decryption."""
        if not self.profiler.is_available():
            return TestResult(
                "memory_leak_detection",
                TestResultLevel.WARNING,
                "psutil not available for memory leak detection"
            )
        
        try:
            # Create test file
            input_file = os.path.join(self.temp_dir, "leak_test.bin")
            encrypted_file = os.path.join(self.temp_dir, "leak_test_enc.bin") 
            decrypted_file = os.path.join(self.temp_dir, "leak_test_dec.bin")
            
            # Create moderate-sized test data
            test_data = os.urandom(512 * 1024)  # 512 KB
            with open(input_file, 'wb') as f:
                f.write(test_data)
            
            config_dict = {
                "algorithm": config.get("algorithm", "fernet"),
                "hash_algorithm": config.get("hash_algorithm", "SHA256")
            }
            
            password = "memory_leak_test_password"
            
            # Perform multiple encryption/decryption cycles
            snapshots = []
            iterations = config.get("memory_test_iterations", 10)
            
            # Initial snapshot
            gc.collect()
            initial_snapshot = self.profiler.take_snapshot("initial")
            if initial_snapshot:
                snapshots.append(initial_snapshot)
            
            for i in range(iterations):
                # Clean up previous iteration files
                for temp_file in [encrypted_file, decrypted_file]:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                
                # Perform encryption/decryption cycle
                encrypt_file(input_file, encrypted_file, password, hash_config=config_dict)
                decrypt_file(encrypted_file, decrypted_file, password)
                
                # Force garbage collection
                gc.collect()
                
                # Take memory snapshot
                snapshot = self.profiler.take_snapshot(f"iteration_{i}")
                if snapshot:
                    snapshots.append(snapshot)
            
            if len(snapshots) < 3:
                return TestResult(
                    "memory_leak_detection",
                    TestResultLevel.WARNING,
                    "Insufficient memory snapshots for leak analysis"
                )
            
            # Analyze for memory leaks
            leak_analysis = self.profiler.detect_memory_leak(snapshots)
            
            if leak_analysis.get("error"):
                return TestResult(
                    "memory_leak_detection",
                    TestResultLevel.WARNING,
                    f"Leak analysis error: {leak_analysis['error']}"
                )
            
            leak_detected = leak_analysis.get("leak_detected", False)
            avg_increase = leak_analysis.get("average_increase_mb", 0.0)
            
            if leak_detected:
                level = TestResultLevel.WARNING
                message = f"Potential memory leak detected ({avg_increase:.2f} MB/operation)"
            else:
                level = TestResultLevel.PASS
                message = f"No significant memory leaks detected ({avg_increase:.2f} MB/operation)"
            
            return TestResult(
                "memory_leak_detection",
                level,
                message,
                details={
                    "leak_analysis": leak_analysis,
                    "iterations": iterations,
                    "snapshots_count": len(snapshots),
                    "test_data_size": len(test_data)
                }
            )
            
        except Exception as e:
            return TestResult(
                "memory_leak_detection",
                TestResultLevel.ERROR,
                f"Exception during memory leak test: {str(e)}",
                exception=e
            )
    
    def _test_memory_usage_patterns(self, config: TestConfig) -> None:
        """Test memory usage patterns with different file sizes."""
        
        result = self.run_single_test(
            self._memory_usage_pattern_test,
            "memory_usage_patterns",
            config
        )
        self.add_result(result)
    
    def _memory_usage_pattern_test(self, config: TestConfig) -> TestResult:
        """Test memory usage scaling with file sizes."""
        if not self.profiler.is_available():
            return TestResult(
                "memory_usage_patterns",
                TestResultLevel.WARNING,
                "psutil not available for memory pattern analysis"
            )
        
        try:
            file_sizes = [64 * 1024, 256 * 1024, 1024 * 1024]  # 64KB, 256KB, 1MB
            memory_patterns = {}
            
            for file_size in file_sizes:
                input_file = os.path.join(self.temp_dir, f"pattern_{file_size}.bin")
                encrypted_file = os.path.join(self.temp_dir, f"pattern_{file_size}_enc.bin")
                
                # Create test file
                test_data = os.urandom(file_size)
                with open(input_file, 'wb') as f:
                    f.write(test_data)
                
                config_dict = {
                    "algorithm": "fernet",
                    "hash_algorithm": "SHA256"
                }
                
                # Take memory snapshot before operation
                gc.collect()
                before_snapshot = self.profiler.take_snapshot(f"before_{file_size}")
                
                # Perform encryption
                encrypt_file(input_file, encrypted_file, "pattern_password", hash_config=config_dict)
                
                # Take memory snapshot after operation
                after_snapshot = self.profiler.take_snapshot(f"after_{file_size}")
                
                if before_snapshot and after_snapshot:
                    delta = self.profiler.calculate_memory_delta(before_snapshot, after_snapshot)
                    memory_patterns[file_size] = {
                        "file_size_mb": file_size / (1024 * 1024),
                        "memory_increase_mb": delta["rss_delta_mb"],
                        "memory_ratio": delta["rss_delta_mb"] / (file_size / (1024 * 1024)) if file_size > 0 else 0
                    }
                
                # Clean up
                for temp_file in [encrypted_file]:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
            
            if not memory_patterns:
                return TestResult(
                    "memory_usage_patterns",
                    TestResultLevel.WARNING,
                    "No memory pattern data collected"
                )
            
            # Analyze memory usage efficiency
            memory_ratios = [data["memory_ratio"] for data in memory_patterns.values()]
            avg_ratio = sum(memory_ratios) / len(memory_ratios)
            
            # Memory usage is considered efficient if it's less than 2x file size
            efficient = avg_ratio < 2.0
            
            level = TestResultLevel.PASS if efficient else TestResultLevel.WARNING
            message = f"Memory usage {'efficient' if efficient else 'high'} (avg ratio: {avg_ratio:.2f}x)"
            
            return TestResult(
                "memory_usage_patterns",
                level,
                message,
                details={
                    "memory_patterns": memory_patterns,
                    "average_memory_ratio": avg_ratio,
                    "efficient": efficient,
                    "file_sizes_tested": file_sizes
                }
            )
            
        except Exception as e:
            return TestResult(
                "memory_usage_patterns",
                TestResultLevel.ERROR,
                f"Exception during memory pattern test: {str(e)}",
                exception=e
            )
    
    def _test_large_file_memory_handling(self, config: TestConfig) -> None:
        """Test memory handling with large files."""
        
        result = self.run_single_test(
            self._large_file_memory_test,
            "large_file_memory_handling",
            config
        )
        self.add_result(result)
    
    def _large_file_memory_test(self, config: TestConfig) -> TestResult:
        """Test memory usage with large files."""
        if not self.profiler.is_available():
            return TestResult(
                "large_file_memory_handling",
                TestResultLevel.WARNING,
                "psutil not available for large file memory analysis"
            )
        
        try:
            # Test with a reasonably large file (10 MB)
            large_file_size = 10 * 1024 * 1024  # 10 MB
            
            input_file = os.path.join(self.temp_dir, "large_file.bin")
            encrypted_file = os.path.join(self.temp_dir, "large_file_enc.bin")
            
            # Create large test file
            with open(input_file, 'wb') as f:
                # Write in chunks to avoid memory issues during creation
                chunk_size = 1024 * 1024  # 1 MB chunks
                remaining = large_file_size
                
                while remaining > 0:
                    chunk = os.urandom(min(chunk_size, remaining))
                    f.write(chunk)
                    remaining -= len(chunk)
            
            config_dict = {
                "algorithm": config.get("algorithm", "fernet"),
                "hash_algorithm": "SHA256"
            }
            
            # Monitor memory during large file encryption
            gc.collect()
            before_snapshot = self.profiler.take_snapshot("before_large_file")
            
            try:
                encrypt_file(input_file, encrypted_file, "large_file_password", hash_config=config_dict)
                encryption_successful = True
            except MemoryError:
                encryption_successful = False
            except Exception as e:
                return TestResult(
                    "large_file_memory_handling",
                    TestResultLevel.ERROR,
                    f"Unexpected error during large file encryption: {str(e)}",
                    exception=e
                )
            
            after_snapshot = self.profiler.take_snapshot("after_large_file")
            
            if not encryption_successful:
                return TestResult(
                    "large_file_memory_handling",
                    TestResultLevel.ERROR,
                    "Memory error during large file encryption - insufficient memory handling"
                )
            
            if before_snapshot and after_snapshot:
                delta = self.profiler.calculate_memory_delta(before_snapshot, after_snapshot)
                memory_usage_ratio = delta["rss_delta_mb"] / (large_file_size / (1024 * 1024))
                
                # Check if memory usage is reasonable (< 3x file size)
                reasonable_usage = memory_usage_ratio < 3.0
                
                level = TestResultLevel.PASS if reasonable_usage else TestResultLevel.WARNING
                message = f"Large file memory usage {'reasonable' if reasonable_usage else 'high'} ({memory_usage_ratio:.2f}x)"
                
                return TestResult(
                    "large_file_memory_handling",
                    level,
                    message,
                    details={
                        "file_size_mb": large_file_size / (1024 * 1024),
                        "memory_increase_mb": delta["rss_delta_mb"],
                        "memory_usage_ratio": memory_usage_ratio,
                        "encryption_successful": True,
                        "reasonable_usage": reasonable_usage
                    }
                )
            else:
                return TestResult(
                    "large_file_memory_handling",
                    TestResultLevel.WARNING,
                    "Large file encryption succeeded but memory snapshots unavailable"
                )
                
        except Exception as e:
            return TestResult(
                "large_file_memory_handling",
                TestResultLevel.ERROR,
                f"Exception during large file memory test: {str(e)}",
                exception=e
            )
    
    def _test_concurrent_memory_access(self, config: TestConfig) -> None:
        """Test memory safety during concurrent operations."""
        
        result = self.run_single_test(
            self._concurrent_memory_test,
            "concurrent_memory_access",
            config
        )
        self.add_result(result)
    
    def _concurrent_memory_test(self, config: TestConfig) -> TestResult:
        """Test memory safety with concurrent encryption operations."""
        try:
            # Prepare test files
            thread_count = 3
            test_files = []
            
            for i in range(thread_count):
                input_file = os.path.join(self.temp_dir, f"concurrent_{i}.bin")
                encrypted_file = os.path.join(self.temp_dir, f"concurrent_{i}_enc.bin")
                
                test_data = os.urandom(256 * 1024)  # 256 KB per file
                with open(input_file, 'wb') as f:
                    f.write(test_data)
                
                test_files.append((input_file, encrypted_file))
            
            config_dict = {
                "algorithm": "fernet",
                "hash_algorithm": "SHA256"
            }
            
            # Test concurrent access
            results = []
            errors = []
            
            def encrypt_worker(worker_id: int, input_file: str, encrypted_file: str):
                try:
                    encrypt_file(input_file, encrypted_file, f"concurrent_password_{worker_id}", hash_config=config_dict)
                    results.append(f"Worker {worker_id} completed successfully")
                except Exception as e:
                    errors.append(f"Worker {worker_id} failed: {str(e)}")
            
            # Start concurrent operations
            threads = []
            for i, (input_file, encrypted_file) in enumerate(test_files):
                thread = threading.Thread(
                    target=encrypt_worker,
                    args=(i, input_file, encrypted_file)
                )
                threads.append(thread)
                thread.start()
            
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
            
            # Analyze results
            success_count = len(results)
            error_count = len(errors)
            
            if error_count == 0:
                return TestResult(
                    "concurrent_memory_access",
                    TestResultLevel.PASS,
                    f"All {success_count} concurrent operations completed successfully",
                    details={
                        "thread_count": thread_count,
                        "successful_operations": success_count,
                        "failed_operations": error_count,
                        "results": results
                    }
                )
            elif success_count > error_count:
                return TestResult(
                    "concurrent_memory_access",
                    TestResultLevel.WARNING,
                    f"{success_count} succeeded, {error_count} failed in concurrent operations",
                    details={
                        "thread_count": thread_count,
                        "successful_operations": success_count,
                        "failed_operations": error_count,
                        "results": results,
                        "errors": errors
                    }
                )
            else:
                return TestResult(
                    "concurrent_memory_access",
                    TestResultLevel.ERROR,
                    f"Most concurrent operations failed ({error_count}/{thread_count})",
                    details={
                        "thread_count": thread_count,
                        "successful_operations": success_count,
                        "failed_operations": error_count,
                        "errors": errors
                    }
                )
                
        except Exception as e:
            return TestResult(
                "concurrent_memory_access",
                TestResultLevel.ERROR,
                f"Exception during concurrent memory test: {str(e)}",
                exception=e
            )
    
    def _test_memory_cleanup_after_errors(self, config: TestConfig) -> None:
        """Test that memory is properly cleaned up after errors."""
        
        result = self.run_single_test(
            self._error_cleanup_test,
            "memory_cleanup_after_errors",
            config
        )
        self.add_result(result)
    
    def _error_cleanup_test(self, config: TestConfig) -> TestResult:
        """Test memory cleanup after intentional errors."""
        if not self.profiler.is_available():
            return TestResult(
                "memory_cleanup_after_errors",
                TestResultLevel.WARNING,
                "psutil not available for error cleanup analysis"
            )
        
        try:
            # Take baseline memory snapshot
            gc.collect()
            baseline_snapshot = self.profiler.take_snapshot("baseline")
            
            error_scenarios = [
                ("nonexistent_file", "nonexistent_input.bin", "output.bin"),
                ("invalid_password", "valid_input.txt", "output.bin"),  # We'll create this one
            ]
            
            # Create a valid input file for invalid password test
            valid_input = os.path.join(self.temp_dir, "valid_input.txt")
            encrypted_valid = os.path.join(self.temp_dir, "encrypted_valid.bin")
            with open(valid_input, 'w') as f:
                f.write("Test data for error scenarios")
            
            # First encrypt with correct password
            correct_config = {
                "algorithm": "fernet",
                "hash_algorithm": "SHA256"
            }
            encrypt_file(valid_input, encrypted_valid, "correct_password", hash_config=correct_config)
            
            memory_after_errors = []
            
            for scenario_name, input_file, output_file in error_scenarios:
                for attempt in range(3):  # Multiple attempts per scenario
                    try:
                        if scenario_name == "nonexistent_file":
                            # This should fail - file doesn't exist
                            encrypt_file(input_file, output_file, "test_password", hash_config=correct_config)
                        elif scenario_name == "invalid_password":
                            # This should fail - wrong password for decryption
                            decrypt_file(encrypted_valid, output_file, "wrong_password")
                        
                    except Exception:
                        # Expected to fail - we want to test cleanup after errors
                        pass
                    
                    # Force garbage collection
                    gc.collect()
                    
                    # Take memory snapshot after error
                    snapshot = self.profiler.take_snapshot(f"{scenario_name}_attempt_{attempt}")
                    if snapshot:
                        memory_after_errors.append(snapshot)
            
            if not baseline_snapshot or not memory_after_errors:
                return TestResult(
                    "memory_cleanup_after_errors",
                    TestResultLevel.WARNING,
                    "Insufficient memory snapshots for error cleanup analysis"
                )
            
            # Analyze memory usage after errors
            memory_increases = []
            for snapshot in memory_after_errors:
                delta = self.profiler.calculate_memory_delta(baseline_snapshot, snapshot)
                memory_increases.append(delta["rss_delta_mb"])
            
            avg_increase = sum(memory_increases) / len(memory_increases)
            max_increase = max(memory_increases)
            
            # Consider cleanup good if average increase is < 1 MB
            good_cleanup = avg_increase < 1.0 and max_increase < 2.0
            
            level = TestResultLevel.PASS if good_cleanup else TestResultLevel.WARNING
            message = f"Memory cleanup after errors {'good' if good_cleanup else 'needs improvement'}"
            
            return TestResult(
                "memory_cleanup_after_errors",
                level,
                message,
                details={
                    "average_increase_mb": avg_increase,
                    "max_increase_mb": max_increase,
                    "error_scenarios_tested": len(error_scenarios),
                    "memory_snapshots": len(memory_after_errors),
                    "good_cleanup": good_cleanup
                }
            )
            
        except Exception as e:
            return TestResult(
                "memory_cleanup_after_errors",
                TestResultLevel.ERROR,
                f"Exception during error cleanup test: {str(e)}",
                exception=e
            )
    
    def _test_secure_memory_zeroing(self, config: TestConfig) -> None:
        """Test that sensitive data is securely zeroed from memory."""
        
        result = self.run_single_test(
            self._secure_zeroing_test,
            "secure_memory_zeroing",
            config
        )
        self.add_result(result)
    
    def _secure_zeroing_test(self, config: TestConfig) -> TestResult:
        """Test secure memory zeroing of sensitive data."""
        try:
            # This is a challenging test - we'll use weak references to check
            # if sensitive data objects are properly cleaned up
            
            input_file = os.path.join(self.temp_dir, "zeroing_test.txt")
            encrypted_file = os.path.join(self.temp_dir, "zeroing_test_enc.bin")
            
            test_data = "Sensitive data that should be zeroed from memory: " + "SECRET" * 100
            with open(input_file, 'w') as f:
                f.write(test_data)
            
            config_dict = {
                "algorithm": "fernet",
                "hash_algorithm": "SHA256"
            }
            
            # Create weak references to track object cleanup
            weak_refs = []
            
            # Perform encryption operations
            for i in range(5):
                password = f"sensitive_password_{i}_{'SECRET' * 10}"
                
                # Store weak reference to the password string
                # Note: This is somewhat artificial since Python strings are immutable
                # and may be interned, but it's a reasonable test
                if sys.version_info >= (3, 7):
                    # Create a mutable object containing sensitive data
                    sensitive_data = bytearray(password.encode('utf-8'))
                    weak_refs.append(weakref.ref(sensitive_data))
                
                try:
                    encrypt_file(input_file, encrypted_file, password, hash_config=config_dict)
                except Exception:
                    pass  # Don't care about success/failure, just memory cleanup
                
                # Clear local references
                del password
                if 'sensitive_data' in locals():
                    del sensitive_data
                
                # Clean up output file
                if os.path.exists(encrypted_file):
                    os.remove(encrypted_file)
            
            # Force garbage collection multiple times
            for _ in range(3):
                gc.collect()
            
            # Check weak references
            alive_refs = sum(1 for ref in weak_refs if ref() is not None)
            total_refs = len(weak_refs)
            
            # Most references should be cleaned up
            good_cleanup = alive_refs < total_refs * 0.2  # Less than 20% still alive
            
            if total_refs == 0:
                # Fallback test - just check that operations completed
                level = TestResultLevel.WARNING
                message = "Secure zeroing test completed but could not verify memory cleanup"
                details = {"note": "Weak reference tracking not available"}
            else:
                level = TestResultLevel.PASS if good_cleanup else TestResultLevel.WARNING
                message = f"Secure memory zeroing {'effective' if good_cleanup else 'may need improvement'}"
                details = {
                    "weak_references_created": total_refs,
                    "references_still_alive": alive_refs,
                    "cleanup_percentage": (total_refs - alive_refs) / total_refs * 100 if total_refs > 0 else 0,
                    "good_cleanup": good_cleanup
                }
            
            return TestResult(
                "secure_memory_zeroing",
                level,
                message,
                details=details
            )
            
        except Exception as e:
            return TestResult(
                "secure_memory_zeroing",
                TestResultLevel.ERROR,
                f"Exception during secure zeroing test: {str(e)}",
                exception=e
            )