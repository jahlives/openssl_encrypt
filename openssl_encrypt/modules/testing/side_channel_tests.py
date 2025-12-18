"""
Side-Channel Resistance Testing Suite for OpenSSL Encrypt Library.

Tests for timing attacks, memory access pattern analysis, and other
side-channel vulnerabilities in cryptographic operations.
"""

import gc
import os
import statistics
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ..crypt_core import decrypt_file, encrypt_file
from .base_test import BaseSecurityTest, TestConfig, TestResult, TestResultLevel


@dataclass
class TimingMeasurement:
    """Represents a timing measurement for statistical analysis."""

    operation: str
    input_size: int
    password_length: int
    duration: float
    metadata: Dict[str, Any]


class StatisticalAnalyzer:
    """Performs statistical analysis on timing measurements."""

    @staticmethod
    def analyze_timing_consistency(measurements: List[float], operation: str) -> Dict[str, Any]:
        """Analyze timing measurements for consistency."""
        if len(measurements) < 3:
            return {
                "operation": operation,
                "sample_size": len(measurements),
                "error": "Insufficient samples for analysis",
            }

        mean_time = statistics.mean(measurements)
        std_dev = statistics.stdev(measurements)
        median_time = statistics.median(measurements)

        # Coefficient of variation (relative standard deviation)
        cv = (std_dev / mean_time) * 100 if mean_time > 0 else float("inf")

        # Detect outliers using IQR method
        q1 = statistics.quantiles(measurements, n=4)[0]
        q3 = statistics.quantiles(measurements, n=4)[2]
        iqr = q3 - q1
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr
        outliers = [x for x in measurements if x < lower_bound or x > upper_bound]

        return {
            "operation": operation,
            "sample_size": len(measurements),
            "mean": mean_time,
            "median": median_time,
            "std_dev": std_dev,
            "coefficient_of_variation": cv,
            "min": min(measurements),
            "max": max(measurements),
            "outliers_count": len(outliers),
            "outliers_percentage": (len(outliers) / len(measurements)) * 100,
            "timing_consistent": cv < 10.0,  # Less than 10% variation is considered consistent
            "has_outliers": len(outliers) > 0,
        }

    @staticmethod
    def compare_timing_distributions(group1: List[float], group2: List[float]) -> Dict[str, Any]:
        """Compare two groups of timing measurements."""
        if len(group1) < 3 or len(group2) < 3:
            return {"error": "Insufficient samples for comparison"}

        mean1 = statistics.mean(group1)
        mean2 = statistics.mean(group2)

        # Simple statistical comparison
        mean_diff_percentage = abs(mean1 - mean2) / max(mean1, mean2) * 100

        # Check if difference is significant (> 20% difference)
        significant_difference = mean_diff_percentage > 20.0

        return {
            "group1_mean": mean1,
            "group2_mean": mean2,
            "mean_difference_percentage": mean_diff_percentage,
            "significant_difference": significant_difference,
            "potentially_vulnerable": significant_difference,
        }


class SideChannelTestSuite(BaseSecurityTest):
    """Side-channel resistance test suite."""

    def __init__(self):
        super().__init__(
            "SideChannelTestSuite",
            "Tests for side-channel vulnerabilities in cryptographic operations",
        )
        self.analyzer = StatisticalAnalyzer()
        self.temp_dir = None

    def setup_temp_directory(self) -> str:
        """Set up temporary directory for test files."""
        if not self.temp_dir:
            self.temp_dir = tempfile.mkdtemp(prefix="sidechannel_test_")
        return self.temp_dir

    def cleanup_temp_directory(self) -> None:
        """Clean up temporary directory."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            import shutil

            shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir = None

    def run_tests(self, **kwargs) -> List[TestResult]:
        """Run all side-channel resistance tests."""
        self.clear_results()
        config = TestConfig(**kwargs)

        try:
            self.setup_temp_directory()

            # Run different categories of side-channel tests
            self._test_password_timing_attack(config)
            self._test_file_size_timing_correlation(config)
            self._test_memory_access_patterns(config)
            self._test_cache_timing_attacks(config)
            self._test_algorithm_timing_consistency(config)

        finally:
            self.cleanup_temp_directory()

        return self.get_results()

    def _measure_operation_timing(self, operation_func, *args, **kwargs) -> float:
        """Measure timing of a cryptographic operation with high precision."""
        # Force garbage collection before measurement
        gc.collect()

        # Warm up the operation (to reduce JIT compilation effects)
        try:
            operation_func(*args, **kwargs)
        except:
            pass  # Ignore errors during warmup

        gc.collect()

        # Perform the actual measurement
        start_time = time.perf_counter()
        try:
            operation_func(*args, **kwargs)
            end_time = time.perf_counter()
            return end_time - start_time
        except Exception as e:
            # Return a sentinel value for failed operations
            return -1.0

    def _test_password_timing_attack(self, config: TestConfig) -> None:
        """Test resistance to timing attacks based on password differences."""

        # Test with correct vs incorrect passwords
        result = self.run_single_test(
            self._password_timing_test, "password_timing_attack_resistance", config
        )
        self.add_result(result)

    def _password_timing_test(self, config: TestConfig) -> TestResult:
        """Test timing differences between correct and incorrect passwords."""
        try:
            # Create test file
            input_file = os.path.join(self.temp_dir, "timing_test.txt")
            encrypted_file = os.path.join(self.temp_dir, "timing_test_enc.bin")
            decrypted_file = os.path.join(self.temp_dir, "timing_test_dec.txt")

            test_data = "Timing attack test data " * 100  # Reasonable size
            with open(input_file, "w") as f:
                f.write(test_data)

            correct_password = "correct_password_123"
            config_dict = {
                "algorithm": config.get("algorithm", "fernet"),
                "hash_algorithm": config.get("hash_algorithm", "SHA256"),
            }

            # Encrypt with correct password
            encrypt_file(input_file, encrypted_file, correct_password, hash_config=config_dict)

            # Test decryption timing with correct password
            correct_timings = []
            for i in range(10):  # Multiple measurements for statistical analysis
                timing = self._measure_operation_timing(
                    decrypt_file, encrypted_file, decrypted_file, correct_password
                )
                if timing > 0:  # Valid measurement
                    correct_timings.append(timing)
                # Clean up for next iteration
                if os.path.exists(decrypted_file):
                    os.remove(decrypted_file)

            # Test decryption timing with incorrect passwords
            incorrect_passwords = [
                "wrong_password_123",
                "incorrect_password_456",
                "bad_password_789",
                "fake_password_000",
            ]

            incorrect_timings = []
            for wrong_password in incorrect_passwords:
                for i in range(3):  # Fewer iterations for wrong passwords
                    try:
                        timing = self._measure_operation_timing(
                            decrypt_file, encrypted_file, decrypted_file, wrong_password
                        )
                        if timing > 0:  # Only count successful timing measurements
                            incorrect_timings.append(timing)
                    except:
                        # Expected to fail, but we want to measure the timing of the failure
                        pass
                    # Clean up
                    if os.path.exists(decrypted_file):
                        os.remove(decrypted_file)

            if len(correct_timings) < 3 or len(incorrect_timings) < 3:
                return TestResult(
                    "password_timing_attack_resistance",
                    TestResultLevel.WARNING,
                    "Insufficient timing measurements collected",
                    details={
                        "correct_samples": len(correct_timings),
                        "incorrect_samples": len(incorrect_timings),
                    },
                )

            # Analyze timing differences
            comparison = self.analyzer.compare_timing_distributions(
                correct_timings, incorrect_timings
            )

            # Analyze consistency within each group
            correct_analysis = self.analyzer.analyze_timing_consistency(
                correct_timings, "correct_password_decryption"
            )
            incorrect_analysis = self.analyzer.analyze_timing_consistency(
                incorrect_timings, "incorrect_password_decryption"
            )

            # Determine result
            if comparison.get("potentially_vulnerable", False):
                level = TestResultLevel.WARNING
                message = f"Potential timing attack vulnerability detected ({comparison['mean_difference_percentage']:.1f}% difference)"
            else:
                level = TestResultLevel.PASS
                message = f"Timing attack resistance confirmed ({comparison['mean_difference_percentage']:.1f}% difference)"

            return TestResult(
                "password_timing_attack_resistance",
                level,
                message,
                details={
                    "comparison": comparison,
                    "correct_password_analysis": correct_analysis,
                    "incorrect_password_analysis": incorrect_analysis,
                },
            )

        except Exception as e:
            return TestResult(
                "password_timing_attack_resistance",
                TestResultLevel.ERROR,
                f"Error during password timing test: {str(e)}",
                exception=e,
            )

    def _test_file_size_timing_correlation(self, config: TestConfig) -> None:
        """Test if timing correlates with file size in unexpected ways."""

        result = self.run_single_test(
            self._file_size_timing_test, "file_size_timing_correlation", config
        )
        self.add_result(result)

    def _file_size_timing_test(self, config: TestConfig) -> TestResult:
        """Test timing correlation with file sizes."""
        try:
            file_sizes = [1024, 2048, 4096, 8192, 16384]  # Powers of 2
            timing_data = {}

            config_dict = {
                "algorithm": config.get("algorithm", "fernet"),
                "hash_algorithm": config.get("hash_algorithm", "SHA256"),
            }

            for size in file_sizes:
                # Create file of specific size
                input_file = os.path.join(self.temp_dir, f"size_test_{size}.bin")
                encrypted_file = os.path.join(self.temp_dir, f"size_test_{size}_enc.bin")

                test_data = b"A" * size
                with open(input_file, "wb") as f:
                    f.write(test_data)

                # Measure encryption timing
                timings = []
                for i in range(5):  # Multiple measurements
                    timing = self._measure_operation_timing(
                        encrypt_file, input_file, encrypted_file, "test_password", config_dict
                    )
                    if timing > 0:
                        timings.append(timing)
                    # Clean up for next iteration
                    if os.path.exists(encrypted_file):
                        os.remove(encrypted_file)

                if timings:
                    timing_data[size] = {
                        "timings": timings,
                        "mean": statistics.mean(timings),
                        "std_dev": statistics.stdev(timings) if len(timings) > 1 else 0,
                    }

            # Analyze correlation
            if len(timing_data) < 3:
                return TestResult(
                    "file_size_timing_correlation",
                    TestResultLevel.WARNING,
                    "Insufficient data for correlation analysis",
                )

            # Check if timing scales roughly linearly with file size
            sizes = list(timing_data.keys())
            means = [timing_data[size]["mean"] for size in sizes]

            # Simple linearity check
            size_ratios = [sizes[i] / sizes[0] for i in range(len(sizes))]
            timing_ratios = [means[i] / means[0] for i in range(len(means))]

            # Check if timing scales approximately linearly with size
            correlation_good = True
            for i in range(1, len(size_ratios)):
                # Allow 50% deviation from linear scaling
                expected_ratio = size_ratios[i]
                actual_ratio = timing_ratios[i]
                deviation = abs(expected_ratio - actual_ratio) / expected_ratio
                if deviation > 0.5:  # More than 50% deviation
                    correlation_good = False
                    break

            level = TestResultLevel.PASS if correlation_good else TestResultLevel.WARNING
            message = f"File size timing correlation {'as expected' if correlation_good else 'shows anomalies'}"

            return TestResult(
                "file_size_timing_correlation",
                level,
                message,
                details={
                    "timing_data": timing_data,
                    "size_ratios": size_ratios,
                    "timing_ratios": timing_ratios,
                    "linear_correlation": correlation_good,
                },
            )

        except Exception as e:
            return TestResult(
                "file_size_timing_correlation",
                TestResultLevel.ERROR,
                f"Error during file size timing test: {str(e)}",
                exception=e,
            )

    def _test_memory_access_patterns(self, config: TestConfig) -> None:
        """Test for consistent memory access patterns."""

        result = self.run_single_test(self._memory_pattern_test, "memory_access_patterns", config)
        self.add_result(result)

    def _memory_pattern_test(self, config: TestConfig) -> TestResult:
        """Test memory access pattern consistency."""
        try:
            import os

            import psutil

            # Create test file
            input_file = os.path.join(self.temp_dir, "memory_test.bin")
            encrypted_file = os.path.join(self.temp_dir, "memory_test_enc.bin")

            test_data = b"Memory access pattern test data " * 1000
            with open(input_file, "wb") as f:
                f.write(test_data)

            config_dict = {
                "algorithm": config.get("algorithm", "fernet"),
                "hash_algorithm": config.get("hash_algorithm", "SHA256"),
            }

            # Measure memory usage during encryption
            process = psutil.Process()

            memory_before = process.memory_info().rss
            encrypt_file(
                input_file, encrypted_file, "memory_test_password", hash_config=config_dict
            )
            memory_after = process.memory_info().rss

            memory_used = memory_after - memory_before

            # Test multiple iterations to check consistency
            memory_measurements = []
            for i in range(3):
                os.remove(encrypted_file)  # Clean up
                gc.collect()

                memory_before = process.memory_info().rss
                encrypt_file(
                    input_file, encrypted_file, "memory_test_password", hash_config=config_dict
                )
                memory_after = process.memory_info().rss

                memory_measurements.append(memory_after - memory_before)

            # Analyze memory usage consistency
            if len(memory_measurements) > 1:
                memory_analysis = self.analyzer.analyze_timing_consistency(
                    [float(m) for m in memory_measurements], "memory_usage"
                )

                consistent_memory = memory_analysis.get("timing_consistent", False)
                level = TestResultLevel.PASS if consistent_memory else TestResultLevel.WARNING
                message = f"Memory access patterns {'consistent' if consistent_memory else 'inconsistent'}"
            else:
                level = TestResultLevel.WARNING
                message = "Insufficient memory measurements"
                memory_analysis = {}

            return TestResult(
                "memory_access_patterns",
                level,
                message,
                details={
                    "memory_measurements": memory_measurements,
                    "analysis": memory_analysis,
                    "input_size": len(test_data),
                },
            )

        except ImportError:
            return TestResult(
                "memory_access_patterns",
                TestResultLevel.WARNING,
                "psutil not available for memory analysis",
            )
        except Exception as e:
            return TestResult(
                "memory_access_patterns",
                TestResultLevel.ERROR,
                f"Error during memory pattern test: {str(e)}",
                exception=e,
            )

    def _test_cache_timing_attacks(self, config: TestConfig) -> None:
        """Test resistance to cache timing attacks."""

        result = self.run_single_test(
            self._cache_timing_test, "cache_timing_attack_resistance", config
        )
        self.add_result(result)

    def _cache_timing_test(self, config: TestConfig) -> TestResult:
        """Test cache timing attack resistance."""
        try:
            # Create test data with different patterns that might affect caching
            patterns = {
                "pattern_a": b"A" * 4096,
                "pattern_b": b"B" * 4096,
                "mixed": b"AB" * 2048,
                "random": os.urandom(4096),
            }

            config_dict = {
                "algorithm": config.get("algorithm", "fernet"),
                "hash_algorithm": config.get("hash_algorithm", "SHA256"),
            }

            timing_results = {}

            for pattern_name, pattern_data in patterns.items():
                input_file = os.path.join(self.temp_dir, f"cache_{pattern_name}.bin")
                encrypted_file = os.path.join(self.temp_dir, f"cache_{pattern_name}_enc.bin")

                with open(input_file, "wb") as f:
                    f.write(pattern_data)

                # Measure timing for this pattern
                timings = []
                for i in range(5):
                    if os.path.exists(encrypted_file):
                        os.remove(encrypted_file)

                    timing = self._measure_operation_timing(
                        encrypt_file, input_file, encrypted_file, "cache_test_password", config_dict
                    )
                    if timing > 0:
                        timings.append(timing)

                if timings:
                    timing_results[pattern_name] = {
                        "timings": timings,
                        "mean": statistics.mean(timings),
                        "std_dev": statistics.stdev(timings) if len(timings) > 1 else 0,
                    }

            if len(timing_results) < 2:
                return TestResult(
                    "cache_timing_attack_resistance",
                    TestResultLevel.WARNING,
                    "Insufficient timing data for cache analysis",
                )

            # Compare timing between different patterns
            pattern_means = [data["mean"] for data in timing_results.values()]
            max_mean = max(pattern_means)
            min_mean = min(pattern_means)

            # Calculate variation between patterns
            variation_percentage = ((max_mean - min_mean) / max_mean) * 100

            # If variation is less than 15%, consider it resistant to cache timing
            cache_resistant = variation_percentage < 15.0

            level = TestResultLevel.PASS if cache_resistant else TestResultLevel.WARNING
            message = f"Cache timing variation: {variation_percentage:.1f}% ({'resistant' if cache_resistant else 'potentially vulnerable'})"

            return TestResult(
                "cache_timing_attack_resistance",
                level,
                message,
                details={
                    "pattern_timings": timing_results,
                    "variation_percentage": variation_percentage,
                    "cache_resistant": cache_resistant,
                },
            )

        except Exception as e:
            return TestResult(
                "cache_timing_attack_resistance",
                TestResultLevel.ERROR,
                f"Error during cache timing test: {str(e)}",
                exception=e,
            )

    def _test_algorithm_timing_consistency(self, config: TestConfig) -> None:
        """Test timing consistency across different algorithms."""

        result = self.run_single_test(
            self._algorithm_consistency_test, "algorithm_timing_consistency", config
        )
        self.add_result(result)

    def _algorithm_consistency_test(self, config: TestConfig) -> TestResult:
        """Test timing consistency within each algorithm."""
        try:
            algorithms = ["fernet", "aes-gcm", "chacha20-poly1305"]
            algorithm_results = {}

            # Create test file
            input_file = os.path.join(self.temp_dir, "algorithm_test.bin")
            test_data = b"Algorithm consistency test data " * 100
            with open(input_file, "wb") as f:
                f.write(test_data)

            for algorithm in algorithms:
                encrypted_file = os.path.join(self.temp_dir, f"algo_{algorithm}_enc.bin")

                config_dict = {
                    "algorithm": algorithm,
                    "hash_algorithm": config.get("hash_algorithm", "SHA256"),
                }

                # Measure timing consistency for this algorithm
                timings = []
                for i in range(7):  # More measurements for better statistics
                    if os.path.exists(encrypted_file):
                        os.remove(encrypted_file)

                    timing = self._measure_operation_timing(
                        encrypt_file, input_file, encrypted_file, "algo_test_password", config_dict
                    )
                    if timing > 0:
                        timings.append(timing)

                if timings and len(timings) >= 3:
                    analysis = self.analyzer.analyze_timing_consistency(timings, algorithm)
                    algorithm_results[algorithm] = analysis

            if not algorithm_results:
                return TestResult(
                    "algorithm_timing_consistency",
                    TestResultLevel.WARNING,
                    "No algorithms could be tested for consistency",
                )

            # Check which algorithms show good timing consistency
            consistent_algorithms = []
            inconsistent_algorithms = []

            for algo, analysis in algorithm_results.items():
                if analysis.get("timing_consistent", False):
                    consistent_algorithms.append(algo)
                else:
                    inconsistent_algorithms.append(algo)

            if len(inconsistent_algorithms) == 0:
                level = TestResultLevel.PASS
                message = f"All {len(consistent_algorithms)} algorithms show consistent timing"
            elif len(inconsistent_algorithms) < len(consistent_algorithms):
                level = TestResultLevel.WARNING
                message = f"{len(consistent_algorithms)} consistent, {len(inconsistent_algorithms)} inconsistent algorithms"
            else:
                level = TestResultLevel.ERROR
                message = (
                    f"Most algorithms ({len(inconsistent_algorithms)}) show timing inconsistencies"
                )

            return TestResult(
                "algorithm_timing_consistency",
                level,
                message,
                details={
                    "algorithm_analysis": algorithm_results,
                    "consistent_algorithms": consistent_algorithms,
                    "inconsistent_algorithms": inconsistent_algorithms,
                },
            )

        except Exception as e:
            return TestResult(
                "algorithm_timing_consistency",
                TestResultLevel.ERROR,
                f"Error during algorithm consistency test: {str(e)}",
                exception=e,
            )
