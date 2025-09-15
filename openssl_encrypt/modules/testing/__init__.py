"""
Advanced Testing Framework for OpenSSL Encrypt Library.

This module provides comprehensive security testing capabilities including:
- Fuzzing tests for input boundary conditions
- Side-channel resistance testing 
- Known-Answer Tests (KAT) with NIST test vectors
- Performance benchmarking and regression detection
- Memory safety testing
- Unified test orchestration and reporting

All components include comprehensive unit test coverage.
"""

from .base_test import BaseSecurityTest, TestResult, TestResultLevel
from .fuzz_testing import FuzzTestSuite
from .side_channel_tests import SideChannelTestSuite
from .kat_tests import KATTestSuite
from .benchmark_suite import BenchmarkTestSuite
from .memory_tests import MemoryTestSuite
from .test_runner import SecurityTestRunner, TestExecutionPlan, TestSuiteType

__all__ = [
    'BaseSecurityTest', 'TestResult', 'TestResultLevel',
    'FuzzTestSuite', 'SideChannelTestSuite', 'KATTestSuite',
    'BenchmarkTestSuite', 'MemoryTestSuite', 'SecurityTestRunner',
    'TestExecutionPlan', 'TestSuiteType'
]

VERSION = "1.0.0"