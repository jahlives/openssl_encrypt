"""
Base classes and common utilities for the Advanced Testing Framework.

Provides foundation classes and data structures used across all test suites.
"""

import logging
import time
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class TestResultLevel(Enum):
    """Test result severity levels."""

    PASS = "pass"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class TestResult:
    """Represents the result of a security test."""

    test_name: str
    level: TestResultLevel
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    duration: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    exception: Optional[Exception] = None

    def is_success(self) -> bool:
        """Check if test result indicates success."""
        return self.level == TestResultLevel.PASS

    def is_failure(self) -> bool:
        """Check if test result indicates failure."""
        return self.level in [TestResultLevel.ERROR, TestResultLevel.CRITICAL]

    def to_dict(self) -> Dict[str, Any]:
        """Convert test result to dictionary for serialization."""
        result = {
            "test_name": self.test_name,
            "level": self.level.value,
            "message": self.message,
            "details": self.details,
            "duration": self.duration,
            "timestamp": self.timestamp.isoformat(),
        }
        if self.exception:
            result["exception"] = {
                "type": type(self.exception).__name__,
                "message": str(self.exception),
                "traceback": traceback.format_exception(
                    type(self.exception), self.exception, self.exception.__traceback__
                ),
            }
        return result


class BaseSecurityTest(ABC):
    """Abstract base class for all security tests."""

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.logger = logging.getLogger(f"security_test.{name}")
        self.results: List[TestResult] = []

    @abstractmethod
    def run_tests(self, **kwargs) -> List[TestResult]:
        """
        Run all tests in this suite.

        Args:
            **kwargs: Test-specific configuration parameters

        Returns:
            List of TestResult objects
        """
        pass

    def run_single_test(self, test_func, test_name: str, *args, **kwargs) -> TestResult:
        """
        Execute a single test function with timing and exception handling.

        Args:
            test_func: Function to execute
            test_name: Name of the test
            *args: Arguments to pass to test function
            **kwargs: Keyword arguments to pass to test function

        Returns:
            TestResult object
        """
        start_time = time.time()

        try:
            result = test_func(*args, **kwargs)
            duration = time.time() - start_time

            if isinstance(result, TestResult):
                result.duration = duration
                return result
            elif isinstance(result, bool):
                level = TestResultLevel.PASS if result else TestResultLevel.ERROR
                message = f"Test {'passed' if result else 'failed'}"
                return TestResult(test_name, level, message, duration=duration)
            else:
                return TestResult(
                    test_name,
                    TestResultLevel.PASS,
                    f"Test completed successfully: {result}",
                    duration=duration,
                    details={"result": result},
                )

        except Exception as e:
            duration = time.time() - start_time
            self.logger.error(f"Test {test_name} failed with exception: {e}")
            return TestResult(
                test_name,
                TestResultLevel.CRITICAL,
                f"Test failed with exception: {str(e)}",
                duration=duration,
                exception=e,
            )

    def add_result(self, result: TestResult) -> None:
        """Add a test result to the suite."""
        self.results.append(result)

        # Log the result
        if result.level == TestResultLevel.PASS:
            self.logger.info(f"✓ {result.test_name}: {result.message}")
        elif result.level == TestResultLevel.INFO:
            self.logger.info(f"ℹ {result.test_name}: {result.message}")
        elif result.level == TestResultLevel.WARNING:
            self.logger.warning(f"⚠ {result.test_name}: {result.message}")
        elif result.level == TestResultLevel.ERROR:
            self.logger.error(f"✗ {result.test_name}: {result.message}")
        elif result.level == TestResultLevel.CRITICAL:
            self.logger.critical(f"🔥 {result.test_name}: {result.message}")

    def get_results(self) -> List[TestResult]:
        """Get all test results."""
        return self.results.copy()

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of test results."""
        total = len(self.results)
        pass_count = sum(1 for r in self.results if r.level == TestResultLevel.PASS)
        warning_count = sum(1 for r in self.results if r.level == TestResultLevel.WARNING)
        error_count = sum(
            1 for r in self.results if r.level in [TestResultLevel.ERROR, TestResultLevel.CRITICAL]
        )

        total_duration = sum(r.duration for r in self.results)

        return {
            "test_suite": self.name,
            "description": self.description,
            "total_tests": total,
            "passed": pass_count,
            "warnings": warning_count,
            "errors": error_count,
            "success_rate": (pass_count / total * 100) if total > 0 else 0,
            "total_duration": total_duration,
            "average_duration": total_duration / total if total > 0 else 0,
        }

    def clear_results(self) -> None:
        """Clear all test results."""
        self.results.clear()


class TestConfig:
    """Configuration class for test parameters."""

    def __init__(self, **kwargs):
        self.config = kwargs

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self.config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set configuration value."""
        self.config[key] = value

    def update(self, **kwargs) -> None:
        """Update configuration with new values."""
        self.config.update(kwargs)


class SecurityTestException(Exception):
    """Base exception for security testing framework."""

    pass


class TestConfigurationError(SecurityTestException):
    """Exception raised for invalid test configuration."""

    pass


class TestExecutionError(SecurityTestException):
    """Exception raised during test execution."""

    pass
