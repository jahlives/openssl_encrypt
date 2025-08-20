#!/usr/bin/env python3
"""
Algorithm Deprecation Warning System

This module provides centralized management of cryptographic algorithm deprecation
warnings. It includes configuration options, warning levels, and utilities for
issuing appropriate deprecation warnings to users.
"""

import datetime
import logging
import warnings
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Union

# Configure logger
logger = logging.getLogger(__name__)


class DeprecationLevel(Enum):
    """Defines the severity levels for algorithm deprecation warnings."""

    INFO = 0  # Algorithm will be deprecated in the future, but is still safe to use now
    WARNING = 1  # Algorithm should be migrated soon, with minor security concerns
    DEPRECATED = 2  # Algorithm is officially deprecated, migration should be prioritized
    UNSAFE = 3  # Algorithm has known security vulnerabilities, immediate migration required


class AlgorithmWarningConfig:
    """Configuration for the algorithm warning system."""

    # Controls whether to show warnings
    _show_warnings = True

    # Controls the minimum level to display
    _min_warning_level = DeprecationLevel.INFO

    # Controls whether to log warnings
    _log_warnings = True

    # Controls whether to show warnings only once per algorithm
    _show_once = True

    # Controls whether we're in verbose mode
    _verbose_mode = False

    # Track which warnings have been shown
    _warned_algorithms: Set[str] = set()

    @classmethod
    def configure(
        cls,
        show_warnings: bool = True,
        min_level: DeprecationLevel = DeprecationLevel.INFO,
        log_warnings: bool = True,
        show_once: bool = True,
        verbose_mode: bool = False,
    ) -> None:
        """
        Configure the warning system behavior.

        Args:
            show_warnings: Whether to display warnings to users
            min_level: Minimum warning level to display
            log_warnings: Whether to log warnings
            show_once: Whether to show each warning only once
            verbose_mode: Whether verbose output is enabled
        """
        cls._show_warnings = show_warnings
        cls._min_warning_level = min_level
        cls._log_warnings = log_warnings
        cls._show_once = show_once
        cls._verbose_mode = verbose_mode

    @classmethod
    def reset(cls) -> None:
        """Reset the warning system to default settings and clear warning history."""
        cls._show_warnings = True
        cls._min_warning_level = DeprecationLevel.INFO
        cls._log_warnings = True
        cls._show_once = True
        cls._verbose_mode = False
        cls._warned_algorithms.clear()

    @classmethod
    def should_warn(cls, algorithm: str, level: DeprecationLevel) -> bool:
        """
        Determine if a warning should be shown for an algorithm.

        Args:
            algorithm: Algorithm identifier
            level: Warning level for the algorithm

        Returns:
            bool: True if warning should be shown, False otherwise
        """
        # Check if warnings are enabled and level is sufficient
        if not cls._show_warnings or level.value < cls._min_warning_level.value:
            return False

        # Check if this algorithm has already been warned about
        if cls._show_once and algorithm in cls._warned_algorithms:
            return False

        return True

    @classmethod
    def mark_warned(cls, algorithm: str) -> None:
        """
        Mark an algorithm as having been warned about.

        Args:
            algorithm: Algorithm identifier
        """
        cls._warned_algorithms.add(algorithm)


# Registry of deprecated algorithms with their status and migration path
# Format: "algorithm_name": (level, replacement, message, removal_version, removal_date)
DEPRECATED_ALGORITHMS: Dict[
    str, Tuple[DeprecationLevel, str, str, str, Optional[datetime.date]]
] = {
    # Symmetric encryption algorithms
    "camellia": (
        DeprecationLevel.DEPRECATED,
        "aes-gcm or chacha20-poly1305",
        "Camellia is not a NIST-recommended algorithm and has limited adoption. Support for new encryption will be removed, but decryption of existing files will continue to work.",
        "1.2.0",
        datetime.date(2026, 1, 1),
    ),
    "aes-ocb3": (
        DeprecationLevel.WARNING,
        "aes-gcm or aes-gcm-siv",
        "AES-OCB3 has security concerns with short nonces. Use AES-GCM or AES-GCM-SIV instead. Support for new encryption will be removed, but decryption of existing files will continue to work.",
        "1.2.0",
        datetime.date(2026, 1, 1),
    ),
    # Post-quantum cryptography algorithms (legacy names)
    "kyber512-hybrid": (
        DeprecationLevel.INFO,
        "ml-kem-512-hybrid",
        "Kyber naming is deprecated in favor of NIST standardized ML-KEM naming. Support for new encryption will be removed, but decryption of existing files will continue to work.",
        "1.2.0",
        datetime.date(2026, 1, 1),
    ),
    "kyber768-hybrid": (
        DeprecationLevel.INFO,
        "ml-kem-768-hybrid",
        "Kyber naming is deprecated in favor of NIST standardized ML-KEM naming. Support for new encryption will be removed, but decryption of existing files will continue to work.",
        "1.2.0",
        datetime.date(2026, 1, 1),
    ),
    "kyber1024-hybrid": (
        DeprecationLevel.INFO,
        "ml-kem-1024-hybrid",
        "Kyber naming is deprecated in favor of NIST standardized ML-KEM naming. Support for new encryption will be removed, but decryption of existing files will continue to work.",
        "1.2.0",
        datetime.date(2026, 1, 1),
    ),
    "Kyber512": (
        DeprecationLevel.INFO,
        "ML-KEM-512",
        "Kyber naming is deprecated in favor of NIST standardized ML-KEM naming. Support for new encryption will be removed, but decryption of existing files will continue to work.",
        "1.2.0",
        datetime.date(2026, 1, 1),
    ),
    "Kyber768": (
        DeprecationLevel.INFO,
        "ML-KEM-768",
        "Kyber naming is deprecated in favor of NIST standardized ML-KEM naming. Support for new encryption will be removed, but decryption of existing files will continue to work.",
        "1.2.0",
        datetime.date(2026, 1, 1),
    ),
    "Kyber1024": (
        DeprecationLevel.INFO,
        "ML-KEM-1024",
        "Kyber naming is deprecated in favor of NIST standardized ML-KEM naming. Support for new encryption will be removed, but decryption of existing files will continue to work.",
        "1.2.0",
        datetime.date(2026, 1, 1),
    ),
    # Hash functions
    "whirlpool": (
        DeprecationLevel.WARNING,
        "sha3-512 or blake2b",
        "Whirlpool has limited adoption and maintenance challenges. Use SHA3-512 or BLAKE2b instead. Support for new encryption will be removed, but decryption of existing files will continue to work.",
        "1.2.0",
        datetime.date(2026, 1, 1),
    ),
    # Key derivation functions
    "pbkdf2": (
        DeprecationLevel.WARNING,
        "argon2id or scrypt",
        "PBKDF2 is not memory-hard. Use Argon2id or Scrypt for stronger password hashing. Support for new encryption will be removed, but decryption of existing files will continue to work.",
        "1.2.0",
        datetime.date(2026, 1, 1),
    ),
}


def warn_deprecated_algorithm(
    algorithm: str, context: Optional[str] = None, show_stack: bool = False
) -> None:
    """
    Issue a deprecation warning for a specified algorithm.

    Args:
        algorithm: The algorithm identifier
        context: Optional context information about where the algorithm is being used
        show_stack: Whether to include stack trace information in the warning
    """
    # Normalize algorithm name to lowercase for comparison
    normalized_algorithm = algorithm.lower().replace("-", "").replace("_", "")

    # Check alternative algorithm names (e.g., different formatting)
    algorithm_info = None
    for alg_name, info in DEPRECATED_ALGORITHMS.items():
        normalized_name = alg_name.lower().replace("-", "").replace("_", "")
        if normalized_algorithm == normalized_name:
            algorithm_info = info
            break

    # If algorithm not found in registry, return without warning
    if not algorithm_info:
        return

    level, replacement, message, removal_version, removal_date = algorithm_info

    # Check if warning should be shown based on configuration
    if not AlgorithmWarningConfig.should_warn(algorithm, level):
        return

    # Construct warning message
    today = datetime.date.today()
    date_info = ""
    if removal_date:
        days_remaining = (removal_date - today).days
        if days_remaining > 0:
            date_info = (
                f" and will be removed in {days_remaining} days (on {removal_date.isoformat()})"
            )
        else:
            date_info = f" and was scheduled for removal on {removal_date.isoformat()}"

    context_info = f" in {context}" if context else ""
    warning_msg = (
        f"Algorithm '{algorithm}'{context_info} is {level.name.lower()}. {message} "
        f"It will be removed in version {removal_version}{date_info}. "
        f"Please migrate to {replacement}."
    )

    # Issue warning - only use Python warnings for non-INFO warnings or when in verbose mode
    if AlgorithmWarningConfig._show_warnings and (
        level != DeprecationLevel.INFO or AlgorithmWarningConfig._verbose_mode
    ):
        category = {
            DeprecationLevel.INFO: UserWarning,
            DeprecationLevel.WARNING: DeprecationWarning,
            DeprecationLevel.DEPRECATED: DeprecationWarning,
            DeprecationLevel.UNSAFE: FutureWarning,
        }.get(level, DeprecationWarning)

        warnings.warn(warning_msg, category=category, stacklevel=2 if show_stack else 1)

    # Log warning - always log, but use DEBUG level for INFO-level warnings when not in verbose mode
    if AlgorithmWarningConfig._log_warnings:
        # If it's an INFO level warning and we're not in verbose mode, use DEBUG instead
        log_level = {
            DeprecationLevel.INFO: (
                logging.DEBUG if not AlgorithmWarningConfig._verbose_mode else logging.INFO
            ),
            DeprecationLevel.WARNING: logging.WARNING,
            DeprecationLevel.DEPRECATED: logging.WARNING,
            DeprecationLevel.UNSAFE: logging.ERROR,
        }.get(level, logging.WARNING)

        logger.log(log_level, warning_msg)

    # Mark algorithm as warned about
    AlgorithmWarningConfig.mark_warned(algorithm)


def is_deprecated(algorithm: str) -> bool:
    """
    Check if an algorithm is marked as deprecated.

    Args:
        algorithm: The algorithm identifier

    Returns:
        bool: True if algorithm is deprecated, False otherwise
    """
    # Normalize algorithm name to lowercase for comparison
    normalized_algorithm = algorithm.lower().replace("-", "").replace("_", "")

    # Check algorithm registry
    for alg_name in DEPRECATED_ALGORITHMS:
        normalized_name = alg_name.lower().replace("-", "").replace("_", "")
        if normalized_algorithm == normalized_name:
            return True

    return False


def get_recommended_replacement(algorithm: str) -> Optional[str]:
    """
    Get the recommended replacement for a deprecated algorithm.

    Args:
        algorithm: The algorithm identifier

    Returns:
        str or None: Recommended replacement algorithm, or None if algorithm not deprecated
    """
    # Normalize algorithm name to lowercase for comparison
    normalized_algorithm = algorithm.lower().replace("-", "").replace("_", "")

    # Check algorithm registry
    for alg_name, info in DEPRECATED_ALGORITHMS.items():
        normalized_name = alg_name.lower().replace("-", "").replace("_", "")
        if normalized_algorithm == normalized_name:
            return info[1]  # replacement algorithm

    return None


def get_all_deprecated_algorithms() -> List[Tuple[str, DeprecationLevel, str]]:
    """
    Get a list of all deprecated algorithms with their level and replacement.

    Returns:
        List of tuples containing (algorithm, level, replacement)
    """
    return [(alg, info[0], info[1]) for alg, info in DEPRECATED_ALGORITHMS.items()]


def get_algorithms_by_level(level: DeprecationLevel) -> List[str]:
    """
    Get a list of all algorithms at or above a specific deprecation level.

    Args:
        level: Minimum deprecation level to include

    Returns:
        List of algorithm names
    """
    return [alg for alg, info in DEPRECATED_ALGORITHMS.items() if info[0].value >= level.value]
