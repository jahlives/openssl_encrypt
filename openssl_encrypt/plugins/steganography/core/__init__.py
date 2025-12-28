"""
Core steganography functionality.

This package contains the foundational classes and utilities for
steganographic operations.
"""

from .base import SteganographyBase
from .config import SteganographyConfig
from .exceptions import (
    CapacityError,
    CoverMediaError,
    ExtractionError,
    SecurityError,
    SteganographyError,
)
from .utils import SteganographyUtils

__all__ = [
    # Base classes
    "SteganographyBase",
    "SteganographyConfig",
    "SteganographyUtils",
    # Exceptions
    "SteganographyError",
    "CapacityError",
    "ExtractionError",
    "CoverMediaError",
    "SecurityError",
]
