#!/usr/bin/env python3
"""
Steganography Exception Classes

Exception hierarchy for steganographic operations.
"""


class SteganographyError(Exception):
    """Base exception for all steganography operations"""

    pass


class CapacityError(SteganographyError):
    """Raised when data exceeds cover media capacity"""

    def __init__(self, required: int, available: int, media_type: str = "unknown"):
        self.required = required
        self.available = available
        self.media_type = media_type
        super().__init__(
            f"Insufficient capacity in {media_type}: need {required} bytes, "
            f"only {available} bytes available"
        )


class ExtractionError(SteganographyError):
    """Raised when data cannot be extracted from cover media"""

    pass


class CoverMediaError(SteganographyError):
    """Raised when cover media is invalid or corrupted"""

    pass


class SecurityError(SteganographyError):
    """Raised when security constraints are violated"""

    pass
