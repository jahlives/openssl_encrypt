"""Error correction modules for steganography."""

from .reed_solomon import (
    AdaptiveErrorCorrection,
    BlockEncoder,
    ErrorCorrectionError,
    GaloisField,
    ReedSolomonDecoder,
    ReedSolomonEncoder,
)
from .simple import AdaptiveSimpleErrorCorrection, HammingEncoder, SimpleRepetitionEncoder

__all__ = [
    # Reed-Solomon classes
    "ReedSolomonEncoder",
    "ReedSolomonDecoder",
    "GaloisField",
    "BlockEncoder",
    "AdaptiveErrorCorrection",
    # Simple error correction classes
    "SimpleRepetitionEncoder",
    "HammingEncoder",
    "AdaptiveSimpleErrorCorrection",
    # Exceptions
    "ErrorCorrectionError",
]
