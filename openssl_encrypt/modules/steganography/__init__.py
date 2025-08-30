#!/usr/bin/env python3
"""
Steganography Module for OpenSSL Encrypt

This module provides steganographic capabilities to hide encrypted data
within cover media files (images, audio, etc.), adding an additional
layer of plausible deniability to the encryption system.

Key Features:
- LSB (Least Significant Bit) steganography for images
- Adaptive hiding based on media content analysis
- Integration with existing OpenSSL Encrypt cryptographic pipeline
- Security analysis and capacity calculation
- Steganalysis resistance techniques

Supported Cover Media:
- PNG images (lossless, recommended)
- BMP images (uncompressed, testing)
- JPEG images (DCT-based, new in v1.3.0)
- TIFF images (LZW/PackBits/uncompressed support, new in v1.3.0)
- WEBP images (lossless/lossy support, new in v1.3.0)
- WAV audio files (uncompressed PCM, new in v1.3.0)
- FLAC audio files (lossless compression, new in v1.3.0)
- MP3 audio files (lossy compression with DCT coefficients, new in v1.3.0)
- Future: GIF, additional audio formats

Security Architecture:
- Cover media → Steganographic hiding → Additional security layers
- Key-based pixel/sample selection for enhanced security
- Plausible deniability through decoy data injection
- Statistical analysis resistance
"""

from .stego_core import (
    SteganographyBase,
    SteganographyError,
    CapacityError,
    ExtractionError,
    CoverMediaError,
)
from .stego_image import (
    ImageSteganography,
    LSBImageStego,
    AdaptiveLSBStego,
)
from .stego_jpeg import (
    JPEGSteganography,
    JPEGSteganalysisResistance,
)
from .jpeg_utils import (
    JPEGAnalyzer,
    DCTUtils,
    create_jpeg_test_image,
    is_jpeg_steganography_available,
)
from .stego_tiff import (
    TIFFSteganography,
    TIFFAnalyzer,
    create_tiff_test_image,
    is_tiff_steganography_available,
)
from .stego_webp import (
    WEBPSteganography,
    WEBPAnalyzer,
    create_webp_test_image,
    is_webp_steganography_available,
)
from .stego_wav import (
    WAVSteganography,
    WAVAnalyzer,
    create_wav_test_audio,
    is_wav_steganography_available,
)
from .stego_flac import (
    FLACSteganography,
    FLACAnalyzer,
    create_flac_test_audio,
    is_flac_steganography_available,
)
from .stego_mp3 import (
    MP3Steganography,
    MP3Analyzer,
    create_mp3_test_audio,
    is_mp3_steganography_available,
)
from .stego_analysis import (
    CapacityAnalyzer,
    SecurityAnalyzer,
    SteganalysisResistance,
)
from .stego_transport import (
    SteganographyTransport,
    create_steganography_transport,
    is_steganography_available,
)

__version__ = "1.3.0"
__author__ = "OpenSSL Encrypt Team"

# Export main classes and functions
__all__ = [
    # Core classes
    'SteganographyBase',
    'ImageSteganography',
    'LSBImageStego',
    'AdaptiveLSBStego',
    'JPEGSteganography',
    'TIFFSteganography',
    'WEBPSteganography',
    'WAVSteganography',
    'FLACSteganography',
    'MP3Steganography',
    
    # Transport layer
    'SteganographyTransport',
    'create_steganography_transport',
    'is_steganography_available',
    'is_jpeg_steganography_available',
    'is_tiff_steganography_available',
    'is_webp_steganography_available',
    'is_wav_steganography_available',
    'is_flac_steganography_available',
    'is_mp3_steganography_available',
    
    # Analysis tools
    'CapacityAnalyzer',
    'SecurityAnalyzer',
    'SteganalysisResistance',
    'JPEGSteganalysisResistance',
    'JPEGAnalyzer',
    'DCTUtils',
    'TIFFAnalyzer',
    'WEBPAnalyzer',
    'WAVAnalyzer',
    'FLACAnalyzer',
    'MP3Analyzer',
    
    # Utilities
    'create_jpeg_test_image',
    'create_tiff_test_image',
    'create_webp_test_image',
    'create_wav_test_audio',
    'create_flac_test_audio',
    'create_mp3_test_audio',
    
    # Exceptions
    'SteganographyError',
    'CapacityError',
    'ExtractionError',
    'CoverMediaError',
]

# Module-level constants
SUPPORTED_IMAGE_FORMATS = ['PNG', 'BMP', 'JPEG', 'JPG', 'TIFF', 'TIF', 'WEBP']
SUPPORTED_AUDIO_FORMATS = ['WAV', 'FLAC', 'MP3']
FUTURE_FORMATS = ['GIF', 'FLAC', 'MP3']
EOF_MARKER = b'\xFF\xFF\xFF\xFE'  # Steganography end-of-file marker
MIN_COVER_SIZE = 1024  # Minimum pixels required for hiding