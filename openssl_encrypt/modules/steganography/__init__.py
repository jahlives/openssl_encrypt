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

Currently Unsupported:
- Video formats (MP4, WEBM, AVI, MKV) - LSB incompatible with video compression
- GIF images - planned for future development

Video Steganography Limitations:
LSB steganography requires bit-perfect preservation of pixel data, which is
fundamentally incompatible with video compression. Even "lossless" video codecs
like H.264 with CRF=0 do not preserve LSB data due to color space conversions,
quantization, and encoding artifacts.

Future video steganography implementations may use:
- DCT-based frequency domain hiding
- Motion vector manipulation
- Container metadata embedding
- Temporal domain spreading techniques

Security Architecture:
- Cover media → Steganographic hiding → Additional security layers
- Key-based pixel/sample selection for enhanced security
- Plausible deniability through decoy data injection
- Statistical analysis resistance
"""

from .jpeg_utils import (
    DCTUtils,
    JPEGAnalyzer,
    create_jpeg_test_image,
    is_jpeg_steganography_available,
)
from .stego_analysis import CapacityAnalyzer, SecurityAnalyzer, SteganalysisResistance
from .stego_core import (
    CapacityError,
    CoverMediaError,
    ExtractionError,
    SteganographyBase,
    SteganographyConfig,
    SteganographyError,
    SteganographyUtils,
)
from .stego_flac import (
    FLACAnalyzer,
    FLACSteganography,
    create_flac_test_audio,
    is_flac_steganography_available,
)
from .stego_image import AdaptiveLSBStego, ImageSteganography, LSBImageStego
from .stego_jpeg import JPEGSteganalysisResistance, JPEGSteganography
from .stego_mp3 import (
    MP3Analyzer,
    MP3Steganography,
    create_mp3_test_audio,
    is_mp3_steganography_available,
)
from .stego_tiff import (
    TIFFAnalyzer,
    TIFFSteganography,
    create_tiff_test_image,
    is_tiff_steganography_available,
)
from .stego_transport import (
    SteganographyTransport,
    create_steganography_transport,
    is_steganography_available,
)
from .stego_wav import (
    WAVAnalyzer,
    WAVSteganography,
    create_wav_test_audio,
    is_wav_steganography_available,
)
from .stego_webp import (
    WEBPAnalyzer,
    WEBPSteganography,
    create_webp_test_image,
    is_webp_steganography_available,
)

# Video steganography disabled due to compression incompatibility issues
# The fundamental problem: Video codecs (even "lossless" ones) don't preserve LSB data
# LSB steganography requires bit-perfect preservation which video compression violates
# Future work: Implement DCT-based frequency domain steganography for video
try:
    from .stego_mp4 import MP4Steganography, create_mp4_test_video, is_mp4_steganography_available
    from .stego_video_core import (
        VideoFormatError,
        VideoSteganographyBase,
        is_video_steganography_available,
    )

    # Force disabled until compression issues are resolved
    VIDEO_STEGANOGRAPHY_AVAILABLE = False
except ImportError:
    # Video steganography dependencies not available
    VideoFormatError = None
    VideoSteganographyBase = None
    MP4Steganography = None
    is_video_steganography_available = lambda: False
    is_mp4_steganography_available = lambda: False
    create_mp4_test_video = None
    VIDEO_STEGANOGRAPHY_AVAILABLE = False

__version__ = "1.3.0"
__author__ = "OpenSSL Encrypt Team"

# Export main classes and functions
__all__ = [
    # Core classes
    "SteganographyBase",
    "ImageSteganography",
    "LSBImageStego",
    "AdaptiveLSBStego",
    "JPEGSteganography",
    "TIFFSteganography",
    "WEBPSteganography",
    "WAVSteganography",
    "FLACSteganography",
    "MP3Steganography",
    # Video steganography classes (new in v1.3.0)
    "VideoSteganographyBase",
    "MP4Steganography",
    # Transport layer
    "SteganographyTransport",
    "create_steganography_transport",
    "is_steganography_available",
    "is_jpeg_steganography_available",
    "is_tiff_steganography_available",
    "is_webp_steganography_available",
    "is_wav_steganography_available",
    "is_flac_steganography_available",
    "is_mp3_steganography_available",
    # Video steganography functions
    "is_video_steganography_available",
    "is_mp4_steganography_available",
    # Analysis tools
    "CapacityAnalyzer",
    "SecurityAnalyzer",
    "SteganalysisResistance",
    "JPEGSteganalysisResistance",
    "JPEGAnalyzer",
    "DCTUtils",
    "TIFFAnalyzer",
    "WEBPAnalyzer",
    "WAVAnalyzer",
    "FLACAnalyzer",
    "MP3Analyzer",
    # Utilities
    "SteganographyConfig",
    "SteganographyUtils",
    "create_jpeg_test_image",
    "create_tiff_test_image",
    "create_webp_test_image",
    "create_wav_test_audio",
    "create_flac_test_audio",
    "create_mp3_test_audio",
    # Video test utilities
    "create_mp4_test_video",
    # Exceptions
    "SteganographyError",
    "CapacityError",
    "ExtractionError",
    "CoverMediaError",
    "VideoFormatError",
]

# Module-level constants
# All formats are now working - WEBP and MP3 issues have been fixed
SUPPORTED_IMAGE_FORMATS = ["PNG", "BMP", "JPEG", "JPG", "TIFF", "TIF", "WEBP"]
SUPPORTED_AUDIO_FORMATS = ["WAV", "FLAC", "MP3"]
SUPPORTED_VIDEO_FORMATS = []  # Disabled due to compression incompatibility

# Disabled formats
DISABLED_IMAGE_FORMATS = []  # All image formats are working
DISABLED_AUDIO_FORMATS = []  # All audio formats are working
DISABLED_VIDEO_FORMATS = [
    "MP4",
    "WEBM",
    "AVI",
    "MKV",
]  # Disabled: LSB incompatible with video compression
FUTURE_FORMATS = ["GIF"]  # Planned formats for future development
EOF_MARKER = b"\xFF\xFF\xFF\xFE"  # Steganography end-of-file marker
MIN_COVER_SIZE = 1024  # Minimum pixels required for hiding
