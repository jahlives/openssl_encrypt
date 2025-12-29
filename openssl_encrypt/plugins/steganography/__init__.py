"""
Steganography Plugin for OpenSSL Encrypt

This plugin provides steganography capabilities for hiding encrypted data
within various media formats including images (PNG, JPEG, TIFF, WEBP) and
audio files (WAV, FLAC, MP3).

Features:
- Multiple embedding methods (LSB, DCT, adaptive)
- Error correction (Reed-Solomon, Hamming codes)
- Capacity and security analysis
- Format-specific optimizations

Security:
- Only works with encrypted data
- No access to encryption keys or plaintext
- Sandboxed execution with whitelisted dependencies
"""

# Export core components for backward compatibility and testing
from .core import (
    CapacityError,
    CoverMediaError,
    SteganographyBase,
    SteganographyConfig,
    SteganographyError,
    SteganographyUtils,
)

# Export error correction
from .error_correction import (
    AdaptiveErrorCorrection,
    AdaptiveSimpleErrorCorrection,
    ReedSolomonDecoder,
    ReedSolomonEncoder,
)

# Export format handlers
from .formats import (
    AdaptiveLSBStego,
    FLACSteganography,
    ImageSteganography,
    JPEGSteganography,
    LSBImageStego,
    MP3Steganography,
    TIFFSteganography,
    WAVSteganography,
    WEBPSteganography,
)

# Export analyzer classes
from .formats.flac import FLACAnalyzer, create_flac_test_audio, is_flac_steganography_available
from .formats.jpeg_utils import (
    JPEGAnalyzer,
    create_jpeg_test_image,
    is_jpeg_steganography_available,
)
from .formats.mp3 import MP3Analyzer, create_mp3_test_audio, is_mp3_steganography_available
from .formats.tiff import TIFFAnalyzer, create_tiff_test_image, is_tiff_steganography_available
from .formats.wav import WAVAnalyzer, create_wav_test_audio, is_wav_steganography_available
from .formats.webp import WEBPAnalyzer, create_webp_test_image, is_webp_steganography_available
from .stego_plugin import SteganographyPlugin, plugin_instance

# Export transport layer
from .transport import SteganographyTransport, create_steganography_transport

__all__ = [
    # Plugin interface
    "SteganographyPlugin",
    "plugin_instance",
    # Core components
    "SteganographyBase",
    "SteganographyConfig",
    "SteganographyUtils",
    "SteganographyError",
    "CapacityError",
    "CoverMediaError",
    # Format handlers
    "ImageSteganography",
    "LSBImageStego",
    "AdaptiveLSBStego",
    "JPEGSteganography",
    "TIFFSteganography",
    "WEBPSteganography",
    "WAVSteganography",
    "FLACSteganography",
    "MP3Steganography",
    # Analyzers
    "JPEGAnalyzer",
    "TIFFAnalyzer",
    "WEBPAnalyzer",
    "WAVAnalyzer",
    "FLACAnalyzer",
    "MP3Analyzer",
    # Test helpers
    "create_jpeg_test_image",
    "create_tiff_test_image",
    "create_webp_test_image",
    "create_wav_test_audio",
    "create_flac_test_audio",
    "create_mp3_test_audio",
    # Availability checks
    "is_jpeg_steganography_available",
    "is_tiff_steganography_available",
    "is_webp_steganography_available",
    "is_wav_steganography_available",
    "is_flac_steganography_available",
    "is_mp3_steganography_available",
    # Transport
    "SteganographyTransport",
    "create_steganography_transport",
    # Error correction
    "ReedSolomonEncoder",
    "ReedSolomonDecoder",
    "AdaptiveErrorCorrection",
    "AdaptiveSimpleErrorCorrection",
]
