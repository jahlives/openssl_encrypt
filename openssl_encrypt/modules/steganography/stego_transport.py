#!/usr/bin/env python3
"""
Steganography Transport Layer

This module provides a simple transport interface for integrating steganography
with the existing encrypt/decrypt workflow. It acts as a transport layer that
can replace file I/O operations.
"""

import logging
import os
from typing import Optional

# Import secure memory functions for handling sensitive data
try:
    from ..secure_memory import SecureBytes, secure_memzero
except ImportError:
    # Fallback for standalone testing
    from openssl_encrypt.modules.secure_memory import SecureBytes, secure_memzero

from .stego_core import CapacityError, CoverMediaError, SteganographyConfig, SteganographyError
from .stego_flac import FLACSteganography
from .stego_image import AdaptiveLSBStego, LSBImageStego
from .stego_jpeg import JPEGSteganography
from .stego_mp3 import MP3Steganography
from .stego_tiff import TIFFSteganography
from .stego_wav import WAVSteganography
from .stego_webp import WEBPSteganography



# Set up module logger
logger = logging.getLogger(__name__)


class SteganographyTransport:
    """
    Simple transport layer for steganography operations

    This class provides a clean interface for hiding encrypted data in images
    and extracting it back, without the steganography code needing to know
    about encryption details.
    """

    def __init__(
        self,
        method: str = "lsb",
        bits_per_channel: int = 1,
        password: Optional[str] = None,
        **options,
    ):
        """
        Initialize steganography transport

        Args:
            method: Steganographic method ('lsb', 'adaptive', 'f5', 'outguess')
            bits_per_channel: LSB bits per color channel (1-3) for non-JPEG/TIFF methods
            password: Optional password for pixel randomization
            **options: Additional steganography options
        """
        self.method = method
        self.bits_per_channel = bits_per_channel
        self.password = password
        self.options = options

        # Create configuration
        self.config = SteganographyConfig()
        self.config.randomize_pixel_order = options.get("randomize_pixels", False)
        self.config.enable_decoy_data = options.get("decoy_data", False)
        self.config.preserve_statistics = options.get("preserve_stats", True)
        self.config.max_bits_per_sample = bits_per_channel

        # Steganography instance will be created dynamically based on image format
        self.stego = None

    def _detect_media_format(self, media_data: bytes) -> str:
        """Detect media format from data (images and audio)"""


        # Image formats
        if media_data.startswith(b"\xFF\xD8\xFF"):
            return "JPEG"
        elif media_data.startswith(b"\x89PNG"):
            return "PNG"
        elif media_data.startswith(b"BM"):
            return "BMP"
        elif media_data.startswith((b"II*\x00", b"MM\x00*")):
            return "TIFF"
        elif media_data.startswith(b"RIFF") and media_data[8:12] == b"WEBP":
            return "WEBP"
        # Audio formats
        elif media_data.startswith(b"RIFF") and media_data[8:12] == b"WAVE":
            return "WAV"
        elif media_data.startswith(b"fLaC"):
            return "FLAC"
        elif len(media_data) >= 4 and media_data[0] == 0xFF and (media_data[1] & 0xE0) == 0xE0:
            # MP3 frame sync pattern (11111111 111xxxxx)
            return "MP3"
        elif media_data.startswith(b"ID3"):
            # MP3 with ID3v2 tag
            return "MP3"
        else:
            # Try to detect via PIL for images
            try:
                import io

                from PIL import Image

                image = Image.open(io.BytesIO(media_data))
                detected_format = image.format or "UNKNOWN"
                # Block disabled formats
                if detected_format == "WEBP":
                    return "UNKNOWN"  # WEBP is disabled
                return detected_format
            except Exception:
                return "UNKNOWN"

    def _create_stego_instance(self, media_format: str):
        """Create appropriate steganography instance based on format"""
        if media_format in ["JPEG", "JPG"]:
            # JPEG methods
            if self.method in ["f5", "outguess"]:
                self.stego = JPEGSteganography(
                    password=self.password,
                    security_level=2,
                    quality_factor=self.options.get("jpeg_quality", 85),
                    dct_method=self.method,
                    config=self.config,
                )
            else:
                # Default to basic JPEG method for lsb/adaptive
                self.stego = JPEGSteganography(
                    password=self.password,
                    security_level=1,
                    quality_factor=self.options.get("jpeg_quality", 85),
                    dct_method="basic",
                    config=self.config,
                )
        elif media_format in ["TIFF", "TIF"]:
            # TIFF methods
            self.stego = TIFFSteganography(
                password=self.password,
                security_level=2 if self.method == "adaptive" else 1,
                bits_per_channel=self.bits_per_channel,
                config=self.config,
            )
        elif media_format == "WEBP":
            # WEBP methods (fixed in v1.3.0)
            self.stego = WEBPSteganography(
                password=self.password,
                security_level=2 if self.method == "adaptive" else 1,
                bits_per_channel=self.bits_per_channel,
                force_lossless=self.options.get(
                    "force_lossless", True
                ),  # Recommended for reliability
                config=self.config,
            )
        elif media_format == "WAV":
            # WAV audio methods
            self.stego = WAVSteganography(
                password=self.password,
                security_level=2 if self.method == "adaptive" else 1,
                bits_per_sample=self.options.get("bits_per_sample", self.bits_per_channel),
                config=self.config,
            )
        elif media_format == "FLAC":
            # FLAC audio methods
            self.stego = FLACSteganography(
                password=self.password,
                security_level=2,
                bits_per_sample=self.options.get("bits_per_sample", self.bits_per_channel),
                config=self.config,
            )
        elif media_format == "MP3":
            # MP3 audio methods
            self.stego = MP3Steganography(
                password=self.password,
                security_level=2,
                coefficient_bits=self.options.get("coefficient_bits", self.bits_per_channel),
                use_bit_reservoir=self.options.get("use_bit_reservoir", True),
                preserve_quality=self.options.get("preserve_quality", True),
                config=self.config,
            )
        else:
            # PNG/BMP methods (existing)
            if self.method == "adaptive":
                self.stego = AdaptiveLSBStego(
                    password=self.password, security_level=2, config=self.config
                )
            else:
                self.stego = LSBImageStego(
                    password=self.password,
                    security_level=1,
                    bits_per_channel=self.bits_per_channel,
                    config=self.config,
                )

    def hide_data_in_media(
        self, encrypted_data: bytes, cover_media_path: str, output_media_path: str
    ) -> None:
        """
        Hide encrypted data in cover media (image or audio)

        Args:
            encrypted_data: Already encrypted data to hide
            cover_media_path: Path to cover media file (image or audio)
            output_media_path: Path for output steganographic media

        Raises:
            CoverMediaError: If cover media is invalid or unsupported
            CapacityError: If data doesn't fit in media
            SteganographyError: If hiding operation fails
        """
        try:
            # Validate cover media exists
            if not os.path.exists(cover_media_path):
                raise CoverMediaError(f"Cover media not found: {cover_media_path}")

            # Read cover media
            with open(cover_media_path, "rb") as f:
                cover_data = f.read()

            # Detect media format and create appropriate steganography instance
            media_format = self._detect_media_format(cover_data)
            if media_format == "UNKNOWN":
                raise CoverMediaError(f"Unsupported media format in: {cover_media_path}")

            self._create_stego_instance(media_format)

            # Standard image/audio handling
            # Check capacity
            capacity = self.stego.calculate_capacity(cover_data)
            if len(encrypted_data) > capacity:
                raise CapacityError(len(encrypted_data), capacity, f"{media_format} media")

            # Hide data
            stego_data = self.stego.hide_data(cover_data, encrypted_data)

            # Write output
            with open(output_media_path, "wb") as f:
                f.write(stego_data)

        except Exception as e:
            if isinstance(e, (SteganographyError, CoverMediaError, CapacityError)):
                raise
            raise SteganographyError(f"Failed to hide data in media: {e}")

    def extract_data_from_media(self, stego_media_path: str) -> bytes:
        """
        Extract encrypted data from steganographic media (image or audio)

        Args:
            stego_media_path: Path to steganographic media file

        Returns:
            Extracted encrypted data

        Raises:
            CoverMediaError: If media file is invalid or unsupported
            SteganographyError: If extraction fails
        """
        try:
            # Validate media exists
            if not os.path.exists(stego_media_path):
                raise CoverMediaError(f"Steganographic media not found: {stego_media_path}")

            # Read media
            with open(stego_media_path, "rb") as f:
                stego_data = f.read()

            # Detect media format and create appropriate steganography instance
            media_format = self._detect_media_format(stego_data)
            if media_format == "UNKNOWN":
                raise CoverMediaError(f"Unsupported media format in: {stego_media_path}")

            self._create_stego_instance(media_format)

            # Standard image/audio handling
            # Extract data
            encrypted_data = self.stego.extract_data(stego_data)

            return encrypted_data

        except Exception as e:
            if isinstance(e, (SteganographyError, CoverMediaError)):
                raise
            raise SteganographyError(f"Failed to extract data from media: {e}")

    # Backward compatibility methods
    def hide_data_in_image(
        self, encrypted_data: bytes, cover_image_path: str, output_image_path: str
    ) -> None:
        """Backward compatibility method for hide_data_in_media"""
        return self.hide_data_in_media(encrypted_data, cover_image_path, output_image_path)

    def extract_data_from_image(self, stego_image_path: str) -> bytes:
        """Backward compatibility method for extract_data_from_media"""
        return self.extract_data_from_media(stego_image_path)

    def get_capacity(self, cover_media_path: str) -> int:
        """
        Get hiding capacity for cover media (image or audio)

        Args:
            cover_media_path: Path to cover media file

        Returns:
            Maximum bytes that can be hidden
        """
        with open(cover_media_path, "rb") as f:
            cover_data = f.read()

        # Detect format and create instance if needed
        media_format = self._detect_media_format(cover_data)
        if media_format == "UNKNOWN":
            raise CoverMediaError(f"Unsupported media format: {cover_media_path}")

        self._create_stego_instance(media_format)

        return self.stego.calculate_capacity(cover_data)


def create_steganography_transport(args) -> Optional[SteganographyTransport]:
    """
    Create steganography transport from CLI arguments

    Args:
        args: Parsed CLI arguments

    Returns:
        SteganographyTransport instance or None if not using steganography
    """
    # Check if steganography is requested
    stego_hide = getattr(args, "stego_hide", None)
    stego_extract = getattr(args, "stego_extract", False)

    if not stego_hide and not stego_extract:
        return None

    try:
        # Extract steganography options
        method = getattr(args, "stego_method", "lsb")
        bits_per_channel = getattr(args, "stego_bits_per_channel", 1)

        # Use dedicated steganography password for security
        stego_password = getattr(args, "stego_password", None)

        options = {
            "randomize_pixels": getattr(args, "stego_randomize_pixels", False),
            "decoy_data": getattr(args, "stego_decoy_data", False),
            "preserve_stats": True,
            # JPEG-specific options
            "jpeg_quality": getattr(args, "jpeg_quality", 85),
        }

        return SteganographyTransport(
            method=method, bits_per_channel=bits_per_channel, password=stego_password, **options
        )

    except ImportError as e:
        logger.error(f"Steganography dependencies not available: {e}")
        raise SteganographyError(
            "Steganography requires additional dependencies. "
            "Install with: pip install Pillow numpy"
        )


def is_steganography_available() -> bool:
    """Check if steganography dependencies are available"""
    try:
        import numpy as np
        from PIL import Image

        return True
    except ImportError:
        return False
