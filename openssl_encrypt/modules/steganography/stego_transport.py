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
from .stego_video_core import VideoFormatError, is_video_steganography_available
from .stego_wav import WAVSteganography
from .stego_webp import WEBPSteganography

# Import video steganography classes
try:
    from .stego_video_mp4 import MP4VideoSteganography

    MP4_AVAILABLE = True
except ImportError:
    MP4_AVAILABLE = False
    MP4VideoSteganography = None

try:
    from .stego_webm import WebMSteganography

    WEBM_AVAILABLE = True
except ImportError:
    WEBM_AVAILABLE = False
    WebMSteganography = None

try:
    from .stego_avi import AVISteganography

    AVI_AVAILABLE = True
except ImportError:
    AVI_AVAILABLE = False
    AVISteganography = None

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
        """Detect media format from data (images, audio, and video)"""
        # Video formats (check first to avoid conflicts with audio/image)
        if len(media_data) >= 12:
            # MP4 format detection (ftyp box)
            if media_data[4:8] == b"ftyp" and (
                media_data[8:12] in [b"mp41", b"mp42", b"isom", b"avc1", b"dash"]
            ):
                return "MP4"
            # Alternative MP4 detection for some files
            elif media_data[4:12] == b"ftypmp41" or media_data[4:12] == b"ftypmp42":
                return "MP4"

        # WebM format detection (EBML signature)
        if media_data.startswith(b"\x1a\x45\xdf\xa3"):
            return "WEBM"

        # AVI format detection
        if media_data.startswith(b"RIFF") and len(media_data) >= 12 and media_data[8:12] == b"AVI ":
            return "AVI"

        # Matroska Video (MKV) - same EBML signature as WebM but different DocType
        if media_data.startswith(b"\x1a\x45\xdf\xa3") and b"matroska" in media_data[:100]:
            return "MKV"

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
        elif media_format == "MP4":
            # MP4 video steganography using DCT frequency domain embedding
            if not MP4_AVAILABLE or not is_video_steganography_available():
                raise VideoFormatError(
                    "MP4 video steganography is not available. Please ensure OpenCV is installed "
                    "and video dependencies are properly configured."
                )

            # Configure QIM algorithm based on method
            qim_algorithm = None
            if self.method == "adaptive":
                from .stego_qim_advanced import AdaptiveQIM

                qim_algorithm = AdaptiveQIM(
                    base_quantization_step=self.options.get("quantization_step", 8.0),
                    adaptation_factor=self.options.get("adaptation_factor", 1.2),
                )
            elif self.method == "distortion_comp":
                from .stego_qim_advanced import DistortionCompensatedQIM

                qim_algorithm = DistortionCompensatedQIM(
                    quantization_step=self.options.get("quantization_step", 8.0),
                    compensation_factor=self.options.get("compensation_factor", 0.5),
                )
            elif self.method == "multi_level":
                from .stego_qim_advanced import MultiLevelQIM

                qim_algorithm = MultiLevelQIM(
                    quantization_step=self.options.get("quantization_step", 16.0),
                    bits_per_coefficient=self.options.get("bits_per_coefficient", 2),
                )
            else:  # Default to uniform QIM
                from .stego_qim_advanced import UniformQIM

                qim_algorithm = UniformQIM(
                    quantization_step=self.options.get("quantization_step", 8.0),
                    embedding_strength=self.options.get("embedding_strength", 1.0),
                )

            self.stego = MP4VideoSteganography(
                container_path="",  # Will be set during hide/extract operations
                password=self.password,
                security_level=self.options.get("security_level", 2),
                quality_preservation=self.options.get("quality_preservation", 8),
                temporal_spread=self.options.get("temporal_spread", True),
                use_audio_track=self.options.get("use_audio_track", False),
                use_motion_vectors=self.options.get("use_motion_vectors", False),
                use_dct=True,
                qim_algorithm="adaptive",  # Will be set based on method
                frame_selection_strategy=self.options.get("frame_selection_strategy", "adaptive"),
            )
            # Set the specific QIM algorithm
            if hasattr(self.stego, "qim_algorithm"):
                self.stego.qim_algorithm = qim_algorithm
        elif media_format == "WEBM":
            # WebM video steganography not yet implemented
            raise VideoFormatError(
                "WebM steganography is not yet implemented. Currently only MP4 video "
                "steganography is supported using DCT frequency domain embedding. "
                "WebM support is planned for future releases."
            )
        elif media_format in ["AVI", "MKV"]:
            # AVI/MKV video steganography not yet implemented
            raise VideoFormatError(
                f"{media_format} steganography is not yet implemented. Currently only MP4 video "
                "steganography is supported using DCT frequency domain embedding. "
                f"{media_format} support is planned for future releases."
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

            # Special handling for video formats
            if media_format in ["MP4", "WEBM", "AVI", "MKV"]:
                # For video, we need to work with file paths directly
                if hasattr(self.stego, "container_path"):
                    self.stego.container_path = cover_media_path

                # Check capacity using file path instead of raw data
                capacity = self.stego.calculate_capacity(cover_data)
                if len(encrypted_data) > capacity:
                    raise CapacityError(len(encrypted_data), capacity, f"{media_format} video")

                # Hide data and get result as bytes
                stego_data = self.stego.hide_data(cover_data, encrypted_data)

                # Write output
                with open(output_media_path, "wb") as f:
                    f.write(stego_data)
            else:
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

            # Special handling for video formats
            if media_format in ["MP4", "WEBM", "AVI", "MKV"]:
                # For video, we need to work with file paths directly
                if hasattr(self.stego, "container_path"):
                    self.stego.container_path = stego_media_path

                # Extract data using the file path
                encrypted_data = self.stego.extract_data(stego_data)
            else:
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
            # Video-specific options
            "quantization_step": getattr(args, "video_quantization_step", 8.0),
            "adaptation_factor": getattr(args, "video_adaptation_factor", 1.2),
            "compensation_factor": getattr(args, "video_compensation_factor", 0.5),
            "bits_per_coefficient": getattr(args, "video_bits_per_coefficient", 2),
            "temporal_spread": getattr(args, "video_temporal_spread", True),
            "quality_preservation": getattr(args, "video_quality_preservation", 8),
            "security_level": 2,  # Use higher security for video steganography
            "use_audio_track": False,  # Disable audio track usage for now
            "use_motion_vectors": False,  # Disable motion vector usage for now
            "frame_selection_strategy": "adaptive",  # Use adaptive frame selection
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
