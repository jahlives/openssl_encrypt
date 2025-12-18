#!/usr/bin/env python3
"""
TIFF Steganography Implementation

This module provides steganography for TIFF images, supporting various compression
methods (uncompressed, LZW, PackBits) and bit depths (8, 16-bit). TIFF's lossless
nature makes it excellent for steganographic applications.
"""

import io
import logging
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

# Import secure memory functions for handling sensitive data
try:
    from ..secure_memory import SecureBytes, secure_memzero
except ImportError:
    # Fallback for standalone testing
    from openssl_encrypt.modules.secure_memory import SecureBytes, secure_memzero

try:
    from PIL import Image, ImageFile
    from PIL.TiffTags import TAGS

    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    Image = None
    ImageFile = None
    TAGS = None

import numpy as np

from .stego_core import (
    CapacityError,
    CoverMediaError,
    ExtractionError,
    SecurityError,
    SteganographyBase,
    SteganographyConfig,
    SteganographyUtils,
)

# Set up module logger
logger = logging.getLogger(__name__)

# TIFF format constants
TIFF_LITTLE_ENDIAN = b"II"
TIFF_BIG_ENDIAN = b"MM"
TIFF_MAGIC_NUMBER = 42
TIFF_BIGTIFF_MAGIC = 43

# TIFF compression types
TIFF_COMPRESSION_NONE = 1
TIFF_COMPRESSION_CCITT_1D = 2
TIFF_COMPRESSION_GROUP3 = 3
TIFF_COMPRESSION_GROUP4 = 4
TIFF_COMPRESSION_LZW = 5
TIFF_COMPRESSION_JPEG = 7
TIFF_COMPRESSION_PACKBITS = 32773

# Supported compression methods for steganography
SUPPORTED_COMPRESSIONS = {
    TIFF_COMPRESSION_NONE: "Uncompressed",
    TIFF_COMPRESSION_LZW: "LZW",
    TIFF_COMPRESSION_PACKBITS: "PackBits",
}

# TIFF tag constants
TAG_IMAGE_WIDTH = 256
TAG_IMAGE_LENGTH = 257
TAG_BITS_PER_SAMPLE = 258
TAG_COMPRESSION = 259
TAG_PHOTOMETRIC = 262
TAG_SAMPLES_PER_PIXEL = 277
TAG_PLANAR_CONFIG = 284


class TIFFSteganography(SteganographyBase):
    """
    TIFF Steganography Implementation

    Supports LSB steganography for TIFF images with various compression methods
    and bit depths. Handles both grayscale and RGB TIFF images.
    """

    SUPPORTED_FORMATS = {"TIFF", "TIF"}

    def __init__(
        self,
        password: Optional[str] = None,
        security_level: int = 1,
        bits_per_channel: int = 1,
        preserve_compression: bool = True,
        config: Optional[SteganographyConfig] = None,
    ):
        """
        Initialize TIFF steganography

        Args:
            password: Optional password for enhanced security
            security_level: Security level (1=basic, 2=enhanced, 3=paranoid)
            bits_per_channel: LSB bits per channel (1-3)
            preserve_compression: Whether to preserve original compression method
            config: Steganography configuration settings
        """
        super().__init__(password, security_level)
        self.config = config or SteganographyConfig()

        if not PIL_AVAILABLE:
            raise ImportError(
                "PIL/Pillow is required for TIFF steganography. " "Install with: pip install Pillow"
            )

        # Validate parameters
        if not (1 <= bits_per_channel <= 3):
            raise ValueError("bits_per_channel must be between 1 and 3")

        self.bits_per_channel = bits_per_channel
        self.preserve_compression = preserve_compression
        self.bit_mask = (1 << bits_per_channel) - 1
        self.clear_mask = ~self.bit_mask & 0xFF

        # TIFF-specific attributes
        self.tiff_info = {}

    def calculate_capacity(self, cover_data: bytes) -> int:
        """Calculate TIFF hiding capacity based on compression and bit depth"""
        self._validate_cover_data(cover_data, min_size=2048)

        try:
            # Use secure memory for capacity analysis
            secure_cover_data = None

            try:
                secure_cover_data = SecureBytes(cover_data)

                # Analyze TIFF structure
                tiff_info = self._analyze_tiff_structure(secure_cover_data)

                if not tiff_info["steganography_suitable"]:
                    raise CoverMediaError(
                        f"TIFF compression method not suitable for steganography: "
                        f"{tiff_info['compression_name']}"
                    )

                # Load TIFF image for detailed analysis
                image = Image.open(io.BytesIO(secure_cover_data))

                if image.format not in self.SUPPORTED_FORMATS:
                    raise CoverMediaError(f"Unsupported format: {image.format}")

                # Calculate theoretical capacity based on image properties
                width, height = image.size
                total_pixels = width * height

                # Handle different TIFF configurations
                samples_per_pixel = tiff_info.get("samples_per_pixel", 1)
                bits_per_sample = tiff_info.get("bits_per_sample", 8)

                # Calculate usable bits based on bit depth
                if bits_per_sample == 16:
                    # For 16-bit, use only LSBs of lower byte to avoid visible artifacts
                    usable_bits_per_sample = min(self.bits_per_channel, 2)
                else:
                    # For 8-bit, use standard LSB approach
                    usable_bits_per_sample = self.bits_per_channel

                # Calculate total capacity
                total_bits = total_pixels * samples_per_pixel * usable_bits_per_sample
                capacity_bytes = total_bits // 8

                # Apply compression-aware safety margin
                compression_type = tiff_info.get("compression", TIFF_COMPRESSION_NONE)
                if compression_type == TIFF_COMPRESSION_NONE:
                    safety_margin = 0.95  # High safety for uncompressed
                elif compression_type == TIFF_COMPRESSION_LZW:
                    safety_margin = 0.85  # More conservative for LZW
                elif compression_type == TIFF_COMPRESSION_PACKBITS:
                    safety_margin = 0.90  # Medium safety for PackBits
                else:
                    safety_margin = 0.75  # Very conservative for unknown

                safe_capacity = int(capacity_bytes * safety_margin)

                # Reserve space for EOF marker
                return max(0, safe_capacity - len(self.eof_marker))

            finally:
                # Clean up secure memory
                if secure_cover_data:
                    secure_memzero(secure_cover_data)

        except Exception as e:
            if isinstance(e, (CoverMediaError, CapacityError)):
                raise
            raise CoverMediaError(f"TIFF capacity analysis failed: {e}")

    def hide_data(self, cover_data: bytes, secret_data: bytes) -> bytes:
        """Hide data in TIFF using LSB techniques adapted for TIFF characteristics"""
        self._validate_cover_data(cover_data, min_size=2048)

        # Check capacity
        capacity = self.calculate_capacity(cover_data)
        if len(secret_data) > capacity:
            raise CapacityError(len(secret_data), capacity, "TIFF")

        try:
            # Use secure memory for data processing
            secure_cover_data = None
            secure_secret_data = None

            try:
                secure_cover_data = SecureBytes(cover_data)
                secure_secret_data = SecureBytes(secret_data)

                # Analyze TIFF structure
                self.tiff_info = self._analyze_tiff_structure(secure_cover_data)

                # Load TIFF image
                image = Image.open(io.BytesIO(secure_cover_data))

                if image.format not in self.SUPPORTED_FORMATS:
                    raise CoverMediaError(f"Unsupported format: {image.format}")

                # Add EOF marker and convert to binary
                data_with_eof = self._add_eof_marker(secure_secret_data)
                binary_data = SteganographyUtils.bytes_to_binary(data_with_eof)

                # Perform LSB hiding adapted for TIFF
                modified_image = self._hide_in_tiff(image, binary_data)

                # Save with appropriate TIFF parameters
                output_buffer = io.BytesIO()
                save_params = self._get_tiff_save_parameters()
                modified_image.save(output_buffer, format="TIFF", **save_params)

                return output_buffer.getvalue()

            finally:
                # Clean up secure memory
                if secure_cover_data:
                    secure_memzero(secure_cover_data)
                if secure_secret_data:
                    secure_memzero(secure_secret_data)

        except Exception as e:
            if isinstance(e, (CoverMediaError, CapacityError, SecurityError)):
                raise
            raise SecurityError(f"TIFF hiding failed: {e}")

    def extract_data(self, stego_data: bytes) -> bytes:
        """Extract hidden data from TIFF using LSB analysis"""
        self._validate_cover_data(stego_data, min_size=2048)

        try:
            # Use secure memory for extraction
            secure_stego_data = None

            try:
                secure_stego_data = SecureBytes(stego_data)

                # Load TIFF image
                image = Image.open(io.BytesIO(secure_stego_data))

                if image.format not in self.SUPPORTED_FORMATS:
                    raise CoverMediaError(f"Unsupported format: {image.format}")

                # Extract data from TIFF
                binary_data = self._extract_from_tiff(image)

                # Convert binary to bytes and find EOF marker
                extracted_bytes = SteganographyUtils.binary_to_bytes(binary_data)
                return self._find_eof_marker(extracted_bytes)

            finally:
                # Clean up secure memory
                if secure_stego_data:
                    secure_memzero(secure_stego_data)

        except Exception as e:
            if isinstance(e, (CoverMediaError, ExtractionError)):
                raise
            raise ExtractionError(f"TIFF extraction failed: {e}")

    def _analyze_tiff_structure(self, tiff_data: bytes) -> Dict[str, Any]:
        """Analyze TIFF file structure and metadata"""
        try:
            # Basic TIFF header validation
            if len(tiff_data) < 8:
                raise CoverMediaError("File too small to be valid TIFF")

            # Check byte order
            byte_order = tiff_data[:2]
            if byte_order == TIFF_LITTLE_ENDIAN:
                endian = "<"
            elif byte_order == TIFF_BIG_ENDIAN:
                endian = ">"
            else:
                raise CoverMediaError("Invalid TIFF byte order marker")

            # Check magic number
            magic = struct.unpack(f"{endian}H", tiff_data[2:4])[0]
            if magic not in [TIFF_MAGIC_NUMBER, TIFF_BIGTIFF_MAGIC]:
                raise CoverMediaError(f"Invalid TIFF magic number: {magic}")

            # Use PIL to get detailed TIFF information
            image = Image.open(io.BytesIO(tiff_data))

            # Extract TIFF tags
            tiff_info = {
                "byte_order": byte_order,
                "endian": endian,
                "magic": magic,
                "is_bigtiff": magic == TIFF_BIGTIFF_MAGIC,
                "width": image.size[0],
                "height": image.size[1],
                "mode": image.mode,
                "format": image.format,
            }

            # Get compression information
            compression = getattr(image, "tag_v2", {}).get(TAG_COMPRESSION, TIFF_COMPRESSION_NONE)
            tiff_info["compression"] = compression
            tiff_info["compression_name"] = SUPPORTED_COMPRESSIONS.get(
                compression, f"Unknown ({compression})"
            )

            # Check if suitable for steganography
            tiff_info["steganography_suitable"] = compression in SUPPORTED_COMPRESSIONS

            # Get additional properties
            tiff_info["bits_per_sample"] = getattr(image, "tag_v2", {}).get(
                TAG_BITS_PER_SAMPLE, (8,)
            )[0]
            tiff_info["samples_per_pixel"] = getattr(image, "tag_v2", {}).get(
                TAG_SAMPLES_PER_PIXEL, 1
            )
            tiff_info["photometric"] = getattr(image, "tag_v2", {}).get(TAG_PHOTOMETRIC, 1)

            return tiff_info

        except Exception as e:
            logger.error(f"TIFF structure analysis failed: {e}")
            return {"steganography_suitable": False, "error": str(e)}

    def _hide_in_tiff(self, image: Image.Image, binary_data: str) -> Image.Image:
        """Hide data in TIFF using LSB method adapted for TIFF characteristics"""
        try:
            # Use secure memory for hiding process
            secure_binary_data = None

            try:
                # Store binary data in secure memory
                secure_binary_data = SecureBytes(binary_data.encode("ascii"))

                # Convert image to numpy array for manipulation
                img_array = np.array(image)
                original_shape = img_array.shape

                # Handle different TIFF bit depths
                if img_array.dtype == np.uint16:
                    # For 16-bit TIFF, work with lower byte only
                    working_array = (img_array & 0xFF).astype(np.uint8)
                    is_16bit = True
                else:
                    # For 8-bit TIFF, work directly
                    working_array = img_array.astype(np.uint8)
                    is_16bit = False

                # Flatten array for processing
                if len(working_array.shape) == 3:
                    flat_pixels = working_array.flatten()
                else:
                    flat_pixels = working_array.flatten()

                # Generate pixel order (random if password provided)
                pixel_indices = list(range(len(flat_pixels)))
                if self.password and self.config.randomize_pixel_order:
                    import random

                    random.seed(self.seed)
                    random.shuffle(pixel_indices)

                # Hide data in pixels
                data_index = 0
                for pixel_idx in pixel_indices:
                    if data_index >= len(binary_data):
                        break

                    # Modify pixel LSB
                    bit_value = int(binary_data[data_index])
                    original_value = flat_pixels[pixel_idx]
                    modified_value = (original_value & self.clear_mask) | bit_value
                    flat_pixels[pixel_idx] = modified_value
                    data_index += 1

                # Reshape back to original dimensions
                if len(original_shape) == 3:
                    modified_array = flat_pixels.reshape(original_shape)
                else:
                    modified_array = flat_pixels.reshape(original_shape)

                # Handle 16-bit reconstruction
                if is_16bit:
                    # Reconstruct 16-bit array with modified lower bytes
                    final_array = (img_array & 0xFF00) | modified_array.astype(np.uint16)
                else:
                    final_array = modified_array

                # Create modified image
                if is_16bit:
                    # PIL handles 16-bit TIFF specially
                    modified_image = Image.fromarray(final_array, mode=image.mode)
                else:
                    modified_image = Image.fromarray(final_array.astype(np.uint8), mode=image.mode)

                return modified_image

            finally:
                # Clean up secure memory
                if secure_binary_data:
                    secure_memzero(secure_binary_data)

        except Exception as e:
            logger.error(f"TIFF hiding failed: {e}")
            return image  # Return original on error

    def _extract_from_tiff(self, image: Image.Image) -> str:
        """Extract data from TIFF using LSB analysis"""
        try:
            # Use secure memory for extraction
            secure_img_data = None

            try:
                # Convert image to numpy array
                img_array = np.array(image)

                # Store image data in secure memory
                secure_img_data = SecureBytes(img_array.tobytes())

                # Handle different TIFF bit depths
                if img_array.dtype == np.uint16:
                    # For 16-bit TIFF, extract from lower byte
                    working_array = (img_array & 0xFF).astype(np.uint8)
                else:
                    # For 8-bit TIFF, work directly
                    working_array = img_array.astype(np.uint8)

                # Flatten array for processing
                flat_pixels = working_array.flatten()

                # Generate same pixel order as hiding
                pixel_indices = list(range(len(flat_pixels)))
                if self.password and self.config.randomize_pixel_order:
                    import random

                    random.seed(self.seed)
                    random.shuffle(pixel_indices)

                # Extract LSBs
                binary_bits = []
                for pixel_idx in pixel_indices:
                    bit_value = flat_pixels[pixel_idx] & 1
                    binary_bits.append(str(bit_value))

                return "".join(binary_bits)

            finally:
                # Clean up secure memory
                if secure_img_data:
                    secure_memzero(secure_img_data)

        except Exception as e:
            logger.error(f"TIFF extraction failed: {e}")
            return ""  # Return empty string on error

    def _get_tiff_save_parameters(self) -> Dict[str, Any]:
        """Get TIFF save parameters based on original file characteristics"""
        save_params = {}

        if self.preserve_compression and self.tiff_info:
            compression = self.tiff_info.get("compression", TIFF_COMPRESSION_NONE)

            if compression == TIFF_COMPRESSION_NONE:
                save_params["compression"] = "raw"
            elif compression == TIFF_COMPRESSION_LZW:
                save_params["compression"] = "lzw"
            elif compression == TIFF_COMPRESSION_PACKBITS:
                save_params["compression"] = "packbits"
            else:
                # Default to uncompressed for unsupported compression
                save_params["compression"] = "raw"
                logger.warning(f"Unsupported compression {compression}, using uncompressed")
        else:
            # Default to LZW compression for good balance of size and compatibility
            save_params["compression"] = "lzw"

        return save_params


class TIFFAnalyzer:
    """
    TIFF format analyzer for steganography assessment

    Provides detailed analysis of TIFF file structure, compression methods,
    and suitability for steganographic operations.
    """

    def __init__(self):
        self.compression_info = SUPPORTED_COMPRESSIONS.copy()

    def analyze_tiff_structure(self, tiff_data: bytes) -> Dict[str, Any]:
        """
        Comprehensive TIFF structure analysis

        Args:
            tiff_data: Raw TIFF data

        Returns:
            Dictionary containing TIFF analysis information
        """
        try:
            # Use secure memory for analysis
            secure_data = None

            try:
                secure_data = SecureBytes(tiff_data)

                if not self._is_valid_tiff(secure_data):
                    raise CoverMediaError("Invalid TIFF format")

                # Basic header analysis
                header_info = self._analyze_tiff_header(secure_data)

                # Image properties analysis
                image_info = self._analyze_tiff_properties(secure_data)

                # Steganography suitability assessment
                stego_assessment = self._assess_tiff_steganography_suitability(
                    header_info, image_info
                )

                return {
                    "format": "TIFF",
                    "valid": True,
                    "header": header_info,
                    "image": image_info,
                    "steganography": stego_assessment,
                    "analysis_version": "1.0",
                }

            finally:
                # Clean up secure memory
                if secure_data:
                    secure_memzero(secure_data)

        except Exception as e:
            logger.error(f"TIFF analysis failed: {e}")
            return {"format": "TIFF", "valid": False, "error": str(e)}

    def _is_valid_tiff(self, tiff_data: bytes) -> bool:
        """Check if data is valid TIFF format"""
        if len(tiff_data) < 8:
            return False

        # Check byte order markers
        byte_order = tiff_data[:2]
        if byte_order not in [TIFF_LITTLE_ENDIAN, TIFF_BIG_ENDIAN]:
            return False

        # Check magic number
        try:
            endian = "<" if byte_order == TIFF_LITTLE_ENDIAN else ">"
            magic = struct.unpack(f"{endian}H", tiff_data[2:4])[0]
            return magic in [TIFF_MAGIC_NUMBER, TIFF_BIGTIFF_MAGIC]
        except (struct.error, IndexError):
            return False

    def _analyze_tiff_header(self, tiff_data: bytes) -> Dict[str, Any]:
        """Analyze TIFF header information"""
        byte_order = tiff_data[:2]
        endian = "<" if byte_order == TIFF_LITTLE_ENDIAN else ">"
        magic = struct.unpack(f"{endian}H", tiff_data[2:4])[0]

        return {
            "byte_order": "little" if endian == "<" else "big",
            "byte_order_marker": byte_order,
            "magic_number": magic,
            "is_bigtiff": magic == TIFF_BIGTIFF_MAGIC,
            "endian_format": endian,
        }

    def _analyze_tiff_properties(self, tiff_data: bytes) -> Dict[str, Any]:
        """Analyze TIFF image properties"""
        try:
            image = Image.open(io.BytesIO(tiff_data))

            # Get basic image properties
            properties = {
                "width": image.size[0],
                "height": image.size[1],
                "mode": image.mode,
                "total_pixels": image.size[0] * image.size[1],
            }

            # Get TIFF-specific tags
            if hasattr(image, "tag_v2"):
                tags = image.tag_v2
                properties.update(
                    {
                        "compression": tags.get(TAG_COMPRESSION, TIFF_COMPRESSION_NONE),
                        "bits_per_sample": tags.get(TAG_BITS_PER_SAMPLE, (8,)),
                        "samples_per_pixel": tags.get(TAG_SAMPLES_PER_PIXEL, 1),
                        "photometric": tags.get(TAG_PHOTOMETRIC, 1),
                        "planar_config": tags.get(TAG_PLANAR_CONFIG, 1),
                    }
                )

            return properties

        except Exception as e:
            logger.warning(f"TIFF property analysis failed: {e}")
            return {"error": str(e)}

    def _assess_tiff_steganography_suitability(
        self, header_info: Dict[str, Any], image_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Assess TIFF suitability for steganography"""
        assessment = {
            "overall_score": 0.0,
            "compression_score": 0.0,
            "size_score": 0.0,
            "bit_depth_score": 0.0,
            "recommendations": [],
        }

        # Compression assessment
        compression = image_info.get("compression", TIFF_COMPRESSION_NONE)
        if compression in SUPPORTED_COMPRESSIONS:
            if compression == TIFF_COMPRESSION_NONE:
                assessment["compression_score"] = 1.0
                assessment["recommendations"].append(
                    "Uncompressed TIFF - excellent for steganography"
                )
            elif compression == TIFF_COMPRESSION_LZW:
                assessment["compression_score"] = 0.9
                assessment["recommendations"].append(
                    "LZW compression - very good for steganography"
                )
            elif compression == TIFF_COMPRESSION_PACKBITS:
                assessment["compression_score"] = 0.8
                assessment["recommendations"].append(
                    "PackBits compression - good for steganography"
                )
        else:
            assessment["compression_score"] = 0.0
            assessment["recommendations"].append(
                f"Unsupported compression method: {SUPPORTED_COMPRESSIONS.get(compression, 'Unknown')}"
            )

        # Size assessment
        pixels = image_info.get("total_pixels", 0)
        if pixels >= 1000000:  # 1MP+
            assessment["size_score"] = 1.0
        elif pixels >= 500000:  # 0.5MP+
            assessment["size_score"] = 0.8
        elif pixels >= 100000:  # 0.1MP+
            assessment["size_score"] = 0.6
        else:
            assessment["size_score"] = 0.3
            assessment["recommendations"].append("Small image - limited hiding capacity")

        # Bit depth assessment
        bits_per_sample = image_info.get("bits_per_sample", (8,))
        if isinstance(bits_per_sample, (list, tuple)):
            max_bits = max(bits_per_sample)
        else:
            max_bits = bits_per_sample

        if max_bits >= 16:
            assessment["bit_depth_score"] = 1.0
            assessment["recommendations"].append("High bit depth - excellent hiding capacity")
        elif max_bits >= 8:
            assessment["bit_depth_score"] = 0.8
            assessment["recommendations"].append("Standard bit depth - good hiding capacity")
        else:
            assessment["bit_depth_score"] = 0.4
            assessment["recommendations"].append("Low bit depth - limited hiding capacity")

        # Calculate overall score
        assessment["overall_score"] = (
            assessment["compression_score"] * 0.5
            + assessment["size_score"] * 0.3
            + assessment["bit_depth_score"] * 0.2
        )

        # Overall recommendations
        if assessment["overall_score"] >= 0.8:
            assessment["recommendations"].insert(0, "Excellent TIFF file for steganography")
        elif assessment["overall_score"] >= 0.6:
            assessment["recommendations"].insert(0, "Good TIFF file with minor limitations")
        else:
            assessment["recommendations"].insert(
                0, "Limited suitability - consider different image"
            )

        return assessment


def create_tiff_test_image(
    width: int = 512, height: int = 384, compression: str = "lzw", bit_depth: int = 8
) -> bytes:
    """
    Create a test TIFF image for steganography testing

    Args:
        width: Image width
        height: Image height
        compression: TIFF compression ('raw', 'lzw', 'packbits')
        bit_depth: Bit depth (8 or 16)

    Returns:
        TIFF image data
    """
    try:
        # Create test pattern
        if bit_depth == 16:
            # Create 16-bit test pattern
            img_array = np.random.randint(0, 65535, (height, width, 3), dtype=np.uint16)
            mode = "I;16"  # 16-bit integer mode
        else:
            # Create 8-bit test pattern
            img_array = np.zeros((height, width, 3), dtype=np.uint8)

            # Add gradient patterns for realistic data
            for y in range(height):
                for x in range(width):
                    img_array[y, x, 0] = (x + y) % 256  # Red gradient
                    img_array[y, x, 1] = (x * 2) % 256  # Green pattern
                    img_array[y, x, 2] = (y * 2) % 256  # Blue pattern
            mode = "RGB"

        # Convert to PIL Image
        image = Image.fromarray(img_array, mode=mode)

        # Save as TIFF with specified compression
        output_buffer = io.BytesIO()
        image.save(output_buffer, format="TIFF", compression=compression)

        return output_buffer.getvalue()

    except Exception as e:
        logger.error(f"Test TIFF creation failed: {e}")
        raise CoverMediaError(f"Could not create test TIFF: {e}")


def is_tiff_steganography_available() -> bool:
    """Check if TIFF steganography dependencies are available"""
    return PIL_AVAILABLE and np is not None
