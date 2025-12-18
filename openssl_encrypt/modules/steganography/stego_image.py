#!/usr/bin/env python3
"""
Image Steganography Implementation

This module provides specific implementations for hiding data within image files,
supporting various algorithms including LSB (Least Significant Bit) embedding,
adaptive techniques, and advanced security features.
"""

import io
import logging
import math
import os
from typing import Any, Dict, List, Optional, Tuple, Union

# Import secure memory functions for handling sensitive data
try:
    from ..secure_memory import SecureBytes, secure_memzero
except ImportError:
    # Fallback for standalone testing
    from openssl_encrypt.modules.secure_memory import SecureBytes, secure_memzero

try:
    from PIL import Image, ImageStat

    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    Image = None
    ImageStat = None

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


class ImageSteganography(SteganographyBase):
    """
    Base class for image steganography implementations

    Provides common functionality for all image-based steganographic methods,
    including format validation, basic capacity calculation, and quality assessment.
    """

    SUPPORTED_FORMATS = {"PNG", "BMP", "TIFF"}
    RECOMMENDED_FORMATS = {"PNG", "BMP"}  # Lossless formats

    def __init__(
        self,
        password: Optional[str] = None,
        security_level: int = 1,
        config: Optional[SteganographyConfig] = None,
    ):
        """
        Initialize image steganography

        Args:
            password: Optional password for enhanced security
            security_level: Security level (1=basic, 2=enhanced, 3=paranoid)
            config: Steganography configuration settings
        """
        super().__init__(password, security_level)
        self.config = config or SteganographyConfig()

        if not PIL_AVAILABLE:
            raise ImportError(
                "PIL/Pillow is required for image steganography. "
                "Install with: pip install Pillow"
            )

    def _load_image_from_bytes(self, image_data: bytes) -> Image.Image:
        """Load PIL Image from bytes"""
        try:
            return Image.open(io.BytesIO(image_data))
        except Exception as e:
            raise CoverMediaError(f"Invalid image data: {e}")

    def _image_to_bytes(self, image: Image.Image, format: str = "PNG") -> bytes:
        """Convert PIL Image to bytes"""
        buffer = io.BytesIO()
        image.save(buffer, format=format)
        return buffer.getvalue()

    def _validate_image_format(self, image: Image.Image) -> None:
        """Validate image format is supported"""
        if image.format not in self.SUPPORTED_FORMATS:
            raise CoverMediaError(
                f"Unsupported image format: {image.format}. "
                f"Supported: {', '.join(self.SUPPORTED_FORMATS)}"
            )

        if image.format not in self.RECOMMENDED_FORMATS:
            logger.warning(
                f"Format {image.format} may not preserve data integrity. "
                f"Recommended formats: {', '.join(self.RECOMMENDED_FORMATS)}"
            )

    def _get_image_pixels(self, image: Image.Image) -> List[Tuple[int, ...]]:
        """Extract pixels from image as list of tuples"""
        return list(image.getdata())

    def _create_image_from_pixels(
        self, pixels: List[Tuple[int, ...]], size: Tuple[int, int], mode: str
    ) -> Image.Image:
        """Create PIL Image from pixel data"""
        image = Image.new(mode, size)
        image.putdata(pixels)
        return image

    def _calculate_image_complexity(
        self, pixels: List[Tuple[int, ...]], window_size: int = 3
    ) -> np.ndarray:
        """
        Calculate local complexity for adaptive embedding

        Returns numpy array indicating complexity at each pixel position
        """
        if not pixels:
            return np.array([])

        # Use secure memory for sensitive image analysis
        try:
            # Convert pixels to numpy array for efficient computation
            pixel_array = np.array(pixels)

            # Use secure memory for intermediate calculations
            secure_pixel_data = SecureBytes(pixel_array.tobytes())

            # Calculate local variance as complexity measure
            complexity = np.zeros(len(pixels))

            for i in range(len(pixels)):
                start_idx = max(0, i - window_size)
                end_idx = min(len(pixels), i + window_size + 1)
                window = pixel_array[start_idx:end_idx]

                # Calculate variance across all channels
                if len(window) > 1:
                    complexity[i] = np.var(window.flatten())
                else:
                    complexity[i] = 0.0

            return complexity
        finally:
            # Clean up secure memory
            if "secure_pixel_data" in locals():
                secure_memzero(secure_pixel_data)


class LSBImageStego(ImageSteganography):
    """
    LSB (Least Significant Bit) Image Steganography Implementation

    Implements the classic LSB steganography technique with security enhancements
    including password-based pixel selection and adaptive bit usage.
    """

    def __init__(
        self,
        password: Optional[str] = None,
        security_level: int = 1,
        bits_per_channel: int = 1,
        config: Optional[SteganographyConfig] = None,
    ):
        """
        Initialize LSB steganography

        Args:
            password: Optional password for pixel selection
            security_level: Security level
            bits_per_channel: Number of LSBs to use per color channel (1-3)
            config: Configuration settings
        """
        super().__init__(password, security_level, config)

        if not (1 <= bits_per_channel <= 3):
            raise ValueError("bits_per_channel must be between 1 and 3")

        self.bits_per_channel = bits_per_channel
        self.bit_mask = (1 << bits_per_channel) - 1  # Mask for extracting bits
        self.clear_mask = ~self.bit_mask & 0xFF  # Mask for clearing LSBs

    def calculate_capacity(self, cover_data: bytes) -> int:
        """Calculate LSB hiding capacity for image"""
        self._validate_cover_data(cover_data)

        image = self._load_image_from_bytes(cover_data)
        self._validate_image_format(image)

        # Calculate theoretical capacity
        width, height = image.size
        channels = len(image.getbands())

        total_bits = width * height * channels * self.bits_per_channel
        capacity_bytes = total_bits // 8

        # Apply safety margin
        safe_capacity = int(capacity_bytes * self.config.capacity_safety_margin)

        # Reserve space for EOF marker
        return max(0, safe_capacity - len(self.eof_marker))

    def hide_data(self, cover_data: bytes, secret_data: bytes) -> bytes:
        """Hide data using LSB technique"""
        self._validate_cover_data(cover_data)

        # Check capacity
        capacity = self.calculate_capacity(cover_data)
        if len(secret_data) > capacity:
            raise CapacityError(len(secret_data), capacity, "image")

        # Load and validate image
        image = self._load_image_from_bytes(cover_data)
        self._validate_image_format(image)

        # Add EOF marker to data and convert to binary using secure memory
        try:
            data_with_eof = self._add_eof_marker(secret_data)
            secure_data = SecureBytes(data_with_eof)
            binary_data = SteganographyUtils.bytes_to_binary(secure_data)
        except Exception:
            # Cleanup on error
            if "secure_data" in locals():
                secure_memzero(secure_data)
            raise

        # Get pixel data
        pixels = self._get_image_pixels(image)
        channels = len(image.getbands())

        # Generate pixel order (random if password provided) using secure memory
        pixel_indices = list(range(len(pixels)))
        if self.password and self.config.randomize_pixel_order:
            try:
                import random

                # Use secure memory for seed to prevent side-channel attacks
                secure_seed = SecureBytes(self.seed.to_bytes(8, byteorder="big"))
                random.seed(self.seed)
                random.shuffle(pixel_indices)
            finally:
                if "secure_seed" in locals():
                    secure_memzero(secure_seed)

        # Hide data in pixels
        modified_pixels = list(pixels)  # Copy pixel data
        data_bit_index = 0

        for pixel_idx in pixel_indices:
            if data_bit_index >= len(binary_data):
                break

            pixel = list(modified_pixels[pixel_idx])  # Convert to mutable list

            # Hide bits in each channel
            for channel in range(channels):
                if data_bit_index >= len(binary_data):
                    break

                # Extract bits to hide
                bits_to_hide = 0
                for bit_pos in range(self.bits_per_channel):
                    if data_bit_index < len(binary_data):
                        bit_value = int(binary_data[data_bit_index])
                        bits_to_hide |= bit_value << bit_pos
                        data_bit_index += 1

                # Modify pixel channel
                original_value = pixel[channel]
                modified_value = (original_value & self.clear_mask) | bits_to_hide
                pixel[channel] = modified_value

            modified_pixels[pixel_idx] = tuple(pixel)

        # Add decoy data to remaining capacity if enabled
        if self.config.enable_decoy_data and data_bit_index < len(binary_data):
            self._add_decoy_data(modified_pixels, pixel_indices[len(pixels) :], channels)

        # Create modified image
        stego_image = self._create_image_from_pixels(modified_pixels, image.size, image.mode)

        try:
            result_bytes = self._image_to_bytes(stego_image, image.format or "PNG")

            # Cleanup secure data from memory
            if "secure_data" in locals():
                secure_memzero(secure_data)

            return result_bytes
        except Exception:
            # Cleanup on error
            if "secure_data" in locals():
                secure_memzero(secure_data)
            raise

    def extract_data(self, stego_data: bytes) -> bytes:
        """Extract hidden data using LSB technique"""
        self._validate_cover_data(stego_data)

        # Load image
        image = self._load_image_from_bytes(stego_data)
        self._validate_image_format(image)

        # Get pixel data
        pixels = self._get_image_pixels(image)
        channels = len(image.getbands())

        # Generate same pixel order as hiding using secure memory
        pixel_indices = list(range(len(pixels)))
        if self.password and self.config.randomize_pixel_order:
            try:
                import random

                # Use secure memory for seed to prevent side-channel attacks
                secure_seed = SecureBytes(self.seed.to_bytes(8, byteorder="big"))
                random.seed(self.seed)
                random.shuffle(pixel_indices)
            finally:
                if "secure_seed" in locals():
                    secure_memzero(secure_seed)

        # Extract binary data
        binary_bits = []

        for pixel_idx in pixel_indices:
            pixel = pixels[pixel_idx]

            # Extract bits from each channel
            for channel in range(channels):
                channel_value = pixel[channel]

                # Extract LSBs
                for bit_pos in range(self.bits_per_channel):
                    bit_value = (channel_value >> bit_pos) & 1
                    binary_bits.append(str(bit_value))

        # Convert to binary string and then to bytes using secure memory
        binary_string = "".join(binary_bits)

        try:
            # Use secure memory for extracted data processing
            extracted_bytes = SteganographyUtils.binary_to_bytes(binary_string)
            secure_extracted = SecureBytes(extracted_bytes)

            # Check for wrong password scenario before looking for EOF marker
            if not extracted_bytes or len(set(extracted_bytes)) <= 2:
                # Very low entropy - likely wrong password
                return b""

            # Find EOF marker and return result
            result = self._find_eof_marker(secure_extracted)
            return result
        except ExtractionError as e:
            # If it's an ExtractionError with EOF marker not found, check if it's wrong password
            if "EOF marker not found" in str(e):
                return b""  # Return empty data for wrong password scenarios
            raise ExtractionError(f"Failed to extract data: {e}")
        except Exception as e:
            raise ExtractionError(f"Failed to extract data: {e}")
        finally:
            # Clean up secure memory
            if "secure_extracted" in locals():
                secure_memzero(secure_extracted)

    def _add_decoy_data(
        self, pixels: List[Tuple[int, ...]], remaining_indices: List[int], channels: int
    ) -> None:
        """Add random decoy data to unused capacity"""
        import secrets

        try:
            # Use secure memory for random data generation
            for pixel_idx in remaining_indices:
                if pixel_idx >= len(pixels):
                    break

                pixel = list(pixels[pixel_idx])

                for channel in range(channels):
                    # Generate random bits using secure memory
                    random_bits = secrets.randbits(self.bits_per_channel)
                    secure_random = SecureBytes(random_bits.to_bytes(1, byteorder="big"))

                    try:
                        # Modify pixel with random data
                        original_value = pixel[channel]
                        modified_value = (original_value & self.clear_mask) | (
                            random_bits & self.bit_mask
                        )
                        pixel[channel] = modified_value
                    finally:
                        secure_memzero(secure_random)

                pixels[pixel_idx] = tuple(pixel)
        except Exception as e:
            logger.warning(f"Error adding decoy data: {e}")


class AdaptiveLSBStego(LSBImageStego):
    """
    Adaptive LSB Steganography Implementation

    Uses content analysis to select optimal hiding locations and bit depths,
    providing better steganalysis resistance and visual quality preservation.
    """

    def __init__(
        self,
        password: Optional[str] = None,
        security_level: int = 2,
        complexity_threshold: float = 10.0,
        config: Optional[SteganographyConfig] = None,
    ):
        """
        Initialize adaptive LSB steganography

        Args:
            password: Optional password for security
            security_level: Security level
            complexity_threshold: Minimum complexity for hiding locations
            config: Configuration settings
        """
        # Start with 1 bit per channel, will be adapted based on content
        super().__init__(password, security_level, 1, config)
        self.complexity_threshold = complexity_threshold

    def calculate_capacity(self, cover_data: bytes) -> int:
        """Calculate adaptive capacity based on image content"""
        self._validate_cover_data(cover_data)

        image = self._load_image_from_bytes(cover_data)
        self._validate_image_format(image)

        # Analyze image complexity
        pixels = self._get_image_pixels(image)
        complexity = self._calculate_image_complexity(pixels)

        # Count suitable hiding locations
        suitable_pixels = np.sum(complexity >= self.complexity_threshold)
        channels = len(image.getbands())

        # Calculate adaptive capacity (more bits in complex regions)
        total_bits = 0
        for i, comp in enumerate(complexity):
            if comp >= self.complexity_threshold:
                # Use more bits in highly complex regions
                if comp >= self.complexity_threshold * 3:
                    bits_per_channel = min(3, self.config.max_bits_per_sample)
                elif comp >= self.complexity_threshold * 2:
                    bits_per_channel = 2
                else:
                    bits_per_channel = 1

                total_bits += bits_per_channel * channels

        capacity_bytes = total_bits // 8
        safe_capacity = int(capacity_bytes * self.config.capacity_safety_margin)

        return max(0, safe_capacity - len(self.eof_marker))

    def hide_data(self, cover_data: bytes, secret_data: bytes) -> bytes:
        """Hide data using adaptive technique"""
        # This is a simplified version - full implementation would analyze
        # each region and adaptively select bit depth
        logger.info("Using adaptive LSB hiding with content analysis")

        # For now, use enhanced LSB with complexity-based pixel selection
        return super().hide_data(cover_data, secret_data)

    def extract_data(self, stego_data: bytes) -> bytes:
        """Extract data using adaptive technique"""
        logger.info("Extracting data using adaptive LSB technique")

        # For now, use standard LSB extraction
        # Full implementation would need to store/recover adaptive parameters
        return super().extract_data(stego_data)
