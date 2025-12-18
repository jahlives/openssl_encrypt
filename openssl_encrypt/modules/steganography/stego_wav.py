#!/usr/bin/env python3
"""
WAV Audio Steganography Module

This module provides steganographic capabilities for WAV audio files, enabling
the hiding of encrypted data within uncompressed PCM audio samples using
Least Significant Bit (LSB) techniques.

Key Features:
- LSB steganography in audio samples (16-bit and 24-bit PCM)
- Multi-channel audio support (mono, stereo, surround)
- Secure memory management throughout operations
- High-capacity hiding potential with audio data
- Imperceptible modifications to original audio

Security Architecture:
- SecureBytes containers for all sensitive data
- Automatic secure memory cleanup after operations
- Key-based sample randomization for enhanced security
- Audio-aware hiding to prevent audible artifacts

Supported WAV Features:
- Uncompressed PCM audio (16-bit, 24-bit, 32-bit)
- Multiple sample rates (8kHz to 192kHz and beyond)
- Mono, stereo, and multi-channel configurations
- Standard RIFF/WAV container format
- Metadata preservation during steganographic operations
"""

import io
import logging
import struct
import wave
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

# Import secure memory functions for handling sensitive data
try:
    from ..secure_memory import SecureBytes, secure_memzero
except ImportError:
    # Fallback for standalone testing
    from openssl_encrypt.modules.secure_memory import SecureBytes, secure_memzero

from .stego_core import (
    CapacityError,
    CoverMediaError,
    ExtractionError,
    SteganographyBase,
    SteganographyConfig,
    SteganographyError,
    SteganographyUtils,
)

# Set up module logger
logger = logging.getLogger(__name__)


class WAVSteganography(SteganographyBase):
    """
    WAV audio steganography implementation using LSB techniques

    This class provides comprehensive WAV steganographic capabilities with
    support for various PCM audio formats and multi-channel configurations.
    """

    SUPPORTED_FORMATS = {"WAV"}

    # WAV format constants
    WAV_HEADER_SIZE = 44  # Minimum WAV header size
    RIFF_SIGNATURE = b"RIFF"
    WAVE_SIGNATURE = b"WAVE"
    FMT_CHUNK = b"fmt "
    DATA_CHUNK = b"data"

    # Supported audio formats
    PCM_FORMAT = 1
    SUPPORTED_SAMPLE_RATES = [8000, 11025, 16000, 22050, 32000, 44100, 48000, 96000, 192000]
    SUPPORTED_BIT_DEPTHS = [16, 24, 32]

    def __init__(
        self,
        password: Optional[str] = None,
        security_level: int = 1,
        bits_per_sample: int = 1,
        preserve_quality: bool = True,
        config: Optional[SteganographyConfig] = None,
    ):
        """
        Initialize WAV steganography

        Args:
            password: Optional password for enhanced security
            security_level: Security level (1-3)
            bits_per_sample: LSB bits per audio sample (1-4)
            preserve_quality: Preserve audio quality by limiting modifications
            config: Steganography configuration
        """
        super().__init__(password, security_level)

        if not (1 <= bits_per_sample <= 4):
            raise ValueError("bits_per_sample must be between 1 and 4")

        self.bits_per_sample = bits_per_sample
        self.preserve_quality = preserve_quality
        self.wav_info = {}

        # Set config or create default
        self.config = config or SteganographyConfig()

        # Configure based on security level
        if security_level >= 2:
            self.config.randomize_pixel_order = True  # Reused for sample order
        if security_level >= 3:
            self.config.enable_decoy_data = True

        # Audio-specific configurations
        if preserve_quality and bits_per_sample > 2:
            logger.warning("High bits_per_sample may affect audio quality")

    def calculate_capacity(self, cover_data: bytes) -> int:
        """
        Calculate steganographic capacity for WAV audio file

        Args:
            cover_data: Raw WAV data

        Returns:
            Maximum bytes that can be hidden

        Raises:
            CoverMediaError: If WAV format is invalid
        """
        try:
            # Use SecureBytes for cover data protection
            secure_cover_data = SecureBytes(cover_data)

            try:
                # Analyze WAV structure
                wav_info = self._analyze_wav_structure(secure_cover_data)

                if wav_info["format"] != self.PCM_FORMAT:
                    raise CoverMediaError(
                        f"Unsupported audio format: {wav_info['format']} (only PCM supported)"
                    )

                # Calculate capacity based on audio samples
                total_samples = wav_info["total_samples"]
                channels = wav_info["channels"]

                # Total hiding capacity = samples * channels * bits_per_sample
                total_bits = total_samples * channels * self.bits_per_sample
                capacity = (total_bits // 8) - 64  # 64 bytes overhead for length and markers

                # Apply quality preservation if enabled
                if self.preserve_quality:
                    capacity = int(capacity * 0.75)  # Use only 75% for quality preservation

                logger.debug(
                    f"WAV capacity: {capacity} bytes ({total_samples} samples, {channels} channels)"
                )
                return max(0, capacity)

            finally:
                # Secure cleanup
                secure_memzero(secure_cover_data)

        except Exception as e:
            logger.error(f"WAV capacity calculation failed: {e}")
            raise CoverMediaError(f"Invalid WAV file: {e}")

    def hide_data(self, cover_data: bytes, secret_data: bytes) -> bytes:
        """
        Hide secret data in WAV audio file

        Args:
            cover_data: Cover WAV audio data
            secret_data: Secret data to hide

        Returns:
            Steganographic WAV audio data

        Raises:
            CapacityError: If secret data is too large
            CoverMediaError: If cover audio is invalid
            SteganographyError: If hiding operation fails
        """
        # Use SecureBytes for sensitive data protection
        secure_cover_data = SecureBytes(cover_data)
        secure_secret_data = SecureBytes(secret_data)

        try:
            # Analyze WAV structure
            wav_info = self._analyze_wav_structure(secure_cover_data)
            self.wav_info = wav_info

            # Check capacity
            capacity = self.calculate_capacity(cover_data)
            if len(secret_data) > capacity:
                raise CapacityError(len(secret_data), capacity, "WAV audio file")

            # Load WAV audio data
            audio_samples = self._load_wav_samples(secure_cover_data, wav_info)

            # Hide data in audio samples
            logger.debug("Hiding data in WAV audio using LSB method")
            stego_samples = self._hide_in_wav_samples(audio_samples, secure_secret_data, wav_info)

            # Convert back to WAV bytes
            return self._samples_to_wav_bytes(stego_samples, wav_info, secure_cover_data)

        except Exception as e:
            if isinstance(e, (CapacityError, CoverMediaError)):
                raise
            logger.error(f"WAV hiding failed: {e}")
            raise SteganographyError(f"WAV steganography failed: {e}")
        finally:
            # Secure cleanup
            secure_memzero(secure_cover_data)
            secure_memzero(secure_secret_data)

    def extract_data(self, stego_data: bytes) -> bytes:
        """
        Extract secret data from steganographic WAV audio file

        Args:
            stego_data: Steganographic WAV audio data

        Returns:
            Extracted secret data

        Raises:
            ExtractionError: If extraction fails
        """
        # Use SecureBytes for data protection
        secure_stego_data = SecureBytes(stego_data)

        try:
            # Analyze WAV structure
            wav_info = self._analyze_wav_structure(secure_stego_data)

            # Load WAV audio data
            audio_samples = self._load_wav_samples(secure_stego_data, wav_info)

            # Extract data from audio samples
            logger.debug("Extracting data from WAV audio using LSB method")
            extracted_data = self._extract_from_wav_samples(audio_samples, wav_info)

            logger.debug(f"Extracted {len(extracted_data)} bytes from WAV")
            return bytes(extracted_data)

        except Exception as e:
            logger.error(f"WAV extraction failed: {e}")
            raise ExtractionError(f"WAV extraction failed: {e}")
        finally:
            # Secure cleanup
            secure_memzero(secure_stego_data)

    def _analyze_wav_structure(self, wav_data: bytes) -> Dict[str, Any]:
        """Analyze WAV file structure and extract audio parameters"""
        try:
            if len(wav_data) < self.WAV_HEADER_SIZE:
                raise CoverMediaError("File too small to be valid WAV")

            # Check RIFF header
            if wav_data[:4] != self.RIFF_SIGNATURE:
                raise CoverMediaError("Invalid WAV file: missing RIFF header")

            # Check WAVE signature
            if wav_data[8:12] != self.WAVE_SIGNATURE:
                raise CoverMediaError("Invalid WAV file: missing WAVE signature")

            wav_info = {
                "format": "WAV",
                "valid": True,
                "file_size": struct.unpack("<I", wav_data[4:8])[0] + 8,
                "riff_size": struct.unpack("<I", wav_data[4:8])[0],
            }

            # Find and parse fmt chunk
            offset = 12
            fmt_found = False
            data_found = False

            while offset < len(wav_data) - 8 and not (fmt_found and data_found):
                chunk_id = wav_data[offset : offset + 4]
                chunk_size = struct.unpack("<I", wav_data[offset + 4 : offset + 8])[0]

                if chunk_id == self.FMT_CHUNK:
                    fmt_data = wav_data[offset + 8 : offset + 8 + chunk_size]
                    wav_info.update(self._parse_fmt_chunk(fmt_data))
                    fmt_found = True
                elif chunk_id == self.DATA_CHUNK:
                    wav_info["data_offset"] = offset + 8
                    wav_info["data_size"] = chunk_size
                    data_found = True

                # Move to next chunk (pad to even bytes)
                offset += 8 + ((chunk_size + 1) & ~1)

            if not fmt_found:
                raise CoverMediaError("WAV file missing fmt chunk")
            if not data_found:
                raise CoverMediaError("WAV file missing data chunk")

            # Calculate total samples
            bytes_per_sample = wav_info["bits_per_sample"] // 8
            wav_info["bytes_per_sample"] = bytes_per_sample
            wav_info["total_samples"] = wav_info["data_size"] // (
                bytes_per_sample * wav_info["channels"]
            )

            return wav_info

        except Exception as e:
            logger.error(f"WAV structure analysis failed: {e}")
            raise CoverMediaError(f"Invalid WAV file: {e}")

    def _parse_fmt_chunk(self, fmt_data: bytes) -> Dict[str, Any]:
        """Parse WAV format chunk"""
        if len(fmt_data) < 16:
            raise CoverMediaError("Invalid fmt chunk size")

        fmt_info = {}
        fmt_info["format"] = struct.unpack("<H", fmt_data[0:2])[0]
        fmt_info["channels"] = struct.unpack("<H", fmt_data[2:4])[0]
        fmt_info["sample_rate"] = struct.unpack("<I", fmt_data[4:8])[0]
        fmt_info["byte_rate"] = struct.unpack("<I", fmt_data[8:12])[0]
        fmt_info["block_align"] = struct.unpack("<H", fmt_data[12:14])[0]
        fmt_info["bits_per_sample"] = struct.unpack("<H", fmt_data[14:16])[0]

        # Validate format
        if fmt_info["format"] != self.PCM_FORMAT:
            logger.warning(f"Non-PCM format detected: {fmt_info['format']}")

        if fmt_info["bits_per_sample"] not in self.SUPPORTED_BIT_DEPTHS:
            logger.warning(f"Unusual bit depth: {fmt_info['bits_per_sample']}")

        return fmt_info

    def _load_wav_samples(self, wav_data: bytes, wav_info: Dict[str, Any]) -> np.ndarray:
        """Load audio samples from WAV data"""
        try:
            data_offset = wav_info["data_offset"]
            data_size = wav_info["data_size"]
            bits_per_sample = wav_info["bits_per_sample"]
            channels = wav_info["channels"]

            # Extract audio data
            audio_data = wav_data[data_offset : data_offset + data_size]

            # Convert to numpy array based on bit depth
            if bits_per_sample == 16:
                samples = np.frombuffer(audio_data, dtype=np.int16)
            elif bits_per_sample == 24:
                # 24-bit is more complex - need to handle 3-byte samples
                samples = self._load_24bit_samples(audio_data)
            elif bits_per_sample == 32:
                samples = np.frombuffer(audio_data, dtype=np.int32)
            else:
                raise CoverMediaError(f"Unsupported bit depth: {bits_per_sample}")

            # Reshape for multi-channel audio
            if channels > 1:
                samples = samples.reshape(-1, channels)

            return samples

        except Exception as e:
            logger.error(f"Failed to load WAV samples: {e}")
            raise CoverMediaError(f"Failed to load WAV samples: {e}")

    def _load_24bit_samples(self, audio_data: bytes) -> np.ndarray:
        """Load 24-bit audio samples (3 bytes per sample)"""
        if len(audio_data) % 3 != 0:
            raise CoverMediaError("Invalid 24-bit audio data length")

        # Convert 24-bit to 32-bit integers
        samples = []
        for i in range(0, len(audio_data), 3):
            # Read 3 bytes and convert to signed 24-bit integer
            bytes_3 = audio_data[i : i + 3]
            # Sign extend to 32-bit
            value = struct.unpack("<I", bytes_3 + b"\x00")[0]
            if value >= 0x800000:  # Check sign bit
                value -= 0x1000000  # Convert to negative
            samples.append(value)

        return np.array(samples, dtype=np.int32)

    def _hide_in_wav_samples(
        self, samples: np.ndarray, secret_data: bytes, wav_info: Dict[str, Any]
    ) -> np.ndarray:
        """Hide data in WAV audio samples using LSB method"""
        try:
            # Prepare data for hiding (add length prefix and end marker)
            data_length = len(secret_data)
            length_bytes = struct.pack("<I", data_length)
            data_to_hide = SecureBytes(
                length_bytes + secret_data + b"\x00\x01\x02\x03\x04\x05\x06\x07"
            )  # End marker

            try:
                # Convert data to binary
                binary_data = list(SteganographyUtils.bytes_to_binary(bytes(data_to_hide)))

                # Work with flattened samples for easier processing
                original_shape = samples.shape
                flat_samples = samples.flatten().copy()

                # Generate sample order (randomized if password provided)
                sample_indices = list(range(len(flat_samples)))
                if self.password:
                    # Use password-based randomization
                    np.random.seed(hash(self.password) & 0xFFFFFFFF)
                    np.random.shuffle(sample_indices)

                # Hide data using LSB
                bit_index = 0
                bits_per_sample = self.bits_per_sample
                # Create proper mask for the sample bit depth
                if wav_info["bits_per_sample"] == 16:
                    max_value = 0x7FFF
                    min_value = -0x8000
                    sample_mask = (~((1 << bits_per_sample) - 1)) & 0xFFFF
                elif wav_info["bits_per_sample"] == 24:
                    max_value = 0x7FFFFF
                    min_value = -0x800000
                    sample_mask = (~((1 << bits_per_sample) - 1)) & 0xFFFFFF
                else:  # 32-bit
                    max_value = 0x7FFFFFFF
                    min_value = -0x80000000
                    sample_mask = (~((1 << bits_per_sample) - 1)) & 0xFFFFFFFF

                for sample_idx in sample_indices:
                    if bit_index >= len(binary_data):
                        break

                    # Extract bits to hide
                    bits_to_hide = 0
                    for bit_offset in range(bits_per_sample):
                        if bit_index + bit_offset < len(binary_data):
                            bits_to_hide |= int(binary_data[bit_index + bit_offset]) << bit_offset

                    # Modify sample with proper bounds checking
                    original_sample = int(flat_samples[sample_idx])
                    modified_sample = (original_sample & sample_mask) | bits_to_hide

                    # Ensure the result stays within valid range for the data type
                    if wav_info["bits_per_sample"] == 16:
                        if modified_sample > 0x7FFF:
                            modified_sample -= 0x10000  # Convert to signed
                        modified_sample = max(min_value, min(max_value, modified_sample))
                    elif wav_info["bits_per_sample"] == 24:
                        if modified_sample > 0x7FFFFF:
                            modified_sample -= 0x1000000  # Convert to signed
                        modified_sample = max(min_value, min(max_value, modified_sample))
                    # 32-bit handled automatically by numpy

                    flat_samples[sample_idx] = modified_sample

                    bit_index += bits_per_sample

                # Reshape back to original shape
                modified_samples = flat_samples.reshape(original_shape)

                return modified_samples

            finally:
                # Secure cleanup
                secure_memzero(data_to_hide)
                if "binary_data" in locals():
                    binary_data.clear()

        except Exception as e:
            logger.error(f"WAV sample hiding failed: {e}")
            raise SteganographyError(f"WAV sample hiding failed: {e}")

    def _extract_from_wav_samples(self, samples: np.ndarray, wav_info: Dict[str, Any]) -> bytes:
        """Extract data from WAV audio samples using LSB method"""
        try:
            # Work with flattened samples
            flat_samples = samples.flatten()

            # Generate same sample order used during hiding
            sample_indices = list(range(len(flat_samples)))
            if self.password:
                np.random.seed(hash(self.password) & 0xFFFFFFFF)
                np.random.shuffle(sample_indices)

            # Extract length first (4 bytes = 32 bits)
            length_bits = []
            bits_per_sample = self.bits_per_sample
            bit_mask = (1 << bits_per_sample) - 1

            # Extract length
            bit_index = 0
            bits_needed_for_length = 32

            for sample_idx in sample_indices:
                if bit_index >= bits_needed_for_length:
                    break

                sample_value = flat_samples[sample_idx]
                extracted_bits = sample_value & bit_mask

                for bit_offset in range(bits_per_sample):
                    if bit_index < bits_needed_for_length:
                        length_bits.append((extracted_bits >> bit_offset) & 1)
                        bit_index += 1

            # Convert length bits to integer
            data_length = 0
            for i, bit in enumerate(length_bits):
                data_length |= bit << i

            if data_length <= 0 or data_length > 100 * 1024 * 1024:  # Sanity check
                raise ExtractionError("Invalid data length detected")

            # Extract actual data + end marker
            total_bits_needed = 32 + (data_length * 8) + 64  # Length + data + end marker
            extracted_bits = []

            bit_index = 0
            for sample_idx in sample_indices:
                if bit_index >= total_bits_needed:
                    break

                sample_value = flat_samples[sample_idx]
                extracted_bits_value = sample_value & bit_mask

                for bit_offset in range(bits_per_sample):
                    if bit_index < total_bits_needed:
                        extracted_bits.append((extracted_bits_value >> bit_offset) & 1)
                        bit_index += 1

            # Convert bits back to bytes
            extracted_bytes = SecureBytes(
                SteganographyUtils.binary_to_bytes("".join(map(str, extracted_bits)))
            )

            try:
                # Extract the actual secret data (skip length prefix)
                if len(extracted_bytes) < 4:
                    raise ExtractionError("Insufficient data extracted")

                secret_data = extracted_bytes[4 : 4 + data_length]
                return bytes(secret_data)

            finally:
                # Secure cleanup
                secure_memzero(extracted_bytes)

        except Exception as e:
            logger.error(f"WAV sample extraction failed: {e}")
            raise ExtractionError(f"WAV sample extraction failed: {e}")

    def _samples_to_wav_bytes(
        self, samples: np.ndarray, wav_info: Dict[str, Any], original_wav_data: bytes
    ) -> bytes:
        """Convert modified samples back to WAV bytes"""
        try:
            # Extract header from original WAV
            data_offset = wav_info["data_offset"]
            header_data = original_wav_data[:data_offset]

            # Convert samples to bytes based on bit depth
            bits_per_sample = wav_info["bits_per_sample"]

            if bits_per_sample == 16:
                audio_bytes = samples.astype(np.int16).tobytes()
            elif bits_per_sample == 24:
                audio_bytes = self._samples_to_24bit_bytes(samples)
            elif bits_per_sample == 32:
                audio_bytes = samples.astype(np.int32).tobytes()
            else:
                raise SteganographyError(f"Unsupported bit depth: {bits_per_sample}")

            # Update data chunk size in header if necessary
            new_data_size = len(audio_bytes)
            updated_header = bytearray(header_data)

            # Find data chunk and update size
            offset = 12
            while offset < len(updated_header) - 8:
                chunk_id = updated_header[offset : offset + 4]
                if chunk_id == self.DATA_CHUNK:
                    # Update data chunk size
                    struct.pack_into("<I", updated_header, offset + 4, new_data_size)
                    break
                chunk_size = struct.unpack("<I", updated_header[offset + 4 : offset + 8])[0]
                offset += 8 + ((chunk_size + 1) & ~1)

            # Update RIFF chunk size
            new_riff_size = len(updated_header) + new_data_size - 8
            struct.pack_into("<I", updated_header, 4, new_riff_size)

            return bytes(updated_header) + audio_bytes

        except Exception as e:
            logger.error(f"WAV reconstruction failed: {e}")
            raise SteganographyError(f"WAV reconstruction failed: {e}")

    def _samples_to_24bit_bytes(self, samples: np.ndarray) -> bytes:
        """Convert samples to 24-bit bytes"""
        audio_bytes = bytearray()

        flat_samples = samples.flatten()
        for sample in flat_samples:
            # Convert to 24-bit signed integer
            if sample < 0:
                sample = (1 << 24) + sample  # Two's complement

            # Pack as 3 bytes (little-endian)
            audio_bytes.extend(struct.pack("<I", sample & 0xFFFFFF)[:3])

        return bytes(audio_bytes)


class WAVAnalyzer:
    """
    WAV format analyzer for steganography assessment

    Provides comprehensive analysis of WAV file structure and suitability
    for steganographic operations.
    """

    def __init__(self):
        self.format_info = {
            1: {"name": "PCM", "steganography_score": 1.0},  # Uncompressed PCM
            3: {"name": "IEEE Float", "steganography_score": 0.8},  # Float PCM
            6: {"name": "A-law", "steganography_score": 0.6},  # Compressed
            7: {"name": "μ-law", "steganography_score": 0.6},  # Compressed
        }

    def analyze_wav_structure(self, wav_data: bytes) -> Dict[str, Any]:
        """
        Comprehensive WAV structure analysis

        Args:
            wav_data: Raw WAV data

        Returns:
            Dictionary with detailed WAV analysis
        """
        try:
            # Basic validation
            if len(wav_data) < 44:
                return {"format": "WAV", "valid": False, "error": "File too small"}

            # Parse WAV structure
            wav_info = {
                "format": "WAV",
                "valid": True,
                "header": self._parse_wav_header(wav_data),
                "audio": {},
                "steganography": {},
            }

            # Parse audio properties
            wav_info["audio"] = self._parse_audio_properties(wav_data)

            # Analyze steganography suitability
            wav_info["steganography"] = self._analyze_steganography_suitability(wav_info)

            return wav_info

        except Exception as e:
            logger.error(f"WAV analysis failed: {e}")
            return {"format": "WAV", "valid": False, "error": str(e)}

    def _parse_wav_header(self, wav_data: bytes) -> Dict[str, Any]:
        """Parse WAV file header"""
        return {
            "riff_signature": wav_data[:4],
            "file_size": struct.unpack("<I", wav_data[4:8])[0] + 8,
            "wave_signature": wav_data[8:12],
            "valid_riff": wav_data[:4] == b"RIFF",
            "valid_wave": wav_data[8:12] == b"WAVE",
        }

    def _parse_audio_properties(self, wav_data: bytes) -> Dict[str, Any]:
        """Parse WAV audio properties"""
        audio_props = {}

        # Find fmt chunk
        offset = 12
        while offset < len(wav_data) - 8:
            chunk_id = wav_data[offset : offset + 4]
            chunk_size = struct.unpack("<I", wav_data[offset + 4 : offset + 8])[0]

            if chunk_id == b"fmt ":
                fmt_data = wav_data[offset + 8 : offset + 8 + min(chunk_size, 16)]
                if len(fmt_data) >= 16:
                    audio_props["format_code"] = struct.unpack("<H", fmt_data[0:2])[0]
                    audio_props["channels"] = struct.unpack("<H", fmt_data[2:4])[0]
                    audio_props["sample_rate"] = struct.unpack("<I", fmt_data[4:8])[0]
                    audio_props["byte_rate"] = struct.unpack("<I", fmt_data[8:12])[0]
                    audio_props["block_align"] = struct.unpack("<H", fmt_data[12:14])[0]
                    audio_props["bits_per_sample"] = struct.unpack("<H", fmt_data[14:16])[0]
                break

            offset += 8 + ((chunk_size + 1) & ~1)

        # Find data chunk
        offset = 12
        while offset < len(wav_data) - 8:
            chunk_id = wav_data[offset : offset + 4]
            chunk_size = struct.unpack("<I", wav_data[offset + 4 : offset + 8])[0]

            if chunk_id == b"data":
                audio_props["data_size"] = chunk_size
                if "bits_per_sample" in audio_props and "channels" in audio_props:
                    bytes_per_sample = audio_props["bits_per_sample"] // 8
                    audio_props["total_samples"] = chunk_size // (
                        bytes_per_sample * audio_props["channels"]
                    )

                    if "sample_rate" in audio_props:
                        audio_props["duration_seconds"] = (
                            audio_props["total_samples"] / audio_props["sample_rate"]
                        )
                break

            offset += 8 + ((chunk_size + 1) & ~1)

        return audio_props

    def _analyze_steganography_suitability(self, wav_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze WAV suitability for steganography"""
        suitability = {
            "overall_score": 0.0,
            "format_score": 0.0,
            "quality_score": 0.0,
            "capacity_score": 0.0,
            "recommendations": [],
        }

        try:
            audio = wav_info["audio"]

            # Format analysis
            format_code = audio.get("format_code", 0)
            format_info = self.format_info.get(format_code, {"steganography_score": 0.5})
            suitability["format_score"] = format_info["steganography_score"]

            if format_code == 1:
                suitability["recommendations"].append("PCM format - excellent for steganography")
            elif format_code in [6, 7]:
                suitability["recommendations"].append(
                    "Compressed audio - limited steganography potential"
                )
            else:
                suitability["recommendations"].append("Non-standard format - check compatibility")

            # Quality analysis (bit depth and sample rate)
            bits_per_sample = audio.get("bits_per_sample", 16)
            sample_rate = audio.get("sample_rate", 44100)

            if bits_per_sample >= 16 and sample_rate >= 44100:
                suitability["quality_score"] = 1.0
                suitability["recommendations"].append(
                    "High quality audio - optimal for steganography"
                )
            elif bits_per_sample >= 16:
                suitability["quality_score"] = 0.8
                suitability["recommendations"].append("Good bit depth, consider higher sample rate")
            else:
                suitability["quality_score"] = 0.5
                suitability["recommendations"].append("Low bit depth - limited hiding capacity")

            # Capacity analysis
            total_samples = audio.get("total_samples", 0)
            channels = audio.get("channels", 1)

            if total_samples > 1000000:  # > ~22 seconds at 44.1kHz
                suitability["capacity_score"] = 1.0
                suitability["recommendations"].append("Large audio file - high hiding capacity")
            elif total_samples > 100000:  # > ~2 seconds at 44.1kHz
                suitability["capacity_score"] = 0.7
                suitability["recommendations"].append("Medium audio file - good hiding capacity")
            else:
                suitability["capacity_score"] = 0.3
                suitability["recommendations"].append("Small audio file - limited hiding capacity")

            # Calculate overall score
            suitability["overall_score"] = (
                suitability["format_score"] * 0.4
                + suitability["quality_score"] * 0.3
                + suitability["capacity_score"] * 0.3
            )

            # Add general recommendations
            if suitability["overall_score"] >= 0.9:
                suitability["recommendations"].append("Excellent WAV for steganography")
            elif suitability["overall_score"] >= 0.7:
                suitability["recommendations"].append("Good WAV with minor limitations")
            else:
                suitability["recommendations"].append(
                    "WAV suitable with careful parameter selection"
                )

        except Exception as e:
            logger.error(f"Steganography suitability analysis failed: {e}")
            suitability["error"] = str(e)

        return suitability


def create_wav_test_audio(
    duration_seconds: float = 5.0,
    sample_rate: int = 44100,
    channels: int = 2,
    bits_per_sample: int = 16,
) -> bytes:
    """
    Create a test WAV audio file for steganography testing

    Args:
        duration_seconds: Duration of audio in seconds
        sample_rate: Audio sample rate (Hz)
        channels: Number of audio channels (1=mono, 2=stereo)
        bits_per_sample: Bit depth (16, 24, or 32)

    Returns:
        WAV audio data as bytes
    """
    try:
        # Generate test audio signal (sine wave)
        total_samples = int(duration_seconds * sample_rate)
        time_array = np.linspace(0, duration_seconds, total_samples)

        # Create a pleasant multi-tone signal
        frequency1 = 440.0  # A4 note
        frequency2 = 554.37  # C#5 note

        # Generate waveform
        waveform = (
            np.sin(2 * np.pi * frequency1 * time_array) * 0.3
            + np.sin(2 * np.pi * frequency2 * time_array) * 0.2
        )

        # Add some gentle amplitude modulation to make it more realistic
        modulation = 1.0 + 0.1 * np.sin(2 * np.pi * 2.0 * time_array)
        waveform = waveform * modulation

        # Scale to appropriate bit depth
        if bits_per_sample == 16:
            max_amplitude = 32767
            waveform_scaled = (waveform * max_amplitude).astype(np.int16)
        elif bits_per_sample == 24:
            max_amplitude = 8388607  # 2^23 - 1
            waveform_scaled = (waveform * max_amplitude).astype(np.int32)
        elif bits_per_sample == 32:
            max_amplitude = 2147483647  # 2^31 - 1
            waveform_scaled = (waveform * max_amplitude).astype(np.int32)
        else:
            raise ValueError(f"Unsupported bit depth: {bits_per_sample}")

        # Handle multi-channel audio
        if channels == 2:
            # Create stereo - slightly different waveforms for left and right
            left_channel = waveform_scaled
            right_channel = (waveform_scaled * 0.8).astype(waveform_scaled.dtype)
            audio_data = np.column_stack((left_channel, right_channel))
        elif channels == 1:
            audio_data = waveform_scaled
        else:
            raise ValueError(f"Unsupported channel count: {channels}")

        # Create WAV file using built-in wave module
        output_buffer = io.BytesIO()
        with wave.open(output_buffer, "wb") as wav_file:
            wav_file.setnchannels(channels)
            wav_file.setsampwidth(bits_per_sample // 8)
            wav_file.setframerate(sample_rate)
            wav_file.writeframes(audio_data.tobytes())

        return output_buffer.getvalue()

    except Exception as e:
        logger.error(f"Test WAV creation failed: {e}")
        raise SteganographyError(f"Failed to create test WAV: {e}")


def is_wav_steganography_available() -> bool:
    """Check if WAV steganography dependencies are available"""
    try:
        import wave

        import numpy as np

        # Test basic WAV functionality
        test_buffer = io.BytesIO()
        with wave.open(test_buffer, "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(44100)
            wav_file.writeframes(b"\x00\x00" * 100)

        return True
    except Exception as e:
        logger.warning(f"WAV steganography not available: {e}")
        return False


if __name__ == "__main__":
    # Simple test
    if is_wav_steganography_available():
        print("WAV steganography is available")

        # Create test audio
        test_wav = create_wav_test_audio(duration_seconds=2.0, sample_rate=44100, channels=2)
        print(f"Created test WAV: {len(test_wav)} bytes")

        # Test steganography
        wav_stego = WAVSteganography(bits_per_sample=2)
        capacity = wav_stego.calculate_capacity(test_wav)
        print(f"WAV capacity: {capacity} bytes")

        # Test hiding/extraction
        test_data = b"WAV audio steganography test!"
        if len(test_data) <= capacity:
            stego_data = wav_stego.hide_data(test_wav, test_data)
            extracted = wav_stego.extract_data(stego_data)
            print(f"Test successful: {extracted == test_data}")
        else:
            print("Test data too large for capacity")
    else:
        print("WAV steganography not available")
