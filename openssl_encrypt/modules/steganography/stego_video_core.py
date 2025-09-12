#!/usr/bin/env python3
"""
Video Steganography Core Module

This module provides the base classes and core functionality for hiding encrypted
data within video files. It supports multiple video formats (MP4, WebM, AVI) and
implements various hiding techniques including spatial domain LSB, frequency domain
DCT coefficient modification, and motion vector manipulation.

Key Features:
- Multi-layer hiding (video frames, audio track, motion vectors, metadata)
- Temporal redundancy for error correction
- Quality preservation with perceptual masking
- Format-agnostic container handling
- Integration with existing steganography architecture
"""

import abc
import logging
import math
import struct
import tempfile
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

try:
    import cv2

    VIDEO_SUPPORT_AVAILABLE = True
except ImportError:
    VIDEO_SUPPORT_AVAILABLE = False
    cv2 = None

# Import steganography base classes
from .stego_core import (
    CapacityError,
    CoverMediaError,
    ExtractionError,
    SecurityError,
    SteganographyBase,
    SteganographyConfig,
    SteganographyError,
    SteganographyUtils,
)

# Import DCT utilities for frequency domain steganography
try:
    from .stego_video_dct import (
        CoefficientSelector,
        DCTSteganographyError,
        QualityMetrics,
        QuantizationMatrix,
        VideoDCTUtils,
    )

    DCT_AVAILABLE = True
except ImportError:
    DCT_AVAILABLE = False
    logger.warning("DCT utilities not available - falling back to LSB mode")

# Import error correction utilities
try:
    from .stego_simple_error_correction import AdaptiveSimpleErrorCorrection, ErrorCorrectionError

    ERROR_CORRECTION_AVAILABLE = True
except ImportError:
    ERROR_CORRECTION_AVAILABLE = False
    logger.warning("Error correction not available")

# Import advanced QIM algorithms
try:
    from .stego_qim_advanced import (
        AdaptiveQIM,
        DistortionCompensatedQIM,
        MultiLevelQIM,
        QIMError,
        UniformQIM,
    )

    QIM_AVAILABLE = True
except ImportError:
    QIM_AVAILABLE = False
    logger.warning("Advanced QIM algorithms not available")

# Import secure memory functions
try:
    from ..secure_memory import SecureBytes, secure_memzero
except ImportError:
    from openssl_encrypt.modules.secure_memory import SecureBytes, secure_memzero

# Set up module logger
logger = logging.getLogger(__name__)


class VideoFormatError(SteganographyError):
    """Raised when video format is unsupported or corrupted"""

    pass


class VideoCodecError(SteganographyError):
    """Raised when video codec operations fail"""

    pass


def is_video_steganography_available() -> bool:
    """Check if video steganography dependencies are available"""
    return VIDEO_SUPPORT_AVAILABLE


class VideoFrameInfo:
    """Information about a video frame for steganography planning"""

    def __init__(
        self,
        frame_number: int,
        frame_type: str,
        size: Tuple[int, int],
        complexity: float = 0.0,
        capacity: int = 0,
    ):
        self.frame_number = frame_number
        self.frame_type = frame_type  # 'I', 'P', 'B'
        self.size = size  # (width, height)
        self.complexity = complexity  # Scene complexity score
        self.capacity = capacity  # Estimated hiding capacity in bytes
        self.data_offset = 0  # Where in the secret data this frame starts
        self.data_length = 0  # How much data this frame contains


class VideoSteganographyBase(SteganographyBase):
    """
    Abstract base class for video steganography implementations

    This class provides the core interface for hiding data in video files,
    with support for multi-layer hiding strategies and quality preservation.
    """

    def __init__(
        self,
        password: Optional[str] = None,
        security_level: int = 1,
        quality_preservation: int = 8,
        temporal_spread: bool = True,
        use_audio_track: bool = True,
        use_motion_vectors: bool = False,
        use_dct: bool = True,
        qim_algorithm: str = "adaptive",
    ):
        """
        Initialize video steganography instance

        Args:
            password: Optional password for randomization
            security_level: Security level (1=basic, 2=enhanced, 3=paranoid)
            quality_preservation: Video quality level (1-10, higher=better quality)
            temporal_spread: Enable spreading data across multiple frames
            use_audio_track: Use audio track for additional capacity
            use_motion_vectors: Use motion vectors for hiding (advanced)
            use_dct: Use DCT-based steganography instead of LSB (default: True)
            qim_algorithm: QIM algorithm to use ("uniform", "adaptive", "distortion_compensated", "multilevel")
        """
        super().__init__(password, security_level)

        if not is_video_steganography_available():
            raise VideoFormatError(
                "Video steganography requires opencv-python: pip install opencv-python"
            )

        self.quality_preservation = max(1, min(10, quality_preservation))
        self.temporal_spread = temporal_spread
        self.use_audio_track = use_audio_track
        self.use_motion_vectors = use_motion_vectors
        self.use_dct = use_dct

        # Video-specific configuration
        self.max_bits_per_pixel = 1  # Conservative default for LSB mode
        self.frame_selection_strategy = "adaptive"  # "all", "keyframes", "adaptive"
        self.error_correction_enabled = temporal_spread

        # Initialize DCT components if available and requested
        if use_dct:
            if not DCT_AVAILABLE:
                logger.warning("DCT requested but not available, falling back to LSB")
                self.use_dct = False
            else:
                self.dct_utils = VideoDCTUtils()
                self.coeff_selector = CoefficientSelector()
                self.quality_metrics = QualityMetrics()
                self.quant_matrix = QuantizationMatrix()

        # Initialize error correction
        self.error_corrector = None
        if ERROR_CORRECTION_AVAILABLE and self.error_correction_enabled:
            self.error_corrector = AdaptiveSimpleErrorCorrection()
            logger.info("Error correction enabled for DCT steganography")

        # Initialize QIM algorithm
        self.qim_algorithm = None
        self.qim_algorithm_name = qim_algorithm
        if use_dct and DCT_AVAILABLE and QIM_AVAILABLE:
            # Calculate base quantization step based on quality preservation
            base_step = max(2.0, (11 - quality_preservation) * 2.0)

            if qim_algorithm == "uniform":
                self.qim_algorithm = UniformQIM(quantization_step=base_step)
            elif qim_algorithm == "adaptive":
                self.qim_algorithm = AdaptiveQIM(base_quantization_step=base_step)
            elif qim_algorithm == "distortion_compensated":
                self.qim_algorithm = DistortionCompensatedQIM(quantization_step=base_step)
            elif qim_algorithm == "multilevel":
                # Use larger step for multi-level and embed 2 bits per coefficient
                self.qim_algorithm = MultiLevelQIM(
                    quantization_step=base_step * 1.5, bits_per_coefficient=2
                )
            else:
                logger.warning(f"Unknown QIM algorithm '{qim_algorithm}', using adaptive")
                self.qim_algorithm = AdaptiveQIM(base_quantization_step=base_step)

            logger.info(f"Initialized {qim_algorithm} QIM algorithm with base step {base_step}")
        elif use_dct:
            logger.warning("QIM algorithms not available, using basic QIM")

        # DCT-specific settings
        if use_dct and DCT_AVAILABLE:
            self.dct_quality = quality_preservation * 10  # Convert to 1-100 scale
            self.coefficients_per_block = 15  # Default number of coefficients to use
            logger.debug("DCT steganography mode enabled")
        else:
            self.dct_utils = None
            logger.debug("LSB steganography mode enabled")

        # Capacity distribution across layers
        self.layer_weights = {
            "video_frames": 0.6,  # Primary hiding location
            "audio_track": 0.25 if use_audio_track else 0.0,
            "motion_vectors": 0.1 if use_motion_vectors else 0.0,
            "metadata": 0.05,
        }

        # Normalize weights
        total_weight = sum(self.layer_weights.values())
        if total_weight > 0:
            self.layer_weights = {k: v / total_weight for k, v in self.layer_weights.items()}

    @abc.abstractmethod
    def parse_container(self, video_data: bytes) -> Dict[str, Any]:
        """
        Parse video container structure

        Returns:
            Dictionary containing container information:
            - 'video_stream': Video stream data
            - 'audio_stream': Audio stream data (if present)
            - 'metadata': Container metadata
            - 'duration': Video duration in seconds
            - 'fps': Frames per second
            - 'resolution': (width, height)
        """
        pass

    @abc.abstractmethod
    def reconstruct_container(
        self,
        container_info: Dict[str, Any],
        modified_frames: List[np.ndarray],
        modified_audio: Optional[bytes] = None,
    ) -> bytes:
        """
        Reconstruct video container with modified data

        Args:
            container_info: Container structure from parse_container
            modified_frames: List of modified video frames
            modified_audio: Modified audio data (if any)

        Returns:
            Complete video file data
        """
        pass

    def extract_frames(
        self, video_data: bytes, max_frames: Optional[int] = None
    ) -> Tuple[List[np.ndarray], Dict[str, Any]]:
        """
        Extract frames from video data

        Args:
            video_data: Raw video file data
            max_frames: Maximum number of frames to extract (None = all)

        Returns:
            Tuple of (frames_list, video_info)
        """
        try:
            # Write video data to temporary file for OpenCV processing
            with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as temp_file:
                temp_file.write(video_data)
                temp_path = temp_file.name

            # Open video with OpenCV
            cap = cv2.VideoCapture(temp_path)

            if not cap.isOpened():
                raise VideoFormatError("Failed to open video file")

            # Get video information
            fps = cap.get(cv2.CAP_PROP_FPS)
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            duration = total_frames / fps if fps > 0 else 0

            video_info = {
                "fps": fps,
                "width": width,
                "height": height,
                "total_frames": total_frames,
                "duration": duration,
                "codec": self._get_codec_info(cap),
            }

            # Extract frames
            frames = []
            frame_count = 0

            while True:
                ret, frame = cap.read()
                if not ret:
                    break

                frames.append(frame.copy())
                frame_count += 1

                if max_frames and frame_count >= max_frames:
                    break

            cap.release()

            # Clean up temporary file
            import os

            try:
                os.unlink(temp_path)
            except OSError:
                pass

            logger.info(f"Extracted {len(frames)} frames from video ({width}x{height}, {fps} fps)")
            return frames, video_info

        except Exception as e:
            raise VideoFormatError(f"Failed to extract frames: {e}")

    def _get_codec_info(self, cap) -> Dict[str, Any]:
        """Extract codec information from OpenCV VideoCapture"""
        codec_fourcc = int(cap.get(cv2.CAP_PROP_FOURCC))
        codec_name = "".join([chr((codec_fourcc >> 8 * i) & 0xFF) for i in range(4)])

        return {
            "fourcc": codec_fourcc,
            "name": codec_name,
            "bitrate": cap.get(cv2.CAP_PROP_BITRATE) if hasattr(cv2, "CAP_PROP_BITRATE") else None,
        }

    def calculate_frame_capacity(self, frame: np.ndarray) -> int:
        """
        Calculate hiding capacity for a single frame

        Args:
            frame: Video frame as numpy array

        Returns:
            Estimated capacity in bytes
        """
        if frame is None or frame.size == 0:
            return 0

        height, width = frame.shape[:2]
        channels = frame.shape[2] if len(frame.shape) == 3 else 1

        # Calculate total pixels
        total_pixels = width * height * channels

        # Apply quality preservation factor
        quality_factor = (11 - self.quality_preservation) / 10.0  # Higher quality = less capacity

        # Calculate usable bits per pixel based on security level
        bits_per_pixel = self.max_bits_per_pixel * quality_factor

        if self.security_level >= 3:
            bits_per_pixel *= 0.7  # More conservative for paranoid mode
        elif self.security_level == 2:
            bits_per_pixel *= 0.85  # Slightly conservative for enhanced mode

        # Calculate capacity in bytes
        total_bits = int(total_pixels * bits_per_pixel)
        capacity_bytes = total_bits // 8

        # Reserve space for synchronization and error correction
        if self.temporal_spread:
            capacity_bytes = int(capacity_bytes * 0.9)  # 10% overhead for error correction

        return max(0, capacity_bytes)

    def calculate_video_capacity(self, frames: List[np.ndarray], video_info: Dict[str, Any]) -> int:
        """
        Calculate total video hiding capacity

        Args:
            frames: List of video frames
            video_info: Video metadata information

        Returns:
            Total capacity in bytes
        """
        total_capacity = 0

        # Calculate frame-based capacity
        if self.layer_weights.get("video_frames", 0) > 0:
            frame_capacities = [self.calculate_frame_capacity(frame) for frame in frames]

            if self.frame_selection_strategy == "keyframes":
                # Only use every Nth frame (simulating keyframes)
                keyframe_interval = max(1, len(frames) // 30)  # Approximate keyframe interval
                frame_capacities = frame_capacities[::keyframe_interval]

            video_capacity = sum(frame_capacities)
            total_capacity += int(video_capacity * self.layer_weights["video_frames"])

        # Add audio capacity (if available)
        if self.layer_weights.get("audio_track", 0) > 0 and video_info.get("has_audio", False):
            # Estimate audio capacity (will be refined by specific audio steganography)
            duration = video_info.get("duration", 0)
            estimated_audio_capacity = int(duration * 1000)  # Rough estimate: 1KB per second
            total_capacity += int(estimated_audio_capacity * self.layer_weights["audio_track"])

        # Add metadata capacity
        if self.layer_weights.get("metadata", 0) > 0:
            metadata_capacity = 1024  # Conservative estimate for container metadata
            total_capacity += int(metadata_capacity * self.layer_weights["metadata"])

        # Apply safety margin
        total_capacity = int(total_capacity * 0.95)  # 5% safety margin

        logger.info(
            f"Calculated video capacity: {total_capacity} bytes "
            f"({len(frames)} frames, {video_info.get('duration', 0):.1f}s)"
        )

        return max(0, total_capacity)

    def calculate_capacity(self, cover_data: bytes) -> int:
        """
        Calculate maximum hiding capacity for video file

        Args:
            cover_data: Raw video file data

        Returns:
            Maximum capacity in bytes
        """
        try:
            frames, video_info = self.extract_frames(
                cover_data, max_frames=100
            )  # Sample frames for estimation

            if not frames:
                raise CapacityError(0, 0, "video")

            # Estimate total capacity based on sample
            sample_capacity = self.calculate_video_capacity(frames, video_info)
            total_frames = video_info.get("total_frames", len(frames))
            sample_frames = len(frames)

            if sample_frames > 0 and total_frames > sample_frames:
                # Scale up based on total frames
                estimated_capacity = int(sample_capacity * (total_frames / sample_frames))
            else:
                estimated_capacity = sample_capacity

            return estimated_capacity

        except Exception as e:
            logger.error(f"Failed to calculate video capacity: {e}")
            raise CapacityError(0, 0, "video")

    def hide_in_frame(
        self, frame: np.ndarray, data: bytes, frame_info: VideoFrameInfo
    ) -> np.ndarray:
        """
        Hide data in a single video frame using DCT or LSB steganography

        Args:
            frame: Video frame as numpy array (H, W, C)
            data: Data to hide in this frame
            frame_info: Frame metadata information

        Returns:
            Modified frame with hidden data
        """
        if len(data) == 0:
            return frame.copy()

        if self.use_dct and self.dct_utils is not None:
            return self._hide_in_frame_dct(frame, data, frame_info)
        else:
            return self._hide_in_frame_lsb(frame, data, frame_info)

    def _hide_in_frame_dct(
        self, frame: np.ndarray, data: bytes, frame_info: VideoFrameInfo
    ) -> np.ndarray:
        """
        Hide data in frame using DCT-based frequency domain steganography

        Args:
            frame: Video frame as numpy array (H, W, C)
            data: Data to hide in this frame
            frame_info: Frame metadata information

        Returns:
            Modified frame with hidden data
        """
        if frame.ndim != 3 or frame.shape[2] != 3:
            raise VideoFormatError("DCT steganography requires RGB frames with shape (H, W, 3)")

        # Create copy to avoid modifying original
        stego_frame = frame.copy().astype(np.float32)

        # Convert to YUV color space (Y channel is best for hiding)
        yuv_frame = self._rgb_to_yuv(stego_frame)
        y_channel = yuv_frame[:, :, 0]

        # Split Y channel into 8x8 blocks
        blocks = self.dct_utils.split_into_blocks(y_channel)

        # Generate password-based coefficient selection
        if self.password:
            frame_seed = (self.seed + frame_info.frame_number) % (2**32)
            coeffs_to_use = self.coeff_selector.get_randomized_coefficients(
                self.password, frame_seed, self.coefficients_per_block
            )
        else:
            coeffs_to_use = self.coeff_selector.get_middle_frequencies(self.coefficients_per_block)

        # Apply error correction if available
        # Create a simple container with metadata
        if self.error_corrector:
            try:
                # Assess channel quality based on frame characteristics
                frame_variance = np.var(y_channel)
                # Higher variance frames provide better hiding capacity
                error_rate = max(0.05, min(0.25, 1.0 / (1.0 + frame_variance / 1000.0)))
                quality_level = self.error_corrector.assess_channel_quality(error_rate)

                # Encode data with error correction
                ec_data = self.error_corrector.encode(data, quality=quality_level)

                # Create container: [EC_FLAG(1) + ORIGINAL_LEN(4) + EC_DATA]
                ec_flag = b"\x01"  # Error correction used
                original_len = struct.pack("<I", len(data))
                encoded_data = ec_flag + original_len + ec_data

                logger.debug(
                    f"Applied {quality_level} quality error correction: {len(data)} -> {len(encoded_data)} bytes"
                )
            except ErrorCorrectionError as e:
                logger.warning(f"Error correction failed: {e}, using raw data")
                # Fallback: no error correction
                ec_flag = b"\x00"  # No error correction
                encoded_data = ec_flag + data
        else:
            # No error correction available
            ec_flag = b"\x00"  # No error correction
            encoded_data = ec_flag + data

        # Convert data to bits
        data_bits = "".join(format(byte, "08b") for byte in encoded_data)
        bit_index = 0

        # Process blocks for hiding
        for block_row in range(len(blocks)):
            for block_col in range(len(blocks[block_row])):
                if bit_index >= len(data_bits):
                    break

                block = blocks[block_row][block_col]

                # Apply DCT
                dct_coeffs = self.dct_utils.apply_dct(block)

                # Get quantization matrix for this block
                quant_matrix = self.quant_matrix.get_adaptive_matrix(block, self.dct_quality)

                # Hide bits in selected coefficients using advanced QIM
                for coeff_pos in coeffs_to_use:
                    if bit_index >= len(data_bits):
                        break

                    row, col = coeff_pos
                    current_coeff = dct_coeffs[row, col]

                    if self.qim_algorithm:
                        # Use advanced QIM algorithm
                        try:
                            if hasattr(self.qim_algorithm, "embed_bits"):
                                # Multi-level QIM - embed multiple bits
                                bits_to_embed = []
                                bits_per_coeff = self.qim_algorithm.bits_per_coefficient

                                for _ in range(bits_per_coeff):
                                    if bit_index < len(data_bits):
                                        bits_to_embed.append(int(data_bits[bit_index]))
                                        bit_index += 1
                                    else:
                                        bits_to_embed.append(0)  # Padding

                                if len(bits_to_embed) == bits_per_coeff:
                                    modified_coeff = self.qim_algorithm.embed_bits(
                                        current_coeff, tuple(bits_to_embed)
                                    )
                                    dct_coeffs[row, col] = modified_coeff

                            elif hasattr(self.qim_algorithm, "embed_bit_adaptive"):
                                # Adaptive QIM
                                bit_to_hide = int(data_bits[bit_index])
                                modified_coeff = self.qim_algorithm.embed_bit_adaptive(
                                    current_coeff, bit_to_hide, position=(row, col)
                                )
                                dct_coeffs[row, col] = modified_coeff
                                bit_index += 1

                            elif hasattr(self.qim_algorithm, "embed_bit_compensated"):
                                # Distortion-compensated QIM
                                bit_to_hide = int(data_bits[bit_index])
                                modified_coeff = self.qim_algorithm.embed_bit_compensated(
                                    current_coeff, bit_to_hide
                                )
                                dct_coeffs[row, col] = modified_coeff
                                bit_index += 1

                            else:
                                # Standard QIM
                                bit_to_hide = int(data_bits[bit_index])
                                modified_coeff = self.qim_algorithm.embed_bit(
                                    current_coeff, bit_to_hide
                                )
                                dct_coeffs[row, col] = modified_coeff
                                bit_index += 1

                        except QIMError as e:
                            logger.warning(f"QIM embedding failed: {e}, using fallback")
                            # Fallback to basic QIM
                            bit_to_hide = int(data_bits[bit_index])
                            quant_step = quant_matrix[row, col]
                            quantized = round(current_coeff / quant_step)

                            if (quantized % 2) != bit_to_hide:
                                quantized += 1 if bit_to_hide == 1 else -1

                            dct_coeffs[row, col] = quantized * quant_step
                            bit_index += 1

                    else:
                        # Fallback to basic QIM if no advanced algorithm available
                        bit_to_hide = int(data_bits[bit_index])
                        quant_step = quant_matrix[row, col]
                        quantized = round(current_coeff / quant_step)

                        if (quantized % 2) != bit_to_hide:
                            quantized += 1 if bit_to_hide == 1 else -1

                        dct_coeffs[row, col] = quantized * quant_step
                        bit_index += 1

                # Apply inverse DCT and update block
                reconstructed_block = self.dct_utils.apply_idct(dct_coeffs)
                blocks[block_row][block_col] = reconstructed_block

        # Reconstruct Y channel from blocks
        original_shape = y_channel.shape
        modified_y = self.dct_utils.reconstruct_from_blocks(blocks, original_shape)

        # Update YUV frame and convert back to RGB
        yuv_frame[:, :, 0] = modified_y
        stego_frame = self._yuv_to_rgb(yuv_frame)

        # Ensure valid pixel range
        stego_frame = np.clip(stego_frame, 0, 255).astype(np.uint8)

        return stego_frame

    def _hide_in_frame_lsb(
        self, frame: np.ndarray, data: bytes, frame_info: VideoFrameInfo
    ) -> np.ndarray:
        """
        Hide data in frame using traditional LSB steganography (fallback method)

        Args:
            frame: Video frame as numpy array
            data: Data to hide in this frame
            frame_info: Frame metadata information

        Returns:
            Modified frame with hidden data
        """
        modified_frame = frame.copy()
        height, width = modified_frame.shape[:2]
        channels = modified_frame.shape[2] if len(modified_frame.shape) == 3 else 1

        # Convert data to binary string
        binary_data = "".join(format(byte, "08b") for byte in data)
        data_index = 0

        # Generate randomized pixel order if password is provided
        if self.password and self.seed:
            pixel_indices = list(range(width * height))
            frame_seed = (self.seed + frame_info.frame_number) % (2**32)
            np.random.seed(frame_seed)
            np.random.shuffle(pixel_indices)
        else:
            pixel_indices = list(range(width * height))

        # Hide data in LSBs
        bits_per_pixel = min(self.max_bits_per_pixel, len(binary_data) // (width * height) + 1)

        for pixel_idx in pixel_indices:
            if data_index >= len(binary_data):
                break

            row = pixel_idx // width
            col = pixel_idx % width

            # Process each channel
            for channel in range(channels):
                if data_index >= len(binary_data):
                    break

                # Get current pixel value
                pixel_value = (
                    modified_frame[row, col, channel] if channels > 1 else modified_frame[row, col]
                )

                # Hide bits_per_pixel bits in this pixel
                for bit_pos in range(bits_per_pixel):
                    if data_index >= len(binary_data):
                        break

                    # Clear LSB and set new bit, ensuring we stay in uint8 range
                    pixel_value = int(pixel_value)
                    pixel_value = (pixel_value & ~1) | int(binary_data[data_index])
                    pixel_value = pixel_value & 0xFF
                    data_index += 1

                # Update pixel value
                if channels > 1:
                    modified_frame[row, col, channel] = pixel_value
                else:
                    modified_frame[row, col] = pixel_value

        return modified_frame

    def _rgb_to_yuv(self, rgb_frame: np.ndarray) -> np.ndarray:
        """Convert RGB frame to YUV color space."""
        if not VIDEO_SUPPORT_AVAILABLE:
            raise VideoFormatError("OpenCV required for color space conversion")

        # OpenCV uses BGR, so convert RGB to BGR first
        bgr_frame = cv2.cvtColor(rgb_frame.astype(np.uint8), cv2.COLOR_RGB2BGR)
        yuv_frame = cv2.cvtColor(bgr_frame, cv2.COLOR_BGR2YUV)

        return yuv_frame.astype(np.float32)

    def _yuv_to_rgb(self, yuv_frame: np.ndarray) -> np.ndarray:
        """Convert YUV frame back to RGB color space."""
        if not VIDEO_SUPPORT_AVAILABLE:
            raise VideoFormatError("OpenCV required for color space conversion")

        # Convert to BGR first, then to RGB
        bgr_frame = cv2.cvtColor(yuv_frame.astype(np.uint8), cv2.COLOR_YUV2BGR)
        rgb_frame = cv2.cvtColor(bgr_frame, cv2.COLOR_BGR2RGB)

        return rgb_frame.astype(np.float32)

    def _analyze_frame_complexity(self, frame: np.ndarray) -> Dict[str, float]:
        """
        Analyze frame complexity for adaptive hiding capacity.

        Args:
            frame: Input frame

        Returns:
            Dictionary with complexity metrics
        """
        # Convert to grayscale for analysis
        if len(frame.shape) == 3:
            gray = (
                cv2.cvtColor(frame, cv2.COLOR_RGB2GRAY) if frame.shape[2] == 3 else frame[:, :, 0]
            )
        else:
            gray = frame

        # Calculate texture measures
        variance = np.var(gray)
        gradient_magnitude = np.mean(np.abs(np.gradient(gray.astype(np.float32))))

        # Normalize texture measure
        texture_measure = min(variance / 1000.0, 1.0)

        # Recommended capacity based on texture
        base_capacity = gray.size // 64  # Base capacity
        recommended_capacity = int(base_capacity * (0.5 + 0.5 * texture_measure))

        return {
            "variance": variance,
            "gradient_magnitude": gradient_magnitude,
            "texture_measure": texture_measure,
            "recommended_capacity": recommended_capacity,
        }

    def extract_from_frame(
        self, frame: np.ndarray, expected_length: int, frame_info: VideoFrameInfo
    ) -> bytes:
        """
        Extract hidden data from a video frame using DCT or LSB

        Args:
            frame: Video frame containing hidden data
            expected_length: Expected number of bytes to extract
            frame_info: Frame metadata information

        Returns:
            Extracted data bytes
        """
        if expected_length <= 0:
            return b""

        if self.use_dct and self.dct_utils is not None:
            return self._extract_from_frame_dct(frame, expected_length, frame_info)
        else:
            return self._extract_from_frame_lsb(frame, expected_length, frame_info)

    def _extract_from_frame_dct(
        self, frame: np.ndarray, expected_length: int, frame_info: VideoFrameInfo
    ) -> bytes:
        """
        Extract data from frame using DCT-based steganography

        Args:
            frame: Video frame containing hidden data
            expected_length: Expected number of bytes to extract
            frame_info: Frame metadata information

        Returns:
            Extracted data bytes
        """
        if frame.ndim != 3 or frame.shape[2] != 3:
            raise VideoFormatError("DCT steganography requires RGB frames with shape (H, W, 3)")

        # Convert to YUV and extract Y channel
        yuv_frame = self._rgb_to_yuv(frame.astype(np.float32))
        y_channel = yuv_frame[:, :, 0]

        # Split into 8x8 blocks
        blocks = self.dct_utils.split_into_blocks(y_channel)

        # Generate same coefficient selection as hiding
        if self.password:
            frame_seed = (self.seed + frame_info.frame_number) % (2**32)
            coeffs_to_use = self.coeff_selector.get_randomized_coefficients(
                self.password, frame_seed, self.coefficients_per_block
            )
        else:
            coeffs_to_use = self.coeff_selector.get_middle_frequencies(self.coefficients_per_block)

        # For error correction, we need to extract more data than expected
        # We need at least 1 byte for EC flag + potentially 4 bytes for length + EC overhead
        if self.error_corrector:
            # Extract more data to account for error correction overhead
            # Container: EC_FLAG(1) + ORIGINAL_LEN(4) + EC_DATA
            # Conservative estimate: 5 bytes header + 4x data for EC overhead
            estimated_encoded_length = expected_length * 5 + 10
        else:
            # Just EC_FLAG(1) + data
            estimated_encoded_length = expected_length + 1

        # Extract bits from blocks
        extracted_bits = []
        bits_needed = estimated_encoded_length * 8

        for block_row in range(len(blocks)):
            for block_col in range(len(blocks[block_row])):
                if len(extracted_bits) >= bits_needed:
                    break

                block = blocks[block_row][block_col]

                # Apply DCT
                dct_coeffs = self.dct_utils.apply_dct(block)

                # Get quantization matrix for this block
                quant_matrix = self.quant_matrix.get_adaptive_matrix(block, self.dct_quality)

                # Extract bits from selected coefficients using advanced QIM
                for coeff_pos in coeffs_to_use:
                    if len(extracted_bits) >= bits_needed:
                        break

                    row, col = coeff_pos
                    current_coeff = dct_coeffs[row, col]

                    if self.qim_algorithm:
                        # Use advanced QIM algorithm for extraction
                        try:
                            if hasattr(self.qim_algorithm, "extract_bits"):
                                # Multi-level QIM - extract multiple bits
                                extracted_tuple = self.qim_algorithm.extract_bits(current_coeff)
                                for bit in extracted_tuple:
                                    if len(extracted_bits) < bits_needed:
                                        extracted_bits.append(bit)

                            elif hasattr(self.qim_algorithm, "extract_bit_adaptive"):
                                # Adaptive QIM
                                extracted_bit = self.qim_algorithm.extract_bit_adaptive(
                                    current_coeff, position=(row, col)
                                )
                                extracted_bits.append(extracted_bit)

                            else:
                                # Standard QIM
                                extracted_bit = self.qim_algorithm.extract_bit(current_coeff)
                                extracted_bits.append(extracted_bit)

                        except QIMError as e:
                            logger.warning(f"QIM extraction failed: {e}, using fallback")
                            # Fallback to basic QIM
                            quant_step = quant_matrix[row, col]
                            quantized = round(current_coeff / quant_step)
                            extracted_bit = quantized % 2
                            extracted_bits.append(extracted_bit)

                    else:
                        # Fallback to basic QIM if no advanced algorithm available
                        quant_step = quant_matrix[row, col]
                        quantized = round(current_coeff / quant_step)
                        extracted_bit = quantized % 2
                        extracted_bits.append(extracted_bit)

        # Convert bits to bytes
        extracted_encoded_data = bytearray()
        for i in range(0, len(extracted_bits), 8):
            if i + 8 <= len(extracted_bits):
                byte_bits = extracted_bits[i : i + 8]
                byte_value = sum(bit * (2 ** (7 - j)) for j, bit in enumerate(byte_bits))
                extracted_encoded_data.append(byte_value)

        # Parse container format and apply error correction if needed
        container_data = bytes(extracted_encoded_data)

        if len(container_data) < 1:
            logger.error("No data extracted")
            return b""

        # Check EC flag (first byte)
        ec_flag = container_data[0]

        if ec_flag == 1:  # Error correction was used
            if not self.error_corrector:
                logger.warning("Data was encoded with error correction but decoder not available")
                return container_data[1 : expected_length + 1] if len(container_data) > 1 else b""

            if len(container_data) < 5:  # Need at least flag + length
                logger.error("Container too short for error correction metadata")
                return b""

            try:
                # Extract original length
                original_length = struct.unpack("<I", container_data[1:5])[0]
                ec_data = container_data[5:]

                # Try different quality levels to decode
                for quality_level in ["medium", "high", "low"]:
                    try:
                        decoded_data = self.error_corrector.decode(ec_data, quality=quality_level)

                        # Check if we got the expected length
                        if len(decoded_data) == original_length == expected_length:
                            logger.debug(
                                f"Successfully decoded with {quality_level} quality error correction"
                            )
                            return decoded_data
                        elif len(decoded_data) >= expected_length:
                            # Truncate to expected length
                            return decoded_data[:expected_length]

                    except (ErrorCorrectionError, UnicodeDecodeError, struct.error):
                        continue

                # If all error correction attempts failed, try raw data
                logger.warning("Error correction decoding failed, trying raw data")
                return ec_data[:expected_length] if len(ec_data) >= expected_length else ec_data

            except Exception as e:
                logger.warning(f"Error correction parsing failed: {e}, using raw data")
                return container_data[1 : expected_length + 1] if len(container_data) > 1 else b""

        else:  # No error correction was used (ec_flag == 0)
            # Return raw data after EC flag
            raw_data = container_data[1:]
            return raw_data[:expected_length] if len(raw_data) >= expected_length else raw_data

    def _extract_from_frame_lsb(
        self, frame: np.ndarray, expected_length: int, frame_info: VideoFrameInfo
    ) -> bytes:
        """
        Extract data from frame using traditional LSB steganography

        Args:
            frame: Video frame containing hidden data
            expected_length: Expected number of bytes to extract
            frame_info: Frame metadata information

        Returns:
            Extracted data bytes
        """
        height, width = frame.shape[:2]
        channels = frame.shape[2] if len(frame.shape) == 3 else 1

        # Generate same randomized pixel order as hiding
        if self.password and self.seed:
            pixel_indices = list(range(width * height))
            frame_seed = (self.seed + frame_info.frame_number) % (2**32)
            np.random.seed(frame_seed)
            np.random.shuffle(pixel_indices)
        else:
            pixel_indices = list(range(width * height))

        # Extract bits
        extracted_bits = []
        bits_needed = expected_length * 8
        bits_per_pixel = min(self.max_bits_per_pixel, bits_needed // (width * height) + 1)

        for pixel_idx in pixel_indices:
            if len(extracted_bits) >= bits_needed:
                break

            row = pixel_idx // width
            col = pixel_idx % width

            # Process each channel
            for channel in range(channels):
                if len(extracted_bits) >= bits_needed:
                    break

                # Get pixel value
                pixel_value = frame[row, col, channel] if channels > 1 else frame[row, col]

                # Extract bits_per_pixel bits
                for bit_pos in range(bits_per_pixel):
                    if len(extracted_bits) >= bits_needed:
                        break

                    extracted_bits.append(pixel_value & 1)

        # Convert bits to bytes
        extracted_data = bytearray()
        for i in range(0, len(extracted_bits), 8):
            if i + 8 <= len(extracted_bits):
                byte_bits = extracted_bits[i : i + 8]
                byte_value = sum(bit * (2 ** (7 - j)) for j, bit in enumerate(byte_bits))
                extracted_data.append(byte_value)

        return bytes(extracted_data[:expected_length])

    def distribute_data(
        self, secret_data: bytes, frames: List[np.ndarray], video_info: Dict[str, Any]
    ) -> List[VideoFrameInfo]:
        """
        Distribute secret data across video frames optimally

        Args:
            secret_data: Data to hide
            frames: List of video frames
            video_info: Video metadata

        Returns:
            List of VideoFrameInfo with data distribution plan
        """
        frame_infos = []
        total_video_capacity = 0

        # Analyze each frame
        for i, frame in enumerate(frames):
            frame_capacity = self.calculate_frame_capacity(frame)
            frame_type = "I" if i % 30 == 0 else "P"  # Simplified frame type detection

            # Calculate scene complexity (using frame variance as proxy)
            complexity = np.var(frame.astype(np.float64)) / 255.0 if frame.size > 0 else 0.0

            frame_info = VideoFrameInfo(
                frame_number=i,
                frame_type=frame_type,
                size=(frame.shape[1], frame.shape[0]) if frame.size > 0 else (0, 0),
                complexity=complexity,
                capacity=frame_capacity,
            )

            frame_infos.append(frame_info)
            total_video_capacity += frame_capacity

        # Check if we have enough capacity
        video_data_size = int(len(secret_data) * self.layer_weights.get("video_frames", 1.0))
        if total_video_capacity < video_data_size:
            raise CapacityError(video_data_size, total_video_capacity, "video frames")

        # Distribute data across frames
        remaining_data = video_data_size
        data_offset = 0

        for frame_info in frame_infos:
            if remaining_data <= 0:
                break

            # Allocate data to this frame
            allocated = min(frame_info.capacity, remaining_data)
            frame_info.data_offset = data_offset
            frame_info.data_length = allocated

            data_offset += allocated
            remaining_data -= allocated

        logger.info(f"Distributed {video_data_size} bytes across {len(frames)} frames")
        return frame_infos

    def prepare_data_for_hiding(self, secret_data: bytes) -> bytes:
        """
        Prepare secret data for hiding by adding headers and error correction

        Args:
            secret_data: Raw secret data

        Returns:
            Prepared data with headers and error correction
        """
        # Add data length header (4 bytes)
        length_header = struct.pack(">I", len(secret_data))

        # Add magic marker to verify extraction
        magic_marker = b"VSTG"  # Video STeGanography marker

        # Combine all data
        prepared_data = magic_marker + length_header + secret_data + self.eof_marker

        # Add simple checksum for integrity verification
        checksum = sum(secret_data) & 0xFFFFFFFF
        checksum_bytes = struct.pack(">I", checksum)

        prepared_data = prepared_data + checksum_bytes

        logger.debug(f"Prepared data: {len(secret_data)} bytes -> {len(prepared_data)} bytes")
        return prepared_data

    def extract_prepared_data(self, raw_data: bytes) -> bytes:
        """
        Extract and verify prepared data

        Args:
            raw_data: Raw extracted data

        Returns:
            Original secret data
        """
        try:
            # Check magic marker
            if len(raw_data) < 8 or raw_data[:4] != b"VSTG":
                raise ExtractionError("Invalid video steganography marker")

            # Extract length
            length = struct.unpack(">I", raw_data[4:8])[0]

            if length <= 0 or length > len(raw_data) - 16:  # 4+4+4+4 bytes overhead
                raise ExtractionError("Invalid data length in video steganography header")

            # Extract secret data
            secret_data = raw_data[8 : 8 + length]

            # Verify EOF marker
            eof_start = 8 + length
            if raw_data[eof_start : eof_start + 4] != self.eof_marker:
                logger.warning("EOF marker not found or corrupted")

            # Verify checksum
            checksum_start = eof_start + 4
            if len(raw_data) >= checksum_start + 4:
                expected_checksum = struct.unpack(
                    ">I", raw_data[checksum_start : checksum_start + 4]
                )[0]
                actual_checksum = sum(secret_data) & 0xFFFFFFFF

                if expected_checksum != actual_checksum:
                    logger.warning("Checksum mismatch - data may be corrupted")

            logger.debug(f"Extracted data: {len(secret_data)} bytes")
            return secret_data

        except (struct.error, IndexError) as e:
            raise ExtractionError(f"Failed to extract prepared data: {e}")
