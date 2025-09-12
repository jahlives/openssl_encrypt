#!/usr/bin/env python3
"""
Video DCT Steganography Utilities

This module provides DCT-based (Discrete Cosine Transform) steganography utilities
for video files. It implements frequency domain data hiding that is compatible
with video compression, unlike spatial domain LSB techniques.

Key Features:
- 2D DCT/IDCT transforms for 8x8 blocks
- Adaptive quantization matrices
- Zigzag coefficient ordering
- Middle frequency coefficient selection
- Video quality metrics (PSNR, SSIM)
- Robust data embedding using QIM (Quantization Index Modulation)

This approach is compatible with video compression because it operates in the
same frequency domain used by video codecs like H.264 and H.265.
"""

import hashlib
import logging
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

# OpenCV for DCT operations
try:
    import cv2

    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False
    cv2 = None

# SciPy for additional signal processing (optional)
try:
    from scipy.fftpack import dct, idct

    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False

# Secure memory handling
try:
    from ..secure_memory import SecureBytes, secure_memzero
except ImportError:
    from openssl_encrypt.modules.secure_memory import SecureBytes, secure_memzero

# Set up module logger
logger = logging.getLogger(__name__)

# DCT Constants
DCT_BLOCK_SIZE = 8
MAX_PIXEL_VALUE = 255.0
EPSILON = 1e-10  # Numerical precision threshold

# Standard JPEG quantization tables (used as reference)
STANDARD_LUMINANCE_QT = np.array(
    [
        [16, 11, 10, 16, 24, 40, 51, 61],
        [12, 12, 14, 19, 26, 58, 60, 55],
        [14, 13, 16, 24, 40, 57, 69, 56],
        [14, 17, 22, 29, 51, 87, 80, 62],
        [18, 22, 37, 56, 68, 109, 103, 77],
        [24, 35, 55, 64, 81, 104, 113, 92],
        [49, 64, 78, 87, 103, 121, 120, 101],
        [72, 92, 95, 98, 112, 100, 103, 99],
    ],
    dtype=np.float64,
)

STANDARD_CHROMINANCE_QT = np.array(
    [
        [17, 18, 24, 47, 99, 99, 99, 99],
        [18, 21, 26, 66, 99, 99, 99, 99],
        [24, 26, 56, 99, 99, 99, 99, 99],
        [47, 66, 99, 99, 99, 99, 99, 99],
        [99, 99, 99, 99, 99, 99, 99, 99],
        [99, 99, 99, 99, 99, 99, 99, 99],
        [99, 99, 99, 99, 99, 99, 99, 99],
        [99, 99, 99, 99, 99, 99, 99, 99],
    ],
    dtype=np.float64,
)


class DCTSteganographyError(Exception):
    """Base exception for DCT steganography errors."""

    pass


class DCTBlock:
    """Represents an 8x8 DCT block with associated operations."""

    def __init__(self, data: np.ndarray):
        """
        Initialize DCT block.

        Args:
            data: 8x8 numpy array of pixel or coefficient data

        Raises:
            DCTSteganographyError: If data is not 8x8
        """
        if not isinstance(data, np.ndarray):
            raise DCTSteganographyError("DCT block data must be numpy array")

        if data.shape != (8, 8):
            raise DCTSteganographyError(f"DCT block must be 8x8, got {data.shape}")

        self.data = data.astype(np.float64)
        self._dct_coefficients = None
        self._is_transformed = False

    def apply_dct(self) -> np.ndarray:
        """Apply 2D DCT to the block."""
        if not CV2_AVAILABLE:
            raise DCTSteganographyError("OpenCV required for DCT operations")

        self._dct_coefficients = cv2.dct(self.data.astype(np.float64))
        self._is_transformed = True
        return self._dct_coefficients.copy()

    def apply_idct(self) -> np.ndarray:
        """Apply inverse 2D DCT to reconstruct the block."""
        if not CV2_AVAILABLE:
            raise DCTSteganographyError("OpenCV required for IDCT operations")

        if self._dct_coefficients is None:
            raise DCTSteganographyError("Must apply DCT before IDCT")

        reconstructed = cv2.idct(self._dct_coefficients.astype(np.float64))
        self._is_transformed = False
        return reconstructed

    def get_coefficient(self, row: int, col: int) -> float:
        """Get specific DCT coefficient."""
        if self._dct_coefficients is None:
            raise DCTSteganographyError("Must apply DCT before accessing coefficients")

        if not (0 <= row < 8 and 0 <= col < 8):
            raise DCTSteganographyError(f"Invalid coefficient position: ({row}, {col})")

        return self._dct_coefficients[row, col]

    def set_coefficient(self, row: int, col: int, value: float):
        """Set specific DCT coefficient."""
        if self._dct_coefficients is None:
            raise DCTSteganographyError("Must apply DCT before modifying coefficients")

        if not (0 <= row < 8 and 0 <= col < 8):
            raise DCTSteganographyError(f"Invalid coefficient position: ({row}, {col})")

        self._dct_coefficients[row, col] = value


class VideoDCTUtils:
    """Core DCT utilities for video steganography."""

    def __init__(self):
        """Initialize DCT utilities."""
        if not CV2_AVAILABLE:
            raise DCTSteganographyError("OpenCV required for DCT operations")

    def apply_dct(self, block: np.ndarray) -> np.ndarray:
        """
        Apply 2D DCT to 8x8 block.

        Args:
            block: 8x8 numpy array

        Returns:
            8x8 array of DCT coefficients

        Raises:
            DCTSteganographyError: If block is invalid
        """
        if not isinstance(block, np.ndarray):
            raise DCTSteganographyError("Input must be numpy array")

        if block.shape != (8, 8):
            raise DCTSteganographyError(f"Block must be 8x8, got {block.shape}")

        # Convert to float64 for precision
        float_block = block.astype(np.float64)

        # Apply 2D DCT
        dct_coefficients = cv2.dct(float_block)

        return dct_coefficients

    def apply_idct(self, coefficients: np.ndarray) -> np.ndarray:
        """
        Apply inverse 2D DCT to reconstruct block.

        Args:
            coefficients: 8x8 array of DCT coefficients

        Returns:
            8x8 reconstructed pixel block

        Raises:
            DCTSteganographyError: If coefficients are invalid
        """
        if not isinstance(coefficients, np.ndarray):
            raise DCTSteganographyError("Coefficients must be numpy array")

        if coefficients.shape != (8, 8):
            raise DCTSteganographyError(f"Coefficients must be 8x8, got {coefficients.shape}")

        # Apply inverse 2D DCT
        reconstructed = cv2.idct(coefficients.astype(np.float64))

        return reconstructed

    def split_into_blocks(self, frame: np.ndarray) -> List[List[np.ndarray]]:
        """
        Split frame into 8x8 blocks.

        Args:
            frame: Input frame (H, W) or (H, W, C)

        Returns:
            2D list of 8x8 blocks
        """
        if len(frame.shape) == 3:
            # Multi-channel frame - process first channel only
            frame = frame[:, :, 0]

        height, width = frame.shape

        # Pad frame to multiple of 8
        pad_h = (8 - height % 8) % 8
        pad_w = (8 - width % 8) % 8

        if pad_h > 0 or pad_w > 0:
            frame = np.pad(frame, ((0, pad_h), (0, pad_w)), mode="edge")

        height, width = frame.shape
        blocks = []

        for i in range(0, height, 8):
            block_row = []
            for j in range(0, width, 8):
                block = frame[i : i + 8, j : j + 8]
                block_row.append(block)
            blocks.append(block_row)

        return blocks

    def reconstruct_from_blocks(
        self, blocks: List[List[np.ndarray]], target_shape: Tuple[int, int]
    ) -> np.ndarray:
        """
        Reconstruct frame from 8x8 blocks.

        Args:
            blocks: 2D list of 8x8 blocks
            target_shape: Desired output shape (H, W)

        Returns:
            Reconstructed frame
        """
        if not blocks or not blocks[0]:
            raise DCTSteganographyError("Empty block list")

        # Calculate full size from blocks
        block_rows = len(blocks)
        block_cols = len(blocks[0])
        full_height = block_rows * 8
        full_width = block_cols * 8

        # Reconstruct full frame
        reconstructed = np.zeros((full_height, full_width), dtype=np.float64)

        for i, block_row in enumerate(blocks):
            for j, block in enumerate(block_row):
                start_row = i * 8
                start_col = j * 8
                reconstructed[start_row : start_row + 8, start_col : start_col + 8] = block

        # Crop to target shape
        target_h, target_w = target_shape
        reconstructed = reconstructed[:target_h, :target_w]

        return reconstructed


class QuantizationMatrix:
    """Generate and manage quantization matrices for DCT steganography."""

    def __init__(self):
        """Initialize quantization matrix generator."""
        pass

    def get_luminance_matrix(self, quality: int) -> np.ndarray:
        """
        Get luminance quantization matrix for given quality.

        Args:
            quality: Quality factor (1-100, higher = better quality)

        Returns:
            8x8 quantization matrix

        Raises:
            DCTSteganographyError: If quality is out of range
        """
        if not (1 <= quality <= 100):
            raise DCTSteganographyError(f"Quality must be 1-100, got {quality}")

        # Scale standard matrix based on quality
        if quality >= 50:
            scale = (100 - quality) / 50.0
        else:
            scale = 50.0 / quality

        # Apply scaling with minimum value of 1
        scaled_matrix = np.maximum(
            (STANDARD_LUMINANCE_QT * scale + 0.5).astype(np.int32), 1
        ).astype(np.float64)

        return scaled_matrix

    def get_chrominance_matrix(self, quality: int) -> np.ndarray:
        """
        Get chrominance quantization matrix for given quality.

        Args:
            quality: Quality factor (1-100)

        Returns:
            8x8 quantization matrix
        """
        if not (1 <= quality <= 100):
            raise DCTSteganographyError(f"Quality must be 1-100, got {quality}")

        # Scale standard matrix based on quality
        if quality >= 50:
            scale = (100 - quality) / 50.0
        else:
            scale = 50.0 / quality

        scaled_matrix = np.maximum(
            (STANDARD_CHROMINANCE_QT * scale + 0.5).astype(np.int32), 1
        ).astype(np.float64)

        return scaled_matrix

    def get_adaptive_matrix(self, block: np.ndarray, base_quality: int) -> np.ndarray:
        """
        Get adaptive quantization matrix based on block texture.

        Args:
            block: 8x8 image block
            base_quality: Base quality factor

        Returns:
            Adaptive quantization matrix
        """
        if block.shape != (8, 8):
            raise DCTSteganographyError(f"Block must be 8x8, got {block.shape}")

        # Calculate block texture using variance
        block_variance = np.var(block)

        # Adjust quality based on texture
        # High texture blocks can hide more data
        texture_factor = min(block_variance / 100.0, 1.0)  # Normalize to [0, 1]
        adaptive_quality = base_quality + int(texture_factor * 20)  # Up to +20 quality
        adaptive_quality = min(adaptive_quality, 100)

        return self.get_luminance_matrix(adaptive_quality)


class CoefficientSelector:
    """Select and manage DCT coefficients for data hiding."""

    def __init__(self):
        """Initialize coefficient selector."""
        self._zigzag_pattern = self._generate_zigzag_pattern()

    def _generate_zigzag_pattern(self) -> List[Tuple[int, int]]:
        """Generate zigzag scanning pattern for 8x8 DCT block."""
        zigzag = []

        # Zigzag pattern for 8x8 block (standard JPEG ordering)
        pattern = [
            (0, 0),
            (0, 1),
            (1, 0),
            (2, 0),
            (1, 1),
            (0, 2),
            (0, 3),
            (1, 2),
            (2, 1),
            (3, 0),
            (4, 0),
            (3, 1),
            (2, 2),
            (1, 3),
            (0, 4),
            (0, 5),
            (1, 4),
            (2, 3),
            (3, 2),
            (4, 1),
            (5, 0),
            (6, 0),
            (5, 1),
            (4, 2),
            (3, 3),
            (2, 4),
            (1, 5),
            (0, 6),
            (0, 7),
            (1, 6),
            (2, 5),
            (3, 4),
            (4, 3),
            (5, 2),
            (6, 1),
            (7, 0),
            (7, 1),
            (6, 2),
            (5, 3),
            (4, 4),
            (3, 5),
            (2, 6),
            (1, 7),
            (2, 7),
            (3, 6),
            (4, 5),
            (5, 4),
            (6, 3),
            (7, 2),
            (7, 3),
            (6, 4),
            (5, 5),
            (4, 6),
            (3, 7),
            (4, 7),
            (5, 6),
            (6, 5),
            (7, 4),
            (7, 5),
            (6, 6),
            (5, 7),
            (6, 7),
            (7, 6),
            (7, 7),
        ]

        return pattern

    def get_zigzag_pattern(self) -> List[Tuple[int, int]]:
        """Get zigzag scanning pattern."""
        return self._zigzag_pattern.copy()

    def get_middle_frequencies(self, count: Optional[int] = None) -> List[Tuple[int, int]]:
        """
        Get middle frequency coefficients suitable for data hiding.

        Args:
            count: Number of coefficients to return (default: auto-select)

        Returns:
            List of (row, col) positions for middle frequency coefficients
        """
        if count is not None and (count <= 0 or count > 64):
            raise DCTSteganographyError(f"Count must be 1-64, got {count}")

        # Select middle frequencies (avoid DC and high frequencies)
        # Skip DC coefficient (0,0) and last few high-frequency coefficients
        available_coeffs = list(range(10, 60))  # Coefficients 10-59 in zigzag order
        default_count = 15  # Default to 15 coefficients for good quality/capacity balance

        if count is not None:
            middle_freq_indices = available_coeffs[:count]
        else:
            middle_freq_indices = available_coeffs[:default_count]

        # Convert indices to (row, col) positions
        middle_freq_positions = [self._zigzag_pattern[i] for i in middle_freq_indices]

        return middle_freq_positions

    def get_randomized_coefficients(
        self, password: str, seed: int = 0, count: int = 15
    ) -> List[Tuple[int, int]]:
        """
        Get randomized coefficient selection based on password.

        Args:
            password: Password for randomization
            seed: Additional seed value
            count: Number of coefficients to select

        Returns:
            List of randomized coefficient positions
        """
        # Create deterministic seed from password
        password_hash = hashlib.sha256(password.encode()).digest()
        password_seed = struct.unpack(">I", password_hash[:4])[0]
        combined_seed = (password_seed + seed) % (2**32)

        # Get middle frequency positions
        middle_freq = self.get_middle_frequencies()

        # Randomize selection
        rng = np.random.RandomState(combined_seed)
        rng.shuffle(middle_freq)

        return middle_freq[:count]


class QualityMetrics:
    """Calculate video quality metrics for steganography assessment."""

    def __init__(self):
        """Initialize quality metrics calculator."""
        pass

    def calculate_psnr(self, original: np.ndarray, modified: np.ndarray) -> float:
        """
        Calculate Peak Signal-to-Noise Ratio (PSNR).

        Args:
            original: Original frame
            modified: Modified frame

        Returns:
            PSNR value in dB (higher is better)

        Raises:
            DCTSteganographyError: If frames have different shapes
        """
        if original.shape != modified.shape:
            raise DCTSteganographyError(
                f"Frame shapes must match: {original.shape} vs {modified.shape}"
            )

        # Calculate Mean Squared Error
        mse = np.mean((original.astype(np.float64) - modified.astype(np.float64)) ** 2)

        # Handle identical frames
        if mse < EPSILON:
            return float("inf")

        # Calculate PSNR
        max_pixel_value = MAX_PIXEL_VALUE
        psnr = 20 * np.log10(max_pixel_value / np.sqrt(mse))

        return psnr

    def calculate_ssim(self, original: np.ndarray, modified: np.ndarray) -> float:
        """
        Calculate Structural Similarity Index (SSIM).

        Args:
            original: Original frame
            modified: Modified frame

        Returns:
            SSIM value [0, 1] (higher is better)

        Raises:
            DCTSteganographyError: If frames have different shapes
        """
        if original.shape != modified.shape:
            raise DCTSteganographyError(
                f"Frame shapes must match: {original.shape} vs {modified.shape}"
            )

        # Convert to grayscale if needed
        if len(original.shape) == 3:
            if original.shape[2] == 3:  # RGB
                original = cv2.cvtColor(original, cv2.COLOR_RGB2GRAY)
                modified = cv2.cvtColor(modified, cv2.COLOR_RGB2GRAY)

        # Convert to float
        img1 = original.astype(np.float64)
        img2 = modified.astype(np.float64)

        # SSIM parameters
        K1 = 0.01
        K2 = 0.03
        L = 255  # Dynamic range

        C1 = (K1 * L) ** 2
        C2 = (K2 * L) ** 2

        # Calculate means
        mu1 = np.mean(img1)
        mu2 = np.mean(img2)

        # Calculate variances and covariance
        sigma1_sq = np.var(img1)
        sigma2_sq = np.var(img2)
        sigma12 = np.mean((img1 - mu1) * (img2 - mu2))

        # Calculate SSIM
        numerator = (2 * mu1 * mu2 + C1) * (2 * sigma12 + C2)
        denominator = (mu1**2 + mu2**2 + C1) * (sigma1_sq + sigma2_sq + C2)

        ssim = numerator / denominator

        return ssim

    def calculate_mse(self, original: np.ndarray, modified: np.ndarray) -> float:
        """
        Calculate Mean Squared Error between frames.

        Args:
            original: Original frame
            modified: Modified frame

        Returns:
            MSE value
        """
        if original.shape != modified.shape:
            raise DCTSteganographyError(
                f"Frame shapes must match: {original.shape} vs {modified.shape}"
            )

        mse = np.mean((original.astype(np.float64) - modified.astype(np.float64)) ** 2)
        return mse


def is_dct_steganography_available() -> bool:
    """Check if DCT steganography dependencies are available."""
    return CV2_AVAILABLE


# Module initialization
if not CV2_AVAILABLE:
    logger.warning("OpenCV not available - DCT steganography disabled")
else:
    logger.debug("DCT steganography utilities initialized successfully")
