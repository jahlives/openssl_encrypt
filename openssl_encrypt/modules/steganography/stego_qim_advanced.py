"""
Advanced Quantization Index Modulation (QIM) algorithms for robust steganography.

This module implements sophisticated QIM techniques that provide robust data
embedding in DCT coefficients, designed to survive video compression and
various distortions while maintaining high embedding capacity and low distortion.
"""

import logging
import math
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

# Set up module logger
logger = logging.getLogger(__name__)


class QIMError(Exception):
    """Exception raised for QIM algorithm errors."""

    pass


class UniformQIM:
    """
    Uniform Quantization Index Modulation for robust bit embedding.

    This is the basic QIM algorithm that uses uniform quantization
    with even/odd index mapping for bit embedding.
    """

    def __init__(self, quantization_step: float = 8.0, embedding_strength: float = 1.0):
        """
        Initialize uniform QIM.

        Args:
            quantization_step: Quantization step size (higher = more robust, more distortion)
            embedding_strength: Embedding strength multiplier
        """
        if quantization_step <= 0:
            raise QIMError("Quantization step must be positive")
        if embedding_strength <= 0:
            raise QIMError("Embedding strength must be positive")

        self.quantization_step = quantization_step
        self.embedding_strength = embedding_strength

        logger.debug(
            f"Initialized UniformQIM with step={quantization_step}, strength={embedding_strength}"
        )

    def embed_bit(self, coefficient: float, bit: int) -> float:
        """
        Embed a single bit in a coefficient using uniform QIM.

        Args:
            coefficient: Original DCT coefficient
            bit: Bit to embed (0 or 1)

        Returns:
            Modified coefficient with embedded bit
        """
        if bit not in [0, 1]:
            raise QIMError(f"Bit must be 0 or 1, got {bit}")

        # Quantize coefficient
        quantized_index = round(coefficient / self.quantization_step)

        # Adjust index to match desired bit parity
        if (quantized_index % 2) != bit:
            # Choose direction that minimizes distortion
            original_quantized = quantized_index * self.quantization_step

            # Try both directions
            option1 = quantized_index + 1
            option2 = quantized_index - 1

            dist1 = abs((option1 * self.quantization_step) - coefficient)
            dist2 = abs((option2 * self.quantization_step) - coefficient)

            # Choose the option that gives us the right parity and minimum distortion
            if (option1 % 2) == bit and (option2 % 2) != bit:
                quantized_index = option1
            elif (option2 % 2) == bit and (option1 % 2) != bit:
                quantized_index = option2
            elif (option1 % 2) == bit and (option2 % 2) == bit:
                quantized_index = option1 if dist1 <= dist2 else option2
            else:
                # Neither gives us the right parity, adjust further
                quantized_index = quantized_index + (1 if bit == 1 else -1)

        # Convert back to coefficient value
        embedded_coefficient = quantized_index * self.quantization_step * self.embedding_strength

        return embedded_coefficient

    def extract_bit(self, coefficient: float) -> int:
        """
        Extract embedded bit from coefficient.

        Args:
            coefficient: Modified coefficient containing embedded bit

        Returns:
            Extracted bit (0 or 1)
        """
        # Quantize coefficient
        quantized_index = round(coefficient / (self.quantization_step * self.embedding_strength))

        # Extract bit from index parity
        return abs(quantized_index) % 2

    def calculate_distortion(self, original: float, embedded: float) -> float:
        """
        Calculate distortion between original and embedded coefficient.

        Args:
            original: Original coefficient value
            embedded: Embedded coefficient value

        Returns:
            Distortion measure (absolute difference)
        """
        return abs(embedded - original)


class AdaptiveQIM:
    """
    Adaptive Quantization Index Modulation that adjusts quantization based on
    coefficient characteristics and position in DCT block.
    """

    def __init__(self, base_quantization_step: float = 8.0, adaptation_factor: float = 1.2):
        """
        Initialize adaptive QIM.

        Args:
            base_quantization_step: Base quantization step
            adaptation_factor: Factor for adapting quantization step
        """
        if base_quantization_step <= 0:
            raise QIMError("Base quantization step must be positive")
        if adaptation_factor <= 0:
            raise QIMError("Adaptation factor must be positive")

        self.base_quantization_step = base_quantization_step
        self.adaptation_factor = adaptation_factor

        # Create perceptual weighting matrix for 8x8 DCT blocks
        self.perceptual_weights = self._create_perceptual_weights()

        logger.debug(
            f"Initialized AdaptiveQIM with base_step={base_quantization_step}, factor={adaptation_factor}"
        )

    def _create_perceptual_weights(self) -> np.ndarray:
        """Create perceptual weighting matrix for DCT coefficients."""
        # Based on JPEG quantization table concepts
        weights = np.array(
            [
                [1.0, 1.2, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0],
                [1.2, 1.4, 1.8, 2.2, 2.8, 3.2, 3.8, 4.2],
                [1.5, 1.8, 2.2, 2.8, 3.2, 3.8, 4.2, 4.8],
                [2.0, 2.2, 2.8, 3.2, 3.8, 4.2, 4.8, 5.2],
                [2.5, 2.8, 3.2, 3.8, 4.2, 4.8, 5.2, 5.8],
                [3.0, 3.2, 3.8, 4.2, 4.8, 5.2, 5.8, 6.2],
                [3.5, 3.8, 4.2, 4.8, 5.2, 5.8, 6.2, 6.8],
                [4.0, 4.2, 4.8, 5.2, 5.8, 6.2, 6.8, 7.2],
            ]
        )
        return weights

    def get_adaptive_step(self, coefficient: float, position: Tuple[int, int]) -> float:
        """
        Get adaptive quantization step for coefficient at given position.

        Args:
            coefficient: DCT coefficient value
            position: Position in DCT block (row, col)

        Returns:
            Adaptive quantization step
        """
        row, col = position

        # Ensure position is within bounds
        row = max(0, min(7, row))
        col = max(0, min(7, col))

        # Get perceptual weight for this position
        perceptual_weight = self.perceptual_weights[row, col]

        # Adapt based on coefficient magnitude
        magnitude_factor = 1.0 + (abs(coefficient) / 100.0) * 0.5

        # Calculate adaptive step
        adaptive_step = self.base_quantization_step * perceptual_weight * magnitude_factor

        return adaptive_step

    def embed_bit_adaptive(self, coefficient: float, bit: int, position: Tuple[int, int]) -> float:
        """
        Embed bit using adaptive quantization.

        Args:
            coefficient: Original coefficient
            bit: Bit to embed (0 or 1)
            position: Position in DCT block

        Returns:
            Modified coefficient
        """
        if bit not in [0, 1]:
            raise QIMError(f"Bit must be 0 or 1, got {bit}")

        adaptive_step = self.get_adaptive_step(coefficient, position)

        # Use uniform QIM with adaptive step
        uniform_qim = UniformQIM(quantization_step=adaptive_step)
        return uniform_qim.embed_bit(coefficient, bit)

    def extract_bit_adaptive(self, coefficient: float, position: Tuple[int, int]) -> int:
        """
        Extract bit using adaptive quantization.

        Args:
            coefficient: Modified coefficient
            position: Position in DCT block

        Returns:
            Extracted bit
        """
        adaptive_step = self.get_adaptive_step(coefficient, position)

        # Use uniform QIM with adaptive step
        uniform_qim = UniformQIM(quantization_step=adaptive_step)
        return uniform_qim.extract_bit(coefficient)


class DistortionCompensatedQIM:
    """
    Distortion-Compensated QIM that tries to minimize embedding distortion
    while maintaining robustness.
    """

    def __init__(
        self,
        quantization_step: float = 8.0,
        compensation_factor: float = 0.5,
        max_compensation: float = 4.0,
    ):
        """
        Initialize distortion-compensated QIM.

        Args:
            quantization_step: Base quantization step
            compensation_factor: Factor for distortion compensation (0-1)
            max_compensation: Maximum compensation allowed
        """
        if quantization_step <= 0:
            raise QIMError("Quantization step must be positive")
        if not 0 <= compensation_factor <= 1:
            raise QIMError("Compensation factor must be between 0 and 1")

        self.quantization_step = quantization_step
        self.compensation_factor = compensation_factor
        self.max_compensation = max_compensation

        # Base QIM for comparison
        self.base_qim = UniformQIM(quantization_step)

        logger.debug(
            f"Initialized DistortionCompensatedQIM with step={quantization_step}, "
            f"compensation={compensation_factor}"
        )

    def predict_distortion(self, coefficient: float, bit: int) -> float:
        """
        Predict distortion for embedding a bit in coefficient.

        Args:
            coefficient: Original coefficient
            bit: Bit to embed

        Returns:
            Predicted distortion
        """
        # Embed using base QIM
        embedded = self.base_qim.embed_bit(coefficient, bit)

        # Calculate and return distortion
        return self.base_qim.calculate_distortion(coefficient, embedded)

    def embed_bit_compensated(self, coefficient: float, bit: int) -> float:
        """
        Embed bit with distortion compensation.

        Args:
            coefficient: Original coefficient
            bit: Bit to embed

        Returns:
            Compensated embedded coefficient
        """
        if bit not in [0, 1]:
            raise QIMError(f"Bit must be 0 or 1, got {bit}")

        # Get regular embedding result
        regular_embedded = self.base_qim.embed_bit(coefficient, bit)
        regular_distortion = abs(regular_embedded - coefficient)

        # Calculate compensation
        compensation = min(regular_distortion * self.compensation_factor, self.max_compensation)

        # Apply compensation in direction that reduces distortion
        if regular_embedded > coefficient:
            compensated = regular_embedded - compensation
        else:
            compensated = regular_embedded + compensation

        # Ensure the bit can still be extracted correctly
        if self.extract_bit(compensated) != bit:
            # Compensation would break extraction, use regular embedding
            return regular_embedded

        return compensated

    def embed_bit(self, coefficient: float, bit: int) -> float:
        """Embed bit using base QIM (for compatibility)."""
        return self.base_qim.embed_bit(coefficient, bit)

    def extract_bit(self, coefficient: float) -> int:
        """Extract bit using base QIM."""
        return self.base_qim.extract_bit(coefficient)


class MultiLevelQIM:
    """
    Multi-Level QIM for embedding multiple bits per coefficient.
    Increases embedding capacity at the cost of some robustness.
    """

    def __init__(self, quantization_step: float = 16.0, bits_per_coefficient: int = 2):
        """
        Initialize multi-level QIM.

        Args:
            quantization_step: Quantization step (should be larger for multi-level)
            bits_per_coefficient: Number of bits to embed per coefficient (1-4)
        """
        if quantization_step <= 0:
            raise QIMError("Quantization step must be positive")
        if not 1 <= bits_per_coefficient <= 4:
            raise QIMError("Bits per coefficient must be between 1 and 4")

        self.quantization_step = quantization_step
        self.bits_per_coefficient = bits_per_coefficient
        self.num_levels = 2**bits_per_coefficient

        logger.debug(
            f"Initialized MultiLevelQIM with step={quantization_step}, "
            f"bits_per_coeff={bits_per_coefficient}, levels={self.num_levels}"
        )

    def embed_bits(self, coefficient: float, bits: Tuple[int, ...]) -> float:
        """
        Embed multiple bits in a single coefficient.

        Args:
            coefficient: Original coefficient
            bits: Tuple of bits to embed

        Returns:
            Modified coefficient
        """
        if len(bits) != self.bits_per_coefficient:
            raise QIMError(f"Expected {self.bits_per_coefficient} bits, got {len(bits)}")

        for bit in bits:
            if bit not in [0, 1]:
                raise QIMError(f"All bits must be 0 or 1, got {bits}")

        # Convert bits to decimal value
        decimal_value = sum(bit * (2**i) for i, bit in enumerate(reversed(bits)))

        # Quantize coefficient
        quantized_index = round(coefficient / self.quantization_step)

        # Adjust index to encode the decimal value
        target_remainder = decimal_value
        current_remainder = abs(quantized_index) % self.num_levels

        if current_remainder != target_remainder:
            # Find the closest indices with correct remainder
            # Check both positive and negative directions
            best_index = quantized_index
            min_distortion = float("inf")

            for direction in [-1, 1]:
                test_index = quantized_index
                for step in range(self.num_levels):
                    test_index += direction
                    if abs(test_index) % self.num_levels == target_remainder:
                        test_distortion = abs(test_index * self.quantization_step - coefficient)
                        if test_distortion < min_distortion:
                            min_distortion = test_distortion
                            best_index = test_index
                        break

            quantized_index = best_index

        # Convert back to coefficient value
        embedded_coefficient = quantized_index * self.quantization_step

        return embedded_coefficient

    def extract_bits(self, coefficient: float) -> Tuple[int, ...]:
        """
        Extract multiple bits from coefficient.

        Args:
            coefficient: Modified coefficient

        Returns:
            Tuple of extracted bits
        """
        # Quantize coefficient
        quantized_index = round(coefficient / self.quantization_step)

        # Get remainder which encodes the bits
        remainder = abs(quantized_index) % self.num_levels

        # Convert decimal back to bits
        bits = []
        for i in range(self.bits_per_coefficient):
            bit = (remainder >> (self.bits_per_coefficient - 1 - i)) & 1
            bits.append(bit)

        return tuple(bits)


class QIMAnalyzer:
    """
    Analyzer for QIM algorithm performance and optimization.
    """

    def __init__(self):
        """Initialize QIM analyzer."""
        logger.debug("Initialized QIM analyzer")

    def analyze_robustness(
        self, qim_algorithm, noise_levels: List[float], num_trials: int = 100
    ) -> List[float]:
        """
        Analyze robustness of QIM algorithm to different noise levels.

        Args:
            qim_algorithm: QIM algorithm to test
            noise_levels: List of noise standard deviations to test
            num_trials: Number of trials per noise level

        Returns:
            List of success rates for each noise level
        """
        results = []

        for noise_level in noise_levels:
            success_count = 0

            for trial in range(num_trials):
                # Generate random coefficient and bit
                coefficient = np.random.uniform(-50, 50)
                bit = np.random.randint(0, 2)

                try:
                    # Embed bit
                    if hasattr(qim_algorithm, "embed_bits"):
                        # Multi-level QIM
                        bits = tuple(
                            np.random.randint(0, 2)
                            for _ in range(qim_algorithm.bits_per_coefficient)
                        )
                        embedded = qim_algorithm.embed_bits(coefficient, bits)
                        # Add noise
                        noisy = embedded + np.random.normal(0, noise_level)
                        # Extract
                        extracted = qim_algorithm.extract_bits(noisy)
                        success = extracted == bits
                    else:
                        # Single-bit QIM
                        embedded = qim_algorithm.embed_bit(coefficient, bit)
                        # Add noise
                        noisy = embedded + np.random.normal(0, noise_level)
                        # Extract
                        extracted = qim_algorithm.extract_bit(noisy)
                        success = extracted == bit

                    if success:
                        success_count += 1

                except Exception as e:
                    logger.warning(f"Trial failed: {e}")
                    continue

            success_rate = success_count / num_trials
            results.append(success_rate)
            logger.debug(f"Noise level {noise_level}: {success_rate:.2%} success rate")

        return results

    def analyze_capacity(self, qim_algorithm, block_size: Tuple[int, int]) -> int:
        """
        Analyze embedding capacity of QIM algorithm.

        Args:
            qim_algorithm: QIM algorithm to analyze
            block_size: Size of coefficient block (height, width)

        Returns:
            Total embedding capacity in bits
        """
        height, width = block_size
        total_coefficients = height * width

        if hasattr(qim_algorithm, "bits_per_coefficient"):
            # Multi-level QIM
            capacity = total_coefficients * qim_algorithm.bits_per_coefficient
        else:
            # Single-bit QIM
            capacity = total_coefficients

        logger.debug(f"Capacity analysis: {capacity} bits for {total_coefficients} coefficients")
        return capacity

    def analyze_distortion(self, qim_algorithm, coefficients: np.ndarray) -> Dict[str, float]:
        """
        Analyze distortion characteristics of QIM embedding.

        Args:
            qim_algorithm: QIM algorithm to analyze
            coefficients: Test coefficients

        Returns:
            Dictionary with distortion statistics
        """
        distortions = []
        flat_coeffs = coefficients.flatten()

        for coeff in flat_coeffs:
            try:
                if hasattr(qim_algorithm, "embed_bits"):
                    # Multi-level QIM
                    bits = tuple(
                        np.random.randint(0, 2) for _ in range(qim_algorithm.bits_per_coefficient)
                    )
                    embedded = qim_algorithm.embed_bits(coeff, bits)
                else:
                    # Single-bit QIM
                    bit = np.random.randint(0, 2)
                    embedded = qim_algorithm.embed_bit(coeff, bit)

                distortion = abs(embedded - coeff)
                distortions.append(distortion)

            except Exception as e:
                logger.warning(f"Distortion analysis failed for coefficient {coeff}: {e}")
                continue

        if not distortions:
            return {"mean_distortion": 0, "max_distortion": 0, "std_distortion": 0}

        stats = {
            "mean_distortion": np.mean(distortions),
            "max_distortion": np.max(distortions),
            "std_distortion": np.std(distortions),
        }

        logger.debug(
            f"Distortion analysis: mean={stats['mean_distortion']:.2f}, "
            f"max={stats['max_distortion']:.2f}, std={stats['std_distortion']:.2f}"
        )

        return stats

    def find_optimal_quantization_step(
        self, target_robustness: float = 0.8, max_distortion: float = 10.0, noise_level: float = 1.0
    ) -> float:
        """
        Find optimal quantization step for given requirements.

        Args:
            target_robustness: Target robustness level (0-1)
            max_distortion: Maximum acceptable distortion
            noise_level: Expected noise level

        Returns:
            Optimal quantization step
        """
        # Binary search for optimal step
        min_step = 2.0
        max_step = 32.0

        for iteration in range(10):  # Limit iterations
            current_step = (min_step + max_step) / 2.0

            # Test current step
            qim = UniformQIM(quantization_step=current_step)
            robustness = self.analyze_robustness(qim, [noise_level], num_trials=50)[0]

            # Test distortion
            test_coeffs = np.random.uniform(-20, 20, (8, 8))
            distortion_stats = self.analyze_distortion(qim, test_coeffs)

            if (
                robustness >= target_robustness
                and distortion_stats["mean_distortion"] <= max_distortion
            ):
                # Current step is good, try smaller
                max_step = current_step
            else:
                # Need larger step
                min_step = current_step

        optimal_step = (min_step + max_step) / 2.0
        logger.debug(f"Optimal quantization step: {optimal_step:.2f}")
        return optimal_step

    def compare_algorithms(self, algorithms: List) -> List[Dict[str, Any]]:
        """
        Compare performance of different QIM algorithms.

        Args:
            algorithms: List of QIM algorithms to compare

        Returns:
            List of performance comparison results
        """
        results = []

        # Test parameters
        noise_level = 1.5
        test_coeffs = np.random.uniform(-30, 30, (8, 8))

        for i, algorithm in enumerate(algorithms):
            try:
                # Analyze robustness
                robustness = self.analyze_robustness(algorithm, [noise_level], num_trials=50)[0]

                # Analyze capacity
                capacity = self.analyze_capacity(algorithm, (8, 8))

                # Analyze distortion
                distortion_stats = self.analyze_distortion(algorithm, test_coeffs)

                result = {
                    "algorithm": f"Algorithm_{i}_{type(algorithm).__name__}",
                    "robustness": robustness,
                    "capacity": capacity,
                    "distortion": distortion_stats["mean_distortion"],
                }
                results.append(result)

                logger.debug(
                    f"Algorithm {i}: robustness={robustness:.2%}, "
                    f"capacity={capacity}, distortion={distortion_stats['mean_distortion']:.2f}"
                )

            except Exception as e:
                logger.error(f"Failed to analyze algorithm {i}: {e}")
                continue

        return results
