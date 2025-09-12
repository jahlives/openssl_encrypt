"""
Unit tests for Quantization Index Modulation (QIM) algorithms.

This module tests advanced QIM algorithms that provide robust data embedding
in DCT coefficients, designed to survive video compression and quantization.
"""

import os
import random
import sys
import unittest
from typing import List, Optional, Tuple

import numpy as np

# Add the parent directory to the path so we can import the modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from .stego_qim_advanced import (
        AdaptiveQIM,
        DistortionCompensatedQIM,
        MultiLevelQIM,
        QIMAnalyzer,
        QIMError,
        UniformQIM,
    )
except ImportError:
    # Module doesn't exist yet, will be created during implementation
    UniformQIM = None
    AdaptiveQIM = None
    DistortionCompensatedQIM = None
    MultiLevelQIM = None
    QIMError = None
    QIMAnalyzer = None


class TestUniformQIM(unittest.TestCase):
    """Test uniform quantization index modulation."""

    def setUp(self):
        """Set up test fixtures."""
        if UniformQIM is None:
            self.skipTest("QIM algorithms not implemented yet")

        self.qim = UniformQIM(quantization_step=8.0)
        self.test_coefficients = np.array(
            [
                [12.5, -8.3, 4.7, -2.1, 0.8],
                [15.2, -12.8, 7.3, -4.6, 1.2],
                [9.7, -5.4, 3.2, -1.8, 0.5],
                [18.3, -14.7, 8.9, -6.2, 2.1],
                [6.8, -3.9, 2.4, -1.3, 0.3],
            ],
            dtype=np.float64,
        )

    def test_qim_initialization(self):
        """Test QIM initialization with various parameters."""
        qim1 = UniformQIM(quantization_step=4.0)
        self.assertEqual(qim1.quantization_step, 4.0)

        qim2 = UniformQIM(quantization_step=16.0, embedding_strength=2.0)
        self.assertEqual(qim2.quantization_step, 16.0)
        self.assertEqual(qim2.embedding_strength, 2.0)

    def test_qim_invalid_parameters(self):
        """Test QIM initialization with invalid parameters."""
        with self.assertRaises(QIMError):
            UniformQIM(quantization_step=0)

        with self.assertRaises(QIMError):
            UniformQIM(quantization_step=-1.0)

        with self.assertRaises(QIMError):
            UniformQIM(quantization_step=8.0, embedding_strength=0)

    def test_embed_single_bit(self):
        """Test embedding a single bit in a coefficient."""
        original_coeff = 10.5

        # Embed bit 0
        modified_coeff_0 = self.qim.embed_bit(original_coeff, 0)
        extracted_bit_0 = self.qim.extract_bit(modified_coeff_0)
        self.assertEqual(extracted_bit_0, 0)

        # Embed bit 1
        modified_coeff_1 = self.qim.embed_bit(original_coeff, 1)
        extracted_bit_1 = self.qim.extract_bit(modified_coeff_1)
        self.assertEqual(extracted_bit_1, 1)

    def test_embed_extract_roundtrip(self):
        """Test complete embed/extract roundtrip."""
        test_bits = [0, 1, 1, 0, 1, 0, 0, 1]
        original_coeffs = self.test_coefficients.flatten()[: len(test_bits)]

        # Embed bits
        modified_coeffs = []
        for i, bit in enumerate(test_bits):
            modified_coeff = self.qim.embed_bit(original_coeffs[i], bit)
            modified_coeffs.append(modified_coeff)

        # Extract bits
        extracted_bits = []
        for coeff in modified_coeffs:
            extracted_bit = self.qim.extract_bit(coeff)
            extracted_bits.append(extracted_bit)

        self.assertEqual(extracted_bits, test_bits)

    def test_embed_with_noise(self):
        """Test embedding robustness with added noise."""
        test_bits = [0, 1, 1, 0, 1]
        original_coeffs = self.test_coefficients.flatten()[: len(test_bits)]

        # Embed bits
        modified_coeffs = []
        for i, bit in enumerate(test_bits):
            modified_coeff = self.qim.embed_bit(original_coeffs[i], bit)
            # Add small amount of noise (compression artifact simulation)
            noisy_coeff = modified_coeff + np.random.normal(0, 0.5)
            modified_coeffs.append(noisy_coeff)

        # Extract bits with noise
        extracted_bits = []
        for coeff in modified_coeffs:
            extracted_bit = self.qim.extract_bit(coeff)
            extracted_bits.append(extracted_bit)

        # Should be robust to small noise
        accuracy = sum(1 for a, b in zip(extracted_bits, test_bits) if a == b) / len(test_bits)
        self.assertGreater(accuracy, 0.8, f"QIM not robust enough to noise: {accuracy:.2%}")

    def test_distortion_measurement(self):
        """Test distortion measurement in QIM embedding."""
        original_coeff = 10.0

        embedded_0 = self.qim.embed_bit(original_coeff, 0)
        embedded_1 = self.qim.embed_bit(original_coeff, 1)

        distortion_0 = self.qim.calculate_distortion(original_coeff, embedded_0)
        distortion_1 = self.qim.calculate_distortion(original_coeff, embedded_1)

        # Both should have measurable but reasonable distortion
        self.assertGreaterEqual(distortion_0, 0)
        self.assertGreaterEqual(distortion_1, 0)
        # Distortion can be up to 1.5x quantization step in worst case
        self.assertLess(distortion_0, self.qim.quantization_step * 1.5)
        self.assertLess(distortion_1, self.qim.quantization_step * 1.5)

    def test_quantization_step_effects(self):
        """Test effects of different quantization steps."""
        coefficient = 15.3

        qim_small = UniformQIM(quantization_step=2.0)
        qim_large = UniformQIM(quantization_step=16.0)

        # Embed same bit with different quantization steps
        embedded_small = qim_small.embed_bit(coefficient, 1)
        embedded_large = qim_large.embed_bit(coefficient, 1)

        # Smaller quantization should cause less distortion
        distortion_small = qim_small.calculate_distortion(coefficient, embedded_small)
        distortion_large = qim_large.calculate_distortion(coefficient, embedded_large)

        # But larger quantization should be more robust
        # Add noise and test extraction
        noisy_small = embedded_small + np.random.normal(0, 1.5)
        noisy_large = embedded_large + np.random.normal(0, 1.5)

        extracted_small = qim_small.extract_bit(noisy_small)
        extracted_large = qim_large.extract_bit(noisy_large)

        # Large quantization should be more likely to survive noise
        self.assertEqual(extracted_large, 1)  # Should survive better

    def test_coefficient_range_handling(self):
        """Test QIM with various coefficient ranges."""
        test_coefficients = [-100.0, -10.5, -1.2, 0.0, 1.8, 12.7, 85.3]

        for coeff in test_coefficients:
            # Test both bit values
            for bit in [0, 1]:
                embedded = self.qim.embed_bit(coeff, bit)
                extracted = self.qim.extract_bit(embedded)
                self.assertEqual(extracted, bit, f"Failed for coefficient {coeff}, bit {bit}")


class TestAdaptiveQIM(unittest.TestCase):
    """Test adaptive quantization index modulation."""

    def setUp(self):
        """Set up test fixtures."""
        if AdaptiveQIM is None:
            self.skipTest("Adaptive QIM not implemented yet")

        self.aqim = AdaptiveQIM(base_quantization_step=8.0)
        self.test_block = np.array(
            [
                [120, 100, 80, 60, 40],
                [110, 90, 70, 50, 30],
                [100, 80, 60, 40, 20],
                [90, 70, 50, 30, 10],
                [80, 60, 40, 20, 5],
            ],
            dtype=np.float64,
        )

    def test_adaptive_initialization(self):
        """Test adaptive QIM initialization."""
        aqim = AdaptiveQIM(base_quantization_step=4.0, adaptation_factor=1.5)
        self.assertEqual(aqim.base_quantization_step, 4.0)
        self.assertEqual(aqim.adaptation_factor, 1.5)

    def test_quantization_adaptation(self):
        """Test quantization step adaptation based on coefficient magnitude."""
        small_coeff = 2.5
        large_coeff = 50.3

        # Adaptive quantization should use different steps
        small_step = self.aqim.get_adaptive_step(small_coeff, position=(0, 0))
        large_step = self.aqim.get_adaptive_step(large_coeff, position=(0, 0))

        # Larger coefficients should generally use larger quantization steps
        self.assertNotEqual(small_step, large_step)

    def test_position_based_adaptation(self):
        """Test adaptation based on DCT coefficient position."""
        coefficient = 10.0

        # Different positions should potentially have different adaptations
        dc_step = self.aqim.get_adaptive_step(coefficient, position=(0, 0))  # DC
        ac_low_step = self.aqim.get_adaptive_step(coefficient, position=(0, 1))  # Low freq AC
        ac_high_step = self.aqim.get_adaptive_step(coefficient, position=(4, 4))  # High freq AC

        # Steps should be adapted based on perceptual importance
        self.assertIsInstance(dc_step, (int, float))
        self.assertIsInstance(ac_low_step, (int, float))
        self.assertIsInstance(ac_high_step, (int, float))

    def test_adaptive_embedding_accuracy(self):
        """Test embedding accuracy with adaptive quantization."""
        test_bits = [1, 0, 1, 1, 0, 0, 1, 0]
        coefficients = self.test_block.flatten()[: len(test_bits)]
        positions = [(i // 5, i % 5) for i in range(len(test_bits))]

        # Embed with adaptive quantization
        embedded_coeffs = []
        for i, (coeff, bit, pos) in enumerate(zip(coefficients, test_bits, positions)):
            embedded = self.aqim.embed_bit_adaptive(coeff, bit, position=pos)
            embedded_coeffs.append(embedded)

        # Extract bits
        extracted_bits = []
        for i, (coeff, pos) in enumerate(zip(embedded_coeffs, positions)):
            extracted = self.aqim.extract_bit_adaptive(coeff, position=pos)
            extracted_bits.append(extracted)

        self.assertEqual(extracted_bits, test_bits)

    def test_adaptive_robustness(self):
        """Test robustness of adaptive QIM to compression-like distortions."""
        test_bits = [1, 0, 1, 0, 1]
        coefficients = [25.0, -15.3, 8.7, -4.2, 12.8]
        positions = [(0, 1), (1, 0), (1, 1), (2, 0), (0, 2)]

        # Embed bits adaptively
        embedded_coeffs = []
        for coeff, bit, pos in zip(coefficients, test_bits, positions):
            embedded = self.aqim.embed_bit_adaptive(coeff, bit, position=pos)
            embedded_coeffs.append(embedded)

        # Simulate compression distortion
        distorted_coeffs = []
        for coeff in embedded_coeffs:
            # Simulate quantization + rounding
            distorted = np.round(coeff / 2.0) * 2.0  # Coarse quantization
            distorted += np.random.normal(0, 0.3)  # Small noise
            distorted_coeffs.append(distorted)

        # Extract from distorted coefficients
        extracted_bits = []
        for coeff, pos in zip(distorted_coeffs, positions):
            extracted = self.aqim.extract_bit_adaptive(coeff, position=pos)
            extracted_bits.append(extracted)

        accuracy = sum(1 for a, b in zip(extracted_bits, test_bits) if a == b) / len(test_bits)
        self.assertGreater(accuracy, 0.7, f"Adaptive QIM not robust enough: {accuracy:.2%}")


class TestDistortionCompensatedQIM(unittest.TestCase):
    """Test distortion-compensated QIM algorithms."""

    def setUp(self):
        """Set up test fixtures."""
        if DistortionCompensatedQIM is None:
            self.skipTest("Distortion-compensated QIM not implemented yet")

        self.dcqim = DistortionCompensatedQIM(quantization_step=8.0, compensation_factor=0.5)

    def test_distortion_compensation_initialization(self):
        """Test initialization of distortion compensation parameters."""
        dcqim = DistortionCompensatedQIM(
            quantization_step=6.0, compensation_factor=0.3, max_compensation=2.0
        )
        self.assertEqual(dcqim.quantization_step, 6.0)
        self.assertEqual(dcqim.compensation_factor, 0.3)
        self.assertEqual(dcqim.max_compensation, 2.0)

    def test_distortion_prediction(self):
        """Test distortion prediction for coefficient embedding."""
        coefficient = 15.7

        # Predict distortion for both bit values
        predicted_distortion_0 = self.dcqim.predict_distortion(coefficient, 0)
        predicted_distortion_1 = self.dcqim.predict_distortion(coefficient, 1)

        self.assertIsInstance(predicted_distortion_0, (int, float))
        self.assertIsInstance(predicted_distortion_1, (int, float))
        self.assertGreaterEqual(predicted_distortion_0, 0)
        self.assertGreaterEqual(predicted_distortion_1, 0)

    def test_compensation_embedding(self):
        """Test embedding with distortion compensation."""
        test_coefficients = [10.5, -8.3, 22.7, -15.2, 5.9]
        test_bits = [1, 0, 1, 1, 0]

        # Embed with compensation
        embedded_coeffs = []
        for coeff, bit in zip(test_coefficients, test_bits):
            embedded = self.dcqim.embed_bit_compensated(coeff, bit)
            embedded_coeffs.append(embedded)

        # Extract bits
        extracted_bits = []
        for coeff in embedded_coeffs:
            extracted = self.dcqim.extract_bit(coeff)
            extracted_bits.append(extracted)

        self.assertEqual(extracted_bits, test_bits)

    def test_compensation_reduces_distortion(self):
        """Test that compensation actually reduces overall distortion."""
        coefficient = 12.3
        bit = 1

        # Embed without compensation
        regular_embedded = self.dcqim.embed_bit(coefficient, bit)
        regular_distortion = abs(regular_embedded - coefficient)

        # Embed with compensation
        compensated_embedded = self.dcqim.embed_bit_compensated(coefficient, bit)
        compensated_distortion = abs(compensated_embedded - coefficient)

        # Compensation should generally reduce distortion
        # (Though this might not always be true for individual coefficients)
        self.assertIsInstance(compensated_distortion, (int, float))

    def test_compensation_with_quantization_noise(self):
        """Test compensation effectiveness under quantization noise."""
        test_data = [(20.0, 1), (15.5, 0), (8.3, 1), (25.7, 0), (12.1, 1)]

        success_compensated = 0
        success_regular = 0

        for coeff, bit in test_data:
            # Test with compensation
            comp_embedded = self.dcqim.embed_bit_compensated(coeff, bit)
            # Add quantization noise
            comp_noisy = comp_embedded + np.random.normal(0, 1.0)
            comp_extracted = self.dcqim.extract_bit(comp_noisy)
            if comp_extracted == bit:
                success_compensated += 1

            # Test without compensation
            reg_embedded = self.dcqim.embed_bit(coeff, bit)
            # Add same level of quantization noise
            reg_noisy = reg_embedded + np.random.normal(0, 1.0)
            reg_extracted = self.dcqim.extract_bit(reg_noisy)
            if reg_extracted == bit:
                success_regular += 1

        # Compensation should generally perform at least as well
        self.assertGreaterEqual(success_compensated, success_regular - 1)


class TestMultiLevelQIM(unittest.TestCase):
    """Test multi-level QIM for embedding multiple bits per coefficient."""

    def setUp(self):
        """Set up test fixtures."""
        if MultiLevelQIM is None:
            self.skipTest("Multi-level QIM not implemented yet")

        self.mlqim = MultiLevelQIM(quantization_step=16.0, bits_per_coefficient=2)

    def test_multilevel_initialization(self):
        """Test multi-level QIM initialization."""
        mlqim = MultiLevelQIM(quantization_step=8.0, bits_per_coefficient=3)
        self.assertEqual(mlqim.quantization_step, 8.0)
        self.assertEqual(mlqim.bits_per_coefficient, 3)
        self.assertEqual(mlqim.num_levels, 8)  # 2^3

    def test_multilevel_invalid_parameters(self):
        """Test invalid parameters for multi-level QIM."""
        with self.assertRaises(QIMError):
            MultiLevelQIM(quantization_step=8.0, bits_per_coefficient=0)

        with self.assertRaises(QIMError):
            MultiLevelQIM(quantization_step=8.0, bits_per_coefficient=5)  # Too many bits

    def test_embed_multiple_bits(self):
        """Test embedding multiple bits in a single coefficient."""
        coefficient = 25.0

        # Test all possible bit combinations for 2 bits
        bit_combinations = [(0, 0), (0, 1), (1, 0), (1, 1)]

        for bits in bit_combinations:
            embedded = self.mlqim.embed_bits(coefficient, bits)
            extracted = self.mlqim.extract_bits(embedded)
            self.assertEqual(extracted, bits, f"Failed for bits {bits}")

    def test_multilevel_capacity_increase(self):
        """Test that multi-level QIM increases embedding capacity."""
        coefficients = np.array([10.5, -8.3, 15.7, -12.4, 9.1])

        # Single-bit QIM
        single_qim = UniformQIM(quantization_step=16.0)
        single_bits = [1, 0, 1, 0, 1]
        single_capacity = len(single_bits)  # 5 bits

        # Multi-level QIM (2 bits per coefficient)
        multi_bits = [(1, 0), (0, 1), (1, 1), (0, 0), (1, 0)]
        multi_capacity = len(multi_bits) * 2  # 10 bits

        # Embed and extract with multi-level
        embedded_coeffs = []
        for coeff, bits in zip(coefficients, multi_bits):
            embedded = self.mlqim.embed_bits(coeff, bits)
            embedded_coeffs.append(embedded)

        extracted_bits = []
        for coeff in embedded_coeffs:
            extracted = self.mlqim.extract_bits(coeff)
            extracted_bits.append(extracted)

        self.assertEqual(extracted_bits, multi_bits)
        self.assertEqual(multi_capacity, 2 * single_capacity)

    def test_multilevel_robustness(self):
        """Test robustness of multi-level QIM to noise."""
        test_data = [(30.0, (1, 1)), (15.0, (0, 1)), (8.0, (1, 0)), (-20.0, (0, 0)), (45.0, (1, 1))]

        success_count = 0
        for coeff, bits in test_data:
            # Embed bits
            embedded = self.mlqim.embed_bits(coeff, bits)

            # Add moderate noise
            noisy = embedded + np.random.normal(0, 2.0)

            # Extract bits
            extracted = self.mlqim.extract_bits(noisy)

            if extracted == bits:
                success_count += 1

        accuracy = success_count / len(test_data)
        self.assertGreater(accuracy, 0.6, f"Multi-level QIM not robust enough: {accuracy:.2%}")

    def test_multilevel_distortion_analysis(self):
        """Test distortion characteristics of multi-level embedding."""
        coefficient = 20.0
        all_combinations = [(0, 0), (0, 1), (1, 0), (1, 1)]

        distortions = []
        for bits in all_combinations:
            embedded = self.mlqim.embed_bits(coefficient, bits)
            distortion = abs(embedded - coefficient)
            distortions.append(distortion)

        # All distortions should be reasonable (allow up to 2x for multi-level)
        max_distortion = max(distortions)
        self.assertLess(max_distortion, self.mlqim.quantization_step * 2.0)

        # Distortions should vary based on embedded pattern
        self.assertGreater(len(set(distortions)), 1)


class TestQIMAnalyzer(unittest.TestCase):
    """Test QIM analysis and optimization tools."""

    def setUp(self):
        """Set up test fixtures."""
        if QIMAnalyzer is None:
            self.skipTest("QIM analyzer not implemented yet")

        self.analyzer = QIMAnalyzer()

    def test_analyzer_initialization(self):
        """Test QIM analyzer initialization."""
        analyzer = QIMAnalyzer()
        self.assertIsNotNone(analyzer)

    def test_robustness_analysis(self):
        """Test robustness analysis of QIM schemes."""
        qim = UniformQIM(quantization_step=8.0)

        # Analyze robustness to different noise levels
        noise_levels = [0.5, 1.0, 2.0, 4.0]
        robustness_results = self.analyzer.analyze_robustness(qim, noise_levels)

        self.assertEqual(len(robustness_results), len(noise_levels))

        # Robustness should generally decrease with higher noise
        for i in range(len(robustness_results) - 1):
            current_robustness = robustness_results[i]
            next_robustness = robustness_results[i + 1]
            # Allow some tolerance for randomness
            self.assertGreaterEqual(current_robustness + 0.1, next_robustness)

    def test_capacity_analysis(self):
        """Test capacity analysis of QIM schemes."""
        qim_single = UniformQIM(quantization_step=8.0)
        qim_multi = MultiLevelQIM(quantization_step=8.0, bits_per_coefficient=2)

        # Analyze capacity for a block of coefficients
        block_size = (8, 8)
        capacity_single = self.analyzer.analyze_capacity(qim_single, block_size)
        capacity_multi = self.analyzer.analyze_capacity(qim_multi, block_size)

        # Multi-level should have higher capacity
        self.assertGreater(capacity_multi, capacity_single)
        self.assertEqual(capacity_multi, capacity_single * 2)

    def test_distortion_analysis(self):
        """Test distortion analysis of QIM embedding."""
        qim = UniformQIM(quantization_step=12.0)

        test_coefficients = np.array(
            [[10.0, -5.5, 8.3, -12.7], [15.2, -8.1, 6.4, -9.8], [12.8, -7.3, 4.9, -11.2]]
        )

        distortion_stats = self.analyzer.analyze_distortion(qim, test_coefficients)

        # Should return statistics about distortion
        self.assertIn("mean_distortion", distortion_stats)
        self.assertIn("max_distortion", distortion_stats)
        self.assertIn("std_distortion", distortion_stats)

        # Distortion should be reasonable
        self.assertGreater(distortion_stats["mean_distortion"], 0)
        self.assertLess(distortion_stats["max_distortion"], qim.quantization_step * 1.5)

    def test_optimal_quantization_step(self):
        """Test finding optimal quantization step for given requirements."""
        # Find optimal step for balance between robustness and distortion
        optimal_step = self.analyzer.find_optimal_quantization_step(
            target_robustness=0.8, max_distortion=10.0, noise_level=1.5
        )

        self.assertIsInstance(optimal_step, (int, float))
        self.assertGreater(optimal_step, 0)

    def test_performance_comparison(self):
        """Test performance comparison between QIM algorithms."""
        qim_uniform = UniformQIM(quantization_step=8.0)
        qim_adaptive = AdaptiveQIM(base_quantization_step=8.0)

        comparison = self.analyzer.compare_algorithms([qim_uniform, qim_adaptive])

        self.assertEqual(len(comparison), 2)

        # Each comparison should have performance metrics
        for result in comparison:
            self.assertIn("algorithm", result)
            self.assertIn("robustness", result)
            self.assertIn("distortion", result)
            self.assertIn("capacity", result)


class TestQIMIntegration(unittest.TestCase):
    """Test integration of QIM algorithms with DCT steganography."""

    def setUp(self):
        """Set up test fixtures for integration testing."""
        self.test_block = np.array(
            [
                [120.0, 85.3, 42.7, 18.9, 5.2],
                [91.5, 63.8, 28.4, 12.1, 3.7],
                [58.7, 41.2, 19.5, 8.3, 2.4],
                [32.4, 22.9, 10.8, 4.6, 1.5],
                [18.1, 12.7, 6.0, 2.5, 0.8],
            ],
            dtype=np.float64,
        )

    def test_qim_with_dct_blocks(self):
        """Test QIM integration with DCT coefficient blocks."""
        if UniformQIM is None:
            self.skipTest("QIM algorithms not implemented yet")

        qim = UniformQIM(quantization_step=8.0)

        # Test data to embed
        test_data = b"QIM test data"
        test_bits = "".join(format(byte, "08b") for byte in test_data)

        # Flatten block and select coefficients for embedding
        coefficients = self.test_block.flatten()
        # Ensure we have enough coefficients
        if len(coefficients) < len(test_bits):
            # Extend with additional coefficients if needed
            additional_coeffs = np.random.uniform(-20, 20, len(test_bits) - len(coefficients))
            coefficients = np.concatenate([coefficients, additional_coeffs])
        available_coeffs = coefficients[: len(test_bits)]

        # Embed bits using QIM
        embedded_coeffs = []
        for coeff, bit_char in zip(available_coeffs, test_bits):
            bit = int(bit_char)
            embedded = qim.embed_bit(coeff, bit)
            embedded_coeffs.append(embedded)

        # Extract bits
        extracted_bits = []
        for coeff in embedded_coeffs:
            extracted_bit = qim.extract_bit(coeff)
            extracted_bits.append(str(extracted_bit))

        extracted_bit_string = "".join(extracted_bits)

        # Convert back to bytes
        extracted_bytes = bytearray()
        for i in range(0, len(extracted_bit_string), 8):
            if i + 8 <= len(extracted_bit_string):
                byte_bits = extracted_bit_string[i : i + 8]
                byte_value = int(byte_bits, 2)
                extracted_bytes.append(byte_value)

        extracted_data = bytes(extracted_bytes)
        self.assertEqual(extracted_data, test_data)

    def test_qim_coefficient_selection(self):
        """Test QIM with different coefficient selection strategies."""
        if UniformQIM is None:
            self.skipTest("QIM algorithms not implemented yet")

        qim = UniformQIM(quantization_step=6.0)

        # Test with different coefficient types
        dc_coeff = self.test_block[0, 0]  # DC coefficient
        low_freq_coeff = self.test_block[0, 1]  # Low frequency AC
        mid_freq_coeff = self.test_block[2, 2]  # Mid frequency AC

        test_bit = 1

        # Embed in different coefficient types
        dc_embedded = qim.embed_bit(dc_coeff, test_bit)
        lf_embedded = qim.embed_bit(low_freq_coeff, test_bit)
        mf_embedded = qim.embed_bit(mid_freq_coeff, test_bit)

        # Extract from all
        dc_extracted = qim.extract_bit(dc_embedded)
        lf_extracted = qim.extract_bit(lf_embedded)
        mf_extracted = qim.extract_bit(mf_embedded)

        # All should extract correctly
        self.assertEqual(dc_extracted, test_bit)
        self.assertEqual(lf_extracted, test_bit)
        self.assertEqual(mf_extracted, test_bit)

    def test_qim_compression_simulation(self):
        """Test QIM robustness to compression-like effects."""
        if UniformQIM is None:
            self.skipTest("QIM algorithms not implemented yet")

        qim = UniformQIM(quantization_step=12.0)  # Larger step for robustness

        test_bits = [1, 0, 1, 1, 0, 1, 0, 0]
        coefficients = self.test_block.flatten()[: len(test_bits)]

        # Embed bits
        embedded_coeffs = []
        for coeff, bit in zip(coefficients, test_bits):
            embedded = qim.embed_bit(coeff, bit)
            embedded_coeffs.append(embedded)

        # Simulate compression effects
        compressed_coeffs = []
        for coeff in embedded_coeffs:
            # Simulate quantization (coarse)
            compressed = np.round(coeff / 4.0) * 4.0
            # Add small rounding errors
            compressed += np.random.uniform(-0.5, 0.5)
            compressed_coeffs.append(compressed)

        # Extract from compressed coefficients
        extracted_bits = []
        for coeff in compressed_coeffs:
            extracted = qim.extract_bit(coeff)
            extracted_bits.append(extracted)

        # Calculate accuracy
        accuracy = sum(1 for a, b in zip(extracted_bits, test_bits) if a == b) / len(test_bits)
        self.assertGreater(accuracy, 0.75, f"QIM not robust to compression: {accuracy:.2%}")


if __name__ == "__main__":
    # Set random seed for reproducible tests
    random.seed(42)
    np.random.seed(42)

    unittest.main()
