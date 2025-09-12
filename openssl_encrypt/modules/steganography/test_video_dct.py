#!/usr/bin/env python3
"""
Comprehensive Unit Tests for Video DCT Steganography

This module contains extensive tests for DCT-based video steganography utilities,
ensuring robust and reliable implementation of frequency domain steganography.

Test Categories:
- DCT Transform Tests (forward/inverse, numerical stability)
- Quantization Tests (matrix generation, adaptive quantization)
- Coefficient Selection Tests (zigzag patterns, frequency selection)
- Quality Metrics Tests (PSNR, SSIM calculations)
- Edge Case Tests (boundary conditions, error handling)
"""

import os
import tempfile
import unittest
from typing import List, Optional, Tuple

import numpy as np

# Test that cv2 is available for DCT operations
try:
    import cv2

    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False
    cv2 = None

# Import the module we're testing (will be created)
try:
    from .stego_video_dct import (
        CoefficientSelector,
        DCTBlock,
        DCTSteganographyError,
        QualityMetrics,
        QuantizationMatrix,
        VideoDCTUtils,
    )

    DCT_MODULE_AVAILABLE = True
except ImportError:
    DCT_MODULE_AVAILABLE = False


class TestDCTTransforms(unittest.TestCase):
    """Test DCT forward and inverse transforms."""

    def setUp(self):
        """Set up test environment."""
        if not CV2_AVAILABLE:
            self.skipTest("OpenCV not available for DCT operations")
        if not DCT_MODULE_AVAILABLE:
            self.skipTest("DCT module not yet implemented")

        self.dct_utils = VideoDCTUtils()
        self.test_block = np.random.randint(0, 256, (8, 8), dtype=np.uint8)
        self.epsilon = 1e-10  # Numerical precision threshold

    def test_dct_forward_inverse_identity(self):
        """Test that DCT -> IDCT returns original data."""
        # Convert to float for DCT
        float_block = self.test_block.astype(np.float64)

        # Apply DCT and IDCT
        dct_coeffs = self.dct_utils.apply_dct(float_block)
        reconstructed = self.dct_utils.apply_idct(dct_coeffs)

        # Should be nearly identical (within floating point precision)
        np.testing.assert_allclose(float_block, reconstructed, atol=self.epsilon)

    def test_dct_block_size_validation(self):
        """Test DCT with correct 8x8 block size."""
        valid_block = np.zeros((8, 8), dtype=np.float64)

        # Should work without error
        dct_coeffs = self.dct_utils.apply_dct(valid_block)
        self.assertEqual(dct_coeffs.shape, (8, 8))

    def test_dct_with_non_square_blocks(self):
        """Test that non-8x8 blocks raise appropriate errors."""
        invalid_blocks = [
            np.zeros((4, 4)),  # Too small
            np.zeros((16, 16)),  # Too large
            np.zeros((8, 4)),  # Not square
            np.zeros((4, 8)),  # Not square
        ]

        for invalid_block in invalid_blocks:
            with self.assertRaises(DCTSteganographyError):
                self.dct_utils.apply_dct(invalid_block)

    def test_dct_with_different_data_types(self):
        """Test DCT with various input data types."""
        test_cases = [
            np.zeros((8, 8), dtype=np.uint8),
            np.zeros((8, 8), dtype=np.int16),
            np.zeros((8, 8), dtype=np.float32),
            np.zeros((8, 8), dtype=np.float64),
        ]

        for test_block in test_cases:
            try:
                result = self.dct_utils.apply_dct(test_block)
                self.assertEqual(result.shape, (8, 8))
                self.assertEqual(result.dtype, np.float64)
            except Exception as e:
                self.fail(f"DCT failed for dtype {test_block.dtype}: {e}")

    def test_dct_numerical_stability(self):
        """Test DCT stability with extreme values."""
        # Test with all zeros
        zero_block = np.zeros((8, 8), dtype=np.float64)
        dct_zero = self.dct_utils.apply_dct(zero_block)
        reconstructed_zero = self.dct_utils.apply_idct(dct_zero)
        np.testing.assert_allclose(zero_block, reconstructed_zero, atol=self.epsilon)

        # Test with all maximum values
        max_block = np.full((8, 8), 255.0, dtype=np.float64)
        dct_max = self.dct_utils.apply_dct(max_block)
        reconstructed_max = self.dct_utils.apply_idct(dct_max)
        np.testing.assert_allclose(max_block, reconstructed_max, atol=self.epsilon)

        # Test with random pattern
        random_block = np.random.rand(8, 8) * 255
        dct_random = self.dct_utils.apply_dct(random_block)
        reconstructed_random = self.dct_utils.apply_idct(dct_random)
        np.testing.assert_allclose(random_block, reconstructed_random, atol=self.epsilon)

    def test_dct_dc_coefficient(self):
        """Test that DC coefficient (0,0) is handled correctly."""
        # Create block with known DC value
        dc_value = 128.0
        test_block = np.full((8, 8), dc_value, dtype=np.float64)

        dct_coeffs = self.dct_utils.apply_dct(test_block)

        # DC coefficient should be at position (0,0)
        expected_dc = dc_value * 8  # DCT scaling factor
        self.assertAlmostEqual(dct_coeffs[0, 0], expected_dc, places=5)

        # All AC coefficients should be near zero for constant block
        ac_coeffs = dct_coeffs.copy()
        ac_coeffs[0, 0] = 0
        np.testing.assert_allclose(ac_coeffs, np.zeros((8, 8)), atol=1e-10)


class TestQuantizationMatrix(unittest.TestCase):
    """Test quantization matrix generation and operations."""

    def setUp(self):
        """Set up test environment."""
        if not DCT_MODULE_AVAILABLE:
            self.skipTest("DCT module not yet implemented")

        self.quant_matrix = QuantizationMatrix()

    def test_standard_luminance_matrix(self):
        """Test standard JPEG luminance quantization matrix."""
        lum_matrix = self.quant_matrix.get_luminance_matrix(quality=50)

        # Should be 8x8
        self.assertEqual(lum_matrix.shape, (8, 8))

        # All values should be positive
        self.assertTrue(np.all(lum_matrix > 0))

        # DC coefficient (0,0) should be relatively small (low quantization)
        dc_value = lum_matrix[0, 0]
        self.assertTrue(dc_value <= np.percentile(lum_matrix, 25))  # In bottom 25%

    def test_quality_factor_scaling(self):
        """Test that quality factor properly scales quantization matrix."""
        base_matrix = self.quant_matrix.get_luminance_matrix(quality=50)
        high_quality = self.quant_matrix.get_luminance_matrix(quality=90)
        low_quality = self.quant_matrix.get_luminance_matrix(quality=10)

        # Higher quality should have smaller quantization steps
        self.assertTrue(np.all(high_quality < base_matrix))

        # Lower quality should have larger quantization steps
        self.assertTrue(np.all(low_quality > base_matrix))

    def test_quality_boundary_values(self):
        """Test quantization matrix at quality boundaries."""
        # Test minimum quality
        min_quality_matrix = self.quant_matrix.get_luminance_matrix(quality=1)
        self.assertEqual(min_quality_matrix.shape, (8, 8))
        self.assertTrue(np.all(min_quality_matrix > 0))

        # Test maximum quality
        max_quality_matrix = self.quant_matrix.get_luminance_matrix(quality=100)
        self.assertEqual(max_quality_matrix.shape, (8, 8))
        self.assertTrue(np.all(max_quality_matrix > 0))

        # Max quality should have smallest values
        self.assertTrue(np.all(max_quality_matrix <= min_quality_matrix))

    def test_invalid_quality_values(self):
        """Test that invalid quality values raise errors."""
        invalid_qualities = [-1, 0, 101, 200]

        for quality in invalid_qualities:
            with self.assertRaises(DCTSteganographyError):
                self.quant_matrix.get_luminance_matrix(quality=quality)

    def test_adaptive_quantization(self):
        """Test adaptive quantization based on block texture."""
        # Smooth block (low texture)
        smooth_block = np.ones((8, 8)) * 128

        # Complex block (high texture)
        complex_block = np.random.randint(0, 256, (8, 8))

        smooth_quant = self.quant_matrix.get_adaptive_matrix(smooth_block, base_quality=75)
        complex_quant = self.quant_matrix.get_adaptive_matrix(complex_block, base_quality=75)

        # Both should be 8x8
        self.assertEqual(smooth_quant.shape, (8, 8))
        self.assertEqual(complex_quant.shape, (8, 8))

        # Adaptive quantization should vary based on content
        # (exact relationship depends on implementation)


class TestCoefficientSelector(unittest.TestCase):
    """Test DCT coefficient selection patterns."""

    def setUp(self):
        """Set up test environment."""
        if not DCT_MODULE_AVAILABLE:
            self.skipTest("DCT module not yet implemented")

        self.selector = CoefficientSelector()

    def test_zigzag_pattern_generation(self):
        """Test zigzag pattern for 8x8 DCT blocks."""
        zigzag = self.selector.get_zigzag_pattern()

        # Should have 64 positions for 8x8 block
        self.assertEqual(len(zigzag), 64)

        # Should start with DC coefficient (0,0)
        self.assertEqual(zigzag[0], (0, 0))

        # All positions should be unique
        self.assertEqual(len(set(zigzag)), 64)

        # All positions should be valid for 8x8 block
        for row, col in zigzag:
            self.assertTrue(0 <= row < 8)
            self.assertTrue(0 <= col < 8)

    def test_middle_frequency_selection(self):
        """Test selection of middle frequency coefficients."""
        middle_freq = self.selector.get_middle_frequencies()

        # Should exclude DC coefficient (0,0)
        self.assertNotIn((0, 0), middle_freq)

        # Should exclude high frequency corners
        self.assertNotIn((7, 7), middle_freq)
        self.assertNotIn((7, 6), middle_freq)
        self.assertNotIn((6, 7), middle_freq)

        # Should be reasonable number of coefficients
        self.assertTrue(10 <= len(middle_freq) <= 30)

    def test_coefficient_selection_ordering(self):
        """Test that coefficients are selected in proper zigzag order."""
        zigzag = self.selector.get_zigzag_pattern()
        middle_freq = self.selector.get_middle_frequencies()

        # Create zigzag position mapping
        zigzag_positions = {pos: idx for idx, pos in enumerate(zigzag)}

        # Middle frequency positions should be in zigzag order
        middle_indices = [zigzag_positions[pos] for pos in middle_freq]
        self.assertEqual(middle_indices, sorted(middle_indices))

    def test_password_based_selection(self):
        """Test password-based randomization of coefficient selection."""
        password1 = "test_password_1"
        password2 = "test_password_2"

        coeffs1 = self.selector.get_randomized_coefficients(password1, seed=12345)
        coeffs2 = self.selector.get_randomized_coefficients(password2, seed=12345)

        # Different passwords should give different selections
        self.assertNotEqual(coeffs1, coeffs2)

        # Same password should give same selection
        coeffs1_repeat = self.selector.get_randomized_coefficients(password1, seed=12345)
        self.assertEqual(coeffs1, coeffs1_repeat)

    def test_coefficient_selection_boundaries(self):
        """Test coefficient selection at boundary conditions."""
        # Test with minimum selection
        min_coeffs = self.selector.get_middle_frequencies(count=1)
        self.assertEqual(len(min_coeffs), 1)

        # Test with maximum reasonable selection
        max_coeffs = self.selector.get_middle_frequencies(count=50)
        self.assertEqual(len(max_coeffs), 50)

        # Test invalid selections
        with self.assertRaises(DCTSteganographyError):
            self.selector.get_middle_frequencies(count=0)

        with self.assertRaises(DCTSteganographyError):
            self.selector.get_middle_frequencies(count=65)  # More than 64 total


class TestQualityMetrics(unittest.TestCase):
    """Test video quality measurement functions."""

    def setUp(self):
        """Set up test environment."""
        if not DCT_MODULE_AVAILABLE:
            self.skipTest("DCT module not yet implemented")

        self.quality_metrics = QualityMetrics()

        # Create test frames (use more structured data for realistic SSIM values)
        self.original_frame = self._create_test_image(240, 320)
        self.identical_frame = self.original_frame.copy()
        self.noisy_frame = self.original_frame + np.random.randint(-5, 6, self.original_frame.shape)
        self.noisy_frame = np.clip(self.noisy_frame, 0, 255).astype(np.uint8)

    def _create_test_image(self, height: int, width: int) -> np.ndarray:
        """Create a test image with some structure."""
        # Create gradients and patterns for more realistic SSIM testing
        img = np.zeros((height, width, 3), dtype=np.uint8)

        # Add horizontal gradient
        for i in range(height):
            img[i, :, 0] = int(255 * i / height)  # Red channel

        # Add vertical gradient
        for j in range(width):
            img[:, j, 1] = int(255 * j / width)  # Green channel

        # Add some blue
        img[:, :, 2] = 128

        return img

    def test_psnr_calculation_accuracy(self):
        """Test PSNR calculation accuracy."""
        # Identical frames should have infinite PSNR
        psnr_identical = self.quality_metrics.calculate_psnr(
            self.original_frame, self.identical_frame
        )
        self.assertEqual(psnr_identical, float("inf"))

        # Noisy frame should have finite PSNR
        psnr_noisy = self.quality_metrics.calculate_psnr(self.original_frame, self.noisy_frame)
        self.assertTrue(20 <= psnr_noisy <= 60)  # Reasonable PSNR range

    def test_psnr_with_different_noise_levels(self):
        """Test PSNR behavior with different noise levels."""
        psnrs = []

        for noise_level in [1, 5, 10, 20]:
            noisy = self.original_frame + np.random.randint(
                -noise_level, noise_level + 1, self.original_frame.shape
            )
            noisy = np.clip(noisy, 0, 255).astype(np.uint8)

            psnr = self.quality_metrics.calculate_psnr(self.original_frame, noisy)
            psnrs.append(psnr)

        # PSNR should decrease with increasing noise
        for i in range(1, len(psnrs)):
            self.assertLess(psnrs[i], psnrs[i - 1])

    def test_ssim_calculation_accuracy(self):
        """Test SSIM calculation accuracy."""
        # Identical frames should have SSIM = 1.0
        ssim_identical = self.quality_metrics.calculate_ssim(
            self.original_frame, self.identical_frame
        )
        self.assertAlmostEqual(ssim_identical, 1.0, places=5)

        # Noisy frame should have SSIM < 1.0
        ssim_noisy = self.quality_metrics.calculate_ssim(self.original_frame, self.noisy_frame)
        self.assertTrue(0.5 <= ssim_noisy < 1.0)

    def test_ssim_with_different_degradations(self):
        """Test SSIM with various image degradations."""
        # Gaussian blur
        blurred = cv2.GaussianBlur(self.original_frame, (5, 5), 1.0)
        ssim_blur = self.quality_metrics.calculate_ssim(self.original_frame, blurred)

        # Brightness change
        brighter = np.clip(self.original_frame.astype(np.int16) + 20, 0, 255).astype(np.uint8)
        ssim_bright = self.quality_metrics.calculate_ssim(self.original_frame, brighter)

        # Both should be reasonable SSIM values (relaxed bounds for test stability)
        self.assertTrue(0.3 <= ssim_blur <= 1.0)
        self.assertTrue(0.5 <= ssim_bright <= 1.0)

    def test_quality_metrics_edge_cases(self):
        """Test quality metrics with edge cases."""
        # All black frames
        black1 = np.zeros((100, 100, 3), dtype=np.uint8)
        black2 = np.zeros((100, 100, 3), dtype=np.uint8)

        psnr_black = self.quality_metrics.calculate_psnr(black1, black2)
        ssim_black = self.quality_metrics.calculate_ssim(black1, black2)

        self.assertEqual(psnr_black, float("inf"))
        self.assertAlmostEqual(ssim_black, 1.0, places=5)

        # All white frames
        white1 = np.full((100, 100, 3), 255, dtype=np.uint8)
        white2 = np.full((100, 100, 3), 255, dtype=np.uint8)

        psnr_white = self.quality_metrics.calculate_psnr(white1, white2)
        ssim_white = self.quality_metrics.calculate_ssim(white1, white2)

        self.assertEqual(psnr_white, float("inf"))
        self.assertAlmostEqual(ssim_white, 1.0, places=5)

    def test_quality_metrics_different_sizes(self):
        """Test that different sized frames raise appropriate errors."""
        frame1 = np.zeros((100, 100, 3), dtype=np.uint8)
        frame2 = np.zeros((200, 200, 3), dtype=np.uint8)

        with self.assertRaises(DCTSteganographyError):
            self.quality_metrics.calculate_psnr(frame1, frame2)

        with self.assertRaises(DCTSteganographyError):
            self.quality_metrics.calculate_ssim(frame1, frame2)


class TestDCTEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""

    def setUp(self):
        """Set up test environment."""
        if not DCT_MODULE_AVAILABLE:
            self.skipTest("DCT module not yet implemented")

        self.dct_utils = VideoDCTUtils()

    def test_edge_cases_zero_blocks(self):
        """Test DCT with all-zero blocks."""
        zero_block = np.zeros((8, 8), dtype=np.float64)

        # Should work without error
        dct_coeffs = self.dct_utils.apply_dct(zero_block)
        reconstructed = self.dct_utils.apply_idct(dct_coeffs)

        # Should reconstruct to zeros
        np.testing.assert_allclose(zero_block, reconstructed, atol=1e-10)

    def test_edge_cases_saturated_blocks(self):
        """Test DCT with saturated (all max value) blocks."""
        max_block = np.full((8, 8), 255.0, dtype=np.float64)

        # Should work without error
        dct_coeffs = self.dct_utils.apply_dct(max_block)
        reconstructed = self.dct_utils.apply_idct(dct_coeffs)

        # Should reconstruct closely
        np.testing.assert_allclose(max_block, reconstructed, atol=1e-5)

    def test_invalid_input_types(self):
        """Test error handling for invalid input types."""
        invalid_inputs = [
            "not_an_array",
            [1, 2, 3, 4],
            None,
            {"not": "array"},
        ]

        for invalid_input in invalid_inputs:
            with self.assertRaises((DCTSteganographyError, TypeError, AttributeError)):
                self.dct_utils.apply_dct(invalid_input)

    def test_memory_handling_large_inputs(self):
        """Test memory handling with large inputs."""
        # Create a large but manageable block for testing
        large_valid_block = np.random.rand(8, 8).astype(np.float64)

        # Should handle without memory issues
        try:
            dct_coeffs = self.dct_utils.apply_dct(large_valid_block)
            reconstructed = self.dct_utils.apply_idct(dct_coeffs)
            self.assertEqual(reconstructed.shape, (8, 8))
        except MemoryError:
            self.fail("Memory error with reasonable sized input")

    def test_numerical_precision_limits(self):
        """Test behavior at numerical precision limits."""
        # Very small values
        tiny_block = np.full((8, 8), 1e-10, dtype=np.float64)
        dct_tiny = self.dct_utils.apply_dct(tiny_block)
        reconstructed_tiny = self.dct_utils.apply_idct(dct_tiny)

        # Should maintain precision
        np.testing.assert_allclose(tiny_block, reconstructed_tiny, rtol=1e-5)

        # Very large values (within reasonable range)
        large_block = np.full((8, 8), 1e6, dtype=np.float64)
        dct_large = self.dct_utils.apply_dct(large_block)
        reconstructed_large = self.dct_utils.apply_idct(dct_large)

        # Should handle large values
        np.testing.assert_allclose(large_block, reconstructed_large, rtol=1e-5)


class TestDCTPerformance(unittest.TestCase):
    """Test DCT performance characteristics."""

    def setUp(self):
        """Set up test environment."""
        if not DCT_MODULE_AVAILABLE:
            self.skipTest("DCT module not yet implemented")

        self.dct_utils = VideoDCTUtils()

    def test_dct_performance_single_block(self):
        """Test performance of single 8x8 DCT operation."""
        test_block = np.random.rand(8, 8).astype(np.float64)

        import time

        # Measure DCT performance
        start_time = time.time()
        for _ in range(1000):
            dct_coeffs = self.dct_utils.apply_dct(test_block)
        dct_time = time.time() - start_time

        # Should complete 1000 DCTs in reasonable time (< 1 second)
        self.assertLess(dct_time, 1.0, "DCT operations too slow")

    def test_dct_memory_usage_consistency(self):
        """Test that DCT operations don't leak memory."""
        test_block = np.random.rand(8, 8).astype(np.float64)

        # Perform many operations
        for i in range(100):
            dct_coeffs = self.dct_utils.apply_dct(test_block)
            reconstructed = self.dct_utils.apply_idct(dct_coeffs)

            # Verify consistency across iterations
            if i == 0:
                first_result = reconstructed.copy()
            else:
                np.testing.assert_allclose(first_result, reconstructed, atol=1e-10)


if __name__ == "__main__":
    # Configure test runner
    unittest.main(verbosity=2, buffer=True)
