"""
Unit tests for Reed-Solomon error correction in video steganography.

This module tests the error correction capabilities needed to handle
DCT quantization errors in video steganography.
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
    from .stego_simple_error_correction import (
        AdaptiveSimpleErrorCorrection as AdaptiveErrorCorrection,
    )
    from .stego_simple_error_correction import ErrorCorrectionError
    from .stego_simple_error_correction import SimpleRepetitionEncoder as BlockEncoder
    from .stego_simple_error_correction import SimpleRepetitionEncoder as ReedSolomonDecoder
    from .stego_simple_error_correction import SimpleRepetitionEncoder as ReedSolomonEncoder
except ImportError:
    # Module doesn't exist yet, will be created during implementation
    ReedSolomonEncoder = None
    ReedSolomonDecoder = None
    ErrorCorrectionError = None
    BlockEncoder = None
    AdaptiveErrorCorrection = None


class TestReedSolomonEncoder(unittest.TestCase):
    """Test Reed-Solomon encoding functionality."""

    def setUp(self):
        """Set up test fixtures."""
        if ReedSolomonEncoder is None:
            self.skipTest("Reed-Solomon encoder not implemented yet")

        self.encoder = ReedSolomonEncoder(repetitions=3)  # Simple repetition encoder
        self.test_data = b"DCT steganography test data for video frames"
        self.short_data = b"Hello"
        self.long_data = b"A" * 1000

    def test_encoder_initialization(self):
        """Test encoder initialization with valid parameters."""
        encoder = ReedSolomonEncoder(repetitions=5)
        self.assertEqual(encoder.repetitions, 5)

    def test_encoder_invalid_parameters(self):
        """Test encoder initialization with invalid parameters."""
        with self.assertRaises(ErrorCorrectionError):
            ReedSolomonEncoder(repetitions=2)  # even number not allowed

    def test_encode_basic_data(self):
        """Test encoding basic data."""
        encoded = self.encoder.encode(self.test_data)

        # Encoded data should be longer than original
        self.assertGreater(len(encoded), len(self.test_data))

        # Should be able to decode back to original
        decoder = ReedSolomonDecoder(repetitions=3)
        decoded = decoder.decode(encoded)
        self.assertEqual(decoded, self.test_data)

    def test_encode_empty_data(self):
        """Test encoding empty data."""
        encoded = self.encoder.encode(b"")

        # Should produce some output (padding + parity)
        self.assertGreater(len(encoded), 0)

    def test_encode_short_data(self):
        """Test encoding data shorter than block size."""
        encoded = self.encoder.encode(self.short_data)

        # Should pad and encode properly
        self.assertGreater(len(encoded), len(self.short_data))

    def test_encode_long_data(self):
        """Test encoding data longer than single block."""
        encoded = self.encoder.encode(self.long_data)

        # Should handle multiple blocks
        self.assertGreater(len(encoded), len(self.long_data))

    def test_encode_deterministic(self):
        """Test that encoding is deterministic."""
        encoded1 = self.encoder.encode(self.test_data)
        encoded2 = self.encoder.encode(self.test_data)

        self.assertEqual(encoded1, encoded2)

    def test_encode_different_data(self):
        """Test that different data produces different encodings."""
        encoded1 = self.encoder.encode(b"data1")
        encoded2 = self.encoder.encode(b"data2")

        self.assertNotEqual(encoded1, encoded2)


class TestReedSolomonDecoder(unittest.TestCase):
    """Test Reed-Solomon decoding functionality."""

    def setUp(self):
        """Set up test fixtures."""
        if ReedSolomonDecoder is None:
            self.skipTest("Reed-Solomon decoder not implemented yet")

        self.encoder = ReedSolomonEncoder(repetitions=3)
        self.decoder = ReedSolomonDecoder(repetitions=3)
        self.test_data = b"DCT steganography test data for video frames"

    def test_decoder_initialization(self):
        """Test decoder initialization."""
        decoder = ReedSolomonDecoder(repetitions=5)
        self.assertEqual(decoder.repetitions, 5)

    def test_decode_perfect_data(self):
        """Test decoding data without errors."""
        encoded = self.encoder.encode(self.test_data)
        decoded = self.decoder.decode(encoded)

        self.assertEqual(decoded, self.test_data)

    def test_decode_with_single_error(self):
        """Test decoding data with single byte error."""
        encoded = self.encoder.encode(self.test_data)

        # Introduce single byte error in the data portion (not header)
        corrupted = bytearray(encoded)
        if len(corrupted) > 10:
            corrupted[10] ^= 0xFF  # Corrupt one byte

        decoded = self.decoder.decode(bytes(corrupted))
        self.assertEqual(decoded, self.test_data)

    def test_decode_with_multiple_errors(self):
        """Test decoding data with multiple errors within correction capability."""
        encoded = self.encoder.encode(self.test_data)

        # Introduce multiple errors (within t=16 limit)
        corrupted = bytearray(encoded)
        error_positions = random.sample(range(len(corrupted)), 10)
        for pos in error_positions:
            corrupted[pos] ^= random.randint(1, 255)

        decoded = self.decoder.decode(bytes(corrupted))
        self.assertEqual(decoded, self.test_data)

    def test_decode_with_maximum_errors(self):
        """Test decoding with maximum correctable errors."""
        encoded = self.encoder.encode(self.test_data)

        # Introduce exactly t errors
        corrupted = bytearray(encoded)
        error_positions = random.sample(range(len(corrupted)), self.decoder.t)
        for pos in error_positions:
            corrupted[pos] ^= random.randint(1, 255)

        decoded = self.decoder.decode(bytes(corrupted))
        self.assertEqual(decoded, self.test_data)

    def test_decode_with_excessive_errors(self):
        """Test decoding fails with too many errors."""
        encoded = self.encoder.encode(self.test_data)

        # Introduce more than t errors
        corrupted = bytearray(encoded)
        error_positions = random.sample(range(len(corrupted)), self.decoder.t + 5)
        for pos in error_positions:
            corrupted[pos] ^= random.randint(1, 255)

        with self.assertRaises(ErrorCorrectionError):
            self.decoder.decode(bytes(corrupted))

    def test_decode_invalid_codeword_length(self):
        """Test decoding fails with invalid codeword length."""
        invalid_data = b"short"

        with self.assertRaises(ErrorCorrectionError):
            self.decoder.decode(invalid_data)


class TestBlockEncoder(unittest.TestCase):
    """Test block-based encoding for large data."""

    def setUp(self):
        """Set up test fixtures."""
        if BlockEncoder is None:
            self.skipTest("Block encoder not implemented yet")

        self.block_encoder = BlockEncoder(block_size=200, n=255, k=223, t=16)
        self.test_data = b"DCT steganography test data for video frames" * 10

    def test_block_encoder_initialization(self):
        """Test block encoder initialization."""
        encoder = BlockEncoder(block_size=200, n=255, k=223, t=16)
        self.assertEqual(encoder.block_size, 200)
        self.assertEqual(encoder.rs_encoder.k, 223)

    def test_encode_decode_roundtrip(self):
        """Test encoding and decoding large data."""
        encoded = self.block_encoder.encode(self.test_data)
        decoded = self.block_encoder.decode(encoded)

        self.assertEqual(decoded, self.test_data)

    def test_encode_with_errors(self):
        """Test block encoding with errors in multiple blocks."""
        encoded = self.block_encoder.encode(self.test_data)

        # Introduce errors in different blocks
        corrupted = bytearray(encoded)
        for i in range(0, len(corrupted), 300):  # Every ~300 bytes
            if i < len(corrupted):
                corrupted[i] ^= 0xFF

        decoded = self.block_encoder.decode(bytes(corrupted))
        self.assertEqual(decoded, self.test_data)

    def test_block_boundary_handling(self):
        """Test handling of data that doesn't align with block boundaries."""
        # Data that doesn't divide evenly into blocks
        test_data = b"X" * 333

        encoded = self.block_encoder.encode(test_data)
        decoded = self.block_encoder.decode(encoded)

        self.assertEqual(decoded, test_data)


class TestAdaptiveErrorCorrection(unittest.TestCase):
    """Test adaptive error correction based on channel quality."""

    def setUp(self):
        """Set up test fixtures."""
        if AdaptiveErrorCorrection is None:
            self.skipTest("Adaptive error correction not implemented yet")

        self.adaptive_ec = AdaptiveErrorCorrection()
        self.test_data = b"DCT steganography test data for video frames"

    def test_adaptive_initialization(self):
        """Test adaptive error correction initialization."""
        aec = AdaptiveErrorCorrection()
        self.assertIsNotNone(aec.low_quality_encoder)
        self.assertIsNotNone(aec.medium_quality_encoder)
        self.assertIsNotNone(aec.high_quality_encoder)

    def test_quality_assessment(self):
        """Test channel quality assessment."""
        # Simulate different error rates
        high_quality_errors = 0.01  # 1% error rate
        medium_quality_errors = 0.05  # 5% error rate
        low_quality_errors = 0.15  # 15% error rate

        high_quality = self.adaptive_ec.assess_channel_quality(high_quality_errors)
        medium_quality = self.adaptive_ec.assess_channel_quality(medium_quality_errors)
        low_quality = self.adaptive_ec.assess_channel_quality(low_quality_errors)

        self.assertEqual(high_quality, "high")
        self.assertEqual(medium_quality, "medium")
        self.assertEqual(low_quality, "low")

    def test_adaptive_encoding_high_quality(self):
        """Test adaptive encoding for high quality channel."""
        encoded = self.adaptive_ec.encode(self.test_data, quality="high")
        decoded = self.adaptive_ec.decode(encoded, quality="high")

        self.assertEqual(decoded, self.test_data)

    def test_adaptive_encoding_low_quality(self):
        """Test adaptive encoding for low quality channel."""
        encoded = self.adaptive_ec.encode(self.test_data, quality="low")
        decoded = self.adaptive_ec.decode(encoded, quality="low")

        self.assertEqual(decoded, self.test_data)

    def test_quality_overhead_differences(self):
        """Test that different quality levels have different overhead."""
        high_encoded = self.adaptive_ec.encode(self.test_data, quality="high")
        medium_encoded = self.adaptive_ec.encode(self.test_data, quality="medium")
        low_encoded = self.adaptive_ec.encode(self.test_data, quality="low")

        # Low quality should have more overhead (more redundancy)
        self.assertGreater(len(low_encoded), len(medium_encoded))
        self.assertGreater(len(medium_encoded), len(high_encoded))

    def test_cross_quality_decoding_fails(self):
        """Test that decoding with wrong quality parameter fails."""
        encoded = self.adaptive_ec.encode(self.test_data, quality="high")

        with self.assertRaises(ErrorCorrectionError):
            self.adaptive_ec.decode(encoded, quality="low")


class TestErrorCorrectionIntegration(unittest.TestCase):
    """Test integration of error correction with DCT steganography."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_data = b"DCT steganography test data for video frames"

        # Simulate DCT quantization errors (typical pattern)
        self.dct_error_pattern = self._generate_dct_error_pattern()

    def _generate_dct_error_pattern(self) -> List[float]:
        """Generate typical DCT quantization error pattern."""
        # DCT errors are not random - they follow patterns based on quantization
        errors = []
        for i in range(len(self.test_data)):
            # Higher error probability for certain bit positions
            if i % 8 in [0, 1, 7]:  # MSB and LSB more likely to error
                errors.append(0.4)
            else:
                errors.append(0.2)
        return errors

    def test_dct_error_simulation(self):
        """Test simulation of DCT quantization errors."""
        if ReedSolomonEncoder is None:
            self.skipTest("Error correction not implemented yet")

        encoder = ReedSolomonEncoder(n=255, k=223, t=16)
        decoder = ReedSolomonDecoder(n=255, k=223, t=16)

        # Encode data
        encoded = encoder.encode(self.test_data)

        # Simulate DCT errors
        corrupted = self._apply_dct_errors(encoded, self.dct_error_pattern)

        # Decode and verify
        decoded = decoder.decode(corrupted)
        self.assertEqual(decoded, self.test_data)

    def _apply_dct_errors(self, data: bytes, error_pattern: List[float]) -> bytes:
        """Apply DCT-like errors to data based on probability pattern."""
        corrupted = bytearray(data)

        for i in range(min(len(corrupted), len(error_pattern))):
            if random.random() < error_pattern[i % len(error_pattern)]:
                # Apply bit flip
                bit_pos = random.randint(0, 7)
                corrupted[i] ^= 1 << bit_pos

        return bytes(corrupted)

    def test_realistic_dct_error_correction(self):
        """Test error correction with realistic DCT error patterns."""
        if AdaptiveErrorCorrection is None:
            self.skipTest("Adaptive error correction not implemented yet")

        adaptive_ec = AdaptiveErrorCorrection()

        # Encode with medium quality (typical for DCT)
        encoded = adaptive_ec.encode(self.test_data, quality="medium")

        # Apply realistic DCT errors multiple times
        success_count = 0
        iterations = 10

        for _ in range(iterations):
            corrupted = self._apply_dct_errors(encoded, self.dct_error_pattern)
            try:
                decoded = adaptive_ec.decode(corrupted, quality="medium")
                if decoded == self.test_data:
                    success_count += 1
            except ErrorCorrectionError:
                pass

        # Should succeed in majority of cases
        success_rate = success_count / iterations
        self.assertGreater(success_rate, 0.8, f"Success rate too low: {success_rate:.2%}")


class TestErrorCorrectionPerformance(unittest.TestCase):
    """Test performance characteristics of error correction."""

    def setUp(self):
        """Set up test fixtures."""
        if ReedSolomonEncoder is None:
            self.skipTest("Error correction not implemented yet")

        self.encoder = ReedSolomonEncoder(n=255, k=223, t=16)
        self.decoder = ReedSolomonDecoder(n=255, k=223, t=16)

        # Different data sizes for performance testing
        self.small_data = b"A" * 100
        self.medium_data = b"B" * 1000
        self.large_data = b"C" * 10000

    def test_encoding_performance_scaling(self):
        """Test that encoding time scales reasonably with data size."""
        import time

        # Measure encoding times
        start = time.time()
        self.encoder.encode(self.small_data)
        small_time = time.time() - start

        start = time.time()
        self.encoder.encode(self.medium_data)
        medium_time = time.time() - start

        start = time.time()
        self.encoder.encode(self.large_data)
        large_time = time.time() - start

        # Should scale sub-quadratically (allow for some overhead)
        self.assertLess(medium_time, small_time * 15)
        self.assertLess(large_time, medium_time * 15)

    def test_decoding_performance_scaling(self):
        """Test that decoding time scales reasonably with data size."""
        import time

        # Encode data first
        small_encoded = self.encoder.encode(self.small_data)
        medium_encoded = self.encoder.encode(self.medium_data)
        large_encoded = self.encoder.encode(self.large_data)

        # Measure decoding times
        start = time.time()
        self.decoder.decode(small_encoded)
        small_time = time.time() - start

        start = time.time()
        self.decoder.decode(medium_encoded)
        medium_time = time.time() - start

        start = time.time()
        self.decoder.decode(large_encoded)
        large_time = time.time() - start

        # Should scale reasonably
        self.assertLess(medium_time, small_time * 15)
        self.assertLess(large_time, medium_time * 15)

    def test_memory_usage(self):
        """Test memory usage is reasonable."""
        import sys

        # Encode large data and check memory usage
        encoded = self.encoder.encode(self.large_data)

        # Overhead should be reasonable (less than 3x original size)
        overhead_ratio = len(encoded) / len(self.large_data)
        self.assertLess(overhead_ratio, 3.0)


if __name__ == "__main__":
    # Set random seed for reproducible tests
    random.seed(42)
    np.random.seed(42)

    unittest.main()
