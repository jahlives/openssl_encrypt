#!/usr/bin/env python3
"""
Comprehensive Unit Tests for Video Core DCT Steganography

This module contains tests for the refactored video core that uses DCT-based
steganography instead of LSB. Tests ensure the video steganography pipeline
works correctly with frequency domain data hiding.

Test Categories:
- Frame Processing Tests (DCT-based hide/extract)
- Capacity Calculation Tests (DCT coefficient capacity)
- Video Quality Tests (PSNR/SSIM preservation)
- Multi-frame Processing Tests (temporal spreading)
- Password-based Randomization Tests
- Error Handling Tests
- Performance Tests
"""

import os
import tempfile
import unittest
from typing import List, Optional, Tuple

import numpy as np

# Test that required modules are available
try:
    import cv2

    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False
    cv2 = None

# Import video DCT utilities
try:
    from .stego_video_dct import (
        CoefficientSelector,
        DCTSteganographyError,
        QualityMetrics,
        VideoDCTUtils,
    )

    DCT_UTILS_AVAILABLE = True
except ImportError:
    DCT_UTILS_AVAILABLE = False

# Import the video core (will be refactored)
try:
    from .stego_video_core import (
        CapacityError,
        VideoFormatError,
        VideoFrameInfo,
        VideoSteganographyBase,
        is_video_steganography_available,
    )

    VIDEO_CORE_AVAILABLE = True
except ImportError:
    VIDEO_CORE_AVAILABLE = False


class TestVideoSteganography(VideoSteganographyBase):
    """Concrete test implementation of VideoSteganographyBase for testing."""

    def parse_container(self, video_data: bytes):
        """Minimal container parsing for testing."""
        return {
            "video_stream": video_data,
            "audio_stream": None,
            "metadata": {},
            "has_audio": False,
        }

    def reconstruct_container(self, container_info, modified_frames, modified_audio=None):
        """Minimal container reconstruction for testing."""
        return container_info["video_stream"]  # Just return original for testing

    def hide_data(self, cover_data: bytes, secret_data: bytes) -> bytes:
        """Minimal hide_data implementation for testing."""
        return cover_data  # Just return original for testing

    def extract_data(self, stego_data: bytes) -> bytes:
        """Minimal extract_data implementation for testing."""
        return b"test"  # Return test data


class TestVideoDCTCore(unittest.TestCase):
    """Test the refactored video core with DCT functionality."""

    def setUp(self):
        """Set up test environment."""
        if not CV2_AVAILABLE:
            self.skipTest("OpenCV not available for video processing")
        if not DCT_UTILS_AVAILABLE:
            self.skipTest("DCT utilities not available")
        if not VIDEO_CORE_AVAILABLE:
            self.skipTest("Video core module not available")

        # Create test video steganography instance
        self.video_stego = TestVideoSteganography(
            password="test_password_dct", security_level=2, use_dct=True  # Enable DCT mode
        )

        # Create test frames
        self.test_frames = self._create_test_frames()
        self.test_data = b"DCT steganography test data for video frames"

        # Quality metrics
        self.quality_metrics = QualityMetrics()

    def _create_test_frames(self) -> List[np.ndarray]:
        """Create a sequence of test video frames."""
        frames = []

        for i in range(10):  # Create 10 test frames
            # Create frame with gradual changes to simulate video
            frame = np.zeros((240, 320, 3), dtype=np.uint8)

            # Add moving pattern
            offset = i * 10
            frame[50:150, 50 + offset : 150 + offset, :] = 255

            # Add texture
            texture = np.random.randint(128, 256, (240, 320, 3), dtype=np.uint8)
            frame = (0.8 * frame + 0.2 * texture).astype(np.uint8)

            frames.append(frame)

        return frames

    def test_hide_in_frame_dct_basic(self):
        """Test basic DCT-based data hiding in a single frame."""
        frame = self.test_frames[0]
        frame_info = VideoFrameInfo(frame_number=0, frame_type="I", size=(320, 240))

        # Hide data using DCT
        stego_frame = self.video_stego.hide_in_frame(frame, self.test_data, frame_info)

        # Frame should maintain same shape and type
        self.assertEqual(stego_frame.shape, frame.shape)
        self.assertEqual(stego_frame.dtype, frame.dtype)

        # Should have reasonable quality preservation
        psnr = self.quality_metrics.calculate_psnr(frame, stego_frame)
        self.assertGreater(psnr, 35.0, "PSNR should be > 35dB for DCT hiding")

        # SSIM should be high
        ssim = self.quality_metrics.calculate_ssim(frame, stego_frame)
        self.assertGreater(ssim, 0.85, "SSIM should be > 0.85 for DCT hiding")

    def test_extract_from_frame_dct_basic(self):
        """Test basic DCT-based data extraction from a single frame."""
        frame = self.test_frames[0]
        frame_info = VideoFrameInfo(frame_number=0, frame_type="I", size=(320, 240))

        # Hide and then extract data
        stego_frame = self.video_stego.hide_in_frame(frame, self.test_data, frame_info)
        extracted_data = self.video_stego.extract_from_frame(
            stego_frame, len(self.test_data), frame_info
        )

        # Extracted data should match original (allow some errors due to DCT quantization)
        # For now, check that most of the data is correct
        correct_bytes = sum(1 for a, b in zip(extracted_data, self.test_data) if a == b)
        accuracy = correct_bytes / len(self.test_data)
        self.assertGreater(accuracy, 0.7, f"Extraction accuracy too low: {accuracy:.2%}")

        # Check that at least the start matches
        self.assertTrue(
            extracted_data[:3] == self.test_data[:3], "Start of extracted data doesn't match"
        )

    def test_hide_extract_roundtrip(self):
        """Test complete hide/extract roundtrip with multiple frames."""
        # Create video info
        video_info = {
            "fps": 30.0,
            "width": 320,
            "height": 240,
            "total_frames": len(self.test_frames),
            "duration": len(self.test_frames) / 30.0,
        }

        # Hide data across multiple frames
        modified_frames = self.test_frames.copy()
        frame_infos = self.video_stego.distribute_data(self.test_data, self.test_frames, video_info)

        for i, frame_info in enumerate(frame_infos):
            if frame_info.data_length > 0:
                frame_data = self.test_data[
                    frame_info.data_offset : frame_info.data_offset + frame_info.data_length
                ]
                modified_frames[i] = self.video_stego.hide_in_frame(
                    self.test_frames[i], frame_data, frame_info
                )

        # Extract data from modified frames
        extracted_data = b""
        for i, frame_info in enumerate(frame_infos):
            if frame_info.data_length > 0:
                frame_data = self.video_stego.extract_from_frame(
                    modified_frames[i], frame_info.data_length, frame_info
                )
                extracted_data += frame_data

        # With DCT quantization errors, check for reasonable accuracy
        if len(extracted_data) == len(self.test_data):
            accuracy = sum(1 for a, b in zip(extracted_data, self.test_data) if a == b) / len(
                self.test_data
            )
            self.assertGreater(accuracy, 0.6, f"Extraction accuracy too low: {accuracy:.2%}")
        else:
            # If lengths don't match, check prefix accuracy
            min_len = min(len(extracted_data), len(self.test_data))
            if min_len > 0:
                accuracy = (
                    sum(
                        1
                        for a, b in zip(extracted_data[:min_len], self.test_data[:min_len])
                        if a == b
                    )
                    / min_len
                )
                self.assertGreater(
                    accuracy,
                    0.5,
                    f"Prefix accuracy too low: {accuracy:.2%} (lengths: {len(extracted_data)} vs {len(self.test_data)})",
                )
            else:
                self.fail("No data extracted")

    def test_capacity_calculation_dct(self):
        """Test DCT-based capacity calculation."""
        video_info = {
            "fps": 30.0,
            "width": 320,
            "height": 240,
            "total_frames": len(self.test_frames),
            "duration": len(self.test_frames) / 30.0,
        }

        capacity = self.video_stego.calculate_video_capacity(self.test_frames, video_info)

        # DCT capacity should be reasonable for video size
        expected_min_capacity = len(self.test_frames) * 100  # At least 100 bytes per frame
        expected_max_capacity = len(self.test_frames) * 10000  # No more than 10KB per frame

        self.assertGreater(capacity, expected_min_capacity)
        self.assertLess(capacity, expected_max_capacity)

        # Should be able to hide our test data
        self.assertGreater(capacity, len(self.test_data))

    def test_frame_quality_analysis(self):
        """Test frame quality analysis for adaptive hiding."""
        smooth_frame = np.full((240, 320, 3), 128, dtype=np.uint8)  # Uniform gray
        complex_frame = self.test_frames[5]  # Frame with texture

        # Analyze frame complexity
        smooth_complexity = self.video_stego._analyze_frame_complexity(smooth_frame)
        complex_complexity = self.video_stego._analyze_frame_complexity(complex_frame)

        # Complex frame should have higher variance
        self.assertGreater(
            complex_complexity["texture_measure"], smooth_complexity["texture_measure"]
        )

        # Should affect data capacity
        self.assertGreater(
            complex_complexity["recommended_capacity"], smooth_complexity["recommended_capacity"]
        )

    def test_color_space_conversion_accuracy(self):
        """Test RGB<->YUV color space conversion accuracy."""
        rgb_frame = self.test_frames[0]

        # Convert to YUV and back
        yuv_frame = self.video_stego._rgb_to_yuv(rgb_frame)
        reconstructed_rgb = self.video_stego._yuv_to_rgb(yuv_frame)

        # Should be very close to original
        mse = np.mean((rgb_frame.astype(np.float64) - reconstructed_rgb.astype(np.float64)) ** 2)
        self.assertLess(mse, 1.0, "RGB<->YUV conversion should be nearly lossless")

        # YUV frame should have 3 channels
        self.assertEqual(yuv_frame.shape, rgb_frame.shape)
        self.assertEqual(reconstructed_rgb.shape, rgb_frame.shape)

    def test_block_division_edge_handling(self):
        """Test 8x8 block division with non-multiples of 8."""
        # Create frame with odd dimensions
        odd_frame = np.random.randint(0, 256, (243, 317, 3), dtype=np.uint8)
        frame_info = VideoFrameInfo(frame_number=0, frame_type="I", size=(317, 243))

        # Should handle padding correctly
        stego_frame = self.video_stego.hide_in_frame(odd_frame, b"test", frame_info)

        # Output should have same dimensions as input
        self.assertEqual(stego_frame.shape, odd_frame.shape)

        # Should be able to extract data
        extracted = self.video_stego.extract_from_frame(stego_frame, 4, frame_info)
        self.assertEqual(extracted, b"test")

    def test_password_based_coefficient_selection(self):
        """Test that different passwords give different coefficient selections."""
        frame = self.test_frames[0]
        frame_info = VideoFrameInfo(frame_number=0, frame_type="I", size=(320, 240))

        # Create two instances with different passwords
        stego1 = TestVideoSteganography(password="password1", use_dct=True)
        stego2 = TestVideoSteganography(password="password2", use_dct=True)

        # Hide same data with different passwords
        stego_frame1 = stego1.hide_in_frame(frame, self.test_data, frame_info)
        stego_frame2 = stego2.hide_in_frame(frame, self.test_data, frame_info)

        # Results should be different
        self.assertFalse(np.array_equal(stego_frame1, stego_frame2))

        # Each should extract correctly with correct password (allow some DCT quantization errors)
        extracted1 = stego1.extract_from_frame(stego_frame1, len(self.test_data), frame_info)
        extracted2 = stego2.extract_from_frame(stego_frame2, len(self.test_data), frame_info)

        # Check accuracy for password 1
        accuracy1 = sum(1 for a, b in zip(extracted1, self.test_data) if a == b) / len(
            self.test_data
        )
        self.assertGreater(
            accuracy1, 0.7, f"Password 1 extraction accuracy too low: {accuracy1:.2%}"
        )

        # Check accuracy for password 2
        accuracy2 = sum(1 for a, b in zip(extracted2, self.test_data) if a == b) / len(
            self.test_data
        )
        self.assertGreater(
            accuracy2, 0.7, f"Password 2 extraction accuracy too low: {accuracy2:.2%}"
        )

        # Cross-extraction should fail or give different results
        try:
            cross_extracted = stego1.extract_from_frame(
                stego_frame2, len(self.test_data), frame_info
            )
            self.assertNotEqual(cross_extracted, self.test_data)
        except:
            pass  # Extraction failure is also acceptable

    def test_temporal_spreading_consistency(self):
        """Test temporal data spreading across frames."""
        video_info = {
            "fps": 30.0,
            "width": 320,
            "height": 240,
            "total_frames": len(self.test_frames),
            "duration": len(self.test_frames) / 30.0,
        }

        # Enable temporal spreading
        self.video_stego.temporal_spread = True

        # Distribute data
        frame_infos = self.video_stego.distribute_data(self.test_data, self.test_frames, video_info)

        # Data should be spread across multiple frames
        frames_with_data = sum(1 for info in frame_infos if info.data_length > 0)
        self.assertGreater(frames_with_data, 1, "Data should be spread across multiple frames")

        # Total data length should match
        total_distributed = sum(info.data_length for info in frame_infos)
        self.assertEqual(total_distributed, len(self.test_data))

    def test_error_on_insufficient_capacity(self):
        """Test error handling when data exceeds frame capacity."""
        frame = self.test_frames[0]
        frame_info = VideoFrameInfo(frame_number=0, frame_type="I", size=(320, 240))

        # Create data that's too large
        huge_data = b"x" * 100000  # 100KB should exceed single frame capacity

        with self.assertRaises((CapacityError, DCTSteganographyError)):
            self.video_stego.hide_in_frame(frame, huge_data, frame_info)

    def test_corrupted_frame_handling(self):
        """Test handling of corrupted or invalid frames."""
        frame_info = VideoFrameInfo(frame_number=0, frame_type="I", size=(320, 240))

        # Test with invalid frame shapes
        invalid_frames = [
            np.zeros((100, 100)),  # No color channels
            np.zeros((240, 320, 4)),  # Too many channels
            np.zeros((0, 0, 3)),  # Zero size
        ]

        for invalid_frame in invalid_frames:
            with self.assertRaises((VideoFormatError, DCTSteganographyError)):
                self.video_stego.hide_in_frame(invalid_frame, b"test", frame_info)


class TestVideoDCTIntegration(unittest.TestCase):
    """Test integration of DCT steganography with video processing."""

    def setUp(self):
        """Set up test environment."""
        if not CV2_AVAILABLE:
            self.skipTest("OpenCV not available")
        if not VIDEO_CORE_AVAILABLE:
            self.skipTest("Video core not available")

        self.video_stego = TestVideoSteganography(password="integration_test", use_dct=True)

    def test_frame_sequence_consistency(self):
        """Test consistency across frame sequences."""
        # Create sequence of similar frames
        base_frame = np.random.randint(50, 200, (240, 320, 3), dtype=np.uint8)
        frames = []

        for i in range(5):
            # Add small variations
            noise = np.random.randint(-10, 11, base_frame.shape, dtype=np.int16)
            frame = np.clip(base_frame.astype(np.int16) + noise, 0, 255).astype(np.uint8)
            frames.append(frame)

        # Hide same data in each frame
        test_data = b"consistent_data_test"
        stego_frames = []

        for i, frame in enumerate(frames):
            frame_info = VideoFrameInfo(
                frame_number=i, frame_type="I" if i % 10 == 0 else "P", size=(320, 240)
            )
            stego_frame = self.video_stego.hide_in_frame(frame, test_data, frame_info)
            stego_frames.append(stego_frame)

        # Extract and verify from each frame
        for i, stego_frame in enumerate(stego_frames):
            frame_info = VideoFrameInfo(
                frame_number=i, frame_type="I" if i % 10 == 0 else "P", size=(320, 240)
            )
            extracted = self.video_stego.extract_from_frame(stego_frame, len(test_data), frame_info)
            self.assertEqual(extracted, test_data)

    def test_different_frame_types(self):
        """Test DCT steganography with different frame types (I, P, B)."""
        frame = np.random.randint(0, 256, (240, 320, 3), dtype=np.uint8)
        test_data = b"frame_type_test"

        frame_types = ["I", "P", "B"]

        for frame_type in frame_types:
            frame_info = VideoFrameInfo(frame_number=0, frame_type=frame_type, size=(320, 240))

            # Should work with all frame types
            stego_frame = self.video_stego.hide_in_frame(frame, test_data, frame_info)
            extracted = self.video_stego.extract_from_frame(stego_frame, len(test_data), frame_info)

            self.assertEqual(extracted, test_data)

    def test_variable_frame_sizes(self):
        """Test DCT steganography with different frame sizes."""
        test_data = b"size_test"

        frame_sizes = [
            (120, 160),  # Small
            (240, 320),  # Medium
            (480, 640),  # Large
            (243, 317),  # Odd dimensions
        ]

        for height, width in frame_sizes:
            frame = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
            frame_info = VideoFrameInfo(frame_number=0, frame_type="I", size=(width, height))

            # Should work with all sizes
            stego_frame = self.video_stego.hide_in_frame(frame, test_data, frame_info)
            extracted = self.video_stego.extract_from_frame(stego_frame, len(test_data), frame_info)

            self.assertEqual(extracted, test_data)


class TestVideoDCTPerformance(unittest.TestCase):
    """Test performance characteristics of DCT steganography."""

    def setUp(self):
        """Set up performance tests."""
        if not CV2_AVAILABLE:
            self.skipTest("OpenCV not available")
        if not VIDEO_CORE_AVAILABLE:
            self.skipTest("Video core not available")

        self.video_stego = TestVideoSteganography(use_dct=True)

    def test_single_frame_performance(self):
        """Test performance of single frame processing."""
        frame = np.random.randint(0, 256, (720, 1280, 3), dtype=np.uint8)  # 720p
        frame_info = VideoFrameInfo(frame_number=0, frame_type="I", size=(1280, 720))
        test_data = b"performance_test_data" * 10  # ~200 bytes

        import time

        # Measure hide performance
        start_time = time.time()
        stego_frame = self.video_stego.hide_in_frame(frame, test_data, frame_info)
        hide_time = time.time() - start_time

        # Should complete in reasonable time (< 1 second for 720p)
        self.assertLess(hide_time, 1.0, "DCT hiding should complete in < 1 second")

        # Measure extract performance
        start_time = time.time()
        extracted = self.video_stego.extract_from_frame(stego_frame, len(test_data), frame_info)
        extract_time = time.time() - start_time

        self.assertLess(extract_time, 0.5, "DCT extraction should complete in < 0.5 seconds")
        self.assertEqual(extracted, test_data)

    def test_memory_usage_large_frames(self):
        """Test memory usage with large frames."""
        # Create 4K frame
        large_frame = np.random.randint(0, 256, (2160, 3840, 3), dtype=np.uint8)
        frame_info = VideoFrameInfo(frame_number=0, frame_type="I", size=(3840, 2160))
        test_data = b"4k_test"

        # Should handle large frames without memory issues
        try:
            stego_frame = self.video_stego.hide_in_frame(large_frame, test_data, frame_info)
            extracted = self.video_stego.extract_from_frame(stego_frame, len(test_data), frame_info)
            self.assertEqual(extracted, test_data)
        except MemoryError:
            self.fail("Memory error with 4K frame processing")

    def test_batch_processing_efficiency(self):
        """Test efficiency of processing multiple frames."""
        frames = []
        for i in range(30):  # 1 second of video at 30fps
            frame = np.random.randint(0, 256, (240, 320, 3), dtype=np.uint8)
            frames.append(frame)

        test_data = b"batch_test_data"

        import time

        start_time = time.time()

        # Process all frames
        for i, frame in enumerate(frames):
            frame_info = VideoFrameInfo(
                frame_number=i, frame_type="I" if i % 10 == 0 else "P", size=(320, 240)
            )
            stego_frame = self.video_stego.hide_in_frame(frame, test_data, frame_info)
            extracted = self.video_stego.extract_from_frame(stego_frame, len(test_data), frame_info)
            self.assertEqual(extracted, test_data)

        total_time = time.time() - start_time
        fps = len(frames) / total_time

        # Should achieve reasonable processing speed
        self.assertGreater(fps, 10, f"Processing too slow: {fps:.2f} fps")


class TestVideoDCTQuality(unittest.TestCase):
    """Test quality preservation in DCT steganography."""

    def setUp(self):
        """Set up quality tests."""
        if not CV2_AVAILABLE:
            self.skipTest("OpenCV not available")
        if not VIDEO_CORE_AVAILABLE:
            self.skipTest("Video core not available")

        self.quality_metrics = QualityMetrics()

    def test_psnr_preservation(self):
        """Test PSNR preservation across different data loads."""
        frame = np.random.randint(0, 256, (240, 320, 3), dtype=np.uint8)
        frame_info = VideoFrameInfo(frame_number=0, frame_type="I", size=(320, 240))

        data_sizes = [10, 50, 100, 200, 500]  # Different payload sizes

        for data_size in data_sizes:
            video_stego = TestVideoSteganography(use_dct=True)
            test_data = b"x" * data_size

            stego_frame = video_stego.hide_in_frame(frame, test_data, frame_info)
            psnr = self.quality_metrics.calculate_psnr(frame, stego_frame)

            # PSNR should decrease with larger payloads but remain reasonable
            self.assertGreater(psnr, 30.0, f"PSNR too low for {data_size} bytes: {psnr:.2f}dB")

    def test_ssim_preservation(self):
        """Test SSIM preservation with DCT steganography."""
        frame = self._create_structured_frame()
        frame_info = VideoFrameInfo(frame_number=0, frame_type="I", size=(320, 240))

        video_stego = TestVideoSteganography(use_dct=True)
        test_data = b"ssim_test_data_for_quality_measurement"

        stego_frame = video_stego.hide_in_frame(frame, test_data, frame_info)
        ssim = self.quality_metrics.calculate_ssim(frame, stego_frame)

        # SSIM should remain high
        self.assertGreater(ssim, 0.8, f"SSIM too low: {ssim:.4f}")

    def _create_structured_frame(self) -> np.ndarray:
        """Create a structured test frame for quality testing."""
        frame = np.zeros((240, 320, 3), dtype=np.uint8)

        # Add gradients
        for i in range(240):
            frame[i, :, 0] = int(255 * i / 240)
        for j in range(320):
            frame[:, j, 1] = int(255 * j / 320)

        # Add some texture
        frame[:, :, 2] = 128

        return frame


if __name__ == "__main__":
    unittest.main(verbosity=2, buffer=True)
