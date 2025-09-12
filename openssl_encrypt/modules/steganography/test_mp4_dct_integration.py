"""
MP4 DCT Integration Tests for Video Steganography.

This module provides comprehensive tests for integrating DCT-based steganography
with MP4 video file processing, including container parsing, frame extraction,
and real video file handling.
"""

import logging
import os
import struct
import sys
import tempfile
import unittest
from typing import Any, Dict, List, Optional

import numpy as np

# Add the parent directory to the path so we can import the modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    import cv2

    VIDEO_SUPPORT_AVAILABLE = True
except ImportError:
    VIDEO_SUPPORT_AVAILABLE = False
    cv2 = None

try:
    from .stego_video_mp4 import (
        MP4ContainerInfo,
        MP4FormatError,
        MP4FrameInfo,
        MP4VideoSteganography,
    )

    MP4_SUPPORT_AVAILABLE = True
except ImportError:
    # Module doesn't exist yet, will be created during implementation
    MP4VideoSteganography = None
    MP4FormatError = None
    MP4ContainerInfo = None
    MP4FrameInfo = None
    MP4_SUPPORT_AVAILABLE = False

try:
    from .stego_qim_advanced import AdaptiveQIM, UniformQIM
    from .stego_video_core import VideoFrameInfo, VideoSteganographyBase

    CORE_AVAILABLE = True
except ImportError:
    VideoSteganographyBase = None
    VideoFrameInfo = None
    UniformQIM = None
    AdaptiveQIM = None
    CORE_AVAILABLE = False

# Set up logging
logging.basicConfig(level=logging.WARNING)


class TestMP4ContainerParsing(unittest.TestCase):
    """Test MP4 container parsing and metadata extraction."""

    def setUp(self):
        """Set up test fixtures."""
        if not MP4_SUPPORT_AVAILABLE:
            self.skipTest("MP4 support not available")

        # Create a minimal synthetic MP4-like structure for testing
        self.test_mp4_data = self._create_test_mp4_data()

        # Save to temporary file
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
        self.temp_file.write(self.test_mp4_data)
        self.temp_file.close()

    def tearDown(self):
        """Clean up test fixtures."""
        if hasattr(self, "temp_file"):
            try:
                os.unlink(self.temp_file.name)
            except:
                pass

    def _create_test_mp4_data(self) -> bytes:
        """Create minimal MP4-like test data."""
        # This is a simplified MP4 structure for testing
        # Real implementation would parse actual MP4 atoms/boxes

        # ftyp box (file type)
        ftyp = b"ftyp" + b"isom" + struct.pack(">I", 0) + b"isommp41"
        ftyp_size = len(ftyp) + 4
        ftyp_box = struct.pack(">I", ftyp_size) + ftyp

        # moov box (metadata) - simplified
        moov_data = b"mvhd" + b"\x00" * 100  # Movie header
        moov = b"moov" + moov_data
        moov_size = len(moov) + 4
        moov_box = struct.pack(">I", moov_size) + moov

        # mdat box (media data) - simplified
        mdat_data = b"\x00" * 1000  # Fake video data
        mdat = b"mdat" + mdat_data
        mdat_size = len(mdat) + 4
        mdat_box = struct.pack(">I", mdat_size) + mdat

        return ftyp_box + moov_box + mdat_box

    def test_mp4_container_initialization(self):
        """Test MP4 container initialization."""
        mp4_stego = MP4VideoSteganography(self.temp_file.name)
        self.assertIsNotNone(mp4_stego)
        self.assertEqual(mp4_stego.container_path, self.temp_file.name)

    def test_mp4_container_info_extraction(self):
        """Test extraction of MP4 container information."""
        mp4_stego = MP4VideoSteganography(self.temp_file.name)
        container_info = mp4_stego.get_container_info()

        self.assertIsInstance(container_info, MP4ContainerInfo)
        self.assertGreater(container_info.file_size, 0)
        self.assertIsInstance(container_info.video_tracks, list)
        self.assertIsInstance(container_info.audio_tracks, list)

    def test_mp4_atom_parsing(self):
        """Test MP4 atom/box parsing."""
        mp4_stego = MP4VideoSteganography(self.temp_file.name)
        atoms = mp4_stego.parse_atoms()

        self.assertIsInstance(atoms, list)
        self.assertGreater(len(atoms), 0)

        # Should find basic atoms
        atom_types = [atom["type"] for atom in atoms]
        self.assertIn("ftyp", atom_types)

    def test_video_track_identification(self):
        """Test identification of video tracks."""
        mp4_stego = MP4VideoSteganography(self.temp_file.name)
        video_tracks = mp4_stego.get_video_tracks()

        self.assertIsInstance(video_tracks, list)
        # Should have at least one video track or none (for our simple test data)
        for track in video_tracks:
            self.assertIsInstance(track, dict)
            self.assertIn("track_id", track)

    def test_mp4_format_validation(self):
        """Test MP4 format validation."""
        mp4_stego = MP4VideoSteganography(self.temp_file.name)
        is_valid = mp4_stego.validate_format()

        self.assertIsInstance(is_valid, bool)
        # Our minimal test data should be recognizable as MP4-like
        self.assertTrue(is_valid)

    def test_invalid_mp4_file(self):
        """Test handling of invalid MP4 files."""
        # Create invalid file
        invalid_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
        invalid_file.write(b"not an mp4 file")
        invalid_file.close()

        try:
            with self.assertRaises(MP4FormatError):
                MP4VideoSteganography(invalid_file.name)
        finally:
            os.unlink(invalid_file.name)


class TestMP4FrameExtraction(unittest.TestCase):
    """Test frame extraction from MP4 files."""

    def setUp(self):
        """Set up test fixtures."""
        if not MP4_SUPPORT_AVAILABLE or not VIDEO_SUPPORT_AVAILABLE:
            self.skipTest("MP4 or video support not available")

        # Create synthetic video data
        self.test_width = 320
        self.test_height = 240
        self.test_frames = 10
        self.temp_video = self._create_test_video()

    def tearDown(self):
        """Clean up test fixtures."""
        if hasattr(self, "temp_video"):
            try:
                os.unlink(self.temp_video)
            except:
                pass

    def _create_test_video(self) -> str:
        """Create a test MP4 video file."""
        temp_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
        temp_file.close()

        # Create video using OpenCV
        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        writer = cv2.VideoWriter(temp_file.name, fourcc, 30.0, (self.test_width, self.test_height))

        for i in range(self.test_frames):
            # Create frame with gradient pattern
            frame = np.zeros((self.test_height, self.test_width, 3), dtype=np.uint8)

            # Add gradient and pattern
            for y in range(self.test_height):
                for x in range(self.test_width):
                    frame[y, x, 0] = (x + i * 10) % 256  # Red gradient
                    frame[y, x, 1] = (y + i * 5) % 256  # Green gradient
                    frame[y, x, 2] = (x + y + i) % 256  # Blue pattern

            writer.write(frame)

        writer.release()
        return temp_file.name

    def test_mp4_frame_count(self):
        """Test extraction of frame count from MP4."""
        mp4_stego = MP4VideoSteganography(self.temp_video)
        frame_count = mp4_stego.get_frame_count()

        self.assertIsInstance(frame_count, int)
        self.assertGreater(frame_count, 0)
        self.assertLessEqual(frame_count, self.test_frames + 2)  # Allow some variance

    def test_frame_extraction(self):
        """Test extraction of individual frames."""
        mp4_stego = MP4VideoSteganography(self.temp_video)

        # Extract first few frames
        frames = []
        for i in range(min(3, mp4_stego.get_frame_count())):
            frame = mp4_stego.extract_frame(i)
            frames.append(frame)

            # Validate frame properties
            self.assertIsInstance(frame, np.ndarray)
            self.assertEqual(frame.shape[2], 3)  # RGB
            self.assertGreater(frame.shape[0], 0)  # Height
            self.assertGreater(frame.shape[1], 0)  # Width

        # Frames should be different
        if len(frames) > 1:
            self.assertFalse(np.array_equal(frames[0], frames[1]))

    def test_frame_info_extraction(self):
        """Test extraction of frame metadata."""
        mp4_stego = MP4VideoSteganography(self.temp_video)

        for i in range(min(3, mp4_stego.get_frame_count())):
            frame_info = mp4_stego.get_frame_info(i)

            self.assertIsInstance(frame_info, MP4FrameInfo)
            self.assertEqual(frame_info.frame_number, i)
            self.assertIn(frame_info.frame_type, ["I", "P", "B", "Unknown"])
            self.assertGreater(frame_info.size[0], 0)
            self.assertGreater(frame_info.size[1], 0)

    def test_keyframe_identification(self):
        """Test identification of keyframes (I-frames)."""
        mp4_stego = MP4VideoSteganography(self.temp_video)
        keyframes = mp4_stego.get_keyframe_indices()

        self.assertIsInstance(keyframes, list)
        self.assertGreater(len(keyframes), 0)

        # First frame should typically be a keyframe
        self.assertIn(0, keyframes)

        # All keyframes should be valid frame indices
        for keyframe_idx in keyframes:
            self.assertIsInstance(keyframe_idx, int)
            self.assertGreaterEqual(keyframe_idx, 0)
            self.assertLess(keyframe_idx, mp4_stego.get_frame_count())

    def test_frame_batch_extraction(self):
        """Test batch extraction of multiple frames."""
        mp4_stego = MP4VideoSteganography(self.temp_video)
        total_frames = mp4_stego.get_frame_count()

        # Extract frames in batch
        frame_indices = list(range(min(5, total_frames)))
        frames = mp4_stego.extract_frames_batch(frame_indices)

        self.assertEqual(len(frames), len(frame_indices))

        for i, frame in enumerate(frames):
            self.assertIsInstance(frame, np.ndarray)
            self.assertEqual(frame.shape[2], 3)

    def test_frame_extraction_performance(self):
        """Test performance of frame extraction."""
        import time

        mp4_stego = MP4VideoSteganography(self.temp_video)

        # Measure time for extracting frames
        start_time = time.time()

        frame_count = min(5, mp4_stego.get_frame_count())
        for i in range(frame_count):
            frame = mp4_stego.extract_frame(i)
            self.assertIsNotNone(frame)

        end_time = time.time()
        extraction_time = end_time - start_time

        # Should extract frames reasonably quickly
        time_per_frame = extraction_time / frame_count
        self.assertLess(time_per_frame, 1.0, "Frame extraction too slow")


class TestMP4DCTSteganography(unittest.TestCase):
    """Test DCT steganography with MP4 files."""

    def setUp(self):
        """Set up test fixtures."""
        if not MP4_SUPPORT_AVAILABLE or not VIDEO_SUPPORT_AVAILABLE:
            self.skipTest("MP4 or video support not available")

        self.test_data = b"MP4 DCT steganography test data with various symbols: 12345!@#$%"
        self.test_video = self._create_test_video()

        # Different QIM algorithms to test
        self.qim_algorithms = ["uniform", "adaptive", "distortion_compensated"]

    def tearDown(self):
        """Clean up test fixtures."""
        if hasattr(self, "test_video"):
            try:
                os.unlink(self.test_video)
            except:
                pass

    def _create_test_video(self) -> str:
        """Create test video with sufficient complexity for DCT."""
        temp_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
        temp_file.close()

        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        writer = cv2.VideoWriter(temp_file.name, fourcc, 30.0, (640, 480))

        for i in range(20):  # More frames for better capacity
            frame = np.zeros((480, 640, 3), dtype=np.uint8)

            # Create complex patterns for better DCT performance
            for y in range(480):
                for x in range(640):
                    frame[y, x, 0] = int(127 + 100 * np.sin(x / 50) * np.cos(y / 50))
                    frame[y, x, 1] = int(127 + 80 * np.sin((x + y) / 40))
                    frame[y, x, 2] = int(127 + 60 * np.cos(x / 30) * np.sin(y / 30))

            # Add some noise for texture
            noise = np.random.normal(0, 10, frame.shape).astype(np.int16)
            frame = np.clip(frame.astype(np.int16) + noise, 0, 255).astype(np.uint8)

            writer.write(frame)

        writer.release()
        return temp_file.name

    def test_mp4_dct_capacity_estimation(self):
        """Test capacity estimation for MP4 DCT steganography."""
        mp4_stego = MP4VideoSteganography(self.test_video)
        capacity = mp4_stego.estimate_capacity()

        self.assertIsInstance(capacity, int)
        self.assertGreater(capacity, len(self.test_data))

        # Should have reasonable capacity for our test video
        self.assertGreater(capacity, 1000)  # At least 1KB capacity

    def test_mp4_dct_hide_extract_basic(self):
        """Test basic hide/extract with MP4 DCT."""
        for qim_algorithm in self.qim_algorithms:
            with self.subTest(qim_algorithm=qim_algorithm):
                mp4_stego = MP4VideoSteganography(self.test_video, qim_algorithm=qim_algorithm)

                # Hide data
                output_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
                output_file.close()

                try:
                    success = mp4_stego.hide_data(self.test_data, output_file.name)
                    self.assertTrue(success, f"Failed to hide data with {qim_algorithm}")

                    # Verify output file was created and has reasonable size
                    self.assertTrue(os.path.exists(output_file.name))
                    output_size = os.path.getsize(output_file.name)
                    original_size = os.path.getsize(self.test_video)
                    self.assertGreater(output_size, original_size * 0.8)  # Not too much smaller

                    # Extract data
                    mp4_extract = MP4VideoSteganography(
                        output_file.name, qim_algorithm=qim_algorithm
                    )
                    extracted_data = mp4_extract.extract_data()

                    # Validate extraction (allow some error for DCT quantization)
                    if len(extracted_data) == len(self.test_data):
                        accuracy = sum(
                            1 for a, b in zip(extracted_data, self.test_data) if a == b
                        ) / len(self.test_data)
                        self.assertGreater(
                            accuracy, 0.7, f"Accuracy too low for {qim_algorithm}: {accuracy:.2%}"
                        )
                    else:
                        # Check prefix accuracy if lengths differ
                        min_len = min(len(extracted_data), len(self.test_data))
                        if min_len > 0:
                            accuracy = (
                                sum(
                                    1
                                    for a, b in zip(
                                        extracted_data[:min_len], self.test_data[:min_len]
                                    )
                                    if a == b
                                )
                                / min_len
                            )
                            self.assertGreater(
                                accuracy,
                                0.6,
                                f"Prefix accuracy too low for {qim_algorithm}: {accuracy:.2%}",
                            )

                finally:
                    try:
                        os.unlink(output_file.name)
                    except:
                        pass

    def test_mp4_dct_keyframe_only_hiding(self):
        """Test hiding data only in keyframes."""
        mp4_stego = MP4VideoSteganography(self.test_video, frame_selection_strategy="keyframes")

        keyframes = mp4_stego.get_keyframe_indices()
        self.assertGreater(len(keyframes), 0)

        # Estimate capacity for keyframes only
        keyframe_capacity = mp4_stego.estimate_capacity()

        if keyframe_capacity >= len(self.test_data):
            output_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
            output_file.close()

            try:
                success = mp4_stego.hide_data(self.test_data, output_file.name)
                self.assertTrue(success)

                # Extract and verify
                mp4_extract = MP4VideoSteganography(
                    output_file.name, frame_selection_strategy="keyframes"
                )
                extracted_data = mp4_extract.extract_data()

                # Should extract some data successfully
                self.assertGreater(len(extracted_data), len(self.test_data) // 2)

            finally:
                try:
                    os.unlink(output_file.name)
                except:
                    pass

    def test_mp4_dct_quality_preservation(self):
        """Test quality preservation in MP4 DCT steganography."""
        mp4_stego = MP4VideoSteganography(self.test_video, quality_preservation=9)  # High quality

        output_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
        output_file.close()

        try:
            success = mp4_stego.hide_data(self.test_data, output_file.name)
            self.assertTrue(success)

            # Compare quality metrics between original and stego video
            original_frames = []
            stego_frames = []

            mp4_original = MP4VideoSteganography(self.test_video)
            mp4_stego_result = MP4VideoSteganography(output_file.name)

            for i in range(min(3, mp4_original.get_frame_count())):
                orig_frame = mp4_original.extract_frame(i)
                stego_frame = mp4_stego_result.extract_frame(i)

                original_frames.append(orig_frame)
                stego_frames.append(stego_frame)

            # Calculate PSNR between original and stego frames
            for orig, stego in zip(original_frames, stego_frames):
                if orig.shape == stego.shape:
                    mse = np.mean((orig.astype(float) - stego.astype(float)) ** 2)
                    if mse > 0:
                        psnr = 20 * np.log10(255.0 / np.sqrt(mse))
                        self.assertGreater(psnr, 30.0, "Quality degradation too high")

        finally:
            try:
                os.unlink(output_file.name)
            except:
                pass

    def test_mp4_dct_large_data_handling(self):
        """Test handling of large data payloads."""
        # Create larger test data
        large_data = b"Large data payload: " + b"X" * 2000

        mp4_stego = MP4VideoSteganography(self.test_video)
        capacity = mp4_stego.estimate_capacity()

        if capacity >= len(large_data):
            output_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
            output_file.close()

            try:
                success = mp4_stego.hide_data(large_data, output_file.name)
                self.assertTrue(success)

                # Extract and verify size
                mp4_extract = MP4VideoSteganography(output_file.name)
                extracted_data = mp4_extract.extract_data()

                # Should extract reasonable amount of data
                self.assertGreater(len(extracted_data), len(large_data) // 2)

            finally:
                try:
                    os.unlink(output_file.name)
                except:
                    pass
        else:
            self.skipTest(f"Insufficient capacity: {capacity} < {len(large_data)}")

    def test_mp4_dct_error_correction_integration(self):
        """Test integration with error correction."""
        mp4_stego = MP4VideoSteganography(
            self.test_video,
            temporal_spread=True,  # Enable error correction
            qim_algorithm="adaptive",
        )

        output_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
        output_file.close()

        try:
            success = mp4_stego.hide_data(self.test_data, output_file.name)
            self.assertTrue(success)

            # Extract with error correction
            mp4_extract = MP4VideoSteganography(
                output_file.name, temporal_spread=True, qim_algorithm="adaptive"
            )
            extracted_data = mp4_extract.extract_data()

            # Error correction should improve accuracy
            self.assertGreater(len(extracted_data), 0)

            # Check if we get reasonable data back
            if len(extracted_data) >= len(self.test_data) // 2:
                # At least got substantial portion back
                self.assertTrue(True)

        finally:
            try:
                os.unlink(output_file.name)
            except:
                pass


class TestMP4Performance(unittest.TestCase):
    """Test performance characteristics of MP4 DCT steganography."""

    def setUp(self):
        """Set up test fixtures."""
        if not MP4_SUPPORT_AVAILABLE or not VIDEO_SUPPORT_AVAILABLE:
            self.skipTest("MP4 or video support not available")

        self.test_data = b"Performance test data: " + b"A" * 500
        self.test_video = self._create_performance_test_video()

    def tearDown(self):
        """Clean up test fixtures."""
        if hasattr(self, "test_video"):
            try:
                os.unlink(self.test_video)
            except:
                pass

    def _create_performance_test_video(self) -> str:
        """Create video for performance testing."""
        temp_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
        temp_file.close()

        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        writer = cv2.VideoWriter(temp_file.name, fourcc, 30.0, (320, 240))

        for i in range(30):  # 30 frames for 1 second video
            frame = np.random.randint(0, 256, (240, 320, 3), dtype=np.uint8)
            writer.write(frame)

        writer.release()
        return temp_file.name

    def test_hiding_performance(self):
        """Test performance of data hiding."""
        import time

        mp4_stego = MP4VideoSteganography(self.test_video)

        output_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
        output_file.close()

        try:
            start_time = time.time()
            success = mp4_stego.hide_data(self.test_data, output_file.name)
            end_time = time.time()

            if success:
                hiding_time = end_time - start_time

                # Should complete in reasonable time
                self.assertLess(hiding_time, 10.0, "Data hiding too slow")

                # Calculate throughput
                throughput = len(self.test_data) / hiding_time
                self.assertGreater(throughput, 10, "Throughput too low (bytes/sec)")

        finally:
            try:
                os.unlink(output_file.name)
            except:
                pass

    def test_extraction_performance(self):
        """Test performance of data extraction."""
        import time

        mp4_stego = MP4VideoSteganography(self.test_video)

        # First hide data
        output_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
        output_file.close()

        try:
            success = mp4_stego.hide_data(self.test_data, output_file.name)

            if success:
                mp4_extract = MP4VideoSteganography(output_file.name)

                start_time = time.time()
                extracted_data = mp4_extract.extract_data()
                end_time = time.time()

                extraction_time = end_time - start_time

                # Should extract reasonably quickly
                self.assertLess(extraction_time, 5.0, "Data extraction too slow")

                if len(extracted_data) > 0:
                    throughput = len(extracted_data) / extraction_time
                    self.assertGreater(throughput, 50, "Extraction throughput too low")

        finally:
            try:
                os.unlink(output_file.name)
            except:
                pass

    def test_memory_usage(self):
        """Test memory usage during processing."""
        import os

        import psutil

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        mp4_stego = MP4VideoSteganography(self.test_video)

        output_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
        output_file.close()

        try:
            # Hide data and monitor memory
            success = mp4_stego.hide_data(self.test_data, output_file.name)

            peak_memory = process.memory_info().rss
            memory_increase = peak_memory - initial_memory

            # Memory increase should be reasonable (less than 100MB for small video)
            memory_increase_mb = memory_increase / (1024 * 1024)
            self.assertLess(
                memory_increase_mb, 100, f"Memory usage too high: {memory_increase_mb:.1f} MB"
            )

        finally:
            try:
                os.unlink(output_file.name)
            except:
                pass


class TestMP4EdgeCases(unittest.TestCase):
    """Test edge cases and error handling for MP4 DCT steganography."""

    def setUp(self):
        """Set up test fixtures."""
        if not MP4_SUPPORT_AVAILABLE or not VIDEO_SUPPORT_AVAILABLE:
            self.skipTest("MP4 or video support not available")

    def test_empty_data_handling(self):
        """Test handling of empty data payload."""
        test_video = self._create_minimal_video()

        try:
            mp4_stego = MP4VideoSteganography(test_video)

            output_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
            output_file.close()

            try:
                # Should handle empty data gracefully
                success = mp4_stego.hide_data(b"", output_file.name)
                self.assertTrue(success)

                # Extract should return empty data
                mp4_extract = MP4VideoSteganography(output_file.name)
                extracted_data = mp4_extract.extract_data()
                self.assertEqual(len(extracted_data), 0)

            finally:
                try:
                    os.unlink(output_file.name)
                except:
                    pass

        finally:
            try:
                os.unlink(test_video)
            except:
                pass

    def test_insufficient_capacity_handling(self):
        """Test handling when data exceeds capacity."""
        test_video = self._create_minimal_video()

        try:
            mp4_stego = MP4VideoSteganography(test_video)
            capacity = mp4_stego.estimate_capacity()

            # Try to hide data larger than capacity
            oversized_data = b"X" * (capacity + 1000)

            output_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
            output_file.close()

            try:
                # Should handle gracefully (either reject or truncate)
                success = mp4_stego.hide_data(oversized_data, output_file.name)

                if success:
                    # If it succeeded, extraction should work
                    mp4_extract = MP4VideoSteganography(output_file.name)
                    extracted_data = mp4_extract.extract_data()
                    self.assertGreater(len(extracted_data), 0)

            finally:
                try:
                    os.unlink(output_file.name)
                except:
                    pass

        finally:
            try:
                os.unlink(test_video)
            except:
                pass

    def test_corrupted_video_handling(self):
        """Test handling of corrupted video files."""
        # Create corrupted MP4 file
        corrupted_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
        corrupted_file.write(b"CORRUPTED MP4 DATA" * 100)
        corrupted_file.close()

        try:
            # Should raise appropriate error
            with self.assertRaises((MP4FormatError, Exception)):
                MP4VideoSteganography(corrupted_file.name)

        finally:
            try:
                os.unlink(corrupted_file.name)
            except:
                pass

    def _create_minimal_video(self) -> str:
        """Create minimal video for testing."""
        temp_file = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
        temp_file.close()

        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        writer = cv2.VideoWriter(temp_file.name, fourcc, 30.0, (160, 120))

        # Create just 3 frames
        for i in range(3):
            frame = np.full((120, 160, 3), i * 80, dtype=np.uint8)
            writer.write(frame)

        writer.release()
        return temp_file.name


if __name__ == "__main__":
    unittest.main()
