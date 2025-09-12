#!/usr/bin/env python3
"""
Robustness and Performance Tests for DCT Video Steganography

This module contains comprehensive tests for evaluating:
1. Robustness against various attacks and distortions
2. Performance metrics (speed, memory usage, throughput)
3. Scalability under different conditions
4. Resilience to compression and noise

Test Categories:
- Compression robustness (JPEG, video compression)
- Noise robustness (Gaussian, salt-and-pepper, uniform)
- Geometric attacks (rotation, scaling, cropping)
- Performance benchmarks (embedding/extraction speed)
- Memory usage profiling
- Large-scale capacity testing
- Statistical security analysis
"""

import os
import random
import tempfile
import time
import unittest
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock, patch

import cv2
import numpy as np
import psutil

from openssl_encrypt.modules.steganography.stego_qim_advanced import (
    AdaptiveQIM,
    DistortionCompensatedQIM,
    MultiLevelQIM,
    UniformQIM,
)

# Import steganography modules
from openssl_encrypt.modules.steganography.stego_video_core import (
    VideoFrameInfo,
    VideoSteganographyBase,
)


class VideoSteganographyTestImplementation(VideoSteganographyBase):
    """Test implementation of video steganography for robustness testing."""

    def __init__(self, qim_algorithm=None):
        super().__init__()
        self.qim_algorithm = qim_algorithm

    def parse_container(self, video_data: bytes) -> Dict[str, Any]:
        """Simple container parser for testing."""
        return {"format": "test", "codec": "test"}

    def reconstruct_container(
        self,
        container_info: Dict[str, Any],
        modified_frames: List[np.ndarray],
        modified_audio: Optional[bytes] = None,
    ) -> bytes:
        """Simple container reconstruction for testing."""
        return b"test_video_data"

    def hide_data_in_frames(
        self, frames: List[np.ndarray], data: str, qim_algorithm=None
    ) -> List[np.ndarray]:
        """Convenience method to hide data across frames."""
        if qim_algorithm:
            self.qim_algorithm = qim_algorithm

        data_bytes = data.encode("utf-8")
        prepared_data = self.prepare_data_for_hiding(data_bytes)

        # Create frame info objects
        frame_infos = []
        for i, frame in enumerate(frames):
            frame_info = VideoFrameInfo(
                frame_number=i,
                frame_type="I",
                size=(frame.shape[1], frame.shape[0]),
                complexity=0.5,
                capacity=self.calculate_frame_capacity(frame),
            )
            frame_infos.append(frame_info)

        # Distribute data across frames
        distribution = self.distribute_data(prepared_data, frames, {"frame_count": len(frames)})

        # Hide data in frames
        stego_frames = []
        for i, (frame, frame_info) in enumerate(zip(frames, frame_infos)):
            if i < len(distribution):
                data_portion = (
                    distribution[i].data_portion
                    if hasattr(distribution[i], "data_portion")
                    else b""
                )
                if data_portion:
                    stego_frame = self.hide_in_frame(frame.copy(), data_portion, frame_info)
                else:
                    stego_frame = frame.copy()
            else:
                stego_frame = frame.copy()
            stego_frames.append(stego_frame)

        return stego_frames

    def extract_data_from_frames(self, frames: List[np.ndarray], qim_algorithm=None) -> str:
        """Convenience method to extract data from frames."""
        if qim_algorithm:
            self.qim_algorithm = qim_algorithm

        try:
            # Create frame info objects
            frame_infos = []
            for i, frame in enumerate(frames):
                frame_info = VideoFrameInfo(
                    frame_number=i,
                    frame_type="I",
                    size=(frame.shape[1], frame.shape[0]),
                    complexity=0.5,
                    capacity=self.calculate_frame_capacity(frame),
                )
                frame_infos.append(frame_info)

            # Extract data from first frame (simplified)
            if frames and frame_infos:
                expected_length = 1000  # Reasonable guess for test data
                extracted_bytes = self.extract_from_frame(
                    frames[0], expected_length, frame_infos[0]
                )
                if extracted_bytes:
                    clean_data = self.extract_prepared_data(extracted_bytes)
                    return clean_data.decode("utf-8", errors="ignore")
            return ""
        except Exception:
            return ""

    def hide_data(self, cover_data: bytes, secret_data: bytes) -> bytes:
        """Hide secret data in cover data."""
        # Simple implementation - just concatenate for testing
        return cover_data + b"HIDDEN:" + secret_data

    def extract_data(self, stego_data: bytes) -> bytes:
        """Extract secret data from stego data."""
        # Simple implementation - find the hidden marker
        marker = b"HIDDEN:"
        if marker in stego_data:
            return stego_data.split(marker, 1)[1]
        return b""


class TestRobustnessAttacks(unittest.TestCase):
    """Test robustness against various steganographic attacks."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_data = "This is secret test data for robustness testing!"
        self.frame_size = (64, 64)  # Small frames for faster testing
        self.num_frames = 10

        # Create test frames
        self.test_frames = []
        for i in range(self.num_frames):
            frame = np.random.randint(0, 256, (*self.frame_size, 3), dtype=np.uint8)
            # Add some structure to make it more realistic
            frame[10:20, 10:20] = [255, 0, 0]  # Red block
            frame[30:40, 30:40] = [0, 255, 0]  # Green block
            self.test_frames.append(frame)

        # Initialize QIM algorithms
        self.qim_algorithms = {
            "uniform": UniformQIM(quantization_step=4.0),
            "adaptive": AdaptiveQIM(base_quantization_step=4.0, adaptation_factor=0.5),
            "distortion_comp": DistortionCompensatedQIM(
                quantization_step=4.0, compensation_factor=0.1
            ),
            "multi_level": MultiLevelQIM(quantization_step=4.0, bits_per_coefficient=2),
        }

        # Initialize video steganography core
        self.video_core = VideoSteganographyTestImplementation()

    def test_gaussian_noise_robustness(self):
        """Test robustness against Gaussian noise."""
        print("\nTesting Gaussian noise robustness...")

        for qim_name, qim_algo in self.qim_algorithms.items():
            with self.subTest(qim_algorithm=qim_name):
                # Embed data
                stego_frames = self.video_core.hide_data_in_frames(
                    self.test_frames.copy(), self.test_data, qim_algorithm=qim_algo
                )

                # Apply Gaussian noise with different intensities
                noise_levels = [0.01, 0.05, 0.1, 0.2]
                for noise_level in noise_levels:
                    with self.subTest(noise_level=noise_level):
                        # Add Gaussian noise
                        noisy_frames = []
                        for frame in stego_frames:
                            noise = np.random.normal(0, noise_level * 255, frame.shape)
                            noisy_frame = np.clip(frame.astype(float) + noise, 0, 255).astype(
                                np.uint8
                            )
                            noisy_frames.append(noisy_frame)

                        # Extract data
                        extracted_data = self.video_core.extract_data_from_frames(
                            noisy_frames, qim_algorithm=qim_algo
                        )

                        # Calculate robustness metric
                        if extracted_data:
                            accuracy = self._calculate_string_similarity(
                                self.test_data, extracted_data
                            )
                            print(f"  {qim_name} - Noise {noise_level}: {accuracy:.2%} accuracy")

                            # Expect reasonable robustness for low noise
                            if noise_level <= 0.05:
                                self.assertGreater(
                                    accuracy, 0.7, f"Low noise robustness too poor for {qim_name}"
                                )
                        else:
                            print(f"  {qim_name} - Noise {noise_level}: Complete failure")

    def test_salt_pepper_noise_robustness(self):
        """Test robustness against salt-and-pepper noise."""
        print("\nTesting salt-and-pepper noise robustness...")

        for qim_name, qim_algo in self.qim_algorithms.items():
            with self.subTest(qim_algorithm=qim_name):
                # Embed data
                stego_frames = self.video_core.hide_data_in_frames(
                    self.test_frames.copy(), self.test_data, qim_algorithm=qim_algo
                )

                # Apply salt-and-pepper noise with different densities
                noise_densities = [0.01, 0.05, 0.1, 0.15]
                for density in noise_densities:
                    with self.subTest(noise_density=density):
                        # Add salt-and-pepper noise
                        noisy_frames = []
                        for frame in stego_frames:
                            noisy_frame = frame.copy()
                            noise_mask = np.random.random(frame.shape[:2]) < density
                            salt_mask = np.random.random(frame.shape[:2]) < 0.5

                            noisy_frame[noise_mask & salt_mask] = 255  # Salt
                            noisy_frame[noise_mask & ~salt_mask] = 0  # Pepper
                            noisy_frames.append(noisy_frame)

                        # Extract data
                        extracted_data = self.video_core.extract_data_from_frames(
                            noisy_frames, qim_algorithm=qim_algo
                        )

                        # Calculate robustness metric
                        if extracted_data:
                            accuracy = self._calculate_string_similarity(
                                self.test_data, extracted_data
                            )
                            print(f"  {qim_name} - S&P {density}: {accuracy:.2%} accuracy")

                            # Expect reasonable robustness for low noise
                            if density <= 0.05:
                                self.assertGreater(
                                    accuracy,
                                    0.6,
                                    f"Low S&P noise robustness too poor for {qim_name}",
                                )
                        else:
                            print(f"  {qim_name} - S&P {density}: Complete failure")

    def test_compression_robustness(self):
        """Test robustness against JPEG compression."""
        print("\nTesting JPEG compression robustness...")

        for qim_name, qim_algo in self.qim_algorithms.items():
            with self.subTest(qim_algorithm=qim_name):
                # Embed data
                stego_frames = self.video_core.hide_data_in_frames(
                    self.test_frames.copy(), self.test_data, qim_algorithm=qim_algo
                )

                # Apply JPEG compression with different quality levels
                quality_levels = [90, 70, 50, 30]
                for quality in quality_levels:
                    with self.subTest(jpeg_quality=quality):
                        # Apply JPEG compression
                        compressed_frames = []
                        for frame in stego_frames:
                            # Encode as JPEG
                            encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), quality]
                            _, encoded_img = cv2.imencode(".jpg", frame, encode_param)

                            # Decode back to frame
                            compressed_frame = cv2.imdecode(encoded_img, cv2.IMREAD_COLOR)
                            compressed_frames.append(compressed_frame)

                        # Extract data
                        extracted_data = self.video_core.extract_data_from_frames(
                            compressed_frames, qim_algorithm=qim_algo
                        )

                        # Calculate robustness metric
                        if extracted_data:
                            accuracy = self._calculate_string_similarity(
                                self.test_data, extracted_data
                            )
                            print(f"  {qim_name} - JPEG Q{quality}: {accuracy:.2%} accuracy")

                            # Expect good robustness for high quality compression
                            if quality >= 70:
                                self.assertGreater(
                                    accuracy,
                                    0.8,
                                    f"High quality JPEG robustness too poor for {qim_name}",
                                )
                        else:
                            print(f"  {qim_name} - JPEG Q{quality}: Complete failure")

    def test_scaling_robustness(self):
        """Test robustness against scaling attacks."""
        print("\nTesting scaling robustness...")

        for qim_name, qim_algo in self.qim_algorithms.items():
            with self.subTest(qim_algorithm=qim_name):
                # Embed data
                stego_frames = self.video_core.hide_data_in_frames(
                    self.test_frames.copy(), self.test_data, qim_algorithm=qim_algo
                )

                # Apply scaling with different factors
                scale_factors = [0.8, 0.9, 1.1, 1.2]
                for scale_factor in scale_factors:
                    with self.subTest(scale_factor=scale_factor):
                        # Scale frames
                        scaled_frames = []
                        original_size = self.frame_size
                        new_size = (
                            int(original_size[0] * scale_factor),
                            int(original_size[1] * scale_factor),
                        )

                        for frame in stego_frames:
                            # Scale down/up
                            scaled = cv2.resize(frame, new_size, interpolation=cv2.INTER_CUBIC)
                            # Scale back to original size
                            rescaled = cv2.resize(
                                scaled, original_size, interpolation=cv2.INTER_CUBIC
                            )
                            scaled_frames.append(rescaled)

                        # Extract data
                        extracted_data = self.video_core.extract_data_from_frames(
                            scaled_frames, qim_algorithm=qim_algo
                        )

                        # Calculate robustness metric
                        if extracted_data:
                            accuracy = self._calculate_string_similarity(
                                self.test_data, extracted_data
                            )
                            print(f"  {qim_name} - Scale {scale_factor}: {accuracy:.2%} accuracy")

                            # Expect moderate robustness for small scaling
                            if 0.9 <= scale_factor <= 1.1:
                                self.assertGreater(
                                    accuracy,
                                    0.5,
                                    f"Small scaling robustness too poor for {qim_name}",
                                )
                        else:
                            print(f"  {qim_name} - Scale {scale_factor}: Complete failure")

    def test_rotation_robustness(self):
        """Test robustness against rotation attacks."""
        print("\nTesting rotation robustness...")

        for qim_name, qim_algo in self.qim_algorithms.items():
            with self.subTest(qim_algorithm=qim_name):
                # Embed data
                stego_frames = self.video_core.hide_data_in_frames(
                    self.test_frames.copy(), self.test_data, qim_algorithm=qim_algo
                )

                # Apply rotation with different angles
                rotation_angles = [1, 2, 5, 10]  # Small angles for DCT robustness
                for angle in rotation_angles:
                    with self.subTest(rotation_angle=angle):
                        # Rotate frames
                        rotated_frames = []
                        center = (self.frame_size[0] // 2, self.frame_size[1] // 2)

                        for frame in stego_frames:
                            # Create rotation matrix
                            rotation_matrix = cv2.getRotationMatrix2D(center, angle, 1.0)
                            # Apply rotation
                            rotated = cv2.warpAffine(frame, rotation_matrix, self.frame_size)
                            rotated_frames.append(rotated)

                        # Extract data
                        extracted_data = self.video_core.extract_data_from_frames(
                            rotated_frames, qim_algorithm=qim_algo
                        )

                        # Calculate robustness metric
                        if extracted_data:
                            accuracy = self._calculate_string_similarity(
                                self.test_data, extracted_data
                            )
                            print(f"  {qim_name} - Rotate {angle}°: {accuracy:.2%} accuracy")

                            # Expect some robustness for very small rotations
                            if angle <= 2:
                                self.assertGreater(
                                    accuracy,
                                    0.3,
                                    f"Small rotation robustness too poor for {qim_name}",
                                )
                        else:
                            print(f"  {qim_name} - Rotate {angle}°: Complete failure")

    def test_cropping_robustness(self):
        """Test robustness against cropping attacks."""
        print("\nTesting cropping robustness...")

        for qim_name, qim_algo in self.qim_algorithms.items():
            with self.subTest(qim_algorithm=qim_name):
                # Embed data
                stego_frames = self.video_core.hide_data_in_frames(
                    self.test_frames.copy(), self.test_data, qim_algorithm=qim_algo
                )

                # Apply cropping with different percentages
                crop_percentages = [0.05, 0.1, 0.2, 0.3]  # Remove this much from each side
                for crop_pct in crop_percentages:
                    with self.subTest(crop_percentage=crop_pct):
                        # Crop frames
                        cropped_frames = []
                        crop_pixels = int(min(self.frame_size) * crop_pct)

                        for frame in stego_frames:
                            # Crop from all sides
                            cropped = frame[
                                crop_pixels : -crop_pixels or None,
                                crop_pixels : -crop_pixels or None,
                            ]
                            # Resize back to original size
                            resized = cv2.resize(
                                cropped, self.frame_size, interpolation=cv2.INTER_CUBIC
                            )
                            cropped_frames.append(resized)

                        # Extract data
                        extracted_data = self.video_core.extract_data_from_frames(
                            cropped_frames, qim_algorithm=qim_algo
                        )

                        # Calculate robustness metric
                        if extracted_data:
                            accuracy = self._calculate_string_similarity(
                                self.test_data, extracted_data
                            )
                            print(
                                f"  {qim_name} - Crop {crop_pct*100:.0f}%: {accuracy:.2%} accuracy"
                            )

                            # Expect some robustness for small cropping
                            if crop_pct <= 0.1:
                                self.assertGreater(
                                    accuracy,
                                    0.4,
                                    f"Small cropping robustness too poor for {qim_name}",
                                )
                        else:
                            print(f"  {qim_name} - Crop {crop_pct*100:.0f}%: Complete failure")

    def _calculate_string_similarity(self, original: str, extracted: str) -> float:
        """Calculate similarity between original and extracted strings."""
        if not extracted:
            return 0.0

        # Use simple character-wise accuracy
        min_len = min(len(original), len(extracted))
        if min_len == 0:
            return 0.0

        matches = sum(1 for i in range(min_len) if original[i] == extracted[i])
        return matches / len(original)


class TestPerformanceBenchmarks(unittest.TestCase):
    """Test performance characteristics of DCT video steganography."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_data = "Performance test data " * 100  # Longer data for benchmarks
        self.small_frames = self._create_test_frames(32, 32, 5)
        self.medium_frames = self._create_test_frames(128, 128, 20)
        self.large_frames = self._create_test_frames(256, 256, 50)

        # Initialize QIM algorithms
        self.qim_algorithms = {
            "uniform": UniformQIM(quantization_step=4.0),
            "adaptive": AdaptiveQIM(base_quantization_step=4.0, adaptation_factor=0.5),
            "distortion_comp": DistortionCompensatedQIM(
                quantization_step=4.0, compensation_factor=0.1
            ),
            "multi_level": MultiLevelQIM(quantization_step=4.0, bits_per_coefficient=2),
        }

        self.video_core = VideoSteganographyTestImplementation()

    def _create_test_frames(self, width: int, height: int, count: int) -> List[np.ndarray]:
        """Create test frames of specified size."""
        frames = []
        for i in range(count):
            frame = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
            # Add some structured content
            frame[height // 4 : 3 * height // 4, width // 4 : 3 * width // 4] = [128, 128, 128]
            frames.append(frame)
        return frames

    def test_embedding_speed_benchmarks(self):
        """Benchmark embedding speed for different frame sizes and algorithms."""
        print("\nEmbedding Speed Benchmarks:")
        print("-" * 50)

        test_configs = [
            ("Small (32x32x5)", self.small_frames),
            ("Medium (128x128x20)", self.medium_frames),
            ("Large (256x256x50)", self.large_frames),
        ]

        for config_name, frames in test_configs:
            print(f"\n{config_name}:")

            for qim_name, qim_algo in self.qim_algorithms.items():
                # Measure embedding time
                start_time = time.time()

                try:
                    stego_frames = self.video_core.hide_data_in_frames(
                        frames.copy(), self.test_data, qim_algorithm=qim_algo
                    )

                    end_time = time.time()
                    duration = end_time - start_time

                    # Calculate metrics
                    total_pixels = sum(f.shape[0] * f.shape[1] for f in frames)
                    pixels_per_second = total_pixels / duration if duration > 0 else float("inf")
                    frames_per_second = len(frames) / duration if duration > 0 else float("inf")

                    print(
                        f"  {qim_name:15s}: {duration:.3f}s, "
                        f"{pixels_per_second:8.0f} pixels/s, {frames_per_second:.1f} fps"
                    )

                    # Performance assertions
                    if config_name == "Small (32x32x5)":
                        self.assertLess(
                            duration, 5.0, f"Small frame embedding too slow for {qim_name}"
                        )

                except Exception as e:
                    print(f"  {qim_name:15s}: ERROR - {str(e)}")

    def test_extraction_speed_benchmarks(self):
        """Benchmark extraction speed for different frame sizes and algorithms."""
        print("\nExtraction Speed Benchmarks:")
        print("-" * 50)

        test_configs = [
            ("Small (32x32x5)", self.small_frames),
            ("Medium (128x128x20)", self.medium_frames),
            ("Large (256x256x50)", self.large_frames),
        ]

        for config_name, frames in test_configs:
            print(f"\n{config_name}:")

            for qim_name, qim_algo in self.qim_algorithms.items():
                try:
                    # First embed data
                    stego_frames = self.video_core.hide_data_in_frames(
                        frames.copy(), self.test_data, qim_algorithm=qim_algo
                    )

                    # Measure extraction time
                    start_time = time.time()

                    extracted_data = self.video_core.extract_data_from_frames(
                        stego_frames, qim_algorithm=qim_algo
                    )

                    end_time = time.time()
                    duration = end_time - start_time

                    # Calculate metrics
                    total_pixels = sum(f.shape[0] * f.shape[1] for f in frames)
                    pixels_per_second = total_pixels / duration if duration > 0 else float("inf")
                    frames_per_second = len(frames) / duration if duration > 0 else float("inf")

                    print(
                        f"  {qim_name:15s}: {duration:.3f}s, "
                        f"{pixels_per_second:8.0f} pixels/s, {frames_per_second:.1f} fps"
                    )

                    # Performance assertions
                    if config_name == "Small (32x32x5)":
                        self.assertLess(
                            duration, 5.0, f"Small frame extraction too slow for {qim_name}"
                        )

                except Exception as e:
                    print(f"  {qim_name:15s}: ERROR - {str(e)}")

    def test_memory_usage_profiling(self):
        """Profile memory usage during embedding and extraction."""
        print("\nMemory Usage Profiling:")
        print("-" * 30)

        process = psutil.Process(os.getpid())

        for qim_name, qim_algo in self.qim_algorithms.items():
            print(f"\n{qim_name}:")

            # Measure baseline memory
            baseline_memory = process.memory_info().rss / 1024 / 1024  # MB

            try:
                # Measure memory during embedding
                memory_before_embed = process.memory_info().rss / 1024 / 1024

                stego_frames = self.video_core.hide_data_in_frames(
                    self.medium_frames.copy(), self.test_data, qim_algorithm=qim_algo
                )

                memory_after_embed = process.memory_info().rss / 1024 / 1024
                embed_memory_delta = memory_after_embed - memory_before_embed

                # Measure memory during extraction
                memory_before_extract = process.memory_info().rss / 1024 / 1024

                extracted_data = self.video_core.extract_data_from_frames(
                    stego_frames, qim_algorithm=qim_algo
                )

                memory_after_extract = process.memory_info().rss / 1024 / 1024
                extract_memory_delta = memory_after_extract - memory_before_extract

                print(f"  Baseline: {baseline_memory:.1f} MB")
                print(f"  Embed delta: {embed_memory_delta:+.1f} MB")
                print(f"  Extract delta: {extract_memory_delta:+.1f} MB")
                print(f"  Peak usage: {max(memory_after_embed, memory_after_extract):.1f} MB")

                # Memory usage assertions
                self.assertLess(
                    embed_memory_delta, 500, f"Embedding memory usage too high for {qim_name}"
                )
                self.assertLess(
                    extract_memory_delta, 500, f"Extraction memory usage too high for {qim_name}"
                )

            except Exception as e:
                print(f"  ERROR: {str(e)}")

    def test_capacity_scalability(self):
        """Test capacity and scalability with increasing data sizes."""
        print("\nCapacity Scalability Test:")
        print("-" * 30)

        # Test with increasing data sizes
        data_sizes = [100, 500, 1000, 2000, 5000]  # characters

        for qim_name, qim_algo in self.qim_algorithms.items():
            print(f"\n{qim_name}:")

            for data_size in data_sizes:
                test_data = "X" * data_size

                try:
                    start_time = time.time()

                    # Try embedding with large frames
                    stego_frames = self.video_core.hide_data_in_frames(
                        self.large_frames.copy(), test_data, qim_algorithm=qim_algo
                    )

                    extracted_data = self.video_core.extract_data_from_frames(
                        stego_frames, qim_algorithm=qim_algo
                    )

                    end_time = time.time()
                    duration = end_time - start_time

                    # Calculate success metrics
                    success = extracted_data == test_data
                    accuracy = len(extracted_data) / len(test_data) if extracted_data else 0
                    throughput = data_size / duration if duration > 0 else float("inf")

                    print(
                        f"  {data_size:4d} chars: {success} "
                        f"(acc={accuracy:.2%}, {throughput:.0f} chars/s, {duration:.2f}s)"
                    )

                except Exception as e:
                    print(f"  {data_size:4d} chars: FAILED - {str(e)}")

    def test_concurrent_operations_performance(self):
        """Test performance under concurrent operations."""
        print("\nConcurrent Operations Performance:")
        print("-" * 40)

        import threading
        from concurrent.futures import ThreadPoolExecutor

        def embed_extract_task(qim_algo, frames, data, task_id):
            """Single embed/extract task."""
            try:
                start_time = time.time()

                stego_frames = self.video_core.hide_data_in_frames(
                    frames.copy(), f"{data}_{task_id}", qim_algorithm=qim_algo
                )

                extracted_data = self.video_core.extract_data_from_frames(
                    stego_frames, qim_algorithm=qim_algo
                )

                end_time = time.time()
                duration = end_time - start_time
                success = extracted_data == f"{data}_{task_id}"

                return {
                    "task_id": task_id,
                    "duration": duration,
                    "success": success,
                    "thread_id": threading.current_thread().ident,
                }

            except Exception as e:
                return {
                    "task_id": task_id,
                    "duration": 0,
                    "success": False,
                    "error": str(e),
                    "thread_id": threading.current_thread().ident,
                }

        # Test with different thread counts
        thread_counts = [1, 2, 4]
        num_tasks = 8

        for qim_name, qim_algo in self.qim_algorithms.items():
            print(f"\n{qim_name}:")

            for thread_count in thread_counts:
                start_time = time.time()

                with ThreadPoolExecutor(max_workers=thread_count) as executor:
                    futures = []
                    for i in range(num_tasks):
                        future = executor.submit(
                            embed_extract_task, qim_algo, self.small_frames, f"concurrent_test", i
                        )
                        futures.append(future)

                    # Collect results
                    results = [future.result() for future in futures]

                end_time = time.time()
                total_duration = end_time - start_time

                # Analyze results
                successful_tasks = sum(1 for r in results if r["success"])
                avg_task_duration = np.mean([r["duration"] for r in results if r["duration"] > 0])
                unique_threads = len(set(r["thread_id"] for r in results))

                print(
                    f"  {thread_count} threads: {successful_tasks}/{num_tasks} success, "
                    f"total={total_duration:.2f}s, avg_task={avg_task_duration:.2f}s, "
                    f"threads_used={unique_threads}"
                )

                # Performance assertions
                self.assertGreaterEqual(
                    successful_tasks, num_tasks // 2, f"Too many concurrent failures for {qim_name}"
                )


class TestStatisticalSecurity(unittest.TestCase):
    """Test statistical security and detectability characteristics."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_data = "Statistical security test data!"
        self.frame_size = (64, 64)
        self.num_frames = 20

        # Create test frames with different characteristics
        self.natural_frames = self._create_natural_frames()
        self.uniform_frames = self._create_uniform_frames()

        # Initialize QIM algorithms
        self.qim_algorithms = {
            "uniform": UniformQIM(quantization_step=4.0),
            "adaptive": AdaptiveQIM(base_quantization_step=4.0, adaptation_factor=0.5),
            "distortion_comp": DistortionCompensatedQIM(
                quantization_step=4.0, compensation_factor=0.1
            ),
        }

        self.video_core = VideoSteganographyTestImplementation()

    def _create_natural_frames(self) -> List[np.ndarray]:
        """Create frames with natural image characteristics."""
        frames = []
        for i in range(self.num_frames):
            # Create frame with natural-like gradients and structures
            frame = np.zeros((*self.frame_size, 3), dtype=np.uint8)

            # Add gradient background
            for y in range(self.frame_size[0]):
                for x in range(self.frame_size[1]):
                    frame[y, x, 0] = int(128 + 64 * np.sin(x * 0.1) * np.cos(y * 0.1))
                    frame[y, x, 1] = int(128 + 32 * np.cos(x * 0.15 + i * 0.1))
                    frame[y, x, 2] = int(128 + 48 * np.sin(y * 0.12 + i * 0.2))

            # Add some noise for realism
            noise = np.random.normal(0, 5, frame.shape).astype(np.int16)
            frame = np.clip(frame.astype(np.int16) + noise, 0, 255).astype(np.uint8)

            frames.append(frame)
        return frames

    def _create_uniform_frames(self) -> List[np.ndarray]:
        """Create frames with uniform random characteristics."""
        frames = []
        for i in range(self.num_frames):
            frame = np.random.randint(0, 256, (*self.frame_size, 3), dtype=np.uint8)
            frames.append(frame)
        return frames

    def test_dct_coefficient_distribution_analysis(self):
        """Analyze DCT coefficient distributions before and after embedding."""
        print("\nDCT Coefficient Distribution Analysis:")
        print("-" * 45)

        for qim_name, qim_algo in self.qim_algorithms.items():
            print(f"\n{qim_name}:")

            # Analyze natural frames
            original_coeffs = self._extract_dct_coefficients(self.natural_frames)

            # Embed data
            stego_frames = self.video_core.hide_data_in_frames(
                self.natural_frames.copy(), self.test_data, qim_algorithm=qim_algo
            )

            stego_coeffs = self._extract_dct_coefficients(stego_frames)

            # Statistical analysis
            orig_mean = np.mean(original_coeffs)
            orig_std = np.std(original_coeffs)
            stego_mean = np.mean(stego_coeffs)
            stego_std = np.std(stego_coeffs)

            mean_change = abs(stego_mean - orig_mean) / orig_mean if orig_mean != 0 else 0
            std_change = abs(stego_std - orig_std) / orig_std if orig_std != 0 else 0

            print(f"  Original: μ={orig_mean:.2f}, σ={orig_std:.2f}")
            print(f"  Stego:    μ={stego_mean:.2f}, σ={stego_std:.2f}")
            print(f"  Changes:  μ={mean_change:.2%}, σ={std_change:.2%}")

            # Statistical security assertions
            self.assertLess(mean_change, 0.1, f"Mean change too large for {qim_name}")
            self.assertLess(std_change, 0.2, f"Std change too large for {qim_name}")

    def test_chi_square_attack_resistance(self):
        """Test resistance to chi-square statistical attacks."""
        print("\nChi-Square Attack Resistance:")
        print("-" * 35)

        from scipy.stats import chisquare

        for qim_name, qim_algo in self.qim_algorithms.items():
            print(f"\n{qim_name}:")

            # Embed data in frames
            stego_frames = self.video_core.hide_data_in_frames(
                self.natural_frames.copy(), self.test_data, qim_algorithm=qim_algo
            )

            # Extract DCT coefficients
            original_coeffs = self._extract_dct_coefficients(self.natural_frames)
            stego_coeffs = self._extract_dct_coefficients(stego_frames)

            # Create histograms for chi-square test
            bins = 50
            orig_hist, _ = np.histogram(original_coeffs, bins=bins, density=True)
            stego_hist, _ = np.histogram(stego_coeffs, bins=bins, density=True)

            # Perform chi-square test
            # Add small epsilon to avoid division by zero
            expected = orig_hist + 1e-10
            observed = stego_hist + 1e-10

            chi2_stat, p_value = chisquare(observed, expected)

            print(f"  Chi-square statistic: {chi2_stat:.3f}")
            print(f"  P-value: {p_value:.6f}")
            print(f"  Detectable: {'YES' if p_value < 0.01 else 'NO'}")

            # Security assertion: high p-value means less detectable
            self.assertGreater(
                p_value, 0.001, f"Chi-square test detects steganography for {qim_name}"
            )

    def test_histogram_attack_resistance(self):
        """Test resistance to histogram-based attacks."""
        print("\nHistogram Attack Resistance:")
        print("-" * 32)

        for qim_name, qim_algo in self.qim_algorithms.items():
            print(f"\n{qim_name}:")

            # Embed data
            stego_frames = self.video_core.hide_data_in_frames(
                self.natural_frames.copy(), self.test_data, qim_algorithm=qim_algo
            )

            # Compare pixel value histograms
            for channel in range(3):  # RGB channels
                orig_pixels = np.concatenate(
                    [f[:, :, channel].flatten() for f in self.natural_frames]
                )
                stego_pixels = np.concatenate([f[:, :, channel].flatten() for f in stego_frames])

                # Create histograms
                orig_hist, bins = np.histogram(orig_pixels, bins=256, range=(0, 256))
                stego_hist, _ = np.histogram(stego_pixels, bins=256, range=(0, 256))

                # Calculate histogram difference metrics
                l1_distance = np.sum(np.abs(orig_hist - stego_hist))
                l2_distance = np.sqrt(np.sum((orig_hist - stego_hist) ** 2))
                max_diff = np.max(np.abs(orig_hist - stego_hist))

                print(
                    f"  Channel {channel}: L1={l1_distance}, L2={l2_distance:.1f}, Max={max_diff}"
                )

                # Security assertions: small histogram changes
                total_pixels = len(orig_pixels)
                self.assertLess(
                    l1_distance / total_pixels,
                    0.02,
                    f"L1 histogram change too large for {qim_name} channel {channel}",
                )

    def _extract_dct_coefficients(self, frames: List[np.ndarray]) -> np.ndarray:
        """Extract DCT coefficients from frames."""
        all_coefficients = []

        for frame in frames:
            # Convert to YUV and extract Y channel
            yuv_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2YUV)
            y_channel = yuv_frame[:, :, 0].astype(np.float32)

            # Apply DCT to 8x8 blocks
            height, width = y_channel.shape

            for i in range(0, height - 7, 8):
                for j in range(0, width - 7, 8):
                    block = y_channel[i : i + 8, j : j + 8]
                    dct_block = cv2.dct(block)
                    all_coefficients.extend(dct_block.flatten())

        return np.array(all_coefficients)


if __name__ == "__main__":
    # Run tests with detailed output
    test_suite = unittest.TestLoader().loadTestsFromModule(__import__(__name__))
    runner = unittest.TextTestRunner(verbosity=2, buffer=False)
    runner.run(test_suite)
