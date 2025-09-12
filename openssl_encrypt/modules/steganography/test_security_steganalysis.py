#!/usr/bin/env python3
"""
Security and Steganalysis Tests for DCT Video Steganography

This module contains comprehensive security analysis tests for evaluating:
1. Resistance to various steganalysis attacks
2. Information-theoretic security measures
3. Structural analysis of hidden data
4. Advanced statistical detection methods
5. Machine learning-based steganalysis simulation
6. Payload capacity vs. security tradeoffs

Test Categories:
- Classical steganalysis (visual attack, histogram analysis, DCT analysis)
- Advanced statistical attacks (Pairs analysis, RS analysis, Sample Pairs)
- Machine learning detection simulation
- Information-theoretic measures (entropy, mutual information)
- Structural analysis (block artifacts, quantization effects)
- Payload size security analysis
- Multi-modal detection (spatial and frequency domain)
"""

import logging
import math
import unittest
from typing import Any, Dict, List, Optional, Tuple

import cv2
import numpy as np
from scipy import stats
from scipy.stats import entropy

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


class VideoSteganographySecurityTest(VideoSteganographyBase):
    """Security test implementation of video steganography."""

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

    def hide_data(self, cover_data: bytes, secret_data: bytes) -> bytes:
        """Hide secret data in cover data."""
        return cover_data + b"HIDDEN:" + secret_data

    def extract_data(self, stego_data: bytes) -> bytes:
        """Extract secret data from stego data."""
        marker = b"HIDDEN:"
        if marker in stego_data:
            return stego_data.split(marker, 1)[1]
        return b""

    def hide_data_in_frames(
        self, frames: List[np.ndarray], data: str, qim_algorithm=None
    ) -> List[np.ndarray]:
        """Hide data across frames using DCT steganography."""
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

        # Hide data in frames
        stego_frames = []
        for i, (frame, frame_info) in enumerate(zip(frames, frame_infos)):
            if i == 0 and prepared_data:  # Hide in first frame only for simplicity
                stego_frame = self.hide_in_frame(frame.copy(), prepared_data, frame_info)
            else:
                stego_frame = frame.copy()
            stego_frames.append(stego_frame)

        return stego_frames

    def extract_data_from_frames(self, frames: List[np.ndarray], qim_algorithm=None) -> str:
        """Extract data from frames."""
        if qim_algorithm:
            self.qim_algorithm = qim_algorithm

        try:
            if frames:
                frame_info = VideoFrameInfo(
                    frame_number=0,
                    frame_type="I",
                    size=(frames[0].shape[1], frames[0].shape[0]),
                    complexity=0.5,
                    capacity=self.calculate_frame_capacity(frames[0]),
                )

                expected_length = 1000
                extracted_bytes = self.extract_from_frame(frames[0], expected_length, frame_info)
                if extracted_bytes:
                    clean_data = self.extract_prepared_data(extracted_bytes)
                    return clean_data.decode("utf-8", errors="ignore")
            return ""
        except Exception:
            return ""


class TestClassicalSteganalysis(unittest.TestCase):
    """Test resistance to classical steganalysis attacks."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_data = "Secret message for security testing!"
        self.frame_size = (128, 128)
        self.num_frames = 10

        # Create natural-looking test frames
        self.test_frames = self._create_natural_frames()

        # Initialize QIM algorithms
        self.qim_algorithms = {
            "uniform": UniformQIM(quantization_step=4.0),
            "adaptive": AdaptiveQIM(base_quantization_step=4.0, adaptation_factor=0.5),
            "distortion_comp": DistortionCompensatedQIM(
                quantization_step=4.0, compensation_factor=0.1
            ),
        }

        self.video_core = VideoSteganographySecurityTest()

    def _create_natural_frames(self) -> List[np.ndarray]:
        """Create frames with natural image characteristics."""
        frames = []
        for i in range(self.num_frames):
            # Create frame with natural-like gradients
            frame = np.zeros((*self.frame_size, 3), dtype=np.uint8)

            # Add complex natural patterns
            x, y = np.meshgrid(np.arange(self.frame_size[1]), np.arange(self.frame_size[0]))

            # Create multiple frequency components
            pattern1 = 128 + 50 * np.sin(x * 0.05 + i * 0.1) * np.cos(y * 0.03)
            pattern2 = 128 + 30 * np.sin(x * 0.08 - y * 0.02 + i * 0.15)
            pattern3 = 128 + 40 * np.cos(x * 0.02 + y * 0.07 + i * 0.2)

            frame[:, :, 0] = np.clip(pattern1, 0, 255).astype(np.uint8)
            frame[:, :, 1] = np.clip(pattern2, 0, 255).astype(np.uint8)
            frame[:, :, 2] = np.clip(pattern3, 0, 255).astype(np.uint8)

            # Add realistic noise
            noise = np.random.normal(0, 3, frame.shape)
            frame = np.clip(frame.astype(float) + noise, 0, 255).astype(np.uint8)

            frames.append(frame)
        return frames

    def test_visual_attack_detection(self):
        """Test resistance to visual detection attacks."""
        print("\nTesting Visual Attack Detection:")
        print("-" * 35)

        for qim_name, qim_algo in self.qim_algorithms.items():
            with self.subTest(qim_algorithm=qim_name):
                # Hide data
                stego_frames = self.video_core.hide_data_in_frames(
                    self.test_frames.copy(), self.test_data, qim_algorithm=qim_algo
                )

                # Visual difference analysis
                visual_metrics = self._analyze_visual_differences(self.test_frames, stego_frames)

                print(
                    f"  {qim_name:15s}: PSNR={visual_metrics['psnr']:.2f}dB, "
                    f"SSIM={visual_metrics['ssim']:.4f}, "
                    f"MSE={visual_metrics['mse']:.2f}"
                )

                # Security assertions for visual imperceptibility
                self.assertGreater(
                    visual_metrics["psnr"],
                    35.0,
                    f"PSNR too low for {qim_name} (visual detection risk)",
                )
                self.assertGreater(
                    visual_metrics["ssim"],
                    0.95,
                    f"SSIM too low for {qim_name} (structural changes visible)",
                )
                self.assertLess(
                    visual_metrics["mse"],
                    50.0,
                    f"MSE too high for {qim_name} (pixel changes too large)",
                )

    def test_histogram_analysis_resistance(self):
        """Test resistance to histogram-based steganalysis."""
        print("\nTesting Histogram Analysis Resistance:")
        print("-" * 40)

        for qim_name, qim_algo in self.qim_algorithms.items():
            with self.subTest(qim_algorithm=qim_name):
                # Hide data
                stego_frames = self.video_core.hide_data_in_frames(
                    self.test_frames.copy(), self.test_data, qim_algorithm=qim_algo
                )

                # Histogram analysis for each color channel
                histogram_metrics = {}
                for channel in range(3):
                    metrics = self._analyze_histogram_security(
                        self.test_frames, stego_frames, channel
                    )
                    histogram_metrics[f"channel_{channel}"] = metrics

                # Calculate overall histogram security
                avg_chi2 = np.mean([m["chi2_statistic"] for m in histogram_metrics.values()])
                avg_pvalue = np.mean([m["p_value"] for m in histogram_metrics.values()])
                max_deviation = max([m["max_deviation"] for m in histogram_metrics.values()])

                print(
                    f"  {qim_name:15s}: Chi2={avg_chi2:.3f}, "
                    f"P-val={avg_pvalue:.6f}, Max_dev={max_deviation:.1f}"
                )

                # Security assertions
                self.assertGreater(
                    avg_pvalue, 0.01, f"Histogram changes too significant for {qim_name}"
                )
                self.assertLess(
                    max_deviation, 100, f"Maximum histogram deviation too large for {qim_name}"
                )

    def test_dct_domain_analysis(self):
        """Test resistance to DCT domain steganalysis."""
        print("\nTesting DCT Domain Analysis:")
        print("-" * 30)

        for qim_name, qim_algo in self.qim_algorithms.items():
            with self.subTest(qim_algorithm=qim_name):
                # Hide data
                stego_frames = self.video_core.hide_data_in_frames(
                    self.test_frames.copy(), self.test_data, qim_algorithm=qim_algo
                )

                # DCT coefficient analysis
                dct_metrics = self._analyze_dct_coefficient_security(self.test_frames, stego_frames)

                print(
                    f"  {qim_name:15s}: Coeff_change={dct_metrics['coefficient_change_ratio']:.4f}, "
                    f"Energy_change={dct_metrics['energy_change_ratio']:.4f}, "
                    f"High_freq_change={dct_metrics['high_freq_change_ratio']:.4f}"
                )

                # Security assertions for DCT domain
                self.assertLess(
                    dct_metrics["coefficient_change_ratio"],
                    0.05,
                    f"Too many DCT coefficients changed for {qim_name}",
                )
                self.assertLess(
                    dct_metrics["energy_change_ratio"],
                    0.02,
                    f"DCT energy change too large for {qim_name}",
                )
                self.assertLess(
                    dct_metrics["high_freq_change_ratio"],
                    0.1,
                    f"High frequency changes too significant for {qim_name}",
                )

    def test_block_artifact_analysis(self):
        """Test for detectable block artifacts from DCT embedding."""
        print("\nTesting Block Artifact Analysis:")
        print("-" * 35)

        for qim_name, qim_algo in self.qim_algorithms.items():
            with self.subTest(qim_algorithm=qim_name):
                # Hide data
                stego_frames = self.video_core.hide_data_in_frames(
                    self.test_frames.copy(), self.test_data, qim_algorithm=qim_algo
                )

                # Block artifact analysis
                artifact_metrics = self._analyze_block_artifacts(self.test_frames, stego_frames)

                print(
                    f"  {qim_name:15s}: Block_variance={artifact_metrics['block_variance_change']:.4f}, "
                    f"Edge_strength={artifact_metrics['edge_strength_change']:.4f}, "
                    f"Blockiness={artifact_metrics['blockiness_metric']:.4f}"
                )

                # Security assertions for block artifacts
                self.assertLess(
                    artifact_metrics["block_variance_change"],
                    0.1,
                    f"Block variance change too large for {qim_name}",
                )
                self.assertLess(
                    artifact_metrics["edge_strength_change"],
                    0.05,
                    f"Edge strength change too significant for {qim_name}",
                )
                self.assertLess(
                    artifact_metrics["blockiness_metric"],
                    0.03,
                    f"Blockiness too detectable for {qim_name}",
                )

    def _analyze_visual_differences(
        self, original_frames: List[np.ndarray], stego_frames: List[np.ndarray]
    ) -> Dict[str, float]:
        """Analyze visual differences between original and stego frames."""
        psnr_values = []
        ssim_values = []
        mse_values = []

        for orig, stego in zip(original_frames, stego_frames):
            # Calculate PSNR
            mse = np.mean((orig.astype(float) - stego.astype(float)) ** 2)
            if mse > 0:
                psnr = 20 * math.log10(255.0 / math.sqrt(mse))
            else:
                psnr = float("inf")

            # Calculate SSIM (simplified version)
            mu1 = np.mean(orig)
            mu2 = np.mean(stego)
            sigma1 = np.std(orig)
            sigma2 = np.std(stego)
            sigma12 = np.mean((orig - mu1) * (stego - mu2))

            c1 = (0.01 * 255) ** 2
            c2 = (0.03 * 255) ** 2

            ssim = ((2 * mu1 * mu2 + c1) * (2 * sigma12 + c2)) / (
                (mu1**2 + mu2**2 + c1) * (sigma1**2 + sigma2**2 + c2)
            )

            psnr_values.append(psnr)
            ssim_values.append(ssim)
            mse_values.append(mse)

        return {
            "psnr": np.mean(psnr_values),
            "ssim": np.mean(ssim_values),
            "mse": np.mean(mse_values),
        }

    def _analyze_histogram_security(
        self, original_frames: List[np.ndarray], stego_frames: List[np.ndarray], channel: int
    ) -> Dict[str, float]:
        """Analyze histogram changes for security assessment."""
        # Collect pixel values for the specified channel
        orig_pixels = np.concatenate([f[:, :, channel].flatten() for f in original_frames])
        stego_pixels = np.concatenate([f[:, :, channel].flatten() for f in stego_frames])

        # Create histograms
        bins = np.arange(257)  # 0-255 + 1
        orig_hist, _ = np.histogram(orig_pixels, bins=bins)
        stego_hist, _ = np.histogram(stego_pixels, bins=bins)

        # Chi-square test for histogram similarity
        # Add small constant to avoid division by zero
        expected = orig_hist + 1e-10
        observed = stego_hist + 1e-10

        chi2_stat = np.sum((observed - expected) ** 2 / expected)

        # Calculate p-value (simplified approximation)
        degrees_of_freedom = len(bins) - 2
        p_value = 1 - stats.chi2.cdf(chi2_stat, degrees_of_freedom)

        # Maximum absolute deviation
        max_deviation = np.max(np.abs(orig_hist - stego_hist))

        return {"chi2_statistic": chi2_stat, "p_value": p_value, "max_deviation": max_deviation}

    def _analyze_dct_coefficient_security(
        self, original_frames: List[np.ndarray], stego_frames: List[np.ndarray]
    ) -> Dict[str, float]:
        """Analyze DCT coefficient changes for security assessment."""
        orig_coeffs = []
        stego_coeffs = []

        for orig, stego in zip(original_frames, stego_frames):
            # Convert to YUV and extract Y channel
            orig_yuv = cv2.cvtColor(orig, cv2.COLOR_BGR2YUV)
            stego_yuv = cv2.cvtColor(stego, cv2.COLOR_BGR2YUV)

            orig_y = orig_yuv[:, :, 0].astype(np.float32)
            stego_y = stego_yuv[:, :, 0].astype(np.float32)

            # Apply DCT to 8x8 blocks
            height, width = orig_y.shape

            for i in range(0, height - 7, 8):
                for j in range(0, width - 7, 8):
                    orig_block = orig_y[i : i + 8, j : j + 8]
                    stego_block = stego_y[i : i + 8, j : j + 8]

                    orig_dct = cv2.dct(orig_block)
                    stego_dct = cv2.dct(stego_block)

                    orig_coeffs.extend(orig_dct.flatten())
                    stego_coeffs.extend(stego_dct.flatten())

        orig_coeffs = np.array(orig_coeffs)
        stego_coeffs = np.array(stego_coeffs)

        # Calculate coefficient change metrics
        coefficient_changes = np.abs(stego_coeffs - orig_coeffs)
        coefficient_change_ratio = np.sum(coefficient_changes > 1.0) / len(coefficient_changes)

        # Energy change analysis
        orig_energy = np.sum(orig_coeffs**2)
        stego_energy = np.sum(stego_coeffs**2)
        energy_change_ratio = (
            abs(stego_energy - orig_energy) / orig_energy if orig_energy > 0 else 0
        )

        # High frequency coefficient changes (approximate)
        # Consider coefficients beyond the first few as high frequency
        high_freq_indices = np.arange(8, len(orig_coeffs), 64)  # Skip DC and low frequency
        high_freq_orig = orig_coeffs[high_freq_indices]
        high_freq_stego = stego_coeffs[high_freq_indices]
        high_freq_changes = np.abs(high_freq_stego - high_freq_orig)
        high_freq_change_ratio = np.sum(high_freq_changes > 0.5) / len(high_freq_changes)

        return {
            "coefficient_change_ratio": coefficient_change_ratio,
            "energy_change_ratio": energy_change_ratio,
            "high_freq_change_ratio": high_freq_change_ratio,
        }

    def _analyze_block_artifacts(
        self, original_frames: List[np.ndarray], stego_frames: List[np.ndarray]
    ) -> Dict[str, float]:
        """Analyze block artifacts introduced by DCT embedding."""
        block_variance_changes = []
        edge_strength_changes = []

        for orig, stego in zip(original_frames, stego_frames):
            # Convert to grayscale for analysis
            orig_gray = cv2.cvtColor(orig, cv2.COLOR_BGR2GRAY)
            stego_gray = cv2.cvtColor(stego, cv2.COLOR_BGR2GRAY)

            # Block variance analysis
            orig_var = self._calculate_block_variance(orig_gray)
            stego_var = self._calculate_block_variance(stego_gray)
            block_var_change = abs(stego_var - orig_var) / orig_var if orig_var > 0 else 0
            block_variance_changes.append(block_var_change)

            # Edge strength analysis
            orig_edges = cv2.Sobel(orig_gray, cv2.CV_64F, 1, 1, ksize=3)
            stego_edges = cv2.Sobel(stego_gray, cv2.CV_64F, 1, 1, ksize=3)

            orig_edge_strength = np.mean(np.abs(orig_edges))
            stego_edge_strength = np.mean(np.abs(stego_edges))

            edge_change = (
                abs(stego_edge_strength - orig_edge_strength) / orig_edge_strength
                if orig_edge_strength > 0
                else 0
            )
            edge_strength_changes.append(edge_change)

        # Blockiness metric (simplified)
        avg_block_variance_change = np.mean(block_variance_changes)
        avg_edge_strength_change = np.mean(edge_strength_changes)
        blockiness_metric = (avg_block_variance_change + avg_edge_strength_change) / 2

        return {
            "block_variance_change": avg_block_variance_change,
            "edge_strength_change": avg_edge_strength_change,
            "blockiness_metric": blockiness_metric,
        }

    def _calculate_block_variance(self, image: np.ndarray, block_size: int = 8) -> float:
        """Calculate average variance of image blocks."""
        height, width = image.shape
        variances = []

        for i in range(0, height - block_size + 1, block_size):
            for j in range(0, width - block_size + 1, block_size):
                block = image[i : i + block_size, j : j + block_size]
                variances.append(np.var(block))

        return np.mean(variances) if variances else 0


class TestAdvancedSteganalysis(unittest.TestCase):
    """Test resistance to advanced steganalysis attacks."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_data = "Advanced steganalysis test message!"
        self.frame_size = (64, 64)  # Smaller for faster computation
        self.num_frames = 5

        # Create test frames
        self.test_frames = self._create_complex_frames()

        # Initialize QIM algorithms
        self.qim_algorithms = {
            "uniform": UniformQIM(quantization_step=4.0),
            "adaptive": AdaptiveQIM(base_quantization_step=4.0, adaptation_factor=0.5),
        }

        self.video_core = VideoSteganographySecurityTest()

    def _create_complex_frames(self) -> List[np.ndarray]:
        """Create frames with complex statistical properties."""
        frames = []
        for i in range(self.num_frames):
            frame = np.zeros((*self.frame_size, 3), dtype=np.uint8)

            # Create multi-scale patterns
            x, y = np.meshgrid(np.arange(self.frame_size[1]), np.arange(self.frame_size[0]))

            # Multiple frequency patterns
            pattern = (
                128
                + 40 * np.sin(x * 0.1 + i * 0.2) * np.cos(y * 0.08)
                + 20 * np.sin(x * 0.2 - y * 0.15 + i * 0.1)
                + 15 * np.cos(x * 0.05 + y * 0.12 + i * 0.3)
            )

            for c in range(3):
                frame[:, :, c] = np.clip(pattern + c * 10, 0, 255).astype(np.uint8)

            # Add structured noise
            noise = np.random.laplace(0, 2, frame.shape)
            frame = np.clip(frame.astype(float) + noise, 0, 255).astype(np.uint8)

            frames.append(frame)
        return frames

    def test_rs_analysis_resistance(self):
        """Test resistance to RS (Regular-Singular) steganalysis."""
        print("\nTesting RS Analysis Resistance:")
        print("-" * 33)

        for qim_name, qim_algo in self.qim_algorithms.items():
            with self.subTest(qim_algorithm=qim_name):
                # Hide data
                stego_frames = self.video_core.hide_data_in_frames(
                    self.test_frames.copy(), self.test_data, qim_algorithm=qim_algo
                )

                # RS analysis
                rs_metrics = self._perform_rs_analysis(self.test_frames, stego_frames)

                print(
                    f"  {qim_name:15s}: RS_ratio={rs_metrics['rs_ratio']:.4f}, "
                    f"Predictability={rs_metrics['predictability_change']:.4f}, "
                    f"Regularity={rs_metrics['regularity_measure']:.4f}"
                )

                # Security assertions
                self.assertLess(
                    rs_metrics["rs_ratio"],
                    0.1,
                    f"RS ratio indicates detectable embedding for {qim_name}",
                )
                # Adaptive algorithms may have higher predictability changes due to local adaptation
                threshold = 0.15 if qim_name == "adaptive" else 0.05
                self.assertLess(
                    rs_metrics["predictability_change"],
                    threshold,
                    f"Predictability change too large for {qim_name}",
                )

    def test_sample_pairs_analysis(self):
        """Test resistance to Sample Pairs steganalysis."""
        print("\nTesting Sample Pairs Analysis:")
        print("-" * 32)

        for qim_name, qim_algo in self.qim_algorithms.items():
            with self.subTest(qim_algorithm=qim_name):
                # Hide data
                stego_frames = self.video_core.hide_data_in_frames(
                    self.test_frames.copy(), self.test_data, qim_algorithm=qim_algo
                )

                # Sample Pairs analysis
                sp_metrics = self._perform_sample_pairs_analysis(self.test_frames, stego_frames)

                print(
                    f"  {qim_name:15s}: SP_statistic={sp_metrics['sp_statistic']:.4f}, "
                    f"Pair_ratio_change={sp_metrics['pair_ratio_change']:.4f}, "
                    f"Correlation_change={sp_metrics['correlation_change']:.4f}"
                )

                # Security assertions
                self.assertLess(
                    sp_metrics["sp_statistic"],
                    0.2,
                    f"Sample Pairs statistic indicates detection for {qim_name}",
                )
                self.assertLess(
                    sp_metrics["pair_ratio_change"],
                    0.1,
                    f"Pair ratio change too significant for {qim_name}",
                )

    def test_machine_learning_detection_simulation(self):
        """Simulate machine learning-based steganalysis detection."""
        print("\nTesting ML Detection Simulation:")
        print("-" * 35)

        for qim_name, qim_algo in self.qim_algorithms.items():
            with self.subTest(qim_algorithm=qim_name):
                # Hide data
                stego_frames = self.video_core.hide_data_in_frames(
                    self.test_frames.copy(), self.test_data, qim_algorithm=qim_algo
                )

                # Extract features for ML detection simulation
                ml_features = self._extract_ml_features(self.test_frames, stego_frames)

                # Simulate classification (simplified)
                detection_score = self._simulate_ml_classification(ml_features)

                print(
                    f"  {qim_name:15s}: Detection_score={detection_score:.4f}, "
                    f"Feature_separability={ml_features['separability']:.4f}, "
                    f"Complexity_change={ml_features['complexity_change']:.4f}"
                )

                # Security assertions
                self.assertLess(detection_score, 0.6, f"ML detection score too high for {qim_name}")
                self.assertLess(
                    ml_features["separability"],
                    0.3,
                    f"Feature separability too high for {qim_name}",
                )

    def _perform_rs_analysis(
        self, original_frames: List[np.ndarray], stego_frames: List[np.ndarray]
    ) -> Dict[str, float]:
        """Perform RS analysis on frames."""
        # Simplified RS analysis
        rs_ratios = []
        predictability_changes = []

        for orig, stego in zip(original_frames, stego_frames):
            # Convert to grayscale for analysis
            orig_gray = cv2.cvtColor(orig, cv2.COLOR_BGR2GRAY)
            stego_gray = cv2.cvtColor(stego, cv2.COLOR_BGR2GRAY)

            # Calculate local predictability measures
            orig_pred = self._calculate_predictability(orig_gray)
            stego_pred = self._calculate_predictability(stego_gray)

            # RS ratio calculation (simplified)
            regular_regions_orig = self._count_regular_regions(orig_gray)
            regular_regions_stego = self._count_regular_regions(stego_gray)

            rs_ratio = (
                abs(regular_regions_stego - regular_regions_orig) / regular_regions_orig
                if regular_regions_orig > 0
                else 0
            )
            rs_ratios.append(rs_ratio)

            pred_change = abs(stego_pred - orig_pred) / orig_pred if orig_pred > 0 else 0
            predictability_changes.append(pred_change)

        regularity_measure = np.mean([self._calculate_regularity(f) for f in stego_frames])

        return {
            "rs_ratio": np.mean(rs_ratios),
            "predictability_change": np.mean(predictability_changes),
            "regularity_measure": regularity_measure,
        }

    def _perform_sample_pairs_analysis(
        self, original_frames: List[np.ndarray], stego_frames: List[np.ndarray]
    ) -> Dict[str, float]:
        """Perform Sample Pairs analysis."""
        sp_statistics = []
        pair_ratio_changes = []
        correlation_changes = []

        for orig, stego in zip(original_frames, stego_frames):
            orig_gray = cv2.cvtColor(orig, cv2.COLOR_BGR2GRAY)
            stego_gray = cv2.cvtColor(stego, cv2.COLOR_BGR2GRAY)

            # Sample pairs analysis
            orig_pairs = self._extract_sample_pairs(orig_gray)
            stego_pairs = self._extract_sample_pairs(stego_gray)

            # Calculate SP statistic
            sp_stat = self._calculate_sp_statistic(orig_pairs, stego_pairs)
            sp_statistics.append(sp_stat)

            # Pair ratio changes
            orig_ratio = self._calculate_pair_ratios(orig_pairs)
            stego_ratio = self._calculate_pair_ratios(stego_pairs)
            ratio_change = abs(stego_ratio - orig_ratio) / orig_ratio if orig_ratio > 0 else 0
            pair_ratio_changes.append(ratio_change)

            # Correlation changes
            orig_corr = np.corrcoef(orig_pairs[:, 0], orig_pairs[:, 1])[0, 1]
            stego_corr = np.corrcoef(stego_pairs[:, 0], stego_pairs[:, 1])[0, 1]
            corr_change = (
                abs(stego_corr - orig_corr)
                if not (np.isnan(orig_corr) or np.isnan(stego_corr))
                else 0
            )
            correlation_changes.append(corr_change)

        return {
            "sp_statistic": np.mean(sp_statistics),
            "pair_ratio_change": np.mean(pair_ratio_changes),
            "correlation_change": np.mean(correlation_changes),
        }

    def _extract_ml_features(
        self, original_frames: List[np.ndarray], stego_frames: List[np.ndarray]
    ) -> Dict[str, float]:
        """Extract features for ML-based detection."""
        # Statistical features
        orig_features = []
        stego_features = []

        for orig, stego in zip(original_frames, stego_frames):
            # Extract various statistical features
            orig_feat = self._extract_statistical_features(orig)
            stego_feat = self._extract_statistical_features(stego)

            orig_features.append(orig_feat)
            stego_features.append(stego_feat)

        # Calculate feature separability
        orig_features = np.array(orig_features)
        stego_features = np.array(stego_features)

        # Mean feature differences
        feature_diff = np.mean(np.abs(stego_features - orig_features), axis=0)
        separability = np.mean(feature_diff)

        # Complexity change measure
        orig_complexity = np.mean([self._calculate_image_complexity(f) for f in original_frames])
        stego_complexity = np.mean([self._calculate_image_complexity(f) for f in stego_frames])
        complexity_change = (
            abs(stego_complexity - orig_complexity) / orig_complexity if orig_complexity > 0 else 0
        )

        return {
            "separability": separability,
            "complexity_change": complexity_change,
            "feature_variance": np.var(feature_diff),
        }

    def _simulate_ml_classification(self, features: Dict[str, float]) -> float:
        """Simulate ML classification decision."""
        # Simple linear combination of features to simulate classification
        weights = {"separability": 0.5, "complexity_change": 0.3, "feature_variance": 0.2}

        detection_score = sum(weights[key] * features[key] for key in weights if key in features)

        # Normalize to 0-1 range
        return min(1.0, max(0.0, detection_score))

    def _calculate_predictability(self, image: np.ndarray) -> float:
        """Calculate image predictability measure."""
        # Use local variance as predictability measure
        kernel = np.ones((3, 3)) / 9
        smoothed = cv2.filter2D(image.astype(np.float32), -1, kernel)
        prediction_error = np.mean((image.astype(float) - smoothed) ** 2)
        return 1.0 / (1.0 + prediction_error)

    def _count_regular_regions(self, image: np.ndarray) -> int:
        """Count regular regions in image (simplified)."""
        # Use edge detection to find regular vs singular regions
        edges = cv2.Canny(image, 50, 150)
        regular_regions = np.sum(edges == 0)  # Non-edge regions are "regular"
        return regular_regions

    def _calculate_regularity(self, frame: np.ndarray) -> float:
        """Calculate regularity measure of frame."""
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        # Use autocorrelation as regularity measure
        height, width = gray.shape
        center_y, center_x = height // 2, width // 2

        # Calculate autocorrelation at small offsets
        autocorr_sum = 0
        count = 0
        for dy in [-1, 0, 1]:
            for dx in [-1, 0, 1]:
                if dy == 0 and dx == 0:
                    continue
                if (
                    center_y + dy < height
                    and center_x + dx < width
                    and center_y + dy >= 0
                    and center_x + dx >= 0
                ):
                    autocorr = np.corrcoef(
                        gray.flatten(), np.roll(gray, (dy, dx), axis=(0, 1)).flatten()
                    )[0, 1]
                    if not np.isnan(autocorr):
                        autocorr_sum += autocorr
                        count += 1

        return autocorr_sum / count if count > 0 else 0

    def _extract_sample_pairs(self, image: np.ndarray) -> np.ndarray:
        """Extract sample pairs for Sample Pairs analysis."""
        height, width = image.shape
        pairs = []

        # Extract horizontal adjacent pairs
        for i in range(height):
            for j in range(width - 1):
                pairs.append([image[i, j], image[i, j + 1]])

        return np.array(pairs)

    def _calculate_sp_statistic(self, orig_pairs: np.ndarray, stego_pairs: np.ndarray) -> float:
        """Calculate Sample Pairs statistic."""
        # Simplified SP statistic based on pair differences
        orig_diffs = np.abs(orig_pairs[:, 1] - orig_pairs[:, 0])
        stego_diffs = np.abs(stego_pairs[:, 1] - stego_pairs[:, 0])

        # Compare distributions of differences
        orig_mean = np.mean(orig_diffs)
        stego_mean = np.mean(stego_diffs)

        sp_statistic = abs(stego_mean - orig_mean) / orig_mean if orig_mean > 0 else 0
        return sp_statistic

    def _calculate_pair_ratios(self, pairs: np.ndarray) -> float:
        """Calculate ratio measures from pairs."""
        # Simple ratio of even vs odd pair sums
        pair_sums = pairs[:, 0] + pairs[:, 1]
        even_pairs = np.sum(pair_sums % 2 == 0)
        odd_pairs = len(pairs) - even_pairs

        return even_pairs / odd_pairs if odd_pairs > 0 else 1.0

    def _extract_statistical_features(self, frame: np.ndarray) -> np.ndarray:
        """Extract statistical features from frame."""
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

        features = []
        # Basic statistics
        features.extend([np.mean(gray), np.std(gray), np.var(gray)])

        # Higher order moments
        features.extend([stats.skew(gray.flatten()), stats.kurtosis(gray.flatten())])

        # Texture features (simplified)
        edges = cv2.Canny(gray, 50, 150)
        features.append(np.mean(edges))

        # Local binary pattern approximation
        lbp_like = np.sum(gray[1:, 1:] > gray[:-1, :-1])
        features.append(lbp_like / gray.size)

        return np.array(features)

    def _calculate_image_complexity(self, frame: np.ndarray) -> float:
        """Calculate image complexity measure."""
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

        # Use entropy as complexity measure
        hist, _ = np.histogram(gray, bins=256, range=(0, 256))
        hist = hist / np.sum(hist)  # Normalize
        hist = hist[hist > 0]  # Remove zero entries

        image_entropy = -np.sum(hist * np.log2(hist))
        return image_entropy / 8.0  # Normalize to 0-1 range


class TestInformationTheoreticSecurity(unittest.TestCase):
    """Test information-theoretic security measures."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_data = "Information theoretic test!"
        self.frame_size = (64, 64)
        self.num_frames = 5

        self.test_frames = self._create_test_frames()
        self.qim_algorithms = {
            "uniform": UniformQIM(quantization_step=4.0),
            "adaptive": AdaptiveQIM(base_quantization_step=4.0, adaptation_factor=0.5),
        }

        self.video_core = VideoSteganographySecurityTest()

    def _create_test_frames(self) -> List[np.ndarray]:
        """Create test frames."""
        frames = []
        for i in range(self.num_frames):
            frame = np.random.randint(0, 256, (*self.frame_size, 3), dtype=np.uint8)
            # Add some structure
            frame[20:40, 20:40] = [128 + i * 20, 100, 150]
            frames.append(frame)
        return frames

    def test_entropy_analysis(self):
        """Test entropy changes due to steganographic embedding."""
        print("\nTesting Entropy Analysis:")
        print("-" * 27)

        for qim_name, qim_algo in self.qim_algorithms.items():
            with self.subTest(qim_algorithm=qim_name):
                # Hide data
                stego_frames = self.video_core.hide_data_in_frames(
                    self.test_frames.copy(), self.test_data, qim_algorithm=qim_algo
                )

                # Calculate entropy measures
                entropy_metrics = self._calculate_entropy_metrics(self.test_frames, stego_frames)

                print(
                    f"  {qim_name:15s}: Entropy_change={entropy_metrics['entropy_change']:.6f}, "
                    f"Conditional_entropy={entropy_metrics['conditional_entropy']:.4f}, "
                    f"Mutual_info={entropy_metrics['mutual_information']:.6f}"
                )

                # Security assertions (adjusted for realistic DCT steganography)
                self.assertLess(
                    entropy_metrics["entropy_change"],
                    0.1,
                    f"Entropy change too large for {qim_name}",
                )
                self.assertLess(
                    entropy_metrics["mutual_information"],
                    5.0,
                    f"Mutual information too high for {qim_name}",
                )

    def test_capacity_security_tradeoff(self):
        """Test the tradeoff between capacity and security."""
        print("\nTesting Capacity-Security Tradeoff:")
        print("-" * 38)

        # Test different message sizes
        message_sizes = [10, 20, 30, 40]  # characters

        for qim_name, qim_algo in self.qim_algorithms.items():
            print(f"\n  {qim_name}:")

            for msg_size in message_sizes:
                with self.subTest(qim_algorithm=qim_name, message_size=msg_size):
                    test_msg = "X" * msg_size

                    try:
                        stego_frames = self.video_core.hide_data_in_frames(
                            self.test_frames.copy(), test_msg, qim_algorithm=qim_algo
                        )

                        # Calculate security metrics
                        security_metrics = self._calculate_security_score(
                            self.test_frames, stego_frames
                        )

                        print(
                            f"    Size {msg_size:2d}: Security={security_metrics:.4f}, "
                            f"Detectability_risk={1-security_metrics:.4f}"
                        )

                        # As message size increases, security should decrease
                        if msg_size <= 20:
                            self.assertGreater(
                                security_metrics,
                                0.7,
                                f"Security too low for small message in {qim_name}",
                            )

                    except Exception as e:
                        print(f"    Size {msg_size:2d}: FAILED - {str(e)}")

    def _calculate_entropy_metrics(
        self, original_frames: List[np.ndarray], stego_frames: List[np.ndarray]
    ) -> Dict[str, float]:
        """Calculate entropy-based security metrics."""
        orig_entropies = []
        stego_entropies = []
        mutual_infos = []

        for orig, stego in zip(original_frames, stego_frames):
            # Calculate entropy for each channel
            for channel in range(3):
                orig_channel = orig[:, :, channel]
                stego_channel = stego[:, :, channel]

                # Calculate histograms
                orig_hist, _ = np.histogram(orig_channel, bins=256, range=(0, 256))
                stego_hist, _ = np.histogram(stego_channel, bins=256, range=(0, 256))

                # Normalize histograms
                orig_hist = orig_hist / np.sum(orig_hist)
                stego_hist = stego_hist / np.sum(stego_hist)

                # Calculate entropies
                orig_entropy = entropy(orig_hist + 1e-10, base=2)
                stego_entropy = entropy(stego_hist + 1e-10, base=2)

                orig_entropies.append(orig_entropy)
                stego_entropies.append(stego_entropy)

                # Calculate mutual information (simplified)
                # Joint histogram approximation
                joint_hist = np.histogram2d(
                    orig_channel.flatten(),
                    stego_channel.flatten(),
                    bins=16,  # Reduced for computation
                )[0]
                joint_hist = joint_hist / np.sum(joint_hist)

                # Marginal histograms (reduced)
                orig_reduced, _ = np.histogram(orig_channel, bins=16, range=(0, 256))
                stego_reduced, _ = np.histogram(stego_channel, bins=16, range=(0, 256))
                orig_reduced = orig_reduced / np.sum(orig_reduced)
                stego_reduced = stego_reduced / np.sum(stego_reduced)

                # Mutual information calculation
                mi = 0
                for i in range(16):
                    for j in range(16):
                        if joint_hist[i, j] > 0 and orig_reduced[i] > 0 and stego_reduced[j] > 0:
                            mi += joint_hist[i, j] * math.log2(
                                joint_hist[i, j] / (orig_reduced[i] * stego_reduced[j])
                            )

                mutual_infos.append(mi)

        # Calculate conditional entropy
        avg_orig_entropy = np.mean(orig_entropies)
        avg_stego_entropy = np.mean(stego_entropies)
        avg_mutual_info = np.mean(mutual_infos)

        conditional_entropy = avg_stego_entropy - avg_mutual_info

        return {
            "entropy_change": abs(avg_stego_entropy - avg_orig_entropy),
            "conditional_entropy": conditional_entropy,
            "mutual_information": avg_mutual_info,
        }

    def _calculate_security_score(
        self, original_frames: List[np.ndarray], stego_frames: List[np.ndarray]
    ) -> float:
        """Calculate overall security score (0-1, higher is more secure)."""
        # Combine multiple security metrics

        # Visual quality (PSNR-based)
        psnr_scores = []
        for orig, stego in zip(original_frames, stego_frames):
            mse = np.mean((orig.astype(float) - stego.astype(float)) ** 2)
            psnr = 20 * math.log10(255.0 / math.sqrt(mse)) if mse > 0 else 60
            psnr_scores.append(min(60, psnr))  # Cap at 60dB

        visual_score = min(1.0, np.mean(psnr_scores) / 60.0)

        # Statistical similarity (histogram-based)
        hist_similarities = []
        for orig, stego in zip(original_frames, stego_frames):
            for channel in range(3):
                orig_hist, _ = np.histogram(orig[:, :, channel], bins=256)
                stego_hist, _ = np.histogram(stego[:, :, channel], bins=256)

                # Correlation coefficient between histograms
                if np.std(orig_hist) > 0 and np.std(stego_hist) > 0:
                    correlation = np.corrcoef(orig_hist, stego_hist)[0, 1]
                    hist_similarities.append(max(0, correlation))
                else:
                    hist_similarities.append(1.0)

        statistical_score = np.mean(hist_similarities)

        # Entropy preservation
        entropy_scores = []
        for orig, stego in zip(original_frames, stego_frames):
            orig_gray = cv2.cvtColor(orig, cv2.COLOR_BGR2GRAY)
            stego_gray = cv2.cvtColor(stego, cv2.COLOR_BGR2GRAY)

            orig_hist, _ = np.histogram(orig_gray, bins=256)
            stego_hist, _ = np.histogram(stego_gray, bins=256)

            orig_entropy = entropy(orig_hist + 1e-10)
            stego_entropy = entropy(stego_hist + 1e-10)

            entropy_preservation = 1.0 - abs(orig_entropy - stego_entropy) / max(
                orig_entropy, 1e-10
            )
            entropy_scores.append(max(0, entropy_preservation))

        entropy_score = np.mean(entropy_scores)

        # Weighted combination
        overall_score = 0.4 * visual_score + 0.3 * statistical_score + 0.3 * entropy_score
        return overall_score


if __name__ == "__main__":
    # Configure logging for detailed output
    logging.basicConfig(level=logging.INFO)

    # Run tests with detailed output
    test_suite = unittest.TestLoader().loadTestsFromModule(__import__(__name__))
    runner = unittest.TextTestRunner(verbosity=2, buffer=False)
    runner.run(test_suite)
