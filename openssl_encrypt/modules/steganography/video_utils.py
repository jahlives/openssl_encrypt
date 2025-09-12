#!/usr/bin/env python3
"""
Video Steganography Utility Functions

This module provides utility functions for video analysis, manipulation, and
quality assessment for steganographic operations. It includes functions for:
- Video format validation and analysis
- Frame quality metrics (PSNR, SSIM)
- Bitrate and compression analysis
- Scene complexity calculation
- Temporal analysis for optimal frame selection
"""

import logging
import math
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

try:
    import cv2
    import ffmpeg

    VIDEO_UTILS_AVAILABLE = True
except ImportError:
    cv2 = None
    ffmpeg = None
    VIDEO_UTILS_AVAILABLE = False

# Set up module logger
logger = logging.getLogger(__name__)


class VideoAnalysisError(Exception):
    """Raised when video analysis operations fail"""

    pass


def is_video_utils_available() -> bool:
    """Check if video utilities dependencies are available"""
    return VIDEO_UTILS_AVAILABLE


def validate_video_file(video_data: bytes) -> Dict[str, Any]:
    """
    Validate video file format and extract basic information

    Args:
        video_data: Raw video file data

    Returns:
        Dictionary containing validation results and basic info
    """
    if not is_video_utils_available():
        raise VideoAnalysisError("Video utilities require opencv-python and ffmpeg-python")

    try:
        # Write to temporary file for analysis
        with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as temp_file:
            temp_file.write(video_data)
            temp_path = temp_file.name

        try:
            # Probe with FFmpeg
            probe = ffmpeg.probe(temp_path)

            # Extract basic information
            format_info = probe.get("format", {})
            video_streams = [s for s in probe["streams"] if s["codec_type"] == "video"]
            audio_streams = [s for s in probe["streams"] if s["codec_type"] == "audio"]

            if not video_streams:
                return {
                    "valid": False,
                    "error": "No video stream found",
                    "format_name": format_info.get("format_name", "unknown"),
                    "size": len(video_data),
                }

            video_stream = video_streams[0]

            result = {
                "valid": True,
                "format_name": format_info.get("format_name", "unknown"),
                "duration": float(format_info.get("duration", 0)),
                "size": len(video_data),
                "bitrate": int(format_info.get("bit_rate", 0)),
                "video": {
                    "codec": video_stream.get("codec_name", "unknown"),
                    "width": int(video_stream.get("width", 0)),
                    "height": int(video_stream.get("height", 0)),
                    "fps": eval(video_stream.get("r_frame_rate", "30/1")),
                    "pixel_format": video_stream.get("pix_fmt", "unknown"),
                    "total_frames": int(video_stream.get("nb_frames", 0)),
                },
                "audio": None,
            }

            # Add audio information if available
            if audio_streams:
                audio_stream = audio_streams[0]
                result["audio"] = {
                    "codec": audio_stream.get("codec_name", "unknown"),
                    "sample_rate": int(audio_stream.get("sample_rate", 0)),
                    "channels": int(audio_stream.get("channels", 0)),
                    "bitrate": int(audio_stream.get("bit_rate", 0)),
                }

            return result

        finally:
            Path(temp_path).unlink(missing_ok=True)

    except Exception as e:
        return {"valid": False, "error": str(e), "size": len(video_data)}


def calculate_psnr(original: np.ndarray, modified: np.ndarray) -> float:
    """
    Calculate Peak Signal-to-Noise Ratio between two images

    Args:
        original: Original image array
        modified: Modified image array

    Returns:
        PSNR value in dB (higher is better)
    """
    if original.shape != modified.shape:
        raise VideoAnalysisError("Images must have the same dimensions")

    # Calculate MSE
    mse = np.mean((original.astype(float) - modified.astype(float)) ** 2)

    if mse == 0:
        return float("inf")  # Perfect match

    # Calculate PSNR
    max_pixel_value = 255.0
    psnr = 20 * math.log10(max_pixel_value / math.sqrt(mse))

    return psnr


def calculate_ssim(
    original: np.ndarray,
    modified: np.ndarray,
    window_size: int = 11,
    k1: float = 0.01,
    k2: float = 0.03,
) -> float:
    """
    Calculate Structural Similarity Index between two images

    Args:
        original: Original image array
        modified: Modified image array
        window_size: Size of the sliding window
        k1, k2: SSIM parameters

    Returns:
        SSIM value between -1 and 1 (1 is perfect match)
    """
    if original.shape != modified.shape:
        raise VideoAnalysisError("Images must have the same dimensions")

    # Convert to grayscale if color
    if len(original.shape) == 3:
        original_gray = cv2.cvtColor(original, cv2.COLOR_BGR2GRAY)
        modified_gray = cv2.cvtColor(modified, cv2.COLOR_BGR2GRAY)
    else:
        original_gray = original
        modified_gray = modified

    # Convert to float
    img1 = original_gray.astype(np.float64)
    img2 = modified_gray.astype(np.float64)

    # Constants
    C1 = (k1 * 255) ** 2
    C2 = (k2 * 255) ** 2

    # Create window
    window = cv2.getGaussianKernel(window_size, 1.5)
    window = np.outer(window, window.transpose())

    # Calculate local means
    mu1 = cv2.filter2D(img1, -1, window)[5:-5, 5:-5]
    mu2 = cv2.filter2D(img2, -1, window)[5:-5, 5:-5]

    mu1_sq = mu1**2
    mu2_sq = mu2**2
    mu1_mu2 = mu1 * mu2

    # Calculate local variances and covariance
    sigma1_sq = cv2.filter2D(img1**2, -1, window)[5:-5, 5:-5] - mu1_sq
    sigma2_sq = cv2.filter2D(img2**2, -1, window)[5:-5, 5:-5] - mu2_sq
    sigma12 = cv2.filter2D(img1 * img2, -1, window)[5:-5, 5:-5] - mu1_mu2

    # SSIM calculation
    numerator = (2 * mu1_mu2 + C1) * (2 * sigma12 + C2)
    denominator = (mu1_sq + mu2_sq + C1) * (sigma1_sq + sigma2_sq + C2)

    ssim_map = numerator / denominator
    return float(np.mean(ssim_map))


def calculate_frame_complexity(frame: np.ndarray) -> Dict[str, float]:
    """
    Calculate various complexity metrics for a video frame

    Args:
        frame: Video frame as numpy array

    Returns:
        Dictionary containing complexity metrics
    """
    if frame.size == 0:
        return {
            "variance": 0.0,
            "gradient_magnitude": 0.0,
            "edge_density": 0.0,
            "entropy": 0.0,
            "complexity_score": 0.0,
        }

    # Convert to grayscale if needed
    if len(frame.shape) == 3:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    else:
        gray = frame

    # Calculate variance (texture complexity)
    variance = float(np.var(gray))

    # Calculate gradient magnitude (edge complexity)
    grad_x = cv2.Sobel(gray, cv2.CV_64F, 1, 0, ksize=3)
    grad_y = cv2.Sobel(gray, cv2.CV_64F, 0, 1, ksize=3)
    gradient_magnitude = float(np.mean(np.sqrt(grad_x**2 + grad_y**2)))

    # Calculate edge density using Canny
    edges = cv2.Canny(gray, 50, 150)
    edge_density = float(np.sum(edges > 0) / edges.size)

    # Calculate entropy (information content)
    hist = cv2.calcHist([gray], [0], None, [256], [0, 256])
    hist = hist / np.sum(hist)  # Normalize
    hist = hist[hist > 0]  # Remove zeros
    entropy = float(-np.sum(hist * np.log2(hist)))

    # Combine into overall complexity score
    # Normalize each metric to 0-1 range (roughly)
    norm_variance = min(variance / 10000, 1.0)
    norm_gradient = min(gradient_magnitude / 100, 1.0)
    norm_entropy = entropy / 8.0  # Max entropy for 8-bit is 8

    complexity_score = (norm_variance + norm_gradient + edge_density + norm_entropy) / 4.0

    return {
        "variance": variance,
        "gradient_magnitude": gradient_magnitude,
        "edge_density": edge_density,
        "entropy": entropy,
        "complexity_score": complexity_score,
    }


def analyze_frame_sequence(
    frames: List[np.ndarray], max_frames: Optional[int] = None
) -> Dict[str, Any]:
    """
    Analyze a sequence of video frames for steganography suitability

    Args:
        frames: List of video frames
        max_frames: Maximum frames to analyze (None = all)

    Returns:
        Dictionary containing sequence analysis results
    """
    if not frames:
        return {"suitable_frames": [], "average_complexity": 0.0, "recommendations": []}

    analyze_count = min(len(frames), max_frames) if max_frames else len(frames)
    frame_analyses = []

    # Analyze each frame
    for i in range(analyze_count):
        complexity = calculate_frame_complexity(frames[i])
        frame_info = {
            "frame_index": i,
            "frame_type": "I" if i % 30 == 0 else "P",  # Simplified
            "complexity": complexity,
            "suitable_for_hiding": complexity["complexity_score"] > 0.3,  # Threshold
        }
        frame_analyses.append(frame_info)

    # Calculate statistics
    complexities = [f["complexity"]["complexity_score"] for f in frame_analyses]
    average_complexity = float(np.mean(complexities))
    suitable_frames = [f for f in frame_analyses if f["suitable_for_hiding"]]

    # Generate recommendations
    recommendations = []
    if average_complexity < 0.2:
        recommendations.append("Low complexity video - consider using fewer bits per pixel")
    elif average_complexity > 0.8:
        recommendations.append("High complexity video - good for steganography")

    if len(suitable_frames) / len(frame_analyses) < 0.3:
        recommendations.append("Limited suitable frames - consider using all frames")

    return {
        "total_frames_analyzed": analyze_count,
        "suitable_frames": suitable_frames,
        "average_complexity": average_complexity,
        "complexity_distribution": {
            "min": float(np.min(complexities)),
            "max": float(np.max(complexities)),
            "std": float(np.std(complexities)),
        },
        "recommendations": recommendations,
        "frame_analyses": frame_analyses[:10],  # Return first 10 for inspection
    }


def estimate_video_capacity(
    video_info: Dict[str, Any], bits_per_pixel: float = 1.0, quality_factor: float = 0.9
) -> Dict[str, int]:
    """
    Estimate steganographic capacity for a video

    Args:
        video_info: Video information from validate_video_file
        bits_per_pixel: Bits per pixel for hiding
        quality_factor: Quality preservation factor (0-1)

    Returns:
        Dictionary containing capacity estimates
    """
    if not video_info.get("valid", False):
        return {"total_capacity": 0, "video_capacity": 0, "audio_capacity": 0}

    video = video_info["video"]
    width = video["width"]
    height = video["height"]
    total_frames = video.get("total_frames", 0)
    duration = video_info.get("duration", 0)
    fps = video["fps"]

    # Calculate video capacity
    pixels_per_frame = width * height * 3  # Assuming RGB
    bits_per_frame = pixels_per_frame * bits_per_pixel * quality_factor
    bytes_per_frame = int(bits_per_frame / 8)

    # Estimate total frames if not available
    if total_frames == 0 and duration > 0:
        total_frames = int(duration * fps)

    video_capacity = bytes_per_frame * total_frames

    # Estimate audio capacity
    audio_capacity = 0
    if video_info.get("audio"):
        # Rough estimate: 1 bit per audio sample
        sample_rate = video_info["audio"].get("sample_rate", 44100)
        channels = video_info["audio"].get("channels", 2)
        audio_samples = int(duration * sample_rate * channels)
        audio_capacity = int(audio_samples / 8 * 0.1)  # Conservative 10% of samples

    # Add container metadata capacity
    metadata_capacity = 1024  # Conservative estimate

    total_capacity = video_capacity + audio_capacity + metadata_capacity

    return {
        "total_capacity": total_capacity,
        "video_capacity": video_capacity,
        "audio_capacity": audio_capacity,
        "metadata_capacity": metadata_capacity,
        "estimated_frames": total_frames,
        "bytes_per_frame": bytes_per_frame,
    }


def compare_video_quality(
    original_path: str, modified_path: str, sample_frames: int = 10
) -> Dict[str, Any]:
    """
    Compare quality between original and modified videos

    Args:
        original_path: Path to original video file
        modified_path: Path to modified video file
        sample_frames: Number of frames to sample for comparison

    Returns:
        Dictionary containing quality metrics
    """
    if not is_video_utils_available():
        raise VideoAnalysisError("Video quality comparison requires opencv-python")

    try:
        # Open videos
        cap_orig = cv2.VideoCapture(original_path)
        cap_mod = cv2.VideoCapture(modified_path)

        if not cap_orig.isOpened() or not cap_mod.isOpened():
            raise VideoAnalysisError("Failed to open video files")

        # Get video info
        total_frames = int(cap_orig.get(cv2.CAP_PROP_FRAME_COUNT))
        frame_indices = np.linspace(0, total_frames - 1, sample_frames, dtype=int)

        psnr_values = []
        ssim_values = []

        for frame_idx in frame_indices:
            # Seek to frame
            cap_orig.set(cv2.CAP_PROP_POS_FRAMES, frame_idx)
            cap_mod.set(cv2.CAP_PROP_POS_FRAMES, frame_idx)

            # Read frames
            ret_orig, frame_orig = cap_orig.read()
            ret_mod, frame_mod = cap_mod.read()

            if not ret_orig or not ret_mod:
                continue

            # Resize if different sizes
            if frame_orig.shape != frame_mod.shape:
                frame_mod = cv2.resize(frame_mod, (frame_orig.shape[1], frame_orig.shape[0]))

            # Calculate metrics
            psnr = calculate_psnr(frame_orig, frame_mod)
            ssim = calculate_ssim(frame_orig, frame_mod)

            psnr_values.append(psnr)
            ssim_values.append(ssim)

        cap_orig.release()
        cap_mod.release()

        if not psnr_values:
            return {"error": "No frames could be compared"}

        # Calculate statistics
        result = {
            "frames_compared": len(psnr_values),
            "psnr": {
                "mean": float(np.mean(psnr_values)),
                "std": float(np.std(psnr_values)),
                "min": float(np.min(psnr_values)),
                "max": float(np.max(psnr_values)),
            },
            "ssim": {
                "mean": float(np.mean(ssim_values)),
                "std": float(np.std(ssim_values)),
                "min": float(np.min(ssim_values)),
                "max": float(np.max(ssim_values)),
            },
            "quality_assessment": {
                "excellent": np.mean(psnr_values) > 40 and np.mean(ssim_values) > 0.98,
                "good": np.mean(psnr_values) > 30 and np.mean(ssim_values) > 0.95,
                "acceptable": np.mean(psnr_values) > 25 and np.mean(ssim_values) > 0.90,
                "poor": np.mean(psnr_values) <= 25 or np.mean(ssim_values) <= 0.90,
            },
        }

        return result

    except Exception as e:
        return {"error": f"Quality comparison failed: {e}"}


def detect_scene_changes(frames: List[np.ndarray], threshold: float = 30.0) -> List[int]:
    """
    Detect scene changes in video frames

    Args:
        frames: List of video frames
        threshold: Scene change threshold (higher = less sensitive)

    Returns:
        List of frame indices where scene changes occur
    """
    if len(frames) < 2:
        return []

    scene_changes = [0]  # First frame is always a scene change

    for i in range(1, len(frames)):
        # Convert to grayscale
        if len(frames[i - 1].shape) == 3:
            prev_gray = cv2.cvtColor(frames[i - 1], cv2.COLOR_BGR2GRAY)
            curr_gray = cv2.cvtColor(frames[i], cv2.COLOR_BGR2GRAY)
        else:
            prev_gray = frames[i - 1]
            curr_gray = frames[i]

        # Calculate histogram difference
        hist_prev = cv2.calcHist([prev_gray], [0], None, [256], [0, 256])
        hist_curr = cv2.calcHist([curr_gray], [0], None, [256], [0, 256])

        # Chi-square distance
        hist_diff = cv2.compareHist(hist_prev, hist_curr, cv2.HISTCMP_CHISQR)

        if hist_diff > threshold:
            scene_changes.append(i)

    return scene_changes


def optimize_frame_selection(
    frames: List[np.ndarray], target_count: int, strategy: str = "complexity"
) -> List[int]:
    """
    Select optimal frames for steganography

    Args:
        frames: List of video frames
        target_count: Target number of frames to select
        strategy: Selection strategy ("complexity", "uniform", "keyframes")

    Returns:
        List of selected frame indices
    """
    if target_count >= len(frames):
        return list(range(len(frames)))

    if strategy == "uniform":
        # Uniform distribution
        indices = np.linspace(0, len(frames) - 1, target_count, dtype=int)
        return list(indices)

    elif strategy == "keyframes":
        # Select keyframes (every Nth frame)
        interval = len(frames) // target_count
        indices = list(range(0, len(frames), interval))[:target_count]
        return indices

    elif strategy == "complexity":
        # Select frames based on complexity
        complexities = []
        for i, frame in enumerate(frames):
            complexity = calculate_frame_complexity(frame)
            complexities.append((i, complexity["complexity_score"]))

        # Sort by complexity (descending) and take top frames
        complexities.sort(key=lambda x: x[1], reverse=True)
        selected = [idx for idx, _ in complexities[:target_count]]
        selected.sort()  # Maintain temporal order
        return selected

    else:
        raise VideoAnalysisError(f"Unknown selection strategy: {strategy}")


def create_video_analysis_report(video_data: bytes, max_frames: int = 50) -> Dict[str, Any]:
    """
    Create comprehensive video analysis report for steganography

    Args:
        video_data: Raw video file data
        max_frames: Maximum frames to analyze

    Returns:
        Comprehensive analysis report
    """
    if not is_video_utils_available():
        raise VideoAnalysisError("Video analysis requires opencv-python and ffmpeg-python")

    report = {
        "timestamp": np.datetime64("now").astype(str),
        "video_size": len(video_data),
        "analysis_parameters": {"max_frames_analyzed": max_frames},
    }

    try:
        # Basic validation
        validation = validate_video_file(video_data)
        report["validation"] = validation

        if not validation["valid"]:
            report["error"] = "Invalid video file"
            return report

        # Extract frames for analysis
        with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as temp_file:
            temp_file.write(video_data)
            temp_path = temp_file.name

        try:
            cap = cv2.VideoCapture(temp_path)
            frames = []

            frame_count = 0
            while frame_count < max_frames:
                ret, frame = cap.read()
                if not ret:
                    break
                frames.append(frame)
                frame_count += 1

            cap.release()

            # Analyze frame sequence
            sequence_analysis = analyze_frame_sequence(frames)
            report["sequence_analysis"] = sequence_analysis

            # Capacity estimation
            capacity = estimate_video_capacity(validation, bits_per_pixel=1.0)
            report["capacity_estimation"] = capacity

            # Scene change detection
            scene_changes = detect_scene_changes(frames)
            report["scene_changes"] = {
                "count": len(scene_changes),
                "indices": scene_changes[:10],  # First 10 changes
                "change_rate": len(scene_changes) / len(frames) if frames else 0,
            }

            # Steganography recommendations
            recommendations = []

            avg_complexity = sequence_analysis["average_complexity"]
            if avg_complexity > 0.7:
                recommendations.append("High complexity video - excellent for steganography")
                recommendations.append("Can use higher bits per pixel (2-3)")
            elif avg_complexity > 0.4:
                recommendations.append("Medium complexity video - good for steganography")
                recommendations.append("Recommended bits per pixel: 1-2")
            else:
                recommendations.append("Low complexity video - use conservative settings")
                recommendations.append("Recommended bits per pixel: 1")

            if len(scene_changes) > len(frames) * 0.1:
                recommendations.append("Many scene changes - good for data distribution")

            suitable_ratio = len(sequence_analysis["suitable_frames"]) / len(frames)
            if suitable_ratio > 0.8:
                recommendations.append("Most frames suitable for hiding data")
            elif suitable_ratio > 0.5:
                recommendations.append("Good frame selection available")
            else:
                recommendations.append("Limited suitable frames - consider all frames")

            report["recommendations"] = recommendations

            # Quality prediction
            predicted_quality = {
                "expected_psnr": 35 + (avg_complexity * 10),  # Higher complexity = better hiding
                "expected_ssim": 0.95 + (avg_complexity * 0.04),
                "quality_level": "excellent"
                if avg_complexity > 0.7
                else "good"
                if avg_complexity > 0.4
                else "acceptable",
            }
            report["predicted_quality"] = predicted_quality

        finally:
            Path(temp_path).unlink(missing_ok=True)

        report["analysis_complete"] = True

    except Exception as e:
        report["error"] = str(e)
        report["analysis_complete"] = False

    return report
