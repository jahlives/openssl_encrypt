#!/usr/bin/env python3
"""
Steganography Configuration

Configuration settings for steganographic operations.
"""

from typing import Any, Dict


class SteganographyConfig:
    """Configuration settings for steganographic operations"""

    def __init__(self):
        # Capacity settings
        self.max_bits_per_sample = 3  # Maximum LSBs to use per sample
        self.min_cover_size = 1024  # Minimum cover media size (bytes)
        self.capacity_safety_margin = 0.95  # Use 95% of theoretical capacity

        # Security settings
        self.use_encryption_integration = True  # Integrate with OpenSSL Encrypt
        self.enable_decoy_data = True  # Add decoy data for deniability
        self.randomize_pixel_order = True  # Use password-based pixel selection
        self.preserve_statistics = True  # Maintain cover media statistics

        # Quality settings
        self.quality_threshold = 50.0  # PSNR threshold for image quality
        self.histogram_preservation = True  # Preserve color histograms
        self.adaptive_embedding = True  # Use content-aware hiding

        # Performance settings
        self.chunk_size = 8192  # Process data in chunks for large files
        self.memory_limit_mb = 512  # Memory usage limit for operations

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            "capacity": {
                "max_bits_per_sample": self.max_bits_per_sample,
                "min_cover_size": self.min_cover_size,
                "safety_margin": self.capacity_safety_margin,
            },
            "security": {
                "encryption_integration": self.use_encryption_integration,
                "decoy_data": self.enable_decoy_data,
                "randomize_pixels": self.randomize_pixel_order,
                "preserve_stats": self.preserve_statistics,
            },
            "quality": {
                "quality_threshold": self.quality_threshold,
                "histogram_preservation": self.histogram_preservation,
                "adaptive_embedding": self.adaptive_embedding,
            },
            "performance": {
                "chunk_size": self.chunk_size,
                "memory_limit_mb": self.memory_limit_mb,
            },
        }

    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> "SteganographyConfig":
        """Create configuration from dictionary"""
        config = cls()

        if "capacity" in config_dict:
            cap = config_dict["capacity"]
            config.max_bits_per_sample = cap.get("max_bits_per_sample", config.max_bits_per_sample)
            config.min_cover_size = cap.get("min_cover_size", config.min_cover_size)
            config.capacity_safety_margin = cap.get("safety_margin", config.capacity_safety_margin)

        if "security" in config_dict:
            sec = config_dict["security"]
            config.use_encryption_integration = sec.get(
                "encryption_integration", config.use_encryption_integration
            )
            config.enable_decoy_data = sec.get("decoy_data", config.enable_decoy_data)
            config.randomize_pixel_order = sec.get("randomize_pixels", config.randomize_pixel_order)
            config.preserve_statistics = sec.get("preserve_stats", config.preserve_statistics)

        if "quality" in config_dict:
            qual = config_dict["quality"]
            config.quality_threshold = qual.get("quality_threshold", config.quality_threshold)
            config.histogram_preservation = qual.get(
                "histogram_preservation", config.histogram_preservation
            )
            config.adaptive_embedding = qual.get("adaptive_embedding", config.adaptive_embedding)

        if "performance" in config_dict:
            perf = config_dict["performance"]
            config.chunk_size = perf.get("chunk_size", config.chunk_size)
            config.memory_limit_mb = perf.get("memory_limit_mb", config.memory_limit_mb)

        return config
