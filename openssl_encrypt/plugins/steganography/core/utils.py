#!/usr/bin/env python3
"""
Steganography Utility Functions

Common utility functions for steganographic operations.
"""

import math
import random
from typing import List


class SteganographyUtils:
    """Utility functions for steganographic operations"""

    @staticmethod
    def bytes_to_binary(data: bytes) -> str:
        """
        Convert bytes to binary string representation

        Args:
            data: Bytes to convert

        Returns:
            Binary string (e.g., "01001000" for byte 0x48)
        """
        return "".join(format(byte, "08b") for byte in data)

    @staticmethod
    def binary_to_bytes(binary_str: str) -> bytes:
        """
        Convert binary string to bytes

        Args:
            binary_str: Binary string (e.g., "01001000")

        Returns:
            Bytes representation
        """
        # Ensure binary string length is multiple of 8
        padding = (8 - len(binary_str) % 8) % 8
        padded_str = binary_str + "0" * padding

        # Convert to bytes
        byte_values = [int(padded_str[i : i + 8], 2) for i in range(0, len(padded_str), 8)]

        return bytes(byte_values)

    @staticmethod
    def calculate_psnr(original: bytes, modified: bytes) -> float:
        """
        Calculate Peak Signal-to-Noise Ratio for quality assessment

        Args:
            original: Original data
            modified: Modified data

        Returns:
            PSNR value in dB (higher is better)

        Raises:
            ValueError: If data lengths don't match
        """
        if len(original) != len(modified):
            raise ValueError("Data lengths must match for PSNR calculation")

        mse = sum((a - b) ** 2 for a, b in zip(original, modified)) / len(original)

        if mse == 0:
            return float("inf")  # Perfect quality

        max_pixel_value = 255.0
        psnr = 20 * math.log10(max_pixel_value / math.sqrt(mse))
        return psnr

    @staticmethod
    def generate_pseudorandom_sequence(seed: int, length: int, max_value: int) -> List[int]:
        """
        Generate pseudorandom sequence for pixel/sample selection

        Args:
            seed: Random seed for reproducible sequence
            length: Length of sequence to generate
            max_value: Maximum value in sequence (exclusive)

        Returns:
            List of pseudorandom integers
        """
        random.seed(seed)
        sequence = random.sample(range(max_value), min(length, max_value))
        return sequence

    @staticmethod
    def analyze_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of data

        Args:
            data: Data to analyze

        Returns:
            Entropy value (0.0 to 8.0 for byte data)
        """
        if not data:
            return 0.0

        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    @staticmethod
    def split_into_chunks(data: bytes, chunk_size: int) -> List[bytes]:
        """
        Split data into fixed-size chunks

        Args:
            data: Data to split
            chunk_size: Size of each chunk

        Returns:
            List of byte chunks
        """
        return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]

    @staticmethod
    def calculate_capacity_bytes(
        total_samples: int, bits_per_sample: int, safety_margin: float = 0.95
    ) -> int:
        """
        Calculate embedding capacity in bytes

        Args:
            total_samples: Total number of samples in cover media
            bits_per_sample: Bits to embed per sample
            safety_margin: Safety margin multiplier (e.g., 0.95 for 95%)

        Returns:
            Capacity in bytes
        """
        total_bits = total_samples * bits_per_sample
        safe_bits = int(total_bits * safety_margin)
        return safe_bits // 8
