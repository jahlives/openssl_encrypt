"""
Simplified error correction for video steganography.

This module provides basic error correction specifically designed for
DCT quantization errors in video steganography. It uses simple redundancy
and voting schemes that are more practical for this specific use case.
"""

import hashlib
import math
import random
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np


class ErrorCorrectionError(Exception):
    """Exception raised for error correction failures."""

    pass


class SimpleRepetitionEncoder:
    """Simple repetition code encoder for DCT steganography."""

    def __init__(self, repetitions: int = 3):
        """
        Initialize repetition encoder.

        Args:
            repetitions: Number of times to repeat each bit (must be odd)
        """
        if repetitions % 2 == 0:
            raise ErrorCorrectionError("Repetitions must be odd for majority voting")

        self.repetitions = repetitions

    def encode(self, data: bytes) -> bytes:
        """
        Encode data using repetition code.

        Args:
            data: Input data to encode

        Returns:
            Encoded data with repetition
        """
        if not data:
            return b""

        # Add length header
        header = struct.pack("<I", len(data))

        # Repeat each byte
        encoded_data = bytearray()
        for byte in data:
            for _ in range(self.repetitions):
                encoded_data.append(byte)

        return header + bytes(encoded_data)

    def decode(self, encoded_data: bytes) -> bytes:
        """
        Decode repetition encoded data using majority voting.

        Args:
            encoded_data: Encoded data with repetitions

        Returns:
            Decoded original data
        """
        if len(encoded_data) < 4:
            raise ErrorCorrectionError("Encoded data too short")

        # Extract original length
        original_length = struct.unpack("<I", encoded_data[:4])[0]
        repeated_data = encoded_data[4:]

        expected_length = original_length * self.repetitions
        if len(repeated_data) != expected_length:
            raise ErrorCorrectionError(
                f"Invalid repeated data length: {len(repeated_data)} != {expected_length}"
            )

        # Decode using majority voting
        decoded = bytearray()
        for i in range(original_length):
            # Get repetitions of this byte
            byte_repetitions = []
            for j in range(self.repetitions):
                idx = i * self.repetitions + j
                if idx < len(repeated_data):
                    byte_repetitions.append(repeated_data[idx])

            # Majority vote
            if byte_repetitions:
                most_common_byte = max(set(byte_repetitions), key=byte_repetitions.count)
                decoded.append(most_common_byte)

        return bytes(decoded)


class HammingEncoder:
    """Simple Hamming code encoder for single error correction."""

    def __init__(self):
        """Initialize Hamming encoder."""
        pass

    def encode(self, data: bytes) -> bytes:
        """
        Encode data using Hamming(7,4) code.

        Args:
            data: Input data to encode

        Returns:
            Encoded data with Hamming parity
        """
        if not data:
            return b""

        # Add length header
        header = struct.pack("<I", len(data))

        # Encode each byte as two 4-bit nibbles
        encoded_data = bytearray()
        for byte in data:
            high_nibble = (byte >> 4) & 0xF
            low_nibble = byte & 0xF

            encoded_high = self._encode_nibble(high_nibble)
            encoded_low = self._encode_nibble(low_nibble)

            encoded_data.append(encoded_high)
            encoded_data.append(encoded_low)

        return header + bytes(encoded_data)

    def decode(self, encoded_data: bytes) -> bytes:
        """
        Decode Hamming encoded data.

        Args:
            encoded_data: Encoded data with Hamming parity

        Returns:
            Decoded original data
        """
        if len(encoded_data) < 4:
            raise ErrorCorrectionError("Encoded data too short")

        # Extract original length
        original_length = struct.unpack("<I", encoded_data[:4])[0]
        hamming_data = encoded_data[4:]

        expected_length = original_length * 2
        if len(hamming_data) != expected_length:
            raise ErrorCorrectionError(
                f"Invalid Hamming data length: {len(hamming_data)} != {expected_length}"
            )

        # Decode each pair of bytes
        decoded = bytearray()
        for i in range(0, len(hamming_data), 2):
            if i + 1 < len(hamming_data):
                encoded_high = hamming_data[i]
                encoded_low = hamming_data[i + 1]

                high_nibble = self._decode_byte(encoded_high)
                low_nibble = self._decode_byte(encoded_low)

                original_byte = (high_nibble << 4) | low_nibble
                decoded.append(original_byte)

        return bytes(decoded[:original_length])

    def _encode_nibble(self, nibble: int) -> int:
        """Encode 4-bit nibble to 7-bit Hamming codeword."""
        # Hamming(7,4) generator matrix
        d1 = (nibble >> 3) & 1
        d2 = (nibble >> 2) & 1
        d3 = (nibble >> 1) & 1
        d4 = nibble & 1

        # Calculate parity bits
        p1 = d1 ^ d2 ^ d4
        p2 = d1 ^ d3 ^ d4
        p3 = d2 ^ d3 ^ d4

        # Pack into 7-bit codeword: p1 p2 d1 p3 d2 d3 d4
        codeword = (p1 << 6) | (p2 << 5) | (d1 << 4) | (p3 << 3) | (d2 << 2) | (d3 << 1) | d4
        return codeword & 0x7F

    def _decode_byte(self, codeword: int) -> int:
        """Decode 7-bit Hamming codeword to 4-bit nibble."""
        # Extract bits
        p1 = (codeword >> 6) & 1
        p2 = (codeword >> 5) & 1
        d1 = (codeword >> 4) & 1
        p3 = (codeword >> 3) & 1
        d2 = (codeword >> 2) & 1
        d3 = (codeword >> 1) & 1
        d4 = codeword & 1

        # Calculate syndrome
        s1 = p1 ^ d1 ^ d2 ^ d4
        s2 = p2 ^ d1 ^ d3 ^ d4
        s3 = p3 ^ d2 ^ d3 ^ d4

        error_position = (s1 << 0) | (s2 << 1) | (s3 << 2)

        # Correct error if present
        if error_position != 0:
            if error_position <= 7:
                # Flip the error bit
                corrected_codeword = codeword ^ (1 << (7 - error_position))

                # Re-extract data bits
                d1 = (corrected_codeword >> 4) & 1
                d2 = (corrected_codeword >> 2) & 1
                d3 = (corrected_codeword >> 1) & 1
                d4 = corrected_codeword & 1

        # Return data nibble
        return (d1 << 3) | (d2 << 2) | (d3 << 1) | d4


class AdaptiveSimpleErrorCorrection:
    """Adaptive error correction using simple methods."""

    def __init__(self):
        """Initialize adaptive error correction."""
        self.high_quality_encoder = SimpleRepetitionEncoder(repetitions=3)  # Light correction
        self.medium_quality_encoder = HammingEncoder()  # Medium correction
        self.low_quality_encoder = SimpleRepetitionEncoder(repetitions=5)  # Heavy correction

        self.encoders = {
            "high": self.high_quality_encoder,
            "medium": self.medium_quality_encoder,
            "low": self.low_quality_encoder,
        }

    def assess_channel_quality(self, error_rate: float) -> str:
        """
        Assess channel quality based on error rate.

        Args:
            error_rate: Observed error rate (0.0 to 1.0)

        Returns:
            Quality level: 'high', 'medium', or 'low'
        """
        if error_rate < 0.05:
            return "high"
        elif error_rate < 0.20:
            return "medium"
        else:
            return "low"

    def encode(self, data: bytes, quality: str = "medium") -> bytes:
        """
        Encode data with adaptive error correction.

        Args:
            data: Data to encode
            quality: Quality level ('high', 'medium', 'low')

        Returns:
            Encoded data with quality marker
        """
        if quality not in self.encoders:
            raise ErrorCorrectionError(f"Invalid quality level: {quality}")

        encoder = self.encoders[quality]
        encoded_data = encoder.encode(data)

        # Add quality marker
        quality_marker = quality.encode("utf-8").ljust(8, b"\x00")[:8]
        return quality_marker + encoded_data

    def decode(self, encoded_data: bytes, quality: str) -> bytes:
        """
        Decode data with adaptive error correction.

        Args:
            encoded_data: Encoded data with quality marker
            quality: Expected quality level

        Returns:
            Decoded data
        """
        if len(encoded_data) < 8:
            raise ErrorCorrectionError("Encoded data too short for quality marker")

        # Extract and verify quality marker
        try:
            stored_quality = encoded_data[:8].rstrip(b"\x00").decode("utf-8")
            if stored_quality != quality:
                raise ErrorCorrectionError(
                    f"Quality mismatch: expected {quality}, got {stored_quality}"
                )
        except UnicodeDecodeError:
            raise ErrorCorrectionError("Invalid quality marker in encoded data")

        # Decode with appropriate decoder
        if quality not in self.encoders:
            raise ErrorCorrectionError(f"Invalid quality level: {quality}")

        decoder = self.encoders[quality]
        return decoder.decode(encoded_data[8:])


# For backward compatibility, create aliases to the simple implementations
ReedSolomonEncoder = SimpleRepetitionEncoder
ReedSolomonDecoder = SimpleRepetitionEncoder
BlockEncoder = SimpleRepetitionEncoder
AdaptiveErrorCorrection = AdaptiveSimpleErrorCorrection
