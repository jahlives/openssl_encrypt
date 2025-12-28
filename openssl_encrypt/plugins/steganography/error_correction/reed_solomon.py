"""
Reed-Solomon error correction for video steganography.

This module provides Reed-Solomon error correction capabilities to handle
DCT quantization errors in video steganography. It includes basic RS encoding/decoding,
block-based processing for large data, and adaptive error correction based on
channel quality assessment.
"""

import hashlib
import math
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np


class ErrorCorrectionError(Exception):
    """Exception raised for error correction failures."""

    pass


class GaloisField:
    """Galois Field GF(2^m) arithmetic for Reed-Solomon codes."""

    def __init__(self, m: int = 8):
        """
        Initialize Galois Field GF(2^m).

        Args:
            m: Field parameter (default 8 for GF(256))
        """
        self.m = m
        self.size = 2**m
        self.prim_poly = self._get_primitive_polynomial(m)

        # Build log and exp tables
        self._build_tables()

    def _get_primitive_polynomial(self, m: int) -> int:
        """Get primitive polynomial for GF(2^m)."""
        # Primitive polynomials for common field sizes
        primitives = {
            4: 0x13,  # x^4 + x + 1
            5: 0x25,  # x^5 + x^2 + 1
            6: 0x43,  # x^6 + x + 1
            7: 0x89,  # x^7 + x^3 + 1
            8: 0x11D,  # x^8 + x^4 + x^3 + x^2 + 1
        }

        if m not in primitives:
            raise ErrorCorrectionError(f"Primitive polynomial for GF(2^{m}) not available")

        return primitives[m]

    def _build_tables(self):
        """Build logarithm and exponential tables."""
        self.exp_table = [0] * (2 * self.size)
        self.log_table = [0] * self.size

        # Build exponential table
        x = 1
        for i in range(self.size - 1):
            self.exp_table[i] = x
            x = self._multiply_no_table(x, 2)

        # Extend table for efficiency
        for i in range(self.size - 1, 2 * self.size - 2):
            self.exp_table[i] = self.exp_table[i - (self.size - 1)]

        # Build logarithm table
        for i in range(1, self.size):
            self.log_table[self.exp_table[i]] = i

    def _multiply_no_table(self, a: int, b: int) -> int:
        """Multiply two elements without using tables (for table construction)."""
        if a == 0 or b == 0:
            return 0

        result = 0
        while b:
            if b & 1:
                result ^= a
            a <<= 1
            if a & self.size:
                a ^= self.prim_poly
            b >>= 1

        return result

    def multiply(self, a: int, b: int) -> int:
        """Multiply two field elements."""
        if a == 0 or b == 0:
            return 0

        return self.exp_table[self.log_table[a] + self.log_table[b]]

    def divide(self, a: int, b: int) -> int:
        """Divide two field elements."""
        if a == 0:
            return 0
        if b == 0:
            raise ZeroDivisionError("Division by zero in Galois field")

        return self.exp_table[self.log_table[a] - self.log_table[b] + (self.size - 1)]

    def power(self, a: int, b: int) -> int:
        """Raise field element to power."""
        if a == 0:
            return 0 if b > 0 else 1

        return self.exp_table[(self.log_table[a] * b) % (self.size - 1)]

    def inverse(self, a: int) -> int:
        """Find multiplicative inverse of field element."""
        if a == 0:
            raise ZeroDivisionError("Cannot invert zero in Galois field")

        return self.exp_table[self.size - 1 - self.log_table[a]]


class ReedSolomonEncoder:
    """Reed-Solomon encoder for error correction."""

    def __init__(self, n: int = 255, k: int = 223, t: int = 16):
        """
        Initialize Reed-Solomon encoder.

        Args:
            n: Codeword length (must be <= 255 for GF(256))
            k: Information symbols
            t: Error correction capability
        """
        if n > 255:
            raise ErrorCorrectionError("Codeword length cannot exceed 255 for GF(256)")
        if k > n:
            raise ErrorCorrectionError("Information symbols cannot exceed codeword length")
        if t < 0:
            raise ErrorCorrectionError("Error correction capability must be non-negative")
        if 2 * t > n - k:
            raise ErrorCorrectionError("Error correction capability too high for given parameters")

        self.n = n
        self.k = k
        self.t = t
        self.parity_symbols = n - k

        self.gf = GaloisField(8)
        self.generator_poly = self._build_generator_polynomial()

    def _build_generator_polynomial(self) -> List[int]:
        """Build generator polynomial for Reed-Solomon code."""
        # Generator polynomial is product of (x - α^i) for i = 0 to 2t-1
        poly = [1]  # Start with polynomial 1

        for i in range(self.parity_symbols):
            # Multiply by (x - α^i)
            alpha_i = self.gf.exp_table[i]
            new_poly = [0] * (len(poly) + 1)

            for j in range(len(poly)):
                new_poly[j] ^= self.gf.multiply(poly[j], alpha_i)
                new_poly[j + 1] ^= poly[j]

            poly = new_poly

        return poly

    def encode(self, data: bytes) -> bytes:
        """
        Encode data with Reed-Solomon error correction.

        Args:
            data: Input data to encode

        Returns:
            Encoded data with parity symbols
        """
        if not data:
            # Handle empty data
            data = b"\x00"

        # Pad data to multiple of k if necessary
        padded_data = self._pad_data(data)

        # Encode each block
        encoded_blocks = []
        for i in range(0, len(padded_data), self.k):
            block = padded_data[i : i + self.k]
            if len(block) < self.k:
                block = block + b"\x00" * (self.k - len(block))

            encoded_block = self._encode_block(block)
            encoded_blocks.append(encoded_block)

        # Add header with original length
        header = struct.pack("<I", len(data))
        result = header + b"".join(encoded_blocks)

        return result

    def _pad_data(self, data: bytes) -> bytes:
        """Pad data to multiple of k bytes."""
        remainder = len(data) % self.k
        if remainder == 0:
            return data

        padding_length = self.k - remainder
        return data + b"\x00" * padding_length

    def _encode_block(self, block: bytes) -> bytes:
        """Encode a single block using systematic encoding."""
        if len(block) != self.k:
            raise ErrorCorrectionError(f"Block size must be {self.k}, got {len(block)}")

        # Convert to list of integers
        data_poly = list(block)

        # Multiply data polynomial by x^(n-k) to shift it left
        shifted_data = data_poly + [0] * self.parity_symbols

        # Calculate remainder when dividing by generator polynomial
        remainder = self._polynomial_remainder(shifted_data, self.generator_poly)

        # Systematic codeword: data + parity (remainder)
        codeword = data_poly + remainder[-self.parity_symbols :]

        return bytes(codeword)

    def _polynomial_remainder(self, dividend: List[int], divisor: List[int]) -> List[int]:
        """Calculate polynomial remainder in GF(256)."""
        # Copy dividend
        remainder = dividend[:]

        # Synthetic division
        for i in range(len(dividend) - len(divisor) + 1):
            coeff = remainder[i]
            if coeff != 0:
                for j in range(len(divisor)):
                    remainder[i + j] ^= self.gf.multiply(divisor[j], coeff)

        return remainder[-(len(divisor) - 1) :]


class ReedSolomonDecoder:
    """Reed-Solomon decoder for error correction."""

    def __init__(self, n: int = 255, k: int = 223, t: int = 16):
        """
        Initialize Reed-Solomon decoder.

        Args:
            n: Codeword length
            k: Information symbols
            t: Error correction capability
        """
        self.n = n
        self.k = k
        self.t = t
        self.parity_symbols = n - k

        self.gf = GaloisField(8)

    def decode(self, encoded_data: bytes) -> bytes:
        """
        Decode Reed-Solomon encoded data.

        Args:
            encoded_data: Encoded data with parity symbols

        Returns:
            Decoded original data
        """
        if len(encoded_data) < 4:
            raise ErrorCorrectionError("Encoded data too short (missing header)")

        # Extract original length from header
        original_length = struct.unpack("<I", encoded_data[:4])[0]
        encoded_blocks = encoded_data[4:]

        if len(encoded_blocks) % self.n != 0:
            raise ErrorCorrectionError(f"Invalid codeword length: {len(encoded_blocks)}")

        # Decode each block
        decoded_blocks = []
        for i in range(0, len(encoded_blocks), self.n):
            block = encoded_blocks[i : i + self.n]
            if len(block) != self.n:
                raise ErrorCorrectionError(f"Invalid block length: {len(block)}")

            decoded_block = self._decode_block(list(block))
            decoded_blocks.append(bytes(decoded_block))

        # Combine blocks and trim to original length
        result = b"".join(decoded_blocks)[:original_length]

        return result

    def _decode_block(self, received: List[int]) -> List[int]:
        """Decode a single received block with basic error correction."""
        if len(received) != self.n:
            raise ErrorCorrectionError(f"Received block must be length {self.n}")

        # Calculate syndromes to detect errors
        syndromes = self._calculate_syndromes_simple(received)

        # If no errors, return data portion
        if all(s == 0 for s in syndromes):
            return received[: self.k]

        # Simple error correction: try to fix up to t single symbol errors
        best_candidate = received[:]
        best_score = self._calculate_syndrome_score(received)

        # Try correcting single symbol errors
        for pos in range(self.n):
            for error_val in range(1, 256):  # Try all possible error values
                test_received = received[:]
                test_received[pos] ^= error_val

                test_syndromes = self._calculate_syndromes_simple(test_received)
                score = sum(1 for s in test_syndromes if s == 0)

                if score > best_score:
                    best_candidate = test_received
                    best_score = score

                # If all syndromes are zero, we found a valid codeword
                if all(s == 0 for s in test_syndromes):
                    return test_received[: self.k]

        # If we can't find a perfect correction, check if too many errors
        final_syndromes = self._calculate_syndromes_simple(best_candidate)
        error_indicators = sum(1 for s in final_syndromes if s != 0)

        if error_indicators > self.t:
            raise ErrorCorrectionError(f"Too many errors: {error_indicators} indicators > {self.t}")

        return best_candidate[: self.k]

    def _calculate_syndromes_simple(self, received: List[int]) -> List[int]:
        """Calculate syndromes using simple polynomial evaluation."""
        syndromes = []

        for i in range(self.parity_symbols):
            syndrome = 0
            power = 1

            # Evaluate received(x) at α^i
            for j in range(self.n):
                syndrome ^= self.gf.multiply(received[j], power)
                power = self.gf.multiply(power, self.gf.exp_table[i % (self.gf.size - 1)])

            syndromes.append(syndrome)

        return syndromes

    def _calculate_syndrome_score(self, received: List[int]) -> int:
        """Calculate how many syndromes are zero (higher is better)."""
        syndromes = self._calculate_syndromes_simple(received)
        return sum(1 for s in syndromes if s == 0)


class BlockEncoder:
    """Block-based encoder for large data."""

    def __init__(self, block_size: int = 200, n: int = 255, k: int = 223, t: int = 16):
        """
        Initialize block encoder.

        Args:
            block_size: Size of data blocks to process
            n, k, t: Reed-Solomon parameters
        """
        self.block_size = block_size
        self.rs_encoder = ReedSolomonEncoder(n, k, t)
        self.rs_decoder = ReedSolomonDecoder(n, k, t)

    def encode(self, data: bytes) -> bytes:
        """Encode large data in blocks."""
        if not data:
            return self.rs_encoder.encode(b"")

        # Split into blocks
        blocks = []
        for i in range(0, len(data), self.block_size):
            block = data[i : i + self.block_size]
            encoded_block = self.rs_encoder.encode(block)
            blocks.append(encoded_block)

        # Add header with number of blocks
        header = struct.pack("<I", len(blocks))
        return header + b"".join(blocks)

    def decode(self, encoded_data: bytes) -> bytes:
        """Decode large data from blocks."""
        if len(encoded_data) < 4:
            raise ErrorCorrectionError("Encoded data too short")

        # Extract number of blocks
        num_blocks = struct.unpack("<I", encoded_data[:4])[0]
        remaining_data = encoded_data[4:]

        decoded_blocks = []
        offset = 0

        for _ in range(num_blocks):
            if offset >= len(remaining_data):
                raise ErrorCorrectionError("Insufficient data for expected blocks")

            # Find block boundary (need to parse header to get block size)
            if len(remaining_data[offset:]) < 4:
                raise ErrorCorrectionError("Incomplete block header")

            # Get original length from block header
            block_original_length = struct.unpack("<I", remaining_data[offset : offset + 4])[0]

            # Calculate encoded block size
            padded_length = (
                (block_original_length + self.rs_encoder.k - 1) // self.rs_encoder.k
            ) * self.rs_encoder.k
            num_codewords = padded_length // self.rs_encoder.k
            encoded_block_size = 4 + num_codewords * self.rs_encoder.n  # Header + codewords

            if offset + encoded_block_size > len(remaining_data):
                raise ErrorCorrectionError("Incomplete encoded block")

            block_data = remaining_data[offset : offset + encoded_block_size]
            decoded_block = self.rs_decoder.decode(block_data)
            decoded_blocks.append(decoded_block)

            offset += encoded_block_size

        return b"".join(decoded_blocks)


class AdaptiveErrorCorrection:
    """Adaptive error correction based on channel quality."""

    def __init__(self):
        """Initialize adaptive error correction."""
        # Different RS configurations for different quality levels
        self.high_quality_encoder = ReedSolomonEncoder(
            n=255, k=247, t=4
        )  # Light correction (8 parity symbols)
        self.medium_quality_encoder = ReedSolomonEncoder(
            n=255, k=223, t=16
        )  # Medium correction (32 parity symbols)
        self.low_quality_encoder = ReedSolomonEncoder(
            n=255, k=191, t=32
        )  # Heavy correction (64 parity symbols)

        self.high_quality_decoder = ReedSolomonDecoder(n=255, k=247, t=4)
        self.medium_quality_decoder = ReedSolomonDecoder(n=255, k=223, t=16)
        self.low_quality_decoder = ReedSolomonDecoder(n=255, k=191, t=32)

        self.encoders = {
            "high": self.high_quality_encoder,
            "medium": self.medium_quality_encoder,
            "low": self.low_quality_encoder,
        }

        self.decoders = {
            "high": self.high_quality_decoder,
            "medium": self.medium_quality_decoder,
            "low": self.low_quality_decoder,
        }

    def assess_channel_quality(self, error_rate: float) -> str:
        """
        Assess channel quality based on error rate.

        Args:
            error_rate: Observed error rate (0.0 to 1.0)

        Returns:
            Quality level: 'high', 'medium', or 'low'
        """
        if error_rate < 0.02:
            return "high"
        elif error_rate < 0.10:
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
        stored_quality = encoded_data[:8].rstrip(b"\x00").decode("utf-8")
        if stored_quality != quality:
            raise ErrorCorrectionError(
                f"Quality mismatch: expected {quality}, got {stored_quality}"
            )

        # Decode with appropriate decoder
        if quality not in self.decoders:
            raise ErrorCorrectionError(f"Invalid quality level: {quality}")

        decoder = self.decoders[quality]
        return decoder.decode(encoded_data[8:])
