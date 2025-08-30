#!/usr/bin/env python3
"""
Core Steganography Classes and Base Interfaces

This module defines the fundamental architecture for steganographic operations,
providing abstract base classes, exception hierarchy, and core utilities
that are used by all steganography implementations.
"""

import abc
import hashlib
import logging
import math
import os
import secrets
from typing import Any, Dict, List, Optional, Tuple, Union

# Import secure memory functions for handling sensitive data
try:
    from ..secure_memory import SecureBytes, secure_memzero
except ImportError:
    # Fallback for standalone testing
    from openssl_encrypt.modules.secure_memory import SecureBytes, secure_memzero

# Set up module logger
logger = logging.getLogger(__name__)

class SteganographyError(Exception):
    """Base exception for all steganography operations"""
    pass

class CapacityError(SteganographyError):
    """Raised when data exceeds cover media capacity"""
    def __init__(self, required: int, available: int, media_type: str = "unknown"):
        self.required = required
        self.available = available
        self.media_type = media_type
        super().__init__(
            f"Insufficient capacity in {media_type}: need {required} bytes, "
            f"only {available} bytes available"
        )

class ExtractionError(SteganographyError):
    """Raised when data cannot be extracted from cover media"""
    pass

class CoverMediaError(SteganographyError):
    """Raised when cover media is invalid or corrupted"""
    pass

class SecurityError(SteganographyError):
    """Raised when security constraints are violated"""
    pass


class SteganographyBase(abc.ABC):
    """
    Abstract base class for all steganography implementations
    
    This class defines the core interface that all steganographic methods
    must implement, ensuring consistent behavior across different media types
    and hiding techniques.
    """
    
    def __init__(self, password: Optional[str] = None, security_level: int = 1):
        """
        Initialize steganography instance
        
        Args:
            password: Optional password for key-based operations
            security_level: Security level (1=basic, 2=enhanced, 3=paranoid)
        """
        self.password = password
        self.security_level = security_level
        self.eof_marker = b'\xFF\xFF\xFF\xFE'
        
        # Generate deterministic seed from password if provided
        if password:
            try:
                # Use secure memory for password processing
                password_bytes = SecureBytes(password.encode())
                hash_digest = hashlib.sha256(password_bytes).digest()
                secure_digest_slice = SecureBytes(hash_digest[:8])
                self.seed = int.from_bytes(secure_digest_slice, byteorder='big')
            finally:
                # Securely wipe sensitive data from memory
                if 'password_bytes' in locals():
                    secure_memzero(password_bytes)
                if 'secure_digest_slice' in locals():
                    secure_memzero(secure_digest_slice)
        else:
            self.seed = None
    
    @abc.abstractmethod
    def calculate_capacity(self, cover_data: bytes) -> int:
        """
        Calculate maximum hiding capacity for given cover media
        
        Args:
            cover_data: Raw cover media data
            
        Returns:
            Maximum bytes that can be hidden
        """
        pass
    
    @abc.abstractmethod
    def hide_data(self, cover_data: bytes, secret_data: bytes) -> bytes:
        """
        Hide secret data within cover media
        
        Args:
            cover_data: Original cover media data
            secret_data: Data to hide
            
        Returns:
            Modified cover media containing hidden data
            
        Raises:
            CapacityError: If secret_data exceeds capacity
            CoverMediaError: If cover_data is invalid
        """
        pass
    
    @abc.abstractmethod
    def extract_data(self, stego_data: bytes) -> bytes:
        """
        Extract hidden data from steganographic media
        
        Args:
            stego_data: Media containing hidden data
            
        Returns:
            Extracted secret data
            
        Raises:
            ExtractionError: If data cannot be extracted
        """
        pass
    
    def _add_eof_marker(self, data: bytes) -> bytes:
        """Add end-of-file marker to data before hiding"""
        return data + self.eof_marker
    
    def _find_eof_marker(self, data: bytes) -> bytes:
        """Find and remove EOF marker from extracted data"""
        try:
            eof_pos = data.index(self.eof_marker)
            return data[:eof_pos]
        except ValueError:
            raise ExtractionError("EOF marker not found - data may be corrupted")
    
    def _validate_cover_data(self, cover_data: bytes, min_size: int = 1024) -> None:
        """Validate cover media meets minimum requirements"""
        if not cover_data:
            raise CoverMediaError("Cover data is empty")
        
        if len(cover_data) < min_size:
            raise CoverMediaError(
                f"Cover data too small: {len(cover_data)} bytes "
                f"(minimum: {min_size} bytes)"
            )
    
    def _generate_security_metadata(self) -> Dict[str, Any]:
        """Generate metadata for security analysis"""
        return {
            'security_level': self.security_level,
            'has_password': self.password is not None,
            'eof_marker_length': len(self.eof_marker),
            'implementation': self.__class__.__name__
        }


class SteganographyConfig:
    """Configuration settings for steganographic operations"""
    
    def __init__(self):
        # Capacity settings
        self.max_bits_per_sample = 3  # Maximum LSBs to use per sample
        self.min_cover_size = 1024    # Minimum cover media size (bytes)
        self.capacity_safety_margin = 0.95  # Use 95% of theoretical capacity
        
        # Security settings
        self.use_encryption_integration = True  # Integrate with OpenSSL Encrypt
        self.enable_decoy_data = True          # Add decoy data for deniability
        self.randomize_pixel_order = True      # Use password-based pixel selection
        self.preserve_statistics = True       # Maintain cover media statistics
        
        # Quality settings
        self.quality_threshold = 50.0  # PSNR threshold for image quality
        self.histogram_preservation = True  # Preserve color histograms
        self.adaptive_embedding = True      # Use content-aware hiding
        
        # Performance settings
        self.chunk_size = 8192  # Process data in chunks for large files
        self.memory_limit_mb = 512  # Memory usage limit for operations
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            'capacity': {
                'max_bits_per_sample': self.max_bits_per_sample,
                'min_cover_size': self.min_cover_size,
                'safety_margin': self.capacity_safety_margin,
            },
            'security': {
                'encryption_integration': self.use_encryption_integration,
                'decoy_data': self.enable_decoy_data,
                'randomize_pixels': self.randomize_pixel_order,
                'preserve_stats': self.preserve_statistics,
            },
            'quality': {
                'quality_threshold': self.quality_threshold,
                'histogram_preservation': self.histogram_preservation,
                'adaptive_embedding': self.adaptive_embedding,
            },
            'performance': {
                'chunk_size': self.chunk_size,
                'memory_limit_mb': self.memory_limit_mb,
            }
        }
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'SteganographyConfig':
        """Create configuration from dictionary"""
        config = cls()
        
        if 'capacity' in config_dict:
            cap = config_dict['capacity']
            config.max_bits_per_sample = cap.get('max_bits_per_sample', config.max_bits_per_sample)
            config.min_cover_size = cap.get('min_cover_size', config.min_cover_size)
            config.capacity_safety_margin = cap.get('safety_margin', config.capacity_safety_margin)
        
        if 'security' in config_dict:
            sec = config_dict['security']
            config.use_encryption_integration = sec.get('encryption_integration', config.use_encryption_integration)
            config.enable_decoy_data = sec.get('decoy_data', config.enable_decoy_data)
            config.randomize_pixel_order = sec.get('randomize_pixels', config.randomize_pixel_order)
            config.preserve_statistics = sec.get('preserve_stats', config.preserve_statistics)
        
        return config


class SteganographyUtils:
    """Utility functions for steganographic operations"""
    
    @staticmethod
    def bytes_to_binary(data: bytes) -> str:
        """Convert bytes to binary string representation"""
        # Use secure memory for sensitive data conversion
        try:
            secure_data = SecureBytes(data)
            binary_str = ''.join(format(byte, '08b') for byte in secure_data)
            return binary_str
        finally:
            # Securely wipe the data copy from memory
            if 'secure_data' in locals():
                secure_memzero(secure_data)
    
    @staticmethod
    def binary_to_bytes(binary_str: str) -> bytes:
        """Convert binary string to bytes"""
        # Ensure binary string length is multiple of 8
        padding = (8 - len(binary_str) % 8) % 8
        padded_str = binary_str + '0' * padding
        
        # Use secure memory for conversion process
        try:
            # Convert to bytes using secure memory
            byte_values = [
                int(padded_str[i:i+8], 2) 
                for i in range(0, len(padded_str), 8)
            ]
            
            result_bytes = bytes(byte_values)
            secure_result = SecureBytes(result_bytes)
            
            # Return a copy, keeping the secure version for cleanup
            return bytes(secure_result)
        finally:
            # Clean up sensitive intermediate data
            if 'secure_result' in locals():
                secure_memzero(secure_result)
    
    @staticmethod
    def calculate_psnr(original: bytes, modified: bytes) -> float:
        """Calculate Peak Signal-to-Noise Ratio for quality assessment"""
        if len(original) != len(modified):
            raise ValueError("Data lengths must match for PSNR calculation")
        
        mse = sum((a - b) ** 2 for a, b in zip(original, modified)) / len(original)
        
        if mse == 0:
            return float('inf')  # Perfect quality
        
        max_pixel_value = 255.0
        psnr = 20 * (max_pixel_value / (mse ** 0.5))
        return psnr
    
    @staticmethod
    def generate_pseudorandom_sequence(seed: int, length: int, max_value: int) -> List[int]:
        """Generate pseudorandom sequence for pixel/sample selection"""
        import random
        
        # Use secure memory for seed processing to prevent side-channel attacks
        try:
            # Convert seed to secure bytes for processing
            seed_bytes = SecureBytes(seed.to_bytes(8, byteorder='big'))
            
            # Use the seed for random generation
            random.seed(seed)
            sequence = random.sample(range(max_value), min(length, max_value))
            
            return sequence
        finally:
            # Securely wipe the seed bytes from memory
            if 'seed_bytes' in locals():
                secure_memzero(seed_bytes)
    
    @staticmethod
    def analyze_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Use secure memory for sensitive data analysis
        try:
            # Secure copy of data for analysis
            secure_data = SecureBytes(data)
            
            # Count byte frequencies
            byte_counts = [0] * 256
            for byte in secure_data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0.0
            data_len = len(secure_data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * math.log2(probability)
            
            return entropy
        finally:
            # Securely wipe the data copy from memory
            if 'secure_data' in locals():
                secure_memzero(secure_data)