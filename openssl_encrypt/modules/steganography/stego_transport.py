#!/usr/bin/env python3
"""
Steganography Transport Layer

This module provides a simple transport interface for integrating steganography
with the existing encrypt/decrypt workflow. It acts as a transport layer that
can replace file I/O operations.
"""

import logging
import os
from typing import Optional

# Import secure memory functions for handling sensitive data
try:
    from ..secure_memory import SecureBytes, secure_memzero
except ImportError:
    # Fallback for standalone testing
    from openssl_encrypt.modules.secure_memory import SecureBytes, secure_memzero

from .stego_core import (
    SteganographyConfig,
    SteganographyError,
    CapacityError,
    CoverMediaError,
)
from .stego_image import LSBImageStego, AdaptiveLSBStego

# Set up module logger
logger = logging.getLogger(__name__)


class SteganographyTransport:
    """
    Simple transport layer for steganography operations
    
    This class provides a clean interface for hiding encrypted data in images
    and extracting it back, without the steganography code needing to know
    about encryption details.
    """
    
    def __init__(self, method: str = "lsb", bits_per_channel: int = 1, 
                 password: Optional[str] = None, **options):
        """
        Initialize steganography transport
        
        Args:
            method: Steganographic method ('lsb' or 'adaptive')
            bits_per_channel: LSB bits per color channel (1-3)
            password: Optional password for pixel randomization
            **options: Additional steganography options
        """
        self.method = method
        self.bits_per_channel = bits_per_channel
        self.password = password
        
        # Create configuration
        self.config = SteganographyConfig()
        self.config.randomize_pixel_order = options.get('randomize_pixels', False)
        self.config.enable_decoy_data = options.get('decoy_data', False)
        self.config.preserve_statistics = options.get('preserve_stats', True)
        self.config.max_bits_per_sample = bits_per_channel
        
        # Create steganography instance
        if method == 'adaptive':
            self.stego = AdaptiveLSBStego(
                password=password,
                security_level=2,
                config=self.config
            )
        else:
            self.stego = LSBImageStego(
                password=password,
                security_level=1,
                bits_per_channel=bits_per_channel,
                config=self.config
            )
    
    def hide_data_in_image(self, encrypted_data: bytes, cover_image_path: str, 
                          output_image_path: str) -> None:
        """
        Hide encrypted data in cover image
        
        Args:
            encrypted_data: Already encrypted data to hide
            cover_image_path: Path to cover image file
            output_image_path: Path for output steganographic image
            
        Raises:
            CoverMediaError: If cover image is invalid
            CapacityError: If data doesn't fit in image
            SteganographyError: If hiding operation fails
        """
        try:
            # Validate cover image exists
            if not os.path.exists(cover_image_path):
                raise CoverMediaError(f"Cover image not found: {cover_image_path}")
            
            # Read cover image
            with open(cover_image_path, 'rb') as f:
                cover_data = f.read()
            
            # Check capacity
            capacity = self.stego.calculate_capacity(cover_data)
            if len(encrypted_data) > capacity:
                raise CapacityError(len(encrypted_data), capacity, "image")
            
            # Hide data
            stego_data = self.stego.hide_data(cover_data, encrypted_data)
            
            # Write output
            with open(output_image_path, 'wb') as f:
                f.write(stego_data)
                
        except Exception as e:
            if isinstance(e, (SteganographyError, CoverMediaError, CapacityError)):
                raise
            raise SteganographyError(f"Failed to hide data in image: {e}")
    
    def extract_data_from_image(self, stego_image_path: str) -> bytes:
        """
        Extract encrypted data from steganographic image
        
        Args:
            stego_image_path: Path to steganographic image
            
        Returns:
            Extracted encrypted data
            
        Raises:
            CoverMediaError: If image file is invalid
            SteganographyError: If extraction fails
        """
        try:
            # Validate image exists
            if not os.path.exists(stego_image_path):
                raise CoverMediaError(f"Steganographic image not found: {stego_image_path}")
            
            # Read image
            with open(stego_image_path, 'rb') as f:
                stego_data = f.read()
            
            # Extract data
            encrypted_data = self.stego.extract_data(stego_data)
            
            return encrypted_data
            
        except Exception as e:
            if isinstance(e, (SteganographyError, CoverMediaError)):
                raise
            raise SteganographyError(f"Failed to extract data from image: {e}")
    
    def get_capacity(self, cover_image_path: str) -> int:
        """
        Get hiding capacity for cover image
        
        Args:
            cover_image_path: Path to cover image
            
        Returns:
            Maximum bytes that can be hidden
        """
        with open(cover_image_path, 'rb') as f:
            cover_data = f.read()
        
        return self.stego.calculate_capacity(cover_data)


def create_steganography_transport(args, derived_key: Optional[bytes] = None) -> Optional[SteganographyTransport]:
    """
    Create steganography transport from CLI arguments
    
    Args:
        args: Parsed CLI arguments  
        password: The main user password to derive steganography key from
        
    Returns:
        SteganographyTransport instance or None if not using steganography
    """
    # Check if steganography is requested
    stego_hide = getattr(args, 'stego_hide', None)
    stego_extract = getattr(args, 'stego_extract', False)
    
    if not stego_hide and not stego_extract:
        return None
    
    try:
        # Extract steganography options
        method = getattr(args, 'stego_method', 'lsb')
        bits_per_channel = getattr(args, 'stego_bits_per_channel', 1)
        
        # Use the derived encryption key for steganography security
        stego_password = None
        if derived_key:
            # Convert first 32 bytes of derived key to a base64 string for compatibility
            import base64
            try:
                # Use SecureBytes for the key slice to protect in memory
                secure_key_slice = SecureBytes(derived_key[:32])
                stego_password = base64.b64encode(secure_key_slice).decode('ascii')
            finally:
                # Securely wipe the key slice from memory
                if 'secure_key_slice' in locals():
                    secure_memzero(secure_key_slice)
        
        options = {
            'randomize_pixels': getattr(args, 'stego_randomize_pixels', False),
            'decoy_data': getattr(args, 'stego_decoy_data', False),
            'preserve_stats': True,
        }
        
        return SteganographyTransport(
            method=method,
            bits_per_channel=bits_per_channel,
            password=stego_password,
            **options
        )
        
    except ImportError as e:
        logger.error(f"Steganography dependencies not available: {e}")
        raise SteganographyError(
            "Steganography requires additional dependencies. "
            "Install with: pip install Pillow numpy"
        )


def is_steganography_available() -> bool:
    """Check if steganography dependencies are available"""
    try:
        from PIL import Image
        import numpy as np
        return True
    except ImportError:
        return False