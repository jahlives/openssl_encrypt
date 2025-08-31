#!/usr/bin/env python3
"""
WEBP Steganography Module

⚠️  **DISABLED - DO NOT USE** ⚠️
This module is currently disabled due to algorithmic issues in the hide/extract cycle.
WEBP steganography does not work correctly and should not be used in production.

Issues:
- Hide/extract cycle fails (returns empty data instead of original data)
- Bit-level extraction logic has fundamental flaws
- Overflow issues in capacity calculations

Status: Code preserved for future development, but functionality is broken.

---

This module provides steganographic capabilities for WEBP images, supporting
both lossless and lossy WEBP formats with appropriate handling for each variant.

Key Features (CURRENTLY BROKEN):
- Lossless WEBP steganography using LSB methods
- Lossy WEBP steganography with DCT-based techniques  
- Automatic lossless/lossy detection and method selection
- Secure memory management throughout operations
- Comprehensive format analysis and capacity calculation

Security Architecture:
- SecureBytes containers for all sensitive data
- Automatic memory cleanup after operations
- Key-based pixel randomization for enhanced security
- Format-aware hiding to prevent detection artifacts

Supported WEBP Features:
- VP8 (lossy) and VP8L (lossless) codecs
- RGB and RGBA color modes
- Animation support (first frame steganography)
- Metadata preservation during steganographic operations
"""

import io
import logging
import struct
from typing import Optional, Dict, Any, Tuple, List
import numpy as np
from PIL import Image

# Import secure memory functions for handling sensitive data
try:
    from ..secure_memory import SecureBytes, secure_memzero
except ImportError:
    # Fallback for standalone testing
    from openssl_encrypt.modules.secure_memory import SecureBytes, secure_memzero

from .stego_core import (
    SteganographyBase,
    SteganographyConfig,
    SteganographyError,
    CapacityError,
    ExtractionError,
    CoverMediaError,
    SteganographyUtils
)

# Set up module logger
logger = logging.getLogger(__name__)


class WEBPSteganography(SteganographyBase):
    """
    ⚠️  **DISABLED - DO NOT USE** ⚠️
    
    WEBP steganography implementation - CURRENTLY BROKEN
    
    This class is disabled due to algorithmic issues and should not be used.
    All methods will raise NotImplementedError to prevent accidental usage.
    
    Issues: Hide/extract cycle fails, bit-level extraction flaws, overflow problems.
    Status: Code preserved for future development.
    """
    
    SUPPORTED_FORMATS = {'WEBP'}
    
    # WEBP format constants
    WEBP_HEADER_SIZE = 12
    WEBP_CHUNK_HEADER_SIZE = 8
    VP8_SIGNATURE = b'VP8 '
    VP8L_SIGNATURE = b'VP8L'
    VP8X_SIGNATURE = b'VP8X'
    
    def __init__(self, password: Optional[str] = None, security_level: int = 1,
                 bits_per_channel: int = 1, force_lossless: bool = False,
                 config: Optional[SteganographyConfig] = None):
        """
        Initialize WEBP steganography
        
        ⚠️  **DISABLED - DO NOT USE** ⚠️
        This implementation is broken and will raise NotImplementedError.
        
        Args:
            password: Optional password for enhanced security
            security_level: Security level (1-3)
            bits_per_channel: LSB bits per color channel (1-3) for lossless WEBP
            force_lossless: Force lossless mode even for lossy WEBP images
            config: Steganography configuration
        """
        raise NotImplementedError(
            "WEBP steganography is currently disabled due to algorithmic issues. "
            "The hide/extract cycle fails and produces incorrect results. "
            "Use PNG, JPEG, TIFF, WAV, or FLAC steganography instead."
        )
        
        super().__init__(password, security_level)
        
        if not (1 <= bits_per_channel <= 3):
            raise ValueError("bits_per_channel must be between 1 and 3")
            
        self.bits_per_channel = bits_per_channel
        self.force_lossless = force_lossless
        self.webp_info = {}
        
        # Set config or create default
        self.config = config or SteganographyConfig()
        
        # Configure based on security level
        if security_level >= 2:
            self.config.randomize_pixel_order = True
        if security_level >= 3:
            self.config.enable_decoy_data = True
    
    def calculate_capacity(self, cover_data: bytes) -> int:
        """
        Calculate steganographic capacity for WEBP image
        
        Args:
            cover_data: Raw WEBP data
            
        Returns:
            Maximum bytes that can be hidden
            
        Raises:
            CoverMediaError: If WEBP format is invalid
        """
        try:
            # Use SecureBytes for cover data protection
            secure_cover_data = SecureBytes(cover_data)
            
            try:
                # Analyze WEBP structure
                webp_info = self._analyze_webp_structure(secure_cover_data)
                
                # Load WEBP image using PIL
                image = Image.open(io.BytesIO(secure_cover_data))
                
                if image.format != 'WEBP':
                    raise CoverMediaError(f"Expected WEBP format, got {image.format}")
                
                # Calculate capacity based on WEBP type
                if webp_info['is_lossless'] or self.force_lossless:
                    # Lossless WEBP - use LSB method
                    capacity = self._calculate_lossless_capacity(image)
                else:
                    # Lossy WEBP - more conservative capacity
                    capacity = self._calculate_lossy_capacity(image)
                
                # Apply safety margin
                capacity = int(capacity * 0.85)  # 15% safety margin
                
                logger.debug(f"WEBP capacity: {capacity} bytes ({webp_info['codec']} format)")
                return max(0, capacity)
                
            finally:
                # Secure cleanup
                secure_memzero(secure_cover_data)
                
        except Exception as e:
            logger.error(f"WEBP capacity calculation failed: {e}")
            raise CoverMediaError(f"Invalid WEBP file: {e}")
    
    def hide_data(self, cover_data: bytes, secret_data: bytes) -> bytes:
        """
        Hide secret data in WEBP image
        
        Args:
            cover_data: Cover WEBP image data
            secret_data: Secret data to hide
            
        Returns:
            Steganographic WEBP image data
            
        Raises:
            CapacityError: If secret data is too large
            CoverMediaError: If cover image is invalid
            SteganographyError: If hiding operation fails
        """
        # Use SecureBytes for sensitive data protection
        secure_cover_data = SecureBytes(cover_data)
        secure_secret_data = SecureBytes(secret_data)
        
        try:
            # Analyze WEBP structure
            webp_info = self._analyze_webp_structure(secure_cover_data)
            self.webp_info = webp_info
            
            # Check capacity
            capacity = self.calculate_capacity(cover_data)
            if len(secret_data) > capacity:
                raise CapacityError(len(secret_data), capacity, "WEBP image")
            
            # Load WEBP image
            image = Image.open(io.BytesIO(secure_cover_data))
            
            # Choose hiding method based on WEBP type
            if webp_info['is_lossless'] or self.force_lossless:
                logger.debug("Using lossless WEBP steganography")
                stego_image = self._hide_in_lossless_webp(image, secure_secret_data)
            else:
                logger.debug("Using lossy WEBP steganography")
                stego_image = self._hide_in_lossy_webp(image, secure_secret_data)
            
            # Convert back to WEBP bytes
            output_buffer = io.BytesIO()
            
            # Preserve original WEBP parameters when possible
            save_params = {
                'format': 'WEBP',
                'lossless': webp_info['is_lossless'] or self.force_lossless,
                'quality': webp_info.get('quality', 90),
                'method': webp_info.get('method', 4)
            }
            
            stego_image.save(output_buffer, **save_params)
            return output_buffer.getvalue()
            
        except Exception as e:
            if isinstance(e, (CapacityError, CoverMediaError)):
                raise
            logger.error(f"WEBP hiding failed: {e}")
            raise SteganographyError(f"WEBP steganography failed: {e}")
        finally:
            # Secure cleanup
            secure_memzero(secure_cover_data)
            secure_memzero(secure_secret_data)
    
    def extract_data(self, stego_data: bytes) -> bytes:
        """
        Extract secret data from steganographic WEBP image
        
        Args:
            stego_data: Steganographic WEBP image data
            
        Returns:
            Extracted secret data
            
        Raises:
            ExtractionError: If extraction fails
        """
        # Use SecureBytes for data protection
        secure_stego_data = SecureBytes(stego_data)
        
        try:
            # Analyze WEBP structure
            webp_info = self._analyze_webp_structure(secure_stego_data)
            
            # Load WEBP image
            image = Image.open(io.BytesIO(secure_stego_data))
            
            # Choose extraction method based on WEBP type
            if webp_info['is_lossless'] or self.force_lossless:
                logger.debug("Extracting from lossless WEBP")
                extracted_data = self._extract_from_lossless_webp(image)
            else:
                logger.debug("Extracting from lossy WEBP")
                extracted_data = self._extract_from_lossy_webp(image)
            
            logger.debug(f"Extracted {len(extracted_data)} bytes from WEBP")
            return bytes(extracted_data)
            
        except Exception as e:
            logger.error(f"WEBP extraction failed: {e}")
            raise ExtractionError(f"WEBP extraction failed: {e}")
        finally:
            # Secure cleanup
            secure_memzero(secure_stego_data)
    
    def _analyze_webp_structure(self, webp_data: bytes) -> Dict[str, Any]:
        """Analyze WEBP file structure and determine format details"""
        try:
            if len(webp_data) < self.WEBP_HEADER_SIZE:
                raise CoverMediaError("File too small to be valid WEBP")
            
            # Check RIFF header
            if webp_data[:4] != b'RIFF':
                raise CoverMediaError("Invalid WEBP file: missing RIFF header")
            
            # Check WEBP signature
            if webp_data[8:12] != b'WEBP':
                raise CoverMediaError("Invalid WEBP file: missing WEBP signature")
            
            webp_info = {
                'format': 'WEBP',
                'valid': True,
                'file_size': struct.unpack('<I', webp_data[4:8])[0] + 8,
                'is_lossless': False,
                'codec': 'unknown',
                'has_alpha': False,
                'is_animated': False,
                'quality': 90,  # Default
                'method': 4     # Default
            }
            
            # Parse chunks to determine format
            offset = 12
            while offset < len(webp_data) - 8:
                # Read chunk header
                chunk_id = webp_data[offset:offset+4]
                chunk_size = struct.unpack('<I', webp_data[offset+4:offset+8])[0]
                
                if chunk_id == self.VP8L_SIGNATURE:
                    webp_info['is_lossless'] = True
                    webp_info['codec'] = 'VP8L'
                elif chunk_id == self.VP8_SIGNATURE:
                    webp_info['is_lossless'] = False
                    webp_info['codec'] = 'VP8'
                elif chunk_id == self.VP8X_SIGNATURE:
                    webp_info['codec'] = 'VP8X'
                    # Parse VP8X flags
                    if offset + 8 + 4 <= len(webp_data):
                        flags = webp_data[offset + 8]
                        webp_info['has_alpha'] = bool(flags & 0x10)
                        webp_info['is_animated'] = bool(flags & 0x02)
                
                # Move to next chunk
                offset += 8 + ((chunk_size + 1) & ~1)  # Pad to even bytes
                if offset >= len(webp_data):
                    break
            
            return webp_info
            
        except Exception as e:
            logger.error(f"WEBP structure analysis failed: {e}")
            raise CoverMediaError(f"Invalid WEBP file: {e}")
    
    def _calculate_lossless_capacity(self, image: Image.Image) -> int:
        """Calculate capacity for lossless WEBP using LSB method"""
        width, height = image.size
        
        # Convert to numpy array for analysis
        img_array = np.array(image)
        
        # Determine channels
        if len(img_array.shape) == 2:
            channels = 1  # Grayscale
        else:
            channels = img_array.shape[2]
        
        # Calculate total bits available
        total_pixels = width * height
        bits_available = total_pixels * channels * self.bits_per_channel
        
        # Convert to bytes (subtract overhead for length and markers)
        capacity = (bits_available // 8) - 32  # 32 bytes overhead
        
        return max(0, capacity)
    
    def _calculate_lossy_capacity(self, image: Image.Image) -> int:
        """Calculate capacity for lossy WEBP - more conservative approach"""
        width, height = image.size
        
        # For lossy WEBP, use more conservative capacity calculation
        # Due to compression artifacts affecting steganography
        total_pixels = width * height
        
        # Use only 25% of theoretical capacity for lossy WEBP
        capacity = (total_pixels // 4) - 64  # Extra overhead for lossy
        
        return max(0, capacity)
    
    def _hide_in_lossless_webp(self, image: Image.Image, secret_data: bytes) -> Image.Image:
        """Hide data in lossless WEBP using LSB method"""
        try:
            # Convert image to numpy array
            img_array = np.array(image)
            original_shape = img_array.shape
            
            # Ensure we have the right data type
            if img_array.dtype != np.uint8:
                img_array = img_array.astype(np.uint8)
            
            # Prepare data for hiding (add length prefix and end marker)
            data_length = len(secret_data)
            length_bytes = struct.pack('<I', data_length)
            data_to_hide = SecureBytes(length_bytes + secret_data + b'\x00\x01\x02\x03')  # End marker
            
            try:
                # Convert data to binary
                binary_data = list(SteganographyUtils.bytes_to_binary(bytes(data_to_hide)))
                
                # Flatten image array for processing
                flat_image = img_array.flatten()
                
                # Generate pixel order (randomized if password provided)
                pixel_indices = list(range(len(flat_image)))
                if self.password:
                    # Use password-based randomization
                    np.random.seed(hash(self.password) & 0xFFFFFFFF)
                    np.random.shuffle(pixel_indices)
                
                # Hide data using LSB
                bit_index = 0
                mask = (0xFF << self.bits_per_channel) & 0xFF
                
                for i, pixel_idx in enumerate(pixel_indices):
                    if bit_index >= len(binary_data):
                        break
                    
                    # Extract bits to hide
                    bits_to_hide = 0
                    for bit_offset in range(self.bits_per_channel):
                        if bit_index + bit_offset < len(binary_data):
                            bits_to_hide |= (int(binary_data[bit_index + bit_offset]) << bit_offset)
                    
                    # Modify pixel
                    original_pixel = flat_image[pixel_idx]
                    modified_pixel = (original_pixel & mask) | bits_to_hide
                    flat_image[pixel_idx] = modified_pixel
                    
                    bit_index += self.bits_per_channel
                
                # Reshape back to original shape
                modified_array = flat_image.reshape(original_shape)
                
                # Create new image
                return Image.fromarray(modified_array, mode=image.mode)
                
            finally:
                # Secure cleanup
                secure_memzero(data_to_hide)
                if 'binary_data' in locals():
                    # Clear binary data list
                    binary_data.clear()
                
        except Exception as e:
            logger.error(f"Lossless WEBP hiding failed: {e}")
            raise SteganographyError(f"Lossless WEBP hiding failed: {e}")
    
    def _hide_in_lossy_webp(self, image: Image.Image, secret_data: bytes) -> Image.Image:
        """Hide data in lossy WEBP using robust method"""
        try:
            # For lossy WEBP, we need to use a more robust hiding method
            # that can survive compression artifacts
            
            # Convert to RGB if necessary
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            
            # Use a simple but robust LSB method with error correction
            data_length = len(secret_data)
            length_bytes = struct.pack('<I', data_length)
            
            # Triple redundancy for lossy formats
            redundant_data = (length_bytes + secret_data) * 3
            data_to_hide = SecureBytes(redundant_data + b'\xFF\xFE\xFD\xFC')  # Strong end marker
            
            try:
                binary_data = list(SteganographyUtils.bytes_to_binary(bytes(data_to_hide)))
                
                height, width, channels = img_array.shape
                total_pixels = height * width * channels
                
                if len(binary_data) > total_pixels:
                    raise CapacityError(len(binary_data), total_pixels, "lossy WEBP")
                
                # Hide in LSB with spacing to reduce compression artifacts
                bit_index = 0
                pixel_index = 0
                
                for y in range(height):
                    for x in range(width):
                        for c in range(channels):
                            if bit_index >= len(binary_data):
                                break
                            
                            # Hide bit with spacing (every 4th pixel for robustness)
                            if pixel_index % 4 == 0 and bit_index < len(binary_data):
                                original_value = img_array[y, x, c]
                                bit_to_hide = int(binary_data[bit_index])
                                
                                # Modify LSB
                                modified_value = (original_value & 0xFE) | bit_to_hide
                                img_array[y, x, c] = modified_value
                                
                                bit_index += 1
                            
                            pixel_index += 1
                
                return Image.fromarray(img_array, 'RGB')
                
            finally:
                secure_memzero(data_to_hide)
                if 'binary_data' in locals():
                    binary_data.clear()
                
        except Exception as e:
            logger.error(f"Lossy WEBP hiding failed: {e}")
            raise SteganographyError(f"Lossy WEBP hiding failed: {e}")
    
    def _extract_from_lossless_webp(self, image: Image.Image) -> bytes:
        """Extract data from lossless WEBP using LSB method"""
        try:
            # Convert image to numpy array
            img_array = np.array(image)
            
            # Flatten for processing
            flat_image = img_array.flatten()
            
            # Generate same pixel order used during hiding
            pixel_indices = list(range(len(flat_image)))
            if self.password:
                np.random.seed(hash(self.password) & 0xFFFFFFFF)
                np.random.shuffle(pixel_indices)
            
            # Extract length first (4 bytes = 32 bits)
            length_bits = []
            bit_mask = (1 << self.bits_per_channel) - 1
            
            # Extract length
            bit_index = 0
            for pixel_idx in pixel_indices[:32 // self.bits_per_channel + 1]:
                if bit_index >= 32:
                    break
                    
                pixel_value = flat_image[pixel_idx]
                extracted_bits = pixel_value & bit_mask
                
                for bit_offset in range(self.bits_per_channel):
                    if bit_index < 32:
                        bit_value = (extracted_bits >> bit_offset) & 1
                        length_bits.append(bit_value)
                        bit_index += 1
            
            # Convert length bits to integer
            data_length = 0
            for i, bit in enumerate(length_bits):
                data_length |= (bit << i)
            
            # More robust sanity check for data length
            # First check for very large values that would cause overflow
            # Be much more conservative to prevent overflow warnings completely
            if data_length <= 0 or data_length > 100 * 1024:  # Max 100KB to prevent overflow
                # This is likely corrupted/wrong password scenario
                return b''
            
            # Extract actual data  
            # Length (4 bytes) + data + end marker (4 bytes) = 8 bytes overhead
            try:
                # Use safe integer operations - prevent overflow warnings
                if data_length > (2**30 - 64) // 8:  # Very conservative limit
                    return b''  # Return empty for suspicious data lengths
                
                # Extra safety check before multiplication to prevent numpy overflow warnings
                if data_length > 2**28:  # ~268MB limit
                    return b''
                    
                data_bits = data_length * 8
                total_bits_needed = data_bits + 64  # Length (32) + data + end marker (32)
                if total_bits_needed < 0:  # Overflow check
                    return b''
            except (OverflowError, ValueError):
                return b''  # Return empty data for calculation errors
            extracted_bits = []
            
            bit_index = 0
            for pixel_idx in pixel_indices:
                if bit_index >= total_bits_needed:
                    break
                
                pixel_value = flat_image[pixel_idx]
                extracted_bits_value = pixel_value & bit_mask
                
                for bit_offset in range(self.bits_per_channel):
                    if bit_index < total_bits_needed:
                        extracted_bits.append((extracted_bits_value >> bit_offset) & 1)
                        bit_index += 1
            
            # Convert bits back to bytes
            extracted_bytes = SecureBytes(SteganographyUtils.binary_to_bytes(''.join(map(str, extracted_bits))))
            
            try:
                # Extract the actual secret data (skip length prefix)
                if len(extracted_bytes) < 4:
                    raise ExtractionError("Insufficient data extracted")
                
                secret_data = extracted_bytes[4:4 + data_length]
                return bytes(secret_data)
                
            finally:
                # Secure cleanup
                secure_memzero(extracted_bytes)
                
        except Exception as e:
            logger.error(f"Lossless WEBP extraction failed: {e}")
            raise ExtractionError(f"Lossless WEBP extraction failed: {e}")
    
    def _extract_from_lossy_webp(self, image: Image.Image) -> bytes:
        """Extract data from lossy WEBP with error correction"""
        try:
            if image.mode != 'RGB':
                image = image.convert('RGB')
                
            img_array = np.array(image)
            height, width, channels = img_array.shape
            
            # Extract with same spacing used during hiding
            extracted_bits = []
            pixel_index = 0
            
            for y in range(height):
                for x in range(width):
                    for c in range(channels):
                        # Extract from every 4th pixel
                        if pixel_index % 4 == 0:
                            pixel_value = img_array[y, x, c]
                            extracted_bit = pixel_value & 1
                            extracted_bits.append(extracted_bit)
                        
                        pixel_index += 1
            
            # Convert bits to bytes
            if len(extracted_bits) < 32:
                raise ExtractionError("Insufficient data for length extraction")
            
            extracted_bytes = SecureBytes(SteganographyUtils.binary_to_bytes(''.join(map(str, extracted_bits))))
            
            try:
                # Extract length (first 4 bytes, repeated 3 times for redundancy)
                length_candidates = []
                for i in range(3):
                    offset = i * 4
                    if offset + 4 <= len(extracted_bytes):
                        length = struct.unpack('<I', extracted_bytes[offset:offset+4])[0]
                        length_candidates.append(length)
                
                # Use majority vote for length
                if not length_candidates:
                    raise ExtractionError("Could not extract data length")
                
                data_length = max(set(length_candidates), key=length_candidates.count)
                
                # More robust sanity check for data length
                if data_length <= 0 or data_length > 10 * 1024 * 1024:  # Max 10MB
                    raise ExtractionError(f"Invalid data length detected: {data_length}")
                
                # Extract data with redundancy (skip 12 bytes of length data)
                data_start = 12
                data_candidates = []
                
                for i in range(3):
                    offset = data_start + (i * data_length)
                    if offset + data_length <= len(extracted_bytes):
                        candidate = extracted_bytes[offset:offset + data_length]
                        data_candidates.append(bytes(candidate))
                
                if not data_candidates:
                    raise ExtractionError("Could not extract secret data")
                
                # Use the most common candidate (simple error correction)
                secret_data = max(set(data_candidates), key=data_candidates.count)
                return secret_data
                
            finally:
                secure_memzero(extracted_bytes)
                
        except Exception as e:
            logger.error(f"Lossy WEBP extraction failed: {e}")
            raise ExtractionError(f"Lossy WEBP extraction failed: {e}")


class WEBPAnalyzer:
    """
    WEBP format analyzer for steganography assessment
    
    Provides comprehensive analysis of WEBP file structure and suitability
    for steganographic operations.
    """
    
    def __init__(self):
        self.format_info = {
            'VP8': {'lossless': False, 'steganography_score': 0.6},
            'VP8L': {'lossless': True, 'steganography_score': 0.9},
            'VP8X': {'lossless': 'variable', 'steganography_score': 0.7}
        }
    
    def analyze_webp_structure(self, webp_data: bytes) -> Dict[str, Any]:
        """
        Comprehensive WEBP structure analysis
        
        Args:
            webp_data: Raw WEBP data
            
        Returns:
            Dictionary with detailed WEBP analysis
        """
        try:
            # Basic validation
            if len(webp_data) < 12:
                return {
                    'format': 'WEBP',
                    'valid': False,
                    'error': 'File too small'
                }
            
            # Parse WEBP structure
            webp_info = {
                'format': 'WEBP',
                'valid': True,
                'header': self._parse_webp_header(webp_data),
                'chunks': self._parse_webp_chunks(webp_data),
                'steganography': {}
            }
            
            # Analyze steganography suitability
            webp_info['steganography'] = self._analyze_steganography_suitability(webp_info)
            
            return webp_info
            
        except Exception as e:
            logger.error(f"WEBP analysis failed: {e}")
            return {
                'format': 'WEBP',
                'valid': False,
                'error': str(e)
            }
    
    def _parse_webp_header(self, webp_data: bytes) -> Dict[str, Any]:
        """Parse WEBP file header"""
        return {
            'signature': webp_data[:4],
            'file_size': struct.unpack('<I', webp_data[4:8])[0],
            'format_signature': webp_data[8:12],
            'valid_riff': webp_data[:4] == b'RIFF',
            'valid_webp': webp_data[8:12] == b'WEBP'
        }
    
    def _parse_webp_chunks(self, webp_data: bytes) -> List[Dict[str, Any]]:
        """Parse WEBP chunks"""
        chunks = []
        offset = 12
        
        while offset < len(webp_data) - 8:
            try:
                chunk_id = webp_data[offset:offset+4]
                chunk_size = struct.unpack('<I', webp_data[offset+4:offset+8])[0]
                
                chunk_info = {
                    'id': chunk_id,
                    'size': chunk_size,
                    'offset': offset
                }
                
                # Determine chunk type
                if chunk_id == b'VP8 ':
                    chunk_info['type'] = 'lossy'
                    chunk_info['codec'] = 'VP8'
                elif chunk_id == b'VP8L':
                    chunk_info['type'] = 'lossless'
                    chunk_info['codec'] = 'VP8L'
                elif chunk_id == b'VP8X':
                    chunk_info['type'] = 'extended'
                    chunk_info['codec'] = 'VP8X'
                else:
                    chunk_info['type'] = 'other'
                
                chunks.append(chunk_info)
                
                # Move to next chunk
                offset += 8 + ((chunk_size + 1) & ~1)
                
            except Exception as e:
                logger.warning(f"Error parsing WEBP chunk at offset {offset}: {e}")
                break
        
        return chunks
    
    def _analyze_steganography_suitability(self, webp_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze WEBP suitability for steganography"""
        suitability = {
            'overall_score': 0.0,
            'format_score': 0.0,
            'size_score': 0.0,
            'recommendations': []
        }
        
        try:
            # Analyze format suitability
            primary_codec = None
            for chunk in webp_info['chunks']:
                if chunk['type'] in ['lossy', 'lossless', 'extended']:
                    primary_codec = chunk['codec']
                    break
            
            if primary_codec:
                format_info = self.format_info.get(primary_codec, {'steganography_score': 0.5})
                suitability['format_score'] = format_info['steganography_score']
                
                if primary_codec == 'VP8L':
                    suitability['recommendations'].append("Lossless WEBP - excellent for steganography")
                elif primary_codec == 'VP8':
                    suitability['recommendations'].append("Lossy WEBP - good but requires robust methods")
                else:
                    suitability['recommendations'].append("Extended WEBP - varies by content")
            
            # Size analysis
            file_size = webp_info['header']['file_size']
            if file_size > 1024 * 1024:  # > 1MB
                suitability['size_score'] = 1.0
                suitability['recommendations'].append("Large file - high hiding capacity")
            elif file_size > 100 * 1024:  # > 100KB
                suitability['size_score'] = 0.7
                suitability['recommendations'].append("Medium file - good hiding capacity")
            else:
                suitability['size_score'] = 0.3
                suitability['recommendations'].append("Small file - limited hiding capacity")
            
            # Calculate overall score
            suitability['overall_score'] = (
                suitability['format_score'] * 0.7 +
                suitability['size_score'] * 0.3
            )
            
            # Add general recommendations
            if suitability['overall_score'] >= 0.8:
                suitability['recommendations'].append("Excellent WEBP for steganography")
            elif suitability['overall_score'] >= 0.6:
                suitability['recommendations'].append("Good WEBP with minor limitations")
            else:
                suitability['recommendations'].append("WEBP suitable with careful parameter selection")
            
        except Exception as e:
            logger.error(f"Steganography suitability analysis failed: {e}")
            suitability['error'] = str(e)
        
        return suitability


def create_webp_test_image(width: int = 512, height: int = 384, 
                          lossless: bool = True, quality: int = 90) -> bytes:
    """
    Create a test WEBP image for steganography testing
    
    Args:
        width: Image width
        height: Image height
        lossless: Create lossless WEBP (True) or lossy (False)
        quality: Quality factor for lossy WEBP (0-100)
        
    Returns:
        WEBP image data as bytes
    """
    try:
        # Create test pattern image
        img_array = np.zeros((height, width, 3), dtype=np.uint8)
        
        # Create colorful test pattern
        for y in range(height):
            for x in range(width):
                # Create gradient pattern with geometric shapes
                r = ((x + y) * 255) // (width + height)
                g = (x * 255) // width
                b = (y * 255) // height
                
                # Add some texture to make it realistic
                if (x // 32 + y // 32) % 2 == 0:
                    r = min(255, r + 50)
                
                img_array[y, x] = [r % 256, g % 256, b % 256]
        
        # Create PIL image
        image = Image.fromarray(img_array, 'RGB')
        
        # Save to bytes
        output_buffer = io.BytesIO()
        image.save(output_buffer, format='WEBP', lossless=lossless, quality=quality)
        
        return output_buffer.getvalue()
        
    except Exception as e:
        logger.error(f"Test WEBP creation failed: {e}")
        raise SteganographyError(f"Failed to create test WEBP: {e}")


def is_webp_steganography_available() -> bool:
    """Check if WEBP steganography dependencies are available"""
    try:
        from PIL import Image
        import numpy as np
        
        # Check if PIL supports WEBP
        test_image = Image.new('RGB', (10, 10), color='red')
        test_buffer = io.BytesIO()
        test_image.save(test_buffer, format='WEBP')
        
        return True
    except Exception as e:
        logger.warning(f"WEBP steganography not available: {e}")
        return False


if __name__ == "__main__":
    # Simple test
    if is_webp_steganography_available():
        print("WEBP steganography is available")
        
        # Create test image
        test_webp = create_webp_test_image(100, 100, lossless=True)
        print(f"Created test WEBP: {len(test_webp)} bytes")
        
        # Test steganography
        webp_stego = WEBPSteganography(bits_per_channel=2)
        capacity = webp_stego.calculate_capacity(test_webp)
        print(f"WEBP capacity: {capacity} bytes")
        
        # Test hiding/extraction
        test_data = b"WEBP steganography test!"
        if len(test_data) <= capacity:
            stego_data = webp_stego.hide_data(test_webp, test_data)
            extracted = webp_stego.extract_data(stego_data)
            print(f"Test successful: {extracted == test_data}")
        else:
            print("Test data too large for capacity")
    else:
        print("WEBP steganography not available")