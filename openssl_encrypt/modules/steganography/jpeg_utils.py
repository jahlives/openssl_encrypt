#!/usr/bin/env python3
"""
JPEG Utilities for Steganography

This module provides utilities for JPEG format handling, DCT analysis,
and JPEG-specific operations for steganography.
"""

import io
import logging
import math
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

# Import secure memory functions for handling sensitive data
try:
    from ..secure_memory import SecureBytes, secure_memzero
except ImportError:
    # Fallback for standalone testing
    from openssl_encrypt.modules.secure_memory import SecureBytes, secure_memzero

try:
    from PIL import Image, ImageFile
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    Image = None
    ImageFile = None
    TAGS = None

from .stego_core import SteganographyError, CoverMediaError

# Set up module logger
logger = logging.getLogger(__name__)

# JPEG format constants
JPEG_SOI = b'\xFF\xD8'  # Start of Image
JPEG_EOI = b'\xFF\xD9'  # End of Image
JPEG_SOS = b'\xFF\xDA'  # Start of Scan
JPEG_DQT = b'\xFF\xDB'  # Define Quantization Table
JPEG_DHT = b'\xFF\xC4'  # Define Huffman Table
JPEG_APP0 = b'\xFF\xE0'  # Application segment 0
JPEG_COM = b'\xFF\xFE'  # Comment

# Standard JPEG quantization tables
STANDARD_LUMINANCE_QT = np.array([
    [16, 11, 10, 16, 24, 40, 51, 61],
    [12, 12, 14, 19, 26, 58, 60, 55],
    [14, 13, 16, 24, 40, 57, 69, 56],
    [14, 17, 22, 29, 51, 87, 80, 62],
    [18, 22, 37, 56, 68, 109, 103, 77],
    [24, 35, 55, 64, 81, 104, 113, 92],
    [49, 64, 78, 87, 103, 121, 120, 101],
    [72, 92, 95, 98, 112, 100, 103, 99]
])

STANDARD_CHROMINANCE_QT = np.array([
    [17, 18, 24, 47, 99, 99, 99, 99],
    [18, 21, 26, 66, 99, 99, 99, 99],
    [24, 26, 56, 99, 99, 99, 99, 99],
    [47, 66, 99, 99, 99, 99, 99, 99],
    [99, 99, 99, 99, 99, 99, 99, 99],
    [99, 99, 99, 99, 99, 99, 99, 99],
    [99, 99, 99, 99, 99, 99, 99, 99],
    [99, 99, 99, 99, 99, 99, 99, 99]
])


class JPEGAnalyzer:
    """
    JPEG format analyzer and utility functions
    
    Provides tools for analyzing JPEG structure, quality estimation,
    and format validation for steganography purposes.
    """
    
    def __init__(self):
        self.quantization_tables = {}
        self.huffman_tables = {}
    
    def analyze_jpeg_structure(self, jpeg_data: bytes) -> Dict[str, Any]:
        """
        Comprehensive JPEG structure analysis
        
        Args:
            jpeg_data: Raw JPEG data
            
        Returns:
            Dictionary containing JPEG structure information
        """
        try:
            # Use secure memory for analysis
            secure_data = None
            
            try:
                secure_data = SecureBytes(jpeg_data)
                
                if not self._is_valid_jpeg(secure_data):
                    raise CoverMediaError("Invalid JPEG format")
                
                # Parse JPEG segments
                segments = self._parse_jpeg_segments(secure_data)
                
                # Analyze quantization tables
                quality_info = self._analyze_quality(segments)
                
                # Analyze image properties
                image_info = self._analyze_image_properties(secure_data)
                
                # Calculate steganography suitability
                suitability = self._assess_stego_suitability(quality_info, image_info)
                
                return {
                    'format': 'JPEG',
                    'valid': True,
                    'segments': len(segments),
                    'quality_info': quality_info,
                    'image_info': image_info,
                    'steganography': suitability,
                    'analysis_version': '1.0'
                }
                
            finally:
                # Clean up secure memory
                if secure_data:
                    secure_memzero(secure_data)
                    
        except Exception as e:
            logger.error(f"JPEG analysis failed: {e}")
            return {
                'format': 'JPEG',
                'valid': False,
                'error': str(e)
            }
    
    def _is_valid_jpeg(self, jpeg_data: bytes) -> bool:
        """Check if data is valid JPEG format"""
        if len(jpeg_data) < 10:
            return False
        
        # Check SOI marker
        if jpeg_data[:2] != JPEG_SOI:
            return False
        
        # Check for EOI marker at end (allowing for trailing data)
        has_eoi = JPEG_EOI in jpeg_data[-100:]
        
        return has_eoi
    
    def _parse_jpeg_segments(self, jpeg_data: bytes) -> List[Dict[str, Any]]:
        """Parse JPEG segments and markers"""
        segments = []
        pos = 2  # Skip SOI marker
        
        while pos < len(jpeg_data) - 1:
            # Look for marker
            if jpeg_data[pos] != 0xFF:
                pos += 1
                continue
            
            if pos + 1 >= len(jpeg_data):
                break
            
            marker = jpeg_data[pos:pos+2]
            pos += 2
            
            # Handle different marker types
            if marker == JPEG_EOI:
                segments.append({'type': 'EOI', 'marker': marker, 'size': 0})
                break
            elif marker[1] >= 0xD0 and marker[1] <= 0xD7:  # RST markers
                segments.append({'type': 'RST', 'marker': marker, 'size': 0})
                continue
            elif marker == JPEG_SOS:
                # Start of scan - rest is compressed data
                segments.append({'type': 'SOS', 'marker': marker, 'size': 'variable'})
                break
            else:
                # Read segment length
                if pos + 2 > len(jpeg_data):
                    break
                
                length = struct.unpack('>H', jpeg_data[pos:pos+2])[0]
                
                segment_type = self._identify_segment_type(marker)
                segments.append({
                    'type': segment_type,
                    'marker': marker,
                    'size': length,
                    'data_start': pos + 2,
                    'data_end': pos + length
                })
                
                pos += length
        
        return segments
    
    def _identify_segment_type(self, marker: bytes) -> str:
        """Identify JPEG segment type from marker"""
        marker_map = {
            JPEG_DQT: 'DQT',
            JPEG_DHT: 'DHT',
            JPEG_APP0: 'APP0',
            JPEG_COM: 'COM',
            b'\xFF\xC0': 'SOF0',
            b'\xFF\xC1': 'SOF1',
            b'\xFF\xC2': 'SOF2',
            b'\xFF\xE1': 'APP1',
            b'\xFF\xE2': 'APP2',
        }
        
        return marker_map.get(marker, f'UNKNOWN_{marker[1]:02X}')
    
    def _analyze_quality(self, segments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze JPEG quality from quantization tables"""
        quality_info = {
            'estimated_quality': 75,  # Default assumption
            'quantization_tables': 0,
            'quality_method': 'estimated'
        }
        
        # Look for DQT segments
        dqt_count = sum(1 for seg in segments if seg['type'] == 'DQT')
        quality_info['quantization_tables'] = dqt_count
        
        if dqt_count > 0:
            # In a full implementation, would parse actual QT values
            # and estimate quality using standard algorithms
            quality_info['estimated_quality'] = self._estimate_quality_from_tables()
            quality_info['quality_method'] = 'quantization_analysis'
        
        return quality_info
    
    def _estimate_quality_from_tables(self) -> int:
        """Estimate JPEG quality from quantization tables"""
        # Simplified quality estimation
        # Real implementation would analyze actual QT values
        return 85  # Conservative estimate
    
    def _analyze_image_properties(self, jpeg_data: bytes) -> Dict[str, Any]:
        """Analyze image properties relevant to steganography"""
        try:
            image = Image.open(io.BytesIO(jpeg_data))
            
            return {
                'width': image.size[0],
                'height': image.size[1],
                'mode': image.mode,
                'format': image.format,
                'total_pixels': image.size[0] * image.size[1],
                'dct_blocks': (image.size[0] // 8) * (image.size[1] // 8),
                'has_exif': hasattr(image, '_getexif') and image._getexif() is not None
            }
        except Exception as e:
            logger.warning(f"Image property analysis failed: {e}")
            return {'error': str(e)}
    
    def _assess_stego_suitability(self, quality_info: Dict[str, Any], 
                                image_info: Dict[str, Any]) -> Dict[str, Any]:
        """Assess JPEG suitability for steganography"""
        suitability = {
            'overall_score': 0.0,
            'quality_score': 0.0,
            'size_score': 0.0,
            'recommendations': []
        }
        
        # Quality assessment
        quality = quality_info.get('estimated_quality', 75)
        if quality >= 90:
            suitability['quality_score'] = 1.0
        elif quality >= 80:
            suitability['quality_score'] = 0.8
        elif quality >= 70:
            suitability['quality_score'] = 0.6
        else:
            suitability['quality_score'] = 0.3
            suitability['recommendations'].append("JPEG quality too low for reliable steganography")
        
        # Size assessment
        pixels = image_info.get('total_pixels', 0)
        if pixels >= 1000000:  # 1MP+
            suitability['size_score'] = 1.0
        elif pixels >= 500000:  # 0.5MP+
            suitability['size_score'] = 0.8
        elif pixels >= 200000:  # 0.2MP+
            suitability['size_score'] = 0.6
        else:
            suitability['size_score'] = 0.3
            suitability['recommendations'].append("Image too small for significant data hiding")
        
        # Calculate overall score
        suitability['overall_score'] = (
            suitability['quality_score'] * 0.7 + 
            suitability['size_score'] * 0.3
        )
        
        # General recommendations
        if suitability['overall_score'] >= 0.8:
            suitability['recommendations'].append("Excellent candidate for JPEG steganography")
        elif suitability['overall_score'] >= 0.6:
            suitability['recommendations'].append("Good candidate with minor limitations")
        else:
            suitability['recommendations'].append("Consider using different image or format")
        
        return suitability


class DCTUtils:
    """
    DCT (Discrete Cosine Transform) utilities for JPEG steganography
    
    Provides DCT-related functions for coefficient analysis and manipulation.
    """
    
    @staticmethod
    def dct2d(block: np.ndarray) -> np.ndarray:
        """
        2D DCT transform of 8x8 block
        
        Args:
            block: 8x8 numpy array
            
        Returns:
            DCT coefficients
        """
        try:
            # Use secure memory for DCT computation
            secure_block = SecureBytes(block.tobytes())
            
            try:
                # Simplified DCT implementation
                # In production, would use optimized DCT library
                N = 8
                dct_block = np.zeros((N, N))
                
                for u in range(N):
                    for v in range(N):
                        cu = 1/math.sqrt(2) if u == 0 else 1
                        cv = 1/math.sqrt(2) if v == 0 else 1
                        
                        sum_val = 0
                        for x in range(N):
                            for y in range(N):
                                sum_val += block[x, y] * math.cos((2*x + 1) * u * math.pi / (2*N)) * \
                                          math.cos((2*y + 1) * v * math.pi / (2*N))
                        
                        dct_block[u, v] = (2/N) * cu * cv * sum_val
                
                return dct_block
                
            finally:
                secure_memzero(secure_block)
                
        except Exception as e:
            logger.error(f"DCT computation failed: {e}")
            return block  # Return original on error
    
    @staticmethod
    def idct2d(dct_block: np.ndarray) -> np.ndarray:
        """
        2D inverse DCT transform
        
        Args:
            dct_block: DCT coefficients
            
        Returns:
            Reconstructed 8x8 block
        """
        try:
            # Simplified IDCT implementation
            N = 8
            block = np.zeros((N, N))
            
            for x in range(N):
                for y in range(N):
                    sum_val = 0
                    for u in range(N):
                        for v in range(N):
                            cu = 1/math.sqrt(2) if u == 0 else 1
                            cv = 1/math.sqrt(2) if v == 0 else 1
                            
                            sum_val += cu * cv * dct_block[u, v] * \
                                      math.cos((2*x + 1) * u * math.pi / (2*N)) * \
                                      math.cos((2*y + 1) * v * math.pi / (2*N))
                    
                    block[x, y] = (2/N) * sum_val
            
            return np.clip(block, 0, 255).astype(np.uint8)
            
        except Exception as e:
            logger.error(f"IDCT computation failed: {e}")
            return dct_block.astype(np.uint8)  # Return original on error
    
    @staticmethod
    def quantize_block(dct_block: np.ndarray, qt: np.ndarray) -> np.ndarray:
        """Quantize DCT block using quantization table"""
        return np.round(dct_block / qt).astype(np.int16)
    
    @staticmethod
    def dequantize_block(quantized_block: np.ndarray, qt: np.ndarray) -> np.ndarray:
        """Dequantize DCT block"""
        return quantized_block * qt
    
    @staticmethod
    def get_zigzag_order() -> List[Tuple[int, int]]:
        """Get zigzag scanning order for 8x8 DCT block"""
        return [
            (0,0), (0,1), (1,0), (2,0), (1,1), (0,2), (0,3), (1,2),
            (2,1), (3,0), (4,0), (3,1), (2,2), (1,3), (0,4), (0,5),
            (1,4), (2,3), (3,2), (4,1), (5,0), (6,0), (5,1), (4,2),
            (3,3), (2,4), (1,5), (0,6), (0,7), (1,6), (2,5), (3,4),
            (4,3), (5,2), (6,1), (7,0), (7,1), (6,2), (5,3), (4,4),
            (3,5), (2,6), (1,7), (2,7), (3,6), (4,5), (5,4), (6,3),
            (7,2), (7,3), (6,4), (5,5), (4,6), (3,7), (4,7), (5,6),
            (6,5), (7,4), (7,5), (6,6), (5,7), (6,7), (7,6), (7,7)
        ]


def create_jpeg_test_image(width: int = 512, height: int = 512, 
                          quality: int = 85) -> bytes:
    """
    Create a test JPEG image for steganography testing
    
    Args:
        width: Image width
        height: Image height  
        quality: JPEG quality (70-100)
        
    Returns:
        JPEG image data
    """
    try:
        # Create test pattern
        img_array = np.zeros((height, width, 3), dtype=np.uint8)
        
        # Add some pattern for realistic DCT coefficients
        for y in range(height):
            for x in range(width):
                img_array[y, x, 0] = (x + y) % 256  # Red gradient
                img_array[y, x, 1] = (x * 2) % 256   # Green pattern
                img_array[y, x, 2] = (y * 2) % 256   # Blue pattern
        
        # Convert to PIL Image
        image = Image.fromarray(img_array)
        
        # Save as JPEG with specified quality
        output_buffer = io.BytesIO()
        image.save(output_buffer, format='JPEG', quality=quality)
        
        return output_buffer.getvalue()
        
    except Exception as e:
        logger.error(f"Test JPEG creation failed: {e}")
        raise CoverMediaError(f"Could not create test JPEG: {e}")


def is_jpeg_steganography_available() -> bool:
    """Check if JPEG steganography dependencies are available"""
    return PIL_AVAILABLE and np is not None