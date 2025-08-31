#!/usr/bin/env python3
"""
MP3 Steganography Implementation for OpenSSL Encrypt

⚠️  **DISABLED - DO NOT USE** ⚠️
This module is currently disabled due to fundamental algorithmic issues.
MP3 steganography does not work correctly and should not be used in production.

Issues:
- Length mismatch errors during data extraction
- Bit alignment/synchronization problems between hide and extract operations
- Randomization state inconsistencies causing extraction failures

Status: Code preserved for future development, but functionality is broken.

---

This module provides steganographic capabilities for MP3 audio files using
advanced lossy compression-aware techniques. Unlike lossless formats, MP3
steganography must account for psychoacoustic masking and quantization.

Key Features (CURRENTLY BROKEN):
- DCT coefficient manipulation in frequency domain
- Bit reservoir utilization for additional capacity
- Frame header modification techniques
- Psychoacoustic model awareness
- Robust embedding surviving MP3 compression cycles
- Joint stereo mode compatibility

Security Features:
- Password-based coefficient selection
- Secure memory management with SecureBytes
- Steganalysis resistance techniques
- Integration with OpenSSL Encrypt security framework

Author: OpenSSL Encrypt Team
Version: 1.3.0
"""

import struct
import logging
import numpy as np
from typing import Dict, List, Tuple, Any, Optional, Union
import os
import tempfile
from dataclasses import dataclass

# Import secure memory and core steganography components
from ..secure_memory import SecureBytes, secure_memzero
from .stego_core import SteganographyBase, SteganographyError, CapacityError, ExtractionError, CoverMediaError, SteganographyUtils

# Set up module logger
logger = logging.getLogger(__name__)

@dataclass
class MP3FrameHeader:
    """MP3 frame header information"""
    sync_word: int
    version: int
    layer: int
    crc_protection: int
    bitrate_index: int
    sampling_freq_index: int
    padding: int
    private: int
    mode: int
    mode_ext: int
    copyright: int
    original: int
    emphasis: int
    bitrate: int
    sample_rate: int
    frame_size: int
    samples_per_frame: int

class MP3Steganography(SteganographyBase):
    """
    ⚠️  **DISABLED - DO NOT USE** ⚠️
    
    MP3 steganography implementation - CURRENTLY BROKEN
    
    This class is disabled due to algorithmic issues and should not be used.
    All methods will raise NotImplementedError to prevent accidental usage.
    
    Issues: Length mismatch errors, bit alignment problems, randomization sync failures.
    Status: Code preserved for future development.
    """
    
    # MP3 constants
    BITRATES = {
        'MPEG1_L3': [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0],
        'MPEG2_L3': [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0],
    }
    
    SAMPLE_RATES = {
        'MPEG1': [44100, 48000, 32000, 0],
        'MPEG2': [22050, 24000, 16000, 0],
        'MPEG2.5': [11025, 12000, 8000, 0],
    }
    
    SAMPLES_PER_FRAME = {
        'MPEG1_L3': 1152,
        'MPEG2_L3': 576,
        'MPEG2.5_L3': 576,
    }
    
    def __init__(self, password: Optional[str] = None, security_level: int = 1,
                 coefficient_bits: int = 1, use_bit_reservoir: bool = True,
                 preserve_quality: bool = True, config: Optional[Any] = None):
        """
        Initialize MP3 steganography
        
        ⚠️  **DISABLED - DO NOT USE** ⚠️
        This implementation is broken and will raise NotImplementedError.
        
        Args:
            password: Optional password for enhanced security
            security_level: Security level (1-5)
            coefficient_bits: Bits per DCT coefficient to use (1-3)
            use_bit_reservoir: Whether to use bit reservoir for hiding
            preserve_quality: Prioritize audio quality preservation
            config: Optional steganography configuration object
        """
        raise NotImplementedError(
            "MP3 steganography is currently disabled due to algorithmic issues. "
            "The hide/extract cycle fails with length mismatch errors and bit alignment problems. "
            "Use WAV, FLAC, or other working audio formats instead."
        )
        
        super().__init__(password, security_level)
        
        # MP3-specific parameters
        self.coefficient_bits = max(1, min(coefficient_bits, 3))
        self.use_bit_reservoir = use_bit_reservoir
        self.preserve_quality = preserve_quality
        
        # Configuration
        if config:
            self.coefficient_bits = getattr(config, 'coefficient_bits', self.coefficient_bits)
            self.use_bit_reservoir = getattr(config, 'use_bit_reservoir', self.use_bit_reservoir)
            self.preserve_quality = getattr(config, 'preserve_quality', self.preserve_quality)
        
        logger.debug(f"MP3 steganography initialized: {self.coefficient_bits} coeff bits, "
                    f"reservoir={self.use_bit_reservoir}, quality={self.preserve_quality}")
    
    def calculate_capacity(self, mp3_data: bytes) -> int:
        """
        Calculate steganographic capacity of MP3 file
        
        Args:
            mp3_data: MP3 audio file data
            
        Returns:
            Maximum capacity in bytes
        """
        try:
            # Use SecureBytes for data protection
            secure_mp3_data = SecureBytes(mp3_data)
            
            # Analyze MP3 structure
            mp3_info = self._analyze_mp3_structure(secure_mp3_data)
            
            # Calculate capacity from frames and bit reservoir
            frame_capacity = self._calculate_frame_capacity(mp3_info)
            reservoir_capacity = self._calculate_reservoir_capacity(mp3_info) if self.use_bit_reservoir else 0
            
            total_capacity = frame_capacity + reservoir_capacity
            
            # Account for metadata overhead (length + end marker)
            metadata_overhead = 6  # 4 bytes length + 2 bytes end marker
            usable_capacity = max(0, total_capacity - metadata_overhead)
            
            logger.debug(f"MP3 capacity: {usable_capacity} bytes "
                        f"(frames: {frame_capacity}, reservoir: {reservoir_capacity})")
            
            return usable_capacity
            
        except Exception as e:
            logger.error(f"MP3 capacity calculation failed: {e}")
            raise CapacityError(f"Cannot calculate MP3 capacity: {e}")
    
    def hide_data(self, mp3_data: bytes, secret_data: bytes) -> bytes:
        """
        Hide secret data in MP3 file
        
        Args:
            mp3_data: Cover MP3 data
            secret_data: Secret data to hide
            
        Returns:
            Steganographic MP3 data
        """
        # Use SecureBytes for data protection
        secure_cover_data = SecureBytes(mp3_data)
        secure_secret_data = SecureBytes(secret_data)
        
        try:
            # Check capacity
            capacity = self.calculate_capacity(secure_cover_data)
            if len(secret_data) > capacity:
                raise CapacityError(f"Secret data too large: {len(secret_data)} > {capacity}")
            
            # Analyze MP3 structure
            mp3_info = self._analyze_mp3_structure(secure_cover_data)
            
            # Parse MP3 frames
            frames = self._parse_mp3_frames(secure_cover_data)
            
            # Hide data using hybrid approach (DCT + bit reservoir)
            logger.debug("Hiding data in MP3 using DCT coefficient modification")
            modified_frames = self._hide_in_mp3_frames(frames, secure_secret_data, mp3_info)
            
            # Reconstruct MP3 file
            stego_mp3 = self._reconstruct_mp3_file(modified_frames, mp3_info)
            
            logger.info(f"Successfully hid {len(secret_data)} bytes in MP3")
            return bytes(stego_mp3)
            
        except Exception as e:
            logger.error(f"MP3 hiding failed: {e}")
            raise SteganographyError(f"MP3 steganography failed: {e}")
        finally:
            # Secure cleanup
            try:
                secure_memzero(secure_cover_data)
                secure_memzero(secure_secret_data)
            except:
                pass
    
    def extract_data(self, stego_data: bytes) -> bytes:
        """
        Extract secret data from steganographic MP3 file
        
        Args:
            stego_data: Steganographic MP3 data
            
        Returns:
            Extracted secret data
        """
        # Use SecureBytes for data protection
        secure_stego_data = SecureBytes(stego_data)
        
        try:
            # Analyze MP3 structure
            mp3_info = self._analyze_mp3_structure(secure_stego_data)
            
            # Parse MP3 frames
            frames = self._parse_mp3_frames(secure_stego_data)
            
            # Extract data from frames
            logger.debug("Extracting data from MP3 DCT coefficients")
            extracted_data = self._extract_from_mp3_frames(frames, mp3_info)
            
            logger.debug(f"Extracted {len(extracted_data)} bytes from MP3")
            return bytes(extracted_data)
            
        except Exception as e:
            logger.error(f"MP3 extraction failed: {e}")
            raise ExtractionError(f"MP3 extraction failed: {e}")
        finally:
            # Secure cleanup
            try:
                secure_memzero(secure_stego_data)
            except:
                pass
    
    def _analyze_mp3_structure(self, mp3_data: bytes) -> Dict[str, Any]:
        """Analyze MP3 file structure"""
        try:
            analysis = {
                'file_size': len(mp3_data),
                'frames': [],
                'total_frames': 0,
                'duration_seconds': 0.0,
                'bitrate': 0,
                'sample_rate': 0,
                'mode': 'unknown',
                'version': 'unknown',
                'has_id3v2': False,
                'has_id3v1': False,
                'audio_offset': 0,
                'audio_size': len(mp3_data)
            }
            
            # Check for ID3v2 tag
            if len(mp3_data) > 10 and mp3_data[:3] == b'ID3':
                # Parse ID3v2 header
                version_major = mp3_data[3]
                version_minor = mp3_data[4]
                flags = mp3_data[5]
                
                # Calculate tag size (synchsafe integer)
                tag_size = ((mp3_data[6] & 0x7F) << 21) | ((mp3_data[7] & 0x7F) << 14) | \
                          ((mp3_data[8] & 0x7F) << 7) | (mp3_data[9] & 0x7F)
                
                analysis['has_id3v2'] = True
                analysis['audio_offset'] = 10 + tag_size
                analysis['audio_size'] = len(mp3_data) - analysis['audio_offset']
                
                logger.debug(f"Found ID3v2.{version_major}.{version_minor} tag, size: {tag_size}")
            
            # Check for ID3v1 tag
            if len(mp3_data) >= 128 and mp3_data[-128:-125] == b'TAG':
                analysis['has_id3v1'] = True
                analysis['audio_size'] -= 128
                logger.debug("Found ID3v1 tag")
            
            # Find first MP3 frame
            frame_start = self._find_first_mp3_frame(mp3_data, analysis['audio_offset'])
            if frame_start != -1:
                analysis['first_frame_offset'] = frame_start
                
                # Parse first frame header for global info
                if frame_start + 4 <= len(mp3_data):
                    header = self._parse_frame_header(mp3_data[frame_start:frame_start+4])
                    if header:
                        analysis['bitrate'] = header.bitrate
                        analysis['sample_rate'] = header.sample_rate
                        analysis['version'] = self._get_version_string(header.version)
                        analysis['mode'] = self._get_mode_string(header.mode)
                        
                        # Estimate duration
                        if header.bitrate > 0:
                            audio_bytes = analysis['audio_size'] - (frame_start - analysis['audio_offset'])
                            analysis['duration_seconds'] = (audio_bytes * 8) / header.bitrate
            
            logger.debug(f"MP3 analysis: {analysis['bitrate']} kbps, "
                        f"{analysis['sample_rate']} Hz, {analysis['version']}")
            
            return analysis
            
        except Exception as e:
            logger.error(f"MP3 structure analysis failed: {e}")
            raise CoverMediaError(f"Invalid MP3 structure: {e}")
    
    def _parse_mp3_frames(self, mp3_data: bytes) -> List[Dict[str, Any]]:
        """Parse MP3 frames from audio data"""
        frames = []
        offset = self._find_first_mp3_frame(mp3_data, 0)
        
        while offset < len(mp3_data) - 4:
            try:
                # Parse frame header
                header_bytes = mp3_data[offset:offset+4]
                header = self._parse_frame_header(header_bytes)
                
                if not header or header.frame_size <= 0:
                    offset += 1
                    continue
                
                # Extract frame data
                frame_end = offset + header.frame_size
                if frame_end > len(mp3_data):
                    break
                
                frame_data = mp3_data[offset:frame_end]
                
                frame_info = {
                    'offset': offset,
                    'header': header,
                    'data': frame_data,
                    'payload': frame_data[4:],  # Skip 4-byte header
                    'size': header.frame_size
                }
                
                frames.append(frame_info)
                offset = frame_end
                
            except Exception as e:
                logger.warning(f"Error parsing frame at offset {offset}: {e}")
                offset += 1
        
        logger.debug(f"Parsed {len(frames)} MP3 frames")
        return frames
    
    def _parse_frame_header(self, header_bytes: bytes) -> Optional[MP3FrameHeader]:
        """Parse MP3 frame header"""
        if len(header_bytes) < 4:
            return None
        
        try:
            # Convert to 32-bit integer
            header_int = struct.unpack('>I', header_bytes)[0]
            
            # Extract fields
            sync_word = (header_int >> 21) & 0x7FF
            if sync_word != 0x7FF:  # Invalid sync word
                return None
            
            version = (header_int >> 19) & 0x3
            layer = (header_int >> 17) & 0x3
            crc_protection = (header_int >> 16) & 0x1
            bitrate_index = (header_int >> 12) & 0xF
            sampling_freq_index = (header_int >> 10) & 0x3
            padding = (header_int >> 9) & 0x1
            private = (header_int >> 8) & 0x1
            mode = (header_int >> 6) & 0x3
            mode_ext = (header_int >> 4) & 0x3
            copyright = (header_int >> 3) & 0x1
            original = (header_int >> 2) & 0x1
            emphasis = header_int & 0x3
            
            # Calculate derived values
            if version == 3:  # MPEG1
                version_key = 'MPEG1'
            elif version == 2:  # MPEG2
                version_key = 'MPEG2'
            elif version == 0:  # MPEG2.5
                version_key = 'MPEG2.5'
            else:
                return None
            
            if layer != 1:  # Not Layer III (MP3)
                return None
            
            # Get bitrate
            bitrate_key = f"{version_key}_L3"
            if bitrate_index >= len(self.BITRATES.get(bitrate_key, [])):
                return None
            bitrate = self.BITRATES[bitrate_key][bitrate_index]
            
            # Get sample rate
            if sampling_freq_index >= len(self.SAMPLE_RATES.get(version_key, [])):
                return None
            sample_rate = self.SAMPLE_RATES[version_key][sampling_freq_index]
            
            if bitrate == 0 or sample_rate == 0:
                return None
            
            # Calculate frame size
            samples_per_frame = self.SAMPLES_PER_FRAME.get(f"{version_key}_L3", 1152)
            frame_size = int((samples_per_frame / 8 * bitrate * 1000) / sample_rate) + padding
            
            return MP3FrameHeader(
                sync_word=sync_word,
                version=version,
                layer=layer,
                crc_protection=crc_protection,
                bitrate_index=bitrate_index,
                sampling_freq_index=sampling_freq_index,
                padding=padding,
                private=private,
                mode=mode,
                mode_ext=mode_ext,
                copyright=copyright,
                original=original,
                emphasis=emphasis,
                bitrate=bitrate,
                sample_rate=sample_rate,
                frame_size=frame_size,
                samples_per_frame=samples_per_frame
            )
            
        except Exception as e:
            logger.warning(f"Frame header parsing failed: {e}")
            return None
    
    def _find_first_mp3_frame(self, mp3_data: bytes, start_offset: int = 0) -> int:
        """Find the first valid MP3 frame header"""
        for i in range(start_offset, len(mp3_data) - 4):
            if mp3_data[i] == 0xFF and (mp3_data[i+1] & 0xE0) == 0xE0:
                # Potential sync word found
                header = self._parse_frame_header(mp3_data[i:i+4])
                if header:
                    return i
        return -1
    
    def _calculate_frame_capacity(self, mp3_info: Dict[str, Any]) -> int:
        """Calculate capacity from DCT coefficient modification"""
        # Estimate based on typical MP3 structure
        # Each frame has ~576 or 1152 granules with frequency coefficients
        
        audio_size = mp3_info['audio_size']
        bitrate = mp3_info.get('bitrate', 128)
        duration = mp3_info.get('duration_seconds', 1.0)
        
        # More realistic estimate: each second of audio provides capacity
        # based on the number of frames and coefficients per frame
        frames_per_second = 38.28  # ~38.28 frames per second for 44.1kHz MP3
        estimated_frames = duration * frames_per_second
        
        # Each frame can hide data in multiple coefficient locations
        coefficients_per_frame = min(200, bitrate // 4)  # Scale with bitrate
        total_coefficients = int(estimated_frames * coefficients_per_frame)
        
        # Bits available for steganography
        total_bits = total_coefficients * self.coefficient_bits
        
        # Convert to bytes
        capacity_bytes = total_bits // 8
        
        # Apply quality preservation factor (less aggressive reduction)
        if self.preserve_quality:
            capacity_bytes = int(capacity_bytes * 0.7)  # Use 70% for quality
        
        return max(0, capacity_bytes)
    
    def _calculate_reservoir_capacity(self, mp3_info: Dict[str, Any]) -> int:
        """Calculate capacity from bit reservoir usage"""
        if not self.use_bit_reservoir:
            return 0
        
        # Bit reservoir provides additional capacity
        # Typically 7680 bits maximum per frame
        audio_size = mp3_info['audio_size']
        frame_size_avg = 144000 if mp3_info.get('bitrate', 128) else 1152  # Rough estimate
        
        if frame_size_avg > 0:
            estimated_frames = audio_size // frame_size_avg
            # Conservative: 100 bits per frame from reservoir
            reservoir_bits = estimated_frames * 100
            return reservoir_bits // 8
        
        return 0
    
    def _hide_in_mp3_frames(self, frames: List[Dict[str, Any]], secret_data: bytes, 
                           mp3_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Hide data in MP3 frames using DCT coefficient modification"""
        try:
            # Prepare data for hiding (length + data + end marker)
            data_length = len(secret_data)
            length_bytes = struct.pack('<I', data_length)
            payload = length_bytes + secret_data + b'\xFF\xFE'  # End marker
            
            # Convert to binary representation
            binary_data = SteganographyUtils.bytes_to_binary(payload)
            
            # Initialize hiding state
            bit_index = 0
            modified_frames = []
            bits_per_coefficient = self.coefficient_bits
            
            # Set up coefficient selection based on password
            if self.password:
                np.random.seed(hash(self.password) & 0xFFFFFFFF)
            
            for frame in frames:
                try:
                    modified_frame = frame.copy()
                    frame_payload = bytearray(frame['payload'])
                    
                    if bit_index >= len(binary_data):
                        # No more data to hide
                        modified_frames.append(modified_frame)
                        continue
                    
                    # Simulate DCT coefficient access
                    # In a full implementation, this would decode the Huffman-coded
                    # spectral data and modify actual DCT coefficients
                    
                    # For this implementation, we'll modify selected bytes that
                    # represent quantized coefficients in the bit stream
                    coefficients_available = min(len(frame_payload) // 4, 200)  # Conservative
                    
                    # Generate coefficient indices for this frame
                    coeff_indices = list(range(coefficients_available))
                    if self.password:
                        np.random.shuffle(coeff_indices)
                    
                    for coeff_idx in coeff_indices:
                        if bit_index >= len(binary_data):
                            break
                        
                        # Calculate byte position in frame payload
                        byte_pos = (coeff_idx * 4) % len(frame_payload)
                        if byte_pos >= len(frame_payload):
                            continue
                        
                        # Modify coefficient bits
                        original_byte = frame_payload[byte_pos]
                        
                        # Extract bits to hide
                        bits_to_hide = 0
                        for b in range(bits_per_coefficient):
                            if bit_index < len(binary_data):
                                if binary_data[bit_index] == '1':
                                    bits_to_hide |= (1 << b)
                                bit_index += 1
                        
                        # Modify the byte (preserve upper bits for quality)
                        mask = (1 << bits_per_coefficient) - 1
                        modified_byte = (original_byte & ~mask) | (bits_to_hide & mask)
                        frame_payload[byte_pos] = modified_byte
                    
                    modified_frame['payload'] = bytes(frame_payload)
                    modified_frame['data'] = frame['data'][:4] + modified_frame['payload']
                    modified_frames.append(modified_frame)
                    
                except Exception as e:
                    logger.warning(f"Error modifying frame: {e}")
                    modified_frames.append(frame)
            
            # Secure cleanup
            binary_data.clear() if hasattr(binary_data, 'clear') else None
            
            logger.debug(f"Modified {len(modified_frames)} frames, embedded {bit_index} bits")
            return modified_frames
            
        except Exception as e:
            logger.error(f"Frame modification failed: {e}")
            raise SteganographyError(f"Frame modification failed: {e}")
    
    def _extract_from_mp3_frames(self, frames: List[Dict[str, Any]], 
                                mp3_info: Dict[str, Any]) -> bytes:
        """Extract data from MP3 frames"""
        try:
            # Initialize extraction state
            extracted_bits = []
            bits_per_coefficient = self.coefficient_bits
            
            # Set up coefficient selection based on password
            if self.password:
                np.random.seed(hash(self.password) & 0xFFFFFFFF)
            
            # Do extraction in single pass to avoid randomization sync issues
            # First, estimate how much data we might need (we'll extract length as we go)
            max_reasonable_bits = 32 + (1024 * 1024 * 8) + 16  # 1MB max + overhead
            
            for frame in frames:
                frame_payload = frame['payload']
                coefficients_available = min(len(frame_payload) // 4, 200)
                
                coeff_indices = list(range(coefficients_available))
                if self.password:
                    np.random.shuffle(coeff_indices)
                
                for coeff_idx in coeff_indices:
                    # Check if we have enough for length extraction
                    if len(extracted_bits) == 32:
                        # We have the length, calculate total needed
                        data_length = 0
                        for i in range(32):
                            data_length |= (extracted_bits[i] << i)
                        
                        if data_length <= 0 or data_length > 10 * 1024 * 1024:
                            raise ExtractionError("Invalid data length")
                        
                        # Set the actual total bits needed
                        total_bits_needed = 32 + (data_length * 8) + 16
                    
                    # Check if we have everything we need
                    if len(extracted_bits) >= 32:  # Only check this after we have length
                        # Re-calculate data_length from current bits if needed
                        if 'total_bits_needed' not in locals():
                            temp_length = 0
                            for i in range(32):
                                temp_length |= (extracted_bits[i] << i)
                            total_bits_needed = 32 + (temp_length * 8) + 16
                        
                        if len(extracted_bits) >= total_bits_needed:
                            break
                    
                    byte_pos = (coeff_idx * 4) % len(frame_payload)
                    if byte_pos >= len(frame_payload):
                        continue
                    
                    byte_val = frame_payload[byte_pos]
                    mask = (1 << bits_per_coefficient) - 1
                    coeff_bits = byte_val & mask
                    
                    for b in range(bits_per_coefficient):
                        if 'total_bits_needed' in locals() and len(extracted_bits) >= total_bits_needed:
                            break
                        extracted_bits.append((coeff_bits >> b) & 1)
                
                # Check if we're done after this frame
                if 'total_bits_needed' in locals() and len(extracted_bits) >= total_bits_needed:
                    break
            
            # Final validation
            if len(extracted_bits) < 32:
                raise ExtractionError("Could not extract data length")
            
            # Get data length from extracted bits
            data_length = 0
            for i in range(32):
                data_length |= (extracted_bits[i] << i)
            
            if data_length <= 0 or data_length > 10 * 1024 * 1024:
                raise ExtractionError("Invalid data length")
            
            total_bits_needed = 32 + (data_length * 8) + 16
            
            if len(extracted_bits) < total_bits_needed:
                raise ExtractionError("Insufficient data extracted")
            
            # Convert bits to bytes
            binary_string = ''.join(str(bit) for bit in extracted_bits)
            extracted_bytes = SteganographyUtils.binary_to_bytes(binary_string)
            
            # Verify and extract payload
            if len(extracted_bytes) < 4:
                raise ExtractionError("Extracted data too short")
            
            extracted_length = struct.unpack('<I', extracted_bytes[:4])[0]
            if extracted_length != data_length:
                raise ExtractionError("Length mismatch in extracted data")
            
            payload = extracted_bytes[4:4+data_length]
            
            logger.debug(f"Successfully extracted {len(payload)} bytes from MP3")
            return payload
            
        except Exception as e:
            logger.error(f"MP3 extraction failed: {e}")
            raise ExtractionError(f"MP3 extraction failed: {e}")
    
    def _reconstruct_mp3_file(self, frames: List[Dict[str, Any]], 
                             mp3_info: Dict[str, Any]) -> bytes:
        """Reconstruct MP3 file from modified frames"""
        try:
            mp3_data = bytearray()
            
            # Add any ID3v2 tag that was present
            # (This would require storing the original tag data)
            
            # Add all frames
            for frame in frames:
                mp3_data.extend(frame['data'])
            
            # Add any ID3v1 tag that was present
            # (This would require storing the original tag data)
            
            return bytes(mp3_data)
            
        except Exception as e:
            logger.error(f"MP3 reconstruction failed: {e}")
            raise SteganographyError(f"MP3 reconstruction failed: {e}")
    
    def _get_version_string(self, version: int) -> str:
        """Get version string from version field"""
        version_map = {3: 'MPEG1', 2: 'MPEG2', 0: 'MPEG2.5', 1: 'Reserved'}
        return version_map.get(version, 'Unknown')
    
    def _get_mode_string(self, mode: int) -> str:
        """Get mode string from mode field"""
        mode_map = {0: 'Stereo', 1: 'Joint Stereo', 2: 'Dual Channel', 3: 'Mono'}
        return mode_map.get(mode, 'Unknown')


class MP3Analyzer:
    """
    MP3 analysis tool for steganographic suitability assessment
    
    Provides detailed analysis of MP3 files to determine optimal
    steganographic parameters and capacity estimates.
    """
    
    def __init__(self):
        """Initialize MP3 analyzer"""
        self.logger = logging.getLogger(__name__ + '.MP3Analyzer')
    
    def analyze_mp3_structure(self, mp3_data: bytes) -> Dict[str, Any]:
        """
        Comprehensive MP3 structure analysis
        
        Args:
            mp3_data: MP3 file data
            
        Returns:
            Analysis results dictionary
        """
        try:
            # Create temporary MP3 steganography instance for analysis
            mp3_stego = MP3Steganography()
            
            # Basic structure analysis
            basic_info = mp3_stego._analyze_mp3_structure(mp3_data)
            
            # Parse frames for detailed analysis
            frames = mp3_stego._parse_mp3_frames(mp3_data)
            
            # Calculate capacities
            frame_capacity = mp3_stego._calculate_frame_capacity(basic_info)
            reservoir_capacity = mp3_stego._calculate_reservoir_capacity(basic_info)
            
            analysis = {
                'valid': len(frames) > 0,
                'file_size': len(mp3_data),
                'audio': {
                    'duration_seconds': basic_info.get('duration_seconds', 0),
                    'bitrate': basic_info.get('bitrate', 0),
                    'sample_rate': basic_info.get('sample_rate', 0),
                    'mode': basic_info.get('mode', 'unknown'),
                    'version': basic_info.get('version', 'unknown'),
                },
                'frames': {
                    'total_frames': len(frames),
                    'avg_frame_size': sum(f['size'] for f in frames) // max(len(frames), 1),
                    'first_frame_offset': basic_info.get('first_frame_offset', 0),
                },
                'tags': {
                    'has_id3v2': basic_info.get('has_id3v2', False),
                    'has_id3v1': basic_info.get('has_id3v1', False),
                },
                'steganography': {
                    'suitable': len(frames) > 0 and basic_info.get('bitrate', 0) >= 96,
                    'frame_capacity': frame_capacity,
                    'reservoir_capacity': reservoir_capacity,
                    'total_capacity': frame_capacity + reservoir_capacity,
                    'quality_impact': 'Low' if basic_info.get('bitrate', 0) >= 192 else 'Medium',
                    'recommended_coefficient_bits': 1 if basic_info.get('bitrate', 0) < 192 else 2,
                }
            }
            
            self.logger.debug(f"MP3 analysis complete: {analysis['steganography']['total_capacity']} bytes capacity")
            return analysis
            
        except Exception as e:
            self.logger.error(f"MP3 analysis failed: {e}")
            return {
                'valid': False,
                'error': str(e),
                'steganography': {'suitable': False, 'total_capacity': 0}
            }


def create_mp3_test_audio(duration_seconds: float = 5.0, bitrate: int = 128,
                         sample_rate: int = 44100, mode: str = 'stereo') -> bytes:
    """
    Create a test MP3 audio file for steganography testing
    
    Args:
        duration_seconds: Duration of audio in seconds
        bitrate: MP3 bitrate in kbps (96, 128, 192, 256, 320)
        sample_rate: Audio sample rate (44100, 48000, 32000)
        mode: Audio mode ('stereo', 'mono', 'joint_stereo')
        
    Returns:
        MP3 audio data as bytes
        
    Note: This creates a synthetic MP3-like file for testing.
    In production, you'd use a proper MP3 encoder library.
    """
    try:
        # Create a synthetic MP3 file structure for testing
        # This is a simplified implementation for demonstration
        
        mp3_data = bytearray()
        
        # Calculate frame parameters
        samples_per_frame = 1152
        frames_needed = int((duration_seconds * sample_rate) / samples_per_frame)
        
        # Mode mapping
        mode_map = {'stereo': 0, 'joint_stereo': 1, 'dual_channel': 2, 'mono': 3}
        mode_val = mode_map.get(mode, 0)
        
        # Bitrate and sample rate indices
        bitrate_map = {96: 5, 128: 9, 192: 11, 256: 13, 320: 14}
        samplerate_map = {44100: 0, 48000: 1, 32000: 2}
        
        bitrate_idx = bitrate_map.get(bitrate, 9)
        samplerate_idx = samplerate_map.get(sample_rate, 0)
        
        # Calculate frame size (correct MP3 formula)
        frame_size = int((samples_per_frame * bitrate * 1000) / (8 * sample_rate))
        frame_size = max(frame_size, 64)  # Minimum realistic frame size
        
        for frame_idx in range(frames_needed):
            # Create frame header
            sync_word = 0x7FF
            version = 3  # MPEG1
            layer = 1    # Layer III
            crc_protection = 1  # No CRC
            padding = 0
            private = 0
            copyright = 0
            original = 1
            emphasis = 0
            
            header = (sync_word << 21) | (version << 19) | (layer << 17) | \
                    (crc_protection << 16) | (bitrate_idx << 12) | \
                    (samplerate_idx << 10) | (padding << 9) | (private << 8) | \
                    (mode_val << 6) | (0 << 4) | (copyright << 3) | \
                    (original << 2) | emphasis
            
            # Add frame header
            mp3_data.extend(struct.pack('>I', header))
            
            # Add frame payload (simplified)
            payload_size = frame_size - 4
            for i in range(payload_size):
                # Create synthetic audio-like data
                value = (frame_idx * 17 + i * 23) % 256
                mp3_data.append(value)
        
        logger.debug(f"Created synthetic MP3: {len(mp3_data)} bytes, {duration_seconds}s, {bitrate} kbps")
        return bytes(mp3_data)
        
    except Exception as e:
        logger.error(f"Test MP3 creation failed: {e}")
        raise SteganographyError(f"Failed to create test MP3: {e}")


def is_mp3_steganography_available() -> bool:
    """Check if MP3 steganography dependencies are available"""
    try:
        import numpy as np
        import struct
        
        # Test basic functionality needed for MP3 steganography
        test_array = np.array([1, 2, 3, 4], dtype=np.int16)
        test_binary = '10101010'
        test_header = struct.pack('>I', 0xFFFBD000)  # Sample MP3 header
        
        return True
    except Exception as e:
        logger.warning(f"MP3 steganography not available: {e}")
        return False


if __name__ == "__main__":
    # Simple test
    if is_mp3_steganography_available():
        print("MP3 steganography is available")
        
        # Create test MP3
        test_mp3 = create_mp3_test_audio(duration_seconds=2.0, bitrate=128)
        print(f"Created test MP3: {len(test_mp3)} bytes")
        
        # Test steganography
        mp3_stego = MP3Steganography(password="test123")
        
        capacity = mp3_stego.calculate_capacity(test_mp3)
        print(f"MP3 capacity: {capacity} bytes")
        
        if capacity > 20:
            test_data = b"MP3 steganography test!"
            print(f"Hiding {len(test_data)} bytes...")
            
            stego_mp3 = mp3_stego.hide_data(test_mp3, test_data)
            print(f"Created steganographic MP3: {len(stego_mp3)} bytes")
            
            extracted = mp3_stego.extract_data(stego_mp3)
            print(f"Extracted: {extracted}")
            print(f"Match: {extracted == test_data}")
    else:
        print("MP3 steganography is not available")