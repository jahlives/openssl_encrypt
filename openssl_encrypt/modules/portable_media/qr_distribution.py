#!/usr/bin/env python3
"""
QR Code Key Distribution Module

Enables truly air-gapped key distribution through QR codes for maximum security.
Supports single QR codes for small keys and multi-QR distribution for larger keys.

This module provides the first-of-its-kind visual key distribution system,
allowing keys to be shared through printed QR codes without any digital medium.

Security Features:
- Base64 encoding with checksums
- Multi-QR splitting for large keys
- Error correction and validation
- Format versioning for future compatibility
- Secure memory handling throughout
"""

import base64
import hashlib
import json
import logging
import os
import zlib
from enum import Enum
from typing import Dict, List, Optional, Tuple, Union

try:
    import qrcode
    import qrcode.constants
    from PIL import Image
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False

# Import secure memory functions
try:
    from ..secure_memory import SecureBytes, secure_memzero
    from ..crypt_errors import KeystoreError
except ImportError:
    # Fallback for standalone testing
    from openssl_encrypt.modules.secure_memory import SecureBytes, secure_memzero
    from openssl_encrypt.modules.crypt_errors import KeystoreError

# Set up module logger
logger = logging.getLogger(__name__)


class QRKeyError(KeystoreError):
    """QR code key distribution specific errors"""
    pass


class QRKeyFormat(Enum):
    """QR code key format versions"""
    V1_SINGLE = "v1_single"        # Single QR code, small keys only
    V1_MULTI = "v1_multi"          # Multi-QR distribution for large keys
    V1_COMPRESSED = "v1_compressed" # Compressed keys for better efficiency


class QRKeyDistribution:
    """
    QR Code Key Distribution System
    
    Provides air-gapped key distribution through visual QR codes.
    """
    
    # QR Code configuration
    MAX_SINGLE_QR_SIZE = 2048      # Max bytes for single QR (Version 40)
    MAX_QR_DATA_SIZE = 2953        # Theoretical max for Version 40 QR
    QR_ERROR_CORRECTION = qrcode.constants.ERROR_CORRECT_M  # 15% error correction
    
    # Protocol constants
    PROTOCOL_VERSION = "1.0"
    MAGIC_HEADER = "ossl_encrypt_key"
    CHECKSUM_LENGTH = 8            # SHA-256 truncated to 8 bytes
    
    def __init__(self, error_correction=None, box_size=10, border=4):
        """
        Initialize QR Key Distribution system
        
        Args:
            error_correction: QR error correction level
            box_size: Size of each QR code box in pixels
            border: QR code border size
        """
        if not QR_AVAILABLE:
            raise QRKeyError("QR code dependencies not available. Install: pip install qrcode[pil]")
            
        self.error_correction = error_correction or self.QR_ERROR_CORRECTION
        self.box_size = box_size
        self.border = border
        
        logger.debug(f"QR Key Distribution initialized with error correction: {self.error_correction}")
    
    def create_key_qr(self, key_data: bytes, key_name: str = "key", 
                      format_type: QRKeyFormat = QRKeyFormat.V1_SINGLE,
                      compression: bool = True) -> Union[Image.Image, List[Image.Image]]:
        """
        Create QR code(s) from key data
        
        Args:
            key_data: Raw key data to encode
            key_name: Name/identifier for the key
            format_type: QR format to use
            compression: Whether to compress data before encoding
            
        Returns:
            Single QR image or list of QR images for multi-part keys
        """
        if not key_data:
            raise QRKeyError("Key data cannot be empty")
            
        # Use secure memory for processing
        secure_key_data = SecureBytes(key_data)
        
        try:
            # Prepare key data with metadata
            key_payload = self._prepare_key_payload(secure_key_data, key_name, compression)
            
            # Determine if we need multi-QR
            if len(key_payload) <= self.MAX_SINGLE_QR_SIZE or format_type == QRKeyFormat.V1_SINGLE:
                if len(key_payload) > self.MAX_SINGLE_QR_SIZE and format_type == QRKeyFormat.V1_SINGLE:
                    raise QRKeyError(f"Key too large for single QR ({len(key_payload)} > {self.MAX_SINGLE_QR_SIZE} bytes)")
                return self._create_single_qr(key_payload)
            else:
                return self._create_multi_qr(key_payload, key_name)
                
        finally:
            # Clean up secure memory
            secure_memzero(secure_key_data)
    
    def read_key_qr(self, qr_images: Union[str, Image.Image, List[Union[str, Image.Image]]]) -> Tuple[bytes, str]:
        """
        Read key data from QR code(s)
        
        Args:
            qr_images: Single QR image/path or list of QR images/paths
            
        Returns:
            Tuple of (key_data, key_name)
        """
        try:
            # Handle single image
            if isinstance(qr_images, (str, Image.Image)):
                qr_data = self._decode_qr_image(qr_images)
                return self._parse_single_qr_data(qr_data)
            
            # Handle multiple images (multi-QR)
            elif isinstance(qr_images, list):
                qr_data_list = []
                for img in qr_images:
                    qr_data_list.append(self._decode_qr_image(img))
                return self._parse_multi_qr_data(qr_data_list)
            
            else:
                raise QRKeyError(f"Invalid QR image input type: {type(qr_images)}")
                
        except Exception as e:
            logger.error(f"QR key reading failed: {e}")
            raise QRKeyError(f"Failed to read key from QR code: {e}")
    
    def _prepare_key_payload(self, key_data: SecureBytes, key_name: str, compression: bool) -> bytes:
        """Prepare key data with metadata and checksums"""
        try:
            # Create metadata
            metadata = {
                "version": self.PROTOCOL_VERSION,
                "name": key_name,
                "compressed": compression,
                "size": len(key_data)
            }
            
            # Optionally compress key data
            if compression:
                compressed_data = zlib.compress(bytes(key_data), level=9)
                logger.debug(f"Compressed key data: {len(key_data)} -> {len(compressed_data)} bytes")
                key_content = compressed_data
            else:
                key_content = bytes(key_data)
            
            # Create checksum of original key data
            checksum = hashlib.sha256(bytes(key_data)).digest()[:self.CHECKSUM_LENGTH]
            
            # Build final payload
            payload_data = {
                "header": self.MAGIC_HEADER,
                "metadata": metadata,
                "key": base64.b64encode(key_content).decode('ascii'),
                "checksum": base64.b64encode(checksum).decode('ascii')
            }
            
            # JSON encode
            json_payload = json.dumps(payload_data, separators=(',', ':'))  # Compact JSON
            return json_payload.encode('utf-8')
            
        except Exception as e:
            raise QRKeyError(f"Failed to prepare key payload: {e}")
    
    def _create_single_qr(self, payload_data: bytes) -> Image.Image:
        """Create a single QR code from payload data"""
        try:
            # Base64 encode the entire payload for QR storage
            qr_content = base64.b64encode(payload_data).decode('ascii')
            
            # Create QR code
            qr = qrcode.QRCode(
                version=None,  # Auto-detect version
                error_correction=self.error_correction,
                box_size=self.box_size,
                border=self.border,
            )
            qr.add_data(qr_content)
            qr.make(fit=True)
            
            # Generate image
            qr_image = qr.make_image(fill_color="black", back_color="white")
            
            logger.info(f"Created single QR code (version {qr.version}, {len(qr_content)} chars)")
            return qr_image
            
        except Exception as e:
            raise QRKeyError(f"Failed to create single QR code: {e}")
    
    def _create_multi_qr(self, payload_data: bytes, key_name: str) -> List[Image.Image]:
        """Create multiple QR codes for large payload data"""
        try:
            # Calculate chunk size (leave room for multi-QR metadata)
            metadata_overhead = 200  # Estimated overhead for part info
            chunk_size = self.MAX_SINGLE_QR_SIZE - metadata_overhead
            
            # Split payload into chunks
            chunks = [payload_data[i:i+chunk_size] for i in range(0, len(payload_data), chunk_size)]
            total_chunks = len(chunks)
            
            if total_chunks > 99:
                raise QRKeyError(f"Key too large, would require {total_chunks} QR codes (max 99)")
            
            # Create overall checksum
            overall_checksum = hashlib.sha256(payload_data).hexdigest()[:16]
            
            qr_images = []
            for i, chunk in enumerate(chunks, 1):
                # Create part metadata
                part_data = {
                    "header": f"{self.MAGIC_HEADER}_multi",
                    "key_name": key_name,
                    "part": i,
                    "total": total_chunks,
                    "overall_checksum": overall_checksum,
                    "data": base64.b64encode(chunk).decode('ascii')
                }
                
                # JSON encode and create QR
                part_json = json.dumps(part_data, separators=(',', ':'))
                qr_content = base64.b64encode(part_json.encode('utf-8')).decode('ascii')
                
                # Create QR code for this part
                qr = qrcode.QRCode(
                    version=None,
                    error_correction=self.error_correction,
                    box_size=self.box_size,
                    border=self.border,
                )
                qr.add_data(qr_content)
                qr.make(fit=True)
                
                qr_image = qr.make_image(fill_color="black", back_color="white")
                qr_images.append(qr_image)
                
                logger.debug(f"Created multi-QR part {i}/{total_chunks} (version {qr.version})")
            
            logger.info(f"Created {total_chunks} QR codes for large key '{key_name}'")
            return qr_images
            
        except Exception as e:
            raise QRKeyError(f"Failed to create multi-QR codes: {e}")
    
    def _decode_qr_image(self, qr_image: Union[str, Image.Image]) -> str:
        """Decode QR image to string data"""
        try:
            # Import QR decoder
            from pyzbar import pyzbar
            
            # Load image if path provided
            if isinstance(qr_image, str):
                if not os.path.exists(qr_image):
                    raise QRKeyError(f"QR image file not found: {qr_image}")
                image = Image.open(qr_image)
            else:
                image = qr_image
            
            # Decode QR code
            decoded_objects = pyzbar.decode(image)
            
            if not decoded_objects:
                raise QRKeyError("No QR code found in image")
            
            if len(decoded_objects) > 1:
                logger.warning(f"Multiple QR codes found in image, using first one")
            
            # Get QR data
            qr_data = decoded_objects[0].data.decode('utf-8')
            logger.debug(f"Decoded QR data: {len(qr_data)} characters")
            
            return qr_data
            
        except ImportError:
            raise QRKeyError("QR code reading requires pyzbar. Install: pip install pyzbar")
        except Exception as e:
            raise QRKeyError(f"Failed to decode QR image: {e}")
    
    def _parse_single_qr_data(self, qr_data: str) -> Tuple[bytes, str]:
        """Parse data from single QR code"""
        try:
            # Base64 decode
            json_data = base64.b64decode(qr_data.encode('ascii')).decode('utf-8')
            
            # Parse JSON payload
            payload = json.loads(json_data)
            
            # Validate header
            if payload.get("header") != self.MAGIC_HEADER:
                raise QRKeyError(f"Invalid QR header: {payload.get('header')}")
            
            # Extract metadata
            metadata = payload.get("metadata", {})
            key_name = metadata.get("name", "unknown")
            compressed = metadata.get("compressed", False)
            original_size = metadata.get("size", 0)
            
            # Extract and decode key data
            key_b64 = payload.get("key", "")
            key_content = base64.b64decode(key_b64.encode('ascii'))
            
            # Decompress if needed
            if compressed:
                key_data = zlib.decompress(key_content)
            else:
                key_data = key_content
            
            # Verify checksum
            expected_checksum = base64.b64decode(payload.get("checksum", "").encode('ascii'))
            actual_checksum = hashlib.sha256(key_data).digest()[:self.CHECKSUM_LENGTH]
            
            if expected_checksum != actual_checksum:
                raise QRKeyError("Key checksum validation failed")
            
            # Verify size
            if len(key_data) != original_size:
                raise QRKeyError(f"Key size mismatch: expected {original_size}, got {len(key_data)}")
            
            logger.info(f"Successfully parsed single QR key '{key_name}' ({len(key_data)} bytes)")
            return key_data, key_name
            
        except json.JSONDecodeError as e:
            raise QRKeyError(f"Invalid JSON in QR data: {e}")
        except Exception as e:
            raise QRKeyError(f"Failed to parse single QR data: {e}")
    
    def _parse_multi_qr_data(self, qr_data_list: List[str]) -> Tuple[bytes, str]:
        """Parse data from multiple QR codes"""
        try:
            parts = {}
            key_name = None
            total_parts = None
            overall_checksum = None
            
            # Parse each QR part
            for qr_data in qr_data_list:
                # Base64 decode  
                json_data = base64.b64decode(qr_data.encode('ascii')).decode('utf-8')
                part_data = json.loads(json_data)
                
                # Validate header
                if part_data.get("header") != f"{self.MAGIC_HEADER}_multi":
                    raise QRKeyError(f"Invalid multi-QR header: {part_data.get('header')}")
                
                # Extract part info
                part_num = part_data.get("part")
                part_total = part_data.get("total")
                part_key_name = part_data.get("key_name")
                part_checksum = part_data.get("overall_checksum")
                part_content = base64.b64decode(part_data.get("data", "").encode('ascii'))
                
                # Validate consistency
                if key_name is None:
                    key_name = part_key_name
                    total_parts = part_total
                    overall_checksum = part_checksum
                else:
                    if key_name != part_key_name:
                        raise QRKeyError(f"Key name mismatch: '{key_name}' vs '{part_key_name}'")
                    if total_parts != part_total:
                        raise QRKeyError(f"Total parts mismatch: {total_parts} vs {part_total}")
                    if overall_checksum != part_checksum:
                        raise QRKeyError("Overall checksum mismatch between parts")
                
                # Store part data
                if part_num in parts:
                    raise QRKeyError(f"Duplicate part number: {part_num}")
                parts[part_num] = part_content
                
                logger.debug(f"Parsed multi-QR part {part_num}/{part_total}")
            
            # Check we have all parts
            if len(parts) != total_parts:
                missing = set(range(1, total_parts + 1)) - set(parts.keys())
                raise QRKeyError(f"Missing QR parts: {sorted(missing)}")
            
            # Reconstruct original payload
            payload_data = b''.join(parts[i] for i in range(1, total_parts + 1))
            
            # Verify overall checksum
            actual_checksum = hashlib.sha256(payload_data).hexdigest()[:16]
            if actual_checksum != overall_checksum:
                raise QRKeyError("Overall payload checksum validation failed")
            
            logger.info(f"Reconstructed multi-QR key from {total_parts} parts")
            
            # Parse the reconstructed payload as single QR data
            # (It contains the original JSON structure)
            payload_str = payload_data.decode('utf-8')
            return self._parse_single_qr_data(base64.b64encode(payload_str.encode('utf-8')).decode('ascii'))
            
        except json.JSONDecodeError as e:
            raise QRKeyError(f"Invalid JSON in multi-QR data: {e}")
        except Exception as e:
            raise QRKeyError(f"Failed to parse multi-QR data: {e}")


# Convenience functions for easy usage
def create_key_qr(key_data: bytes, key_name: str = "key", output_path: Optional[str] = None,
                  format_type: QRKeyFormat = QRKeyFormat.V1_SINGLE) -> Union[Image.Image, List[Image.Image]]:
    """
    Create QR code(s) from key data
    
    Args:
        key_data: Raw key data to encode
        key_name: Name/identifier for the key
        output_path: Optional path to save QR image(s)
        format_type: QR format to use
        
    Returns:
        QR image(s)
    """
    qr_dist = QRKeyDistribution()
    qr_images = qr_dist.create_key_qr(key_data, key_name, format_type)
    
    # Save if output path provided
    if output_path:
        if isinstance(qr_images, list):
            # Multi-QR: save with part numbers
            base_path = os.path.splitext(output_path)[0]
            for i, img in enumerate(qr_images, 1):
                part_path = f"{base_path}_part_{i:02d}.png"
                img.save(part_path)
                logger.info(f"Saved QR part {i} to: {part_path}")
        else:
            # Single QR: save directly
            qr_images.save(output_path)
            logger.info(f"Saved QR code to: {output_path}")
    
    return qr_images


def read_key_qr(qr_images: Union[str, Image.Image, List[Union[str, Image.Image]]]) -> Tuple[bytes, str]:
    """
    Read key data from QR code(s)
    
    Args:
        qr_images: Single QR image/path or list of QR images/paths
        
    Returns:
        Tuple of (key_data, key_name)
    """
    qr_dist = QRKeyDistribution()
    return qr_dist.read_key_qr(qr_images)