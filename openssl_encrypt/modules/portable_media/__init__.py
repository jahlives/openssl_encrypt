#!/usr/bin/env python3
"""
Portable Media & Offline Distribution Module

This module provides air-gapped security features for offline distribution
and portable media integration, maintaining strict network-free operation.

Key Features:
- QR Code Key Distribution
- USB Drive Encryption
- Secure Media Sanitization  
- Air-Gapped System Integration Tools

Author: OpenSSL Encrypt Team
Version: 1.3.0
"""

from .qr_distribution import (
    QRKeyDistribution,
    QRKeyError,
    QRKeyFormat,
    create_key_qr,
    read_key_qr,
    SecureBytes,
)

from .usb_creator import (
    USBDriveCreator,
    USBCreationError,
    USBSecurityProfile,
    create_portable_usb,
    verify_usb_integrity,
)

__all__ = [
    'QRKeyDistribution',
    'QRKeyError', 
    'QRKeyFormat',
    'create_key_qr',
    'read_key_qr',
    'SecureBytes',
    'USBDriveCreator',
    'USBCreationError',
    'USBSecurityProfile', 
    'create_portable_usb',
    'verify_usb_integrity',
]

__version__ = '1.3.0'