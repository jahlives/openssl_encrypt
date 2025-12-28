"""
OpenSSL Encrypt Plugin System

This package contains plugins that extend OpenSSL Encrypt functionality.

Available plugin types:
- HSM plugins: Hardware Security Module integrations (Yubikey, etc.)
- Steganography plugin: Hide encrypted data in media files (images, audio)

For plugin development guidance, see PLUGIN_DEVELOPMENT.md
"""

from . import steganography

__all__ = ["hsm", "steganography"]
