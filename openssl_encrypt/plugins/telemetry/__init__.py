#!/usr/bin/env python3
"""
Telemetry Plugin for OpenSSL Encrypt

This plugin collects anonymous telemetry data about cryptographic algorithm usage
to help prioritize future development. It implements strict privacy guarantees:

PRIVACY GUARANTEES:
- Only algorithm names and parameters are collected (no sensitive data)
- No passwords, keys, salts, filenames, or IP addresses
- Data filtered through TelemetryDataFilter (strict whitelist)
- Opt-in by default (disabled unless explicitly enabled)
- User can inspect all pending events before upload
- Full opt-out with complete data deletion

COMPONENTS:
- api_key_manager: Handles anonymous client registration and API key management
- local_buffer: SQLite-based local event storage
- uploader: HTTPS batch uploader with retry logic
- telemetry_plugin: Main plugin class integrating all components
"""

__version__ = "1.0.0"

from .telemetry_plugin import OpenSSLEncryptTelemetryPlugin

__all__ = ["OpenSSLEncryptTelemetryPlugin"]
