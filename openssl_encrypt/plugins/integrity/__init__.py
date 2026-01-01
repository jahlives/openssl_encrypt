#!/usr/bin/env python3
"""
OpenSSL Encrypt Integrity Plugin

Client plugin for encrypted file metadata integrity verification.

FEATURES:
- Store SHA-256 hashes of encrypted file metadata on remote server
- Verify file integrity before decryption
- Batch verification support (up to 100 files)
- Tamper detection with comprehensive audit logging
- mTLS authentication with client certificates

SECURITY:
- OPT-IN by default (enabled=False)
- mTLS authentication required
- HTTPS-only connections
- No sensitive data transmitted (only SHA-256 hashes)
- Auto-registration on first connection

USAGE:
    from openssl_encrypt.plugins.integrity import IntegrityPlugin, IntegrityConfig
    from pathlib import Path

    # Configure plugin
    config = IntegrityConfig(
        enabled=True,
        server_url="https://integrity.example.com",
        client_cert=Path("~/.openssl_encrypt/integrity/certs/client.crt"),
        client_key=Path("~/.openssl_encrypt/integrity/certs/client.key"),
        ca_cert=Path("~/.openssl_encrypt/integrity/certs/ca.crt")
    )

    # Use plugin
    with IntegrityPlugin(config) as plugin:
        # Store metadata hash
        file_id = plugin.compute_file_id(Path("file.enc"))
        metadata_hash = plugin.compute_metadata_hash(metadata_bytes)
        plugin.store_hash(file_id, metadata_hash, algorithm="aes-256-gcm")

        # Verify integrity later
        match, details = plugin.verify(file_id, metadata_hash)
        if not match:
            print(f"INTEGRITY VIOLATION: {details['warning']}")

CONFIGURATION:
    Config file: ~/.openssl_encrypt/plugins/integrity.json
    Example:
    {
        "enabled": true,
        "server_url": "https://integrity.example.com",
        "client_cert": "~/.openssl_encrypt/integrity/certs/client.crt",
        "client_key": "~/.openssl_encrypt/integrity/certs/client.key",
        "ca_cert": "~/.openssl_encrypt/integrity/certs/ca.crt",
        "connect_timeout_seconds": 10,
        "read_timeout_seconds": 30
    }
"""

from .config import IntegrityConfig
from .integrity_plugin import IntegrityPlugin, IntegrityPluginError, IntegrityVerificationError

__all__ = ["IntegrityPlugin", "IntegrityConfig", "IntegrityPluginError", "IntegrityVerificationError"]

__version__ = "1.4.0"
