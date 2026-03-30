"""
Pepper Plugin - Secure remote pepper storage with mTLS authentication.

This plugin provides opt-in secure pepper storage via a remote server
with client certificate authentication.

Features:
- Store/retrieve encrypted peppers with mTLS
- TOTP 2FA for destructive operations
- Dead man's switch (auto-wipe on missed check-ins)
- Emergency panic wipe functionality

SECURITY:
- OPT-IN by default (disabled)
- mTLS authentication required
- Peppers encrypted client-side before upload
- HTTPS-only communication
- TOTP 2FA for destructive operations

Usage:
    from openssl_encrypt.plugins.pepper import PepperPlugin, PepperConfig

    # Configure
    config = PepperConfig(
        enabled=True,
        server_url="https://pepper.example.com",
        client_cert=Path("~/.openssl_encrypt/pepper/client.crt"),
        client_key=Path("~/.openssl_encrypt/pepper/client.key"),
    )

    # Initialize plugin
    plugin = PepperPlugin(config)

    # Get profile (auto-registers on first request)
    profile = plugin.get_profile()

    # Setup TOTP
    totp_setup = plugin.setup_totp()
    # Scan QR code, then verify:
    result = plugin.verify_totp("123456")
    backup_codes = result["backup_codes"]  # Save these!

    # Store encrypted pepper
    pepper_data = b"my secret pepper data"
    # IMPORTANT: Encrypt pepper_data client-side before storing!
    plugin.store_pepper("my-pepper", pepper_data, "Description")

    # Retrieve pepper
    encrypted_pepper = plugin.get_pepper("my-pepper")
    # IMPORTANT: Decrypt encrypted_pepper client-side!

    # Configure dead man's switch
    plugin.configure_deadman(interval="7d", grace_period="24h")

    # Regular check-in to prevent auto-wipe
    plugin.checkin()

    # Emergency panic wipe (requires TOTP)
    plugin.panic_all(totp_code="123456")
"""

from .config import ConfigError, PepperConfig
from .pepper_plugin import (
    AuthenticationError,
    NetworkError,
    PepperError,
    PepperPlugin,
    TOTPRequiredError,
)

__all__ = [
    "PepperPlugin",
    "PepperConfig",
    "PepperError",
    "NetworkError",
    "AuthenticationError",
    "TOTPRequiredError",
    "ConfigError",
]
