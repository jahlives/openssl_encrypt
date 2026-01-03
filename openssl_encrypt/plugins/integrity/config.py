#!/usr/bin/env python3
"""
Integrity Plugin Configuration

This module handles configuration for the integrity plugin.

Configuration is stored in: ~/.openssl_encrypt/plugins/integrity.json
Client certificates are referenced (not stored in config) for mTLS authentication.

SECURITY:
- OPT-IN by default (enabled=False)
- Client certificates stored securely (not in config file)
- HTTPS-only server URLs enforced
- mTLS authentication required for all operations
- Configurable timeouts prevent hanging connections
"""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ...modules.plugin_system.plugin_config import ensure_plugin_data_dir

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Base exception for configuration errors"""

    pass


def _get_default_config_dir() -> Path:
    """Get default configuration directory for integrity plugin."""
    config_dir = Path.home() / ".openssl_encrypt" / "plugins" / "integrity"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def _get_default_config_path() -> Path:
    """Get default integrity config file path."""
    return _get_default_config_dir() / "config.json"


def _get_default_cert_dir() -> Optional[Path]:
    """Get default certificate directory with secure permissions."""
    cert_dir = ensure_plugin_data_dir("integrity", "certs")
    if cert_dir is None:
        logger.error("Failed to create secure integrity certificate directory")
    return cert_dir


@dataclass
class IntegrityConfig:
    """
    Configuration for integrity plugin.

    SECURITY:
    - enabled: OPT-IN by default (False)
    - mTLS authentication required (client certificate + key)
    - HTTPS-only for all server URLs
    - Certificates referenced by path, not stored in config

    Attributes:
        enabled: Whether integrity plugin is enabled (OPT-IN, default: False)
        server_url: Integrity server URL (HTTPS only)
        client_cert: Path to client certificate for mTLS authentication
        client_key: Path to client private key for mTLS authentication
        ca_cert: Path to CA certificate for server verification (optional)
        connect_timeout_seconds: Connection timeout (default: 10s)
        read_timeout_seconds: Read timeout (default: 30s)
    """

    enabled: bool = False  # OPT-IN by default
    server_url: str = "https://integrity.openssl-encrypt.org"  # HTTPS only
    client_cert: Optional[Path] = None
    client_key: Optional[Path] = None
    ca_cert: Optional[Path] = None
    connect_timeout_seconds: int = 10
    read_timeout_seconds: int = 30

    def __post_init__(self):
        """Validate configuration after initialization."""
        # Convert string paths to Path objects
        if isinstance(self.client_cert, str):
            self.client_cert = Path(self.client_cert).expanduser() if self.client_cert else None
        if isinstance(self.client_key, str):
            self.client_key = Path(self.client_key).expanduser() if self.client_key else None
        if isinstance(self.ca_cert, str):
            self.ca_cert = Path(self.ca_cert).expanduser() if self.ca_cert else None

        # Validate server URL is HTTPS only
        if not self.server_url.startswith("https://"):
            raise ConfigError(
                f"Invalid server URL: {self.server_url}. Only HTTPS URLs are allowed for security."
            )

        # Validate timeouts
        if self.connect_timeout_seconds <= 0:
            raise ConfigError("connect_timeout_seconds must be positive")
        if self.read_timeout_seconds <= 0:
            raise ConfigError("read_timeout_seconds must be positive")

        # If enabled, validate certificate paths exist
        if self.enabled:
            if not self.client_cert or not self.client_key:
                raise ConfigError(
                    "client_cert and client_key are required when integrity plugin is enabled. "
                    "Generate client certificates for mTLS authentication."
                )

            if not self.client_cert.exists():
                raise ConfigError(f"Client certificate not found: {self.client_cert}")
            if not self.client_key.exists():
                raise ConfigError(f"Client key not found: {self.client_key}")

            # Warn if CA cert specified but doesn't exist
            if self.ca_cert and not self.ca_cert.exists():
                logger.warning(f"CA certificate not found: {self.ca_cert} (server cert verification may fail)")

    @classmethod
    def from_file(cls, config_path: Optional[Path] = None) -> "IntegrityConfig":
        """
        Load configuration from JSON file.

        Args:
            config_path: Path to config file (default: ~/.openssl_encrypt/plugins/integrity.json)

        Returns:
            IntegrityConfig instance

        Note:
            If file doesn't exist, returns default config (disabled)
        """
        if config_path is None:
            config_path = _get_default_config_path()

        if not config_path.exists():
            logger.info(f"Integrity config not found at {config_path}, using defaults (disabled)")
            return cls()

        try:
            with open(config_path, "r") as f:
                data = json.load(f)

            # Convert paths
            if "client_cert" in data and data["client_cert"]:
                data["client_cert"] = Path(data["client_cert"]).expanduser()
            if "client_key" in data and data["client_key"]:
                data["client_key"] = Path(data["client_key"]).expanduser()
            if "ca_cert" in data and data["ca_cert"]:
                data["ca_cert"] = Path(data["ca_cert"]).expanduser()

            config = cls(**data)
            logger.info(f"Loaded integrity config from {config_path} (enabled={config.enabled})")
            return config

        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid JSON in {config_path}: {e}")
        except TypeError as e:
            raise ConfigError(f"Invalid config structure in {config_path}: {e}")

    def to_file(self, config_path: Optional[Path] = None):
        """
        Save configuration to JSON file.

        Args:
            config_path: Path to save config (default: ~/.openssl_encrypt/plugins/integrity.json)
        """
        if config_path is None:
            config_path = _get_default_config_path()

        # Ensure parent directory exists
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Convert to dict and serialize paths
        data = {
            "enabled": self.enabled,
            "server_url": self.server_url,
            "client_cert": str(self.client_cert) if self.client_cert else None,
            "client_key": str(self.client_key) if self.client_key else None,
            "ca_cert": str(self.ca_cert) if self.ca_cert else None,
            "connect_timeout_seconds": self.connect_timeout_seconds,
            "read_timeout_seconds": self.read_timeout_seconds,
        }

        with open(config_path, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved integrity config to {config_path}")


# Example usage and testing
if __name__ == "__main__":
    # Example 1: Create default config (disabled)
    config = IntegrityConfig()
    print(f"Default config: enabled={config.enabled}, server_url={config.server_url}")

    # Example 2: Create config with mTLS certificates
    cert_dir = _get_default_cert_dir()
    config = IntegrityConfig(
        enabled=True,
        server_url="https://integrity.example.com",
        client_cert=cert_dir / "client.crt",
        client_key=cert_dir / "client.key",
        ca_cert=cert_dir / "ca.crt",
    )

    # Save and load
    config.to_file()
    loaded_config = IntegrityConfig.from_file()
    print(f"Loaded config: enabled={loaded_config.enabled}")
