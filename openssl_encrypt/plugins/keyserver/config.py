#!/usr/bin/env python3
"""
Keyserver Plugin Configuration

This module handles configuration for the keyserver plugin.

Configuration is stored in: ~/.openssl_encrypt/plugins/keyserver.json
API token (if set) is stored separately in: ~/.openssl_encrypt/keyserver/token
with restrictive permissions (0600) for security.

SECURITY:
- OPT-IN by default (enabled=False)
- API token stored in separate file with restrictive permissions
- HTTPS-only server URLs enforced
- Configurable timeouts prevent hanging connections
"""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from ...modules.crypt_utils import eprint
from ...modules.file_permissions import (
    PermissionLevel,
    check_permissions,
    get_posix_mode,
    set_permissions,
)
from ...modules.plugin_system.plugin_config import ensure_plugin_data_dir

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Base exception for configuration errors"""

    pass


@dataclass
class KeyserverConfig:
    """
    Configuration for keyserver plugin.

    SECURITY:
    - enabled: OPT-IN by default (False)
    - API token stored separately from config file
    - HTTPS-only for all server URLs

    Attributes:
        enabled: Whether keyserver plugin is enabled (OPT-IN, default: False)
        servers: List of keyserver URLs (HTTPS only)
        cache_ttl_seconds: Cache TTL in seconds (default: 24 hours)
        cache_max_entries: Maximum cache entries (default: 1000)
        cache_path: Path to SQLite cache database
        connect_timeout_seconds: Connection timeout (default: 10s)
        read_timeout_seconds: Read timeout (default: 30s)
        upload_enabled: Allow uploading keys to keyserver (default: True)
        api_token: API token for uploads (Bearer token, optional)
        api_token_file: Path to API token file (default: ~/.openssl_encrypt/keyserver/token)
    """

    enabled: bool = False  # OPT-IN by default
    servers: List[str] = field(
        default_factory=lambda: ["https://keys.openssl-encrypt.org"]
    )  # HTTPS only
    cache_ttl_seconds: int = 86400  # 24 hours
    cache_max_entries: int = 1000
    cache_path: Path = field(default_factory=lambda: _get_default_cache_path())
    connect_timeout_seconds: int = 10
    read_timeout_seconds: int = 30
    upload_enabled: bool = True

    # Authentication for uploads (stored securely)
    api_token: Optional[str] = None  # Bearer token for uploads
    api_token_file: Path = field(default_factory=lambda: _get_default_token_path())
    refresh_token_file: Path = field(default_factory=lambda: _get_default_refresh_token_path())

    # Password storage for authenticated login
    password_file: Path = field(default_factory=lambda: _get_default_password_path())

    # Certificate pinning (SHA-256 fingerprints)
    cert_fingerprints: Optional[List[str]] = None  # Expected cert fingerprints for pinning
    enable_cert_pinning: bool = False  # Enable certificate pinning validation

    def __post_init__(self):
        """Validate configuration after initialization."""
        # Convert string paths to Path objects
        if isinstance(self.cache_path, str):
            self.cache_path = Path(self.cache_path).expanduser()
        if isinstance(self.api_token_file, str):
            self.api_token_file = Path(self.api_token_file).expanduser()
        if isinstance(self.refresh_token_file, str):
            self.refresh_token_file = Path(self.refresh_token_file).expanduser()

        # Validate server URLs are HTTPS only
        for server in self.servers:
            if not server.startswith("https://"):
                raise ConfigError(
                    f"Invalid server URL: {server}. Only HTTPS URLs are allowed for security."
                )

        # Validate timeouts
        if self.connect_timeout_seconds <= 0:
            raise ConfigError("connect_timeout_seconds must be positive")
        if self.read_timeout_seconds <= 0:
            raise ConfigError("read_timeout_seconds must be positive")

        # Validate cache settings
        if self.cache_ttl_seconds <= 0:
            raise ConfigError("cache_ttl_seconds must be positive")
        if self.cache_max_entries <= 0:
            raise ConfigError("cache_max_entries must be positive")

    @classmethod
    def from_file(cls, config_path: Optional[Path] = None) -> "KeyserverConfig":
        """
        Load configuration from JSON file.

        Args:
            config_path: Path to config file (default: ~/.openssl_encrypt/plugins/keyserver.json)

        Returns:
            KeyserverConfig instance

        Note:
            If file doesn't exist, returns default configuration.
        """
        if config_path is None:
            config_path = _get_default_config_path()

        config_path = Path(config_path).expanduser()

        # Return default config if file doesn't exist
        if not config_path.exists():
            logger.debug(f"Config file not found at {config_path}, using defaults")
            return cls()

        try:
            with open(config_path, "r") as f:
                data = json.load(f)

            # Convert path strings to Path objects
            if "cache_path" in data:
                data["cache_path"] = Path(data["cache_path"]).expanduser()
            if "api_token_file" in data:
                data["api_token_file"] = Path(data["api_token_file"]).expanduser()

            config = cls(**data)
            logger.info(f"Loaded keyserver config from {config_path}")
            return config

        except Exception as e:
            logger.error(f"Failed to load config from {config_path}: {e}")
            raise ConfigError(f"Failed to load configuration: {e}")

    def to_file(self, config_path: Optional[Path] = None) -> None:
        """
        Save configuration to JSON file.

        Args:
            config_path: Path to config file (default: ~/.openssl_encrypt/plugins/keyserver.json)

        Note:
            API token is NOT saved to config file. Use save_api_token() separately.
        """
        if config_path is None:
            config_path = _get_default_config_path()

        config_path = Path(config_path).expanduser()

        # Ensure parent directory exists
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Convert to dictionary (exclude api_token for security)
        data = {
            "enabled": self.enabled,
            "servers": self.servers,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "cache_max_entries": self.cache_max_entries,
            "cache_path": str(self.cache_path),
            "connect_timeout_seconds": self.connect_timeout_seconds,
            "read_timeout_seconds": self.read_timeout_seconds,
            "upload_enabled": self.upload_enabled,
            "api_token_file": str(self.api_token_file),
        }

        try:
            with open(config_path, "w") as f:
                json.dump(data, f, indent=2)

            # Set restrictive permissions
            os.chmod(config_path, 0o600)

            logger.info(f"Saved keyserver config to {config_path}")

        except Exception as e:
            logger.error(f"Failed to save config to {config_path}: {e}")
            raise ConfigError(f"Failed to save configuration: {e}")

    def load_api_token(self) -> Optional[str]:
        """
        Load API token from secure file.

        Returns:
            API token string or None if not set

        Note:
            Token file must have restrictive permissions (0600).
        """
        token_file = self.api_token_file.expanduser()

        if not token_file.exists():
            return None

        try:
            # Check file permissions (should be 0600)
            stat_info = token_file.stat()
            mode = stat_info.st_mode & 0o777

            if mode != 0o600:
                logger.warning(
                    f"API token file has insecure permissions: {oct(mode)}. "
                    f"Should be 0600 (owner read/write only)"
                )

            # Read token
            with open(token_file, "r") as f:
                token = f.read().strip()

            if token:
                logger.debug("Loaded API token from file")
                return token
            else:
                logger.warning("API token file is empty")
                return None

        except Exception as e:
            logger.error(f"Failed to load API token: {e}")
            return None

    def save_api_token(self, token: str) -> None:
        """
        Save API token to secure file.

        Args:
            token: API token string

        Note:
            File is created with restrictive permissions (0600).
        """
        token_file = self.api_token_file.expanduser()

        try:
            # Ensure parent directory exists
            token_file.parent.mkdir(parents=True, exist_ok=True)

            # Write token
            with open(token_file, "w") as f:
                f.write(token)

            # Set restrictive permissions (owner read/write only)
            os.chmod(token_file, 0o600)

            logger.info(f"Saved API token to {token_file} with secure permissions")

        except Exception as e:
            logger.error(f"Failed to save API token: {e}")
            raise ConfigError(f"Failed to save API token: {e}")

    def clear_api_token(self) -> bool:
        """
        Delete API token file.

        Returns:
            True if token was deleted, False if it didn't exist
        """
        token_file = self.api_token_file.expanduser()

        if not token_file.exists():
            return False

        try:
            token_file.unlink()
            logger.info(f"Deleted API token file: {token_file}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete API token: {e}")
            raise ConfigError(f"Failed to delete API token: {e}")

    def load_refresh_token(self) -> Optional[str]:
        """
        Load refresh token from secure file.

        Returns:
            Refresh token string or None if not set
        """
        token_file = self.refresh_token_file.expanduser()

        if not token_file.exists():
            return None

        try:
            if not check_permissions(token_file, PermissionLevel.OWNER_ONLY):
                logger.warning(
                    f"Refresh token file has insecure permissions: {oct(get_posix_mode(token_file))}. "
                    f"Should be 0600 (owner read/write only)"
                )

            with open(token_file, "r") as f:
                token = f.read().strip()

            if token:
                logger.debug("Loaded refresh token from file")
                return token
            else:
                logger.warning("Refresh token file is empty")
                return None

        except Exception as e:
            logger.error(f"Failed to load refresh token: {e}")
            return None

    def save_refresh_token(self, token: str) -> None:
        """
        Save refresh token to secure file.

        Args:
            token: Refresh token string
        """
        token_file = self.refresh_token_file.expanduser()

        try:
            token_file.parent.mkdir(parents=True, exist_ok=True)

            with open(token_file, "w") as f:
                f.write(token)

            set_permissions(token_file, PermissionLevel.OWNER_ONLY)

            logger.info(f"Saved refresh token to {token_file} with secure permissions")

        except Exception as e:
            logger.error(f"Failed to save refresh token: {e}")
            raise ConfigError(f"Failed to save refresh token: {e}")

    def clear_refresh_token(self) -> bool:
        """
        Delete refresh token file.

        Returns:
            True if token was deleted, False if it didn't exist
        """
        token_file = self.refresh_token_file.expanduser()

        if not token_file.exists():
            return False

        try:
            token_file.unlink()
            logger.info(f"Deleted refresh token file: {token_file}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete refresh token: {e}")
            raise ConfigError(f"Failed to delete refresh token: {e}")

    def load_password(self) -> Optional[str]:
        """
        Load stored password from secure file.

        Returns:
            Password string or None if not set
        """
        pw_file = self.password_file.expanduser()

        if not pw_file.exists():
            return None

        try:
            if not check_permissions(pw_file, PermissionLevel.OWNER_ONLY):
                logger.warning(
                    f"Password file has insecure permissions: {oct(get_posix_mode(pw_file))}. "
                    f"Should be 0600 (owner read/write only)"
                )

            with open(pw_file, "r") as f:
                password = f.read().strip()

            if password:
                logger.debug("Loaded password from file")
                return password
            else:
                logger.warning("Password file is empty")
                return None

        except Exception as e:
            logger.error(f"Failed to load password: {e}")
            return None

    def save_password(self, password: str) -> None:
        """
        Save password to secure file.

        Args:
            password: Password string

        Note:
            File is created with restrictive permissions (0600).
        """
        pw_file = self.password_file.expanduser()

        try:
            pw_file.parent.mkdir(parents=True, exist_ok=True)

            with open(pw_file, "w") as f:
                f.write(password)

            set_permissions(pw_file, PermissionLevel.OWNER_ONLY)

            logger.info(f"Saved password to {pw_file} with secure permissions")

        except Exception as e:
            logger.error(f"Failed to save password: {e}")
            raise ConfigError(f"Failed to save password: {e}")

    def clear_password(self) -> bool:
        """
        Delete password file.

        Returns:
            True if password was deleted, False if it didn't exist
        """
        pw_file = self.password_file.expanduser()

        if not pw_file.exists():
            return False

        try:
            pw_file.unlink()
            logger.info(f"Deleted password file: {pw_file}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete password: {e}")
            raise ConfigError(f"Failed to delete password: {e}")


def _get_default_config_path() -> Path:
    """Get default configuration file path."""
    # Use plugins/keyserver/ as base directory
    config_dir = Path.home() / ".openssl_encrypt" / "plugins" / "keyserver"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "config.json"


def _get_default_cache_path() -> Optional[Path]:
    """Get default cache database path with secure permissions."""
    keyserver_dir = ensure_plugin_data_dir("keyserver", "")
    if keyserver_dir is None:
        logger.error("Failed to create secure keyserver directory")
        return None
    return keyserver_dir / "cache.db"


def _get_default_token_path() -> Optional[Path]:
    """Get default API token file path with secure permissions."""
    keyserver_dir = ensure_plugin_data_dir("keyserver", "")
    if keyserver_dir is None:
        logger.error("Failed to create secure keyserver directory")
        return None
    return keyserver_dir / "token"


def _get_default_refresh_token_path() -> Optional[Path]:
    """Get default refresh token file path with secure permissions."""
    keyserver_dir = ensure_plugin_data_dir("keyserver", "")
    if keyserver_dir is None:
        logger.error("Failed to create secure keyserver directory")
        return None
    return keyserver_dir / "refresh_token"


def _get_default_password_path() -> Optional[Path]:
    """Get default password file path with secure permissions."""
    keyserver_dir = ensure_plugin_data_dir("keyserver", "")
    if keyserver_dir is None:
        logger.error("Failed to create secure keyserver directory")
        return None
    return keyserver_dir / "password"


if __name__ == "__main__":
    # Simple test
    eprint("KeyserverConfig module loaded successfully")

    # Test default config
    config = KeyserverConfig()
    eprint(f"Default config: enabled={config.enabled}, servers={config.servers}")
    eprint(f"Cache path: {config.cache_path}")
    eprint(f"Token file: {config.api_token_file}")
