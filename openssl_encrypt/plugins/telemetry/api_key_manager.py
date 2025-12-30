#!/usr/bin/env python3
"""
API Key Manager - Handles client registration and API key management.

PRIVACY CRITICAL:
- Client ID is random (NOT hardware-based, NOT user-identifying)
- API key stored with 0600 permissions (owner read/write only)
- Automatic refresh on expiration
- NO IP addresses collected
- NO hardware IDs (MAC, serial numbers, etc.)
- NO user identifiers

The client ID is purely for rate limiting and deduplication on the server side.
It cannot be used to identify a specific user or machine.
"""

import hashlib
import json
import os
import secrets
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional

import requests


class APIKeyManager:
    """
    Manages API key for telemetry communication.

    SECURITY:
    - Client ID: Random 32-character hex (NOT hardware-based)
    - API key file: 0600 permissions (owner only)
    - Automatic registration and refresh
    - NO personal or hardware identifiers collected
    """

    def __init__(self, config):
        """
        Initialize APIKeyManager.

        Args:
            config: Configuration object with server_url and key storage path
        """
        self.config = config
        self.server_url = config.server_url
        self.key_file = config.buffer_path.parent / "api_key.json"
        self._cached_key_data = None

    def _generate_client_id(self) -> str:
        """
        Generates anonymous client ID.

        IMPORTANT: NO hardware IDs, NO user IDs, NO IP hashes!
        Just a random identifier for rate limiting on the server.

        This is NOT a tracking identifier - it's purely random and
        cannot be correlated to a specific user or machine.

        Returns:
            str: Random 32-character hex string
        """
        return secrets.token_hex(16)  # 16 bytes = 32 hex chars

    def _ensure_key_file_permissions(self) -> None:
        """
        Ensures API key file has secure permissions (0600).

        SECURITY: Key file must only be readable/writable by owner.
        """
        if self.key_file.exists():
            # Set permissions to 0600 (read/write for owner only)
            os.chmod(self.key_file, stat.S_IRUSR | stat.S_IWUSR)

    def _load_key_data(self) -> Optional[Dict]:
        """
        Loads API key data from file.

        Returns:
            dict or None: Key data if file exists and is valid, None otherwise
        """
        if not self.key_file.exists():
            return None

        try:
            with open(self.key_file, "r") as f:
                data = json.load(f)

            # Validate required fields
            if not all(k in data for k in ["client_id", "api_key", "expires"]):
                return None

            return data
        except (json.JSONDecodeError, IOError, KeyError):
            return None

    def _save_key_data(self, data: Dict) -> None:
        """
        Saves API key data to file with secure permissions.

        Args:
            data: Dictionary with client_id, api_key, expires
        """
        # Ensure parent directory exists
        self.key_file.parent.mkdir(parents=True, exist_ok=True)

        # Write key data
        with open(self.key_file, "w") as f:
            json.dump(data, f, indent=2)

        # Set secure permissions (0600)
        self._ensure_key_file_permissions()

        # Update cache
        self._cached_key_data = data

    def _is_key_expired(self, expires_str: str) -> bool:
        """
        Checks if API key has expired.

        Args:
            expires_str: ISO 8601 expiration timestamp

        Returns:
            bool: True if expired, False otherwise
        """
        try:
            expires = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
            # Consider key expired 1 day before actual expiration (safety margin)
            safety_margin = timedelta(days=1)
            return datetime.now(timezone.utc) >= (expires - safety_margin)
        except (ValueError, AttributeError):
            return True  # If we can't parse, assume expired

    def has_valid_key(self) -> bool:
        """
        Checks if we have a valid (non-expired) API key.

        Returns:
            bool: True if valid key exists, False otherwise
        """
        # Check cache first
        if self._cached_key_data:
            if not self._is_key_expired(self._cached_key_data.get("expires", "")):
                return True

        # Load from disk
        data = self._load_key_data()
        if data and not self._is_key_expired(data.get("expires", "")):
            self._cached_key_data = data
            return True

        return False

    def get_api_key(self) -> Optional[str]:
        """
        Returns valid API key, registering or refreshing if necessary.

        Returns:
            str or None: API key if successful, None on failure
        """
        # Check if we have a valid cached key
        if self._cached_key_data and not self._is_key_expired(
            self._cached_key_data.get("expires", "")
        ):
            return self._cached_key_data["api_key"]

        # Load from disk
        data = self._load_key_data()
        if data and not self._is_key_expired(data.get("expires", "")):
            self._cached_key_data = data
            return data["api_key"]

        # Key expired or doesn't exist - register new client
        if self.register():
            return self._cached_key_data["api_key"]

        return None

    def register(self) -> bool:
        """
        Registers with server and obtains API key.

        PRIVACY: Only sends anonymous client_id and platform info.
        NO IP addresses, NO hardware IDs.

        Returns:
            bool: True if registration successful, False otherwise
        """
        try:
            # Generate anonymous client ID
            client_id = self._generate_client_id()

            # Determine platform (generic only - linux/macos/windows/other)
            platform = self._get_generic_platform()

            # Get client version
            client_version = self._get_client_version()

            # Registration payload (NO identifying information!)
            payload = {
                "client_id": client_id,
                "platform": platform,  # Generic: "linux", "macos", "windows", "other"
                "client_version": client_version,  # e.g., "1.4.0"
            }

            # Send registration request
            response = requests.post(
                f"{self.server_url}/api/v1/register",
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"},
            )

            if response.status_code != 200:
                return False

            # Parse response
            result = response.json()

            # Save key data
            key_data = {
                "client_id": client_id,
                "api_key": result["api_key"],
                "expires": result["expires"],
                "registered_at": datetime.now(timezone.utc).isoformat(),
            }

            self._save_key_data(key_data)
            return True

        except (requests.RequestException, KeyError, json.JSONDecodeError):
            return False

    def refresh_key(self) -> bool:
        """
        Refreshes API key using current key for authentication.

        Returns:
            bool: True if refresh successful, False otherwise
        """
        try:
            # Load current key
            data = self._load_key_data()
            if not data or "api_key" not in data:
                # No current key - need to register
                return self.register()

            # Send refresh request with current key
            response = requests.post(
                f"{self.server_url}/api/v1/key/refresh",
                headers={
                    "Authorization": f"Bearer {data['api_key']}",
                    "Content-Type": "application/json",
                },
                timeout=10,
            )

            if response.status_code == 401:
                # Unauthorized - current key invalid, need to re-register
                return self.register()

            if response.status_code != 200:
                return False

            # Parse response
            result = response.json()

            # Update key data
            data["api_key"] = result["api_key"]
            data["expires"] = result["expires"]
            data["refreshed_at"] = datetime.now(timezone.utc).isoformat()

            self._save_key_data(data)
            return True

        except (requests.RequestException, KeyError, json.JSONDecodeError):
            return False

    def _get_generic_platform(self) -> str:
        """
        Returns generic platform identifier.

        PRIVACY: Only returns generic values (linux/macos/windows/other).
        NO version numbers, NO specific distributions.

        Returns:
            str: Generic platform string
        """
        platform = sys.platform.lower()

        if platform.startswith("linux"):
            return "linux"
        elif platform.startswith("darwin"):
            return "macos"
        elif platform.startswith("win"):
            return "windows"
        else:
            return "other"

    def _get_client_version(self) -> str:
        """
        Returns client version.

        Returns:
            str: Client version (e.g., "1.4.0")
        """
        try:
            # Try to import version from main module
            from openssl_encrypt import __version__

            return __version__
        except (ImportError, AttributeError):
            return "unknown"

    def delete_key(self) -> None:
        """
        Deletes API key file (for opt-out).
        """
        if self.key_file.exists():
            self.key_file.unlink()
        self._cached_key_data = None
