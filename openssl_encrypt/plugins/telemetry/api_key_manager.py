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

            # Validate required fields (backward compatible with both "api_key" and "token")
            if "client_id" not in data:
                return None
            if "token" not in data and "api_key" not in data:
                return None
            if "expires" not in data:
                return None

            # Normalize old "api_key" to new "token" format
            if "api_key" in data and "token" not in data:
                data["token"] = data["api_key"]

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
        Returns valid JWT token, registering if necessary.

        Returns:
            str or None: JWT token if successful, None on failure
        """
        # Check if we have a valid cached key
        if self._cached_key_data and not self._is_key_expired(
            self._cached_key_data.get("expires", "")
        ):
            return self._cached_key_data.get("token") or self._cached_key_data.get("api_key")

        # Load from disk
        data = self._load_key_data()
        if data and not self._is_key_expired(data.get("expires", "")):
            self._cached_key_data = data
            return data.get("token") or data.get("api_key")

        # Token expired or doesn't exist - register new client
        if self.register():
            return self._cached_key_data.get("token")

        return None

    def register(self) -> bool:
        """
        Registers with server and obtains JWT token.

        PRIVACY: Server generates client_id. NO identifying information sent.
        NO IP addresses, NO hardware IDs, NO platform info.

        Returns:
            bool: True if registration successful, False otherwise
        """
        try:
            # Send registration request (empty POST, server generates client_id)
            response = requests.post(
                f"{self.server_url}/api/v1/telemetry/register",
                timeout=10,
            )

            if response.status_code != 200:
                return False

            # Parse response
            result = response.json()

            # Save JWT token data
            key_data = {
                "client_id": result["client_id"],  # Server-generated
                "token": result["token"],  # JWT token
                "expires": result["expires_at"],  # ISO 8601 datetime
                "registered_at": datetime.now(timezone.utc).isoformat(),
            }

            self._save_key_data(key_data)
            return True

        except (requests.RequestException, KeyError, json.JSONDecodeError):
            return False

    def refresh_key(self) -> bool:
        """
        Refreshes JWT token by re-registering.

        Note: JWT tokens don't have a refresh endpoint. Just re-register to get a new token.
        This method is kept for backward compatibility.

        Returns:
            bool: True if registration successful, False otherwise
        """
        return self.register()

    def delete_key(self) -> None:
        """
        Deletes API key file (for opt-out).
        """
        if self.key_file.exists():
            self.key_file.unlink()
        self._cached_key_data = None
