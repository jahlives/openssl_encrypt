#!/usr/bin/env python3
"""
Pepper Plugin - Secure remote pepper storage with mTLS authentication.

This plugin provides secure, opt-in pepper storage via a remote pepper server.

SECURITY GUARANTEES:
- Plugin NEVER stores plaintext peppers (always encrypted client-side)
- mTLS authentication required for all operations
- HTTPS-only communication
- TOTP 2FA for destructive operations (delete, panic)
- Dead man's switch for automatic pepper wiping

Features:
- Store/retrieve encrypted peppers remotely
- TOTP 2FA protection for sensitive operations
- Dead man's switch (auto-wipe if client doesn't check in)
- Panic wipe (emergency delete all peppers)
- Profile management
"""

import base64
import logging
from typing import Dict, List, Optional

import requests

from ...modules.plugin_system.plugin_base import BasePlugin, PluginCapability, PluginType
from .config import PepperConfig

logger = logging.getLogger(__name__)


class PepperError(Exception):
    """Base exception for pepper operations"""

    pass


class NetworkError(PepperError):
    """Raised when network request fails"""

    pass


class AuthenticationError(PepperError):
    """Raised when mTLS authentication fails"""

    pass


class TOTPRequiredError(PepperError):
    """Raised when TOTP code is required but not provided"""

    pass


class PepperPlugin(BasePlugin):
    """
    Main pepper plugin implementation.

    This plugin:
    1. Stores encrypted peppers remotely with mTLS authentication
    2. Retrieves peppers by name
    3. Manages TOTP 2FA for destructive operations
    4. Supports dead man's switch for automatic wiping
    5. Emergency panic wipe functionality

    SECURITY:
    - Peppers are ALWAYS encrypted client-side before upload
    - mTLS authentication required for all operations
    - TOTP verification for destructive operations
    - HTTPS-only communication
    """

    def __init__(self, config: Optional[PepperConfig] = None):
        """
        Initialize pepper plugin.

        Args:
            config: Optional configuration object
        """
        # Initialize base plugin
        super().__init__(
            plugin_id="openssl_encrypt_pepper",
            name="OpenSSL Encrypt Pepper Storage",
            version="1.0.0",
        )

        # Configuration
        if config is None:
            config = PepperConfig.from_file()
        self.config = config

        logger.info(f"Initialized pepper plugin (enabled={self.config.enabled})")

    def get_required_capabilities(self) -> set:
        """
        Return required capabilities for this plugin.

        Returns:
            Set of PluginCapability
        """
        return {
            PluginCapability.NETWORK_ACCESS,  # Connect to pepper server
            PluginCapability.ACCESS_CONFIG,  # Read plugin configuration
            PluginCapability.WRITE_LOGS,  # Logging
        }

    def get_plugin_type(self) -> PluginType:
        """
        Return plugin type.

        Returns:
            PluginType.UTILITY
        """
        return PluginType.UTILITY

    def get_description(self) -> str:
        """
        Return human-readable description of plugin functionality.

        Returns:
            Plugin description string
        """
        return (
            "Secure remote pepper storage with mTLS authentication. "
            "Store encrypted peppers remotely with TOTP 2FA, dead man's switch, "
            "and emergency panic wipe functionality."
        )

    def execute(self, context) -> dict:
        """
        Execute the plugin with given security context.

        Note: This plugin is primarily a utility plugin providing API methods
        rather than a pipeline processor. Use the specific methods (store_pepper,
        get_pepper, etc.) directly instead of execute().

        Args:
            context: PluginSecurityContext (unused for this plugin type)

        Returns:
            PluginResult with status information
        """
        from ...modules.plugin_system.plugin_base import PluginResult

        return PluginResult(
            success=True,
            message="Pepper plugin is a utility plugin. Use specific methods (store_pepper, get_pepper, etc.) directly.",
            data={
                "enabled": self.config.enabled,
                "server_url": self.config.server_url,
            },
        )

    def _get_session(self) -> requests.Session:
        """
        Create requests session with mTLS authentication.

        Returns:
            Configured requests.Session

        Raises:
            PepperError: If certificates not configured
        """
        if not self.config.client_cert or not self.config.client_key:
            raise PepperError("Client certificate and key must be configured for mTLS authentication")

        session = requests.Session()

        # Configure mTLS
        session.cert = (str(self.config.client_cert), str(self.config.client_key))

        # Configure CA verification
        if self.config.ca_cert:
            session.verify = str(self.config.ca_cert)
        else:
            session.verify = True  # Use system CA bundle

        # Configure timeouts
        session.timeout = (self.config.connect_timeout_seconds, self.config.read_timeout_seconds)

        return session

    def _make_request(
        self,
        method: str,
        endpoint: str,
        json_data: Optional[Dict] = None,
        totp_code: Optional[str] = None,
    ) -> Dict:
        """
        Make authenticated request to pepper server.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (e.g., "/peppers")
            json_data: JSON data for request body
            totp_code: Optional TOTP code for 2FA

        Returns:
            Response JSON

        Raises:
            NetworkError: If request fails
            AuthenticationError: If mTLS auth fails
            TOTPRequiredError: If TOTP code required but not provided
        """
        if not self.config.enabled:
            raise PepperError("Pepper plugin is disabled in configuration")

        url = f"{self.config.server_url}/api/v1/pepper{endpoint}"

        try:
            session = self._get_session()

            # Add TOTP header if provided
            headers = {}
            if totp_code:
                headers["X-TOTP-Code"] = totp_code

            response = session.request(
                method=method,
                url=url,
                json=json_data,
                headers=headers,
                timeout=(self.config.connect_timeout_seconds, self.config.read_timeout_seconds),
            )

            # Handle authentication errors
            if response.status_code == 401:
                error_msg = response.json().get("detail", "Authentication failed")
                if "TOTP" in error_msg or "2FA" in error_msg:
                    raise TOTPRequiredError(error_msg)
                raise AuthenticationError(error_msg)

            if response.status_code == 403:
                raise AuthenticationError("Access forbidden - check client certificate")

            # Handle other errors
            if response.status_code >= 400:
                error_detail = response.json().get("detail", f"HTTP {response.status_code}")
                raise PepperError(f"Server error: {error_detail}")

            return response.json()

        except requests.exceptions.SSLError as e:
            raise AuthenticationError(f"mTLS authentication failed: {e}")
        except requests.exceptions.Timeout as e:
            raise NetworkError(f"Request timeout: {e}")
        except requests.exceptions.ConnectionError as e:
            raise NetworkError(f"Connection failed: {e}")
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Request failed: {e}")

    # Profile Management

    def get_profile(self) -> Dict:
        """
        Get client profile information.

        Returns:
            Profile dict with: cert_fingerprint, name, totp_enabled, created_at, pepper_count

        Raises:
            NetworkError: If request fails
            AuthenticationError: If mTLS auth fails
        """
        return self._make_request("GET", "/profile")

    def update_profile(self, name: str) -> Dict:
        """
        Update client profile.

        Args:
            name: Display name for the client

        Returns:
            Updated profile dict

        Raises:
            NetworkError: If request fails
        """
        return self._make_request("PUT", "/profile", json_data={"name": name})

    def delete_profile(self, totp_code: str) -> Dict:
        """
        Delete client profile and ALL associated data.

        DESTRUCTIVE: This deletes the entire account, all peppers, and TOTP configuration.
        Requires TOTP verification.

        Args:
            totp_code: TOTP code from authenticator app

        Returns:
            Deletion confirmation

        Raises:
            TOTPRequiredError: If TOTP not configured or code invalid
        """
        return self._make_request("DELETE", "/profile", totp_code=totp_code)

    # TOTP Management

    def setup_totp(self) -> Dict:
        """
        Setup TOTP 2FA for this client.

        Returns:
            Dict with: secret, qr_svg, uri, message

        Note:
            - Scan QR code with authenticator app (Google Authenticator, Authy, etc.)
            - Call verify_totp() with a code to complete setup
        """
        return self._make_request("POST", "/totp/setup")

    def verify_totp(self, code: str) -> Dict:
        """
        Verify TOTP setup and enable 2FA.

        Args:
            code: 6-digit TOTP code from authenticator app

        Returns:
            Dict with: message, backup_codes (list of 10 codes)

        Note:
            - Save backup codes securely (they can only be used once each)
            - After verification, TOTP will be required for destructive operations
        """
        return self._make_request("POST", "/totp/verify", json_data={"code": code})

    def disable_totp(self, totp_code: str) -> Dict:
        """
        Disable TOTP 2FA.

        Args:
            totp_code: Current TOTP code for verification

        Returns:
            Confirmation message

        Raises:
            TOTPRequiredError: If code invalid
        """
        return self._make_request("DELETE", "/totp", totp_code=totp_code)

    def generate_backup_codes(self, totp_code: str) -> Dict:
        """
        Generate new TOTP backup codes.

        Args:
            totp_code: Current TOTP code for verification

        Returns:
            Dict with: message, backup_codes (list of 10 new codes)

        Note:
            Old backup codes are invalidated
        """
        return self._make_request("POST", "/totp/backup", totp_code=totp_code)

    # Pepper Storage Operations

    def store_pepper(self, name: str, pepper_encrypted: bytes, description: str = "") -> Dict:
        """
        Store encrypted pepper on server.

        SECURITY: Pepper MUST be encrypted client-side before calling this method.
        The server stores only the encrypted blob.

        Args:
            name: Unique name for the pepper (identifier)
            pepper_encrypted: Encrypted pepper bytes (base64 encoded)
            description: Optional description

        Returns:
            Pepper metadata dict

        Raises:
            PepperError: If pepper with same name exists
        """
        # Encode bytes to base64 for JSON transport
        pepper_b64 = base64.b64encode(pepper_encrypted).decode("ascii")

        return self._make_request(
            "POST",
            "/peppers",
            json_data={
                "name": name,
                "pepper_encrypted": pepper_b64,
                "description": description,
            },
        )

    def get_pepper(self, name: str) -> bytes:
        """
        Retrieve encrypted pepper from server.

        Args:
            name: Pepper name

        Returns:
            Encrypted pepper bytes (must be decrypted client-side)

        Raises:
            PepperError: If pepper not found
        """
        response = self._make_request("GET", f"/peppers/{name}")
        pepper_b64 = response["pepper_encrypted"]
        return base64.b64decode(pepper_b64)

    def list_peppers(self) -> List[Dict]:
        """
        List all peppers (metadata only, no encrypted data).

        Returns:
            List of pepper metadata dicts (name, description, created_at, updated_at, access_count)
        """
        response = self._make_request("GET", "/peppers")
        return response["peppers"]

    def update_pepper(self, name: str, pepper_encrypted: bytes, description: Optional[str] = None) -> Dict:
        """
        Update existing pepper.

        Args:
            name: Pepper name
            pepper_encrypted: New encrypted pepper bytes
            description: Optional new description

        Returns:
            Updated pepper metadata

        Raises:
            PepperError: If pepper not found
        """
        pepper_b64 = base64.b64encode(pepper_encrypted).decode("ascii")

        data = {"pepper_encrypted": pepper_b64}
        if description is not None:
            data["description"] = description

        return self._make_request("PUT", f"/peppers/{name}", json_data=data)

    def delete_pepper(self, name: str) -> Dict:
        """
        Delete specific pepper.

        Args:
            name: Pepper name

        Returns:
            Deletion confirmation

        Raises:
            PepperError: If pepper not found
        """
        return self._make_request("DELETE", f"/peppers/{name}")

    # Dead Man's Switch

    def get_deadman_status(self) -> Dict:
        """
        Get dead man's switch status.

        Returns:
            Dict with: configured, enabled, interval_seconds, grace_period_seconds,
                      last_checkin, next_deadline, time_remaining_seconds,
                      panic_triggered, panic_triggered_at
        """
        return self._make_request("GET", "/deadman")

    def configure_deadman(self, interval: str, grace_period: str, enabled: bool = True) -> Dict:
        """
        Configure dead man's switch.

        The dead man's switch will automatically delete ALL peppers if you don't
        check in within the specified interval + grace period.

        Args:
            interval: Check-in interval (e.g., "7d", "24h", "30m")
            grace_period: Grace period after deadline (e.g., "24h", "12h")
            enabled: Whether to enable the switch

        Returns:
            Dead man's switch status

        Note:
            - Must check in at least every <interval> to prevent automatic wipe
            - Grace period gives extra time after deadline before panic trigger
            - Minimum interval: 1 hour, minimum grace: 1 hour
        """
        return self._make_request(
            "PUT",
            "/deadman",
            json_data={
                "interval": interval,
                "grace_period": grace_period,
                "enabled": enabled,
            },
        )

    def checkin(self) -> Dict:
        """
        Check in to reset dead man's switch timer.

        Returns:
            Updated dead man's switch status with new deadline

        Note:
            Call this periodically to prevent automatic pepper wipe
        """
        return self._make_request("POST", "/deadman/checkin")

    def disable_deadman(self) -> Dict:
        """
        Disable dead man's switch.

        Returns:
            Confirmation message
        """
        return self._make_request("DELETE", "/deadman")

    # Panic Operations

    def panic_all(self, totp_code: str) -> Dict:
        """
        EMERGENCY: Delete ALL peppers immediately.

        DESTRUCTIVE: This cannot be undone!
        Requires TOTP verification.

        Args:
            totp_code: TOTP code for verification

        Returns:
            Dict with: message, peppers_wiped (count)

        Raises:
            TOTPRequiredError: If TOTP not configured or code invalid
        """
        return self._make_request("POST", "/panic", totp_code=totp_code)

    def panic_single(self, name: str, totp_code: str) -> Dict:
        """
        EMERGENCY: Delete specific pepper immediately.

        DESTRUCTIVE: This cannot be undone!
        Requires TOTP verification.

        Args:
            name: Pepper name to delete
            totp_code: TOTP code for verification

        Returns:
            Dict with: message, peppers_wiped (should be 1)

        Raises:
            TOTPRequiredError: If TOTP not configured or code invalid
        """
        return self._make_request("POST", f"/panic/{name}", totp_code=totp_code)
