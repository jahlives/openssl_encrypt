#!/usr/bin/env python3
"""
Yubikey Challenge-Response HSM Plugin

This plugin implements hardware-bound key derivation using Yubikey's
Challenge-Response mode (HMAC-SHA1). It enhances encryption security by
adding a hardware-specific pepper value that cannot be extracted from
the encrypted file.

Security Model:
- Salt from encryption is used as Challenge to Yubikey
- Yubikey's HMAC-SHA1 Response becomes the hsm_pepper
- Pepper is combined with password+salt in key derivation
- Pepper is NEVER stored - requires Yubikey present for decryption

Supported Modes:
- Auto-detection: Automatically finds Yubikey slot with Challenge-Response configured
- Manual slot: Specify slot 1 or 2 via configuration

Requirements:
- yubikey-manager library (ykman)
- Yubikey with Challenge-Response configured (OATH-HOTP or Yubico OTP slot)

Usage:
    encrypt --hsm yubikey file.txt file.enc
    encrypt --hsm yubikey --hsm-slot 1 file.txt file.enc
"""

import logging
from typing import Any, Dict, Set

try:
    from ...modules.plugin_system import (
        HSMPlugin,
        PluginCapability,
        PluginResult,
        PluginSecurityContext,
    )
except ImportError:
    # Fallback for different import paths
    import os
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))
    from modules.plugin_system import (
        HSMPlugin,
        PluginCapability,
        PluginResult,
        PluginSecurityContext,
    )

logger = logging.getLogger(__name__)


class YubikeyHSMPlugin(HSMPlugin):
    """
    Yubikey Challenge-Response HSM plugin for hardware-bound key derivation.
    """

    def __init__(self):
        super().__init__(
            plugin_id="yubikey_hsm", name="Yubikey Challenge-Response HSM", version="1.0.0"
        )
        self._ykman_available = None
        self._cached_slot = None

    def get_required_capabilities(self) -> Set[PluginCapability]:
        """Yubikey HSM requires no file system capabilities."""
        return {PluginCapability.ACCESS_CONFIG, PluginCapability.WRITE_LOGS}

    def get_description(self) -> str:
        return (
            "Hardware-bound key derivation using Yubikey Challenge-Response mode. "
            "Enhances encryption security by adding a hardware-specific pepper value "
            "derived from Yubikey HMAC-SHA1 Challenge-Response."
        )

    def _check_ykman_available(self) -> bool:
        """Check if yubikey-manager is available."""
        if self._ykman_available is None:
            try:
                import ykman

                self._ykman_available = True
            except ImportError:
                self._ykman_available = False
        return self._ykman_available

    def _find_challenge_response_slot(self) -> int:
        """
        Auto-detect which Yubikey slot has Challenge-Response configured.

        Returns:
            Slot number (1 or 2) or None if not found
        """
        try:
            from ykman.device import list_all_devices
            from yubikit.core.smartcard import SmartCardConnection
            from yubikit.yubiotp import YubiOtpSession

            # Find connected Yubikey
            devices, _ = list_all_devices()
            if not devices:
                self.logger.error("No Yubikey device found")
                return None

            # Use first device
            device = devices[0]

            # Open connection and check slots
            with device.open_connection(SmartCardConnection) as conn:
                session = YubiOtpSession(conn)

                # Check slot 1
                try:
                    config1 = session.get_config_state()
                    if config1.is_configured(1):
                        self.logger.info("Challenge-Response found on slot 1")
                        return 1
                except Exception as e:
                    self.logger.debug(f"Slot 1 check failed: {e}")

                # Check slot 2
                try:
                    config2 = session.get_config_state()
                    if config2.is_configured(2):
                        self.logger.info("Challenge-Response found on slot 2")
                        return 2
                except Exception as e:
                    self.logger.debug(f"Slot 2 check failed: {e}")

            return None

        except Exception as e:
            self.logger.error(f"Error detecting Yubikey slot: {e}")
            return None

    def _calculate_challenge_response(self, challenge: bytes, slot: int) -> bytes:
        """
        Perform Challenge-Response operation with Yubikey.

        Args:
            challenge: Challenge bytes (salt)
            slot: Yubikey slot (1 or 2)

        Returns:
            Response bytes (hsm_pepper)

        Raises:
            Exception: If Yubikey operation fails
        """
        try:
            from ykman.device import list_all_devices
            from yubikit.core.smartcard import SmartCardConnection
            from yubikit.yubiotp import YubiOtpSession

            # Find connected Yubikey
            devices, _ = list_all_devices()
            if not devices:
                raise RuntimeError("No Yubikey device found")

            device = devices[0]

            # Perform Challenge-Response
            with device.open_connection(SmartCardConnection) as conn:
                session = YubiOtpSession(conn)

                # Calculate response (HMAC-SHA1)
                # Yubikey Challenge-Response produces 20-byte HMAC-SHA1
                response = session.calculate_hmac_sha1(slot, challenge)

                self.logger.info(
                    f"Challenge-Response successful: "
                    f"challenge={len(challenge)} bytes, "
                    f"response={len(response)} bytes"
                )

                return response

        except ImportError as e:
            raise RuntimeError(
                f"yubikey-manager library not installed: {e}. "
                f"Install with: pip install yubikey-manager"
            )
        except Exception as e:
            raise RuntimeError(f"Yubikey Challenge-Response failed: {e}")

    def get_hsm_pepper(self, salt: bytes, context: PluginSecurityContext) -> PluginResult:
        """
        Derive HSM pepper from salt using Yubikey Challenge-Response.

        Args:
            salt: The encryption salt (16 bytes) to use as challenge
            context: Security context with optional slot configuration

        Returns:
            PluginResult with hsm_pepper in data['hsm_pepper']
        """
        try:
            # Check if yubikey-manager is available
            if not self._check_ykman_available():
                return PluginResult.error_result(
                    "yubikey-manager library not installed. "
                    "Install with: pip install yubikey-manager"
                )

            # Validate salt
            if not salt or len(salt) != 16:
                return PluginResult.error_result(
                    f"Invalid salt length: expected 16 bytes, got {len(salt) if salt else 0}"
                )

            # Determine slot (manual or auto-detect)
            slot = context.config.get("slot")

            if slot:
                # Manual slot specified
                if slot not in [1, 2]:
                    return PluginResult.error_result(
                        f"Invalid Yubikey slot: {slot}. Must be 1 or 2."
                    )
                self.logger.info(f"Using manually specified slot {slot}")
            else:
                # Auto-detect slot
                if self._cached_slot:
                    slot = self._cached_slot
                    self.logger.info(f"Using cached slot {slot}")
                else:
                    self.logger.info("Auto-detecting Challenge-Response slot...")
                    slot = self._find_challenge_response_slot()

                    if not slot:
                        return PluginResult.error_result(
                            "No Yubikey with Challenge-Response found. "
                            "Configure Challenge-Response on your Yubikey or specify slot with --hsm-slot"
                        )

                    self._cached_slot = slot
                    self.logger.info(f"Auto-detected slot {slot}")

            # Perform Challenge-Response
            self.logger.info(f"Performing Challenge-Response with Yubikey slot {slot}...")
            response = self._calculate_challenge_response(salt, slot)

            # Response is the hsm_pepper (20 bytes HMAC-SHA1)
            return PluginResult.success_result(
                f"Yubikey Challenge-Response successful (slot {slot})",
                data={"hsm_pepper": response, "slot": slot},
            )

        except Exception as e:
            error_msg = f"Yubikey HSM plugin error: {str(e)}"
            self.logger.error(error_msg)
            return PluginResult.error_result(error_msg)

    def initialize(self, config: Dict[str, Any]) -> PluginResult:
        """Initialize plugin with configuration."""
        self.logger.info("Initializing Yubikey HSM plugin")

        # Check if yubikey-manager is available
        if not self._check_ykman_available():
            return PluginResult.error_result(
                "yubikey-manager library not available. "
                "Install with: pip install yubikey-manager"
            )

        return PluginResult.success_result("Yubikey HSM plugin initialized")
