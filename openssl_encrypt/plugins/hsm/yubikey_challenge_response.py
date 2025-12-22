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
            from yubikit.core.otp import OtpConnection
            from yubikit.yubiotp import YubiOtpSession

            # Find connected Yubikey
            result = list_all_devices()
            # Handle different API versions: newer returns list, older returns (list, state)
            devices = result if isinstance(result, list) else result[0]
            if not devices:
                self.logger.error("No Yubikey device found")
                return None

            # Use first device - handle tuple format (device, device_info)
            device_entry = devices[0]
            device = device_entry[0] if isinstance(device_entry, tuple) else device_entry

            # Open connection and check slots via OTP (HID) interface
            with device.open_connection(OtpConnection) as conn:
                session = YubiOtpSession(conn)

                # Get config state once
                config = session.get_config_state()

                # Check both slots - try to use them, not just check if configured
                # because is_configured() doesn't tell us if it's Challenge-Response
                for slot in [1, 2]:
                    if config.is_configured(slot):
                        # Try a test challenge to verify it's actually Challenge-Response
                        try:
                            test_challenge = b'\x00' * 16
                            session.calculate_hmac_sha1(slot, test_challenge)
                            self.logger.info(f"Challenge-Response found on slot {slot}")
                            return slot
                        except Exception as e:
                            self.logger.debug(f"Slot {slot} configured but not for Challenge-Response: {e}")
                            continue

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
            from yubikit.core.otp import OtpConnection
            from yubikit.yubiotp import YubiOtpSession

            # Find connected Yubikey
            result = list_all_devices()
            # Handle different API versions: newer returns list, older returns (list, state)
            devices = result if isinstance(result, list) else result[0]
            if not devices:
                raise RuntimeError("No Yubikey device found")

            # Use first device - handle tuple format (device, device_info)
            device_entry = devices[0]
            device = device_entry[0] if isinstance(device_entry, tuple) else device_entry

            # Perform Challenge-Response via OTP (HID) interface
            with device.open_connection(OtpConnection) as conn:
                session = YubiOtpSession(conn)

                # Prompt user to touch Yubikey if required
                self.logger.info(f"Performing Challenge-Response on slot {slot}...")
                self.logger.info("👆 Touch your Yubikey if touch is required")

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
            import traceback
            error_details = f"{type(e).__name__}: {str(e)}\n{traceback.format_exc()}"
            self.logger.error(f"Challenge-Response exception details: {error_details}")
            raise RuntimeError(f"Yubikey Challenge-Response failed: {str(e)}") from e

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
            print(f"👆 Touch your Yubikey now (slot {slot})...")
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
