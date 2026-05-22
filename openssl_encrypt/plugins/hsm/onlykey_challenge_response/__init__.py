#!/usr/bin/env python3
"""
OnlyKey Challenge-Response HSM Plugin

This plugin implements hardware-bound key derivation using OnlyKey's
HMAC-SHA1 Challenge-Response mode. OnlyKey speaks the same HMAC-SHA1
wire protocol as YubiKey — only the USB VID/PID differs
(0x1d50:0x60fc vs Yubico's 0x1050).

Security Model:
- Salt from encryption is used as Challenge to the OnlyKey
- OnlyKey's HMAC-SHA1 Response becomes the hsm_pepper
- Pepper is combined with password+salt in key derivation
- Pepper is NEVER stored - requires OnlyKey present for decryption

Cross-Device Compatibility:
- A single 20-byte HMAC-SHA1 secret loaded identically on a YubiKey and an
  OnlyKey will produce identical responses for identical challenges, since
  HMAC-SHA1 is fully specified by RFC 2104. This allows users to encrypt
  with one device and decrypt with another in the same fleet.

Requirements:
- OnlyKey device with HMAC-SHA1 challenge-response configured
  (configure via the official OnlyKey App on slot 1 or 2)
- yubikit (Python — transitively from yubikey-manager) for the OTP
  protocol; OnlyKey speaks the same protocol over its own USB VID/PID
- hidapi (transitively present via yubikit)

Usage:
    encrypt --hsm onlykey file.txt file.enc
    encrypt --hsm onlykey --hsm-slot 1 file.txt file.enc
"""

import logging
import sys
from typing import Iterable, List, Set, Tuple

from ....modules.plugin_system.plugin_base import (
    HSMPlugin,
    PluginCapability,
    PluginResult,
    PluginSecurityContext,
)

logger = logging.getLogger(__name__)


class OnlykeyHSMPlugin(HSMPlugin):
    """
    OnlyKey Challenge-Response HSM plugin for hardware-bound key derivation.

    Mirrors YubikeyHSMPlugin's behavior but enumerates OnlyKey USB devices
    (VID/PID 0x1d50:0x60fc) and reuses the YubiKey HMAC-SHA1 wire protocol.
    """

    # OnlyKey USB identifiers (https://docs.crp.to / hardware spec)
    ONLYKEY_VID = 0x1D50
    ONLYKEY_PID = 0x60FC

    def __init__(self):
        super().__init__(
            plugin_id="onlykey_hsm",
            name="OnlyKey Challenge-Response HSM",
            version="1.0.0",
        )
        self._libs_available = None
        self._cached_slot = None

    def _check_libs_available(self) -> bool:
        """
        Memoized probe: are the underlying HID + yubikit libraries importable?

        OnlyKey reuses YubiKey's HMAC-SHA1 wire protocol, so we depend on the
        same yubikit OTP machinery the YubikeyHSMPlugin uses. The actual HID
        device enumeration is done via ykman's per-platform HID helpers
        because we need raw access to non-Yubico VID/PID devices.
        """
        if self._libs_available is None:
            try:
                import yubikit.core.otp  # noqa: F401
                import yubikit.yubiotp  # noqa: F401

                self._libs_available = True
            except ImportError:
                self._libs_available = False
        return self._libs_available

    def get_required_capabilities(self) -> Set[PluginCapability]:
        """OnlyKey HSM requires no file system capabilities."""
        return {PluginCapability.ACCESS_CONFIG, PluginCapability.WRITE_LOGS}

    def get_description(self) -> str:
        return (
            "Hardware-bound key derivation using OnlyKey HMAC-SHA1 "
            "Challenge-Response. Provides cross-device-compatible hardware "
            "pepper derivation in the same fleet as YubiKey devices loaded "
            "with the same 20-byte secret."
        )

    def _enumerate_hidraw(self) -> Iterable[Tuple[str, int, int]]:
        """
        Yield (path, vid, pid) for every HID device on the current platform.

        Reuses ykman's per-platform HID enumeration primitives so we benefit
        from its existing handling of permissions, raw device parsing, and
        path conventions across Linux / macOS / Windows / FreeBSD.

        OnlyKey-specific filtering is done by the caller (_list_onlykey_devices).
        """
        platform = sys.platform
        if platform == "linux":
            import glob

            from ykman.hid.linux import get_info

            for hidraw in glob.glob("/dev/hidraw*"):
                try:
                    with open(hidraw, "rb") as f:
                        _bustype, vid, pid = get_info(f)
                    yield hidraw, vid, pid
                except Exception:
                    continue
        elif platform == "darwin":
            from ykman.hid.macos import list_paths  # type: ignore

            for path, vid, pid in list_paths():
                yield path, vid, pid
        elif platform == "win32":
            from ykman.hid.windows import list_paths  # type: ignore

            for path, vid, pid in list_paths():
                yield path, vid, pid
        elif platform.startswith("freebsd"):
            from ykman.hid.freebsd import list_paths  # type: ignore

            for path, vid, pid in list_paths():
                yield path, vid, pid
        else:
            raise NotImplementedError(
                f"OnlyKey HID enumeration not implemented on platform {platform!r}"
            )

    def _make_otp_device(self, path: str, pid: int):
        """
        Construct an OtpYubiKeyDevice for a given HID path.

        OnlyKey speaks the YubiKey HMAC-SHA1 wire protocol, so we reuse
        ykman's OtpYubiKeyDevice + HidrawConnection (Linux) / equivalent
        on other platforms. The PID is passed through because YubiOtpSession
        consults it for protocol-version negotiation.
        """
        platform = sys.platform
        if platform == "linux":
            from ykman.hid.base import OtpYubiKeyDevice
            from ykman.hid.linux import HidrawConnection

            return OtpYubiKeyDevice(path, pid, HidrawConnection)
        elif platform == "darwin":
            from ykman.hid.base import OtpYubiKeyDevice
            from ykman.hid.macos import MacHidOtpConnection  # type: ignore

            return OtpYubiKeyDevice(path, pid, MacHidOtpConnection)
        elif platform == "win32":
            from ykman.hid.base import OtpYubiKeyDevice
            from ykman.hid.windows import WinHidOtpConnection  # type: ignore

            return OtpYubiKeyDevice(path, pid, WinHidOtpConnection)
        elif platform.startswith("freebsd"):
            from ykman.hid.base import OtpYubiKeyDevice
            from ykman.hid.freebsd import FreeBsdHidOtpConnection  # type: ignore

            return OtpYubiKeyDevice(path, pid, FreeBsdHidOtpConnection)
        else:
            raise NotImplementedError(
                f"OnlyKey HID device construction not implemented on platform {platform!r}"
            )

    def _list_onlykey_devices(self) -> List:
        """Return list of OnlyKey OtpYubiKeyDevice handles currently attached."""
        devices = []
        for path, vid, pid in self._enumerate_hidraw():
            if vid == self.ONLYKEY_VID and pid == self.ONLYKEY_PID:
                devices.append(self._make_otp_device(path, pid))
        return devices

    def get_hsm_pepper(
        self, salt: bytes, context: PluginSecurityContext
    ) -> PluginResult:
        """Derive HSM pepper from salt. Implementation forthcoming."""
        return PluginResult.error_result(
            "OnlyKey HSM plugin not yet implemented"
        )
