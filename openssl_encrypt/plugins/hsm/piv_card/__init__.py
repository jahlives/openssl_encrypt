#!/usr/bin/env python3
"""PIV / PKCS#11 HSM Plugin.

Hardware-bound key derivation using a PIV application on a PKCS#11 token. The
PIV private key signs a deterministic challenge derived from the encryption
salt, and the raw signature is normalized into a fixed-length pepper via
HKDF-SHA256.

Security Model:
- The encryption salt is turned into a 64-byte signing challenge (HKDF).
- The PIV key signs the challenge; the signature is HKDF'd into the pepper.
- The pepper is NEVER stored -- the token must be present for decryption.
- The same private key imported on multiple tokens yields identical peppers,
  enabling multi-device redundancy (deterministic schemes only: Ed25519 and
  RSA PKCS#1 v1.5; ECDSA / RSA-PSS are rejected).

Supported hardware:
- YubiKey Bio MPE (PIV, Ed25519 or RSA)
- Token2 PIN+ R3.3+ (PIV, RSA-2048/3072/4096)
- Any PKCS#11-compliant PIV smart card or token

Requirements:
- python-pkcs11 (imported as ``pkcs11``)
- A PKCS#11 module (e.g. opensc-pkcs11.so or ykcs11.so), path supplied by config

Configuration (via the HSM security context ``config``):
- ``pkcs11_lib_path`` (required): path to the PKCS#11 .so/.dll
- ``slot_index`` (default 0): PKCS#11 slot index
- ``piv_slot`` (default 0x9A): PIV key slot (0x9A/0x9C/0x9D/0x9E)
- ``pepper_length`` (default 32): pepper length in bytes
- ``biometric`` (default False): True for Bio keys -- skips the PIN prompt
"""

import getpass
import logging
from typing import Any, Callable, Dict, Optional, Set

from ....modules.piv_backend import PIVBackend, PIVError
from ....modules.plugin_system.plugin_base import (
    HSMPlugin,
    PluginCapability,
    PluginResult,
    PluginSecurityContext,
)

logger = logging.getLogger(__name__)


def _default_pin_provider() -> bytearray:
    """Prompt for the PIV PIN with getpass (never echoes, never via argv).

    Returns a bytearray so the caller can zero it. An empty entry signals the
    biometric / no-PIN flow.
    """
    pin_str = getpass.getpass("Enter PIV PIN (leave empty for biometric/touch): ")
    return bytearray(pin_str.encode("utf-8"))


class PIVHSMPlugin(HSMPlugin):
    """PIV/PKCS#11 HSM plugin for hardware-bound key derivation."""

    def __init__(self, pin_provider: Optional[Callable[[], bytearray]] = None):
        super().__init__(
            plugin_id="piv_hsm",
            name="PIV/PKCS#11 HSM",
            version="1.0.0",
        )
        self._pin_provider = pin_provider or _default_pin_provider

    def get_required_capabilities(self) -> Set[PluginCapability]:
        return {PluginCapability.ACCESS_CONFIG, PluginCapability.WRITE_LOGS}

    def get_description(self) -> str:
        return (
            "Hardware-bound key derivation using a PIV application on a PKCS#11 token. "
            "Signs a deterministic challenge with the PIV key (Ed25519 or RSA PKCS#1 v1.5) "
            "and derives a fixed-length pepper via HKDF-SHA256. Supports YubiKey Bio MPE, "
            "Token2 PIN+, and any PKCS#11-compliant PIV smart card."
        )

    def get_hsm_pepper(self, salt: bytes, context: PluginSecurityContext) -> PluginResult:
        """Derive the HSM pepper from the salt using the PIV key.

        Per the HSMPlugin contract this returns a PluginResult and does not raise.
        The PIN is obtained via getpass (unless biometric) and is never logged or
        included in the result.
        """
        try:
            config = context.config or {}
            lib_path = config.get("pkcs11_lib_path")
            if not lib_path:
                return PluginResult.error_result(
                    "PIV HSM requires 'pkcs11_lib_path' (path to a PKCS#11 module such as "
                    "opensc-pkcs11.so or ykcs11.so). Provide it via --hsm-pkcs11-lib."
                )

            if not salt or len(salt) != 16:
                return PluginResult.error_result(
                    f"Invalid salt length: expected 16 bytes, got {len(salt) if salt else 0}"
                )

            slot_index = config.get("slot_index", 0)
            piv_slot = config.get("piv_slot", 0x9A)
            pepper_length = config.get("pepper_length", 32)
            biometric = bool(config.get("biometric", False))

            backend = PIVBackend(
                lib_path,
                slot_index=slot_index,
                piv_slot=piv_slot,
                pepper_length=pepper_length,
            )

            pin = None
            if not biometric:
                provided = self._pin_provider()
                # An empty PIN entry means "use the biometric / no-PIN flow".
                pin = provided if provided else None

            self.logger.info("Deriving PIV pepper (slot %#x)...", piv_slot)
            pepper = backend.get_pepper(bytes(salt), pin=pin)

            return PluginResult.success_result(
                f"PIV pepper derived (PIV slot {piv_slot:#x})",
                data={"hsm_pepper": pepper, "piv_slot": piv_slot},
            )

        except PIVError as exc:
            # PIVError messages are PIN-free by construction.
            msg = f"PIV HSM error: {exc}"
            self.logger.error(msg)
            return PluginResult.error_result(msg)
        except Exception:  # never leak details from an unexpected failure
            self.logger.error("PIV HSM plugin encountered an unexpected error")
            return PluginResult.error_result("PIV HSM error: unexpected failure")

    def initialize(self, config: Dict[str, Any]) -> PluginResult:
        self.logger.info("Initializing PIV/PKCS#11 HSM plugin")
        return PluginResult.success_result("PIV HSM plugin initialized")
