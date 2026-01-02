"""HSM (Hardware Security Module) plugins for OpenSSL Encrypt."""

from .yubikey_challenge_response import YubikeyHSMPlugin
from .fido2_pepper import FIDO2HSMPlugin

__all__ = ["YubikeyHSMPlugin", "FIDO2HSMPlugin"]
