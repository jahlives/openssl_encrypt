"""HSM (Hardware Security Module) plugins for OpenSSL Encrypt."""

from .yubikey_challenge_response import YubikeyHSMPlugin

__all__ = ["YubikeyHSMPlugin"]
