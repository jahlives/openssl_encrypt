#!/usr/bin/env python3
"""
Keyserver Plugin - Fetch public keys from remote keyserver.

This plugin enables fetching public keys from a remote keyserver for
asymmetric encryption. It provides a secure, opt-in mechanism for
key distribution.

SECURITY GUARANTEES:
- Plugin NEVER receives private keys or passwords
- Plugin ONLY receives identifier strings for search
- Plugin ONLY returns public keys (PublicKeyBundle)
- All bundles cryptographically verified before use
- OPT-IN by default (disabled)
- Local keyring always checked first

Features:
- SQLite cache with TTL for performance
- HTTPS-only communication with keyserver
- API token authentication for uploads
- Self-signature verification of all keys
- Interactive trust confirmation for new keys
"""

from .cache import KeyserverCache
from .config import KeyserverConfig
from .keyserver_plugin import KeyserverPlugin

__all__ = ["KeyserverPlugin", "KeyserverConfig", "KeyserverCache"]
