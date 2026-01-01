#!/usr/bin/env python3
"""
Pepper authentication handler.

Unified authentication that delegates to either ProxyAuth or MTLSAuth based on
configuration.
"""

import logging
from typing import Optional

from fastapi import Request

from ...core.auth.mtls import MTLSAuth
from ...core.auth.proxy import ProxyAuth
from ...config import PepperConfig

logger = logging.getLogger(__name__)


class PepperAuthHandler:
    """
    Unified authentication handler for Pepper module.

    Delegates to either ProxyAuth (Nginx terminates mTLS) or MTLSAuth (direct mTLS)
    based on configuration.

    The handler returns the client certificate fingerprint which is used as the
    primary identifier for pepper clients.
    """

    def __init__(self, config: PepperConfig):
        """
        Initialize pepper auth handler.

        Args:
            config: PepperConfig with auth mode and settings
        """
        self.mode = config.auth_mode

        if self.mode == "proxy":
            # Proxy mode: Nginx terminates mTLS, passes headers
            self.handler = ProxyAuth(
                fingerprint_header=config.proxy.fingerprint_header,
                trusted_proxies=config.proxy.trusted_proxies,
                dn_header=config.proxy.dn_header,
                verify_header=config.proxy.verify_header,
            )
            logger.info("Pepper auth: proxy mode")
        elif self.mode == "mtls":
            # Direct mTLS: Server handles TLS
            self.handler = MTLSAuth()
            logger.info("Pepper auth: direct mTLS mode")
        else:
            raise ValueError(f"Unknown pepper auth mode: {self.mode}")

    async def get_client_fingerprint(self, request: Request) -> str:
        """
        Get client certificate fingerprint.

        Args:
            request: FastAPI Request object

        Returns:
            SHA-256 certificate fingerprint (64 hex chars, lowercase)

        Raises:
            HTTPException: 401/403 on authentication failure
        """
        return await self.handler.get_client_fingerprint(request)

    async def get_client_dn(self, request: Request) -> Optional[str]:
        """
        Get client certificate Distinguished Name.

        Args:
            request: FastAPI Request object

        Returns:
            Certificate DN if available, None otherwise
        """
        return await self.handler.get_client_dn(request)


# Global pepper auth instance
_pepper_auth: Optional[PepperAuthHandler] = None


def init_pepper_auth(config: PepperConfig):
    """
    Initialize global pepper auth handler.

    Args:
        config: PepperConfig instance
    """
    global _pepper_auth
    _pepper_auth = PepperAuthHandler(config)
    logger.info("Pepper authentication initialized")


def get_pepper_auth() -> PepperAuthHandler:
    """
    Get global pepper auth handler.

    Returns:
        PepperAuthHandler instance

    Raises:
        RuntimeError: If auth not initialized
    """
    if not _pepper_auth:
        raise RuntimeError("Pepper auth not initialized. Call init_pepper_auth() first.")
    return _pepper_auth


# FastAPI dependency for routes
async def require_pepper_auth(request: Request) -> str:
    """
    FastAPI dependency for pepper authentication.

    Returns certificate fingerprint for authenticated clients.

    Args:
        request: FastAPI Request object

    Returns:
        Client certificate fingerprint

    Raises:
        HTTPException: 401/403 on authentication failure
    """
    auth = get_pepper_auth()
    return await auth.get_client_fingerprint(request)
