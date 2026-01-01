#!/usr/bin/env python3
"""
Integrity Authentication Handler

Provides mTLS-based authentication for integrity verification endpoints.
Uses the same ProxyAuth/MTLSAuth handlers as the pepper module.
"""

import logging
from typing import Optional

from fastapi import Depends, Request

from ...core.auth.mtls import MTLSAuth
from ...core.auth.proxy import ProxyAuth

logger = logging.getLogger(__name__)

# Global auth handler instance
_integrity_auth_handler: Optional["IntegrityAuthHandler"] = None


class IntegrityAuthHandler:
    """
    Unified mTLS authentication handler for integrity module.

    Delegates to ProxyAuth or MTLSAuth based on configuration.
    """

    def __init__(self, config):
        """
        Initialize integrity auth handler.

        Args:
            config: IntegrityConfig instance with auth_mode setting
        """
        self.config = config
        self.auth_mode = config.auth_mode

        if self.auth_mode == "proxy":
            # Proxy mode: Nginx terminates mTLS, passes cert fingerprint in header
            self.handler = ProxyAuth(
                fingerprint_header=config.proxy.fingerprint_header,
                trusted_proxies=config.proxy.trusted_proxies,
                dn_header=config.proxy.dn_header,
                verify_header=config.proxy.verify_header,
            )
            logger.info("Integrity auth: proxy mode")
        elif self.auth_mode == "mtls":
            # Direct mTLS mode: Server terminates TLS, extracts cert from SSL context
            self.handler = MTLSAuth()
            logger.info("Integrity auth: direct mTLS mode")
        else:
            raise ValueError(f"Invalid integrity auth_mode: {self.auth_mode}")

    async def get_client_fingerprint(self, request: Request) -> str:
        """
        Extract and validate client certificate fingerprint.

        Args:
            request: FastAPI Request object

        Returns:
            Normalized certificate fingerprint (SHA-256, 64 hex chars)

        Raises:
            HTTPException: 401/403 for authentication failures
        """
        return await self.handler.get_client_fingerprint(request)

    async def get_client_dn(self, request: Request) -> Optional[str]:
        """
        Extract client certificate Distinguished Name (DN).

        Args:
            request: FastAPI Request object

        Returns:
            Certificate DN if available, None otherwise
        """
        return await self.handler.get_client_dn(request)


def init_integrity_auth(config):
    """
    Initialize global integrity authentication handler.

    Args:
        config: IntegrityConfig instance
    """
    global _integrity_auth_handler
    _integrity_auth_handler = IntegrityAuthHandler(config)
    logger.info("Integrity authentication initialized")


def get_integrity_auth() -> IntegrityAuthHandler:
    """
    Get the global integrity authentication handler.

    Returns:
        IntegrityAuthHandler instance

    Raises:
        RuntimeError: If auth not initialized
    """
    if _integrity_auth_handler is None:
        raise RuntimeError("Integrity authentication not initialized")
    return _integrity_auth_handler


async def require_integrity_auth(request: Request) -> str:
    """
    FastAPI dependency for integrity authentication.

    Validates client certificate and returns fingerprint.

    Args:
        request: FastAPI Request object

    Returns:
        Client certificate fingerprint (SHA-256)

    Raises:
        HTTPException: 401/403 for authentication failures
    """
    auth = get_integrity_auth()
    return await auth.get_client_fingerprint(request)


async def get_client_info(request: Request) -> tuple[str, Optional[str]]:
    """
    FastAPI dependency to get client fingerprint and DN.

    Args:
        request: FastAPI Request object

    Returns:
        Tuple of (fingerprint, dn)
    """
    auth = get_integrity_auth()
    fingerprint = await auth.get_client_fingerprint(request)
    dn = await auth.get_client_dn(request)
    return fingerprint, dn
