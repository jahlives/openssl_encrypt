#!/usr/bin/env python3
"""
Keyserver-specific authentication.

Initializes TokenAuth with keyserver-specific configuration.
"""

import logging
from typing import Optional

from ...core.auth.token import TokenAuth, TokenConfig
from .models import KSClient

logger = logging.getLogger(__name__)

# Module-specific auth instance
_keyserver_auth: Optional[TokenAuth] = None


def init_keyserver_auth(config) -> TokenAuth:
    """
    Initialize Keyserver authentication.

    Args:
        config: Keyserver configuration with token settings

    Returns:
        TokenAuth: Initialized auth handler
    """
    global _keyserver_auth

    logger.info("Initializing Keyserver authentication...")

    token_config = TokenConfig(
        secret=config.token.secret,
        algorithm=config.token.algorithm,
        expiry_days=config.token.expiry_days,
        issuer=config.token.issuer,  # "openssl_encrypt_keyserver"
    )

    _keyserver_auth = TokenAuth(config=token_config, client_model=KSClient)

    logger.info(f"Keyserver auth initialized with issuer: {config.token.issuer}")

    return _keyserver_auth


def get_keyserver_auth() -> TokenAuth:
    """
    Get Keyserver auth instance.

    Returns:
        TokenAuth: Auth handler

    Raises:
        RuntimeError: If auth not initialized
    """
    if not _keyserver_auth:
        raise RuntimeError("Keyserver auth not initialized. Call init_keyserver_auth() first.")
    return _keyserver_auth
