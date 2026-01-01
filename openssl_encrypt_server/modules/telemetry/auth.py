#!/usr/bin/env python3
"""
Telemetry-specific authentication.

Initializes TokenAuth with telemetry-specific configuration.
"""

import logging
from typing import Optional

from ...core.auth.token import TokenAuth, TokenConfig
from .models import TMClient

logger = logging.getLogger(__name__)

# Module-specific auth instance
_telemetry_auth: Optional[TokenAuth] = None


def init_telemetry_auth(config) -> TokenAuth:
    """
    Initialize Telemetry authentication.

    Args:
        config: Telemetry configuration with token settings

    Returns:
        TokenAuth: Initialized auth handler
    """
    global _telemetry_auth

    logger.info("Initializing Telemetry authentication...")

    token_config = TokenConfig(
        secret=config.token.secret,
        algorithm=config.token.algorithm,
        expiry_days=config.token.expiry_days,
        issuer=config.token.issuer,  # "openssl_encrypt_telemetry"
    )

    _telemetry_auth = TokenAuth(config=token_config, client_model=TMClient)

    logger.info(f"Telemetry auth initialized with issuer: {config.token.issuer}")

    return _telemetry_auth


def get_telemetry_auth() -> TokenAuth:
    """
    Get Telemetry auth instance.

    Returns:
        TokenAuth: Auth handler

    Raises:
        RuntimeError: If auth not initialized
    """
    if not _telemetry_auth:
        raise RuntimeError(
            "Telemetry auth not initialized. Call init_telemetry_auth() first."
        )
    return _telemetry_auth
