#!/usr/bin/env python3
"""
Keyserver Configuration

This module handles server configuration with environment variable support.

SECURITY:
- Database credentials from environment variables
- API token validation configuration
- CORS settings for security
"""

import logging
import os
from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Server settings with environment variable support.

    All settings can be overridden via environment variables.
    Example: DATABASE_URL, API_TOKEN_SECRET, etc.
    """

    # Application
    app_name: str = "OpenSSL Encrypt Keyserver"
    version: str = "1.0.0"
    debug: bool = False

    # Database - MUST be set via environment variable
    database_url: str = os.getenv("DATABASE_URL", "")

    # Security - MUST be set via environment variable (min 32 chars)
    api_token_secret: str = os.getenv("API_TOKEN_SECRET", "")
    cors_origins: List[str] = ["*"]  # Configure appropriately in production

    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_requests_per_minute: int = 60
    rate_limit_upload_per_day: int = 10

    # Allowed algorithms (strict PQC only)
    allowed_kem_algorithms: List[str] = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
    allowed_signing_algorithms: List[str] = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]

    class Config:
        env_file = ".env"
        case_sensitive = False


def validate_settings(s: Settings) -> None:
    """Validate critical settings at startup.

    Raises:
        ValueError: If required settings are missing or insecure.
    """
    if not s.database_url:
        if s.debug:
            logger.warning(
                "SECURITY WARNING: DATABASE_URL not set. "
                "Using in-memory SQLite for debug mode only."
            )
            s.database_url = "sqlite:///./debug_keyserver.db"
        else:
            raise ValueError(
                "DATABASE_URL environment variable is required. "
                "Example: DATABASE_URL=postgresql://user:pass@host/dbname"
            )

    if not s.api_token_secret or len(s.api_token_secret) < 32:
        if s.debug:
            logger.warning(
                "SECURITY WARNING: API_TOKEN_SECRET not set or too short. "
                "Using insecure default for debug mode only."
            )
            s.api_token_secret = "debug-only-insecure-secret-not-for-production!!"
        else:
            raise ValueError(
                "API_TOKEN_SECRET environment variable is required (min 32 characters). "
                'Generate with: python -c "import secrets; print(secrets.token_urlsafe(48))"'
            )


logger = logging.getLogger(__name__)

# Global settings instance
settings = Settings()
validate_settings(settings)
