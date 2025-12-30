#!/usr/bin/env python3
"""
Keyserver Configuration

This module handles server configuration with environment variable support.

SECURITY:
- Database credentials from environment variables
- API token validation configuration
- CORS settings for security
"""

import os
from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Server settings with environment variable support.

    All settings can be overridden via environment variables.
    Example: DATABASE_URL, API_TOKEN_SALT, etc.
    """

    # Application
    app_name: str = "OpenSSL Encrypt Keyserver"
    version: str = "1.0.0"
    debug: bool = False

    # Database
    database_url: str = os.getenv(
        "DATABASE_URL", "postgresql://keyserver:keyserver@localhost/keyserver"
    )

    # Security
    api_token_salt: str = os.getenv("API_TOKEN_SALT", "change-me-in-production")
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


# Global settings instance
settings = Settings()
