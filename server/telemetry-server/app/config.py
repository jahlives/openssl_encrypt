#!/usr/bin/env python3
"""
Configuration for Telemetry Server.

Environment variables:
- DATABASE_URL: PostgreSQL connection string
- SECRET_KEY: Secret key for JWT/hashing
- API_KEY_EXPIRY_DAYS: Days until API key expires (default: 365)
- MAX_EVENTS_PER_REQUEST: Maximum events per batch upload (default: 1000)
- RATE_LIMIT_EVENTS_PER_DAY: Rate limit per API key (default: 10000)
- RAW_DATA_RETENTION_DAYS: Days to keep raw telemetry data (default: 90)
"""

import logging
import os

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""

    # Application
    app_name: str = "OpenSSL Encrypt Telemetry Server"
    app_version: str = "1.0.0"
    debug: bool = False

    # Database - MUST be set via environment variable
    database_url: str = os.getenv("DATABASE_URL", "")

    # Security - MUST be set via environment variable (min 32 chars)
    secret_key: str = os.getenv("SECRET_KEY", "")
    api_key_expiry_days: int = 365
    api_key_hash_algorithm: str = "sha256"

    # Rate Limiting
    max_events_per_request: int = 1000
    rate_limit_events_per_day: int = 10000
    rate_limit_registrations_per_hour: int = 10

    # Data Retention
    raw_data_retention_days: int = 90

    # CORS (for public stats endpoint)
    cors_origins: list = ["*"]  # Configure for production

    class Config:
        env_file = ".env"
        case_sensitive = False


logger = logging.getLogger(__name__)


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
            s.database_url = "sqlite:///./debug_telemetry.db"
        else:
            raise ValueError(
                "DATABASE_URL environment variable is required. "
                "Example: DATABASE_URL=postgresql://user:pass@host:5432/dbname"
            )

    if not s.secret_key or len(s.secret_key) < 32:
        if s.debug:
            logger.warning(
                "SECURITY WARNING: SECRET_KEY not set or too short. "
                "Using insecure default for debug mode only."
            )
            s.secret_key = "debug-only-insecure-secret-not-for-production!!"
        else:
            raise ValueError(
                "SECRET_KEY environment variable is required (min 32 characters). "
                'Generate with: python -c "import secrets; print(secrets.token_urlsafe(48))"'
            )

    # Reject known insecure defaults even in non-debug mode
    insecure_defaults = {"CHANGE_THIS_IN_PRODUCTION", "changeme", "secret"}
    if s.secret_key in insecure_defaults:
        raise ValueError(
            "SECRET_KEY contains an insecure default value. "
            'Generate a proper secret with: python -c "import secrets; print(secrets.token_urlsafe(48))"'
        )


# Global settings instance
settings = Settings()
validate_settings(settings)
