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

import os
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""

    # Application
    app_name: str = "OpenSSL Encrypt Telemetry Server"
    app_version: str = "1.0.0"
    debug: bool = False

    # Database
    database_url: str = os.getenv(
        "DATABASE_URL", "postgresql://telemetry:telemetry@localhost:5432/telemetry"
    )

    # Security
    secret_key: str = os.getenv("SECRET_KEY", "CHANGE_THIS_IN_PRODUCTION")
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


# Global settings instance
settings = Settings()
