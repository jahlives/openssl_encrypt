#!/usr/bin/env python3
"""
Configuration for OpenSSL Encrypt Server

Environment variables (see .env.example):
- DATABASE_URL or POSTGRES_* variables for database connection
- SERVER_HOST, SERVER_PORT for server binding
- KEYSERVER_TOKEN_SECRET, TELEMETRY_TOKEN_SECRET for JWT signing
- Module enable flags
- CORS settings
"""

import os
from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class TokenConfig(BaseSettings):
    """Token configuration for a module"""
    secret: str = Field(..., min_length=32)
    algorithm: str = "HS256"
    expiry_days: int = 365
    issuer: str


class KeyserverConfig(BaseSettings):
    """Keyserver module configuration"""
    enabled: bool = True
    token: Optional[TokenConfig] = None
    max_key_size_kb: int = 100
    require_self_signature: bool = True
    allowed_kem_algorithms: List[str] = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
    allowed_signing_algorithms: List[str] = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]


class TelemetryConfig(BaseSettings):
    """Telemetry module configuration"""
    enabled: bool = True
    token: Optional[TokenConfig] = None
    retention_days: int = 365
    max_events_per_request: int = 1000
    rate_limit_events_per_day: int = 10000


class Settings(BaseSettings):
    """
    Server settings with environment variable support.

    All settings can be overridden via environment variables.
    """

    # Application
    app_name: str = "OpenSSL Encrypt Server"
    version: str = "1.0.0"
    debug: bool = Field(default=False, validation_alias="DEBUG")
    log_level: str = Field(default="INFO", validation_alias="LOG_LEVEL")

    # Server
    server_host: str = Field(default="0.0.0.0", validation_alias="SERVER_HOST")
    server_port: int = Field(default=8080, validation_alias="SERVER_PORT")

    # Database
    database_url: Optional[str] = Field(default=None, validation_alias="DATABASE_URL")
    postgres_user: str = Field(default="openssl_server", validation_alias="POSTGRES_USER")
    postgres_password: str = Field(default="changeme", validation_alias="POSTGRES_PASSWORD")
    postgres_db: str = Field(default="openssl_encrypt", validation_alias="POSTGRES_DB")
    postgres_host: str = Field(default="localhost", validation_alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, validation_alias="POSTGRES_PORT")

    # CORS
    cors_origins: str = Field(default="*", validation_alias="CORS_ORIGINS")

    # Modules
    keyserver_enabled: bool = Field(default=True, validation_alias="KEYSERVER_ENABLED")
    keyserver_token_secret: str = Field(
        default="keyserver-secret-change-me-min-32-chars",
        validation_alias="KEYSERVER_TOKEN_SECRET"
    )

    telemetry_enabled: bool = Field(default=True, validation_alias="TELEMETRY_ENABLED")
    telemetry_token_secret: str = Field(
        default="telemetry-secret-change-me-min-32-chars",
        validation_alias="TELEMETRY_TOKEN_SECRET"
    )

    def get_cors_origins_list(self) -> List[str]:
        """Parse CORS origins string into list"""
        if not self.cors_origins:
            return ["*"]
        return [origin.strip() for origin in self.cors_origins.split(",")]

    def get_database_url(self) -> str:
        """Get database URL, constructing from parts if not provided directly"""
        if self.database_url:
            return self.database_url

        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    def get_keyserver_config(self) -> KeyserverConfig:
        """Get keyserver configuration"""
        return KeyserverConfig(
            enabled=self.keyserver_enabled,
            token=TokenConfig(
                secret=self.keyserver_token_secret,
                algorithm="HS256",
                expiry_days=365,
                issuer="openssl_encrypt_keyserver"
            )
        )

    def get_telemetry_config(self) -> TelemetryConfig:
        """Get telemetry configuration"""
        return TelemetryConfig(
            enabled=self.telemetry_enabled,
            token=TokenConfig(
                secret=self.telemetry_token_secret,
                algorithm="HS256",
                expiry_days=365,
                issuer="openssl_encrypt_telemetry"
            )
        )

    class Config:
        env_file = ".env"
        case_sensitive = False


def validate_config(settings: Settings):
    """
    Validate configuration at startup.

    Ensures:
    - Token secrets are different between modules
    - Token secrets are at least 32 characters

    Raises:
        ValueError: If configuration is invalid
    """
    secrets = []

    if settings.keyserver_enabled:
        ks_secret = settings.keyserver_token_secret
        if len(ks_secret) < 32:
            raise ValueError(
                "KEYSERVER_TOKEN_SECRET must be at least 32 characters long"
            )
        secrets.append(("Keyserver", ks_secret))

    if settings.telemetry_enabled:
        tm_secret = settings.telemetry_token_secret
        if len(tm_secret) < 32:
            raise ValueError(
                "TELEMETRY_TOKEN_SECRET must be at least 32 characters long"
            )
        secrets.append(("Telemetry", tm_secret))

    # Check all secrets are unique
    seen = {}
    for name, secret in secrets:
        if secret in seen:
            raise ValueError(
                f"SECURITY ERROR: {name} and {seen[secret]} token secrets MUST be different! "
                "Using the same secret would allow cross-module token usage."
            )
        seen[secret] = name


# Global settings instance
settings = Settings()
