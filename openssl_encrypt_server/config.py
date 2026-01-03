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
from typing import List, Literal, Optional
from pydantic import Field, field_validator, ConfigDict
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


class PepperProxyConfig(BaseSettings):
    """Pepper proxy mode configuration

    SECURITY: trusted_proxies must be explicitly configured with specific IPs.
    Defaults only include localhost. Broad network ranges (< /24) are rejected.
    """
    fingerprint_header: str = "X-Client-Cert-Fingerprint"
    dn_header: Optional[str] = "X-Client-Cert-DN"
    verify_header: Optional[str] = "X-Client-Cert-Verify"
    trusted_proxies: List[str] = [
        "127.0.0.1",  # IPv4 localhost only
        "::1",        # IPv6 localhost only
        # IMPORTANT: Add your reverse proxy IPs here explicitly
        # Do NOT use broad network ranges - specify exact IPs or small subnets (/24 or smaller)
    ]


class PepperMTLSConfig(BaseSettings):
    """Pepper mTLS mode configuration"""
    host: str = "0.0.0.0"
    port: int = 8444
    cert: str = "/certs/pepper-server.crt"
    key: str = "/certs/pepper-server.key"
    client_ca: str = "/certs/client-ca.crt"


class PepperConfig(BaseSettings):
    """Pepper module configuration"""
    enabled: bool = False  # OPT-IN by default
    auth_mode: Literal["proxy", "mtls"] = "proxy"
    proxy: PepperProxyConfig = PepperProxyConfig()
    mtls: PepperMTLSConfig = PepperMTLSConfig()
    totp_secret_encryption_key: Optional[str] = None
    deadman_enabled: bool = True
    deadman_check_interval: str = "1h"
    deadman_default_interval: str = "7d"
    deadman_grace_period: str = "24h"
    max_peppers_per_client: int = 100


class IntegrityProxyConfig(BaseSettings):
    """Integrity proxy mode configuration (same as Pepper)"""
    fingerprint_header: str = "X-Client-Cert-Fingerprint"
    dn_header: Optional[str] = "X-Client-Cert-DN"
    verify_header: Optional[str] = "X-Client-Cert-Verify"
    trusted_proxies: List[str] = [
        "127.0.0.1",
        "::1",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16"
    ]


class IntegrityMTLSConfig(BaseSettings):
    """Integrity mTLS mode configuration"""
    host: str = "0.0.0.0"
    port: int = 8445
    cert: str = "/certs/integrity-server.crt"
    key: str = "/certs/integrity-server.key"
    client_ca: str = "/certs/client-ca.crt"


class IntegrityConfig(BaseSettings):
    """Integrity module configuration"""
    enabled: bool = False  # OPT-IN by default
    auth_mode: Literal["proxy", "mtls"] = "proxy"
    proxy: IntegrityProxyConfig = IntegrityProxyConfig()
    mtls: IntegrityMTLSConfig = IntegrityMTLSConfig()


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
    database_query_timeout: int = Field(
        default=30,  # 30 seconds
        validation_alias="DATABASE_QUERY_TIMEOUT"
    )
    database_pool_size: int = Field(
        default=20,
        validation_alias="DATABASE_POOL_SIZE"
    )
    database_max_overflow: int = Field(
        default=10,
        validation_alias="DATABASE_MAX_OVERFLOW"
    )

    # CORS - SECURITY: Must be explicitly configured for production
    cors_origins: str = Field(
        default="",  # Empty = no CORS (secure default)
        validation_alias="CORS_ORIGINS"
    )
    cors_allow_credentials: bool = Field(
        default=False,  # Secure default
        validation_alias="CORS_ALLOW_CREDENTIALS"
    )
    cors_allow_methods: str = Field(
        default="GET,POST,PUT,DELETE",
        validation_alias="CORS_ALLOW_METHODS"
    )
    cors_allow_headers: str = Field(
        default="Authorization,Content-Type",
        validation_alias="CORS_ALLOW_HEADERS"
    )
    cors_max_age: int = Field(
        default=600,  # 10 minutes
        validation_alias="CORS_MAX_AGE"
    )

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

    pepper_enabled: bool = Field(default=False, validation_alias="PEPPER_ENABLED")
    pepper_auth_mode: str = Field(default="proxy", validation_alias="PEPPER_AUTH_MODE")
    pepper_totp_secret_key: Optional[str] = Field(default=None, validation_alias="PEPPER_TOTP_SECRET_KEY")
    pepper_deadman_enabled: bool = Field(default=True, validation_alias="PEPPER_DEADMAN_ENABLED")
    pepper_mtls_port: int = Field(default=8444, validation_alias="PEPPER_MTLS_PORT")
    pepper_mtls_cert: str = Field(default="/certs/pepper-server.crt", validation_alias="PEPPER_MTLS_CERT")
    pepper_mtls_key: str = Field(default="/certs/pepper-server.key", validation_alias="PEPPER_MTLS_KEY")
    pepper_mtls_client_ca: str = Field(default="/certs/client-ca.crt", validation_alias="PEPPER_MTLS_CLIENT_CA")

    integrity_enabled: bool = Field(default=False, validation_alias="INTEGRITY_ENABLED")
    integrity_auth_mode: str = Field(default="proxy", validation_alias="INTEGRITY_AUTH_MODE")
    integrity_mtls_port: int = Field(default=8445, validation_alias="INTEGRITY_MTLS_PORT")
    integrity_mtls_cert: str = Field(default="/certs/integrity-server.crt", validation_alias="INTEGRITY_MTLS_CERT")
    integrity_mtls_key: str = Field(default="/certs/integrity-server.key", validation_alias="INTEGRITY_MTLS_KEY")
    integrity_mtls_client_ca: str = Field(default="/certs/client-ca.crt", validation_alias="INTEGRITY_MTLS_CLIENT_CA")

    def get_cors_origins_list(self) -> List[str]:
        """
        Parse CORS origins string into list.

        SECURITY: Returns empty list if no origins configured (CORS disabled).
        Warns if wildcard "*" is used.
        """
        if not self.cors_origins or self.cors_origins.strip() == "":
            return []  # No CORS enabled (secure default)

        origins = [origin.strip() for origin in self.cors_origins.split(",")]

        # Warn about wildcard origins
        if "*" in origins:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(
                "SECURITY WARNING: CORS configured with wildcard '*' origin. "
                "This allows requests from ANY domain. "
                "Use specific origins for production: CORS_ORIGINS=https://app.example.com"
            )

        return origins

    def get_cors_methods_list(self) -> List[str]:
        """Parse CORS methods string into list"""
        return [method.strip() for method in self.cors_allow_methods.split(",")]

    def get_cors_headers_list(self) -> List[str]:
        """Parse CORS headers string into list"""
        return [header.strip() for header in self.cors_allow_headers.split(",")]

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

    def get_pepper_config(self) -> PepperConfig:
        """Get pepper configuration"""
        return PepperConfig(
            enabled=self.pepper_enabled,
            auth_mode=self.pepper_auth_mode,  # type: ignore
            mtls=PepperMTLSConfig(
                port=self.pepper_mtls_port,
                cert=self.pepper_mtls_cert,
                key=self.pepper_mtls_key,
                client_ca=self.pepper_mtls_client_ca
            ),
            totp_secret_encryption_key=self.pepper_totp_secret_key,
            deadman_enabled=self.pepper_deadman_enabled,
        )

    def get_integrity_config(self) -> IntegrityConfig:
        """Get integrity configuration"""
        return IntegrityConfig(
            enabled=self.integrity_enabled,
            auth_mode=self.integrity_auth_mode,  # type: ignore
            mtls=IntegrityMTLSConfig(
                port=self.integrity_mtls_port,
                cert=self.integrity_mtls_cert,
                key=self.integrity_mtls_key,
                client_ca=self.integrity_mtls_client_ca
            ),
        )

    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=False,
        populate_by_name=True,  # Allow both field names and aliases
    )


def validate_config(settings: Settings):
    """
    Validate configuration at startup.

    Ensures:
    - Token secrets are different between modules
    - Token secrets are at least 32 characters
    - Pepper TOTP encryption key is configured if pepper enabled

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

    # Validate pepper configuration
    if settings.pepper_enabled:
        if not settings.pepper_totp_secret_key:
            raise ValueError(
                "PEPPER_TOTP_SECRET_KEY must be set when pepper module is enabled. "
                "Generate with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
            )
        # Validate it's a valid Fernet key (44 characters, base64)
        if len(settings.pepper_totp_secret_key) != 44:
            raise ValueError(
                "PEPPER_TOTP_SECRET_KEY must be a valid Fernet key (44 characters)"
            )


# Global settings instance
settings = Settings()
