#!/usr/bin/env python3
"""
Keyserver Pydantic Schemas

Request/response validation for keyserver endpoints.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class RegisterResponse(BaseModel):
    """Response for client registration with access and refresh tokens"""

    client_id: str
    token: str  # Deprecated: kept for backward compatibility, same as access_token
    access_token: Optional[str] = None  # Explicit access token (1-hour expiry)
    refresh_token: Optional[str] = None  # Refresh token for sliding expiration (7-day expiry)
    expires_at: str  # ISO 8601 datetime (access token expiry)
    refresh_expires_at: Optional[str] = None  # ISO 8601 datetime (refresh token expiry)
    token_type: str = "Bearer"


class KeyBundleSchema(BaseModel):
    """
    Schema for public key bundle.

    Matches the PublicKeyBundle format from the client.
    """

    name: str = Field(..., min_length=1, max_length=255)
    email: Optional[str] = Field(None, max_length=255)
    fingerprint: str = Field(..., min_length=1, max_length=255)
    created_at: str = Field(..., description="ISO 8601 timestamp")

    encryption_public_key: str = Field(..., description="Base64-encoded public key")
    signing_public_key: str = Field(..., description="Base64-encoded public key")

    encryption_algorithm: str = Field(..., max_length=50)
    signing_algorithm: str = Field(..., max_length=50)

    self_signature: str = Field(..., description="Base64-encoded signature")

    @field_validator("encryption_algorithm")
    @classmethod
    def validate_encryption_algorithm(cls, v):
        """Validate encryption algorithm against whitelist."""
        allowed = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
        if v not in allowed:
            raise ValueError(f"Invalid encryption algorithm. Allowed: {', '.join(allowed)}")
        return v

    @field_validator("signing_algorithm")
    @classmethod
    def validate_signing_algorithm(cls, v):
        """Validate signing algorithm against whitelist."""
        allowed = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
        if v not in allowed:
            raise ValueError(f"Invalid signing algorithm. Allowed: {', '.join(allowed)}")
        return v


class KeyUploadResponse(BaseModel):
    """Response for successful key upload"""

    success: bool = True
    fingerprint: str
    message: str = "Key uploaded successfully"


class KeySearchResponse(BaseModel):
    """Response for key search"""

    key: Optional[KeyBundleSchema] = None
    message: Optional[str] = None


class RevocationRequest(BaseModel):
    """Request for key revocation"""

    signature: str = Field(..., description="Hex-encoded revocation signature")


class RevocationResponse(BaseModel):
    """Response for key revocation"""

    success: bool = True
    fingerprint: str
    message: str = "Key revoked successfully"


class ErrorResponse(BaseModel):
    """Standard error response"""

    detail: str
    success: bool = False
