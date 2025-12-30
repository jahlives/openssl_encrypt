#!/usr/bin/env python3
"""
Pydantic Schemas

This module defines Pydantic schemas for API request/response validation.

SECURITY:
- Validates all input data
- Enforces algorithm whitelists
- Ensures required fields present
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class KeyBundleSchema(BaseModel):
    """
    Schema for public key bundle.

    This matches the PublicKeyBundle format from the client.
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

    class Config:
        json_schema_extra = {
            "example": {
                "name": "alice",
                "email": "alice@example.com",
                "fingerprint": "3a:4b:5c:6d:7e:8f:...",
                "created_at": "2025-12-30T12:00:00Z",
                "encryption_public_key": "base64_encoded_key",
                "signing_public_key": "base64_encoded_key",
                "encryption_algorithm": "ML-KEM-768",
                "signing_algorithm": "ML-DSA-65",
                "self_signature": "base64_encoded_signature",
            }
        }


class KeyUploadResponse(BaseModel):
    """Response for successful key upload."""

    success: bool = True
    fingerprint: str
    message: str = "Key uploaded successfully"


class KeySearchResponse(BaseModel):
    """Response for key search."""

    key: Optional[KeyBundleSchema] = None
    message: Optional[str] = None


class RevocationRequest(BaseModel):
    """Request for key revocation."""

    signature: str = Field(..., description="Hex-encoded revocation signature")


class RevocationResponse(BaseModel):
    """Response for key revocation."""

    success: bool = True
    fingerprint: str
    message: str = "Key revoked successfully"


class ErrorResponse(BaseModel):
    """Standard error response."""

    detail: str
