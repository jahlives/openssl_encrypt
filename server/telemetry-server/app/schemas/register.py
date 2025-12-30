#!/usr/bin/env python3
"""
Pydantic schemas for client registration.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class RegistrationRequest(BaseModel):
    """Client registration request."""

    client_id: str = Field(..., min_length=32, max_length=64, description="Random client ID")
    platform: str = Field(..., description="Platform: linux, macos, windows, other")
    client_version: str = Field(..., max_length=32, description="Client version")

    class Config:
        json_schema_extra = {
            "example": {
                "client_id": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
                "platform": "linux",
                "client_version": "1.4.0",
            }
        }


class RegistrationResponse(BaseModel):
    """Client registration response."""

    api_key: str = Field(..., description="API key for authentication")
    expires: datetime = Field(..., description="Expiration timestamp (ISO 8601)")

    class Config:
        json_schema_extra = {
            "example": {
                "api_key": "sk_1234567890abcdef1234567890abcdef",
                "expires": "2025-12-30T00:00:00Z",
            }
        }


class KeyRefreshResponse(BaseModel):
    """API key refresh response."""

    api_key: str = Field(..., description="New API key")
    expires: datetime = Field(..., description="New expiration timestamp")

    class Config:
        json_schema_extra = {
            "example": {
                "api_key": "sk_abcdef1234567890abcdef1234567890",
                "expires": "2026-12-30T00:00:00Z",
            }
        }
