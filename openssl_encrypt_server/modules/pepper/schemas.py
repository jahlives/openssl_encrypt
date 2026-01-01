#!/usr/bin/env python3
"""
Pepper API schemas (Pydantic models for request/response validation).
"""

from typing import List, Optional

from pydantic import BaseModel, Field


# Profile schemas
class ProfileResponse(BaseModel):
    """Client profile information"""

    cert_fingerprint: str
    cert_dn: Optional[str] = None
    name: Optional[str] = None
    totp_enabled: bool
    created_at: str
    last_seen_at: Optional[str] = None
    pepper_count: int


class ProfileUpdateRequest(BaseModel):
    """Update profile (name only)"""

    name: Optional[str] = Field(None, max_length=255, description="Friendly name for the client")


# Pepper schemas
class PepperCreateRequest(BaseModel):
    """Create new pepper"""

    name: str = Field(..., min_length=1, max_length=255, description="Pepper identifier (unique per client)")
    pepper_encrypted: str = Field(..., description="Base64-encoded encrypted pepper blob")
    description: Optional[str] = Field(None, max_length=1000, description="Optional description")


class PepperUpdateRequest(BaseModel):
    """Update pepper"""

    pepper_encrypted: str = Field(..., description="Base64-encoded encrypted pepper blob")
    description: Optional[str] = Field(None, max_length=1000, description="Optional description")


class PepperResponse(BaseModel):
    """Pepper with encrypted blob"""

    name: str
    pepper_encrypted: str  # Base64
    description: Optional[str] = None
    created_at: str
    updated_at: str
    last_accessed_at: Optional[str] = None
    access_count: int


class PepperListItem(BaseModel):
    """Pepper metadata (no encrypted blob)"""

    name: str
    description: Optional[str] = None
    created_at: str
    updated_at: str
    access_count: int


class PepperListResponse(BaseModel):
    """List of peppers"""

    peppers: List[PepperListItem]
    total: int


# TOTP schemas
class TOTPSetupResponse(BaseModel):
    """TOTP setup response with QR code"""

    secret: str = Field(..., description="Base32-encoded TOTP secret")
    qr_svg: str = Field(..., description="SVG QR code for authenticator apps")
    uri: str = Field(..., description="otpauth:// URI for manual entry")
    message: str


class TOTPVerifyRequest(BaseModel):
    """Verify TOTP code"""

    code: str = Field(..., min_length=6, max_length=10, description="6-digit TOTP code or backup code")


class TOTPVerifyResponse(BaseModel):
    """TOTP verification response"""

    message: str
    backup_codes: List[str] = Field(..., description="10 single-use backup codes")
    backup_codes_warning: str


class TOTPBackupCodesResponse(BaseModel):
    """New backup codes"""

    backup_codes: List[str] = Field(..., description="10 new single-use backup codes")
    warning: str


# Deadman schemas
class DeadmanConfigRequest(BaseModel):
    """Configure deadman switch"""

    interval_seconds: Optional[int] = Field(None, ge=3600, description="Check-in interval (minimum 1 hour)")
    grace_period_seconds: Optional[int] = Field(None, ge=3600, description="Grace period after deadline (minimum 1 hour)")
    enabled: bool = True


class DeadmanStatusResponse(BaseModel):
    """Deadman switch status"""

    configured: bool
    enabled: Optional[bool] = None
    interval_seconds: Optional[int] = None
    grace_period_seconds: Optional[int] = None
    last_checkin: Optional[str] = None
    next_deadline: Optional[str] = None
    time_remaining_seconds: Optional[int] = None
    panic_triggered: Optional[bool] = None
    panic_triggered_at: Optional[str] = None


class CheckinResponse(BaseModel):
    """Check-in response"""

    message: str
    next_deadline: str
    time_remaining_seconds: int


# Panic schemas
class PanicResponse(BaseModel):
    """Panic wipe response"""

    message: str
    peppers_wiped: int
    trigger_type: str  # 'manual', 'deadman', 'emergency'
