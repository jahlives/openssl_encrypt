#!/usr/bin/env python3
"""
Integrity Pydantic Schemas

Request/response validation for integrity verification endpoints.
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class HashStoreRequest(BaseModel):
    """Request to store a metadata hash"""

    file_id: str = Field(..., min_length=1, max_length=128, description="Unique file identifier (e.g., SHA-256 of filename)")
    metadata_hash: str = Field(..., min_length=64, max_length=64, description="SHA-256 hash of encrypted file metadata")
    algorithm: Optional[str] = Field(None, max_length=50, description="Encryption algorithm used (e.g., 'symmetric-aes256')")
    description: Optional[str] = Field(None, max_length=1000, description="Optional description")


class HashUpdateRequest(BaseModel):
    """Request to update a metadata hash"""

    metadata_hash: str = Field(..., min_length=64, max_length=64, description="New SHA-256 hash of encrypted file metadata")
    description: Optional[str] = Field(None, max_length=1000, description="Updated description")


class HashResponse(BaseModel):
    """Response containing hash information"""

    file_id: str
    metadata_hash: str
    algorithm: Optional[str]
    description: Optional[str]
    created_at: datetime
    updated_at: datetime
    verified_at: Optional[datetime]
    verification_count: int


class HashListResponse(BaseModel):
    """Response containing list of hashes"""

    hashes: List[HashResponse]
    total: int


class VerifyRequest(BaseModel):
    """Request to verify a file's integrity"""

    file_id: str = Field(..., min_length=1, max_length=128, description="File identifier")
    metadata_hash: str = Field(..., min_length=64, max_length=64, description="Current SHA-256 hash to verify")


class VerifyResponse(BaseModel):
    """Response from integrity verification"""

    file_id: str
    match: bool = Field(..., description="True if hashes match, False otherwise")
    stored_hash: Optional[str] = Field(None, description="Hash stored on server")
    provided_hash: str = Field(..., description="Hash provided in request")
    last_updated: Optional[datetime] = Field(None, description="When stored hash was last updated")
    warning: Optional[str] = Field(None, description="Warning message if integrity violation detected")


class BatchVerifyRequest(BaseModel):
    """Request to verify multiple files at once"""

    verifications: List[VerifyRequest] = Field(..., min_length=1, max_length=100, description="List of files to verify (max 100)")


class BatchVerifyResponse(BaseModel):
    """Response from batch verification"""

    results: List[VerifyResponse]
    total: int
    matches: int
    mismatches: int


class ProfileResponse(BaseModel):
    """Client profile information"""

    cert_fingerprint: str
    cert_dn: Optional[str]
    name: Optional[str]
    created_at: datetime
    last_seen_at: Optional[datetime]
    hash_count: int


class ProfileUpdateRequest(BaseModel):
    """Request to update profile"""

    name: str = Field(..., min_length=1, max_length=255, description="Display name")


class StatsResponse(BaseModel):
    """Integrity verification statistics"""

    total_hashes: int = Field(..., description="Total metadata hashes stored")
    total_verifications: int = Field(..., description="Total verification attempts")
    successful_verifications: int = Field(..., description="Successful verifications (matches)")
    failed_verifications: int = Field(..., description="Failed verifications (mismatches)")
    files_not_found: int = Field(..., description="Verifications where file hash not found")
    success_rate: float = Field(..., description="Success rate (0.0-1.0)")
    last_verification: Optional[datetime] = Field(None, description="Most recent verification timestamp")


class DeleteResponse(BaseModel):
    """Response from delete operation"""

    message: str
    deleted_count: int


class ErrorResponse(BaseModel):
    """Error response"""

    detail: str
