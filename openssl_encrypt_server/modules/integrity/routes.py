#!/usr/bin/env python3
"""
Integrity API Routes

REST API endpoints for integrity verification operations.
"""

import logging
from typing import List

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address

from ...core.database import get_db
from .auth import get_client_info, require_integrity_auth
from .schemas import (
    BatchVerifyRequest,
    BatchVerifyResponse,
    DeleteResponse,
    HashListResponse,
    HashResponse,
    HashStoreRequest,
    HashUpdateRequest,
    ProfileResponse,
    ProfileUpdateRequest,
    StatsResponse,
    VerifyRequest,
    VerifyResponse,
)
from .service import IntegrityService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/integrity", tags=["integrity"])

# Initialize rate limiter (60/minute for all integrity endpoints)
limiter = Limiter(key_func=get_remote_address)


@limiter.limit("60/minute")
@router.get("/profile", response_model=ProfileResponse)
async def get_profile(
    cert_fingerprint: str = Depends(require_integrity_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Get client profile information.

    Auto-registers client on first request.
    """
    service = IntegrityService(db)
    return await service.get_profile(cert_fingerprint)


@limiter.limit("60/minute")
@router.put("/profile", response_model=ProfileResponse)
async def update_profile(
    request: ProfileUpdateRequest,
    cert_fingerprint: str = Depends(require_integrity_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Update client profile (display name).
    """
    service = IntegrityService(db)
    return await service.update_profile(cert_fingerprint, request.name)


@limiter.limit("60/minute")
@router.post("/hashes", response_model=HashResponse, status_code=201)
async def store_hash(
    request: HashStoreRequest,
    cert_fingerprint: str = Depends(require_integrity_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Store a new metadata hash for integrity verification.

    The file_id should be a unique identifier for the file (e.g., SHA-256 of filename).
    The metadata_hash should be the SHA-256 hash of the encrypted file's metadata.
    """
    service = IntegrityService(db)
    return await service.store_hash(cert_fingerprint, request)


@limiter.limit("60/minute")
@router.get("/hashes", response_model=HashListResponse)
async def list_hashes(
    cert_fingerprint: str = Depends(require_integrity_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    List all stored metadata hashes for this client.
    """
    service = IntegrityService(db)
    return await service.list_hashes(cert_fingerprint)


@limiter.limit("60/minute")
@router.get("/hashes/{file_id}", response_model=HashResponse)
async def get_hash(
    file_id: str,
    cert_fingerprint: str = Depends(require_integrity_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Get a specific metadata hash by file_id.
    """
    service = IntegrityService(db)
    return await service.get_hash(cert_fingerprint, file_id)


@limiter.limit("60/minute")
@router.put("/hashes/{file_id}", response_model=HashResponse)
async def update_hash(
    file_id: str,
    request: HashUpdateRequest,
    cert_fingerprint: str = Depends(require_integrity_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Update an existing metadata hash.

    Useful after re-encrypting a file or updating metadata.
    """
    service = IntegrityService(db)
    return await service.update_hash(cert_fingerprint, file_id, request)


@limiter.limit("60/minute")
@router.delete("/hashes/{file_id}")
async def delete_hash(
    file_id: str,
    cert_fingerprint: str = Depends(require_integrity_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Delete a specific metadata hash.
    """
    service = IntegrityService(db)
    return await service.delete_hash(cert_fingerprint, file_id)


@limiter.limit("60/minute")
@router.delete("/hashes", response_model=DeleteResponse)
async def delete_all_hashes(
    cert_fingerprint: str = Depends(require_integrity_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Delete ALL metadata hashes for this client.

    WARNING: This operation cannot be undone!
    """
    service = IntegrityService(db)
    return await service.delete_all_hashes(cert_fingerprint)


@limiter.limit("60/minute")
@router.post("/verify", response_model=VerifyResponse)
async def verify_hash(
    request: VerifyRequest,
    http_request: Request,
    cert_fingerprint: str = Depends(require_integrity_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Verify a file's integrity by comparing the current metadata hash
    with the stored hash.

    Returns match=true if hashes match, match=false with warning if mismatch detected.
    """
    # Get client IP for audit logging
    ip_address = http_request.client.host if http_request.client else None

    service = IntegrityService(db)
    return await service.verify_hash(cert_fingerprint, request, ip_address)


@limiter.limit("60/minute")
@router.post("/verify/batch", response_model=BatchVerifyResponse)
async def verify_batch(
    request: BatchVerifyRequest,
    http_request: Request,
    cert_fingerprint: str = Depends(require_integrity_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Verify multiple files at once.

    Maximum 100 files per batch.
    """
    # Get client IP for audit logging
    ip_address = http_request.client.host if http_request.client else None

    service = IntegrityService(db)
    results: List[VerifyResponse] = []

    for verify_req in request.verifications:
        result = await service.verify_hash(cert_fingerprint, verify_req, ip_address)
        results.append(result)

    matches = sum(1 for r in results if r.match)
    mismatches = sum(1 for r in results if not r.match)

    return BatchVerifyResponse(
        results=results,
        total=len(results),
        matches=matches,
        mismatches=mismatches,
    )


@limiter.limit("60/minute")
@router.get("/stats", response_model=StatsResponse)
async def get_stats(
    cert_fingerprint: str = Depends(require_integrity_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Get integrity verification statistics for this client.

    Includes total hashes stored, verification counts, success rates, etc.
    """
    service = IntegrityService(db)
    return await service.get_stats(cert_fingerprint)
