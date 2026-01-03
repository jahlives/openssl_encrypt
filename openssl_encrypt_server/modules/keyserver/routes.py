#!/usr/bin/env python3
"""
Keyserver API Routes

Endpoints:
- POST /api/v1/keys/register - Register new client (no auth)
- POST /api/v1/keys - Upload key (auth required)
- GET /api/v1/keys/search - Search key (public)
- POST /api/v1/keys/{fingerprint}/revoke - Revoke key (auth required)
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address

from ...core.database import get_db
from .auth import get_keyserver_auth
from .schemas import (
    ErrorResponse,
    KeyBundleSchema,
    KeySearchResponse,
    KeyUploadResponse,
    RegisterResponse,
    RevocationRequest,
    RevocationResponse,
)
from .service import KeyserverService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/keys", tags=["keyserver"])

security = HTTPBearer()

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)


# Dependency that lazily gets the auth instance
async def get_current_client(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> str:
    """Get current authenticated client ID"""
    auth = get_keyserver_auth()
    payload = auth.verify_token(credentials.credentials)

    # Update last seen (fire and forget)
    try:
        await auth.update_last_seen(payload.sub)
    except Exception:
        pass

    return payload.sub


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_200_OK,
    summary="Register new keyserver client",
)
@limiter.limit("10/hour")
async def register(request: Request):
    """
    Register a new Keyserver client.

    Returns a JWT token that can ONLY be used for Keyserver endpoints.
    The token includes an issuer claim that prevents cross-module usage.

    Returns:
        RegisterResponse: Client ID, JWT token, expiration
    """
    auth = get_keyserver_auth()
    return await auth.register_client()


@router.post(
    "",
    response_model=KeyUploadResponse,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid bundle or verification failed"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        409: {"model": ErrorResponse, "description": "Key already exists"},
    },
    summary="Upload public key",
)
@limiter.limit("60/minute")
async def upload_key(
    request: Request,
    bundle: KeyBundleSchema,
    db: AsyncSession = Depends(get_db),
    client_id: str = Depends(get_current_client),
):
    """
    Upload public key bundle to keyserver.

    SECURITY:
    - Requires Keyserver JWT token
    - Verifies self-signature before storage
    - Validates fingerprint
    - Enforces algorithm whitelist

    Args:
        bundle: Public key bundle (validated by Pydantic)
        request: FastAPI request
        db: Database session
        client_id: Authenticated client ID

    Returns:
        KeyUploadResponse: Success status and fingerprint
    """
    service = KeyserverService(db)
    ip_address = request.client.host if request.client else None
    return await service.upload_key(client_id, bundle, ip_address)


@router.get(
    "/search",
    response_model=KeySearchResponse,
    status_code=status.HTTP_200_OK,
    responses={404: {"model": ErrorResponse, "description": "Key not found"}},
    summary="Search for public key",
)
@limiter.limit("100/minute")
async def search_key(
    request: Request,
    q: str = Query(..., description="Search query: fingerprint, name, or email"),
    db: AsyncSession = Depends(get_db),
):
    """
    Search for public key by fingerprint, name, or email.

    PUBLIC ENDPOINT: No authentication required.

    Search priority:
    1. Exact fingerprint match
    2. Fingerprint prefix match
    3. Exact name match
    4. Exact email match

    Args:
        q: Search query string
        request: FastAPI request
        db: Database session

    Returns:
        KeySearchResponse: Key bundle if found
    """
    service = KeyserverService(db)
    ip_address = request.client.host if request.client else None
    return await service.search_key(q, None, ip_address)


@router.post(
    "/{fingerprint}/revoke",
    response_model=RevocationResponse,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid revocation signature"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        404: {"model": ErrorResponse, "description": "Key not found"},
    },
    summary="Revoke public key",
)
@limiter.limit("60/minute")
async def revoke_key(
    request: Request,
    fingerprint: str,
    revocation: RevocationRequest,
    db: AsyncSession = Depends(get_db),
    client_id: str = Depends(get_current_client),
):
    """
    Revoke public key.

    SECURITY:
    - Requires Keyserver JWT token
    - Requires revocation signature (proof of ownership)
    - Marks key as revoked (doesn't delete)

    Args:
        fingerprint: Fingerprint of key to revoke
        revocation: Revocation request with signature
        request: FastAPI request
        db: Database session
        client_id: Authenticated client ID

    Returns:
        RevocationResponse: Success status
    """
    service = KeyserverService(db)
    ip_address = request.client.host if request.client else None
    return await service.revoke_key(fingerprint, revocation, client_id, ip_address)


@router.post(
    "/refresh",
    response_model=RegisterResponse,
    status_code=status.HTTP_200_OK,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid or expired refresh token"},
    },
    summary="Refresh access token",
)
@limiter.limit("60/hour")
async def refresh_token(
    request: Request,
    refresh_token: str = Query(..., description="Refresh token")
):
    """
    Use refresh token to get new access and refresh tokens (sliding expiration).

    SECURITY:
    - Requires valid refresh token (7-day expiry)
    - Returns new token pair with extended expiration
    - Implements sliding expiration: tokens auto-extend on use within TTL

    Token Flow:
    1. Client uses access token (1-hour expiry) for API calls
    2. Before access token expires, client uses refresh token
    3. Server returns NEW access token (1 hour) + NEW refresh token (7 days)
    4. This provides sliding expiration - active clients never locked out

    Args:
        request: FastAPI request
        refresh_token: Valid refresh token (from registration or previous refresh)

    Returns:
        RegisterResponse: New access and refresh tokens
    """
    auth = get_keyserver_auth()
    result = auth.refresh_access_token(refresh_token)

    return RegisterResponse(
        client_id=result["client_id"],
        token=result["access_token"],  # For backward compatibility
        access_token=result["access_token"],
        refresh_token=result["refresh_token"],
        expires_at=result["access_token_expires_at"],
        refresh_expires_at=result["refresh_token_expires_at"],
        token_type=result["token_type"]
    )
