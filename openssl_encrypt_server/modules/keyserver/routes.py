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
async def register():
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
async def upload_key(
    bundle: KeyBundleSchema,
    request: Request,
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
async def search_key(
    q: str = Query(..., description="Search query: fingerprint, name, or email"),
    request: Request = None,
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
async def revoke_key(
    fingerprint: str,
    revocation: RevocationRequest,
    request: Request,
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
