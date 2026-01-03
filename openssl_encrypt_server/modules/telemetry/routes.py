#!/usr/bin/env python3
"""
Telemetry API Routes

Endpoints:
- POST /api/v1/telemetry/register - Register new client (no auth)
- POST /api/v1/telemetry/events - Submit events (auth required)
- GET /api/v1/telemetry/stats - Get public statistics (no auth)
"""

import logging

from fastapi import APIRouter, Depends, Query, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address

from ...core.database import get_db
from .auth import get_telemetry_auth
from .schemas import (
    ErrorResponse,
    RegisterResponse,
    StatsResponse,
    TelemetryBatchRequest,
    TelemetryBatchResponse,
)
from .service import TelemetryService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/telemetry", tags=["telemetry"])

security = HTTPBearer()

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)


# Dependency that lazily gets the auth instance
async def get_current_client(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> str:
    """Get current authenticated client ID"""
    auth = get_telemetry_auth()
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
    summary="Register new telemetry client",
)
@limiter.limit("10/hour")
async def register(request: Request):
    """
    Register a new Telemetry client.

    Returns a JWT token that can ONLY be used for Telemetry endpoints.
    The token includes an issuer claim that prevents cross-module usage.

    Returns:
        RegisterResponse: Client ID, JWT token, expiration
    """
    auth = get_telemetry_auth()
    return await auth.register_client()


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
    auth = get_telemetry_auth()
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


@router.post(
    "/events",
    response_model=TelemetryBatchResponse,
    status_code=status.HTTP_200_OK,
    responses={
        401: {"model": ErrorResponse, "description": "Authentication required"},
        400: {"model": ErrorResponse, "description": "Invalid events"},
    },
    summary="Submit telemetry events",
)
@limiter.limit("1000/hour")
async def submit_events(
    http_request: Request,
    request: TelemetryBatchRequest,
    db: AsyncSession = Depends(get_db),
    client_id: str = Depends(get_current_client),
):
    """
    Submit telemetry events.

    SECURITY:
    - Requires Telemetry JWT token
    - Max 1000 events per request
    - Rate limiting enforced

    Args:
        request: Batch of telemetry events
        db: Database session
        client_id: Authenticated client ID

    Returns:
        TelemetryBatchResponse: Processing results
    """
    service = TelemetryService(db)
    return await service.record_events(client_id, request.events)


@router.get(
    "/stats",
    response_model=StatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get public statistics",
)
@limiter.limit("100/minute")
async def get_stats(request: Request, db: AsyncSession = Depends(get_db)):
    """
    Get aggregated telemetry statistics.

    PUBLIC ENDPOINT: No authentication required.

    Returns:
        StatsResponse: Aggregated statistics
    """
    service = TelemetryService(db)
    return await service.get_public_stats()
