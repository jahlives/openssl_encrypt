#!/usr/bin/env python3
"""
Telemetry API Routes

Endpoints:
- POST /api/v1/telemetry/register - Register new client (no auth)
- POST /api/v1/telemetry/events - Submit events (auth required)
- GET /api/v1/telemetry/stats - Get public statistics (no auth)
"""

import logging

from fastapi import APIRouter, Depends, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

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
async def register():
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
    "/events",
    response_model=TelemetryBatchResponse,
    status_code=status.HTTP_200_OK,
    responses={
        401: {"model": ErrorResponse, "description": "Authentication required"},
        400: {"model": ErrorResponse, "description": "Invalid events"},
    },
    summary="Submit telemetry events",
)
async def submit_events(
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
async def get_stats(db: AsyncSession = Depends(get_db)):
    """
    Get aggregated telemetry statistics.

    PUBLIC ENDPOINT: No authentication required.

    Returns:
        StatsResponse: Aggregated statistics
    """
    service = TelemetryService(db)
    return await service.get_public_stats()
