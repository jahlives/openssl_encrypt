#!/usr/bin/env python3
"""
Telemetry API - Batch telemetry event uploads.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from ...config import settings
from ...database import get_db
from ...schemas import TelemetryBatchRequest, TelemetryBatchResponse
from ...services import KeyService, TelemetryService

router = APIRouter()
security = HTTPBearer()


@router.post("/telemetry", response_model=TelemetryBatchResponse, status_code=status.HTTP_200_OK)
def upload_telemetry_batch(
    request: TelemetryBatchRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """
    Upload batch of telemetry events.

    SECURITY:
    - Requires valid API key (Bearer token)
    - Rate limited per API key
    - Maximum 1000 events per request

    Returns:
        TelemetryBatchResponse: Count of received and processed events
    """
    # Validate API key
    api_key = KeyService.validate_api_key(db, credentials.credentials)

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired API key"
        )

    # Check rate limit
    if not KeyService.check_rate_limit(db, api_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Maximum events per day reached.",
            headers={"Retry-After": "86400"},  # 24 hours
        )

    # Validate batch size
    if len(request.events) > settings.max_events_per_request:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Too many events. Maximum {settings.max_events_per_request} per request.",
        )

    # Store events
    received, processed = TelemetryService.store_batch(db, api_key, request.events)

    # Increment request count for rate limiting
    KeyService.increment_request_count(db, api_key, count=processed)

    return TelemetryBatchResponse(received=received, processed=processed)
