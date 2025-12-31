#!/usr/bin/env python3
"""
Registration API - Client registration and key management.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from ...database import get_db
from ...schemas import KeyRefreshResponse, RegistrationRequest, RegistrationResponse
from ...services import KeyService

router = APIRouter()
security = HTTPBearer()


@router.post("/register", response_model=RegistrationResponse, status_code=status.HTTP_200_OK)
def register_client(request: RegistrationRequest, db: Session = Depends(get_db)):
    """
    Register new client and issue API key.

    PRIVACY: Only stores anonymous client_id and generic platform info.

    Returns:
        RegistrationResponse: API key and expiration
    """
    # Validate platform
    allowed_platforms = ["linux", "macos", "windows", "other"]
    if request.platform not in allowed_platforms:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid platform. Must be one of: {', '.join(allowed_platforms)}",
        )

    # Check if client_id already exists
    from ...models import APIKey

    existing = db.query(APIKey).filter(APIKey.client_id == request.client_id).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Client ID already registered"
        )

    # Create API key
    db_key, api_key = KeyService.create_api_key(
        db=db,
        client_id=request.client_id,
        platform=request.platform,
        client_version=request.client_version,
    )

    return RegistrationResponse(api_key=api_key, expires=db_key.expires_at)


@router.post("/key/refresh", response_model=KeyRefreshResponse, status_code=status.HTTP_200_OK)
def refresh_api_key(
    credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)
):
    """
    Refresh API key (requires valid current key).

    Returns:
        KeyRefreshResponse: New API key and expiration
    """
    # Validate current key
    current_key = KeyService.validate_api_key(db, credentials.credentials)

    if not current_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired API key"
        )

    # Generate new key
    refreshed_key, new_api_key = KeyService.refresh_api_key(db, current_key)

    return KeyRefreshResponse(api_key=new_api_key, expires=refreshed_key.expires_at)
