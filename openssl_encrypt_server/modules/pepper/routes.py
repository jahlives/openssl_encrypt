#!/usr/bin/env python3
"""
Pepper API routes.

Endpoints:
- Profile: GET/PUT/DELETE /profile
- TOTP: POST /totp/setup, POST /totp/verify, DELETE /totp, POST /totp/backup
- Peppers: POST/GET /peppers, GET/PUT/DELETE /peppers/{name}
- Deadman: GET/PUT/DELETE /deadman, POST /deadman/checkin
- Panic: POST /panic, POST /panic/{name}

Authentication:
- All endpoints require mTLS authentication (certificate fingerprint)
- Destructive operations require TOTP 2FA via X-TOTP-Code header if enabled
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address

from ...config import settings
from ...core.database import get_db
from .auth import require_pepper_auth
from .deadman import DeadmanService
from .schemas import (
    CheckinResponse,
    DeadmanConfigRequest,
    DeadmanStatusResponse,
    PanicResponse,
    PepperCreateRequest,
    PepperListResponse,
    PepperResponse,
    PepperUpdateRequest,
    ProfileResponse,
    ProfileUpdateRequest,
    TOTPBackupCodesResponse,
    TOTPSetupResponse,
    TOTPVerifyRequest,
    TOTPVerifyResponse,
)
from .service import PepperService
from .totp import TOTPService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/pepper", tags=["pepper"])

# Initialize rate limiter (60/minute for all pepper endpoints)
limiter = Limiter(key_func=get_remote_address)


# Helper to get client IP
def get_client_ip(request: Request) -> Optional[str]:
    """Extract client IP from request."""
    if request.client:
        return request.client.host
    return None


# Helper to verify TOTP for destructive operations
async def verify_totp_if_enabled(
    cert_fingerprint: str,
    totp_code: Optional[str],
    db: AsyncSession
):
    """
    Verify TOTP code if 2FA enabled for client.

    Args:
        cert_fingerprint: Client certificate fingerprint
        totp_code: TOTP code from X-TOTP-Code header
        db: Database session

    Raises:
        HTTPException: If TOTP enabled but code invalid/missing
    """
    service = PepperService(db, settings.get_pepper_config())
    client = await service.get_client(cert_fingerprint)

    if client and client.totp_verified:
        # TOTP is enabled - require code
        if not totp_code:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="TOTP code required. Provide X-TOTP-Code header."
            )

        # Verify code
        totp_service = TOTPService(
            db,
            issuer="openssl_encrypt",
            fernet_key=settings.pepper_totp_secret_key
        )
        if not await totp_service.verify_code(client, totp_code):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid TOTP code"
            )


# Profile endpoints
@limiter.limit("60/minute")
@router.get("/profile", response_model=ProfileResponse)
async def get_profile(
    request: Request,
    cert_fingerprint: str = Depends(require_pepper_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Get client profile.

    Returns profile information including TOTP status and pepper count.
    """
    service = PepperService(db, settings.get_pepper_config())
    profile = await service.get_profile(cert_fingerprint)
    return ProfileResponse(**profile)


@limiter.limit("60/minute")
@router.put("/profile", response_model=ProfileResponse)
async def update_profile(
    request: Request,
    body: ProfileUpdateRequest,
    cert_fingerprint: str = Depends(require_pepper_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Update client profile (name only).
    """
    service = PepperService(db, settings.get_pepper_config())
    profile = await service.update_profile(cert_fingerprint, request)
    return ProfileResponse(**profile)


@limiter.limit("60/minute")
@router.delete("/profile")
async def delete_profile(
    request: Request,
    cert_fingerprint: str = Depends(require_pepper_auth),
    db: AsyncSession = Depends(get_db),
    x_totp_code: Optional[str] = Header(None, alias="X-TOTP-Code"),
):
    """
    Delete profile and ALL associated data.

    DESTRUCTIVE: Deletes client, all peppers, TOTP, deadman config, backup codes.
    Requires TOTP code if 2FA enabled.
    """
    await verify_totp_if_enabled(cert_fingerprint, x_totp_code, db)

    service = PepperService(db, settings.get_pepper_config())
    result = await service.delete_profile(cert_fingerprint)
    return result


# TOTP endpoints
@limiter.limit("60/minute")
@router.post("/totp/setup", response_model=TOTPSetupResponse)
async def setup_totp(
    request: Request,
    cert_fingerprint: str = Depends(require_pepper_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Setup TOTP 2FA.

    Returns TOTP secret and QR code for authenticator apps.
    Must verify with code before TOTP is enabled.
    """
    service = PepperService(db, settings.get_pepper_config())
    client = await service.get_or_create_client(cert_fingerprint)

    if client.totp_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP already enabled. Disable first to set up new secret."
        )

    totp_service = TOTPService(
        db,
        issuer="openssl_encrypt",
        fernet_key=settings.pepper_totp_secret_key
    )
    result = await totp_service.setup(client)
    return TOTPSetupResponse(**result)


@limiter.limit("60/minute")
@router.post("/totp/verify", response_model=TOTPVerifyResponse)
async def verify_totp(
    request: Request,
    body: TOTPVerifyRequest,
    cert_fingerprint: str = Depends(require_pepper_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Verify TOTP setup with code.

    Enables TOTP and returns backup codes.
    """
    service = PepperService(db, settings.get_pepper_config())
    client = await service.get_or_create_client(cert_fingerprint)

    if client.totp_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP already verified"
        )

    totp_service = TOTPService(
        db,
        issuer="openssl_encrypt",
        fernet_key=settings.pepper_totp_secret_key
    )

    try:
        result = await totp_service.verify_setup(client, body.code)
        return TOTPVerifyResponse(**result)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@limiter.limit("60/minute")
@router.delete("/totp")
async def disable_totp(
    request: Request,
    cert_fingerprint: str = Depends(require_pepper_auth),
    db: AsyncSession = Depends(get_db),
    x_totp_code: Optional[str] = Header(None, alias="X-TOTP-Code"),
):
    """
    Disable TOTP 2FA.

    Requires valid TOTP code for confirmation.
    """
    if not x_totp_code:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="TOTP code required. Provide X-TOTP-Code header."
        )

    service = PepperService(db, settings.get_pepper_config())
    client = await service.get_or_create_client(cert_fingerprint)

    totp_service = TOTPService(
        db,
        issuer="openssl_encrypt",
        fernet_key=settings.pepper_totp_secret_key
    )

    try:
        result = await totp_service.disable(client, x_totp_code)
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )


@limiter.limit("60/minute")
@router.post("/totp/backup", response_model=TOTPBackupCodesResponse)
async def regenerate_backup_codes(
    request: Request,
    cert_fingerprint: str = Depends(require_pepper_auth),
    db: AsyncSession = Depends(get_db),
    x_totp_code: Optional[str] = Header(None, alias="X-TOTP-Code"),
):
    """
    Regenerate backup codes.

    Deletes old codes and creates 10 new ones.
    Requires TOTP code for confirmation.
    """
    if not x_totp_code:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="TOTP code required. Provide X-TOTP-Code header."
        )

    service = PepperService(db, settings.get_pepper_config())
    client = await service.get_or_create_client(cert_fingerprint)

    totp_service = TOTPService(
        db,
        issuer="openssl_encrypt",
        fernet_key=settings.pepper_totp_secret_key
    )

    try:
        backup_codes = await totp_service.regenerate_backup_codes(client.id, x_totp_code)
        return TOTPBackupCodesResponse(
            backup_codes=backup_codes,
            warning="Save these backup codes in a secure location. Each can only be used once."
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )


# Pepper endpoints
@limiter.limit("60/minute")
@router.post("/peppers", response_model=PepperResponse)
async def create_pepper(
    request: Request,
    body: PepperCreateRequest,
    cert_fingerprint: str = Depends(require_pepper_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Create new pepper.

    Pepper must be encrypted client-side before upload.
    """
    service = PepperService(db, settings.get_pepper_config())
    client = await service.get_or_create_client(cert_fingerprint)

    try:
        pepper = await service.create_pepper(client, request)
        return pepper
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@limiter.limit("60/minute")
@router.get("/peppers", response_model=PepperListResponse)
async def list_peppers(
    request: Request,
    cert_fingerprint: str = Depends(require_pepper_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    List all peppers (metadata only, no encrypted blobs).
    """
    service = PepperService(db, settings.get_pepper_config())
    client = await service.get_or_create_client(cert_fingerprint)

    result = await service.list_peppers(client)
    return PepperListResponse(**result)


@limiter.limit("60/minute")
@router.get("/peppers/{name}", response_model=PepperResponse)
async def get_pepper(
    request: Request,
    name: str,
    cert_fingerprint: str = Depends(require_pepper_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Get specific pepper with encrypted blob.

    Updates last_accessed_at and access_count.
    """
    service = PepperService(db, settings.get_pepper_config())
    client = await service.get_or_create_client(cert_fingerprint)

    try:
        pepper = await service.get_pepper(client, name)
        return pepper
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )


@limiter.limit("60/minute")
@router.put("/peppers/{name}", response_model=PepperResponse)
async def update_pepper(
    request: Request,
    name: str,
    body: PepperUpdateRequest,
    cert_fingerprint: str = Depends(require_pepper_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Update pepper (encrypted blob and/or description).
    """
    service = PepperService(db, settings.get_pepper_config())
    client = await service.get_or_create_client(cert_fingerprint)

    try:
        pepper = await service.update_pepper(client, name, request)
        return pepper
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )


@limiter.limit("60/minute")
@router.delete("/peppers/{name}")
async def delete_pepper(
    request: Request,
    name: str,
    cert_fingerprint: str = Depends(require_pepper_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Delete specific pepper.
    """
    service = PepperService(db, settings.get_pepper_config())
    client = await service.get_or_create_client(cert_fingerprint)

    try:
        result = await service.delete_pepper(client, name)
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )


# Deadman endpoints
@limiter.limit("60/minute")
@router.get("/deadman", response_model=DeadmanStatusResponse)
async def get_deadman_status(
    request: Request,
    cert_fingerprint: str = Depends(require_pepper_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Get deadman switch status.
    """
    service = PepperService(db, settings.get_pepper_config())
    client = await service.get_or_create_client(cert_fingerprint)

    pepper_config = settings.get_pepper_config()
    deadman_service = DeadmanService(
        db,
        default_interval=pepper_config.deadman_default_interval,
        default_grace=pepper_config.deadman_grace_period
    )

    status_dict = await deadman_service.get_status(client.id)
    return DeadmanStatusResponse(**status_dict)


@limiter.limit("60/minute")
@router.put("/deadman", response_model=DeadmanStatusResponse)
async def configure_deadman(
    request: Request,
    body: DeadmanConfigRequest,
    cert_fingerprint: str = Depends(require_pepper_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Configure deadman switch.

    Sets check-in interval and grace period.
    """
    service = PepperService(db, settings.get_pepper_config())
    client = await service.get_or_create_client(cert_fingerprint)

    pepper_config = settings.get_pepper_config()
    deadman_service = DeadmanService(
        db,
        default_interval=pepper_config.deadman_default_interval,
        default_grace=pepper_config.deadman_grace_period
    )

    try:
        status_dict = await deadman_service.configure(
            client.id,
            interval_seconds=body.interval_seconds,
            grace_period_seconds=body.grace_period_seconds,
            enabled=body.enabled
        )
        return DeadmanStatusResponse(**status_dict)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@limiter.limit("60/minute")
@router.post("/deadman/checkin", response_model=CheckinResponse)
async def deadman_checkin(
    request: Request,
    cert_fingerprint: str = Depends(require_pepper_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Check in to reset deadman timer.
    """
    service = PepperService(db, settings.get_pepper_config())
    client = await service.get_or_create_client(cert_fingerprint)

    pepper_config = settings.get_pepper_config()
    deadman_service = DeadmanService(
        db,
        default_interval=pepper_config.deadman_default_interval,
        default_grace=pepper_config.deadman_grace_period
    )

    try:
        result = await deadman_service.checkin(client.id)
        return CheckinResponse(**result)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@limiter.limit("60/minute")
@router.delete("/deadman")
async def disable_deadman(
    request: Request,
    cert_fingerprint: str = Depends(require_pepper_auth),
    db: AsyncSession = Depends(get_db),
):
    """
    Disable deadman switch.
    """
    service = PepperService(db, settings.get_pepper_config())
    client = await service.get_or_create_client(cert_fingerprint)

    pepper_config = settings.get_pepper_config()
    deadman_service = DeadmanService(
        db,
        default_interval=pepper_config.deadman_default_interval,
        default_grace=pepper_config.deadman_grace_period
    )

    try:
        result = await deadman_service.disable(client.id)
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )


# Panic endpoints
@limiter.limit("60/minute")
@router.post("/panic", response_model=PanicResponse)
async def panic_all(
    request: Request,
    request_obj: Request,
    cert_fingerprint: str = Depends(require_pepper_auth),
    db: AsyncSession = Depends(get_db),
    x_totp_code: Optional[str] = Header(None, alias="X-TOTP-Code"),
):
    """
    PANIC: Wipe ALL peppers immediately.

    DESTRUCTIVE: Deletes all peppers for this client.
    Requires TOTP code if 2FA enabled.
    """
    await verify_totp_if_enabled(cert_fingerprint, x_totp_code, db)

    service = PepperService(db, settings.get_pepper_config())
    client = await service.get_or_create_client(cert_fingerprint)

    ip_address = get_client_ip(request_obj)
    result = await service.panic_all(client, trigger_type="manual", ip_address=ip_address)
    return PanicResponse(**result)


@limiter.limit("60/minute")
@router.post("/panic/{name}", response_model=PanicResponse)
async def panic_single(
    request: Request,
    name: str,
    request_obj: Request,
    cert_fingerprint: str = Depends(require_pepper_auth),
    db: AsyncSession = Depends(get_db),
    x_totp_code: Optional[str] = Header(None, alias="X-TOTP-Code"),
):
    """
    PANIC: Wipe specific pepper immediately.

    DESTRUCTIVE: Deletes single pepper.
    Requires TOTP code if 2FA enabled.
    """
    await verify_totp_if_enabled(cert_fingerprint, x_totp_code, db)

    service = PepperService(db, settings.get_pepper_config())
    client = await service.get_or_create_client(cert_fingerprint)

    try:
        ip_address = get_client_ip(request_obj)
        result = await service.panic_single(client, name, trigger_type="manual", ip_address=ip_address)
        return PanicResponse(**result)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
