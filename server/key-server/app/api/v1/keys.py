#!/usr/bin/env python3
"""
API Endpoints - Keys

This module implements the keyserver API endpoints:
- POST /api/v1/keys - Upload key (requires authentication)
- GET /api/v1/keys/search - Search for key (public, no auth)
- POST /api/v1/keys/{fingerprint}/revoke - Revoke key (requires authentication)

SECURITY:
- Upload and revoke require Bearer token authentication
- Search is public (no authentication)
- All bundles verified before storage
- Rate limiting applied
"""

import json
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from ...config import settings
from ...database import get_db
from ...models.public_key import PublicKey
from ...schemas.key_bundle import (
    ErrorResponse,
    KeyBundleSchema,
    KeySearchResponse,
    KeyUploadResponse,
    RevocationRequest,
    RevocationResponse,
)
from ...services.verification import (
    FingerprintMismatchError,
    VerificationError,
    verify_bundle_signature,
    verify_revocation_signature,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["keys"])


def verify_api_token(authorization: Optional[str] = Header(None)) -> bool:
    """
    Verify Bearer token authentication using HMAC-signed tokens.

    Token format: base64(payload_json).base64(hmac_signature)
    Payload must contain: exp (expiration timestamp), iss (issuer)

    Args:
        authorization: Authorization header (Bearer token)

    Returns:
        True if authenticated

    Raises:
        HTTPException: If authentication fails
    """
    import base64
    import hashlib
    import hmac
    import json
    import time

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format. Expected: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization[7:]  # Remove "Bearer " prefix

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Empty API token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Validate HMAC-signed token
    try:
        parts = token.split(".")
        if len(parts) != 2:
            raise ValueError("Invalid token format")

        payload_b64, signature_b64 = parts

        # Verify HMAC signature
        expected_sig = hmac.new(
            settings.api_token_secret.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256,
        ).digest()

        provided_sig = base64.urlsafe_b64decode(signature_b64 + "==")  # Pad base64

        if not hmac.compare_digest(expected_sig, provided_sig):
            raise ValueError("Invalid token signature")

        # Decode and validate payload
        # Add padding for base64
        padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))

        # Validate expiration
        if "exp" not in payload:
            raise ValueError("Token missing expiration claim")

        if time.time() > payload["exp"]:
            raise ValueError("Token has expired")

        # Validate issuer
        expected_issuer = "openssl_encrypt_keyserver"
        if payload.get("iss") != expected_issuer:
            raise ValueError(f"Invalid token issuer: expected '{expected_issuer}'")

        logger.debug("API token validated successfully")
        return True

    except ValueError as e:
        logger.warning(f"Token validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.error(f"Unexpected token validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token validation failed",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post(
    "/keys",
    response_model=KeyUploadResponse,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid bundle or verification failed"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        409: {"model": ErrorResponse, "description": "Key already exists"},
    },
)
async def upload_key(
    bundle: KeyBundleSchema,
    db: Session = Depends(get_db),
    authenticated: bool = Depends(verify_api_token),
):
    """
    Upload public key bundle to keyserver.

    SECURITY:
    - Requires Bearer token authentication
    - Verifies self-signature before storage
    - Validates fingerprint
    - Enforces algorithm whitelist

    Args:
        bundle: Public key bundle (validated by Pydantic)
        db: Database session
        authenticated: Authentication status (from dependency)

    Returns:
        KeyUploadResponse with success status

    Raises:
        HTTPException 400: If bundle verification fails
        HTTPException 401: If authentication fails
        HTTPException 409: If key already exists
    """
    logger.info(f"Upload request for key '{bundle.name}' (fp: {bundle.fingerprint[:20]}...)")

    # Verify bundle signature and fingerprint
    try:
        bundle_dict = bundle.model_dump()
        verify_bundle_signature(bundle_dict)
    except (VerificationError, FingerprintMismatchError) as e:
        logger.error(f"Bundle verification failed: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected verification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Verification failed: {e}"
        )

    # Check if key already exists
    existing_key = db.query(PublicKey).filter(PublicKey.fingerprint == bundle.fingerprint).first()

    if existing_key:
        if not existing_key.revoked:
            # Key exists and is not revoked - return conflict
            logger.info(f"Key already exists: {bundle.fingerprint}")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Key with fingerprint {bundle.fingerprint} already exists",
            )
        else:
            # Key was revoked - allow re-upload (un-revoke)
            logger.info(f"Re-uploading previously revoked key: {bundle.fingerprint}")
            existing_key.bundle_json = json.dumps(bundle_dict)
            existing_key.name = bundle.name
            existing_key.email = bundle.email
            existing_key.encryption_algorithm = bundle.encryption_algorithm
            existing_key.signing_algorithm = bundle.signing_algorithm
            existing_key.revoked = False
            existing_key.revoked_at = None
            existing_key.upload_count += 1
            existing_key.updated_at = datetime.utcnow()
            db.commit()

            return KeyUploadResponse(
                success=True,
                fingerprint=bundle.fingerprint,
                message="Key re-uploaded successfully (un-revoked)",
            )

    # Store new key
    new_key = PublicKey(
        fingerprint=bundle.fingerprint,
        name=bundle.name,
        email=bundle.email,
        encryption_algorithm=bundle.encryption_algorithm,
        signing_algorithm=bundle.signing_algorithm,
        bundle_json=json.dumps(bundle_dict),
        revoked=False,
    )

    db.add(new_key)
    db.commit()
    db.refresh(new_key)

    logger.info(f"Key uploaded successfully: {bundle.name} (fp: {bundle.fingerprint[:20]}...)")

    return KeyUploadResponse(
        success=True, fingerprint=bundle.fingerprint, message="Key uploaded successfully"
    )


@router.get(
    "/keys/search",
    response_model=KeySearchResponse,
    status_code=status.HTTP_200_OK,
    responses={404: {"model": ErrorResponse, "description": "Key not found"}},
)
async def search_key(
    q: str = Query(..., description="Search query: fingerprint, name, or email"),
    db: Session = Depends(get_db),
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
        db: Database session

    Returns:
        KeySearchResponse with key bundle if found

    Raises:
        HTTPException 404: If key not found
    """
    logger.info(f"Search request for: '{q}'")

    # Search by fingerprint (exact or prefix), name, or email
    # Priority: fingerprint > name > email
    key = (
        db.query(PublicKey)
        .filter(
            (PublicKey.fingerprint == q)
            | (PublicKey.fingerprint.startswith(q))
            | (PublicKey.name == q)
            | (PublicKey.email == q)
        )
        .filter(PublicKey.revoked == False)  # Only active keys
        .order_by(PublicKey.created_at.desc())  # Newest first
        .first()
    )

    if not key:
        logger.info(f"Key not found for query: '{q}'")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")

    # Parse bundle JSON
    bundle_data = json.loads(key.bundle_json)

    logger.info(f"Key found: {key.name} (fp: {key.fingerprint[:20]}...)")

    return KeySearchResponse(key=KeyBundleSchema(**bundle_data), message="Key found")


@router.post(
    "/keys/{fingerprint}/revoke",
    response_model=RevocationResponse,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid revocation signature"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        404: {"model": ErrorResponse, "description": "Key not found"},
    },
)
async def revoke_key(
    fingerprint: str,
    revocation: RevocationRequest,
    db: Session = Depends(get_db),
    authenticated: bool = Depends(verify_api_token),
):
    """
    Revoke public key.

    SECURITY:
    - Requires Bearer token authentication
    - Requires revocation signature (proof of ownership)
    - Marks key as revoked (doesn't delete)

    Args:
        fingerprint: Fingerprint of key to revoke
        revocation: Revocation request with signature
        db: Database session
        authenticated: Authentication status (from dependency)

    Returns:
        RevocationResponse with success status

    Raises:
        HTTPException 400: If revocation signature invalid
        HTTPException 401: If authentication fails
        HTTPException 404: If key not found
    """
    logger.info(f"Revocation request for fingerprint: {fingerprint[:20]}...")

    # Find key
    key = db.query(PublicKey).filter(PublicKey.fingerprint == fingerprint).first()

    if not key:
        logger.error(f"Key not found for revocation: {fingerprint}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")

    if key.revoked:
        logger.info(f"Key already revoked: {fingerprint}")
        return RevocationResponse(
            success=True, fingerprint=fingerprint, message="Key already revoked"
        )

    # Parse bundle to get signing public key
    bundle_data = json.loads(key.bundle_json)

    # Verify revocation signature — this IS the ownership check.
    # The revocation must be signed with the private key corresponding to
    # the bundle's signing public key. Only the key owner possesses this
    # private key, making this cryptographic proof of ownership (stronger
    # than account-based checks).
    try:
        verify_revocation_signature(
            fingerprint=fingerprint,
            signature_hex=revocation.signature,
            signing_public_key_b64=bundle_data["signing_public_key"],
            signing_algorithm=bundle_data["signing_algorithm"],
        )
        logger.info(f"Revocation signature verified (ownership proven) for: {fingerprint[:20]}...")
    except VerificationError as e:
        logger.error(f"Revocation signature verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid revocation signature: {e}"
        )

    # Mark as revoked
    key.revoked = True
    key.revoked_at = datetime.utcnow()
    db.commit()

    logger.info(f"Key revoked successfully: {fingerprint}")

    return RevocationResponse(
        success=True, fingerprint=fingerprint, message="Key revoked successfully"
    )
