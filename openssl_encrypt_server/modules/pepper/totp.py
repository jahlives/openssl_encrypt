#!/usr/bin/env python3
"""
TOTP 2FA Service.

Implements Time-based One-Time Password (TOTP) two-factor authentication with:
- QR code generation for authenticator apps
- Backup codes for account recovery
- Fernet encryption of TOTP secrets at rest
- Argon2 hashing of backup codes

SECURITY:
- TOTP secrets encrypted with Fernet before storage
- Backup codes hashed with Argon2 (irreversible)
- Single-use backup codes (marked as used)
- 30-second time window for TOTP codes
"""

import base64
import io
import logging
import secrets
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from uuid import UUID

import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.security_logger import (
    SecurityEventSeverity,
    SecurityEventType,
    get_security_logger,
)
from .models import PPClient, PPTOTPBackupCode

logger = logging.getLogger(__name__)
security_logger = get_security_logger()


class TOTPRateLimiter:
    """
    Rate limiter for TOTP verification attempts.

    Prevents brute force attacks on TOTP codes by:
    - Limiting to 5 attempts per 5 minutes per client
    - Locking out client for 15 minutes after 5 failed attempts
    - Cleaning up old attempt records automatically

    Thread-safe for concurrent requests.
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_minutes: int = 5,
        lockout_minutes: int = 15
    ):
        """
        Initialize rate limiter.

        Args:
            max_attempts: Maximum attempts allowed in window
            window_minutes: Time window for counting attempts (minutes)
            lockout_minutes: Lockout duration after max attempts exceeded (minutes)
        """
        self.max_attempts = max_attempts
        self.window = timedelta(minutes=window_minutes)
        self.lockout_duration = timedelta(minutes=lockout_minutes)

        # Track attempts: client_id -> list of attempt timestamps
        self.attempts: Dict[str, List[datetime]] = defaultdict(list)

        # Track lockouts: client_id -> lockout_until timestamp
        self.lockouts: Dict[str, datetime] = {}

        logger.info(
            f"TOTP rate limiter initialized: {max_attempts} attempts per "
            f"{window_minutes} minutes, {lockout_minutes} minute lockout"
        )

    def _clean_old_attempts(self, client_id: str):
        """Remove attempts older than the time window."""
        now = datetime.now(timezone.utc)
        cutoff = now - self.window

        if client_id in self.attempts:
            self.attempts[client_id] = [
                timestamp for timestamp in self.attempts[client_id]
                if timestamp > cutoff
            ]

            # Remove empty lists to save memory
            if not self.attempts[client_id]:
                del self.attempts[client_id]

    def check_rate_limit(self, client_id: str) -> None:
        """
        Check if client is rate limited.

        Args:
            client_id: Client identifier (cert fingerprint)

        Raises:
            HTTPException: 429 if client is rate limited or locked out
        """
        now = datetime.now(timezone.utc)

        # Check if client is locked out
        if client_id in self.lockouts:
            lockout_until = self.lockouts[client_id]
            if now < lockout_until:
                remaining_seconds = int((lockout_until - now).total_seconds())
                remaining_minutes = remaining_seconds // 60
                logger.warning(
                    f"TOTP verification blocked - client locked out: "
                    f"{client_id[:16]}... ({remaining_seconds}s remaining)"
                )
                if remaining_minutes > 0:
                    detail_msg = f"Too many failed TOTP attempts. Try again in {remaining_minutes} minute(s)."
                else:
                    detail_msg = f"Too many failed TOTP attempts. Try again in {remaining_seconds} seconds."
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=detail_msg
                )
            else:
                # Lockout expired, remove it
                del self.lockouts[client_id]
                logger.info(f"TOTP lockout expired for {client_id[:16]}...")

        # Clean old attempts
        self._clean_old_attempts(client_id)

        # Check attempt count
        attempt_count = len(self.attempts.get(client_id, []))
        if attempt_count >= self.max_attempts:
            # Lock out the client
            lockout_until = now + self.lockout_duration
            self.lockouts[client_id] = lockout_until

            lockout_seconds = int(self.lockout_duration.total_seconds())

            logger.warning(
                f"TOTP rate limit exceeded - locking out client: {client_id[:16]}... "
                f"for {self.lockout_duration.total_seconds()/60} minutes"
            )

            # Log security event
            security_logger.log_totp_lockout(
                client_id=client_id,
                attempts=attempt_count,
                lockout_duration_seconds=lockout_seconds
            )

            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed TOTP attempts. Locked out for {lockout_seconds} seconds."
            )

    def record_attempt(self, client_id: str):
        """
        Record a failed TOTP verification attempt.

        Args:
            client_id: Client identifier (cert fingerprint)
        """
        now = datetime.now(timezone.utc)
        self.attempts[client_id].append(now)

        attempt_count = len(self.attempts[client_id])
        logger.debug(
            f"TOTP attempt recorded for {client_id[:16]}... "
            f"({attempt_count}/{self.max_attempts})"
        )

    def clear_attempts(self, client_id: str):
        """
        Clear attempts for client (after successful verification).

        Args:
            client_id: Client identifier (cert fingerprint)
        """
        if client_id in self.attempts:
            del self.attempts[client_id]
            logger.debug(f"TOTP attempts cleared for {client_id[:16]}...")

        # Also clear any lockout
        if client_id in self.lockouts:
            del self.lockouts[client_id]


class TOTPService:
    """
    TOTP 2FA service.

    Handles TOTP setup, verification, and backup code management with rate limiting.
    """

    # Shared rate limiter across all TOTPService instances
    _rate_limiter = TOTPRateLimiter()

    def __init__(self, db: AsyncSession, issuer: str = "openssl_encrypt", fernet_key: Optional[str] = None):
        """
        Initialize TOTP service.

        Args:
            db: Database session
            issuer: Issuer name for TOTP URIs
            fernet_key: Fernet encryption key for TOTP secrets (44-char base64)
        """
        self.db = db
        self.issuer = issuer
        self._fernet = Fernet(fernet_key.encode()) if fernet_key else None
        self._ph = PasswordHasher()  # Argon2 for backup codes

    def _encrypt_secret(self, secret: str) -> bytes:
        """
        Encrypt TOTP secret with Fernet.

        Args:
            secret: Base32-encoded TOTP secret

        Returns:
            Encrypted secret bytes

        Raises:
            RuntimeError: If Fernet key not configured
        """
        if not self._fernet:
            raise RuntimeError("TOTP secret encryption key not configured")
        return self._fernet.encrypt(secret.encode())

    def _decrypt_secret(self, encrypted: bytes) -> str:
        """
        Decrypt TOTP secret.

        Args:
            encrypted: Encrypted secret bytes

        Returns:
            Decrypted base32-encoded secret

        Raises:
            RuntimeError: If Fernet key not configured
        """
        if not self._fernet:
            raise RuntimeError("TOTP secret encryption key not configured")
        return self._fernet.decrypt(encrypted).decode()

    async def setup(self, client: PPClient) -> dict:
        """
        Setup TOTP for client.

        Generates a new TOTP secret and QR code for authenticator apps.

        Args:
            client: PPClient instance

        Returns:
            dict with secret, qr_svg, uri, message
        """
        # Generate random TOTP secret (base32)
        secret = pyotp.random_base32()

        # Create TOTP object
        totp = pyotp.TOTP(secret)

        # Generate provisioning URI for authenticator apps
        # Format: otpauth://totp/issuer:account?secret=...&issuer=...
        account = client.name or client.cert_fingerprint[:16]
        uri = totp.provisioning_uri(name=account, issuer_name=self.issuer)

        # Generate QR code as SVG
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(uri)
        qr.make(fit=True)

        # Convert to SVG
        img_buffer = io.BytesIO()
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(img_buffer, format="PNG")
        img_buffer.seek(0)

        # For SVG, use factory
        from qrcode.image.svg import SvgPathImage
        qr_svg = qrcode.QRCode(image_factory=SvgPathImage)
        qr_svg.add_data(uri)
        qr_svg.make(fit=True)
        svg_buffer = io.BytesIO()
        qr_svg.make_image().save(svg_buffer)
        svg_str = svg_buffer.getvalue().decode()

        # Encrypt and store secret (not yet verified)
        client.totp_secret_encrypted = self._encrypt_secret(secret)
        client.totp_verified = False
        await self.db.commit()

        logger.info(f"TOTP setup initiated for client {client.cert_fingerprint[:16]}")

        return {
            "secret": secret,
            "qr_svg": svg_str,
            "uri": uri,
            "message": "Scan QR code with your authenticator app, then verify with a code"
        }

    async def verify_setup(self, client: PPClient, code: str) -> dict:
        """
        Verify TOTP setup with a code.

        Generates backup codes and marks TOTP as verified.

        Args:
            client: PPClient instance
            code: 6-digit TOTP code from authenticator app

        Returns:
            dict with message and backup_codes

        Raises:
            ValueError: If TOTP not set up or code invalid
        """
        if not client.totp_secret_encrypted:
            raise ValueError("TOTP not set up. Call setup() first.")

        # Decrypt secret
        secret = self._decrypt_secret(client.totp_secret_encrypted)

        # Verify code
        totp = pyotp.TOTP(secret)
        if not totp.verify(code, valid_window=1):
            raise ValueError("Invalid TOTP code")

        # Mark as verified
        client.totp_verified = True

        # Generate backup codes
        backup_codes = await self._generate_backup_codes(client.id)

        await self.db.commit()

        logger.info(f"TOTP verified for client {client.cert_fingerprint[:16]}")

        return {
            "message": "TOTP enabled successfully",
            "backup_codes": backup_codes,
            "backup_codes_warning": "Save these backup codes in a secure location. Each can only be used once."
        }

    async def verify_code(self, client: PPClient, code: str) -> bool:
        """
        Verify TOTP code or backup code with rate limiting.

        SECURITY: Rate limiting prevents brute force attacks on TOTP codes.
        - Maximum 5 attempts per 5 minutes per client
        - 15-minute lockout after exceeding limit

        Args:
            client: PPClient instance
            code: TOTP code (6 digits) or backup code (longer)

        Returns:
            True if code valid, False otherwise

        Raises:
            HTTPException: 429 if rate limited or locked out
        """
        if not client.totp_secret_encrypted or not client.totp_verified:
            return False

        # Check rate limit BEFORE attempting verification
        # This prevents timing attacks and brute force
        self._rate_limiter.check_rate_limit(client.cert_fingerprint)

        verification_successful = False

        # Try TOTP code first (6 digits)
        if len(code) == 6 and code.isdigit():
            secret = self._decrypt_secret(client.totp_secret_encrypted)
            totp = pyotp.TOTP(secret)
            if totp.verify(code, valid_window=1):
                logger.debug(f"TOTP code verified for {client.cert_fingerprint[:16]}")
                verification_successful = True

        # Try backup code if TOTP didn't match
        if not verification_successful:
            if await self._verify_backup_code(client.id, code):
                logger.info(f"Backup code used for {client.cert_fingerprint[:16]}")
                verification_successful = True

        # Handle rate limiting based on verification result
        if verification_successful:
            # Clear attempts on successful verification
            self._rate_limiter.clear_attempts(client.cert_fingerprint)
            return True
        else:
            # Record failed attempt
            self._rate_limiter.record_attempt(client.cert_fingerprint)

            # Log security event for failed TOTP attempt
            attempt_count = len(self._rate_limiter.attempts.get(client.cert_fingerprint, []))
            security_logger.log_event(
                SecurityEventType.TOTP_FAILURE,
                SecurityEventSeverity.WARNING,
                client.cert_fingerprint,
                {"attempt_count": attempt_count, "max_attempts": self._rate_limiter.max_attempts},
                f"Failed TOTP verification ({attempt_count}/{self._rate_limiter.max_attempts})"
            )

            return False

    async def disable(self, client: PPClient, code: str) -> dict:
        """
        Disable TOTP for client.

        Requires valid TOTP code for confirmation.

        Args:
            client: PPClient instance
            code: TOTP code for confirmation

        Returns:
            dict with message

        Raises:
            ValueError: If code invalid
        """
        if not await self.verify_code(client, code):
            raise ValueError("Invalid TOTP code")

        # Delete TOTP secret and backup codes
        client.totp_secret_encrypted = None
        client.totp_verified = False

        # Delete all backup codes
        await self.db.execute(
            select(PPTOTPBackupCode).where(PPTOTPBackupCode.client_id == client.id)
        )
        await self.db.execute(
            PPTOTPBackupCode.__table__.delete().where(PPTOTPBackupCode.client_id == client.id)
        )

        await self.db.commit()

        logger.info(f"TOTP disabled for client {client.cert_fingerprint[:16]}")

        return {"message": "TOTP disabled successfully"}

    async def regenerate_backup_codes(self, client_id: UUID, code: str) -> List[str]:
        """
        Generate new backup codes.

        Deletes old codes and creates new ones.

        Args:
            client_id: Client UUID
            code: TOTP code for confirmation

        Returns:
            List of new backup codes

        Raises:
            ValueError: If TOTP code invalid
        """
        # Get client
        result = await self.db.execute(
            select(PPClient).where(PPClient.id == client_id)
        )
        client = result.scalar_one_or_none()
        if not client:
            raise ValueError("Client not found")

        # Verify TOTP code
        if not await self.verify_code(client, code):
            raise ValueError("Invalid TOTP code")

        # Delete old backup codes
        await self.db.execute(
            PPTOTPBackupCode.__table__.delete().where(PPTOTPBackupCode.client_id == client_id)
        )

        # Generate new codes
        backup_codes = await self._generate_backup_codes(client_id)

        await self.db.commit()

        logger.info(f"Backup codes regenerated for client {client.cert_fingerprint[:16]}")

        return backup_codes

    async def _generate_backup_codes(self, client_id: UUID, count: int = 10) -> List[str]:
        """
        Generate backup codes for client.

        Args:
            client_id: Client UUID
            count: Number of codes to generate (default: 10)

        Returns:
            List of backup codes (plaintext, to be shown once)
        """
        backup_codes = []

        for _ in range(count):
            # Generate random 8-character alphanumeric code
            code = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(8))
            backup_codes.append(code)

            # Hash with Argon2 and store
            code_hash = self._ph.hash(code)
            backup_code = PPTOTPBackupCode(
                client_id=client_id,
                code_hash=code_hash,
            )
            self.db.add(backup_code)

        return backup_codes

    async def _verify_backup_code(self, client_id: UUID, code: str) -> bool:
        """
        Verify and mark backup code as used.

        Args:
            client_id: Client UUID
            code: Backup code to verify

        Returns:
            True if code valid and not used, False otherwise
        """
        # Get unused backup codes
        result = await self.db.execute(
            select(PPTOTPBackupCode).where(
                PPTOTPBackupCode.client_id == client_id,
                PPTOTPBackupCode.used_at.is_(None)
            )
        )
        codes = result.scalars().all()

        # Try to verify against each unused code
        for backup_code in codes:
            try:
                self._ph.verify(backup_code.code_hash, code)
                # Code matches! Mark as used
                backup_code.used_at = datetime.now(timezone.utc)
                await self.db.commit()
                return True
            except VerifyMismatchError:
                continue

        return False
