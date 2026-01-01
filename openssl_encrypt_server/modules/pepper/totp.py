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
from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import PPClient, PPTOTPBackupCode

logger = logging.getLogger(__name__)


class TOTPService:
    """
    TOTP 2FA service.

    Handles TOTP setup, verification, and backup code management.
    """

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
        Verify TOTP code or backup code.

        Args:
            client: PPClient instance
            code: TOTP code (6 digits) or backup code (longer)

        Returns:
            True if code valid, False otherwise
        """
        if not client.totp_secret_encrypted or not client.totp_verified:
            return False

        # Try TOTP code first (6 digits)
        if len(code) == 6 and code.isdigit():
            secret = self._decrypt_secret(client.totp_secret_encrypted)
            totp = pyotp.TOTP(secret)
            if totp.verify(code, valid_window=1):
                logger.debug(f"TOTP code verified for {client.cert_fingerprint[:16]}")
                return True

        # Try backup code
        if await self._verify_backup_code(client.id, code):
            logger.info(f"Backup code used for {client.cert_fingerprint[:16]}")
            return True

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
