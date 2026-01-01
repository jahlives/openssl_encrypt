#!/usr/bin/env python3
"""
Pepper service - Business logic for pepper CRUD operations.

Handles:
- Client profile management
- Pepper storage (encrypted blobs)
- Pepper retrieval and listing
- Panic/wipe operations

SECURITY:
- Peppers are encrypted client-side (server stores encrypted blobs)
- Server never sees plaintext peppers
- All operations authenticated via mTLS certificate fingerprint
- Panic operations require TOTP 2FA if enabled
"""

import base64
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import PepperConfig
from .models import PPClient, PPPanicLog, PPPepper
from .schemas import (
    PepperCreateRequest,
    PepperListItem,
    PepperResponse,
    PepperUpdateRequest,
    ProfileUpdateRequest,
)

logger = logging.getLogger(__name__)


class PepperService:
    """
    Service for pepper CRUD operations.

    Handles all business logic for pepper storage, retrieval, and management.
    """

    def __init__(self, db: AsyncSession, config: PepperConfig):
        """
        Initialize pepper service.

        Args:
            db: Database session
            config: PepperConfig instance
        """
        self.db = db
        self.config = config

    async def get_or_create_client(self, cert_fingerprint: str, cert_dn: Optional[str] = None) -> PPClient:
        """
        Get existing client or create new one.

        Auto-registration: First request with valid certificate creates client.

        Args:
            cert_fingerprint: SHA-256 certificate fingerprint
            cert_dn: Optional certificate DN

        Returns:
            PPClient instance
        """
        # Try to get existing client
        result = await self.db.execute(
            select(PPClient).where(PPClient.cert_fingerprint == cert_fingerprint)
        )
        client = result.scalar_one_or_none()

        if client:
            # Update last seen
            client.last_seen_at = datetime.now(timezone.utc)
            await self.db.commit()
            return client

        # Create new client
        client = PPClient(
            cert_fingerprint=cert_fingerprint,
            cert_dn=cert_dn,
        )
        self.db.add(client)
        await self.db.commit()
        await self.db.refresh(client)

        logger.info(f"New pepper client registered: {cert_fingerprint[:16]}")
        return client

    async def get_client(self, cert_fingerprint: str) -> Optional[PPClient]:
        """
        Get client by certificate fingerprint.

        Args:
            cert_fingerprint: SHA-256 certificate fingerprint

        Returns:
            PPClient or None
        """
        result = await self.db.execute(
            select(PPClient).where(PPClient.cert_fingerprint == cert_fingerprint)
        )
        return result.scalar_one_or_none()

    async def get_profile(self, cert_fingerprint: str) -> dict:
        """
        Get client profile.

        Args:
            cert_fingerprint: Certificate fingerprint

        Returns:
            dict with profile information
        """
        client = await self.get_or_create_client(cert_fingerprint)

        # Count peppers
        result = await self.db.execute(
            select(func.count()).select_from(PPPepper).where(PPPepper.client_id == client.id)
        )
        pepper_count = result.scalar()

        return {
            "cert_fingerprint": client.cert_fingerprint,
            "cert_dn": client.cert_dn,
            "name": client.name,
            "totp_enabled": client.totp_verified,
            "created_at": client.created_at.isoformat(),
            "last_seen_at": client.last_seen_at.isoformat() if client.last_seen_at else None,
            "pepper_count": pepper_count,
        }

    async def update_profile(self, cert_fingerprint: str, request: ProfileUpdateRequest) -> dict:
        """
        Update client profile.

        Args:
            cert_fingerprint: Certificate fingerprint
            request: Profile update request

        Returns:
            dict with updated profile
        """
        client = await self.get_or_create_client(cert_fingerprint)

        if request.name is not None:
            client.name = request.name

        await self.db.commit()

        logger.info(f"Profile updated for {cert_fingerprint[:16]}")
        return await self.get_profile(cert_fingerprint)

    async def delete_profile(self, cert_fingerprint: str) -> dict:
        """
        Delete client profile and all associated data.

        DESTRUCTIVE: Deletes client, all peppers, TOTP config, backup codes, deadman config.

        Args:
            cert_fingerprint: Certificate fingerprint

        Returns:
            dict with deletion confirmation
        """
        client = await self.get_or_create_client(cert_fingerprint)

        # Count peppers before deletion
        result = await self.db.execute(
            select(func.count()).select_from(PPPepper).where(PPPepper.client_id == client.id)
        )
        peppers_deleted = result.scalar()

        # Log deletion
        panic_log = PPPanicLog(
            client_id=client.id,
            trigger_type="manual",
            peppers_wiped=peppers_deleted,
            notes="Account deletion"
        )
        self.db.add(panic_log)

        # Delete client (cascade deletes peppers, TOTP, deadman, etc.)
        await self.db.delete(client)
        await self.db.commit()

        logger.warning(f"Profile deleted for {cert_fingerprint[:16]}: {peppers_deleted} peppers wiped")

        return {
            "message": "Profile deleted successfully",
            "peppers_deleted": peppers_deleted
        }

    async def create_pepper(self, client: PPClient, request: PepperCreateRequest) -> PepperResponse:
        """
        Create new pepper.

        Args:
            client: PPClient instance
            request: Pepper creation request

        Returns:
            PepperResponse

        Raises:
            ValueError: If pepper name already exists or limit reached
        """
        # Check for duplicate name
        result = await self.db.execute(
            select(PPPepper).where(
                PPPepper.client_id == client.id,
                PPPepper.name == request.name
            )
        )
        if result.scalar_one_or_none():
            raise ValueError(f"Pepper '{request.name}' already exists")

        # Check pepper limit
        result = await self.db.execute(
            select(func.count()).select_from(PPPepper).where(PPPepper.client_id == client.id)
        )
        pepper_count = result.scalar()
        if pepper_count >= self.config.max_peppers_per_client:
            raise ValueError(f"Maximum {self.config.max_peppers_per_client} peppers per client")

        # Decode base64 pepper
        try:
            pepper_bytes = base64.b64decode(request.pepper_encrypted)
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding: {e}")

        # Create pepper
        pepper = PPPepper(
            client_id=client.id,
            name=request.name,
            pepper_encrypted=pepper_bytes,
            description=request.description,
        )
        self.db.add(pepper)
        await self.db.commit()
        await self.db.refresh(pepper)

        logger.info(f"Pepper created: {request.name} for {client.cert_fingerprint[:16]}")

        return PepperResponse(
            name=pepper.name,
            pepper_encrypted=base64.b64encode(pepper.pepper_encrypted).decode(),
            description=pepper.description,
            created_at=pepper.created_at.isoformat(),
            updated_at=pepper.updated_at.isoformat(),
            last_accessed_at=pepper.last_accessed_at.isoformat() if pepper.last_accessed_at else None,
            access_count=pepper.access_count,
        )

    async def get_pepper(self, client: PPClient, name: str) -> PepperResponse:
        """
        Get pepper by name.

        Args:
            client: PPClient instance
            name: Pepper name

        Returns:
            PepperResponse

        Raises:
            ValueError: If pepper not found
        """
        result = await self.db.execute(
            select(PPPepper).where(
                PPPepper.client_id == client.id,
                PPPepper.name == name
            )
        )
        pepper = result.scalar_one_or_none()
        if not pepper:
            raise ValueError(f"Pepper '{name}' not found")

        # Update access tracking
        pepper.last_accessed_at = datetime.now(timezone.utc)
        pepper.access_count += 1
        await self.db.commit()

        return PepperResponse(
            name=pepper.name,
            pepper_encrypted=base64.b64encode(pepper.pepper_encrypted).decode(),
            description=pepper.description,
            created_at=pepper.created_at.isoformat(),
            updated_at=pepper.updated_at.isoformat(),
            last_accessed_at=pepper.last_accessed_at.isoformat() if pepper.last_accessed_at else None,
            access_count=pepper.access_count,
        )

    async def list_peppers(self, client: PPClient) -> dict:
        """
        List all peppers for client (metadata only, no encrypted blobs).

        Args:
            client: PPClient instance

        Returns:
            dict with peppers list and total count
        """
        result = await self.db.execute(
            select(PPPepper).where(PPPepper.client_id == client.id).order_by(PPPepper.created_at)
        )
        peppers = result.scalars().all()

        pepper_list = [
            PepperListItem(
                name=p.name,
                description=p.description,
                created_at=p.created_at.isoformat(),
                updated_at=p.updated_at.isoformat(),
                access_count=p.access_count,
            )
            for p in peppers
        ]

        return {
            "peppers": pepper_list,
            "total": len(pepper_list),
        }

    async def update_pepper(self, client: PPClient, name: str, request: PepperUpdateRequest) -> PepperResponse:
        """
        Update pepper.

        Args:
            client: PPClient instance
            name: Pepper name
            request: Update request

        Returns:
            PepperResponse

        Raises:
            ValueError: If pepper not found
        """
        result = await self.db.execute(
            select(PPPepper).where(
                PPPepper.client_id == client.id,
                PPPepper.name == name
            )
        )
        pepper = result.scalar_one_or_none()
        if not pepper:
            raise ValueError(f"Pepper '{name}' not found")

        # Decode base64 pepper
        try:
            pepper_bytes = base64.b64decode(request.pepper_encrypted)
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding: {e}")

        # Update pepper
        pepper.pepper_encrypted = pepper_bytes
        if request.description is not None:
            pepper.description = request.description
        pepper.updated_at = datetime.now(timezone.utc)

        await self.db.commit()

        logger.info(f"Pepper updated: {name} for {client.cert_fingerprint[:16]}")

        return PepperResponse(
            name=pepper.name,
            pepper_encrypted=base64.b64encode(pepper.pepper_encrypted).decode(),
            description=pepper.description,
            created_at=pepper.created_at.isoformat(),
            updated_at=pepper.updated_at.isoformat(),
            last_accessed_at=pepper.last_accessed_at.isoformat() if pepper.last_accessed_at else None,
            access_count=pepper.access_count,
        )

    async def delete_pepper(self, client: PPClient, name: str) -> dict:
        """
        Delete specific pepper.

        Args:
            client: PPClient instance
            name: Pepper name

        Returns:
            dict with deletion confirmation

        Raises:
            ValueError: If pepper not found
        """
        result = await self.db.execute(
            select(PPPepper).where(
                PPPepper.client_id == client.id,
                PPPepper.name == name
            )
        )
        pepper = result.scalar_one_or_none()
        if not pepper:
            raise ValueError(f"Pepper '{name}' not found")

        await self.db.delete(pepper)
        await self.db.commit()

        logger.info(f"Pepper deleted: {name} for {client.cert_fingerprint[:16]}")

        return {"message": f"Pepper '{name}' deleted successfully"}

    async def panic_all(self, client: PPClient, trigger_type: str = "manual", ip_address: Optional[str] = None) -> dict:
        """
        Panic: Wipe ALL peppers for client.

        DESTRUCTIVE: Deletes all peppers immediately.

        Args:
            client: PPClient instance
            trigger_type: 'manual', 'deadman', or 'emergency'
            ip_address: Optional IP address for audit

        Returns:
            dict with peppers_wiped count
        """
        # Count peppers
        result = await self.db.execute(
            select(func.count()).select_from(PPPepper).where(PPPepper.client_id == client.id)
        )
        peppers_wiped = result.scalar()

        # Delete all peppers
        await self.db.execute(
            PPPepper.__table__.delete().where(PPPepper.client_id == client.id)
        )

        # Log panic event
        panic_log = PPPanicLog(
            client_id=client.id,
            trigger_type=trigger_type,
            peppers_wiped=peppers_wiped,
            ip_address=ip_address,
            notes=f"All peppers wiped via {trigger_type} panic"
        )
        self.db.add(panic_log)

        await self.db.commit()

        logger.warning(f"PANIC: All peppers wiped for {client.cert_fingerprint[:16]}: {peppers_wiped} peppers")

        return {
            "message": "All peppers wiped",
            "peppers_wiped": peppers_wiped,
            "trigger_type": trigger_type,
        }

    async def panic_single(
        self,
        client: PPClient,
        name: str,
        trigger_type: str = "manual",
        ip_address: Optional[str] = None
    ) -> dict:
        """
        Panic: Wipe specific pepper.

        DESTRUCTIVE: Deletes single pepper immediately.

        Args:
            client: PPClient instance
            name: Pepper name
            trigger_type: 'manual', 'deadman', or 'emergency'
            ip_address: Optional IP address for audit

        Returns:
            dict with deletion confirmation

        Raises:
            ValueError: If pepper not found
        """
        result = await self.db.execute(
            select(PPPepper).where(
                PPPepper.client_id == client.id,
                PPPepper.name == name
            )
        )
        pepper = result.scalar_one_or_none()
        if not pepper:
            raise ValueError(f"Pepper '{name}' not found")

        # Delete pepper
        await self.db.delete(pepper)

        # Log panic event
        panic_log = PPPanicLog(
            client_id=client.id,
            trigger_type=trigger_type,
            peppers_wiped=1,
            specific_pepper=name,
            ip_address=ip_address,
            notes=f"Single pepper '{name}' wiped via {trigger_type} panic"
        )
        self.db.add(panic_log)

        await self.db.commit()

        logger.warning(f"PANIC: Pepper '{name}' wiped for {client.cert_fingerprint[:16]}")

        return {
            "message": f"Pepper '{name}' wiped",
            "peppers_wiped": 1,
            "trigger_type": trigger_type,
        }
