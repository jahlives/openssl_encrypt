#!/usr/bin/env python3
"""
Integrity Service Layer

Business logic for integrity verification operations.
"""

import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.security_logger import get_security_logger
from .models import INClient, INMetadataHash, INVerificationLog
from .schemas import (
    HashListResponse,
    HashResponse,
    HashStoreRequest,
    HashUpdateRequest,
    ProfileResponse,
    StatsResponse,
    VerifyRequest,
    VerifyResponse,
)

logger = logging.getLogger(__name__)
security_logger = get_security_logger()


class IntegrityService:
    """Service layer for integrity operations"""

    def __init__(self, db: AsyncSession):
        """
        Initialize integrity service.

        Args:
            db: AsyncSession for database operations
        """
        self.db = db

    async def get_or_create_client(
        self, cert_fingerprint: str, cert_dn: Optional[str] = None
    ) -> INClient:
        """
        Get existing client or create new one (auto-registration).

        Args:
            cert_fingerprint: Client certificate SHA-256 fingerprint
            cert_dn: Optional certificate Distinguished Name

        Returns:
            INClient instance
        """
        # Try to find existing client
        result = await self.db.execute(
            select(INClient).where(INClient.cert_fingerprint == cert_fingerprint)
        )
        client = result.scalar_one_or_none()

        if client:
            # Update last_seen_at
            client.last_seen_at = datetime.now(timezone.utc)
            await self.db.commit()
            await self.db.refresh(client)
            return client

        # Create new client
        client = INClient(
            cert_fingerprint=cert_fingerprint,
            cert_dn=cert_dn,
        )
        self.db.add(client)
        await self.db.commit()
        await self.db.refresh(client)

        logger.info(f"New integrity client registered: {cert_fingerprint[:16]}...")
        return client

    async def get_profile(self, cert_fingerprint: str) -> ProfileResponse:
        """
        Get client profile information.

        Args:
            cert_fingerprint: Client certificate fingerprint

        Returns:
            ProfileResponse with client info and hash count
        """
        client = await self.get_or_create_client(cert_fingerprint)

        # Count hashes for this client
        result = await self.db.execute(
            select(func.count()).select_from(INMetadataHash).where(
                INMetadataHash.cert_fingerprint == cert_fingerprint
            )
        )
        hash_count = result.scalar_one()

        return ProfileResponse(
            cert_fingerprint=client.cert_fingerprint,
            cert_dn=client.cert_dn,
            name=client.name,
            created_at=client.created_at,
            last_seen_at=client.last_seen_at,
            hash_count=hash_count,
        )

    async def update_profile(self, cert_fingerprint: str, name: str) -> ProfileResponse:
        """
        Update client profile.

        Args:
            cert_fingerprint: Client certificate fingerprint
            name: New display name

        Returns:
            Updated ProfileResponse
        """
        client = await self.get_or_create_client(cert_fingerprint)
        client.name = name
        client.last_seen_at = datetime.now(timezone.utc)
        await self.db.commit()
        await self.db.refresh(client)

        return await self.get_profile(cert_fingerprint)

    async def store_hash(
        self, cert_fingerprint: str, request: HashStoreRequest
    ) -> HashResponse:
        """
        Store a new metadata hash.

        Args:
            cert_fingerprint: Client certificate fingerprint
            request: HashStoreRequest with file details

        Returns:
            HashResponse with stored hash info

        Raises:
            HTTPException: If hash already exists for this file
        """
        # Ensure client exists
        await self.get_or_create_client(cert_fingerprint)

        # Check if hash already exists
        result = await self.db.execute(
            select(INMetadataHash).where(
                INMetadataHash.cert_fingerprint == cert_fingerprint,
                INMetadataHash.file_id == request.file_id,
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Hash already exists for file_id '{request.file_id}'. Use PUT to update.",
            )

        # Create new hash record
        hash_record = INMetadataHash(
            cert_fingerprint=cert_fingerprint,
            file_id=request.file_id,
            metadata_hash=request.metadata_hash,
            algorithm=request.algorithm,
            description=request.description,
        )
        self.db.add(hash_record)
        await self.db.commit()
        await self.db.refresh(hash_record)

        logger.info(f"Stored hash for {cert_fingerprint[:16]}... / {request.file_id}")

        return HashResponse(
            file_id=hash_record.file_id,
            metadata_hash=hash_record.metadata_hash,
            algorithm=hash_record.algorithm,
            description=hash_record.description,
            created_at=hash_record.created_at,
            updated_at=hash_record.updated_at,
            verified_at=hash_record.verified_at,
            verification_count=hash_record.verification_count,
        )

    async def list_hashes(self, cert_fingerprint: str) -> HashListResponse:
        """
        List all stored hashes for a client.

        Args:
            cert_fingerprint: Client certificate fingerprint

        Returns:
            HashListResponse with list of hashes
        """
        result = await self.db.execute(
            select(INMetadataHash)
            .where(INMetadataHash.cert_fingerprint == cert_fingerprint)
            .order_by(INMetadataHash.created_at.desc())
        )
        hashes = result.scalars().all()

        hash_responses = [
            HashResponse(
                file_id=h.file_id,
                metadata_hash=h.metadata_hash,
                algorithm=h.algorithm,
                description=h.description,
                created_at=h.created_at,
                updated_at=h.updated_at,
                verified_at=h.verified_at,
                verification_count=h.verification_count,
            )
            for h in hashes
        ]

        return HashListResponse(hashes=hash_responses, total=len(hash_responses))

    async def get_hash(self, cert_fingerprint: str, file_id: str) -> HashResponse:
        """
        Get a specific hash by file_id.

        Args:
            cert_fingerprint: Client certificate fingerprint
            file_id: File identifier

        Returns:
            HashResponse

        Raises:
            HTTPException: 404 if hash not found
        """
        result = await self.db.execute(
            select(INMetadataHash).where(
                INMetadataHash.cert_fingerprint == cert_fingerprint,
                INMetadataHash.file_id == file_id,
            )
        )
        hash_record = result.scalar_one_or_none()

        if not hash_record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Hash not found for file_id '{file_id}'",
            )

        return HashResponse(
            file_id=hash_record.file_id,
            metadata_hash=hash_record.metadata_hash,
            algorithm=hash_record.algorithm,
            description=hash_record.description,
            created_at=hash_record.created_at,
            updated_at=hash_record.updated_at,
            verified_at=hash_record.verified_at,
            verification_count=hash_record.verification_count,
        )

    async def update_hash(
        self, cert_fingerprint: str, file_id: str, request: HashUpdateRequest
    ) -> HashResponse:
        """
        Update an existing hash.

        Args:
            cert_fingerprint: Client certificate fingerprint
            file_id: File identifier
            request: HashUpdateRequest with new hash value

        Returns:
            HashResponse with updated info

        Raises:
            HTTPException: 404 if hash not found
        """
        result = await self.db.execute(
            select(INMetadataHash).where(
                INMetadataHash.cert_fingerprint == cert_fingerprint,
                INMetadataHash.file_id == file_id,
            )
        )
        hash_record = result.scalar_one_or_none()

        if not hash_record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Hash not found for file_id '{file_id}'",
            )

        # Update hash
        hash_record.metadata_hash = request.metadata_hash
        if request.description is not None:
            hash_record.description = request.description
        hash_record.updated_at = datetime.now(timezone.utc)

        await self.db.commit()
        await self.db.refresh(hash_record)

        logger.info(f"Updated hash for {cert_fingerprint[:16]}... / {file_id}")

        return HashResponse(
            file_id=hash_record.file_id,
            metadata_hash=hash_record.metadata_hash,
            algorithm=hash_record.algorithm,
            description=hash_record.description,
            created_at=hash_record.created_at,
            updated_at=hash_record.updated_at,
            verified_at=hash_record.verified_at,
            verification_count=hash_record.verification_count,
        )

    async def delete_hash(self, cert_fingerprint: str, file_id: str) -> dict:
        """
        Delete a specific hash.

        Args:
            cert_fingerprint: Client certificate fingerprint
            file_id: File identifier

        Returns:
            Dict with deletion confirmation

        Raises:
            HTTPException: 404 if hash not found
        """
        result = await self.db.execute(
            select(INMetadataHash).where(
                INMetadataHash.cert_fingerprint == cert_fingerprint,
                INMetadataHash.file_id == file_id,
            )
        )
        hash_record = result.scalar_one_or_none()

        if not hash_record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Hash not found for file_id '{file_id}'",
            )

        await self.db.delete(hash_record)
        await self.db.commit()

        logger.info(f"Deleted hash for {cert_fingerprint[:16]}... / {file_id}")

        return {"message": "Hash deleted successfully", "file_id": file_id}

    async def delete_all_hashes(self, cert_fingerprint: str) -> dict:
        """
        Delete all hashes for a client.

        Args:
            cert_fingerprint: Client certificate fingerprint

        Returns:
            Dict with deletion count
        """
        result = await self.db.execute(
            select(INMetadataHash).where(INMetadataHash.cert_fingerprint == cert_fingerprint)
        )
        hashes = result.scalars().all()
        count = len(hashes)

        for h in hashes:
            await self.db.delete(h)

        await self.db.commit()

        logger.info(f"Deleted {count} hashes for {cert_fingerprint[:16]}...")

        return {"message": f"Deleted {count} hash(es)", "deleted_count": count}

    async def verify_hash(
        self, cert_fingerprint: str, request: VerifyRequest, ip_address: Optional[str] = None
    ) -> VerifyResponse:
        """
        Verify a file's integrity by comparing hashes.

        Args:
            cert_fingerprint: Client certificate fingerprint
            request: VerifyRequest with file_id and current hash
            ip_address: Optional client IP for audit logging

        Returns:
            VerifyResponse with verification result
        """
        # Get stored hash
        result = await self.db.execute(
            select(INMetadataHash).where(
                INMetadataHash.cert_fingerprint == cert_fingerprint,
                INMetadataHash.file_id == request.file_id,
            )
        )
        hash_record = result.scalar_one_or_none()

        if not hash_record:
            # Log verification attempt (not found)
            log_entry = INVerificationLog(
                cert_fingerprint=cert_fingerprint,
                file_id=request.file_id,
                result="not_found",
                expected_hash=None,
                actual_hash=request.metadata_hash,
                ip_address=ip_address,
            )
            self.db.add(log_entry)
            await self.db.commit()

            return VerifyResponse(
                file_id=request.file_id,
                match=False,
                stored_hash=None,
                provided_hash=request.metadata_hash,
                last_updated=None,
                warning="Hash not found for this file. Store a hash first with POST /hashes.",
            )

        # Compare hashes
        match = hash_record.metadata_hash == request.metadata_hash

        # Update verification stats
        hash_record.verification_count += 1
        if match:
            hash_record.verified_at = datetime.now(timezone.utc)

        await self.db.commit()

        # Log verification attempt
        log_entry = INVerificationLog(
            cert_fingerprint=cert_fingerprint,
            file_id=request.file_id,
            result="match" if match else "mismatch",
            expected_hash=hash_record.metadata_hash,
            actual_hash=request.metadata_hash,
            ip_address=ip_address,
        )
        self.db.add(log_entry)
        await self.db.commit()

        warning = None
        if not match:
            warning = "INTEGRITY VIOLATION: Metadata has been modified! The stored hash does not match the provided hash."
            logger.warning(
                f"Integrity mismatch for {cert_fingerprint[:16]}... / {request.file_id}"
            )

            # Log critical security event for integrity violation
            security_logger.log_integrity_mismatch(
                client_id=cert_fingerprint,
                file_id=request.file_id,
                expected_hash=hash_record.metadata_hash,
                actual_hash=request.metadata_hash,
                ip_address=ip_address
            )

        return VerifyResponse(
            file_id=request.file_id,
            match=match,
            stored_hash=hash_record.metadata_hash,
            provided_hash=request.metadata_hash,
            last_updated=hash_record.updated_at,
            warning=warning,
        )

    async def get_stats(self, cert_fingerprint: str) -> StatsResponse:
        """
        Get integrity verification statistics for a client.

        Args:
            cert_fingerprint: Client certificate fingerprint

        Returns:
            StatsResponse with statistics
        """
        # Count total hashes
        result = await self.db.execute(
            select(func.count()).select_from(INMetadataHash).where(
                INMetadataHash.cert_fingerprint == cert_fingerprint
            )
        )
        total_hashes = result.scalar_one()

        # Get verification log stats
        result = await self.db.execute(
            select(func.count()).select_from(INVerificationLog).where(
                INVerificationLog.cert_fingerprint == cert_fingerprint
            )
        )
        total_verifications = result.scalar_one()

        result = await self.db.execute(
            select(func.count()).select_from(INVerificationLog).where(
                INVerificationLog.cert_fingerprint == cert_fingerprint,
                INVerificationLog.result == "match",
            )
        )
        successful = result.scalar_one()

        result = await self.db.execute(
            select(func.count()).select_from(INVerificationLog).where(
                INVerificationLog.cert_fingerprint == cert_fingerprint,
                INVerificationLog.result == "mismatch",
            )
        )
        failed = result.scalar_one()

        result = await self.db.execute(
            select(func.count()).select_from(INVerificationLog).where(
                INVerificationLog.cert_fingerprint == cert_fingerprint,
                INVerificationLog.result == "not_found",
            )
        )
        not_found = result.scalar_one()

        # Get last verification timestamp
        result = await self.db.execute(
            select(INVerificationLog.timestamp)
            .where(INVerificationLog.cert_fingerprint == cert_fingerprint)
            .order_by(INVerificationLog.timestamp.desc())
            .limit(1)
        )
        last_verification = result.scalar_one_or_none()

        # Calculate success rate
        success_rate = (
            successful / total_verifications if total_verifications > 0 else 0.0
        )

        return StatsResponse(
            total_hashes=total_hashes,
            total_verifications=total_verifications,
            successful_verifications=successful,
            failed_verifications=failed,
            files_not_found=not_found,
            success_rate=success_rate,
            last_verification=last_verification,
        )
