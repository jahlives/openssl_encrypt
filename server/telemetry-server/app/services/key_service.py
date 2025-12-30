#!/usr/bin/env python3
"""
API Key Service - Handles key generation, validation, and management.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from ..config import settings
from ..models import APIKey


class KeyService:
    """Service for API key management."""

    @staticmethod
    def generate_api_key() -> str:
        """
        Generates a new API key.

        Returns:
            str: Random API key (32 hex characters)
        """
        return f"sk_{secrets.token_hex(32)}"

    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """
        Hashes API key for storage.

        Args:
            api_key: Plain API key

        Returns:
            str: SHA-256 hash of API key
        """
        return hashlib.sha256(api_key.encode()).hexdigest()

    @staticmethod
    def create_api_key(
        db: Session, client_id: str, platform: str, client_version: str
    ) -> tuple[APIKey, str]:
        """
        Creates new API key for client.

        Args:
            db: Database session
            client_id: Client identifier
            platform: Client platform
            client_version: Client version

        Returns:
            tuple: (APIKey model, plain API key)
        """
        # Generate API key
        api_key = KeyService.generate_api_key()
        api_key_hash = KeyService.hash_api_key(api_key)

        # Calculate expiration
        expires_at = datetime.now(timezone.utc) + timedelta(days=settings.api_key_expiry_days)

        # Create model
        db_key = APIKey(
            client_id=client_id,
            api_key_hash=api_key_hash,
            client_version=client_version,
            platform=platform,
            status="active",
            expires_at=expires_at,
        )

        db.add(db_key)
        db.commit()
        db.refresh(db_key)

        return db_key, api_key

    @staticmethod
    def get_key_by_hash(db: Session, api_key_hash: str) -> APIKey | None:
        """
        Gets API key by hash.

        Args:
            db: Database session
            api_key_hash: Hashed API key

        Returns:
            APIKey or None: API key model if found
        """
        return db.query(APIKey).filter(APIKey.api_key_hash == api_key_hash).first()

    @staticmethod
    def validate_api_key(db: Session, api_key: str) -> APIKey | None:
        """
        Validates API key and returns model if valid.

        Args:
            db: Database session
            api_key: Plain API key

        Returns:
            APIKey or None: API key model if valid, None otherwise
        """
        api_key_hash = KeyService.hash_api_key(api_key)
        db_key = KeyService.get_key_by_hash(db, api_key_hash)

        if not db_key:
            return None

        # Check if expired
        if db_key.expires_at < datetime.now(timezone.utc):
            return None

        # Check if revoked
        if db_key.status != "active":
            return None

        # Update last used timestamp
        db_key.last_used_at = datetime.now(timezone.utc)
        db.commit()

        return db_key

    @staticmethod
    def check_rate_limit(db: Session, api_key: APIKey) -> bool:
        """
        Checks if API key has exceeded rate limit.

        Args:
            db: Database session
            api_key: APIKey model

        Returns:
            bool: True if within limit, False if exceeded
        """
        now = datetime.now(timezone.utc)

        # Reset counter if day has passed
        if api_key.requests_reset_at.date() < now.date():
            api_key.requests_today = 0
            api_key.requests_reset_at = now
            db.commit()

        # Check limit
        if api_key.requests_today >= settings.rate_limit_events_per_day:
            return False

        return True

    @staticmethod
    def increment_request_count(db: Session, api_key: APIKey, count: int = 1) -> None:
        """
        Increments request count for rate limiting.

        Args:
            db: Database session
            api_key: APIKey model
            count: Number to increment by
        """
        api_key.requests_today += count
        db.commit()

    @staticmethod
    def refresh_api_key(db: Session, old_key: APIKey) -> tuple[APIKey, str]:
        """
        Generates new API key for existing client.

        Args:
            db: Database session
            old_key: Existing API key model

        Returns:
            tuple: (New APIKey model, plain API key)
        """
        # Generate new API key
        new_api_key = KeyService.generate_api_key()
        new_api_key_hash = KeyService.hash_api_key(new_api_key)

        # Calculate new expiration
        new_expires_at = datetime.now(timezone.utc) + timedelta(days=settings.api_key_expiry_days)

        # Update existing key
        old_key.api_key_hash = new_api_key_hash
        old_key.expires_at = new_expires_at

        db.commit()
        db.refresh(old_key)

        return old_key, new_api_key
