#!/usr/bin/env python3
"""
API Key Model - Manages client authentication.

PRIVACY: Client ID is random (NOT hardware-based).
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String

from ..database import Base


class APIKey(Base):
    """
    API Key model for client authentication.

    PRIVACY:
    - client_id: Random identifier (NOT hardware-based)
    - platform: Generic only (linux/macos/windows/other)
    - NO IP addresses logged
    - NO hardware identifiers stored
    """

    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)

    # Client identification (random, anonymous)
    client_id = Column(String(64), unique=True, index=True, nullable=False)
    api_key_hash = Column(String(64), unique=True, index=True, nullable=False)

    # Client metadata (generic only)
    client_version = Column(String(32))
    platform = Column(String(16))  # "linux", "macos", "windows", "other"

    # Status
    status = Column(String(16), default="active")  # "active", "revoked"

    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    last_used_at = Column(DateTime(timezone=True))

    # Rate limiting
    requests_today = Column(Integer, default=0)
    requests_reset_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<APIKey(client_id={self.client_id}, status={self.status})>"
