#!/usr/bin/env python3
"""
Keyserver database models.

Table prefix: ks_ (keyserver)
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSON, UUID

from ...core.database import Base


class KSClient(Base):
    """
    Keyserver client (API token authenticated).

    Each client receives a unique JWT token for accessing keyserver endpoints.
    """

    __tablename__ = "ks_clients"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id = Column(String(64), unique=True, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    client_metadata = Column(JSON, nullable=True)  # Optional client info

    def __repr__(self):
        return f"<KSClient(client_id={self.client_id})>"


class KSKey(Base):
    """
    Public key storage.

    Stores post-quantum public keys with metadata and verification status.
    """

    __tablename__ = "ks_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    fingerprint = Column(String(100), unique=True, nullable=False, index=True)  # SHA-256 with colons: 95 chars
    name = Column(String(255), nullable=True, index=True)
    email = Column(String(255), nullable=True, index=True)
    bundle_json = Column(Text, nullable=False)  # Complete PublicKeyBundle JSON
    encryption_algorithm = Column(String(50), nullable=False)  # e.g., "ML-KEM-768"
    signing_algorithm = Column(String(50), nullable=False)  # e.g., "ML-DSA-65"
    revoked = Column(Boolean, nullable=False, default=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revocation_reason = Column(Text, nullable=True)
    owner_client_id = Column(String(64), nullable=True)  # Optional: track uploader
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    upload_count = Column(Integer, nullable=False, default=1)

    def __repr__(self):
        return f"<KSKey(fingerprint={self.fingerprint[:20]}..., name={self.name})>"


class KSAccessLog(Base):
    """
    Access log for keyserver operations.

    Tracks key uploads, downloads, searches, and revocations.
    """

    __tablename__ = "ks_access_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key_fingerprint = Column(String(100), nullable=False)  # SHA-256 with colons: 95 chars
    action = Column(String(20), nullable=False)  # 'upload', 'download', 'search', 'revoke'
    client_id = Column(String(64), nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv4/IPv6
    timestamp = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    def __repr__(self):
        return f"<KSAccessLog(action={self.action}, fingerprint={self.key_fingerprint[:20]}...)>"
