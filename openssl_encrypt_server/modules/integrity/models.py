#!/usr/bin/env python3
"""
Integrity database models.

Table prefix: in_ (integrity)
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import INET, JSON, UUID

from ...core.database import Base


class INClient(Base):
    """
    Integrity client (mTLS certificate authenticated).

    Each client is identified by their certificate fingerprint (SHA-256).
    No API tokens - authentication via client certificates only.
    """

    __tablename__ = "in_clients"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cert_fingerprint = Column(String(64), unique=True, nullable=False, index=True)
    cert_dn = Column(String(500), nullable=True)  # Certificate Distinguished Name
    name = Column(String(255), nullable=True)  # Optional display name
    created_at = Column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    client_metadata = Column(JSON, nullable=True)  # Optional client info

    def __repr__(self):
        return f"<INClient(cert_fingerprint={self.cert_fingerprint[:16]}...)>"


class INMetadataHash(Base):
    """
    Metadata hash storage for integrity verification.

    Stores SHA-256 hashes of encrypted file metadata to detect tampering.
    Each file is identified by a client-generated file_id (e.g., filename hash).
    """

    __tablename__ = "in_metadata_hashes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cert_fingerprint = Column(
        String(64),
        ForeignKey("in_clients.cert_fingerprint", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    file_id = Column(String(128), nullable=False, index=True)
    metadata_hash = Column(String(64), nullable=False)  # SHA-256 of encrypted file metadata
    algorithm = Column(String(50), nullable=True)  # Algorithm used (e.g., "symmetric-aes256")
    description = Column(Text, nullable=True)  # Optional description
    created_at = Column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at = Column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    verified_at = Column(DateTime(timezone=True), nullable=True)  # Last successful verification
    verification_count = Column(BigInteger, nullable=False, default=0)

    def __repr__(self):
        return f"<INMetadataHash(file_id={self.file_id}, cert_fingerprint={self.cert_fingerprint[:8]}...)>"


class INVerificationLog(Base):
    """
    Integrity verification audit log.

    Logs all verification attempts for auditing and security monitoring.
    Helps detect repeated integrity violations which may indicate attacks.
    """

    __tablename__ = "in_verification_log"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    cert_fingerprint = Column(String(64), nullable=False, index=True)
    file_id = Column(String(128), nullable=False)
    result = Column(String(20), nullable=False)  # 'match', 'mismatch', 'not_found'
    expected_hash = Column(String(64), nullable=True)
    actual_hash = Column(String(64), nullable=True)
    ip_address = Column(INET, nullable=True)
    timestamp = Column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True
    )

    def __repr__(self):
        return f"<INVerificationLog(file_id={self.file_id}, result={self.result})>"
