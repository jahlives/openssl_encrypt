#!/usr/bin/env python3
"""
Database Models

This module defines SQLAlchemy models for storing public key bundles.

SECURITY:
- Only stores public keys (no private keys)
- Stores complete bundle JSON for verification
- Tracks revocation status
- Indexed fields for fast searching
"""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, Text

from ..database import Base


class PublicKey(Base):
    """
    Public key storage model.

    Stores self-signed public key bundles with metadata for searching.

    Security:
    - Stores complete bundle JSON (includes signature)
    - All bundles verified before storage
    - Revocation support
    """

    __tablename__ = "public_keys"

    # Primary key
    id = Column(Integer, primary_key=True, index=True)

    # Identity information (for searching)
    fingerprint = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(255), index=True, nullable=False)
    email = Column(String(255), index=True, nullable=True)

    # Algorithm information (for filtering)
    encryption_algorithm = Column(String(50), nullable=False)
    signing_algorithm = Column(String(50), nullable=False)

    # Complete bundle (JSON)
    bundle_json = Column(Text, nullable=False)

    # Status
    revoked = Column(Boolean, default=False, nullable=False)
    revoked_at = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Metadata
    upload_count = Column(Integer, default=1, nullable=False)  # Track re-uploads

    # Indices for efficient searching
    __table_args__ = (
        Index("ix_fingerprint_prefix", fingerprint),  # For prefix search
        Index("ix_name_email", name, email),  # For name+email search
        Index("ix_revoked_created", revoked, created_at),  # For filtering active keys
    )

    def __repr__(self):
        return f"<PublicKey(fingerprint={self.fingerprint[:20]}..., name={self.name}, revoked={self.revoked})>"
