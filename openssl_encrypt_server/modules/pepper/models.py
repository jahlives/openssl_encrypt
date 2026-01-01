#!/usr/bin/env python3
"""
Pepper database models.

Table prefix: pp_ (pepper)

Security Model:
- Clients identified by mTLS certificate fingerprint (SHA-256)
- Peppers are encrypted client-side before storage
- TOTP secrets encrypted at rest with Fernet
- Backup codes hashed with Argon2
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID

from ...core.database import Base


class PPClient(Base):
    """
    Pepper client (mTLS authenticated via certificate fingerprint).

    Each client is identified by their certificate's SHA-256 fingerprint.
    No personal information is stored - only the cert fingerprint and optional name.
    """

    __tablename__ = "pp_clients"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cert_fingerprint = Column(String(64), unique=True, nullable=False, index=True)
    cert_dn = Column(String(500), nullable=True)  # Certificate Distinguished Name
    name = Column(String(255), nullable=True)  # Optional friendly name

    # TOTP 2FA (encrypted at rest with Fernet)
    totp_secret_encrypted = Column(LargeBinary, nullable=True)
    totp_verified = Column(Boolean, nullable=False, default=False)

    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self):
        return f"<PPClient(fingerprint={self.cert_fingerprint[:16]}...)>"


class PPPepper(Base):
    """
    Pepper storage (client-encrypted blobs).

    Peppers are encrypted client-side before upload. The server only stores
    the encrypted blob without any knowledge of the plaintext pepper value.

    SECURITY: Server never sees plaintext peppers!
    """

    __tablename__ = "pp_peppers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id = Column(UUID(as_uuid=True), ForeignKey("pp_clients.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)  # Pepper identifier (unique per client)
    pepper_encrypted = Column(LargeBinary, nullable=False)  # Client-encrypted pepper blob
    description = Column(Text, nullable=True)  # Optional description

    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_accessed_at = Column(DateTime(timezone=True), nullable=True)
    access_count = Column(BigInteger, nullable=False, default=0)

    # Unique constraint: one pepper name per client
    __table_args__ = (
        UniqueConstraint("client_id", "name", name="uq_client_pepper_name"),
        Index("ix_pp_peppers_client_id_name", "client_id", "name"),
    )

    def __repr__(self):
        return f"<PPPepper(name={self.name})>"


class PPDeadman(Base):
    """
    Dead man's switch configuration.

    If a client doesn't check in within the configured interval + grace period,
    the server automatically wipes all their peppers.

    SECURITY: Protects against compromise or coercion scenarios.
    """

    __tablename__ = "pp_deadman"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id = Column(UUID(as_uuid=True), ForeignKey("pp_clients.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)

    enabled = Column(Boolean, nullable=False, default=True)
    interval_seconds = Column(BigInteger, nullable=False)  # Check-in interval
    grace_period_seconds = Column(BigInteger, nullable=False)  # Grace period after deadline

    last_checkin = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    next_deadline = Column(DateTime(timezone=True), nullable=False)

    # Panic state
    panic_triggered = Column(Boolean, nullable=False, default=False)
    panic_triggered_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self):
        return f"<PPDeadman(client_id={self.client_id}, enabled={self.enabled})>"


class PPPanicLog(Base):
    """
    Panic audit log.

    Records all pepper wipe events for security auditing.

    Trigger types:
    - manual: User-initiated panic
    - deadman: Deadman switch triggered automatically
    - emergency: Administrative emergency wipe
    """

    __tablename__ = "pp_panic_log"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    client_id = Column(UUID(as_uuid=True), ForeignKey("pp_clients.id", ondelete="CASCADE"), nullable=False, index=True)

    trigger_type = Column(String(20), nullable=False)  # 'manual', 'deadman', 'emergency'
    peppers_wiped = Column(Integer, nullable=False, default=0)
    specific_pepper = Column(String(255), nullable=True)  # If single pepper wipe

    timestamp = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    notes = Column(Text, nullable=True)

    def __repr__(self):
        return f"<PPPanicLog(trigger={self.trigger_type}, peppers={self.peppers_wiped})>"


class PPTOTPBackupCode(Base):
    """
    TOTP backup codes (hashed with Argon2).

    Backup codes allow account recovery if TOTP device is lost.

    SECURITY:
    - Codes are hashed with Argon2 (not reversible)
    - Single-use only (marked as used after first use)
    - Typically 10 codes generated during TOTP setup
    """

    __tablename__ = "pp_totp_backup_codes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id = Column(UUID(as_uuid=True), ForeignKey("pp_clients.id", ondelete="CASCADE"), nullable=False, index=True)

    code_hash = Column(String(128), nullable=False)  # Argon2 hash
    used_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_pp_totp_backup_codes_client_unused", "client_id", "used_at"),
    )

    def __repr__(self):
        return f"<PPTOTPBackupCode(client_id={self.client_id}, used={self.used_at is not None})>"
