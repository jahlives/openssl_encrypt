#!/usr/bin/env python3
"""
Telemetry database models.

Table prefix: tm_ (telemetry)
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSON, UUID

from ...core.database import Base


class TMClient(Base):
    """
    Telemetry client (API token authenticated).

    Each client receives a unique JWT token for submitting telemetry events.
    """

    __tablename__ = "tm_clients"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id = Column(String(64), unique=True, nullable=False, index=True)
    created_at = Column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    client_metadata = Column(JSON, nullable=True)  # Optional client info (version, platform, etc.)

    def __repr__(self):
        return f"<TMClient(client_id={self.client_id})>"


class TMEvent(Base):
    """
    Telemetry event storage.

    Stores individual telemetry events with algorithm usage and success/failure metrics.
    """

    __tablename__ = "tm_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(50), nullable=False, index=True)  # 'encrypt', 'decrypt', 'keygen', etc.
    client_id = Column(String(64), nullable=False, index=True)
    version = Column(String(20), nullable=True)  # openssl_encrypt version
    algorithm = Column(String(100), nullable=True)  # Algorithm used
    success = Column(Boolean, nullable=False)
    error_type = Column(String(100), nullable=True)
    duration_ms = Column(Integer, nullable=True)
    event_metadata = Column(JSON, nullable=True)
    timestamp = Column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True
    )

    # Extended fields for compatibility with existing telemetry server
    operation = Column(String(16), nullable=True)  # "encrypt" or "decrypt"
    mode = Column(String(16), nullable=True)  # "symmetric" or "asymmetric"
    format_version = Column(Integer, nullable=True)
    hash_algorithms = Column(JSON, nullable=True)
    kdf_algorithms = Column(JSON, nullable=True)
    encryption_algorithm = Column(String(64), nullable=True)
    pqc_kem_algorithm = Column(String(32), nullable=True)
    pqc_signing_algorithm = Column(String(32), nullable=True)

    def __repr__(self):
        return f"<TMEvent(event_type={self.event_type}, client_id={self.client_id[:8]}..., success={self.success})>"


class TMDailyStats(Base):
    """
    Aggregated daily statistics.

    Pre-computed statistics for efficient querying.
    """

    __tablename__ = "tm_daily_stats"

    date = Column(DateTime(timezone=True), primary_key=True)
    total_events = Column(Integer, nullable=False, default=0)
    unique_clients = Column(Integer, nullable=False, default=0)
    events_by_type = Column(JSON, nullable=False, default={})
    events_by_algorithm = Column(JSON, nullable=False, default={})
    avg_duration_ms = Column(JSON, nullable=False, default={})

    def __repr__(self):
        return f"<TMDailyStats(date={self.date}, total_events={self.total_events})>"
