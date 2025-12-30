#!/usr/bin/env python3
"""
Telemetry Raw Data Model - Stores individual telemetry events.

RETENTION: 90 days, then aggregated and deleted.
"""

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String

from ..database import Base


class TelemetryRaw(Base):
    """
    Raw telemetry event storage.

    PRIVACY:
    - Only stores pre-filtered data (already sanitized by client)
    - NO passwords, keys, salts, filenames
    - Deleted after 90 days (aggregated first)
    """

    __tablename__ = "telemetry_raw"

    id = Column(Integer, primary_key=True, index=True)

    # Foreign key to API key (for rate limiting and statistics)
    api_key_id = Column(Integer, ForeignKey("api_keys.id"), index=True, nullable=False)

    # Event metadata
    event_timestamp = Column(DateTime(timezone=True), nullable=False)
    received_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Operation details
    operation = Column(String(16), nullable=False)  # "encrypt" or "decrypt"
    mode = Column(String(16), nullable=False)  # "symmetric" or "asymmetric"
    format_version = Column(Integer, nullable=False)

    # Algorithms (stored as JSON arrays)
    hash_algorithms = Column(JSON, nullable=False)
    kdf_algorithms = Column(JSON, nullable=False)
    kdf_parameters = Column(JSON)  # Optional KDF parameters

    # Encryption
    encryption_algorithm = Column(String(64), nullable=False)

    # Cascade encryption (format v8)
    cascade_enabled = Column(Boolean, default=False)
    cascade_cipher_count = Column(Integer)

    # Post-Quantum Cryptography
    pqc_kem_algorithm = Column(String(32))
    pqc_signing_algorithm = Column(String(32))

    # HSM
    hsm_plugin_used = Column(String(32))

    # Success/Failure
    success = Column(Boolean, default=True)
    error_category = Column(String(32))

    # Aggregation status
    aggregated = Column(Boolean, default=False, index=True)

    def __repr__(self):
        return f"<TelemetryRaw(id={self.id}, operation={self.operation}, algorithm={self.encryption_algorithm})>"
