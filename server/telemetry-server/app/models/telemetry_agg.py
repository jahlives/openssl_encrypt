#!/usr/bin/env python3
"""
Telemetry Aggregated Data Model - Stores aggregated statistics.

RETENTION: Permanent (for public statistics).
"""

from datetime import datetime, timezone

from sqlalchemy import Column, Date, Integer, String

from ..database import Base


class TelemetryAggregated(Base):
    """
    Aggregated telemetry statistics.

    PRIVACY:
    - Daily aggregated counts only
    - NO client identification
    - Public statistics (safe for public API)
    """

    __tablename__ = "telemetry_aggregated"

    id = Column(Integer, primary_key=True, index=True)

    # Date (daily aggregation)
    date = Column(Date, nullable=False, index=True)

    # Grouping dimensions
    mode = Column(String(16), index=True)  # "symmetric" or "asymmetric"
    format_version = Column(Integer, index=True)
    encryption_algorithm = Column(String(64), index=True)

    # Hash combination (JSON string for unique identification)
    hash_combination = Column(String(256))

    # KDF combination (JSON string for unique identification)
    kdf_combination = Column(String(256))

    # Counts
    total_operations = Column(Integer, default=0)
    successful_operations = Column(Integer, default=0)
    failed_operations = Column(Integer, default=0)

    # Unique clients (anonymized count only)
    unique_clients = Column(Integer, default=0)

    def __repr__(self):
        return f"<TelemetryAggregated(date={self.date}, algorithm={self.encryption_algorithm}, count={self.total_operations})>"
