#!/usr/bin/env python3
"""
Telemetry Service - Handles telemetry event storage and retrieval.
"""

import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..models import APIKey, TelemetryRaw
from ..schemas import TelemetryEventSchema


class TelemetryService:
    """Service for telemetry event management."""

    @staticmethod
    def store_event(db: Session, api_key: APIKey, event: TelemetryEventSchema) -> TelemetryRaw:
        """
        Stores telemetry event in database.

        Args:
            db: Database session
            api_key: API key model (for foreign key)
            event: Telemetry event data

        Returns:
            TelemetryRaw: Created database record
        """
        # Parse event timestamp
        try:
            event_timestamp = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            # Fallback to current time if timestamp invalid
            event_timestamp = datetime.now(timezone.utc)

        # Create database record
        db_event = TelemetryRaw(
            api_key_id=api_key.id,
            event_timestamp=event_timestamp,
            operation=event.operation,
            mode=event.mode,
            format_version=event.format_version,
            hash_algorithms=json.dumps(event.hash_algorithms),
            kdf_algorithms=json.dumps(event.kdf_algorithms),
            kdf_parameters=json.dumps(event.kdf_parameters) if event.kdf_parameters else None,
            encryption_algorithm=event.encryption_algorithm,
            cascade_enabled=event.cascade_enabled,
            cascade_cipher_count=event.cascade_cipher_count,
            pqc_kem_algorithm=event.pqc_kem_algorithm,
            pqc_signing_algorithm=event.pqc_signing_algorithm,
            hsm_plugin_used=event.hsm_plugin_used,
            success=event.success,
            error_category=event.error_category,
            aggregated=False,
        )

        db.add(db_event)
        return db_event

    @staticmethod
    def store_batch(
        db: Session, api_key: APIKey, events: list[TelemetryEventSchema]
    ) -> tuple[int, int]:
        """
        Stores batch of telemetry events.

        Args:
            db: Database session
            api_key: API key model
            events: List of telemetry events

        Returns:
            tuple: (received count, processed count)
        """
        received = len(events)
        processed = 0

        for event in events:
            try:
                TelemetryService.store_event(db, api_key, event)
                processed += 1
            except Exception:
                # Skip invalid events but continue processing
                continue

        # Commit all events at once
        try:
            db.commit()
        except Exception:
            db.rollback()
            return received, 0

        return received, processed

    @staticmethod
    def get_total_operations(db: Session) -> int:
        """
        Gets total number of operations.

        Args:
            db: Database session

        Returns:
            int: Total operations count
        """
        return db.query(TelemetryRaw).count()

    @staticmethod
    def get_success_rate(db: Session) -> float:
        """
        Calculates success rate.

        Args:
            db: Database session

        Returns:
            float: Success rate (0.0 - 1.0)
        """
        total = db.query(TelemetryRaw).count()
        if total == 0:
            return 1.0

        successful = db.query(TelemetryRaw).filter(TelemetryRaw.success == True).count()
        return successful / total
