#!/usr/bin/env python3
"""
Telemetry business logic.

Handles event storage and statistics aggregation.
"""

import logging
from datetime import datetime, timezone
from typing import Dict

from dateutil import parser as dateparser
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import TMEvent
from .schemas import TelemetryEventSchema

logger = logging.getLogger(__name__)


class TelemetryService:
    """Service for telemetry operations"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def record_events(self, client_id: str, events: list[TelemetryEventSchema]) -> dict:
        """
        Record telemetry events.

        Args:
            client_id: Client identifier
            events: List of telemetry events

        Returns:
            dict: Response with received and processed counts
        """
        logger.info(f"Recording {len(events)} events from client {client_id[:8]}...")

        processed = 0
        for event in events:
            try:
                await self._store_event(client_id, event)
                processed += 1
            except Exception as e:
                logger.error(f"Failed to store event: {e}")
                # Continue processing other events

        await self.db.commit()

        logger.info(f"Processed {processed}/{len(events)} events from {client_id[:8]}...")

        return {"received": len(events), "processed": processed}

    async def _store_event(self, client_id: str, event: TelemetryEventSchema):
        """Store single telemetry event"""
        # Parse timestamp
        try:
            event_timestamp = dateparser.isoparse(event.timestamp)
        except Exception:
            event_timestamp = datetime.now(timezone.utc)

        # Create event record
        db_event = TMEvent(
            event_type=event.operation,  # Map operation to event_type
            client_id=client_id,
            algorithm=event.encryption_algorithm,
            success=event.success,
            error_type=event.error_category,
            timestamp=event_timestamp,
            # Extended fields
            operation=event.operation,
            mode=event.mode,
            format_version=event.format_version,
            hash_algorithms=event.hash_algorithms,
            kdf_algorithms=event.kdf_algorithms,
            encryption_algorithm=event.encryption_algorithm,
            pqc_kem_algorithm=event.pqc_kem_algorithm,
            pqc_signing_algorithm=event.pqc_signing_algorithm,
            metadata={
                "cascade_enabled": event.cascade_enabled,
                "cascade_cipher_count": event.cascade_cipher_count,
                "hsm_plugin_used": event.hsm_plugin_used,
                "kdf_parameters": event.kdf_parameters,
            },
        )

        self.db.add(db_event)

    async def get_public_stats(self) -> Dict:
        """
        Get aggregated public statistics.

        Returns:
            dict: Public statistics
        """
        logger.debug("Fetching public statistics...")

        # Total operations
        stmt = select(func.count(TMEvent.id))
        result = await self.db.execute(stmt)
        total_operations = result.scalar() or 0

        # Unique clients
        stmt = select(func.count(func.distinct(TMEvent.client_id)))
        result = await self.db.execute(stmt)
        total_clients = result.scalar() or 0

        # Algorithms
        stmt = select(TMEvent.encryption_algorithm, func.count(TMEvent.id)).group_by(
            TMEvent.encryption_algorithm
        )
        result = await self.db.execute(stmt)
        algorithms = {algo: count for algo, count in result.all() if algo}

        # Operations
        stmt = select(TMEvent.operation, func.count(TMEvent.id)).group_by(TMEvent.operation)
        result = await self.db.execute(stmt)
        operations = {op: count for op, count in result.all() if op}

        # Success rate
        stmt = select(func.count(TMEvent.id)).where(TMEvent.success == True)
        result = await self.db.execute(stmt)
        successful = result.scalar() or 0

        success_rate = (successful / total_operations * 100) if total_operations > 0 else 0.0

        return {
            "total_operations": total_operations,
            "total_clients": total_clients,
            "algorithms": algorithms,
            "operations": operations,
            "success_rate": round(success_rate, 2),
        }
