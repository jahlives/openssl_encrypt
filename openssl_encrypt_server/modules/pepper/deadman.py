#!/usr/bin/env python3
"""
Dead Man's Switch Service.

Implements automatic pepper wipe if client doesn't check in within configured interval.

SECURITY:
- Protects against compromise, coercion, or extended unavailability
- Configurable check-in interval and grace period
- Background task monitors deadlines
- Automatic panic wipe when deadline exceeded
- Audit logging of all wipes

Design:
- Client configures interval (e.g., 7 days) and grace period (e.g., 24 hours)
- Client must check in before deadline
- If deadline + grace period passes, peppers are automatically wiped
- Grace period prevents accidental wipes from temporary unavailability
"""

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from .models import PPClient, PPDeadman, PPPanicLog, PPPepper

logger = logging.getLogger(__name__)


def parse_duration(duration_str: str) -> timedelta:
    """
    Parse duration string to timedelta.

    Formats: "7d", "24h", "30m", "3600s"

    Args:
        duration_str: Duration string (e.g., "7d")

    Returns:
        timedelta object

    Raises:
        ValueError: If format invalid
    """
    match = re.match(r"^(\d+)([dhms])$", duration_str.lower())
    if not match:
        raise ValueError(f"Invalid duration format: {duration_str}. Use format like '7d', '24h', '30m', '3600s'")

    value = int(match.group(1))
    unit = match.group(2)

    if unit == "d":
        return timedelta(days=value)
    elif unit == "h":
        return timedelta(hours=value)
    elif unit == "m":
        return timedelta(minutes=value)
    elif unit == "s":
        return timedelta(seconds=value)

    raise ValueError(f"Unknown duration unit: {unit}")


class DeadmanWatcher:
    """
    Background task that monitors deadman switches.

    Checks for expired deadlines and triggers automatic pepper wipes.
    """

    def __init__(self, check_interval: str = "1h"):
        """
        Initialize deadman watcher.

        Args:
            check_interval: How often to check for expired deadlines (e.g., "1h")
        """
        self.check_interval = parse_duration(check_interval)
        self._task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self):
        """Start the deadman watcher background task."""
        if self._running:
            logger.warning("Deadman watcher already running")
            return

        self._running = True
        self._task = asyncio.create_task(self._watch_loop())
        logger.info(f"Deadman watcher started (check interval: {self.check_interval})")

    async def stop(self):
        """Stop the deadman watcher background task."""
        if not self._running:
            return

        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Deadman watcher stopped")

    async def _watch_loop(self):
        """Main watch loop - checks for expired deadlines."""
        while self._running:
            try:
                expired_count = await self._check_expired()
                if expired_count > 0:
                    logger.info(f"Deadman watcher triggered {expired_count} panic wipes")

                # Wait for next check
                await asyncio.sleep(self.check_interval.total_seconds())

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in deadman watcher: {e}", exc_info=True)
                # Continue watching even if error occurs
                await asyncio.sleep(60)  # Brief pause before retry

    async def _check_expired(self) -> int:
        """
        Check for expired deadman switches and trigger wipes.

        Returns:
            Number of expired deadman switches triggered
        """
        expired_count = 0

        async for session in get_db():
            try:
                now = datetime.now(timezone.utc)

                # Find enabled deadman switches past grace period
                result = await session.execute(
                    select(PPDeadman).where(
                        PPDeadman.enabled == True,  # noqa: E712
                        PPDeadman.panic_triggered == False,  # noqa: E712
                        PPDeadman.next_deadline < now
                    )
                )
                expired_deadmans = result.scalars().all()

                for deadman in expired_deadmans:
                    # Check if grace period has also passed
                    grace_end = deadman.next_deadline + timedelta(seconds=deadman.grace_period_seconds)
                    if now >= grace_end:
                        await self._trigger_panic(session, deadman, now)
                        expired_count += 1

                await session.commit()

            except Exception as e:
                logger.error(f"Error checking expired deadman switches: {e}", exc_info=True)
                await session.rollback()

        return expired_count

    async def _trigger_panic(self, session: AsyncSession, deadman: PPDeadman, now: datetime):
        """
        Trigger panic wipe for expired deadman switch.

        Args:
            session: Database session
            deadman: PPDeadman instance
            now: Current timestamp
        """
        logger.warning(f"Deadman switch triggered for client {deadman.client_id}")

        # Get client
        result = await session.execute(
            select(PPClient).where(PPClient.id == deadman.client_id)
        )
        client = result.scalar_one_or_none()
        if not client:
            logger.error(f"Client not found for deadman {deadman.id}")
            return

        # Count peppers
        result = await session.execute(
            select(PPPepper).where(PPPepper.client_id == deadman.client_id)
        )
        peppers = result.scalars().all()
        peppers_wiped = len(peppers)

        # Delete all peppers
        await session.execute(
            PPPepper.__table__.delete().where(PPPepper.client_id == deadman.client_id)
        )

        # Mark deadman as triggered
        deadman.panic_triggered = True
        deadman.panic_triggered_at = now

        # Log panic event
        panic_log = PPPanicLog(
            client_id=deadman.client_id,
            trigger_type="deadman",
            peppers_wiped=peppers_wiped,
            notes=f"Automatic wipe due to missed check-in. Last check-in: {deadman.last_checkin}"
        )
        session.add(panic_log)

        logger.warning(
            f"Deadman panic triggered: client={client.cert_fingerprint[:16]}, "
            f"peppers_wiped={peppers_wiped}, last_checkin={deadman.last_checkin}"
        )


class DeadmanService:
    """
    Service for deadman switch operations.

    Handles configuration, check-ins, and status queries.
    """

    def __init__(self, db: AsyncSession, default_interval: str = "7d", default_grace: str = "24h"):
        """
        Initialize deadman service.

        Args:
            db: Database session
            default_interval: Default check-in interval
            default_grace: Default grace period
        """
        self.db = db
        self.default_interval = parse_duration(default_interval)
        self.default_grace = parse_duration(default_grace)

    async def get_status(self, client_id: UUID) -> dict:
        """
        Get deadman switch status for client.

        Args:
            client_id: Client UUID

        Returns:
            dict with status information
        """
        result = await self.db.execute(
            select(PPDeadman).where(PPDeadman.client_id == client_id)
        )
        deadman = result.scalar_one_or_none()

        if not deadman:
            return {"configured": False}

        now = datetime.now(timezone.utc)
        time_remaining = (deadman.next_deadline - now).total_seconds()

        return {
            "configured": True,
            "enabled": deadman.enabled,
            "interval_seconds": deadman.interval_seconds,
            "grace_period_seconds": deadman.grace_period_seconds,
            "last_checkin": deadman.last_checkin.isoformat(),
            "next_deadline": deadman.next_deadline.isoformat(),
            "time_remaining_seconds": max(0, int(time_remaining)),
            "panic_triggered": deadman.panic_triggered,
            "panic_triggered_at": deadman.panic_triggered_at.isoformat() if deadman.panic_triggered_at else None,
        }

    async def configure(
        self,
        client_id: UUID,
        interval_seconds: Optional[int] = None,
        grace_period_seconds: Optional[int] = None,
        enabled: bool = True
    ) -> dict:
        """
        Configure deadman switch for client.

        Args:
            client_id: Client UUID
            interval_seconds: Check-in interval (minimum 3600 = 1 hour)
            grace_period_seconds: Grace period (minimum 3600 = 1 hour)
            enabled: Enable/disable switch

        Returns:
            dict with new configuration

        Raises:
            ValueError: If intervals too short
        """
        # Validate intervals
        if interval_seconds and interval_seconds < 3600:
            raise ValueError("Interval must be at least 1 hour (3600 seconds)")
        if grace_period_seconds and grace_period_seconds < 3600:
            raise ValueError("Grace period must be at least 1 hour (3600 seconds)")

        # Get or create deadman config
        result = await self.db.execute(
            select(PPDeadman).where(PPDeadman.client_id == client_id)
        )
        deadman = result.scalar_one_or_none()

        now = datetime.now(timezone.utc)

        if not deadman:
            # Create new deadman config
            interval = interval_seconds or int(self.default_interval.total_seconds())
            grace = grace_period_seconds or int(self.default_grace.total_seconds())

            deadman = PPDeadman(
                client_id=client_id,
                enabled=enabled,
                interval_seconds=interval,
                grace_period_seconds=grace,
                last_checkin=now,
                next_deadline=now + timedelta(seconds=interval)
            )
            self.db.add(deadman)
            logger.info(f"Deadman configured for client {client_id}: interval={interval}s, grace={grace}s")
        else:
            # Update existing config
            if interval_seconds:
                deadman.interval_seconds = interval_seconds
            if grace_period_seconds:
                deadman.grace_period_seconds = grace_period_seconds
            deadman.enabled = enabled

            # Recalculate deadline if interval changed
            if interval_seconds:
                time_since_checkin = now - deadman.last_checkin
                if time_since_checkin > timedelta(seconds=interval_seconds):
                    # Already overdue - reset with new interval
                    deadman.last_checkin = now
                    deadman.next_deadline = now + timedelta(seconds=interval_seconds)
                else:
                    # Not overdue - keep existing deadline
                    pass

            logger.info(f"Deadman updated for client {client_id}: enabled={enabled}")

        await self.db.commit()

        return await self.get_status(client_id)

    async def checkin(self, client_id: UUID) -> dict:
        """
        Check in to reset deadman timer.

        Args:
            client_id: Client UUID

        Returns:
            dict with next deadline and time remaining

        Raises:
            ValueError: If deadman not configured
        """
        result = await self.db.execute(
            select(PPDeadman).where(PPDeadman.client_id == client_id)
        )
        deadman = result.scalar_one_or_none()

        if not deadman:
            raise ValueError("Deadman switch not configured. Configure it first.")

        if deadman.panic_triggered:
            raise ValueError("Deadman switch already triggered. Cannot check in.")

        # Update check-in time and calculate new deadline
        now = datetime.now(timezone.utc)
        deadman.last_checkin = now
        deadman.next_deadline = now + timedelta(seconds=deadman.interval_seconds)

        await self.db.commit()

        time_remaining = deadman.interval_seconds

        logger.info(f"Deadman check-in for client {client_id}: next deadline in {time_remaining}s")

        return {
            "message": "Check-in successful",
            "next_deadline": deadman.next_deadline.isoformat(),
            "time_remaining_seconds": time_remaining,
        }

    async def disable(self, client_id: UUID) -> dict:
        """
        Disable deadman switch.

        Args:
            client_id: Client UUID

        Returns:
            dict with message

        Raises:
            ValueError: If deadman not configured
        """
        result = await self.db.execute(
            select(PPDeadman).where(PPDeadman.client_id == client_id)
        )
        deadman = result.scalar_one_or_none()

        if not deadman:
            raise ValueError("Deadman switch not configured")

        # Delete deadman config
        await self.db.delete(deadman)
        await self.db.commit()

        logger.info(f"Deadman disabled for client {client_id}")

        return {"message": "Deadman switch disabled"}
