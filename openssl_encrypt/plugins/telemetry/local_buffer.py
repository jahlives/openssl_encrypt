#!/usr/bin/env python3
"""
Local Buffer - SQLite-based persistent storage for telemetry events.

PRIVACY CRITICAL:
- Only stores filtered TelemetryEvent data (already sanitized)
- User can inspect all pending events (transparency)
- FIFO queue with automatic cleanup when full
- Supports opt-out with complete data deletion

This buffer provides:
1. Persistence across restarts
2. Batch retrieval for efficient uploads
3. User transparency (export for inspection)
4. Retry support (mark as pending/uploaded)
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ...modules.telemetry_filter import TelemetryDataFilter, TelemetryEvent


class LocalBuffer:
    """
    SQLite-based local buffer for telemetry events.

    SECURITY:
    - Only stores filtered TelemetryEvent data (no sensitive information)
    - User-inspectable for transparency
    - Automatic cleanup when buffer reaches max size (FIFO)
    - Support for opt-out (complete deletion)
    """

    def __init__(self, buffer_path: Path, max_buffer_size: int = 10000):
        """
        Initialize LocalBuffer.

        Args:
            buffer_path: Path to SQLite database file
            max_buffer_size: Maximum number of events to store (FIFO cleanup)
        """
        self.buffer_path = buffer_path
        self.max_buffer_size = max_buffer_size

        # Ensure parent directory exists
        self.buffer_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._init_database()

    def _init_database(self) -> None:
        """
        Initializes SQLite database with schema.
        """
        with sqlite3.connect(self.buffer_path) as conn:
            cursor = conn.cursor()

            # Create events table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    format_version INTEGER NOT NULL,
                    hash_algorithms TEXT NOT NULL,
                    kdf_algorithms TEXT NOT NULL,
                    kdf_parameters TEXT,
                    encryption_algorithm TEXT NOT NULL,
                    cascade_enabled INTEGER NOT NULL DEFAULT 0,
                    cascade_cipher_count INTEGER,
                    pqc_kem_algorithm TEXT,
                    pqc_signing_algorithm TEXT,
                    hsm_plugin_used TEXT,
                    success INTEGER NOT NULL DEFAULT 1,
                    error_category TEXT,
                    created_at TEXT NOT NULL,
                    uploaded INTEGER NOT NULL DEFAULT 0,
                    retry_count INTEGER NOT NULL DEFAULT 0
                )
            """
            )

            # Create index for efficient queries
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_uploaded
                ON events(uploaded, created_at)
            """
            )

            conn.commit()

    def add(self, event: TelemetryEvent) -> None:
        """
        Adds telemetry event to buffer.

        Args:
            event: TelemetryEvent (already filtered, safe data only)
        """
        # Check buffer size and cleanup if needed
        self._cleanup_if_full()

        # Convert event to dictionary for storage
        event_dict = TelemetryDataFilter.to_dict(event)

        with sqlite3.connect(self.buffer_path) as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO events (
                    timestamp, operation, mode, format_version,
                    hash_algorithms, kdf_algorithms, kdf_parameters,
                    encryption_algorithm, cascade_enabled, cascade_cipher_count,
                    pqc_kem_algorithm, pqc_signing_algorithm, hsm_plugin_used,
                    success, error_category, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    event.timestamp,
                    event.operation,
                    event.mode,
                    event.format_version,
                    json.dumps(list(event.hash_algorithms)),
                    json.dumps(list(event.kdf_algorithms)),
                    json.dumps(event.kdf_parameters),
                    event.encryption_algorithm,
                    1 if event.cascade_enabled else 0,
                    event.cascade_cipher_count,
                    event.pqc_kem_algorithm,
                    event.pqc_signing_algorithm,
                    event.hsm_plugin_used,
                    1 if event.success else 0,
                    event.error_category,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

            conn.commit()

    def _cleanup_if_full(self) -> None:
        """
        Removes oldest events if buffer is at max capacity (FIFO).
        """
        with sqlite3.connect(self.buffer_path) as conn:
            cursor = conn.cursor()

            # Get current count
            cursor.execute("SELECT COUNT(*) FROM events WHERE uploaded = 0")
            count = cursor.fetchone()[0]

            # If at or over capacity, delete oldest events
            if count >= self.max_buffer_size:
                # Delete oldest 10% to reduce frequency of cleanup
                delete_count = max(1, self.max_buffer_size // 10)

                cursor.execute(
                    """
                    DELETE FROM events
                    WHERE id IN (
                        SELECT id FROM events
                        WHERE uploaded = 0
                        ORDER BY created_at ASC
                        LIMIT ?
                    )
                """,
                    (delete_count,),
                )

                conn.commit()

    def get_batch(self, batch_size: int = 100) -> List[Tuple[int, Dict]]:
        """
        Gets batch of pending events for upload.

        Args:
            batch_size: Maximum number of events to retrieve

        Returns:
            List of (id, event_dict) tuples
        """
        with sqlite3.connect(self.buffer_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM events
                WHERE uploaded = 0
                ORDER BY created_at ASC
                LIMIT ?
            """,
                (batch_size,),
            )

            rows = cursor.fetchall()

            # Convert rows to (id, event_dict) tuples
            result = []
            for row in rows:
                event_dict = {
                    "timestamp": row["timestamp"],
                    "operation": row["operation"],
                    "mode": row["mode"],
                    "format_version": row["format_version"],
                    "hash_algorithms": json.loads(row["hash_algorithms"]),
                    "kdf_algorithms": json.loads(row["kdf_algorithms"]),
                    "kdf_parameters": json.loads(row["kdf_parameters"])
                    if row["kdf_parameters"]
                    else {},
                    "encryption_algorithm": row["encryption_algorithm"],
                    "cascade_enabled": bool(row["cascade_enabled"]),
                    "cascade_cipher_count": row["cascade_cipher_count"],
                    "pqc_kem_algorithm": row["pqc_kem_algorithm"],
                    "pqc_signing_algorithm": row["pqc_signing_algorithm"],
                    "hsm_plugin_used": row["hsm_plugin_used"],
                    "success": bool(row["success"]),
                    "error_category": row["error_category"],
                }

                result.append((row["id"], event_dict))

            return result

    def mark_uploaded(self, event_ids: List[int]) -> None:
        """
        Marks events as successfully uploaded.

        Args:
            event_ids: List of event IDs to mark as uploaded
        """
        if not event_ids:
            return

        with sqlite3.connect(self.buffer_path) as conn:
            cursor = conn.cursor()

            # Use parameterized query with placeholders
            placeholders = ",".join("?" * len(event_ids))
            cursor.execute(
                f"""
                UPDATE events
                SET uploaded = 1
                WHERE id IN ({placeholders})
            """,
                event_ids,
            )

            conn.commit()

    def increment_retry(self, event_ids: List[int]) -> None:
        """
        Increments retry count for failed uploads.

        Args:
            event_ids: List of event IDs to increment retry count
        """
        if not event_ids:
            return

        with sqlite3.connect(self.buffer_path) as conn:
            cursor = conn.cursor()

            placeholders = ",".join("?" * len(event_ids))
            cursor.execute(
                f"""
                UPDATE events
                SET retry_count = retry_count + 1
                WHERE id IN ({placeholders})
            """,
                event_ids,
            )

            conn.commit()

    def get_pending_count(self) -> int:
        """
        Returns count of pending (not uploaded) events.

        Returns:
            int: Number of pending events
        """
        with sqlite3.connect(self.buffer_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM events WHERE uploaded = 0")
            count = cursor.fetchone()[0]

            return count

    def export_pending(self, limit: int = 100) -> List[Dict]:
        """
        Exports pending events for user inspection (transparency).

        Args:
            limit: Maximum number of events to export

        Returns:
            List of event dictionaries
        """
        with sqlite3.connect(self.buffer_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM events
                WHERE uploaded = 0
                ORDER BY created_at DESC
                LIMIT ?
            """,
                (limit,),
            )

            rows = cursor.fetchall()

            # Convert to dictionaries
            result = []
            for row in rows:
                event_dict = {
                    "id": row["id"],
                    "timestamp": row["timestamp"],
                    "operation": row["operation"],
                    "mode": row["mode"],
                    "format_version": row["format_version"],
                    "hash_algorithms": json.loads(row["hash_algorithms"]),
                    "kdf_algorithms": json.loads(row["kdf_algorithms"]),
                    "kdf_parameters": json.loads(row["kdf_parameters"])
                    if row["kdf_parameters"]
                    else {},
                    "encryption_algorithm": row["encryption_algorithm"],
                    "cascade_enabled": bool(row["cascade_enabled"]),
                    "cascade_cipher_count": row["cascade_cipher_count"],
                    "pqc_kem_algorithm": row["pqc_kem_algorithm"],
                    "pqc_signing_algorithm": row["pqc_signing_algorithm"],
                    "hsm_plugin_used": row["hsm_plugin_used"],
                    "success": bool(row["success"]),
                    "error_category": row["error_category"],
                    "created_at": row["created_at"],
                    "retry_count": row["retry_count"],
                }

                result.append(event_dict)

            return result

    def clear_all(self) -> int:
        """
        Deletes all events (for opt-out).

        Returns:
            int: Number of events deleted
        """
        with sqlite3.connect(self.buffer_path) as conn:
            cursor = conn.cursor()

            # Get count before deletion
            cursor.execute("SELECT COUNT(*) FROM events")
            count = cursor.fetchone()[0]

            # Delete all events
            cursor.execute("DELETE FROM events")

            conn.commit()

            return count

    def delete_uploaded(self, older_than_days: int = 7) -> int:
        """
        Deletes uploaded events older than specified days (cleanup).

        Args:
            older_than_days: Delete uploaded events older than this many days

        Returns:
            int: Number of events deleted
        """
        from datetime import timedelta

        cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
        cutoff_str = cutoff.isoformat()

        with sqlite3.connect(self.buffer_path) as conn:
            cursor = conn.cursor()

            # Delete old uploaded events
            cursor.execute(
                """
                DELETE FROM events
                WHERE uploaded = 1 AND created_at < ?
            """,
                (cutoff_str,),
            )

            deleted = cursor.rowcount
            conn.commit()

            return deleted
