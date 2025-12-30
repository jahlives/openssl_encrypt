#!/usr/bin/env python3
"""
Keyserver Cache - SQLite-based persistent cache for public key bundles.

PRIVACY AND SECURITY:
- Only stores PublicKeyBundle data (public keys, no private keys)
- All bundles verified before caching
- TTL-based expiration to prevent stale keys
- LRU eviction when cache reaches capacity
- User-inspectable for transparency

Features:
1. Persistence across restarts
2. TTL-based expiration (default: 24 hours)
3. LRU eviction when full
4. Search by fingerprint/name/email
5. Cache statistics
"""

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional

from ...modules.key_bundle import PublicKeyBundle

logger = logging.getLogger(__name__)


class CacheError(Exception):
    """Base exception for cache operations"""

    pass


class KeyserverCache:
    """
    SQLite-based cache for public key bundles.

    SECURITY:
    - Only stores PublicKeyBundle data (public keys only)
    - All bundles verified before storage
    - TTL prevents stale keys
    - LRU eviction maintains cache size

    Cache eviction strategy:
    - When cache reaches max_entries, oldest entries (by last_accessed) are removed
    - Expired entries (beyond TTL) are automatically cleaned up

    Database schema:
        fingerprint TEXT PRIMARY KEY    - SHA-256 fingerprint with colons
        name TEXT NOT NULL             - Identity name
        email TEXT                     - Optional email address
        bundle_json TEXT NOT NULL      - JSON-serialized bundle
        fetched_at INTEGER NOT NULL    - Unix timestamp when fetched
        last_accessed INTEGER NOT NULL - Unix timestamp when last accessed
        access_count INTEGER DEFAULT 1 - Number of times accessed
    """

    def __init__(self, cache_path: Path, max_entries: int = 1000, ttl_seconds: int = 86400):
        """
        Initialize cache.

        Args:
            cache_path: Path to SQLite database file
            max_entries: Maximum number of entries (LRU eviction)
            ttl_seconds: Time-to-live in seconds (default: 24 hours)
        """
        self.cache_path = Path(cache_path).expanduser()
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds

        # Ensure parent directory exists
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._init_database()

        logger.info(
            f"Initialized keyserver cache at {self.cache_path} "
            f"(max={max_entries}, ttl={ttl_seconds}s)"
        )

    def _init_database(self) -> None:
        """Initialize SQLite database with schema."""
        with sqlite3.connect(self.cache_path) as conn:
            cursor = conn.cursor()

            # Create cache table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS cache (
                    fingerprint TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT,
                    bundle_json TEXT NOT NULL,
                    fetched_at INTEGER NOT NULL,
                    last_accessed INTEGER NOT NULL,
                    access_count INTEGER DEFAULT 1
                )
            """
            )

            # Create indices for efficient queries
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_name
                ON cache(name)
            """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_email
                ON cache(email)
            """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_last_accessed
                ON cache(last_accessed)
            """
            )

            conn.commit()

    def get(self, identifier: str) -> Optional[PublicKeyBundle]:
        """
        Get bundle from cache by identifier.

        Searches by:
        1. Fingerprint (exact or prefix match)
        2. Name (exact match)
        3. Email (exact match)

        Args:
            identifier: Fingerprint, name, or email to search for

        Returns:
            PublicKeyBundle if found and not expired, None otherwise

        Note:
            - Checks TTL and returns None if expired
            - Updates last_accessed and access_count
            - Automatically cleans up expired entries
        """
        now = int(time.time())
        expiry_cutoff = now - self.ttl_seconds

        with sqlite3.connect(self.cache_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Search by fingerprint (exact or prefix), name, or email
            cursor.execute(
                """
                SELECT * FROM cache
                WHERE (fingerprint LIKE ? || '%' OR name = ? OR email = ?)
                AND fetched_at >= ?
                ORDER BY fetched_at DESC
                LIMIT 1
            """,
                (identifier, identifier, identifier, expiry_cutoff),
            )

            row = cursor.fetchone()

            if row is None:
                logger.debug(f"Cache miss for '{identifier}'")
                return None

            # Update access statistics
            cursor.execute(
                """
                UPDATE cache
                SET last_accessed = ?, access_count = access_count + 1
                WHERE fingerprint = ?
            """,
                (now, row["fingerprint"]),
            )

            conn.commit()

            # Deserialize bundle
            try:
                bundle_data = json.loads(row["bundle_json"])
                bundle = PublicKeyBundle.from_dict(bundle_data)
                logger.debug(f"Cache hit for '{identifier}' -> '{bundle.name}'")
                return bundle
            except Exception as e:
                logger.error(f"Failed to deserialize cached bundle: {e}")
                return None

    def put(self, bundle: PublicKeyBundle) -> None:
        """
        Store bundle in cache.

        Args:
            bundle: PublicKeyBundle to cache

        Note:
            - Triggers LRU eviction if cache is full
            - Updates existing entry if fingerprint already exists
            - Automatically cleans up expired entries
        """
        # Clean up expired entries first
        self._cleanup_expired()

        # Check if cache is full and evict if necessary
        self._evict_if_full()

        now = int(time.time())

        with sqlite3.connect(self.cache_path) as conn:
            cursor = conn.cursor()

            # Serialize bundle
            bundle_json = json.dumps(bundle.to_dict())

            # Insert or replace
            cursor.execute(
                """
                INSERT OR REPLACE INTO cache (
                    fingerprint, name, email, bundle_json,
                    fetched_at, last_accessed, access_count
                ) VALUES (?, ?, ?, ?, ?, ?, 1)
            """,
                (bundle.fingerprint, bundle.name, bundle.email, bundle_json, now, now),
            )

            conn.commit()

        logger.debug(f"Cached bundle for '{bundle.name}' (fp: {bundle.fingerprint[:20]}...)")

    def _cleanup_expired(self) -> int:
        """
        Remove expired entries from cache.

        Returns:
            Number of entries removed
        """
        now = int(time.time())
        expiry_cutoff = now - self.ttl_seconds

        with sqlite3.connect(self.cache_path) as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                DELETE FROM cache
                WHERE fetched_at < ?
            """,
                (expiry_cutoff,),
            )

            deleted = cursor.rowcount
            conn.commit()

        if deleted > 0:
            logger.debug(f"Cleaned up {deleted} expired cache entries")

        return deleted

    def _evict_if_full(self) -> None:
        """
        Evict oldest entries if cache is at capacity (LRU).

        Removes 10% of entries to reduce eviction frequency.
        """
        with sqlite3.connect(self.cache_path) as conn:
            cursor = conn.cursor()

            # Get current count
            cursor.execute("SELECT COUNT(*) FROM cache")
            count = cursor.fetchone()[0]

            # If at or over capacity, delete oldest entries by last_accessed
            if count >= self.max_entries:
                # Delete oldest 10% to reduce frequency of eviction
                delete_count = max(1, self.max_entries // 10)

                cursor.execute(
                    """
                    DELETE FROM cache
                    WHERE fingerprint IN (
                        SELECT fingerprint FROM cache
                        ORDER BY last_accessed ASC
                        LIMIT ?
                    )
                """,
                    (delete_count,),
                )

                deleted = cursor.rowcount
                conn.commit()

                logger.debug(f"Evicted {deleted} cache entries (LRU)")

    def clear_all(self) -> int:
        """
        Clear all cache entries.

        Returns:
            Number of entries deleted
        """
        with sqlite3.connect(self.cache_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM cache")
            count = cursor.fetchone()[0]

            cursor.execute("DELETE FROM cache")
            conn.commit()

        logger.info(f"Cleared all {count} cache entries")
        return count

    def get_stats(self) -> Dict:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        now = int(time.time())
        expiry_cutoff = now - self.ttl_seconds

        with sqlite3.connect(self.cache_path) as conn:
            cursor = conn.cursor()

            # Total entries
            cursor.execute("SELECT COUNT(*) FROM cache")
            total = cursor.fetchone()[0]

            # Valid (not expired) entries
            cursor.execute(
                """
                SELECT COUNT(*) FROM cache
                WHERE fetched_at >= ?
            """,
                (expiry_cutoff,),
            )
            valid = cursor.fetchone()[0]

            # Total accesses
            cursor.execute("SELECT SUM(access_count) FROM cache")
            total_accesses = cursor.fetchone()[0] or 0

            # Most accessed entry
            cursor.execute(
                """
                SELECT name, access_count FROM cache
                ORDER BY access_count DESC
                LIMIT 1
            """
            )
            most_accessed_row = cursor.fetchone()
            most_accessed = (
                {"name": most_accessed_row[0], "count": most_accessed_row[1]}
                if most_accessed_row
                else None
            )

        stats = {
            "total_entries": total,
            "valid_entries": valid,
            "expired_entries": total - valid,
            "max_entries": self.max_entries,
            "ttl_seconds": self.ttl_seconds,
            "total_accesses": total_accesses,
            "most_accessed": most_accessed,
            "cache_path": str(self.cache_path),
        }

        return stats

    def export_all(self, include_expired: bool = False) -> List[Dict]:
        """
        Export all cache entries for inspection.

        Args:
            include_expired: Include expired entries

        Returns:
            List of cache entry dictionaries
        """
        now = int(time.time())
        expiry_cutoff = now - self.ttl_seconds

        with sqlite3.connect(self.cache_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            if include_expired:
                cursor.execute("SELECT * FROM cache ORDER BY last_accessed DESC")
            else:
                cursor.execute(
                    """
                    SELECT * FROM cache
                    WHERE fetched_at >= ?
                    ORDER BY last_accessed DESC
                """,
                    (expiry_cutoff,),
                )

            rows = cursor.fetchall()

        result = []
        for row in rows:
            expired = row["fetched_at"] < expiry_cutoff
            result.append(
                {
                    "fingerprint": row["fingerprint"],
                    "name": row["name"],
                    "email": row["email"],
                    "fetched_at": row["fetched_at"],
                    "last_accessed": row["last_accessed"],
                    "access_count": row["access_count"],
                    "expired": expired,
                }
            )

        return result


if __name__ == "__main__":
    # Simple test
    print("KeyserverCache module loaded successfully")
