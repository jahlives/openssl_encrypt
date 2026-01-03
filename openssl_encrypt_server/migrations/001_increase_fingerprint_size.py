#!/usr/bin/env python3
"""
Migration: Increase fingerprint column size from 64 to 100

Date: 2026-01-03
Reason: SHA-256 fingerprints with colon separators are 95 characters (32 bytes * 2 hex + 31 colons)
        Previous size of 64 was insufficient

Usage:
    python3 001_increase_fingerprint_size.py --database-url "postgresql+asyncpg://user:pass@host/db"
"""

import asyncio
import argparse
import logging
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def run_migration(database_url: str):
    """
    Run the migration to increase fingerprint column sizes.

    Args:
        database_url: PostgreSQL connection URL (asyncpg format)
    """
    logger.info("Starting migration: Increase fingerprint column size")
    logger.info(f"Database: {database_url.split('@')[1] if '@' in database_url else database_url}")

    # Create engine
    engine = create_async_engine(database_url, echo=False)

    try:
        async with engine.begin() as conn:
            # Check current column size
            logger.info("Checking current fingerprint column sizes...")

            result = await conn.execute(
                text(
                    """
                    SELECT
                        column_name,
                        character_maximum_length
                    FROM information_schema.columns
                    WHERE table_name IN ('ks_keys', 'ks_access_log')
                    AND column_name IN ('fingerprint', 'key_fingerprint')
                    ORDER BY table_name, column_name
                    """
                )
            )

            current_sizes = result.fetchall()
            for row in current_sizes:
                logger.info(f"  {row[0]}: VARCHAR({row[1]})")

            # Run migration
            logger.info("Altering ks_keys.fingerprint column...")
            await conn.execute(text("ALTER TABLE ks_keys ALTER COLUMN fingerprint TYPE VARCHAR(100)"))

            logger.info("Altering ks_access_log.key_fingerprint column...")
            await conn.execute(
                text("ALTER TABLE ks_access_log ALTER COLUMN key_fingerprint TYPE VARCHAR(100)")
            )

            # Add comments
            logger.info("Adding column comments...")
            await conn.execute(
                text(
                    "COMMENT ON COLUMN ks_keys.fingerprint IS 'SHA-256 fingerprint with colons (e.g., 3a:4b:5c:...) - 95 characters'"
                )
            )
            await conn.execute(
                text(
                    "COMMENT ON COLUMN ks_access_log.key_fingerprint IS 'SHA-256 fingerprint with colons (e.g., 3a:4b:5c:...) - 95 characters'"
                )
            )

            # Verify changes
            logger.info("Verifying changes...")
            result = await conn.execute(
                text(
                    """
                    SELECT
                        column_name,
                        character_maximum_length
                    FROM information_schema.columns
                    WHERE table_name IN ('ks_keys', 'ks_access_log')
                    AND column_name IN ('fingerprint', 'key_fingerprint')
                    ORDER BY table_name, column_name
                    """
                )
            )

            new_sizes = result.fetchall()
            for row in new_sizes:
                logger.info(f"  {row[0]}: VARCHAR({row[1]}) ✓")

        logger.info("✓ Migration completed successfully")

    except Exception as e:
        logger.error(f"✗ Migration failed: {e}")
        raise

    finally:
        await engine.dispose()


def main():
    parser = argparse.ArgumentParser(description="Run fingerprint column migration")
    parser.add_argument(
        "--database-url",
        required=True,
        help="PostgreSQL connection URL (asyncpg format: postgresql+asyncpg://user:pass@host/db)",
    )

    args = parser.parse_args()

    # Run migration
    asyncio.run(run_migration(args.database_url))


if __name__ == "__main__":
    main()
