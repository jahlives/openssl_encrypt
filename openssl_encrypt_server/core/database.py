#!/usr/bin/env python3
"""
Database setup with async SQLAlchemy.

Uses asyncpg driver for PostgreSQL with connection pooling.
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import declarative_base

logger = logging.getLogger(__name__)

# Base class for all models
Base = declarative_base()

# Global engine and session factory
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def init_engine(
    database_url: str,
    pool_size: int = 20,
    max_overflow: int = 10,
    query_timeout: int = 30,
):
    """
    Initialize async database engine.

    Args:
        database_url: PostgreSQL connection URL (must use asyncpg driver)
        pool_size: Number of connections in pool
        max_overflow: Maximum overflow connections
        query_timeout: Query timeout in seconds (default: 30)
    """
    global _engine, _session_factory

    logger.info(f"Initializing database engine: {database_url.split('@')[1] if '@' in database_url else database_url}")
    logger.info(f"Query timeout: {query_timeout}s")

    # Configure asyncpg-specific settings
    connect_args = {
        "command_timeout": query_timeout,  # Timeout for commands (queries)
        "server_settings": {
            "statement_timeout": f"{query_timeout}s",  # PostgreSQL statement timeout
        },
    }

    _engine = create_async_engine(
        database_url,
        echo=False,  # Set to True for SQL query logging
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=True,  # Verify connections before using
        connect_args=connect_args,  # Pass timeout configuration
    )

    _session_factory = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )

    logger.info("Database engine initialized successfully")


async def init_db():
    """
    Initialize database tables.

    Creates all tables defined in Base metadata.
    """
    global _engine

    if not _engine:
        raise RuntimeError("Database engine not initialized. Call init_engine() first.")

    logger.info("Creating database tables...")

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    logger.info("Database tables created successfully")


async def close_db():
    """Close database engine and connections."""
    global _engine

    if _engine:
        logger.info("Closing database engine...")
        await _engine.dispose()
        logger.info("Database engine closed")


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager for database sessions.

    Usage:
        async with get_db_session() as session:
            result = await session.execute(query)

    Yields:
        AsyncSession: Database session
    """
    global _session_factory

    if not _session_factory:
        raise RuntimeError("Database not initialized. Call init_engine() first.")

    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for database sessions.

    Usage:
        @router.get("/")
        async def endpoint(db: AsyncSession = Depends(get_db)):
            result = await db.execute(query)

    Yields:
        AsyncSession: Database session
    """
    async with get_db_session() as session:
        yield session
