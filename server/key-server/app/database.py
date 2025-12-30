#!/usr/bin/env python3
"""
Database Setup

This module handles PostgreSQL database connection and session management.
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from .config import settings

# Create database engine
engine = create_engine(settings.database_url, pool_pre_ping=True)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()


def get_db():
    """
    Database dependency for FastAPI.

    Yields:
        Database session

    Example:
        @app.get("/keys")
        def get_keys(db: Session = Depends(get_db)):
            return db.query(PublicKey).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Initialize database (create all tables).

    Call this on application startup.
    """
    Base.metadata.create_all(bind=engine)
