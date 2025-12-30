#!/usr/bin/env python3
"""
OpenSSL Encrypt Keyserver - Main Application

This is the main FastAPI application for the keyserver.

SECURITY:
- Bearer token authentication for uploads/revocations
- Public search endpoint (no auth)
- Signature verification for all uploaded keys
- CORS configuration
- Rate limiting

Features:
- Upload public keys (authenticated)
- Search for public keys (public)
- Revoke keys (authenticated)
- Health check endpoint
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.v1 import keys
from .config import settings
from .database import init_db

# Set up logging
logging.basicConfig(
    level=logging.INFO if not settings.debug else logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan event handler for FastAPI.

    Runs on startup and shutdown.
    """
    # Startup
    logger.info("Starting OpenSSL Encrypt Keyserver...")
    logger.info(f"Version: {settings.version}")
    logger.info(f"Debug mode: {settings.debug}")

    # Initialize database
    try:
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

    # Check if liboqs is available
    try:
        import oqs

        logger.info("liboqs is available - signature verification enabled")
    except ImportError:
        logger.warning(
            "liboqs not available - signature verification will fail. "
            "Install with: pip install liboqs-python"
        )

    yield

    # Shutdown
    logger.info("Shutting down OpenSSL Encrypt Keyserver...")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Post-quantum keyserver for public key distribution",
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(keys.router)


@app.get("/health")
async def health_check():
    """
    Health check endpoint.

    Returns:
        Status information
    """
    return {
        "status": "healthy",
        "version": settings.version,
        "service": "keyserver",
    }


@app.get("/")
async def root():
    """
    Root endpoint with service information.

    Returns:
        Service information
    """
    return {
        "service": settings.app_name,
        "version": settings.version,
        "endpoints": {
            "health": "/health",
            "upload": "POST /api/v1/keys (authenticated)",
            "search": "GET /api/v1/keys/search?q=<query> (public)",
            "revoke": "POST /api/v1/keys/{fingerprint}/revoke (authenticated)",
        },
        "authentication": "Bearer token required for upload and revoke",
        "algorithms": {
            "kem": settings.allowed_kem_algorithms,
            "signing": settings.allowed_signing_algorithms,
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8080,
        reload=settings.debug,
        log_level="debug" if settings.debug else "info",
    )
