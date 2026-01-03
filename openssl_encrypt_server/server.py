#!/usr/bin/env python3
"""
OpenSSL Encrypt Server - Main Entry Point

Unified FastAPI server for Keyserver and Telemetry modules.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from .config import Settings, settings, validate_config
from .core.database import close_db, init_db, init_engine
from .core.exceptions import ServerException, server_exception_handler
from .modules import load_modules

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
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
    logger.info("=" * 60)
    logger.info(f"Starting {settings.app_name}...")
    logger.info(f"Version: {settings.version}")
    logger.info(f"Debug mode: {settings.debug}")
    logger.info("=" * 60)

    # Validate configuration
    try:
        validate_config(settings)
        logger.info("Configuration validated successfully")
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        raise

    # Import all models (must be done before init_db)
    if settings.keyserver_enabled:
        from .modules.keyserver import models as ks_models  # noqa: F401
    if settings.telemetry_enabled:
        from .modules.telemetry import models as tm_models  # noqa: F401
    if settings.pepper_enabled:
        from .modules.pepper import models as pp_models  # noqa: F401
    if settings.integrity_enabled:
        from .modules.integrity import models as in_models  # noqa: F401

    # Initialize database
    try:
        database_url = settings.get_database_url()
        init_engine(
            database_url,
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            query_timeout=settings.database_query_timeout,
        )
        await init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

    # Check if liboqs is available
    try:
        import oqs

        logger.info("liboqs is available - PQC signature verification enabled")
    except ImportError:
        logger.warning(
            "liboqs not available - keyserver signature verification will fail. "
            "Install with: pip install liboqs-python"
        )

    # Load enabled modules
    try:
        loaded_modules = load_modules(app, settings)
        logger.info(f"Loaded modules: {', '.join(loaded_modules)}")
    except Exception as e:
        logger.error(f"Failed to load modules: {e}")
        raise

    logger.info("=" * 60)
    logger.info(f"Server started on {settings.server_host}:{settings.server_port}")
    logger.info("=" * 60)

    yield

    # Shutdown
    logger.info("Shutting down server...")
    await close_db()
    logger.info("Server shutdown complete")


def create_app() -> FastAPI:
    """
    Create FastAPI application.

    Returns:
        FastAPI: Configured application
    """
    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        description="Unified server for Keyserver and Telemetry modules",
        lifespan=lifespan,
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
    )

    # Initialize rate limiter
    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter

    # Add CORS middleware - SECURITY: Only if origins are configured
    cors_origins = settings.get_cors_origins_list()
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=settings.cors_allow_credentials,
            allow_methods=settings.get_cors_methods_list(),
            allow_headers=settings.get_cors_headers_list(),
            max_age=settings.cors_max_age,
        )
        logger.info(f"CORS enabled for origins: {cors_origins}")
    else:
        logger.info("CORS disabled (no origins configured)")

    # Add exception handlers
    app.add_exception_handler(ServerException, server_exception_handler)
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Core routes
    @app.get("/health")
    async def health_check():
        """Health check endpoint"""
        return {
            "status": "healthy",
            "version": settings.version,
            "service": "openssl_encrypt_server",
        }

    @app.get("/ready")
    async def readiness_check():
        """Readiness check (database connectivity)"""
        try:
            from sqlalchemy import text
            from .core.database import _engine

            if not _engine:
                return {"status": "not_ready", "reason": "Database not initialized"}

            # Simple connection check
            async with _engine.connect() as conn:
                await conn.execute(text("SELECT 1"))

            return {"status": "ready"}
        except Exception as e:
            return {"status": "not_ready", "reason": str(e)}

    @app.get("/info")
    async def server_info():
        """Server information"""
        return {
            "name": settings.app_name,
            "version": settings.version,
            "modules": {
                "keyserver": {
                    "enabled": settings.keyserver_enabled,
                    "endpoints": ["/api/v1/keys/*"],
                },
                "telemetry": {
                    "enabled": settings.telemetry_enabled,
                    "endpoints": ["/api/v1/telemetry/*"],
                },
                "pepper": {
                    "enabled": settings.pepper_enabled,
                    "endpoints": ["/api/v1/pepper/*"],
                },
                "integrity": {
                    "enabled": settings.integrity_enabled,
                    "endpoints": ["/api/v1/integrity/*"],
                },
            },
        }

    @app.get("/")
    async def root():
        """Root endpoint"""
        return {
            "service": settings.app_name,
            "version": settings.version,
            "docs": "/docs" if settings.debug else "disabled",
            "health": "/health",
            "ready": "/ready",
            "info": "/info",
        }

    return app


# Create app instance
app = create_app()


if __name__ == "__main__":
    uvicorn.run(
        "server:app",
        host=settings.server_host,
        port=settings.server_port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )
