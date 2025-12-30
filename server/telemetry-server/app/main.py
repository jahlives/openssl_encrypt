#!/usr/bin/env python3
"""
Main FastAPI application for OpenSSL Encrypt Telemetry Server.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.v1 import router as api_v1_router
from .config import settings
from .database import init_db

# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Anonymous telemetry server for OpenSSL Encrypt algorithm usage statistics",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add CORS middleware (for public stats endpoint)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# Health check endpoint
@app.get("/health", tags=["health"])
def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": settings.app_version}


# Include API routers
app.include_router(api_v1_router)


# Startup event
@app.on_event("startup")
def startup_event():
    """Initialize database on startup."""
    init_db()


# Root endpoint
@app.get("/", tags=["root"])
def root():
    """Root endpoint with API information."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/health",
        "api": {
            "v1": {
                "register": "/api/v1/register",
                "telemetry": "/api/v1/telemetry",
                "stats": "/api/v1/stats",
                "key_refresh": "/api/v1/key/refresh",
            }
        },
    }
