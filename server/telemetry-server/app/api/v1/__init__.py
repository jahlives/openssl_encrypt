#!/usr/bin/env python3
"""
API v1 endpoints.
"""

from fastapi import APIRouter

from .register import router as register_router
from .stats import router as stats_router
from .telemetry import router as telemetry_router

# Create main router
router = APIRouter(prefix="/api/v1", tags=["v1"])

# Include sub-routers
router.include_router(register_router, tags=["registration"])
router.include_router(telemetry_router, tags=["telemetry"])
router.include_router(stats_router, tags=["statistics"])

__all__ = ["router"]
