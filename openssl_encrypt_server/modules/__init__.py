#!/usr/bin/env python3
"""
Module loader for dynamic module initialization.

Loads enabled modules based on configuration.
"""

import logging

from fastapi import FastAPI

logger = logging.getLogger(__name__)


def load_modules(app: FastAPI, settings) -> list[str]:
    """
    Load enabled modules based on configuration.

    Args:
        app: FastAPI application
        settings: Server settings

    Returns:
        list: Names of loaded modules
    """
    loaded = []

    # Load Keyserver
    if settings.keyserver_enabled:
        try:
            from .keyserver import auth as ks_auth
            from .keyserver import routes as ks_routes

            # Initialize auth
            ks_auth.init_keyserver_auth(settings.get_keyserver_config())

            # Include router
            app.include_router(ks_routes.router)

            loaded.append("keyserver")
            logger.info("Keyserver module loaded")
        except Exception as e:
            logger.error(f"Failed to load Keyserver module: {e}")
            raise

    # Load Telemetry
    if settings.telemetry_enabled:
        try:
            from .telemetry import auth as tm_auth
            from .telemetry import routes as tm_routes

            # Initialize auth
            tm_auth.init_telemetry_auth(settings.get_telemetry_config())

            # Include router
            app.include_router(tm_routes.router)

            loaded.append("telemetry")
            logger.info("Telemetry module loaded")
        except Exception as e:
            logger.error(f"Failed to load Telemetry module: {e}")
            raise

    return loaded
