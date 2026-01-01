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

    # Load Pepper
    if settings.pepper_enabled:
        try:
            from .pepper import auth as pp_auth
            from .pepper import routes as pp_routes
            from .pepper.deadman import DeadmanWatcher

            # Initialize auth
            pp_auth.init_pepper_auth(settings.get_pepper_config())

            # Include router
            app.include_router(pp_routes.router)

            # Start deadman watcher if enabled
            pepper_config = settings.get_pepper_config()
            if pepper_config.deadman_enabled:
                watcher = DeadmanWatcher(pepper_config.deadman_check_interval)

                @app.on_event("startup")
                async def start_deadman_watcher():
                    await watcher.start()

                @app.on_event("shutdown")
                async def stop_deadman_watcher():
                    await watcher.stop()

            loaded.append("pepper")
            logger.info(f"Pepper module loaded (auth mode: {pepper_config.auth_mode})")
        except Exception as e:
            logger.error(f"Failed to load Pepper module: {e}")
            raise

    # Load Integrity
    if settings.integrity_enabled:
        try:
            from .integrity import auth as in_auth
            from .integrity import routes as in_routes

            # Initialize auth
            integrity_config = settings.get_integrity_config()
            in_auth.init_integrity_auth(integrity_config)

            # Include router
            app.include_router(in_routes.router)

            loaded.append("integrity")
            logger.info(f"Integrity module loaded (auth mode: {integrity_config.auth_mode})")
        except Exception as e:
            logger.error(f"Failed to load Integrity module: {e}")
            raise

    return loaded
