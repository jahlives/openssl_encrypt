#!/usr/bin/env python3
"""
OpenSSL Encrypt Telemetry Plugin - Main plugin implementation.

This plugin collects anonymous telemetry data about cryptographic algorithm usage
to help prioritize future development.

ACTIVATION (opt-in):
- CLI: --telemetry
- Config: telemetry.enabled = true
- Env: OPENSSL_ENCRYPT_TELEMETRY=1

PRIVACY GUARANTEES:
- Collects ONLY: Algorithms, KDF parameters, format versions
- Collects NOT: Passwords, keys, filenames, IPs, user identifiers
- User can inspect all data before upload
- Full opt-out deletes all local data
- Data filtered through TelemetryDataFilter (strict whitelist)

COMPONENTS:
- APIKeyManager: Anonymous client registration
- LocalBuffer: SQLite-based event storage
- TelemetryUploader: HTTPS batch uploads with retry
"""

import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from ...modules.plugin_system.plugin_base import (
    PluginCapability,
    PluginResult,
    PluginType,
    TelemetryPlugin,
)
from ...modules.telemetry_filter import TelemetryEvent
from .api_key_manager import APIKeyManager
from .local_buffer import LocalBuffer
from .uploader import TelemetryUploader

logger = logging.getLogger(__name__)


@dataclass
class TelemetryPluginConfig:
    """Configuration for telemetry plugin."""

    server_url: str
    buffer_path: Path
    max_buffer_size: int = 10000
    batch_size: int = 100
    upload_interval: int = 3600  # 1 hour


class OpenSSLEncryptTelemetryPlugin(TelemetryPlugin):
    """
    Main telemetry plugin implementation.

    This plugin:
    1. Receives filtered TelemetryEvent from core
    2. Buffers locally in SQLite
    3. Background uploads every 1 hour (configurable)
    4. Allows user inspection of all pending events
    5. Supports full opt-out with data deletion

    PRIVACY:
    - Only receives pre-filtered data (TelemetryEvent)
    - No access to sensitive information
    - User can inspect all data before upload
    - Full opt-out available
    """

    def __init__(self, config: Optional[TelemetryPluginConfig] = None):
        """
        Initialize telemetry plugin.

        Args:
            config: Optional configuration object
        """
        # Initialize base plugin
        super().__init__(
            plugin_id="openssl_encrypt_telemetry",
            name="OpenSSL Encrypt Telemetry",
            version="1.0.0",
        )

        # Configuration
        if config is None:
            config = self._get_default_config()
        self.telemetry_config = config

        # Components
        self.key_manager = APIKeyManager(self.telemetry_config)
        self.buffer = LocalBuffer(
            self.telemetry_config.buffer_path, self.telemetry_config.max_buffer_size
        )
        self.uploader = TelemetryUploader(self.telemetry_config, self.key_manager)

        # Background upload thread
        self._upload_thread: Optional[threading.Thread] = None
        self._stop_upload = threading.Event()
        self._start_background_upload()

    def _get_default_config(self) -> TelemetryPluginConfig:
        """
        Returns default configuration.

        Returns:
            TelemetryPluginConfig: Default configuration
        """
        # Get server URL from environment or use default
        server_url = os.getenv(
            "TELEMETRY_SERVER_URL", "https://telemetry.openssl-encrypt.example.com"
        )

        # Get buffer path (in user's home directory)
        buffer_path = Path.home() / ".openssl_encrypt" / "telemetry" / "buffer.db"

        return TelemetryPluginConfig(
            server_url=server_url,
            buffer_path=buffer_path,
            max_buffer_size=10000,
            batch_size=100,
            upload_interval=3600,  # 1 hour
        )

    def get_plugin_type(self) -> PluginType:
        """Returns plugin type."""
        return PluginType.TELEMETRY

    def get_required_capabilities(self) -> Set[PluginCapability]:
        """Returns required capabilities."""
        return {
            PluginCapability.TELEMETRY,
            PluginCapability.NETWORK_ACCESS,
            PluginCapability.ACCESS_CONFIG,
            PluginCapability.WRITE_LOGS,
        }

    def get_description(self) -> str:
        """Returns human-readable description of plugin functionality."""
        return (
            "Collects anonymous algorithm usage statistics to help prioritize future development. "
            "Privacy-preserving: only algorithm names and parameters are collected, "
            "never passwords, keys, filenames, or identifying information."
        )

    def on_telemetry_event(self, event: TelemetryEvent) -> None:
        """
        Receives filtered telemetry event from core.

        SECURITY: Event is already filtered by TelemetryDataFilter.
        This method only stores it locally for later upload.

        Args:
            event: TelemetryEvent (safe data only)
        """
        try:
            self.buffer.add(event)
            logger.debug(f"Telemetry event buffered: {event.operation}")
        except Exception as e:
            # Never crash on telemetry errors
            logger.debug(f"Failed to buffer telemetry event: {e}")

    def flush(self) -> PluginResult:
        """
        Uploads all buffered events immediately.

        Returns:
            PluginResult: Success or failure with message
        """
        try:
            uploaded_count = self._do_upload()

            if uploaded_count > 0:
                return PluginResult.success_result(f"Uploaded {uploaded_count} events")
            elif uploaded_count == 0:
                return PluginResult.success_result("No pending events to upload")
            else:
                return PluginResult(
                    success=False, message="Upload failed (network or server error)"
                )

        except Exception as e:
            logger.error(f"Telemetry flush failed: {e}")
            return PluginResult(success=False, message=f"Flush failed: {e}")

    def get_status(self) -> Dict[str, Any]:
        """
        Returns status for CLI display.

        Returns:
            dict: Status information
        """
        return {
            "enabled": True,
            "pending_events": self.buffer.get_pending_count(),
            "server_url": self.telemetry_config.server_url,
            "has_api_key": self.key_manager.has_valid_key(),
            "upload_interval": self.telemetry_config.upload_interval,
            "upload_thread_alive": self._upload_thread.is_alive() if self._upload_thread else False,
        }

    def get_pending_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Returns buffered events for user inspection (transparency).

        Args:
            limit: Maximum number of events to return

        Returns:
            List of event dictionaries
        """
        return self.buffer.export_pending(limit)

    def _start_background_upload(self) -> None:
        """
        Starts background upload thread.
        """
        if self._upload_thread and self._upload_thread.is_alive():
            return  # Already running

        self._stop_upload.clear()
        self._upload_thread = threading.Thread(
            target=self._background_upload_worker, daemon=True, name="TelemetryUploader"
        )
        self._upload_thread.start()
        logger.debug("Telemetry background upload thread started")

    def _background_upload_worker(self) -> None:
        """
        Background worker that uploads events periodically.
        """
        while not self._stop_upload.is_set():
            try:
                # Wait for upload interval (with periodic checks for stop signal)
                if self._stop_upload.wait(timeout=self.telemetry_config.upload_interval):
                    break  # Stop signal received

                # Upload events
                self._do_upload()

            except Exception as e:
                logger.debug(f"Background upload error: {e}")
                # Continue running despite errors

    def _do_upload(self) -> int:
        """
        Performs upload of buffered events.

        Returns:
            int: Number of events uploaded, or -1 on error
        """
        uploaded_count = 0

        try:
            # Get batch of pending events
            batch = self.buffer.get_batch(self.telemetry_config.batch_size)

            if not batch:
                return 0  # No events to upload

            # Extract event IDs and dictionaries
            event_ids = [event_id for event_id, _ in batch]
            events = [event_dict for _, event_dict in batch]

            # Upload batch
            result = self.uploader.upload_batch(events)

            if result:
                # Upload successful
                processed = result.get("processed", len(events))
                uploaded_count = processed

                # Mark as uploaded
                self.buffer.mark_uploaded(event_ids[:processed])

                logger.debug(f"Uploaded {processed} telemetry events")

                # Cleanup old uploaded events (older than 7 days)
                self.buffer.delete_uploaded(older_than_days=7)

            else:
                # Upload failed - increment retry count
                self.buffer.increment_retry(event_ids)
                logger.debug("Telemetry upload failed, will retry later")
                return -1

            return uploaded_count

        except Exception as e:
            logger.error(f"Telemetry upload error: {e}")
            return -1

    def stop(self) -> None:
        """
        Stops background upload thread (cleanup).
        """
        if self._upload_thread and self._upload_thread.is_alive():
            self._stop_upload.set()
            self._upload_thread.join(timeout=5)
            logger.debug("Telemetry background upload thread stopped")

    def opt_out(self) -> PluginResult:
        """
        Complete opt-out: deletes all local data.

        Returns:
            PluginResult: Success with count of deleted events
        """
        try:
            # Stop background uploads
            self.stop()

            # Clear all buffered events
            deleted_count = self.buffer.clear_all()

            # Delete API key
            self.key_manager.delete_key()

            return PluginResult.success_result(
                f"Opted out successfully. Deleted {deleted_count} events and API key."
            )

        except Exception as e:
            logger.error(f"Opt-out failed: {e}")
            return PluginResult(success=False, message=f"Opt-out failed: {e}")

    def __del__(self):
        """
        Cleanup on plugin destruction.
        """
        try:
            self.stop()
        except:
            pass
