#!/usr/bin/env python3
"""
Security Audit Logger for OpenSSL Encrypt

This module provides security event logging for forensic analysis and compliance.
All security-relevant operations are logged in structured JSON format for easy
analysis and integration with SIEM systems.

Privacy Features:
- Never logs passwords, keys, or decrypted content
- Supports log anonymization for sensitive environments
- Configurable log retention and rotation

Usage:
    from openssl_encrypt.modules.security_logger import get_security_logger

    logger = get_security_logger()
    logger.log_event(
        "encryption_started",
        "info",
        {"algorithm": "aes-256-gcm", "file_count": 1}
    )
"""

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class SecurityAuditLogger:
    """
    Security audit logger for tracking security-relevant events.

    Features:
    - Structured JSON logging
    - Thread-safe operation
    - Automatic log rotation
    - Syslog integration (optional)
    - Privacy-preserving (no sensitive data logging)
    """

    # Singleton instance
    _instance: Optional["SecurityAuditLogger"] = None
    _lock = threading.Lock()

    # Event severity levels
    SEVERITY_INFO = "info"
    SEVERITY_WARNING = "warning"
    SEVERITY_CRITICAL = "critical"

    def __new__(cls, *args, **kwargs):
        """Ensure singleton pattern for logger."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, log_dir: Optional[str] = None, enabled: bool = True):
        """
        Initialize security audit logger.

        Args:
            log_dir: Directory for log files (default: ~/.openssl_encrypt/)
            enabled: Enable/disable logging (can be controlled via env var)
        """
        # Only initialize once
        if hasattr(self, "_initialized"):
            return

        self._initialized = True
        self._write_lock = threading.Lock()

        # Check if logging is disabled via environment variable
        self.enabled = enabled and os.getenv("OPENSSL_ENCRYPT_DISABLE_AUDIT_LOG") != "1"

        if not self.enabled:
            logger.info("Security audit logging is disabled")
            return

        # Determine log directory
        if log_dir:
            self.log_dir = Path(log_dir)
        else:
            # Check environment variable first
            env_log_dir = os.getenv("OPENSSL_ENCRYPT_AUDIT_LOG_DIR")
            if env_log_dir:
                self.log_dir = Path(env_log_dir)
            else:
                # Default to user's home directory
                self.log_dir = Path.home() / ".openssl_encrypt"

        # Create log directory if it doesn't exist
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        except Exception as e:
            logger.error(f"Failed to create log directory {self.log_dir}: {e}")
            self.enabled = False
            return

        self.log_file = self.log_dir / "security-audit.log"

        # Initialize syslog if requested
        self.syslog_enabled = os.getenv("OPENSSL_ENCRYPT_SYSLOG") == "1"
        self.syslog_handler = None

        if self.syslog_enabled:
            try:
                import logging.handlers

                self.syslog_handler = logging.handlers.SysLogHandler(address="/dev/log")
                logger.info("Syslog integration enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize syslog: {e}")
                self.syslog_enabled = False

        logger.info(f"Security audit logging initialized: {self.log_file}")

    def log_event(
        self,
        event_type: str,
        severity: str,
        details: Optional[Dict[str, Any]] = None,
        sensitive_fields: Optional[list] = None,
    ) -> None:
        """
        Log a security event.

        Args:
            event_type: Type of event (e.g., "encryption_started", "plugin_blocked")
            severity: Event severity ("info", "warning", "critical")
            details: Additional event details (dict)
            sensitive_fields: List of field names to anonymize (default: password, key)

        Example:
            logger.log_event(
                "decryption_failed",
                "warning",
                {"file": "document.txt.enc", "reason": "invalid_password"}
            )
        """
        if not self.enabled:
            return

        if details is None:
            details = {}

        # Default sensitive fields to anonymize
        if sensitive_fields is None:
            sensitive_fields = ["password", "key", "passphrase", "secret"]

        # Create event structure
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event_type": event_type,
            "severity": severity,
            "pid": os.getpid(),
            "user": os.getenv("USER", "unknown"),
        }

        # Add details, filtering sensitive fields
        filtered_details = {}
        for key, value in details.items():
            if any(sensitive in key.lower() for sensitive in sensitive_fields):
                filtered_details[key] = "***REDACTED***"
            else:
                # Truncate long values
                if isinstance(value, str) and len(value) > 256:
                    filtered_details[key] = value[:256] + "...[truncated]"
                else:
                    filtered_details[key] = value

        event["details"] = filtered_details

        # Write to log file
        self._write_to_log(event)

        # Send to syslog if enabled and severity is warning or critical
        if self.syslog_enabled and severity in [self.SEVERITY_WARNING, self.SEVERITY_CRITICAL]:
            self._send_to_syslog(event)

    def _write_to_log(self, event: dict) -> None:
        """Write event to log file (thread-safe)."""
        with self._write_lock:
            try:
                # Check if log rotation is needed
                self._rotate_log_if_needed()

                # Write event as JSON line
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event) + "\n")
            except Exception as e:
                logger.error(f"Failed to write to audit log: {e}")

    def _rotate_log_if_needed(self) -> None:
        """Rotate log file if it exceeds size limit."""
        max_size = 10 * 1024 * 1024  # 10 MB

        try:
            if self.log_file.exists() and self.log_file.stat().st_size > max_size:
                # Rotate: security-audit.log -> security-audit.log.1
                # Keep last 5 rotated logs
                for i in range(4, 0, -1):
                    old_file = self.log_dir / f"security-audit.log.{i}"
                    new_file = self.log_dir / f"security-audit.log.{i+1}"
                    if old_file.exists():
                        old_file.rename(new_file)

                # Move current log to .1
                self.log_file.rename(self.log_dir / "security-audit.log.1")
                logger.info("Security audit log rotated")
        except Exception as e:
            logger.error(f"Failed to rotate log: {e}")

    def _send_to_syslog(self, event: dict) -> None:
        """Send event to syslog."""
        if not self.syslog_handler:
            return

        try:
            # Map severity to syslog level
            severity_map = {
                self.SEVERITY_INFO: logging.INFO,
                self.SEVERITY_WARNING: logging.WARNING,
                self.SEVERITY_CRITICAL: logging.CRITICAL,
            }
            level = severity_map.get(event["severity"], logging.INFO)

            # Format message
            message = f"openssl_encrypt[{event['pid']}]: {event['event_type']} - {json.dumps(event['details'])}"

            # Create log record
            record = logging.LogRecord(
                name="openssl_encrypt.security",
                level=level,
                pathname="",
                lineno=0,
                msg=message,
                args=(),
                exc_info=None,
            )

            self.syslog_handler.emit(record)
        except Exception as e:
            logger.error(f"Failed to send to syslog: {e}")

    def get_recent_events(
        self, hours: int = 24, event_type: Optional[str] = None, severity: Optional[str] = None
    ) -> list:
        """
        Retrieve recent security events from log.

        Args:
            hours: Number of hours to look back (default: 24)
            event_type: Filter by event type (optional)
            severity: Filter by severity (optional)

        Returns:
            List of matching events
        """
        if not self.enabled or not self.log_file.exists():
            return []

        cutoff_time = time.time() - (hours * 3600)
        events = []

        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())

                        # Parse timestamp
                        event_time = datetime.fromisoformat(
                            event["timestamp"].replace("Z", "+00:00")
                        )
                        if event_time.timestamp() < cutoff_time:
                            continue

                        # Apply filters
                        if event_type and event["event_type"] != event_type:
                            continue
                        if severity and event["severity"] != severity:
                            continue

                        events.append(event)
                    except (json.JSONDecodeError, KeyError, ValueError):
                        continue
        except Exception as e:
            logger.error(f"Failed to read audit log: {e}")

        return events

    def clear_logs(self) -> bool:
        """
        Clear all security audit logs.

        Returns:
            True if successful, False otherwise

        Note:
            Use with caution - this removes forensic evidence!
        """
        try:
            if self.log_file.exists():
                self.log_file.unlink()

            # Remove rotated logs
            for i in range(1, 6):
                rotated = self.log_dir / f"security-audit.log.{i}"
                if rotated.exists():
                    rotated.unlink()

            logger.info("Security audit logs cleared")
            return True
        except Exception as e:
            logger.error(f"Failed to clear audit logs: {e}")
            return False


# Global singleton instance
_security_logger: Optional[SecurityAuditLogger] = None


def get_security_logger() -> SecurityAuditLogger:
    """
    Get the global security audit logger instance.

    Returns:
        SecurityAuditLogger singleton instance
    """
    global _security_logger
    if _security_logger is None:
        _security_logger = SecurityAuditLogger()
    return _security_logger


def is_audit_logging_enabled() -> bool:
    """
    Check if security audit logging is enabled.

    Returns:
        True if logging is enabled, False otherwise
    """
    return get_security_logger().enabled
