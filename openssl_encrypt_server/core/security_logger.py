#!/usr/bin/env python3
"""
Centralized Security Event Logger.

Provides structured logging for security-critical events across all modules.
Events are logged to a dedicated security log file in JSON format for easy
parsing and SIEM integration.

Security events include:
- Authentication failures (mTLS, JWT, TOTP)
- Rate limiting violations
- Integrity check failures
- Panic mode activations
- Certificate revocations
- Suspicious activity patterns
"""

import json
import logging
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional


class SecurityEventType(Enum):
    """Security event types for categorization and filtering."""

    # Authentication events
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    TOTP_FAILURE = "totp_failure"
    TOTP_LOCKOUT = "totp_lockout"

    # Rate limiting events
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"

    # Integrity events
    INTEGRITY_MISMATCH = "integrity_mismatch"
    INTEGRITY_CHECK_FAILED = "integrity_check_failed"

    # Panic mode events
    PANIC_TRIGGERED = "panic_triggered"
    PANIC_ACTIVATED = "panic_activated"

    # Certificate events
    KEY_REVOKED = "key_revoked"
    CERT_VERIFICATION_FAILED = "cert_verification_failed"

    # Suspicious activity
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    UNTRUSTED_PROXY = "untrusted_proxy"

    # Plugin security events
    PLUGIN_SANDBOX_VIOLATION = "plugin_sandbox_violation"
    PLUGIN_CAPABILITY_VIOLATION = "plugin_capability_violation"


class SecurityEventSeverity(Enum):
    """Event severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class SecurityLogger:
    """
    Centralized security event logger.

    Logs structured security events to a dedicated log file separate from
    application logs. Each event includes timestamp, event type, severity,
    client identifier, and contextual details.

    Thread-safe for concurrent logging from multiple modules.
    """

    def __init__(
        self,
        log_file: str = "/var/log/openssl-encrypt/security.log",
        log_level: int = logging.INFO,
    ):
        """
        Initialize security logger.

        Args:
            log_file: Path to security log file
            log_level: Minimum logging level (default: INFO)
        """
        self.logger = logging.getLogger("security")
        self.logger.setLevel(log_level)

        # Create log directory if it doesn't exist
        log_path = Path(log_file)
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self.log_file = log_file
        except PermissionError:
            # Fall back to temp directory for testing/development
            import tempfile
            fallback_dir = Path(tempfile.gettempdir()) / "openssl-encrypt"
            fallback_dir.mkdir(parents=True, exist_ok=True)
            self.log_file = str(fallback_dir / "security.log")
            # Log warning to console
            print(f"WARNING: Cannot write to {log_file}, using fallback: {self.log_file}")

        # Configure JSON formatter for structured logging
        handler = logging.FileHandler(self.log_file)
        handler.setFormatter(
            logging.Formatter(
                '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
                '"event_type": "%(event_type)s", "severity": "%(severity)s", '
                '"client_id": "%(client_id)s", "details": %(details)s}'
            )
        )
        self.logger.addHandler(handler)

        # Also log to console for development
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter(
                "[SECURITY] %(levelname)s - %(event_type)s - %(client_id)s - %(message)s"
            )
        )
        self.logger.addHandler(console_handler)

        self.logger.info("Security logger initialized", extra={
            "event_type": "system",
            "severity": "info",
            "client_id": "system",
            "details": json.dumps({"log_file": log_file})
        })

    def log_event(
        self,
        event_type: SecurityEventType,
        severity: SecurityEventSeverity,
        client_id: str,
        details: Optional[Dict[str, Any]] = None,
        message: Optional[str] = None,
    ):
        """
        Log a security event.

        Args:
            event_type: Type of security event
            severity: Event severity level
            client_id: Client identifier (cert fingerprint, client ID, or 'system')
            details: Additional event details (will be JSON serialized)
            message: Human-readable message (optional)
        """
        # Sanitize client_id for logging (truncate if too long)
        safe_client_id = str(client_id)[:64] if client_id else "unknown"

        # Prepare event details
        event_details = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type.value,
            **(details or {})
        }

        # Choose log level based on severity
        log_level_map = {
            SecurityEventSeverity.INFO: logging.INFO,
            SecurityEventSeverity.WARNING: logging.WARNING,
            SecurityEventSeverity.ERROR: logging.ERROR,
            SecurityEventSeverity.CRITICAL: logging.CRITICAL,
        }
        log_level = log_level_map[severity]

        # Log with structured data
        self.logger.log(
            log_level,
            message or f"{event_type.value} event",
            extra={
                "event_type": event_type.value,
                "severity": severity.value,
                "client_id": safe_client_id,
                "details": json.dumps(event_details, default=str),
            }
        )

    def log_auth_failure(
        self,
        client_id: str,
        reason: str,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """
        Log authentication failure event.

        Args:
            client_id: Client attempting authentication
            reason: Reason for failure
            ip_address: Client IP address (optional)
            details: Additional context
        """
        event_details = {
            "reason": reason,
            "ip_address": ip_address,
            **(details or {})
        }
        self.log_event(
            SecurityEventType.AUTH_FAILURE,
            SecurityEventSeverity.WARNING,
            client_id,
            event_details,
            f"Authentication failed: {reason}"
        )

    def log_rate_limit(
        self,
        client_id: str,
        endpoint: str,
        attempts: int,
        ip_address: Optional[str] = None,
    ):
        """
        Log rate limit exceeded event.

        Args:
            client_id: Client exceeding rate limit
            endpoint: API endpoint being rate limited
            attempts: Number of attempts made
            ip_address: Client IP address (optional)
        """
        self.log_event(
            SecurityEventType.RATE_LIMIT_EXCEEDED,
            SecurityEventSeverity.WARNING,
            client_id,
            {
                "endpoint": endpoint,
                "attempts": attempts,
                "ip_address": ip_address,
            },
            f"Rate limit exceeded on {endpoint}"
        )

    def log_integrity_mismatch(
        self,
        client_id: str,
        file_id: str,
        expected_hash: str,
        actual_hash: str,
        ip_address: Optional[str] = None,
    ):
        """
        Log integrity check mismatch (potential tampering).

        Args:
            client_id: Client with mismatched hash
            file_id: File identifier
            expected_hash: Stored hash
            actual_hash: Computed hash
            ip_address: Client IP address (optional)
        """
        self.log_event(
            SecurityEventType.INTEGRITY_MISMATCH,
            SecurityEventSeverity.CRITICAL,
            client_id,
            {
                "file_id": file_id,
                "expected_hash": expected_hash[:16] + "...",  # Truncate for privacy
                "actual_hash": actual_hash[:16] + "...",
                "ip_address": ip_address,
            },
            f"INTEGRITY VIOLATION: File {file_id} hash mismatch detected"
        )

    def log_panic_triggered(
        self,
        client_id: str,
        trigger_reason: str,
        ip_address: Optional[str] = None,
    ):
        """
        Log panic mode activation.

        Args:
            client_id: Client triggering panic mode
            trigger_reason: Reason for panic trigger
            ip_address: Client IP address (optional)
        """
        self.log_event(
            SecurityEventType.PANIC_TRIGGERED,
            SecurityEventSeverity.CRITICAL,
            client_id,
            {
                "trigger_reason": trigger_reason,
                "ip_address": ip_address,
            },
            f"PANIC MODE TRIGGERED: {trigger_reason}"
        )

    def log_totp_lockout(
        self,
        client_id: str,
        attempts: int,
        lockout_duration_seconds: int,
    ):
        """
        Log TOTP brute force lockout.

        Args:
            client_id: Client being locked out
            attempts: Number of failed attempts
            lockout_duration_seconds: Lockout duration
        """
        self.log_event(
            SecurityEventType.TOTP_LOCKOUT,
            SecurityEventSeverity.WARNING,
            client_id,
            {
                "failed_attempts": attempts,
                "lockout_duration_seconds": lockout_duration_seconds,
            },
            f"TOTP lockout: {attempts} failed attempts"
        )

    def log_plugin_violation(
        self,
        plugin_id: str,
        violation_type: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        """
        Log plugin security violation.

        Args:
            plugin_id: Plugin identifier
            violation_type: Type of violation
            details: Additional context
        """
        self.log_event(
            SecurityEventType.PLUGIN_SANDBOX_VIOLATION,
            SecurityEventSeverity.ERROR,
            plugin_id,
            {
                "violation_type": violation_type,
                **(details or {})
            },
            f"Plugin sandbox violation: {violation_type}"
        )


# Global security logger instance (initialized on first import)
_security_logger: Optional[SecurityLogger] = None


def get_security_logger() -> SecurityLogger:
    """
    Get or create global security logger instance.

    Returns:
        SecurityLogger instance
    """
    global _security_logger
    if _security_logger is None:
        _security_logger = SecurityLogger()
    return _security_logger


# Convenience function for quick logging
def log_security_event(
    event_type: SecurityEventType,
    severity: SecurityEventSeverity,
    client_id: str,
    details: Optional[Dict[str, Any]] = None,
    message: Optional[str] = None,
):
    """
    Quick logging function using global logger.

    Args:
        event_type: Type of security event
        severity: Event severity level
        client_id: Client identifier
        details: Additional event details
        message: Human-readable message
    """
    logger = get_security_logger()
    logger.log_event(event_type, severity, client_id, details, message)
