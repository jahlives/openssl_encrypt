#!/usr/bin/env python3
"""
Audit Logger Plugin

This plugin demonstrates comprehensive audit logging and security monitoring
capabilities within the OpenSSL Encrypt plugin system. It shows how to
safely log encryption operations while maintaining security boundaries.

Features:
- Comprehensive audit logging for all operations
- Security event monitoring and alerting
- Structured log format with timestamps
- Log rotation and retention management
- Safe logging (no sensitive data exposure)
- Performance metrics collection

Security Notes:
- Never logs sensitive data (passwords, keys, plaintext)
- Uses structured logging with proper sanitization
- Implements secure log file handling
- Respects user privacy while maintaining audit trails
- Configurable log levels and retention policies
"""

import hashlib
import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...modules.plugin_system import (
    MetadataHandlerPlugin,
    PluginCapability,
    PluginResult,
    PluginSecurityContext,
    PostProcessorPlugin,
    PreProcessorPlugin,
    UtilityPlugin,
)


class AuditLogger:
    """Centralized audit logging functionality."""

    def __init__(self, log_dir: Optional[str] = None):
        self.log_dir = Path(log_dir) if log_dir else Path.home() / ".openssl_encrypt_audit"
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Set secure permissions on log directory
        os.chmod(self.log_dir, 0o700)

        # Setup logging
        self.logger = logging.getLogger("openssl_encrypt_audit")
        self.logger.setLevel(logging.INFO)

        # Create file handler with rotation
        log_file = self.log_dir / "audit.log"
        handler = logging.FileHandler(log_file)

        # Secure log file permissions
        if log_file.exists():
            os.chmod(log_file, 0o600)

        # Format for structured logging
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)

        if not self.logger.handlers:
            self.logger.addHandler(handler)

        self.lock = threading.Lock()

    def log_event(self, event_type: str, details: Dict[str, Any], level: str = "INFO"):
        """Log an audit event with structured data."""
        with self.lock:
            # Sanitize details to ensure no sensitive data
            safe_details = self._sanitize_details(details)

            event_data = {
                "event_type": event_type,
                "timestamp": time.time(),
                "details": safe_details,
            }

            log_message = json.dumps(event_data, default=str)

            if level.upper() == "ERROR":
                self.logger.error(log_message)
            elif level.upper() == "WARNING":
                self.logger.warning(log_message)
            else:
                self.logger.info(log_message)

    def _sanitize_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive data from log details."""
        safe_details = {}
        sensitive_keys = {
            "password",
            "key",
            "secret",
            "token",
            "auth",
            "credential",
            "private",
            "passphrase",
            "salt",
            "iv",
            "nonce",
            "plaintext",
            "decrypted",
            "unencrypted",
        }

        for key, value in details.items():
            key_lower = key.lower()

            # Skip sensitive keys
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                safe_details[key] = "[REDACTED]"
                continue

            # Handle nested dictionaries
            if isinstance(value, dict):
                safe_details[key] = self._sanitize_details(value)
            elif isinstance(value, list):
                safe_details[key] = [
                    self._sanitize_details(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                safe_details[key] = value

        return safe_details


class EncryptionAuditPlugin(PreProcessorPlugin):
    """Pre-processor that logs encryption operations."""

    def __init__(self):
        super().__init__("encryption_auditor", "Encryption Audit Logger", "1.0.0")
        self.audit_logger = None

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES, PluginCapability.WRITE_LOGS}

    def get_description(self):
        return "Logs encryption operations for audit and compliance purposes"

    def initialize(self, config: Dict[str, Any]) -> PluginResult:
        """Initialize audit logging."""
        try:
            log_dir = config.get("audit_log_directory")
            self.audit_logger = AuditLogger(log_dir)

            self.audit_logger.log_event(
                "plugin_initialized",
                {
                    "plugin_id": self.plugin_id,
                    "plugin_name": self.name,
                    "version": self.version,
                    "log_directory": str(self.audit_logger.log_dir),
                },
            )

            return PluginResult.success_result("Audit logging initialized")

        except Exception as e:
            return PluginResult.error_result(f"Audit initialization failed: {str(e)}")

    def process_file(self, file_path: str, context: PluginSecurityContext) -> PluginResult:
        """Log encryption operation start."""
        try:
            if not self.audit_logger:
                self.audit_logger = AuditLogger()

            if not os.path.exists(file_path):
                self.audit_logger.log_event(
                    "encryption_error",
                    {
                        "error": "file_not_found",
                        "file_path": file_path,
                        "operation": "encrypt_start",
                    },
                    "ERROR",
                )
                return PluginResult.error_result(f"File not found: {file_path}")

            # Get safe file information
            stat = os.stat(file_path)
            file_info = {
                "file_name": os.path.basename(file_path),
                "file_size": stat.st_size,
                "file_extension": Path(file_path).suffix.lower(),
                "operation": context.metadata.get("operation", "unknown"),
                "algorithm": context.metadata.get("algorithm", "unknown"),
                "session_id": self._generate_session_id(context),
            }

            # Add to context for correlation with post-processing
            context.add_metadata("audit_session_id", file_info["session_id"])
            context.add_metadata("operation_start_time", time.time())

            self.audit_logger.log_event("encryption_started", file_info)

            return PluginResult.success_result(
                f"Logged encryption start for {file_info['file_name']}",
                {"session_id": file_info["session_id"]},
            )

        except Exception as e:
            if self.audit_logger:
                self.audit_logger.log_event(
                    "audit_error",
                    {"error": str(e), "plugin": self.plugin_id, "operation": "process_file"},
                    "ERROR",
                )
            return PluginResult.error_result(f"Audit logging failed: {str(e)}")

    def _generate_session_id(self, context: PluginSecurityContext) -> str:
        """Generate a unique session ID for operation correlation."""
        session_data = f"{context.plugin_id}_{time.time()}_{os.getpid()}"
        return hashlib.sha256(session_data.encode()).hexdigest()[:16]


class EncryptionCompletionAuditor(PostProcessorPlugin):
    """Post-processor that logs encryption completion."""

    def __init__(self):
        super().__init__("completion_auditor", "Encryption Completion Auditor", "1.0.0")
        self.audit_logger = None

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES, PluginCapability.WRITE_LOGS}

    def get_description(self):
        return "Logs encryption completion and performance metrics"

    def initialize(self, config: Dict[str, Any]) -> PluginResult:
        """Initialize audit logging."""
        try:
            log_dir = config.get("audit_log_directory")
            self.audit_logger = AuditLogger(log_dir)
            return PluginResult.success_result("Completion auditing initialized")
        except Exception as e:
            return PluginResult.error_result(f"Completion audit initialization failed: {str(e)}")

    def process_encrypted_file(
        self, encrypted_file_path: str, context: PluginSecurityContext
    ) -> PluginResult:
        """Log encryption completion."""
        try:
            if not self.audit_logger:
                self.audit_logger = AuditLogger()

            if not os.path.exists(encrypted_file_path):
                self.audit_logger.log_event(
                    "encryption_error",
                    {
                        "error": "encrypted_file_not_found",
                        "file_path": encrypted_file_path,
                        "operation": "encrypt_complete",
                    },
                    "ERROR",
                )
                return PluginResult.error_result(f"Encrypted file not found: {encrypted_file_path}")

            # Calculate operation duration
            start_time = context.metadata.get("operation_start_time", 0)
            duration = time.time() - start_time if start_time else 0

            # Get file information
            encrypted_stat = os.stat(encrypted_file_path)
            completion_info = {
                "encrypted_file_name": os.path.basename(encrypted_file_path),
                "encrypted_size": encrypted_stat.st_size,
                "original_size": context.metadata.get("original_file_size", 0),
                "session_id": context.metadata.get("audit_session_id", "unknown"),
                "operation": context.metadata.get("operation", "unknown"),
                "algorithm": context.metadata.get("algorithm", "unknown"),
                "duration_seconds": duration,
                "success": True,
            }

            # Calculate overhead if original size is available
            if completion_info["original_size"] > 0:
                overhead = completion_info["encrypted_size"] - completion_info["original_size"]
                completion_info["overhead_bytes"] = overhead
                completion_info["overhead_percentage"] = (
                    overhead / completion_info["original_size"]
                ) * 100

            self.audit_logger.log_event("encryption_completed", completion_info)

            return PluginResult.success_result(
                f"Logged encryption completion for {completion_info['encrypted_file_name']}",
                {
                    "session_id": completion_info["session_id"],
                    "duration": duration,
                    "success": True,
                },
            )

        except Exception as e:
            if self.audit_logger:
                self.audit_logger.log_event(
                    "audit_error",
                    {
                        "error": str(e),
                        "plugin": self.plugin_id,
                        "operation": "process_encrypted_file",
                    },
                    "ERROR",
                )
            return PluginResult.error_result(f"Completion audit failed: {str(e)}")


class SecurityEventMonitor(MetadataHandlerPlugin):
    """Metadata handler that monitors for security events."""

    def __init__(self):
        super().__init__("security_monitor", "Security Event Monitor", "1.0.0")
        self.audit_logger = None

    def get_required_capabilities(self):
        return {PluginCapability.MODIFY_METADATA, PluginCapability.WRITE_LOGS}

    def get_description(self):
        return "Monitors for security events and suspicious activities"

    def initialize(self, config: Dict[str, Any]) -> PluginResult:
        """Initialize security monitoring."""
        try:
            log_dir = config.get("audit_log_directory")
            self.audit_logger = AuditLogger(log_dir)
            return PluginResult.success_result("Security monitoring initialized")
        except Exception as e:
            return PluginResult.error_result(f"Security monitor initialization failed: {str(e)}")

    def process_metadata(
        self, metadata: Dict[str, Any], context: PluginSecurityContext
    ) -> PluginResult:
        """Monitor metadata for security events."""
        try:
            if not self.audit_logger:
                self.audit_logger = AuditLogger()

            security_events = []

            # Check for suspicious patterns
            if self._detect_bulk_operations(metadata, context):
                security_events.append("bulk_operations_detected")

            if self._detect_unusual_file_sizes(metadata):
                security_events.append("unusual_file_size")

            if self._detect_frequent_operations(metadata, context):
                security_events.append("high_frequency_operations")

            # Log security events if found
            if security_events:
                event_info = {
                    "security_events": security_events,
                    "operation": context.metadata.get("operation", "unknown"),
                    "file_count": len(context.file_paths),
                    "session_info": {"plugin_id": context.plugin_id, "timestamp": time.time()},
                }

                self.audit_logger.log_event("security_event_detected", event_info, "WARNING")

                # Add security metadata for other plugins
                context.add_metadata("security_events_detected", security_events)
                context.add_metadata("security_monitoring_active", True)

            return PluginResult.success_result(
                f"Security monitoring complete, {len(security_events)} events detected",
                {"security_events": security_events, "monitoring_active": True},
            )

        except Exception as e:
            if self.audit_logger:
                self.audit_logger.log_event(
                    "audit_error",
                    {"error": str(e), "plugin": self.plugin_id, "operation": "process_metadata"},
                    "ERROR",
                )
            return PluginResult.error_result(f"Security monitoring failed: {str(e)}")

    def _detect_bulk_operations(
        self, metadata: Dict[str, Any], context: PluginSecurityContext
    ) -> bool:
        """Detect if this appears to be a bulk operation."""
        # Consider it bulk if processing many files or very large files
        file_count = len(context.file_paths)
        file_size = metadata.get("original_file_size", 0)

        return file_count > 10 or file_size > 100 * 1024 * 1024  # 100MB

    def _detect_unusual_file_sizes(self, metadata: Dict[str, Any]) -> bool:
        """Detect unusually large or small files."""
        file_size = metadata.get("original_file_size", 0)

        # Flag very large files (>1GB) or suspiciously small files
        return file_size > 1024 * 1024 * 1024 or (file_size > 0 and file_size < 10)

    def _detect_frequent_operations(
        self, metadata: Dict[str, Any], context: PluginSecurityContext
    ) -> bool:
        """Detect high frequency operations (simplified check)."""
        # This would typically check against a time window of operations
        # For now, just check if operations are happening very quickly
        start_time = context.metadata.get("operation_start_time", 0)
        if start_time > 0:
            duration = time.time() - start_time
            return duration < 0.1  # Very fast operation might be automated
        return False


class AuditUtilityPlugin(UtilityPlugin):
    """Utility plugin for audit log management."""

    def __init__(self):
        super().__init__("audit_utils", "Audit Utility Plugin", "1.0.0")

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES, PluginCapability.WRITE_LOGS}

    def get_description(self):
        return "Provides utility functions for audit log management and analysis"

    def get_utility_functions(self) -> Dict[str, callable]:
        """Return available utility functions."""
        return {
            "analyze_audit_logs": self.analyze_audit_logs,
            "cleanup_old_logs": self.cleanup_old_logs,
            "export_audit_report": self.export_audit_report,
            "get_audit_statistics": self.get_audit_statistics,
        }

    def analyze_audit_logs(self, log_dir: Optional[str] = None, days: int = 7) -> Dict[str, Any]:
        """Analyze audit logs for patterns and statistics."""
        try:
            if not log_dir:
                log_dir = Path.home() / ".openssl_encrypt_audit"
            else:
                log_dir = Path(log_dir)

            log_file = log_dir / "audit.log"
            if not log_file.exists():
                return {"error": "Audit log file not found"}

            # Parse log entries
            events = []
            cutoff_time = time.time() - (days * 24 * 3600)

            with open(log_file, "r") as f:
                for line in f:
                    try:
                        # Parse log line
                        if " | " in line:
                            parts = line.strip().split(" | ", 3)
                            if len(parts) >= 4:
                                timestamp_str, level, logger_name, message = parts

                                # Parse timestamp
                                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

                                # Skip old entries
                                if timestamp.timestamp() < cutoff_time:
                                    continue

                                # Try to parse JSON message
                                try:
                                    event_data = json.loads(message)
                                    event_data["level"] = level
                                    event_data["log_timestamp"] = timestamp.isoformat()
                                    events.append(event_data)
                                except json.JSONDecodeError:
                                    # Not JSON, treat as plain message
                                    events.append(
                                        {
                                            "level": level,
                                            "message": message,
                                            "log_timestamp": timestamp.isoformat(),
                                        }
                                    )
                    except Exception:
                        continue  # Skip malformed lines

            # Analyze events
            analysis = {
                "total_events": len(events),
                "time_range_days": days,
                "event_types": {},
                "error_count": 0,
                "warning_count": 0,
                "operations": {"encrypt": 0, "decrypt": 0, "other": 0},
                "security_events": [],
            }

            for event in events:
                # Count event types
                event_type = event.get("event_type", "unknown")
                analysis["event_types"][event_type] = analysis["event_types"].get(event_type, 0) + 1

                # Count log levels
                level = event.get("level", "INFO")
                if level == "ERROR":
                    analysis["error_count"] += 1
                elif level == "WARNING":
                    analysis["warning_count"] += 1

                # Count operations
                details = event.get("details", {})
                operation = details.get("operation", "other")
                if "encrypt" in operation:
                    analysis["operations"]["encrypt"] += 1
                elif "decrypt" in operation:
                    analysis["operations"]["decrypt"] += 1
                else:
                    analysis["operations"]["other"] += 1

                # Collect security events
                if event_type == "security_event_detected":
                    analysis["security_events"].append(
                        {
                            "timestamp": event.get("log_timestamp"),
                            "events": details.get("security_events", []),
                        }
                    )

            return analysis

        except Exception as e:
            return {"error": f"Log analysis failed: {str(e)}"}

    def cleanup_old_logs(
        self, log_dir: Optional[str] = None, days_to_keep: int = 90
    ) -> Dict[str, Any]:
        """Clean up old audit logs."""
        try:
            if not log_dir:
                log_dir = Path.home() / ".openssl_encrypt_audit"
            else:
                log_dir = Path(log_dir)

            log_file = log_dir / "audit.log"
            if not log_file.exists():
                return {"error": "Audit log file not found"}

            # Read all log lines and filter by date
            cutoff_time = time.time() - (days_to_keep * 24 * 3600)
            kept_lines = []
            removed_count = 0

            with open(log_file, "r") as f:
                for line in f:
                    try:
                        if " | " in line:
                            timestamp_str = line.strip().split(" | ")[0]
                            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

                            if timestamp.timestamp() >= cutoff_time:
                                kept_lines.append(line)
                            else:
                                removed_count += 1
                        else:
                            kept_lines.append(line)  # Keep non-standard lines
                    except Exception:
                        kept_lines.append(line)  # Keep unparseable lines

            # Write back filtered logs
            with open(log_file, "w") as f:
                f.writelines(kept_lines)

            return {
                "removed_entries": removed_count,
                "kept_entries": len(kept_lines),
                "days_kept": days_to_keep,
                "cleanup_timestamp": time.time(),
            }

        except Exception as e:
            return {"error": f"Log cleanup failed: {str(e)}"}

    def export_audit_report(self, log_dir: Optional[str] = None, days: int = 30) -> Dict[str, Any]:
        """Export comprehensive audit report."""
        try:
            analysis = self.analyze_audit_logs(log_dir, days)
            if "error" in analysis:
                return analysis

            # Create comprehensive report
            report = {
                "report_generated": datetime.now().isoformat(),
                "analysis_period_days": days,
                "summary": {
                    "total_events": analysis["total_events"],
                    "errors": analysis["error_count"],
                    "warnings": analysis["warning_count"],
                    "security_events": len(analysis["security_events"]),
                },
                "operations": analysis["operations"],
                "event_breakdown": analysis["event_types"],
                "security_events": analysis["security_events"],
            }

            # Save report to file
            if not log_dir:
                log_dir = Path.home() / ".openssl_encrypt_audit"
            else:
                log_dir = Path(log_dir)

            report_file = log_dir / f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

            with open(report_file, "w") as f:
                json.dump(report, f, indent=2, default=str)

            # Set secure permissions
            os.chmod(report_file, 0o600)

            report["report_file"] = str(report_file)
            return report

        except Exception as e:
            return {"error": f"Report export failed: {str(e)}"}

    def get_audit_statistics(self, log_dir: Optional[str] = None) -> Dict[str, Any]:
        """Get basic audit log statistics."""
        try:
            if not log_dir:
                log_dir = Path.home() / ".openssl_encrypt_audit"
            else:
                log_dir = Path(log_dir)

            log_file = log_dir / "audit.log"
            if not log_file.exists():
                return {"error": "Audit log file not found"}

            # Get file statistics
            stat = log_file.stat()

            # Count lines
            with open(log_file, "r") as f:
                line_count = sum(1 for _ in f)

            return {
                "log_file": str(log_file),
                "file_size": stat.st_size,
                "line_count": line_count,
                "created": stat.st_ctime,
                "modified": stat.st_mtime,
                "accessible": os.access(log_file, os.R_OK),
                "statistics_timestamp": time.time(),
            }

        except Exception as e:
            return {"error": f"Statistics failed: {str(e)}"}
