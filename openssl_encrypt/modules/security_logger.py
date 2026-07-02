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
import math
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# A contiguous run of high-entropy token characters (hex / base64-ish), long
# enough to look like a key, token, or ciphertext rather than ordinary text.
# '/' , '.' and '-' are excluded so file paths and UUIDs are not false positives.
_SECRET_TOKEN_RE = re.compile(r"[A-Za-z0-9+_=]{32,}")

# Environment variables known to carry secrets; a logged value equal to one of
# these is redacted even if it is short/low-entropy (e.g. a plain password).
_SECRET_ENV_VARS = ("CRYPT_PASSWORD", "OPENSSL_ENCRYPT_PASSWORD")

_REDACTED = "***REDACTED***"


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _value_looks_secret(value: str) -> bool:
    """Whether a string value looks like a secret regardless of its field name."""
    for var in _SECRET_ENV_VARS:
        env_val = os.environ.get(var)
        if env_val and value == env_val:
            return True
    # A long token-charset run is only treated as secret if it is actually
    # high-entropy, so long low-entropy values (e.g. "x" * 500) are truncated,
    # not redacted.
    match = _SECRET_TOKEN_RE.search(value)
    return bool(match and _shannon_entropy(match.group()) >= 3.0)


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

    def __init__(
        self,
        log_dir: Optional[str] = None,
        enabled: bool = True,
        chain_enabled: Optional[bool] = None,
    ):
        """
        Initialize security audit logger.

        Args:
            log_dir: Directory for log files (default: ~/.openssl_encrypt/)
            enabled: Enable/disable logging (can be controlled via env var)
            chain_enabled: If True, append-only hash-chained mode is active and
                each event carries seq/prev_hash/mac fields. If None (default),
                read OPENSSL_ENCRYPT_AUDIT_CHAIN env var (=="1" enables).
        """
        # Only initialize once
        if hasattr(self, "_initialized"):
            return

        self._initialized = True
        self._write_lock = threading.Lock()
        self._chain_state = None
        self.chain_enabled = False
        self.seed_file: Optional[Path] = None
        self.state_file: Optional[Path] = None
        self.anchor_interval: int = 0
        self.anchor_pubkey_file: Optional[Path] = None
        self.anchor_privkey_file: Optional[Path] = None
        self._anchor_signer = None
        self._anchor_pubkey: Optional[bytes] = None
        self._anchor_privkey: Optional[bytes] = None

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

        # Chain mode: opt-in via env var or constructor arg.
        if chain_enabled is None:
            chain_enabled = os.getenv("OPENSSL_ENCRYPT_AUDIT_CHAIN") == "1"
        if chain_enabled:
            try:
                self._init_chain()
            except Exception as e:
                logger.error(f"Failed to initialize audit chain; disabling chain mode: {e}")
                self.chain_enabled = False

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

        # Redact by field NAME (blocklist) and, recursively, by VALUE shape so a
        # secret stored under a differently-named field is not logged verbatim
        # (#56). Keys are matched against sensitive_fields; string values are
        # redacted when they look like a secret, otherwise truncated if long.
        def _scrub(value):
            if isinstance(value, dict):
                return {
                    k: (
                        "***REDACTED***"
                        if any(s in str(k).lower() for s in sensitive_fields)
                        else _scrub(v)
                    )
                    for k, v in value.items()
                }
            if isinstance(value, (list, tuple)):
                return [_scrub(v) for v in value]
            if isinstance(value, str):
                if _value_looks_secret(value):
                    return _REDACTED
                if len(value) > 256:
                    return value[:256] + "...[truncated]"
            return value

        event["details"] = _scrub(details)

        # Write to log file
        self._write_to_log(event)

        # Send to syslog if enabled and severity is warning or critical
        if self.syslog_enabled and severity in [self.SEVERITY_WARNING, self.SEVERITY_CRITICAL]:
            self._send_to_syslog(event)

    def _write_to_log(self, event: dict) -> None:
        """Write event to log file (thread-safe).

        In chained mode the event is augmented with seq/prev_hash/mac via
        ChainState.append_record before serialization, and the chain state is
        persisted atomically after each successful append.
        """
        with self._write_lock:
            try:
                # Check if log rotation is needed
                self._rotate_log_if_needed()

                if self.chain_enabled and self._chain_state is not None:
                    event = self._chain_state.append_record(event)

                self._append_log_line(event)

                # Periodic Merkle anchor.
                if self.chain_enabled and self._chain_state is not None:
                    self._maybe_emit_anchor()

                if self.chain_enabled and self._chain_state is not None and self.state_file:
                    self._chain_state.save_atomic(self.state_file)
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

    def clear_logs(self, break_glass: bool = False) -> bool:
        """
        Clear all security audit logs.

        Args:
            break_glass: In chained mode, this MUST be set True to confirm
                that the operator accepts the loss of forensic continuity.
                The chain seed and state are also reset, and a fresh chain
                starts at seq=0 on the next event.

        Returns:
            True if successful, False otherwise.

        Raises:
            PermissionError: If chained mode is active and break_glass is False.

        Note:
            Use with caution - this removes forensic evidence!
        """
        if self.chain_enabled and not break_glass:
            raise PermissionError(
                "clear_logs() refused: chained audit mode is active. "
                "Pass break_glass=True to acknowledge that this destroys "
                "forensic continuity (chain seed and state will be wiped, "
                "and a fresh chain will start at seq=0)."
            )
        try:
            if self.log_file.exists():
                self.log_file.unlink()

            # Remove rotated logs
            for i in range(1, 6):
                rotated = self.log_dir / f"security-audit.log.{i}"
                if rotated.exists():
                    rotated.unlink()

            # If chained, reset seed/state/anchor keypair so next event
            # starts fresh.
            if self.chain_enabled:
                for path in (
                    self.state_file,
                    self.seed_file,
                    self.anchor_pubkey_file,
                    self.anchor_privkey_file,
                ):
                    if path is not None and path.exists():
                        path.unlink()
                self._chain_state = None
                self._anchor_signer = None
                self._anchor_pubkey = None
                self._anchor_privkey = None
                # Re-initialize so the next log_event resumes in chained mode.
                try:
                    self._init_chain()
                except Exception as e:
                    logger.error(f"Failed to re-init audit chain after clear: {e}")
                    self.chain_enabled = False

            logger.info("Security audit logs cleared")
            return True
        except Exception as e:
            logger.error(f"Failed to clear audit logs: {e}")
            return False

    # --- Chain mode helpers ---

    def _init_chain(self) -> None:
        """Set up chained mode: seed, state, anchor keypair, legacy migration.

        Idempotent: safe to call again after a break-glass clear.
        """
        from .audit_chain import ChainState

        # Seed file location (env override allowed for keystore/HSM follow-ups).
        env_seed = os.getenv("OPENSSL_ENCRYPT_AUDIT_SEED_FILE")
        self.seed_file = Path(env_seed) if env_seed else (self.log_dir / "audit-seed.bin")
        self.state_file = self.log_dir / "audit-state.json"
        self.anchor_pubkey_file = self.log_dir / "audit-anchor-pubkey.bin"
        self.anchor_privkey_file = self.log_dir / "audit-anchor-privkey.bin"

        # Anchor cadence: env-driven so operators can disable anchors
        # (interval=0) or tighten them. Default = 100 records.
        try:
            self.anchor_interval = int(os.getenv("OPENSSL_ENCRYPT_AUDIT_ANCHOR_INTERVAL", "100"))
        except ValueError:
            self.anchor_interval = 100
        if self.anchor_interval < 0:
            self.anchor_interval = 0

        seed = self._load_or_create_seed()
        self._archive_legacy_log_if_needed()

        if self.state_file.exists():
            self._chain_state = ChainState.load(self.state_file)
        else:
            self._chain_state = ChainState.initial(seed=seed)
            self._chain_state.save_atomic(self.state_file)

        if self.anchor_interval > 0:
            try:
                self._load_or_create_anchor_keypair()
            except Exception as e:
                logger.warning("Audit anchor keypair init failed; disabling anchors: %s", e)
                self.anchor_interval = 0

        self.chain_enabled = True
        logger.info(
            "Audit chain enabled: seed=%s state=%s seq=%d anchors=%s",
            self.seed_file,
            self.state_file,
            self._chain_state.current_seq,
            "every %d" % self.anchor_interval if self.anchor_interval else "disabled",
        )

    def _load_or_create_seed(self) -> bytes:
        """Read the seed file or create a fresh 32-byte seed with 0600 perms."""
        assert self.seed_file is not None  # set by _init_chain
        seed_path = self.seed_file
        if seed_path.exists():
            return seed_path.read_bytes()

        seed_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        seed = secrets.token_bytes(32)
        # O_EXCL guards against a TOCTOU race with another process.
        fd = os.open(str(seed_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, seed)
            os.fsync(fd)
        finally:
            os.close(fd)
        return seed

    def _read_seed(self) -> bytes:
        """Read the seed file. Used by the verifier and tests."""
        if self.seed_file is None or not self.seed_file.exists():
            raise FileNotFoundError("audit chain seed file not present")
        return self.seed_file.read_bytes()

    def _append_log_line(self, event: dict) -> None:
        """Write a single chained or unchained event line to the log file."""
        if not self.log_file.exists():
            from .file_permissions import PermissionLevel, create_secure_file

            fd = create_secure_file(self.log_file, PermissionLevel.OWNER_ONLY)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        else:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")

    def _load_or_create_anchor_keypair(self) -> None:
        """Load the ML-DSA-65 anchor keypair from disk, or generate fresh."""
        from .audit_anchor import AnchorSigner

        self._anchor_signer = AnchorSigner()
        assert self.anchor_pubkey_file is not None and self.anchor_privkey_file is not None

        if self.anchor_pubkey_file.exists() and self.anchor_privkey_file.exists():
            self._anchor_pubkey = self.anchor_pubkey_file.read_bytes()
            self._anchor_privkey = self.anchor_privkey_file.read_bytes()
            return

        pubkey, privkey = self._anchor_signer.generate_keypair()

        # Pubkey: world-readable (needed for verification by anyone holding
        # the log + log_dir). Privkey: owner-only.
        self.anchor_pubkey_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(self.anchor_pubkey_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        try:
            os.write(fd, pubkey)
            os.fsync(fd)
        finally:
            os.close(fd)

        fd = os.open(str(self.anchor_privkey_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, privkey)
            os.fsync(fd)
        finally:
            os.close(fd)

        self._anchor_pubkey = pubkey
        self._anchor_privkey = privkey

    def _maybe_emit_anchor(self) -> None:
        """If the pending leaves window is full, emit a signed anchor record.

        The anchor itself is appended via ChainState.append_record so it
        carries seq/prev_hash/mac like every other record. After emission
        the pending_leaves list contains only the anchor's own chain hash,
        which becomes the first leaf of the next window.
        """
        if self.anchor_interval <= 0 or self._chain_state is None or self._anchor_signer is None:
            return
        if len(self._chain_state.pending_leaves) < self.anchor_interval:
            return

        from .audit_anchor import build_anchor_payload

        leaves_snapshot = list(self._chain_state.pending_leaves)
        start = self._chain_state.current_seq - len(leaves_snapshot)
        end = self._chain_state.current_seq - 1

        payload = build_anchor_payload(
            anchor_seq_start=start,
            anchor_seq_end=end,
            leaves=leaves_snapshot,
            signer=self._anchor_signer,
            privkey=self._anchor_privkey,
            pubkey=self._anchor_pubkey,
        )

        # Reset BEFORE appending so the anchor's own hash starts the next
        # window and the verifier's leaf set matches the sealed snapshot.
        self._chain_state.pending_leaves = []
        self._chain_state.last_anchor_seq = self._chain_state.current_seq

        anchor_record = self._chain_state.append_record(payload)
        self._append_log_line(anchor_record)

    def _archive_legacy_log_if_needed(self) -> None:
        """If the existing log is unchained, rename it to .legacy and start fresh.

        We only treat the log as legacy when (a) it exists and is non-empty,
        (b) its first JSON line is decodable, and (c) that line lacks a 'seq'
        field. Malformed logs are left in place so a human can inspect.
        """
        if not self.log_file.exists():
            return
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                first_line = f.readline().strip()
        except OSError:
            return
        if not first_line:
            return
        try:
            first_event = json.loads(first_line)
        except json.JSONDecodeError:
            logger.warning("audit log %s has malformed first line; not archiving", self.log_file)
            return
        if isinstance(first_event, dict) and "seq" in first_event:
            return  # already chained

        legacy_path = self.log_dir / "security-audit.log.legacy"
        i = 0
        while legacy_path.exists():
            i += 1
            legacy_path = self.log_dir / f"security-audit.log.legacy.{i}"
        self.log_file.rename(legacy_path)
        logger.info("Archived legacy unchained audit log to %s", legacy_path)


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
