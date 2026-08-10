#!/usr/bin/env python3
"""Secure File Encryption Tool - Command Line Interface.

This module provides the command-line interface for the encryption tool,
handling user input, parsing arguments, and calling the appropriate
functionality from the core and utils modules.
"""

import argparse
import atexit
import base64
import getpass
import hashlib
import json
import logging
import os
import secrets
import signal
import sys
import time
import uuid
from enum import Enum
from typing import Any, Dict, Optional

import yaml

from .algorithm_warnings import (
    AlgorithmWarningConfig,
    get_encryption_block_message,
    get_recommended_replacement,
    is_deprecated,
    is_encryption_blocked_for_algorithm,
    warn_deprecated_algorithm,
)

# Import from local modules
from .crypt_core import (
    ARGON2_AVAILABLE,
    ARGON2_TYPE_INT_MAP,
    LATEST_STABLE_FORMAT_VERSION,
    WHIRLPOOL_AVAILABLE,
    EncryptionAlgorithm,
    check_argon2_support,
    decrypt_file,
    encrypt_file,
    extract_file_metadata,
    get_file_permissions,
)
from .crypt_errors import set_debug_mode
from .crypt_utils import (
    display_password_with_timeout,
    eprint,
    expand_glob_patterns,
    generate_strong_password,
    prompt_and_read,
    request_confirmation,
    sanitize_for_display,
    secure_shred_file,
    show_security_recommendations,
    tty_clear_line,
)
from .debug_redaction import debug_secret, set_show_secrets, show_secrets_enabled

# Try to import the CLI helper module
try:
    from .crypt_cli_helper import add_extended_algorithm_help, enhance_cli_args
except ImportError:
    # Dummy implementations if the helper is not available
    def enhance_cli_args(args):
        """Stub implementation that returns args unchanged."""
        return args

    def add_extended_algorithm_help(parser):
        """Stub implementation that does nothing."""
        pass


from . import crypt_errors
from .cli_aliases import add_cli_aliases, process_cli_aliases
from .config_analyzer import ConfigurationAnalyzer
from .config_wizard import generate_cli_arguments, run_configuration_wizard
from .credential_env import CredentialError, consume_env, resolve_credential
from .credential_env import validated as credential_validated
from .keystore_utils import auto_generate_pqc_key

# Import keystore-related modules
from .keystore_wrapper import decrypt_file_with_keystore, encrypt_file_with_keystore
from .password_policy import PasswordPolicy, get_password_strength
from .security_logger import register_consumed_secret
from .security_scorer import SecurityScorer

# Import security audit logger
try:
    from .security_logger import get_security_logger

    security_logger = get_security_logger()
except ImportError:
    security_logger = None
from .template_manager import TemplateCategory, TemplateFormat, TemplateManager

# Set up module-level logger
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# .pqc keyfile private-key wrapping KDF (gitlab#131 / F16)
#
# A --pqc-keyfile stores a long-lived PQC private key wrapped under a
# password-derived AES-256-GCM key. New keyfiles derive that key with Argon2id
# and record a self-describing "key_kdf" descriptor. Keyfiles written before
# this fix carry no "key_kdf" and used PBKDF2-HMAC-SHA256 100k (below the OWASP
# floor) plus a redundant trailing SHA-256; they still decrypt via the legacy
# branch below, so the change is backward compatible.
# ---------------------------------------------------------------------------
_PQC_KEYFILE_ARGON2_TIME_COST = 3
_PQC_KEYFILE_ARGON2_MEMORY_KIB = 65536  # 64 MiB
_PQC_KEYFILE_ARGON2_PARALLELISM = 4
# Upper bounds for Argon2 cost read from an (untrusted) keyfile: a tampered
# keyfile could otherwise declare a huge memory_cost and OOM the host on decrypt
# before the AES-GCM tag authenticates (same class as gitlab#128/#129). Mirrors
# identity_protection._validate_identity_argon2_params.
_PQC_KEYFILE_ARGON2_MAX_TIME = 64
_PQC_KEYFILE_ARGON2_MAX_MEMORY = 2 * 1024 * 1024  # KiB (2 GiB)
_PQC_KEYFILE_ARGON2_MAX_PARALLELISM = 16


def _new_pqc_keyfile_kdf() -> Dict[str, Any]:
    """Return the KDF descriptor stored in a freshly written .pqc keyfile."""
    return {
        "type": "argon2id",
        "time_cost": _PQC_KEYFILE_ARGON2_TIME_COST,
        "memory_cost": _PQC_KEYFILE_ARGON2_MEMORY_KIB,
        "parallelism": _PQC_KEYFILE_ARGON2_PARALLELISM,
    }


def _derive_pqc_keyfile_key(
    keyfile_password: bytes, key_salt: bytes, kdf: Optional[Dict[str, Any]]
) -> bytes:
    """Derive the 32-byte AES-256-GCM key that wraps a .pqc keyfile private key.

    Args:
        keyfile_password: The keyfile password.
        key_salt: The per-keyfile random salt.
        kdf: The keyfile's ``key_kdf`` descriptor, or ``None`` for a legacy
            keyfile written before gitlab#131 (PBKDF2-SHA256 100k + a redundant
            trailing SHA-256).

    Returns:
        A 32-byte wrapping key.

    Raises:
        ValueError: On an unsupported or out-of-range KDF descriptor.
    """
    if kdf is None:
        # Legacy keyfiles (pre-gitlab#131 F16): PBKDF2-SHA256 100k, then a
        # redundant SHA-256 kept only so existing keyfiles still decrypt.
        return hashlib.sha256(
            hashlib.pbkdf2_hmac("sha256", keyfile_password, key_salt, 100000)
        ).digest()

    ktype = kdf.get("type") if isinstance(kdf, dict) else None
    if ktype != "argon2id":
        raise ValueError(f"Unsupported .pqc keyfile KDF type: {ktype!r}")

    time_cost = kdf.get("time_cost")
    memory_cost = kdf.get("memory_cost")
    parallelism = kdf.get("parallelism")
    for name, value, lo, hi in (
        ("time_cost", time_cost, 1, _PQC_KEYFILE_ARGON2_MAX_TIME),
        ("memory_cost", memory_cost, 8, _PQC_KEYFILE_ARGON2_MAX_MEMORY),
        ("parallelism", parallelism, 1, _PQC_KEYFILE_ARGON2_MAX_PARALLELISM),
    ):
        # bool is an int subclass; reject it and any non-int explicitly.
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"Invalid .pqc keyfile Argon2 {name}: {value!r}")
        if not (lo <= value <= hi):
            raise ValueError(
                f".pqc keyfile Argon2 {name} out of allowed range [{lo}, {hi}]: {value}"
            )

    from argon2.low_level import Type, hash_secret_raw

    return hash_secret_raw(
        secret=keyfile_password,
        salt=key_salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=Type.ID,
    )


def resolve_identity_store_path(args):
    """Resolve identity store path from args with proper priority.

    Priority (lowest to highest):
    1. Default (handled by get_identity_store)
    2. Environment variable (handled by get_identity_store)
    3. Global --identity-store parameter
    4. Command-specific --identity-store parameter

    Args:
        args: Parsed command-line arguments

    Returns:
        Path or None: Resolved path if explicitly provided, None to use default resolution
    """
    from pathlib import Path

    # Command-specific overrides global
    path = getattr(args, "identity_store", None)
    if path:
        return Path(path).expanduser()
    return None


def detect_encryption_type(input_file: str) -> dict:
    """
    Read file and detect encryption type from metadata.

    Args:
        input_file: Path to encrypted file

    Returns:
        Dictionary with:
            - type: "symmetric" or "asymmetric"
            - format_version: int (format version number)
            - recipient_fingerprints: List[str] (only for asymmetric)
            - sender_fingerprint: str (only for asymmetric)

    Returns {"type": "symmetric", "format_version": 0} if detection fails.
    """
    import base64
    import json

    try:
        with open(input_file, "rb") as f:
            content = f.read()

        metadata = None

        # Try new format: base64(metadata):base64(data)
        if b":" in content:
            colon_pos = content.index(b":")
            metadata_b64 = content[:colon_pos]
            try:
                metadata_json = base64.b64decode(metadata_b64)
                metadata = json.loads(metadata_json)
            except (ValueError, json.JSONDecodeError):
                pass

        # Try old format: ---ENCRYPTED_DATA---
        if metadata is None and b"---ENCRYPTED_DATA---" in content:
            try:
                content_str = content.decode("utf-8", errors="ignore")
                metadata_str = content_str.split("---ENCRYPTED_DATA---")[0]
                metadata = json.loads(metadata_str)
            except (json.JSONDecodeError, UnicodeDecodeError, IndexError):
                pass

        # Check if asymmetric
        if metadata:
            format_version = metadata.get("format_version", 0)
            mode = metadata.get("mode", "symmetric")

            if format_version == 7 and mode == "asymmetric":
                # Extract recipient and sender info
                asymmetric_data = metadata.get("asymmetric", {})
                recipients = asymmetric_data.get("recipients", [])
                sender = asymmetric_data.get("sender", {})

                recipient_fingerprints = [r.get("key_id", "") for r in recipients]
                sender_fingerprint = sender.get("key_id", "")

                return {
                    "type": "asymmetric",
                    "format_version": format_version,
                    "recipient_fingerprints": recipient_fingerprints,
                    "sender_fingerprint": sender_fingerprint,
                }

        # Default to symmetric
        return {"type": "symmetric", "format_version": 0}

    except Exception:
        # If we can't read the file, assume symmetric
        return {"type": "symmetric", "format_version": 0}


class ReconstructedStdinStream:
    """
    A file-like object that replays consumed data followed by remaining stdin stream.

    This allows us to read metadata from stdin and then provide the complete
    stream to the decryption function as if nothing was consumed.
    """

    def __init__(self, consumed_data, separator, original_stream):
        """
        Initialize with consumed metadata, separator, and original stream.

        Args:
            consumed_data (bytes): The metadata bytes that were already read
            separator (bytes): The ':' separator byte
            original_stream: The original stdin stream
        """
        self.prefix_data = consumed_data + separator  # Reconstruct: metadata + ':'
        self.original_stream = original_stream
        self.prefix_pos = 0

    def read(self, size=-1):
        """Read from prefix data first, then from original stream."""
        if self.prefix_pos < len(self.prefix_data):
            # Still have prefix data to return
            if size == -1:
                # Read all remaining prefix data
                result = self.prefix_data[self.prefix_pos :]
                self.prefix_pos = len(self.prefix_data)

                # Also read all from original stream
                remaining = self.original_stream.read()
                return result + remaining
            else:
                # Read up to 'size' bytes from prefix
                available = len(self.prefix_data) - self.prefix_pos
                if size <= available:
                    # Can satisfy entirely from prefix
                    result = self.prefix_data[self.prefix_pos : self.prefix_pos + size]
                    self.prefix_pos += size
                    return result
                else:
                    # Need to read from both prefix and stream
                    prefix_part = self.prefix_data[self.prefix_pos :]
                    self.prefix_pos = len(self.prefix_data)

                    remaining_needed = size - len(prefix_part)
                    stream_part = self.original_stream.read(remaining_needed)
                    return prefix_part + stream_part
        else:
            # Prefix exhausted, read from original stream
            return self.original_stream.read(size)

    def __enter__(self):
        """Enter the context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the context manager without closing the original stream."""
        # Don't close the original stream as it might be sys.stdin
        pass


class StdinMetadataExtractor:
    """
    Extracts metadata from stdin without consuming the entire stream.

    Reads byte-by-byte until the ':' separator is found, then parses
    only the metadata portion and creates a reconstructed stream.
    """

    def __init__(self, stdin_stream):
        """Initialize with stdin stream."""
        self.stdin_stream = stdin_stream

    def extract_metadata_and_create_stream(self):
        """
        Extract metadata from stdin and create a reconstructed stream.

        Returns:
            tuple: (metadata_dict, reconstructed_stream)
                metadata_dict: Parsed metadata with algorithm info
                reconstructed_stream: Stream that replays full encrypted data

        Raises:
            ValueError: If metadata format is invalid
        """
        # Read metadata bytes until separator
        metadata_bytes = self._read_until_separator()

        # Parse metadata
        metadata = self._parse_metadata(metadata_bytes)

        # Create reconstructed stream
        reconstructed_stream = ReconstructedStdinStream(metadata_bytes, b":", self.stdin_stream)

        return metadata, reconstructed_stream

    def _read_until_separator(self):
        """Read stdin byte-by-byte until ':' separator is found."""
        metadata_bytes = bytearray()

        while True:
            byte = self.stdin_stream.read(1)
            if not byte:  # EOF
                raise ValueError("Invalid encrypted file format: no separator found")
            if byte == b":":
                break
            metadata_bytes.extend(byte)

        return bytes(metadata_bytes)

    def _parse_metadata(self, metadata_b64):
        """Parse base64 metadata and extract algorithm information."""
        try:
            # Decode base64 metadata
            metadata_json = base64.b64decode(metadata_b64).decode("utf-8")
            # MED-8 Security fix: Use secure JSON validation for metadata parsing.
            #
            # The import is resolved BEFORE the try that uses it (gitlab#118).
            # It used to sit inside that try, with `except (JSONSecurityError,
            # JSONValidationError)` as the first handler -- and evaluating
            # that tuple needs names the failed import never bound, so it
            # raised UnboundLocalError before `except ImportError` was ever
            # considered. The fallback was unreachable.
            try:
                from .json_validator import (
                    JSONSecurityError,
                    JSONValidationError,
                    secure_metadata_loads,
                )
            except ImportError:
                secure_metadata_loads = None
                # Empty tuples never match, so the handler below is inert on
                # this path rather than referencing unbound names.
                JSONSecurityError = JSONValidationError = ()

            if secure_metadata_loads is not None:
                try:
                    metadata = secure_metadata_loads(metadata_json)
                except (JSONSecurityError, JSONValidationError) as e:
                    eprint(f"Error: Invalid metadata JSON: {e}")
                    return None
            else:
                # Fallback: basic JSON loading, with the bounds the validator
                # would otherwise have applied.
                try:
                    metadata = json.loads(metadata_json)
                except json.JSONDecodeError as e:
                    eprint(f"Error: Invalid JSON in metadata: {e}")
                    return None
                if not isinstance(metadata, dict):
                    eprint("Error: Invalid metadata JSON: not an object")
                    return None

            # Extract algorithm info based on format version.
            #
            # Bounded rather than taken as-is: a crafted file must not decide
            # this field's type. bool is an int subclass and `True >= 4` would
            # silently select the legacy branch, so it is rejected explicitly
            # -- the same guard crypt_core.py's equivalent site already has
            # (gitlab#118).
            format_version = metadata.get("format_version", 1)
            if isinstance(format_version, bool) or not isinstance(format_version, int):
                eprint(f"Error: Invalid metadata format version: {format_version!r}")
                return None
            if not (1 <= format_version <= LATEST_STABLE_FORMAT_VERSION):
                eprint(f"Error: Unsupported metadata format version: {format_version}")
                return None

            if format_version >= 4:  # v4+ hierarchical metadata (see crypt_core gate fix)
                encryption = metadata.get("encryption", {})
                algorithm = encryption.get("algorithm", "fernet")
                encryption_data = encryption.get("encryption_data", "aes-gcm")
            else:
                algorithm = metadata.get("algorithm", "fernet")
                encryption_data = "aes-gcm"  # Default for older formats

            return {
                "format_version": format_version,
                "algorithm": algorithm,
                "encryption_data": encryption_data,
                "metadata": metadata,
            }

        except Exception as e:
            raise ValueError(f"Invalid metadata format: {str(e)}")


def clear_password_environment():
    """Securely clear password from environment variables with multiple overwrites."""
    try:
        if "CRYPT_PASSWORD" in os.environ:
            # Register the fingerprint before the overwrites destroy the value,
            # so a later log_event still redacts it once the variable is gone
            # (gitlab#147).
            register_consumed_secret("CRYPT_PASSWORD", os.environ["CRYPT_PASSWORD"])
            # Get the original length to overwrite with same size
            original_length = len(os.environ["CRYPT_PASSWORD"])

            # Overwrite with random data multiple times (like secure_memory does)
            import secrets

            for _ in range(3):
                # Overwrite with random bytes of same length
                random_data = "".join(
                    secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
                    for _ in range(original_length)
                )
                os.environ["CRYPT_PASSWORD"] = random_data

            # Overwrite with zeros
            os.environ["CRYPT_PASSWORD"] = "0" * original_length

            # Overwrite with different pattern
            os.environ["CRYPT_PASSWORD"] = "X" * original_length

            # Finally delete the environment variable
            del os.environ["CRYPT_PASSWORD"]

    except Exception:
        pass  # Best effort cleanup


def debug_hash_config(args, hash_config, message="Hash configuration"):
    """Debug output for hash configuration."""
    logger.debug(f"\n{message}:")
    logger.debug(
        f"SHA3-512: args={args.sha3_512_rounds}, hash_config={hash_config.get('sha3_512', 'Not set')}"
    )
    logger.debug(
        f"SHA3-256: args={args.sha3_256_rounds}, hash_config={hash_config.get('sha3_256', 'Not set')}"
    )
    logger.debug(
        f"SHA-512: args={args.sha512_rounds}, hash_config={hash_config.get('sha512', 'Not set')}"
    )
    logger.debug(
        f"SHA-256: args={args.sha256_rounds}, hash_config={hash_config.get('sha256', 'Not set')}"
    )
    logger.debug(
        f"BLAKE2b: args={args.blake2b_rounds}, hash_config={hash_config.get('blake2b', 'Not set')}"
    )
    logger.debug(
        f"BLAKE3: args={args.blake3_rounds}, hash_config={hash_config.get('blake3', 'Not set')}"
    )
    logger.debug(
        f"SHAKE-256: args={args.shake256_rounds}, hash_config={hash_config.get('shake256', 'Not set')}"
    )
    logger.debug(
        f"PBKDF2: args={args.pbkdf2_iterations}, hash_config={hash_config.get('pbkdf2_iterations', 'Not set')}"
    )
    logger.debug(
        f"Scrypt: args.n={args.scrypt_n}, hash_config.n={hash_config.get('scrypt', {}).get('n', 'Not set')}"
    )
    logger.debug(
        f"Argon2: args.enable_argon2={args.enable_argon2}, hash_config.enabled={hash_config.get('argon2', {}).get('enabled', 'Not set')}"
    )


class SecurityTemplate(Enum):
    """Security template presets for encryption configuration."""

    STANDARD = "standard"
    PARANOID = "paranoid"
    QUICK = "quick"


def show_version_info():
    """Display version information including git commit hash, Python version and dependencies."""
    import platform
    import sys
    from importlib.metadata import version as pkg_version

    # Import version information from version.py
    try:
        from openssl_encrypt.version import __git_commit__, __version__
    except ImportError:
        __version__ = "unknown"
        __git_commit__ = "unknown"

    # Get Python version
    python_version = sys.version.split()[0]
    python_implementation = platform.python_implementation()

    # Get system information
    system = platform.system()
    release = platform.release()

    # Get dependency versions
    dependencies = {
        "cryptography": "unknown",
        "argon2-cffi": "unknown",
        "PyYAML": "unknown",
    }

    # Try to get actual versions of dependencies
    for dep in dependencies:
        try:
            dependencies[dep] = pkg_version(dep)
        except Exception:
            pass

    # Format the output
    version_info = [
        f"openssl_encrypt: v{__version__} (commit: {__git_commit__})",
        f"Python: {python_implementation} {python_version}",
        f"System: {system} {release}",
        "\nDependencies:",
    ]

    for dep, ver in dependencies.items():
        version_info.append(f"  {dep}: {ver}")

    return "\n".join(version_info)


def load_template_file(template_name: str) -> Optional[Dict[str, Any]]:
    """
    Load a template file from the ./template directory.
    Supports JSON and YAML formats.

    Args:
        template_name: Name of the template file (without extension)

    Returns:
        Template configuration dict or None if template not found
    """
    # Security: Validate template name to prevent path traversal attacks
    if not template_name or not isinstance(template_name, str):
        eprint("Error: Invalid template name provided")
        sys.exit(1)

    # Remove any path separators and parent directory references
    safe_template_name = os.path.basename(template_name)

    # Additional check for path traversal attempts
    if (
        ".." in template_name
        or os.sep in template_name
        or "/" in template_name
        or "\\" in template_name
    ):
        eprint(
            f"Error: Invalid template name '{template_name}'. Template names cannot contain path separators or parent directory references."
        )
        sys.exit(1)

    # Ensure the cleaned name is not empty
    if not safe_template_name:
        eprint("Error: Empty template name after security validation")
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Move up one level from the modules directory to the project root
    project_root = os.path.dirname(script_dir)

    # Templates are in project root
    template_dir = os.path.join(project_root, "templates")

    # SECURITY: this is the path `encrypt --template` uses, and it never
    # constructs a TemplateManager -- so harden the template directory HERE too,
    # not only in TemplateManager.__init__. A group/other-writable dir lets
    # another local user plant a template this path would then apply (gitlab#169).
    from .file_permissions import harden_directory_permissions

    harden_directory_permissions(template_dir)

    # Try different extensions
    for ext in [".json", ".yaml", ".yml"]:
        template_path = os.path.join(template_dir, safe_template_name + ext)

        # Additional security check: ensure the resolved path is still within template_dir
        resolved_template_path = os.path.abspath(template_path)
        resolved_template_dir = os.path.abspath(template_dir)

        # Use os.path.commonpath for robust path traversal prevention
        try:
            common_path = os.path.commonpath([resolved_template_path, resolved_template_dir])
            if common_path != resolved_template_dir:
                eprint(
                    f"Error: Security violation - template path '{template_path}' is outside allowed directory"
                )
                sys.exit(1)
        except ValueError:
            # Different drives/roots on Windows - definitely not under template_dir
            eprint(
                f"Error: Security violation - template path '{template_path}' is outside allowed directory"
            )
            sys.exit(1)

        if os.path.exists(template_path):
            try:
                with open(template_path, "r") as f:
                    if ext == ".json":
                        # MED-8 Security fix: Use secure JSON validation for template loading
                        json_content = f.read()
                        try:
                            from .json_validator import (
                                JSONSecurityError,
                                JSONValidationError,
                                secure_template_loads,
                            )

                            return secure_template_loads(json_content)
                        except (JSONSecurityError, JSONValidationError) as e:
                            eprint(f"Error: Invalid template JSON in {template_path}: {e}")
                            sys.exit(1)
                        except ImportError:
                            # Fallback to basic JSON loading if validator not available
                            try:
                                return json.loads(json_content)
                            except json.JSONDecodeError as e:
                                eprint(f"Error: Invalid JSON in template {template_path}: {e}")
                                sys.exit(1)
                    else:
                        return yaml.safe_load(f)
            except Exception as e:
                eprint(f"Error loading template {template_path}: {e}")
                sys.exit(1)

    eprint(f"Template {safe_template_name} not found in {template_dir}")
    sys.exit(1)


def _warn_if_weak_template_kdf(hash_config, source) -> None:
    """Warn (loudly; does NOT block) when a template's applied KDF parameters
    fall below a safe floor.

    A template file dropped into the template directory could otherwise silently
    downgrade key derivation -- e.g. ``pbkdf2_iterations: 1`` with Argon2
    disabled -- delivered through the template interface (gitlab#169). This is
    advisory: the encryption still runs (the user asked for this template), but
    the weakness is surfaced instead of hidden. Only file templates pass through
    here; the built-in --quick/--standard/--paranoid presets do not.
    """
    if not isinstance(hash_config, dict):
        return

    def _num(value):
        return value if isinstance(value, (int, float)) and not isinstance(value, bool) else 0

    def _kdf(name):
        entry = hash_config.get(name)
        return entry if isinstance(entry, dict) else {}

    argon2, scrypt, balloon = _kdf("argon2"), _kdf("scrypt"), _kdf("balloon")
    pbkdf2 = _num(hash_config.get("pbkdf2_iterations"))

    # A memory-hard KDF at reasonable strength is the real protection; if one is
    # present, the config is not "weak" regardless of pbkdf2. Each is gated on a
    # strength floor, not merely "enabled" -- otherwise a planted
    # balloon:{enabled:true, space_cost:1} (or similar) would evade the check.
    strong_memory_hard = (
        (argon2.get("enabled") and _num(argon2.get("memory_cost")) >= 65536)
        or (scrypt.get("enabled") and _num(scrypt.get("n")) >= 16384)
        or (balloon.get("enabled") and _num(balloon.get("space_cost")) >= 65536)
    )
    if strong_memory_hard:
        return
    # No strong memory-hard KDF -> PBKDF2 is the fallback and must clear a
    # minimal iteration floor (600,000, current OWASP PBKDF2-HMAC-SHA256
    # guidance).
    if pbkdf2 >= 600000:
        return

    eprint(
        f"⚠️  SECURITY WARNING: template '{source}' configures weak key "
        "derivation -- no memory-hard KDF (Argon2/scrypt/Balloon) at strength "
        f"and pbkdf2_iterations={pbkdf2} (below the 600,000 minimum, current "
        "OWASP guidance). This is far easier to brute-force. Encryption will "
        "proceed; consider a stronger template (e.g. --standard or --paranoid)."
    )


def get_template_config(template: str or SecurityTemplate) -> Dict[str, Any]:
    """
    Returns predefined hash configurations matching your metadata structure.
    """
    templates = {
        SecurityTemplate.QUICK: {
            "hash_config": {
                "sha512": 0,
                "sha256": 1000,
                "sha3_256": 0,
                "sha3_512": 10000,
                "blake2b": 0,
                "shake256": 0,
                "whirlpool": 0,
                "scrypt": {"enabled": False, "n": 128, "r": 8, "p": 1, "rounds": 1000},
                "argon2": {
                    "enabled": False,
                    "time_cost": 2,
                    "memory_cost": 65536,  # 64MB
                    "parallelism": 4,
                    "hash_len": 32,
                    "type": 2,
                    "rounds": 10,
                },
                "pbkdf2_iterations": 10000,
                "type": "id",
                "algorithm": "fernet",
            }
        },
        SecurityTemplate.STANDARD: {
            "hash_config": {
                "sha512": 0,
                "sha256": 0,
                "sha3_256": 0,
                "sha3_512": 10000,
                "blake2b": 0,
                "blake3": 10000,
                "shake256": 0,
                "whirlpool": 0,
                "scrypt": {"enabled": False},
                "argon2": {
                    "enabled": True,
                    "time_cost": 3,
                    "memory_cost": 65536,
                    "parallelism": 4,
                    "hash_len": 32,
                    "type": 2,
                    "rounds": 10,
                },
                "randomx": {
                    "enabled": True,
                    "rounds": 10,
                    "mode": "light",
                    "height": 1,
                    "hash_len": 32,
                },
                "pbkdf2_iterations": 0,
                "type": "id",
                "algorithm": "aes-gcm-siv",
            },
            "cascade": "standard",
        },
        SecurityTemplate.PARANOID: {
            "hash_config": {
                "sha512": 10000,
                "sha256": 10000,
                "sha3_256": 10000,
                "sha3_512": 800000,
                "blake2b": 800000,
                "shake256": 400000,
                "scrypt": {"enabled": True, "n": 256, "r": 16, "p": 2, "rounds": 100},
                "argon2": {
                    "enabled": True,
                    "time_cost": 4,
                    "memory_cost": 131072,  # 128MB
                    "parallelism": 8,
                    "hash_len": 64,
                    "type": 2,
                    "rounds": 200,
                },
                "balloon": {
                    "enabled": True,
                    "time_cost": 3,
                    "space_cost": 65536,
                    "parallelism": 4,
                    "hash_len": 64,
                    "rounds": 5,
                },
                "pbkdf2_iterations": 0,
                "type": "id",
                "algorithm": "xchacha20-poly1305",
            }
        },
    }

    # If template is a SecurityTemplate enum, use built-in template
    if isinstance(template, SecurityTemplate):
        return templates[template]

    # Otherwise, load template from file
    if isinstance(template, str):
        try:
            custom_template = load_template_file(template)
            if custom_template:
                # Validate template structure
                if "hash_config" in custom_template:
                    # A template file is untrusted (any local process could drop
                    # one in); surface a KDF downgrade instead of applying it
                    # silently (gitlab#169).
                    _warn_if_weak_template_kdf(custom_template["hash_config"], template)
                    return custom_template
                else:
                    eprint("Invalid template format: missing 'hash_config' key")
                    sys.exit(1)
        except Exception as e:
            eprint(f"Error loading template file: {e}")
            sys.exit(1)


# Environment channel for the keyed-hidden-mode second password (gitlab#154).
# Read once and deleted; see modules/credential_env.py for the rationale.
SECOND_PASSWORD_ENV = "OPENSSL_ENCRYPT_SECOND_PASSWORD"

# Subcommands whose credential arrives as a POSITIONAL argument, which
# SECRET_VALUE_CLI_OPTIONS cannot match because it keys on option names.
SECRET_POSITIONAL_SUBCOMMANDS = frozenset({"set-token", "login"})

# Value-taking CLI options whose VALUE is a secret. Their values must never
# appear in the --debug argv dump; they are routed through the debug_secret()
# redaction chokepoint instead. Keep in sync with the parsers in this module
# and crypt_cli_subparser.py. File-path/fd options (--password-file,
# --password-fd, --recovery-share, --random-password-out, ...) are not secrets
# themselves.
SECRET_VALUE_CLI_OPTIONS = frozenset(
    {
        "-p",
        "--password",
        "--second-password",
        "--keystore-password",
        "--manifest-password",
        "--rekey-password",
        "--recovery-code",
        "--encryption-data",
        # The one-time TOTP code for `plugin pepper verify-totp` — ephemeral,
        # but an auth credential that must not appear in a --debug argv dump.
        "--code",
        # Steganographic security password (gitlab#215 item 5): a real
        # secret, distinct from the encryption password.
        "--stego-password",
    }
)


def _write_generated_password_file(path, password):
    """Write a `--random` generated password to a file only its owner can read.

    The generated password is the only thing standing between an attacker and
    the file's plaintext, so it must not travel on a general-purpose stream.
    stderr -- where it used to be printed -- is collapsed into stdout by
    `2>&1`, lands in terminal scrollback, in `script(1)` transcripts, in CI job
    logs and in the desktop GUI's persistent debug log. Writing it ourselves is
    the only way the tool controls the permissions (gitlab#152).

    Args:
        path: Destination, created 0600 and refused if it already exists.
        password: The generated password.

    Raises:
        ValueError: If the destination already exists.
        OSError: If the file cannot be created or written.
    """
    from .file_permissions import PermissionLevel, create_secure_file

    # Same hardened primitive as the recovery-code writer (gitlab#146): it adds
    # O_NOFOLLOW and O_EXCL, so a pre-planted symlink, FIFO or device is
    # refused outright, rejects non-regular and foreign-owned targets, and pins
    # the mode with an unconditional fchmod rather than trusting open()'s mode
    # (which is ignored for an existing file, and which a restrictive umask
    # would otherwise subtract from).
    fd = create_secure_file(path, PermissionLevel.OWNER_ONLY, exclusive=True)
    try:
        os.write(fd, (password + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)

    # fsync the directory too: the whole point of writing the credential before
    # the ciphertext is that it survives a crash the ciphertext also survives,
    # and an unsynced directory entry can vanish while the encrypted file stays.
    #
    # Best-effort by design. Windows cannot open a directory handle this way,
    # and a write-only destination directory refuses it on POSIX; failing here
    # would abort a correct operation *after* the O_EXCL file already exists,
    # so the obvious retry would then die with FileExistsError.
    try:
        dir_fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:  # pragma: no cover - platform/filesystem dependent
        pass
    finally:
        os.close(dir_fd)


def _warn_orphan_random_password(args, ciphertext_maybe_written=True):
    """Warn that a `--random-password-out` file was written and left in place.

    The generated password is written before the ciphertext, so a later failure
    can leave a 0600 orphan on disk. Deleting it automatically would be wrong
    when a matching encrypted file might exist (the file is then its only
    credential), but an unannounced orphan is its own hazard: the obvious retry
    dies with FileExistsError, and a stale file beside a later run looks like a
    live credential.

    Coverage is structural (gitlab#223): the encrypt dispatch is wrapped in a
    try/finally that calls this on every incomplete exit -- including the
    `return 1` / `sys.exit(1)` sites (steganography failure, cascade-diversity
    abort, XOR mutual-exclusivity, keystore-branch failures) that the
    `except Exception` handler cannot see (gitlab#182, gitlab#152, mirroring
    gitlab#146). The finally passes ciphertext_maybe_written from the
    _ciphertext_on_disk flag, so a post-processing failure after the output
    was written (armor rewrite, shred) gets the verify-first wording. The
    only direct call sites besides the finally are the password-write-failure
    handler (fires before the dispatch try) and the signal handler (a signal
    death runs neither the finally nor atexit).

    Args:
        args: Parsed CLI arguments.
        ciphertext_maybe_written: True at the top-level handler, where the
            failure could have struck after the encrypted file was written, so
            the file may be a live credential and the user is told to check
            decryptability before removing it. False at the sites that provably
            fail before any usable encrypted file exists (a pre-encryption abort,
            or the password write itself failing part-way) -- there the orphan
            can simply be removed, and claiming otherwise would tell the user to
            test a file that cannot exist.
    """
    orphan = getattr(args, "random_password_out", None)
    if not (orphan and os.path.exists(orphan)):
        return
    # gitlab#172 discipline: the path is caller-supplied text echoed to the
    # terminal -- strip ANSI/bidi controls like every other untrusted echo.
    orphan = sanitize_for_display(orphan)
    if ciphertext_maybe_written:
        eprint(
            f"\nNOTE: a generated password was already written to {orphan}. "
            f"It is NOT deleted, because this failure does not prove the "
            f"encrypted file was not written. Check whether the output file "
            f"exists and is decryptable with it before removing it; until you "
            f"do, a retry with the same --random-password-out will refuse to "
            f"overwrite it."
        )
    else:
        eprint(
            f"\nNOTE: a password file may remain at {orphan} (the encryption "
            f"did not complete, so no usable encrypted file was written). You "
            f"can remove it; until you do, a retry with the same "
            f"--random-password-out will refuse to overwrite it."
        )


def _effective_encrypt_output(args):
    """The path the encrypt run will actually write its ciphertext to.

    `args.output` is not normalized anywhere, so reading it alone misses the
    two derived cases: `--overwrite` writes back over the input, and an
    omitted `--output` appends ".encrypted". A collision check that consulted
    only `args.output` would therefore pass for
    `encrypt -i f --random-password-out f.encrypted` and let the ciphertext
    truncate the password file (gitlab#152).

    Args:
        args: Parsed CLI arguments.

    Returns:
        The output path, or None when it cannot be determined (stdin input
        with no explicit output, which goes to stdout).
    """
    if getattr(args, "overwrite", False):
        return args.input
    if getattr(args, "output", None):
        return args.output
    if args.input == "/dev/stdin":
        return None
    return args.input + ".encrypted"


def _check_random_password_destination(out_path, input_path, output_path):
    """Refuse a destination that the run would then destroy.

    A destination equal to the output would be truncated by the ciphertext
    write moments later, destroying the password and reporting success -- the
    file would be sealed under a value that no longer exists anywhere. O_EXCL
    does not catch it, because the destination does not exist yet at the time
    it is created.

    Args:
        out_path: Destination given with --random-password-out.
        input_path: The --input path.
        output_path: The --output path.

    Raises:
        ValueError: If the destination collides with the input or output.
    """
    if out_path is None:
        return
    if not out_path.strip():
        raise ValueError("--random-password-out needs a path")
    out_real = os.path.realpath(out_path)
    for label, other in (("--input", input_path), ("--output", output_path)):
        if not other:
            continue
        if out_real == os.path.realpath(other):
            raise ValueError(f"--random-password-out must differ from {label}")
        # realpath resolves symlinks but NOT hard links, so a destination
        # hardlinked to --output passed this check and was then truncated by
        # the ciphertext write moments later (gitlab#182). samefile compares
        # st_dev/st_ino, which is what "the same file" actually means.
        # Only meaningful when both already exist; the usual case is a
        # destination this run is about to create, and that is handled by the
        # realpath comparison above plus O_EXCL at creation.
        try:
            if os.path.exists(out_path) and os.path.samefile(out_path, other):
                raise ValueError(f"--random-password-out must differ from {label}")
        except OSError:
            pass  # unreadable/missing: the realpath comparison stands


def _random_password_destination_ok(isatty, out_path, quiet=False):
    """Whether a generated password has somewhere safe to go.

    A destination is required whenever the password cannot be displayed:
    without a terminal there is nowhere safe to put it, and under --quiet the
    banner is suppressed entirely -- which would otherwise encrypt the file
    successfully, print nothing, exit 0, and leave nobody holding the
    password. This mirrors `add-recovery --add-code --json`, refused rather
    than silently withholding the credential.

    Args:
        isatty: Whether the display stream is a terminal.
        out_path: Destination given with --random-password-out, or None.
        quiet: Whether --quiet suppresses the display.

    Returns:
        True if the password can actually be delivered.
    """
    if out_path:
        return True
    return bool(isatty) and not quiet


def _display_generated_password(password):
    """Show a generated password on the terminal, once, before encrypting.

    Called BEFORE the ciphertext is written: any later failure would otherwise
    leave an encrypted file whose password was never disclosed.

    Deliberately makes no claim to erase anything. The previous version ran a
    10-second countdown, emitted \\033[2J and announced "Password has been
    cleared from screen" -- which was false. That sequence repaints the visible
    screen; it removes nothing from scrollback, from a pipe, from a `script(1)`
    transcript, or from a CI log. Claiming otherwise is worse than saying
    nothing, because the user stops taking their own precautions
    (gitlab#152).

    Args:
        password: The generated password.
    """
    eprint("\n" + "!" * 80)
    eprint("SAVE THIS PASSWORD NOW".center(80))
    eprint("!" * 80)
    eprint(f"\nGenerated Password: {password}")
    eprint("\nThis is the ONLY time this password is shown.")
    eprint("If you lose it, the data CANNOT be recovered.")
    eprint(
        "\nIt is now in this terminal's scrollback, and in any transcript or\n"
        "log of this session. Use --random-password-out PATH to have it\n"
        "written to a 0600 file instead and never displayed."
    )


# Short options that take a value and whose value is a secret. Derived from
# SECRET_VALUE_CLI_OPTIONS so the two cannot drift.
_SECRET_SHORT_OPTIONS = frozenset(
    opt for opt in SECRET_VALUE_CLI_OPTIONS if len(opt) == 2 and opt[0] == "-" and opt[1] != "-"
)


def _resolve_secret_long_option(token):
    """Whether a ``--`` token names a secret-valued option (gitlab#209).

    argparse accepts unambiguous prefixes -- no parser here sets
    ``allow_abbrev=False`` -- so ``--manifest-p`` binds
    ``--manifest-password`` and the exact-membership test missed it.

    Fails CLOSED, which is the opposite of _is_boolean_option's default: an
    ambiguous prefix that could name a secret option is redacted, because
    printing a password is worse than redacting a filename.
    """
    if token in SECRET_VALUE_CLI_OPTIONS:
        return True
    if not token.startswith("--") or len(token) <= 2:
        return False
    return any(opt.startswith(token) for opt in SECRET_VALUE_CLI_OPTIONS if opt.startswith("--"))


def _split_secret_short_bundle(token):
    """Split ``-apSECRET``/``-ap`` into (prefix, attached_value_or_None).

    argparse resolves a bundle of short options, so ``-ap<value>`` is ``-a``
    plus ``-p <value>`` -- and the previous ``startswith("-p")`` rule saw
    neither (gitlab#209). Returns (None, None) when the token contains no
    secret-valued short option.

    A returned attached value of None means the SECRET IS THE NEXT TOKEN.
    """
    if not token.startswith("-") or token.startswith("--") or len(token) < 2:
        return (None, None)
    for position, letter in enumerate(token[1:], start=1):
        if f"-{letter}" in _SECRET_SHORT_OPTIONS:
            attached = token[position + 1 :]
            return (token[: position + 1], attached if attached else None)
    return (None, None)


def sanitize_argv_for_debug(argv: list) -> list:
    """
    Return a copy of argv with secret option values redacted for debug output.

    Covers the ``--opt value``, ``--opt=value`` and attached short
    ``-pVALUE`` forms for every option in :data:`SECRET_VALUE_CLI_OPTIONS`.
    Values are rendered through the :func:`debug_secret` chokepoint, so they
    stay redacted by default and appear in cleartext only under
    ``--debug --unsafe-show-secrets``.

    Args:
        argv: The raw process argv (``sys.argv``-shaped list of str).

    Returns:
        A new list safe to include in debug output.
    """
    sanitized = list(argv)
    redact_next = False
    for i, arg in enumerate(sanitized):
        if redact_next:
            if arg == "--":
                # The separator is not the credential -- it is what a user
                # MUST type when the token starts with "-", and base64url
                # tokens and JWT segments legitimately do. Redacting it here
                # consumed the redaction and printed the token in cleartext
                # on the next iteration (security review of gitlab#177).
                continue
            sanitized[i] = debug_secret("", arg)
            redact_next = False
        elif _resolve_secret_long_option(arg) or arg in SECRET_VALUE_CLI_OPTIONS:
            redact_next = True
        elif arg in SECRET_POSITIONAL_SUBCOMMANDS:
            # These subcommands take a credential as a POSITIONAL argument, so
            # SECRET_VALUE_CLI_OPTIONS (which matches option names) cannot see
            # it; redact whatever follows.
            #
            # `keyserver set-token <token>` is the bearer token (gitlab#134,
            # F17). `keyserver login <client_id>` is equally a credential: the
            # login body is {"client_id": ...} with the password optional, so
            # the client_id alone yields access and refresh tokens. It became
            # reachable here only with gitlab#171 -- before that, argparse
            # rejected `--debug` after `keyserver` and this dump never ran.
            redact_next = True
        elif "=" in arg and _resolve_secret_long_option(arg.split("=", 1)[0]):
            opt, value = arg.split("=", 1)
            sanitized[i] = f"{opt}={debug_secret('', value)}"
        else:
            # Short-option bundles: argparse reads -apSECRET as -a plus
            # -p SECRET, and -ap SECRET as the same with the value in the
            # next token. The old rule only matched a token literally
            # starting with "-p", so both spellings printed the password
            # (gitlab#209).
            prefix, attached = _split_secret_short_bundle(arg)
            if prefix is not None:
                if attached is not None:
                    sanitized[i] = f"{prefix}{debug_secret('', attached)}"
                else:
                    redact_next = True
    return sanitized


# Every command name recognised on the command line, used by
# preprocess_global_args to find where the command starts. It is ONE list on
# purpose: this was previously two hand-maintained copies, and the
# preprocessor's had drifted to less than half the real set, so global flags
# placed after `identity`, `keyserver`, `telemetry`, `plugin`, `hsm`, `test`
# and 11 others were never relocated and argparse rejected them (gitlab#171).
#
# This is deliberately NOT the routing set. Membership here says "this token
# is a command, so the flags after it belong to it" -- which is true of every
# command whichever parser ends up handling it. Which parser that is comes
# from _subparser_choices() below, read off the real subparser.
#
# Those two questions were one list until gitlab#179, and that conflation is
# what broke seven commands: create-usb, verify-usb and the five *-plugin
# commands were listed, had no subparser registered, and so routed to a
# parser that rejected them with `invalid choice` even though the monolithic
# parser declared them and their handlers existed.
KNOWN_COMMANDS = (
    "encrypt",
    "decrypt",
    "rekey",
    "armor",
    "dearmor",
    "shred",
    "generate-password",
    "derive-password",
    "list-algorithms",
    "list-available-algorithms",
    "install-dependencies",
    "security-info",
    "analyze-security",
    "config-wizard",
    "analyze-config",
    "template",
    "smart-recommendations",
    "test",
    "identity",
    "check-argon2",
    "check-pqc",
    "check-password",
    "version",
    "show-version-file",
    # Handled by the monolithic parser, which accepts global flags anywhere,
    # so its absence here was latent rather than user-visible -- but the list
    # means "every command name", and a subparser for it would break the day
    # it was added (gitlab#176).
    "info",
    "create-usb",
    "verify-usb",
    "list-plugins",
    "plugin-info",
    "enable-plugin",
    "disable-plugin",
    "reload-plugin",
    "plugin",
    "telemetry",
    "keyserver",
    "hsm",
    "verify-integrity",
    "sign",
    "verify-signature",
    "list-recovery",
    "recover",
    "add-recovery",
    "remove-recovery",
)

# Back-compatible alias. The old name described what the list was used for
# rather than what it contains, which is how it came to answer two different
# questions (gitlab#179).
SUBPARSER_COMMANDS = KNOWN_COMMANDS

_BUILT_SUBPARSER = None


def _shared_subparser():
    """One built subparser, shared by the two caches below.

    Both _subparser_choices() and _top_level_flags() run on every
    invocation, and each used to build its own -- double the few
    milliseconds the caches were budgeted for (security review of
    gitlab#177). Returns None if it cannot be built; each caller has its own
    fallback for that.
    """
    global _BUILT_SUBPARSER
    if _BUILT_SUBPARSER is None:
        try:
            from .crypt_cli_subparser import build_subparser

            _BUILT_SUBPARSER = (build_subparser(),)
        except Exception:  # noqa: BLE001 - routing must not be fatal
            _BUILT_SUBPARSER = (None,)
    return _BUILT_SUBPARSER[0]


_SUBPARSER_CHOICES = None


def _subparser_choices():
    """The commands the subparser actually registers.

    Read off the built parser rather than kept as a list beside it: a
    hand-maintained copy is exactly what drifted in gitlab#171 and again in
    gitlab#179. A command with no subparser must fall through to the
    monolithic parser, which declares it and has its handler -- routing it to
    a parser that has never heard of it is a dead command, not a fallback.

    Cached because build_subparser() costs a few milliseconds and the answer
    cannot change within a process.

    Returns a frozenset, not the mutable cache: handing out the live set lets
    any in-process caller re-create gitlab#179 at runtime -- .clear() sends
    every command to the monolithic parser, and .add("x") routes x to a
    subparser that will reject it with `invalid choice`. Immutability also
    makes the unsynchronised check-then-set below provably harmless: two
    threads would build equivalent values and neither can observe a
    half-built one.

    A failure to build degrades to "nothing is routed" rather than taking the
    whole CLI down. This is now on the unconditional path -- every
    invocation, including the monolithic ones -- where before, importing
    crypt_cli_subparser only happened for commands that were about to use it.
    Falling back to the monolithic parser, which declares every command, is
    the safe direction.
    """
    global _SUBPARSER_CHOICES
    if _SUBPARSER_CHOICES is None:
        import argparse as _argparse

        choices = set()
        parser = _shared_subparser()
        if parser is not None:
            for action in parser._actions:
                if isinstance(action, _argparse._SubParsersAction):
                    choices |= set(action.choices)
        _SUBPARSER_CHOICES = frozenset(choices)
    return _SUBPARSER_CHOICES


# Flags that are truly global and can appear anywhere on the command line.
#
# Membership here means "relocate this to the front so the top-level parser
# consumes it". Only add a flag that is declared ONLY on the top-level parser:
# if a subparser also declares the same dest, its default overwrites the
# relocated value when argparse copies the subcommand namespace back, and the
# flag is silently dropped instead of working (gitlab#171).
#
# In particular -t/--template must never appear here: it is a subcommand
# option on encrypt/decrypt that selects the KDF/hash parameters, so a silent
# drop would mean encrypting at default cost instead of the requested one.
TRULY_GLOBAL_FLAGS = frozenset(
    {
        "--debug",
        "--unsafe-show-secrets",
        "--verbose",
        "--quiet",
        "-q",
        "--progress",
        "--parallel-kdf",
        "--kdf-workers",
        # gitlab#176: declared top-level as "Automatic yes to prompts (for
        # install-dependencies command)", recognised for routing, but never
        # relocated -- so `install-dependencies --yes`, the one invocation it
        # exists for, exited 2. Held back from gitlab#171 because `hsm
        # fido2-unregister` declares its own --yes whose default would clobber
        # a relocated one; that declaration now uses default=SUPPRESS, the
        # same treatment --quiet needed.
        "--yes",
        "-y",
    }
)

# The single global flag that carries a value; its value must move with it.
VALUE_CARRYING_GLOBAL_FLAGS = frozenset({"--kdf-workers"})


_TOP_LEVEL_FLAGS = None


def _top_level_flags():
    """(value-taking, boolean) top-level option strings.

    Read off the real parser rather than hand-listed (gitlab#177), for the
    same reason as _subparser_choices: a copy beside the definition drifts,
    and this one decides whether the next token is a command or somebody
    else's value.

    Falls back to the known set if the parser cannot be built, so a failure
    here degrades to today's behaviour rather than mis-scanning every argv.
    """
    global _TOP_LEVEL_FLAGS
    if _TOP_LEVEL_FLAGS is None:
        import argparse as _argparse

        value_flags, boolean_flags = set(), set()
        parser = _shared_subparser()
        try:
            if parser is None:
                raise RuntimeError("subparser unavailable")
            for action in parser._actions:
                if not action.option_strings:
                    continue
                boolean = (
                    isinstance(
                        action,
                        (
                            _argparse._StoreTrueAction,
                            _argparse._StoreFalseAction,
                            _argparse._HelpAction,
                            _argparse._VersionAction,
                        ),
                    )
                    or action.nargs == 0
                )
                (boolean_flags if boolean else value_flags).update(action.option_strings)
        except Exception:  # noqa: BLE001 - scanning must not be fatal
            value_flags = {"--kdf-workers", "--identity-store", "--keyring-remove"}
            # MINUS the value-carrying ones: TRULY_GLOBAL_FLAGS contains
            # --kdf-workers, and calling it boolean here means the fallback
            # would not consume its value and would read "4" as the command
            # -- verbatim the gitlab#171 bug this file elsewhere says is
            # fixed (security review of gitlab#177).
            boolean_flags = (set(TRULY_GLOBAL_FLAGS) - set(VALUE_CARRYING_GLOBAL_FLAGS)) | {
                "-h",
                "--help",
            }
        _TOP_LEVEL_FLAGS = (frozenset(value_flags), frozenset(boolean_flags))
    return _TOP_LEVEL_FLAGS


def _find_command(argv):
    """(command, index) for the command in argv, or (None, None).

    The INDEX matters to preprocess_global_args: whether to strip a leading
    `--` is a question about position, and testing "is the command already
    in the output list" stood in for it badly -- a token equal to the
    command name appearing earlier as some option's value suppressed a strip
    that should have happened (follow-up review of gitlab#177).

    Two rules the previous scans lacked (gitlab#177):

      * Stop at a bare ``--``. Everything after it is data by POSIX
        convention, so a file literally named ``--quiet`` must not be read as
        a flag and a positional named ``encrypt`` must not be read as the
        command.
      * A value belongs to its option, not to the scan. gitlab#171 widened
        the command set from 20 names to 42, which added ordinary barewords
        -- test, version, sign, recover, template, identity, plugin, hsm,
        armor -- so ``--alias telemetry`` used to look like the ``telemetry``
        command.

    An option this scan does not recognise is assumed to take a value. That
    is safe because the recognised sets ARE the top-level parser's own: an
    unrecognised option at this position is one argparse will reject anyway,
    so consuming its value cannot break a command line that would otherwise
    have worked. Both sets are needed, not just the value-taking one --
    --yes/-y and -h/--help are top-level booleans that are NOT in
    TRULY_GLOBAL_FLAGS (they are recognised but not relocatable), so keying
    off that set alone made `crypt --yes encrypt` swallow the command.
    """
    commands = set(KNOWN_COMMANDS)
    value_flags, boolean_flags = _top_level_flags()

    index = 1
    while index < len(argv):
        token = argv[index]
        if token == "--":
            # POSIX and argparse both take the NEXT token as the positional,
            # so the command can legitimately follow the separator. Returning
            # None here sent `crypt -- identity list` to the wrong parser
            # (security review of gitlab#177). Everything after is data, so
            # the search stops at that one token.
            following = argv[index + 1] if index + 1 < len(argv) else None
            return (following, index + 1) if following in commands else (None, None)
        if token.startswith("-") and token != "-":
            # --flag=value is self-contained; it never consumes the next token.
            if "=" not in token and not _is_boolean_option(token, boolean_flags, value_flags):
                index += 1  # its value, whether the flag is known or not
            index += 1
            continue
        return (token, index) if token in commands else (None, None)
    return (None, None)


def _first_command_token(argv):
    """The command name in argv, or None. See _find_command for the rules."""
    return _find_command(argv)[0]


def _is_boolean_option(token, boolean_flags, value_flags):
    """Whether this option token takes no value.

    Exact membership is not enough, because argparse accepts two forms the
    flag sets cannot express (security review of gitlab#177):

      * **Bundled short options.** `-qy` is `-q` plus `-y`, both booleans,
        but matches neither set -- so the scan assumed a value and swallowed
        the command. `-qy install-dependencies` failed while `-q -y
        install-dependencies` worked, and `-qy` is the natural spelling for
        the one command --yes exists for.
      * **Abbreviated long options.** No parser here sets
        `allow_abbrev=False`, so `--deb` is a valid unambiguous prefix of
        `--debug` -- and it swallowed the command too.

    Unknown or ambiguous stays "takes a value", which is the fail-closed
    direction: it is what stopped `--alias telemetry` being read as the
    `telemetry` command, and an option argparse cannot resolve is one it
    will reject anyway.
    """
    if token in boolean_flags:
        return True
    if token in value_flags:
        return False

    if token.startswith("--"):
        # Unambiguous prefix, resolved against both sets together so an
        # abbreviation shared by a boolean and a value flag stays unknown.
        matches = {flag for flag in boolean_flags | value_flags if flag.startswith(token)}
        if len(matches) == 1:
            return matches.pop() in boolean_flags
        return False

    # A short-option bundle is boolean only if EVERY letter in it is.
    singles = {flag for flag in boolean_flags if len(flag) == 2 and flag[0] == "-"}
    return len(token) > 2 and all(f"-{letter}" in singles for letter in token[1:])


def _keyring_remove_label(argv):
    """The label `--keyring-remove` was given, or None.

    Only honoured in top-level option position: before any `--`, and before
    the command token. `--keyring-remove` is declared on the top-level
    parser, so after a subcommand it is that subcommand's argument, not a
    request to delete a credential.

    Both spellings are recognised. The old scan matched only the separate
    form, so `--keyring-remove=LABEL` silently did nothing.
    """
    _value_flags, boolean_flags = _top_level_flags()
    command = _first_command_token(argv)
    found = None

    index = 1
    while index < len(argv):
        token = argv[index]
        if token == "--":
            break
        if command is not None and token == command:
            break

        if token.startswith("--keyring-remove="):
            candidate = token.split("=", 1)[1]
            # An empty label is a mistake, not a request to delete "".
            found = candidate or None
            index += 1
            continue

        if _is_keyring_remove_option(token):
            candidate = argv[index + 1] if index + 1 < len(argv) else None
            # A label that looks like a flag means the user forgot it.
            found = candidate if candidate and not candidate.startswith("-") else None
            index += 2
            continue

        if token.startswith("-") and token != "-":
            # Skip this option's VALUE too. Without it, `--identity-store
            # --keyring-remove encrypt` deleted the entry named "encrypt" --
            # a "forgot the path" typo that argparse would have rejected
            # outright (follow-up review of gitlab#177).
            if "=" not in token and not _is_boolean_option(token, boolean_flags, _value_flags):
                index += 1
            index += 1
            continue

        index += 1

    # Last occurrence wins, as argparse binds it.
    return found


def _is_keyring_remove_option(token):
    """Whether this token names --keyring-remove, abbreviations included.

    argparse accepts unambiguous prefixes, so `--keyring-rem` binds the
    option -- and the exact-match scan ignored it, making the option a
    silent no-op in that spelling (follow-up review of gitlab#177).
    """
    if token == "--keyring-remove":
        return True
    if not token.startswith("--") or len(token) <= 2 or "=" in token:
        return False
    _value_flags, boolean_flags = _top_level_flags()
    candidates = {flag for flag in set(_value_flags) | set(boolean_flags) if flag.startswith(token)}
    return candidates == {"--keyring-remove"}


def preprocess_global_args(argv):
    """Preprocess sys.argv to move truly global flags to the front for subparser compatibility.

    This allows global flags like --debug, --verbose, --quiet, --progress to be specified
    anywhere in the command line, maintaining backward compatibility with v1.2.1 behavior.
    """
    # Every command, not just the routed ones: a flag written after
    # `create-usb` belongs to create-usb regardless of which parser handles
    # it. Shared with main()'s routing scan so the two cannot disagree
    # (gitlab#177).
    command_token, command_index = _find_command(argv)
    if command_token is None:
        return argv  # No command found, return as-is

    # Extract global flags and their values from anywhere in the command line
    global_args = []
    other_args = [argv[0]]  # Keep script name
    i = 1

    while i < len(argv):
        arg = argv[i]

        if arg == "--":
            # Everything from here is data, not flags (gitlab#177). Copy the
            # rest verbatim: a file literally named --quiet was being hoisted
            # out of its subcommand's argument list and read as a flag.
            #
            # A separator BEFORE the command is dropped rather than kept.
            # POSIX reads `crypt -- identity list` as "identity is a
            # positional", but argparse does not strip it for a subparser --
            # it reports `invalid choice: '--'` -- so passing it through
            # makes a legitimate invocation fail (security review of
            # gitlab#177, whose premise that argparse strips it turned out
            # not to hold; verified directly against argparse).
            if command_index == i + 1:
                other_args.extend(argv[i + 1 :])
            else:
                other_args.extend(argv[i:])
            break

        # The --flag=value form is one token, so an exact membership test
        # misses it and argparse then rejects it after a subcommand -- the
        # same gitlab#171 symptom, for the "=" spelling.
        if "=" in arg and arg.split("=", 1)[0] in VALUE_CARRYING_GLOBAL_FLAGS:
            global_args.append(arg)
        elif arg in TRULY_GLOBAL_FLAGS:
            global_args.append(arg)
            # Check if this flag takes a value.
            #
            # --kdf-workers is the only value-carrying global flag. Do NOT add
            # --template/-t here: it is a *subcommand* option on encrypt and
            # decrypt, and it selects the KDF/hash parameters. Relocating it
            # would hand it to the top-level parser, whose value the encrypt
            # subparser's own `template=None` default then overwrites -- so
            # `encrypt -t hardened` would silently encrypt at default KDF cost
            # instead of the requested one. (It was listed here for a long
            # time but is unreachable: the branch above requires membership in
            # TRULY_GLOBAL_FLAGS, which -t/--template are not.)
            if (
                arg in VALUE_CARRYING_GLOBAL_FLAGS
                and i + 1 < len(argv)
                and not argv[i + 1].startswith("-")
            ):
                i += 1
                global_args.append(argv[i])
        else:
            other_args.append(arg)
        i += 1

    # Rebuild argv: script_name + global_args + other_args
    return [argv[0]] + global_args + other_args[1:]


def analyze_current_security_configuration(args):
    """
    Analyze the current security configuration and display a security score.

    Args:
        args: Parsed command line arguments containing security configuration
    """
    output_format = getattr(args, "output_format", "text")
    if output_format != "json":
        eprint("\nSECURITY CONFIGURATION ANALYSIS")
        eprint("===============================")

    try:
        # Extract hash configuration
        hash_config = {}

        # Process all available hash algorithms
        hash_algorithms = [
            "sha256",
            "sha512",
            "sha224",
            "sha384",
            "sha3_256",
            "sha3_512",
            "sha3_224",
            "sha3_384",
            "blake2b",
            "blake3",
            "shake256",
            "shake128",
            "whirlpool",
        ]

        for hash_name in hash_algorithms:
            rounds = getattr(args, f"{hash_name}_rounds", 0) or 0
            if rounds > 0:
                hash_config[hash_name] = {"rounds": rounds}

        # Extract KDF configuration
        kdf_config = {}

        # Argon2 configuration
        argon2_memory_cost = getattr(args, "argon2_memory_cost", 0) or 0
        if argon2_memory_cost > 0:
            kdf_config["argon2"] = {
                "enabled": True,
                "memory_cost": argon2_memory_cost,
                "time_cost": getattr(args, "argon2_time_cost", 3) or 3,
                "parallelism": getattr(args, "argon2_parallelism", 4) or 4,
            }

        # Scrypt configuration
        scrypt_n = getattr(args, "scrypt_n", 0) or 0
        if scrypt_n > 0:
            kdf_config["scrypt"] = {
                "enabled": True,
                "n": scrypt_n,
                "r": getattr(args, "scrypt_r", 8) or 8,
                "p": getattr(args, "scrypt_p", 1) or 1,
            }

        # PBKDF2 configuration
        pbkdf2_rounds = getattr(args, "pbkdf2_rounds", 0) or 0
        if pbkdf2_rounds > 0:
            kdf_config["pbkdf2"] = {
                "enabled": True,
                "rounds": pbkdf2_rounds,
            }

        # Balloon configuration
        balloon_space_cost = getattr(args, "balloon_space_cost", 0) or 0
        if balloon_space_cost > 0:
            kdf_config["balloon"] = {
                "enabled": True,
                "space_cost": balloon_space_cost,
                "time_cost": getattr(args, "balloon_time_cost", 20) or 20,
            }

        # HKDF configuration
        hkdf_rounds = getattr(args, "hkdf_rounds", 0) or 0
        if hkdf_rounds > 0:
            kdf_config["hkdf"] = {
                "enabled": True,
                "rounds": hkdf_rounds,
                "hash_algorithm": getattr(args, "hkdf_hash_algorithm", "sha256") or "sha256",
            }

        # Extract encryption algorithm information
        encryption_data_algorithm = getattr(args, "encryption_data_algorithm", "aes-gcm")
        cipher_info = {"algorithm": encryption_data_algorithm}

        # Extract post-quantum configuration
        pqc_info = None
        pqc_algorithm = getattr(args, "pqc_algorithm", None)
        if pqc_algorithm and pqc_algorithm.lower() != "none":
            pqc_info = {"enabled": True, "algorithm": pqc_algorithm}

        # Initialize security scorer and analyze
        scorer = SecurityScorer()
        analysis = scorer.score_configuration(hash_config, kdf_config, cipher_info, pqc_info)

        # Machine-readable document on stdout so a GUI reads the real security
        # analysis instead of scraping the unversioned human report (gitlab#162).
        # A misparsed security readout is worse than none, so emit structured
        # data. The only non-JSON-native value is the overall SecurityLevel enum.
        if output_format == "json":
            import json

            result = dict(analysis)
            result["overall"] = dict(analysis["overall"])
            result["overall"]["level"] = analysis["overall"]["level"].name
            print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
            return

        # Display analysis results
        eprint(f"\nOVERALL SECURITY SCORE: {analysis['overall']['score']}/10")
        eprint(f"Security Level: {analysis['overall']['level'].name}")
        eprint(f"Description: {analysis['overall']['description']}")

        eprint("\nCOMPONENT ANALYSIS:")
        eprint("─────────────────────")
        eprint(
            f"Hash Security: {analysis['hash_analysis']['score']:.1f}/10 ({analysis['hash_analysis']['description']})"
        )
        if analysis["hash_analysis"]["algorithms"]:
            eprint(f"  Active algorithms: {', '.join(analysis['hash_analysis']['algorithms'])}")
            eprint(f"  Total rounds: {analysis['hash_analysis']['total_rounds']:,}")

        eprint(
            f"KDF Security: {analysis['kdf_analysis']['score']:.1f}/10 ({analysis['kdf_analysis']['description']})"
        )
        if analysis["kdf_analysis"]["algorithms"]:
            eprint(f"  Active algorithms: {', '.join(analysis['kdf_analysis']['algorithms'])}")

        eprint(
            f"Encryption: {analysis['cipher_analysis']['score']:.1f}/10 ({analysis['cipher_analysis']['description']})"
        )
        eprint(f"  Algorithm: {analysis['cipher_analysis']['algorithm']}")
        eprint(
            f"  Authenticated: {'Yes' if analysis['cipher_analysis']['authenticated'] else 'No'}"
        )

        if analysis["pqc_analysis"]["enabled"]:
            eprint(f"Post-Quantum: {analysis['pqc_analysis']['score']:.1f}/10 (Quantum-resistant)")
        else:
            eprint("Post-Quantum: Not enabled")

        eprint("\nSECURITY ESTIMATES:")
        eprint("─────────────────────")
        eprint(f"Estimated brute-force time: {analysis['estimates']['brute_force_time']}")
        eprint(f"Note: {analysis['estimates']['note']}")
        eprint(f"Disclaimer: {analysis['estimates']['disclaimer']}")

        if analysis["suggestions"]:
            eprint("\nRECOMMENDATIONS:")
            eprint("─────────────────")
            for i, suggestion in enumerate(analysis["suggestions"], 1):
                eprint(f"{i}. {suggestion}")

        eprint()

    except Exception as e:
        # In json mode stdout must stay a reliable contract: a scoring failure
        # emits a structured error document and exits non-zero, so a GUI/script
        # can tell failure from an empty success instead of getting empty
        # stdout + exit 0 (gitlab#162 security review).
        if output_format == "json":
            import json

            print(json.dumps({"error": str(e)}))
            sys.exit(1)
        eprint(f"Error analyzing security configuration: {e}")
        eprint("Please check your configuration parameters.")


def validate_algorithm_availability(args):
    """
    Validate that specified algorithms are available on this system.

    Checks hash and KDF algorithms specified via CLI flags and warns
    if they're not available (e.g., missing optional dependencies).

    Args:
        args: Parsed command line arguments

    Returns:
        List of warning messages for unavailable algorithms
    """
    warnings = []

    try:
        from .registry import validate_algorithm_name

        # Check hash algorithms
        hash_algorithms = []
        if (getattr(args, "sha256_rounds", 0) or 0) > 0:
            hash_algorithms.append("sha256")
        if (getattr(args, "sha512_rounds", 0) or 0) > 0:
            hash_algorithms.append("sha512")
        if (getattr(args, "sha384_rounds", 0) or 0) > 0:
            hash_algorithms.append("sha384")
        if (getattr(args, "blake2b_rounds", 0) or 0) > 0:
            hash_algorithms.append("blake2b")
        if (getattr(args, "blake3_rounds", 0) or 0) > 0:
            hash_algorithms.append("blake3")
        if (getattr(args, "shake256_rounds", 0) or 0) > 0:
            hash_algorithms.append("shake256")
        if (getattr(args, "whirlpool_rounds", 0) or 0) > 0:
            hash_algorithms.append("whirlpool")

        for algo in hash_algorithms:
            is_valid, error_msg = validate_algorithm_name(algo, "hash")
            if not is_valid:
                warnings.append(f"Hash algorithm '{algo}': {error_msg}")

        # Check KDF algorithms
        if getattr(args, "enable_argon2", False):
            is_valid, error_msg = validate_algorithm_name("argon2id", "kdf")
            if not is_valid:
                warnings.append(f"Argon2: {error_msg}")

        if getattr(args, "enable_scrypt", False):
            is_valid, error_msg = validate_algorithm_name("scrypt", "kdf")
            if not is_valid:
                warnings.append(f"Scrypt: {error_msg}")

        if getattr(args, "enable_randomx", False):
            is_valid, error_msg = validate_algorithm_name("randomx", "kdf")
            if not is_valid:
                warnings.append(f"RandomX: {error_msg}")

        if getattr(args, "enable_balloon", False):
            is_valid, error_msg = validate_algorithm_name("balloon", "kdf")
            if not is_valid:
                warnings.append(f"Balloon: {error_msg}")

        if getattr(args, "enable_hkdf", False):
            is_valid, error_msg = validate_algorithm_name("hkdf", "kdf")
            if not is_valid:
                warnings.append(f"HKDF: {error_msg}")

    except ImportError:
        # Registry not available, skip validation
        pass
    except Exception as e:
        # Don't fail on validation errors
        logger.debug(f"Algorithm validation error: {e}")

    return warnings


def show_algorithm_registry(args):
    """
    Display available algorithms from the registry system.

    Args:
        args: Parsed command line arguments with category and format options
    """
    try:
        from .registry import format_algorithm_help

        category = getattr(args, "category", "all")
        output_format = getattr(args, "format", "detailed")

        if category == "all":
            # Show all categories
            categories = ["cipher", "hash", "kdf", "kem", "signature"]
        else:
            # Map plural form to singular
            category_map = {
                "ciphers": "cipher",
                "hashes": "hash",
                "kdfs": "kdf",
                "kems": "kem",
                "signatures": "signature",
            }
            categories = [category_map.get(category, category)]

        if output_format == "detailed":
            # Show detailed information with descriptions
            for cat in categories:
                eprint(format_algorithm_help(cat))
                eprint()  # Blank line between categories
        else:
            # Simple format - just list names
            from .registry import (
                get_available_ciphers,
                get_available_hashes,
                get_available_kdfs,
                get_available_kems,
                get_available_signatures,
            )

            getters = {
                "cipher": ("Ciphers", get_available_ciphers),
                "hash": ("Hash Functions", get_available_hashes),
                "kdf": ("Key Derivation Functions", get_available_kdfs),
                "kem": ("KEMs (Post-Quantum)", get_available_kems),
                "signature": ("Signatures (Post-Quantum)", get_available_signatures),
            }

            for cat in categories:
                if cat in getters:
                    title, getter = getters[cat]
                    algorithms = getter()
                    eprint(f"\n{title}:")
                    eprint("=" * len(title))
                    for algo in algorithms:
                        eprint(f"  {algo}")

    except ImportError:
        eprint("Error: Registry system not available.")
        eprint("The algorithm registry module could not be imported.")
        sys.exit(1)
    except Exception as e:
        eprint(f"Error displaying algorithms: {e}")
        sys.exit(1)


def output_available_algorithms_json(args):
    """
    Output all algorithm availability information as JSON.

    Used by Flutter GUI to dynamically enable/disable algorithms based on
    installed crypto libraries.

    Args:
        args: Parsed command line arguments
    """
    import subprocess

    try:
        from .registry import (
            CipherRegistry,
            HashRegistry,
            KDFRegistry,
            KEMRegistry,
            SignatureRegistry,
        )
    except ImportError as e:
        print(json.dumps({"error": f"Registry system not available: {e}"}))
        sys.exit(1)

    result = {
        "ciphers": {},
        "hashes": {},
        "kdfs": {},
        "kems": {},
        "signatures": {},
        "libraries": {},
    }

    # Library availability checks
    libraries = {
        "threefish_native": {
            "available": False,
            "version": None,
            "required_for": ["threefish-512", "threefish-1024"],
        },
        "blake3": {"available": False, "version": None, "required_for": ["blake3"]},
        "argon2-cffi": {
            "available": False,
            "version": None,
            "required_for": ["argon2id", "argon2i", "argon2d"],
        },
        "randomx": {"available": False, "version": None, "required_for": ["randomx"]},
        "liboqs": {
            "available": False,
            "version": None,
            "required_for": [
                "ml-kem-*",
                "kyber*",
                "hqc-*",
                "mayo-*",
                "cross-*",
                "ml-dsa-*",
                "slh-dsa-*",
                "fn-dsa-*",
            ],
        },
    }

    # Check threefish_native
    try:
        import threefish_native

        libraries["threefish_native"]["available"] = True
        libraries["threefish_native"]["version"] = getattr(
            threefish_native, "__version__", "installed"
        )
    except ImportError:
        pass

    # Check blake3
    try:
        import blake3

        libraries["blake3"]["available"] = True
        libraries["blake3"]["version"] = getattr(blake3, "__version__", "installed")
    except ImportError:
        pass

    # Check argon2-cffi
    try:
        import argon2

        libraries["argon2-cffi"]["available"] = True
        libraries["argon2-cffi"]["version"] = getattr(argon2, "__version__", "installed")
    except ImportError:
        pass

    # Check randomx (using subprocess for safety - may cause SIGILL on unsupported CPUs)
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "import randomx; print(getattr(randomx, '__version__', 'installed'))",
            ],
            capture_output=True,
            timeout=2,
            check=False,
        )
        if proc.returncode == 0:
            libraries["randomx"]["available"] = True
            libraries["randomx"]["version"] = proc.stdout.decode().strip()
    except (subprocess.TimeoutExpired, OSError):
        pass

    # Check liboqs
    try:
        import oqs

        libraries["liboqs"]["available"] = True
        libraries["liboqs"]["version"] = (
            oqs.get_version()
            if hasattr(oqs, "get_version")
            else getattr(oqs, "__version__", "installed")
        )
    except ImportError:
        pass

    result["libraries"] = libraries

    # Helper function to determine required library for an algorithm
    def get_required_library(name: str, category: str) -> Optional[str]:
        if category == "cipher":
            if name.startswith("threefish"):
                return "threefish_native"
        elif category == "hash":
            if name == "blake3":
                return "blake3"
        elif category == "kdf":
            if name.startswith("argon2"):
                return "argon2-cffi"
            elif name == "randomx":
                return "randomx"
        elif category in ("kem", "signature"):
            return "liboqs"
        return None

    # Get algorithm info from registries
    try:
        for name, (info, available) in CipherRegistry.default().list_all().items():
            required_lib = get_required_library(name, "cipher")
            result["ciphers"][name] = {
                "display_name": info.display_name,
                "available": available,
                "required_library": required_lib,
                "security_level": info.security_level.name,
                "description": info.description or "",
            }
    except Exception:
        pass

    # Add fernet manually (legacy algorithm not in registry)
    result["ciphers"]["fernet"] = {
        "display_name": "Fernet",
        "available": True,
        "required_library": None,
        "security_level": "STANDARD",
        "description": "AES-128-CBC with HMAC authentication (Default, Legacy)",
    }

    try:
        for name, (info, available) in HashRegistry.default().list_all().items():
            required_lib = get_required_library(name, "hash")
            result["hashes"][name] = {
                "display_name": info.display_name,
                "available": available,
                "required_library": required_lib,
                "security_level": info.security_level.name,
                "description": info.description or "",
            }
    except Exception:
        pass

    try:
        for name, (info, available) in KDFRegistry.default().list_all().items():
            required_lib = get_required_library(name, "kdf")
            result["kdfs"][name] = {
                "display_name": info.display_name,
                "available": available,
                "required_library": required_lib,
                "security_level": info.security_level.name,
                "description": info.description or "",
            }
    except Exception:
        pass

    try:
        for name, (info, available) in KEMRegistry.default().list_all().items():
            required_lib = get_required_library(name, "kem")
            result["kems"][name] = {
                "display_name": info.display_name,
                "available": available,
                "required_library": required_lib,
                "security_level": info.security_level.name,
                "description": info.description or "",
            }
    except Exception:
        pass

    try:
        for name, (info, available) in SignatureRegistry.default().list_all().items():
            required_lib = get_required_library(name, "signature")
            result["signatures"][name] = {
                "display_name": info.display_name,
                "available": available,
                "required_library": required_lib,
                "security_level": info.security_level.name,
                "description": info.description or "",
            }
    except Exception:
        pass

    # Output JSON
    print(json.dumps(result, indent=2))


def install_optional_dependencies(args):
    """
    Install optional dependencies (liboqs, liboqs-python, threefish).

    This command helps users install advanced crypto libraries after
    the base package is installed. It builds:
    - liboqs (C library for post-quantum cryptography)
    - liboqs-python (Python bindings)
    - threefish_native (Rust extension for Threefish cipher)

    Args:
        args: Parsed command line arguments
    """
    import os
    import shutil
    import subprocess

    eprint("\n" + "=" * 70)
    eprint("OpenSSL-Encrypt: Optional Dependencies Installer")
    eprint("=" * 70)
    eprint("\nThis will install:")
    eprint("  • liboqs 0.12.0 (post-quantum cryptography)")
    eprint("  • liboqs-python 0.12.0 (Python bindings)")
    eprint("  • threefish_native (large-block cipher)")
    eprint("\nRequirements:")
    eprint("  • cmake, ninja (or make), gcc, g++, git")
    eprint("  • Rust toolchain (rustc, cargo) for threefish")
    eprint("  • ~500MB disk space, ~10-15 minutes build time")
    eprint("=" * 70 + "\n")

    if not args.yes:
        response = prompt_and_read("Continue? [y/N]: ").strip().lower()
        if response not in ("y", "yes"):
            eprint("Installation cancelled.")
            return

    success_count = 0
    failed = []

    # Check for required build tools
    eprint("\n[1/4] Checking build tools...")
    required_tools = {
        "cmake": "cmake",
        "ninja or make": ["ninja", "make"],
        "gcc": "gcc",
        "g++": "g++",
        "git": "git",
        "cargo": "cargo",  # For threefish
    }

    missing_tools = []
    for tool_name, commands in required_tools.items():
        if isinstance(commands, str):
            commands = [commands]
        found = any(shutil.which(cmd) for cmd in commands)
        if found:
            eprint(f"  ✓ {tool_name} found")
        else:
            eprint(f"  ✗ {tool_name} NOT found")
            missing_tools.append(tool_name)

    if missing_tools:
        eprint(f"\n✗ Missing required tools: {', '.join(missing_tools)}")
        eprint("\nPlease install them first:")
        eprint("  Ubuntu/Debian: sudo apt-get install cmake ninja-build gcc g++ git cargo")
        eprint("  Fedora: sudo dnf install cmake ninja-build gcc g++ git cargo")
        eprint("  macOS: brew install cmake ninja gcc git rust")
        sys.exit(1)

    # Get package root directory
    try:
        import openssl_encrypt

        package_dir = os.path.dirname(os.path.abspath(openssl_encrypt.__file__))
        repo_root = os.path.dirname(package_dir)  # Go up one level
    except Exception as e:
        eprint(f"✗ Could not locate package directory: {e}")
        sys.exit(1)

    # [2/4] Build liboqs
    eprint("\n[2/4] Building liboqs 0.12.0...")
    try:
        # Check if already installed
        result = subprocess.run(
            ["pkg-config", "--modversion", "liboqs"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip() == "0.12.0":
            eprint("  ✓ liboqs 0.12.0 already installed")
            success_count += 1
        else:
            # Try using the build script if available
            build_script = os.path.join(repo_root, "scripts", "build_local_deps.sh")
            if not os.path.exists(build_script):
                # Build manually
                eprint("  Building from source...")
                build_dir = os.path.expanduser("~/.cache/openssl-encrypt-build")
                os.makedirs(build_dir, exist_ok=True)

                # Clone liboqs
                liboqs_dir = os.path.join(build_dir, "liboqs")
                if os.path.exists(liboqs_dir):
                    shutil.rmtree(liboqs_dir)

                subprocess.run(
                    [
                        "git",
                        "clone",
                        "--branch",
                        "0.12.0",
                        "--depth",
                        "1",
                        "https://github.com/open-quantum-safe/liboqs.git",
                        liboqs_dir,
                    ],
                    check=True,
                )

                # Build
                build_path = os.path.join(liboqs_dir, "build")
                os.makedirs(build_path, exist_ok=True)

                subprocess.run(
                    [
                        "cmake",
                        "-GNinja",
                        "-DCMAKE_INSTALL_PREFIX=" + os.path.expanduser("~/.local"),
                        "..",
                    ],
                    cwd=build_path,
                    check=True,
                )
                subprocess.run(["ninja"], cwd=build_path, check=True)
                subprocess.run(["ninja", "install"], cwd=build_path, check=True)

                eprint("  ✓ liboqs 0.12.0 built and installed to ~/.local")
                success_count += 1
            else:
                # Use build script
                env = os.environ.copy()
                env["LIBOQS_INSTALL_PREFIX"] = os.path.expanduser("~/.local")
                env["LIBOQS_VERSION"] = "0.12.0"
                env["LIBOQS_PYTHON_VERSION"] = "0.12.0"

                bash_cmd = shutil.which("bash") or "/bin/bash"
                subprocess.run([bash_cmd, build_script], env=env, check=True)
                eprint("  ✓ liboqs 0.12.0 built and installed")
                success_count += 1
    except Exception as e:
        eprint(f"  ✗ Failed to build liboqs: {e}")
        failed.append("liboqs")

    # [3/4] Install liboqs-python
    eprint("\n[3/4] Installing liboqs-python 0.12.0...")
    try:
        # Check if already installed
        result = subprocess.run(
            [sys.executable, "-c", "import oqs; print(oqs.oqs_python_version())"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip() == "0.12.0":
            eprint("  ✓ liboqs-python 0.12.0 already installed")
            success_count += 1
        else:
            # Install via pip
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "git+https://github.com/open-quantum-safe/liboqs-python.git@0.12.0",
                ],
                check=True,
            )
            eprint("  ✓ liboqs-python 0.12.0 installed")
            success_count += 1
    except Exception as e:
        eprint(f"  ✗ Failed to install liboqs-python: {e}")
        failed.append("liboqs-python")

    # [4/4] Build threefish_native
    eprint("\n[4/4] Building threefish_native...")
    try:
        # Check if already installed
        try:
            import threefish_native

            eprint(
                f"  ✓ threefish_native already installed (version {getattr(threefish_native, '__version__', 'unknown')})"
            )
            success_count += 1
        except ImportError:
            # Try to build it
            threefish_dir = os.path.join(repo_root, "threefish_native")
            if not os.path.exists(threefish_dir):
                eprint("  ✗ threefish_native source not found")
                eprint("     This is only available when installing from source repository")
                failed.append("threefish_native")
            else:
                # Install maturin if needed
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "maturin"],
                    capture_output=True,
                    check=True,
                )

                # Build with maturin
                env = os.environ.copy()
                env["PYO3_USE_ABI3_FORWARD_COMPATIBILITY"] = "1"

                subprocess.run(
                    ["maturin", "build", "--release"],
                    cwd=threefish_dir,
                    env=env,
                    check=True,
                )

                # Install the built wheel
                wheels_dir = os.path.join(threefish_dir, "target", "wheels")
                wheels = [f for f in os.listdir(wheels_dir) if f.endswith(".whl")]
                if wheels:
                    subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "pip",
                            "install",
                            "--force-reinstall",
                            os.path.join(wheels_dir, wheels[0]),
                        ],
                        check=True,
                    )
                    eprint("  ✓ threefish_native built and installed")
                    success_count += 1
                else:
                    eprint("  ✗ No wheel file found after build")
                    failed.append("threefish_native")
    except Exception as e:
        eprint(f"  ✗ Failed to build threefish_native: {e}")
        failed.append("threefish_native")

    # Summary
    eprint("\n" + "=" * 70)
    eprint("Installation Summary")
    eprint("=" * 70)
    eprint(f"  Successfully installed: {success_count}/3 components")
    if failed:
        eprint(f"  Failed: {', '.join(failed)}")
    else:
        eprint("  All components installed successfully!")

    eprint("\nTo verify installation, run:")
    eprint("  openssl-encrypt list-available-algorithms")
    eprint("=" * 70 + "\n")

    if failed:
        sys.exit(1)


def run_config_wizard(args):
    """
    Run the configuration wizard and display results.

    Args:
        args: Parsed command line arguments
    """
    try:
        quiet = getattr(args, "quiet", False)

        if not quiet:
            eprint("Starting Configuration Wizard...")
            eprint("This will help you create secure encryption settings.\n")

        # Run the wizard
        config = run_configuration_wizard(quiet=quiet)

        if not quiet:
            # Generate CLI arguments for the configuration
            cli_args = generate_cli_arguments(config)

            eprint("\nTo use this configuration, run:")
            eprint("─" * 40)
            eprint(f"crypt_cli encrypt --input <file> {' '.join(cli_args)}")
            eprint("\nOr save these settings to a template file for reuse.")

        return config

    except KeyboardInterrupt:
        if not quiet:
            eprint("\n\nConfiguration wizard cancelled.")
        return None
    except Exception as e:
        eprint(f"Error running configuration wizard: {e}")
        return None


def _build_analysis_config(args):
    """Translate analyze-config argv into the dict the analyzer reads.

    ``ConfigurationAnalyzer`` reads a different set of key names than the
    analyze-config parser produces (``pbkdf2_iterations`` vs ``pbkdf2_rounds``,
    ``argon2_memory`` vs ``argon2_memory_cost``, ``enable_scrypt`` /
    ``enable_balloon`` / ``enable_hkdf`` which the parser never defines, and
    ``algorithm`` vs ``encryption_data_algorithm``), so feeding it ``vars(args)``
    scored the flags the user passed as absent (gitlab#168). This renames each
    flag to the key the analyzer reads and derives the missing ``enable_*``
    booleans from a positive cost, so a passed flag actually moves the score.

    It is also a whitelist: only analysis inputs are copied, never the live
    ``Namespace.__dict__`` (which the old ``vars(args)`` aliased and then
    mutated, and which on the monolithic entry can carry secret-valued
    attributes), so no secret can ride along into a future ``eprint(config)``.
    Sub-parameters are only set when explicitly given, so the analyzer's own
    defaults fire for the rest rather than being duplicated here.
    """

    def _int(name):
        try:
            return int(getattr(args, name, 0) or 0)
        except (TypeError, ValueError):
            return 0

    config = {}

    # Hash rounds -- the analyzer reads "<name>_rounds" directly, same dests.
    for name in ("sha256", "sha512", "blake2b", "blake3"):
        config[f"{name}_rounds"] = _int(f"{name}_rounds")

    # PBKDF2: parser dest pbkdf2_rounds -> analyzer key pbkdf2_iterations.
    if _int("pbkdf2_rounds") > 0:
        config["pbkdf2_iterations"] = _int("pbkdf2_rounds")

    # Argon2: an explicit --enable-argon2 flag; *_cost dests -> *_memory/*_time.
    if bool(getattr(args, "enable_argon2", False)):
        config["enable_argon2"] = True
        if _int("argon2_memory_cost") > 0:
            config["argon2_memory"] = _int("argon2_memory_cost")
        if _int("argon2_time_cost") > 0:
            config["argon2_time"] = _int("argon2_time_cost")
        if _int("argon2_parallelism") > 0:
            config["argon2_parallelism"] = _int("argon2_parallelism")

    # Scrypt/Balloon/HKDF have no --enable flag; a positive cost IS the signal.
    if _int("scrypt_n") > 0:
        config["enable_scrypt"] = True
        config["scrypt_n"] = _int("scrypt_n")
        if _int("scrypt_r") > 0:
            config["scrypt_r"] = _int("scrypt_r")
        if _int("scrypt_p") > 0:
            config["scrypt_p"] = _int("scrypt_p")

    balloon_space = _int("balloon_space_cost")
    balloon_time = _int("balloon_time_cost")
    if balloon_space > 0 or balloon_time > 0:
        config["enable_balloon"] = True
        if balloon_space > 0:
            config["balloon_space_cost"] = balloon_space
        if balloon_time > 0:
            config["balloon_time_cost"] = balloon_time

    if _int("hkdf_rounds") > 0:
        config["enable_hkdf"] = True
        config["hkdf_rounds"] = _int("hkdf_rounds")

    # Cipher: parser dest encryption_data_algorithm -> analyzer key algorithm.
    config["algorithm"] = getattr(args, "encryption_data_algorithm", None) or "aes-gcm"

    # PQC: the analyzer reads pqc_algorithm directly (it already treats the
    # argparse default "none" as absent, gitlab#166).
    config["pqc_algorithm"] = getattr(args, "pqc_algorithm", None)

    # Context for use-case-aware analysis.
    config["use_case"] = getattr(args, "use_case", None)

    return config


def run_config_analyzer(args):
    """
    Run configuration analysis and display detailed results.

    Args:
        args: Parsed command line arguments
    """
    try:
        quiet = getattr(args, "quiet", False)
        use_case = getattr(args, "use_case", None)
        output_format = getattr(args, "output_format", "text")
        compliance_frameworks = getattr(args, "compliance_frameworks", None)

        if not quiet and output_format == "text":
            eprint("Analyzing Configuration...")
            eprint("Performing comprehensive security and performance analysis.\n")

        # Translate argv into the analyzer's key names, as an explicit
        # whitelisted copy (not the live namespace); see _build_analysis_config.
        config = _build_analysis_config(args)

        # Add compliance requirements if specified
        if compliance_frameworks:
            config["compliance_requirements"] = compliance_frameworks

        # Run the analysis
        analyzer = ConfigurationAnalyzer()
        analysis = analyzer.analyze_configuration(config, use_case, compliance_frameworks)

        if output_format == "json":
            _display_json_results(analysis)
        elif not quiet:
            _display_analysis_results(analysis)

        return analysis

    except Exception as e:
        eprint(f"Error analyzing configuration: {e}")
        sys.exit(1)


def _display_analysis_results(analysis):
    """Display formatted analysis results."""

    eprint("=" * 60)
    eprint("CONFIGURATION ANALYSIS RESULTS")
    eprint("=" * 60)
    eprint()

    # Overall Summary
    eprint("📊 OVERALL ASSESSMENT")
    eprint("─" * 30)
    eprint(f"Security Score: {analysis.overall_score:.1f}/10.0")
    eprint(f"Security Level: {analysis.security_level.name}")
    eprint(f"Analysis Time: {analysis.analysis_timestamp}")
    eprint()

    # Configuration Summary
    eprint("⚙️  CONFIGURATION SUMMARY")
    eprint("─" * 30)
    summary = analysis.configuration_summary
    eprint(f"Algorithm: {summary['algorithm']}")
    eprint(f"Hash Functions: {', '.join(summary['active_hash_functions']) or 'None'}")
    eprint(f"Key Derivation: {', '.join(summary['active_kdfs']) or 'None'}")
    eprint(f"Post-Quantum: {'Yes' if summary['post_quantum_enabled'] else 'No'}")
    eprint(f"Complexity: {summary['configuration_complexity'].title()}")
    eprint(f"Suitable For: {', '.join(summary['suitable_for'])}")
    eprint()

    # Performance Assessment
    eprint("🚀 PERFORMANCE ASSESSMENT")
    eprint("─" * 30)
    perf = analysis.performance_assessment
    eprint(f"Overall Score: {perf['overall_score']:.1f}/10.0")
    eprint(f"Speed Rating: {perf['estimated_relative_speed'].replace('_', ' ').title()}")
    eprint(
        f"Memory Usage: {perf['memory_requirements']['estimated_peak_mb']}MB ({perf['memory_requirements']['classification']})"
    )
    eprint(f"CPU Intensity: {perf['cpu_intensity'].replace('_', ' ').title()}")
    eprint()

    # Compatibility
    eprint("🔗 COMPATIBILITY")
    eprint("─" * 30)
    compat = analysis.compatibility_matrix
    eprint(f"Overall Score: {compat['overall_compatibility_score']:.1f}/10.0")

    platform_issues = [p for p, status in compat["platform_compatibility"].items() if not status]
    if platform_issues:
        eprint(f"Platform Limitations: {', '.join(platform_issues)}")
    else:
        eprint("Platform Support: Universal")

    library_issues = [lib for lib, status in compat["library_compatibility"].items() if not status]
    if library_issues:
        eprint(f"Library Limitations: {', '.join(library_issues)}")
    else:
        eprint("Library Support: Excellent")
    eprint()

    # Future Proofing
    eprint("🔮 FUTURE PROOFING")
    eprint("─" * 30)
    future = analysis.future_proofing
    eprint(f"Algorithm Longevity: {future['algorithm_longevity_score']:.1f}/10.0")
    eprint(f"Key Size Adequacy: {future['key_size_adequacy_score']:.1f}/10.0")
    eprint(f"Quantum Resistant: {'Yes' if future['post_quantum_ready'] else 'No'}")
    eprint(f"Estimated Secure: {future['estimated_secure_years']}")
    eprint()

    # Compliance Status
    if analysis.compliance_status:
        eprint("📋 COMPLIANCE STATUS")
        eprint("─" * 30)
        for framework, status in analysis.compliance_status.items():
            framework_name = framework.replace("_", " ").title()
            compliance_status = "✅ Compliant" if status["compliant"] else "❌ Non-Compliant"
            eprint(f"{framework_name}: {compliance_status}")

            if status.get("issues"):
                for issue in status["issues"]:
                    eprint(f"  • {issue}")
        eprint()

    # Recommendations
    if analysis.recommendations:
        eprint("💡 RECOMMENDATIONS")
        eprint("─" * 30)

        # Group recommendations by priority
        by_priority = {}
        for rec in analysis.recommendations:
            priority = rec.priority.value
            if priority not in by_priority:
                by_priority[priority] = []
            by_priority[priority].append(rec)

        # Display by priority
        priority_icons = {
            "critical": "🚨",
            "high": "⚠️",
            "medium": "💡",
            "low": "ℹ️",
            "info": "📝",
        }

        for priority in ["critical", "high", "medium", "low", "info"]:
            if priority in by_priority:
                recommendations = by_priority[priority]
                eprint(f"\n{priority_icons[priority]} {priority.upper()} PRIORITY:")

                for i, rec in enumerate(recommendations, 1):
                    eprint(f"\n{i}. {rec.title}")
                    eprint(f"   Category: {rec.category.value.replace('_', ' ').title()}")
                    eprint(f"   Issue: {rec.description}")
                    eprint(f"   Action: {rec.action}")
                    eprint(f"   Impact: {rec.impact}")

                    if rec.applies_to and rec.applies_to != ["all"]:
                        eprint(f"   Applies To: {', '.join(rec.applies_to)}")
    else:
        eprint("💡 RECOMMENDATIONS")
        eprint("─" * 30)
        eprint("✅ No specific recommendations - configuration looks good!")

    eprint()
    eprint("=" * 60)
    eprint("Analysis complete. Use recommendations above to enhance your configuration.")
    eprint("=" * 60)


def _display_json_results(analysis):
    """Display analysis results in JSON format."""
    import json
    from dataclasses import asdict

    # Convert analysis to dictionary, handling enum values
    def convert_analysis(obj):
        if hasattr(obj, "__dataclass_fields__"):
            return asdict(obj)
        elif hasattr(obj, "value"):  # Enum
            return obj.value
        elif hasattr(obj, "name"):  # Enum
            return obj.name
        return obj

    # Convert the analysis object to a dictionary
    result_dict = {
        "overall_score": analysis.overall_score,
        "security_level": analysis.security_level.name,
        "analysis_timestamp": analysis.analysis_timestamp,
        "configuration_summary": analysis.configuration_summary,
        "performance_assessment": analysis.performance_assessment,
        "compatibility_matrix": analysis.compatibility_matrix,
        "compliance_status": analysis.compliance_status,
        "future_proofing": analysis.future_proofing,
        "recommendations": [],
    }

    # Convert recommendations
    for rec in analysis.recommendations:
        rec_dict = {
            "category": rec.category.value,
            "priority": rec.priority.value,
            "title": rec.title,
            "description": rec.description,
            "action": rec.action,
            "impact": rec.impact,
            "rationale": rec.rationale,
            "applies_to": rec.applies_to,
        }
        result_dict["recommendations"].append(rec_dict)

    # Output JSON
    print(json.dumps(result_dict, indent=2, ensure_ascii=False))


def run_template_manager(args):
    """Run template management operations."""
    try:
        template_mgr = TemplateManager()
        subcommand = getattr(args, "template_action", None)

        if subcommand == "list":
            _handle_template_list(template_mgr, args)
        elif subcommand == "create":
            _handle_template_create(template_mgr, args)
        elif subcommand == "analyze":
            _handle_template_analyze(template_mgr, args)
        elif subcommand == "compare":
            _handle_template_compare(template_mgr, args)
        elif subcommand == "recommend":
            _handle_template_recommend(template_mgr, args)
        elif subcommand == "delete":
            _handle_template_delete(template_mgr, args)
        else:
            eprint("Invalid template subcommand. Use --help for available options.")
            # Previously fell through to an unconditional sys.exit(0) at the
            # dispatch, so a mistyped subcommand reported success (gitlab#167).
            return 1

    except Exception as e:
        eprint(f"Error in template management: {e}")
        return 1

    return 0


def run_smart_recommendations(args):
    """Run smart recommendations system."""
    try:
        from .smart_recommendations import SmartRecommendationEngine

        engine = SmartRecommendationEngine()
        subcommand = getattr(args, "recommendations_action", None)

        if subcommand == "get":
            _handle_recommendations_get(engine, args)
        elif subcommand == "profile":
            _handle_recommendations_profile(engine, args)
        elif subcommand == "feedback":
            _handle_recommendations_feedback(engine, args)
        elif subcommand == "quick":
            _handle_recommendations_quick(engine, args)
        else:
            eprint("Invalid smart recommendations subcommand. Use --help for available options.")

    except Exception as e:
        eprint(f"Error in smart recommendations: {e}")
        sys.exit(1)


def _handle_recommendations_get(engine, args):
    """Handle get recommendations command."""
    from .smart_recommendations import UserContext

    # Build user context from arguments
    user_context = UserContext()

    # Apply provided arguments
    if hasattr(args, "user_type") and args.user_type:
        user_context.user_type = args.user_type
    if hasattr(args, "experience_level") and args.experience_level:
        user_context.experience_level = args.experience_level
    if hasattr(args, "use_cases") and args.use_cases:
        user_context.primary_use_cases = args.use_cases
    if hasattr(args, "data_sensitivity") and args.data_sensitivity:
        user_context.data_sensitivity = args.data_sensitivity
    if hasattr(args, "performance_priority") and args.performance_priority:
        user_context.performance_priority = args.performance_priority
    if hasattr(args, "compliance_requirements") and args.compliance_requirements:
        user_context.compliance_requirements = args.compliance_requirements

    # Load existing user profile if available
    user_id = getattr(args, "user_id", "default")
    saved_context = engine.load_user_context(user_id)
    if saved_context:
        # Merge saved context with provided arguments
        if not hasattr(args, "user_type") or not args.user_type:
            user_context.user_type = saved_context.user_type
        if not hasattr(args, "experience_level") or not args.experience_level:
            user_context.experience_level = saved_context.experience_level
        if not hasattr(args, "use_cases") or not args.use_cases:
            user_context.primary_use_cases = saved_context.primary_use_cases
        user_context.preferred_algorithms = saved_context.preferred_algorithms
        user_context.avoided_algorithms = saved_context.avoided_algorithms
        user_context.feedback_history = saved_context.feedback_history

    # Get current configuration if available
    current_config = None
    if hasattr(args, "analyze_current") and args.analyze_current:
        # Try to analyze current configuration from args
        try:
            current_config = vars(args)
        except Exception:
            pass

    # Generate recommendations
    recommendations = engine.generate_recommendations(user_context, current_config)

    # Machine-readable document on stdout so a GUI reads the recommendation
    # list instead of scraping the unversioned human report (gitlab#162).
    if getattr(args, "output_format", "text") == "json":
        import json

        print(
            json.dumps(
                {"recommendations": [_recommendation_to_dict(r) for r in recommendations]},
                indent=2,
                ensure_ascii=False,
                default=str,
            )
        )
        engine.save_user_context(user_id, user_context)
        return

    # Display recommendations
    eprint("🧠 SMART RECOMMENDATIONS")
    eprint("=" * 50)
    eprint()

    if not recommendations:
        eprint("No specific recommendations at this time.")
        eprint("Your current configuration appears to be well-optimized!")
        return

    for i, rec in enumerate(recommendations, 1):
        _display_recommendation(rec, i)

    # Save updated context
    engine.save_user_context(user_id, user_context)


def _handle_recommendations_profile(engine, args):
    """Handle profile management command."""
    from .smart_recommendations import UserContext

    user_id = getattr(args, "user_id", "default")

    if hasattr(args, "create") and args.create:
        # Create new profile
        user_context = UserContext()

        eprint("Creating new user profile...")
        eprint("Please answer the following questions to personalize your recommendations:")
        eprint()

        # Interactive profile creation
        user_context.user_type = (
            prompt_and_read("User type [personal/business/developer/compliance]: ").strip()
            or "personal"
        )
        user_context.experience_level = (
            prompt_and_read("Experience level [beginner/intermediate/advanced/expert]: ").strip()
            or "intermediate"
        )

        use_cases_str = prompt_and_read(
            "Primary use cases (comma-separated) [personal/business/compliance/archival]: "
        ).strip()
        if use_cases_str:
            user_context.primary_use_cases = [uc.strip() for uc in use_cases_str.split(",")]
        else:
            user_context.primary_use_cases = ["personal"]

        user_context.data_sensitivity = (
            prompt_and_read("Data sensitivity [low/medium/high/top_secret]: ").strip() or "medium"
        )
        user_context.performance_priority = (
            prompt_and_read("Performance priority [speed/security/balanced]: ").strip()
            or "balanced"
        )

        compliance_str = prompt_and_read(
            "Compliance requirements (comma-separated) [fips_140_2/common_criteria/nist_guidelines]: "
        ).strip()
        if compliance_str:
            user_context.compliance_requirements = [
                req.strip() for req in compliance_str.split(",")
            ]

        engine.save_user_context(user_id, user_context)
        eprint(f"\n✅ Profile '{user_id}' created successfully!")

    elif hasattr(args, "show") and args.show:
        # Show existing profile
        user_context = engine.load_user_context(user_id)
        if not user_context:
            eprint(f"❌ No profile found for user '{user_id}'")
            return

        eprint(f"👤 USER PROFILE: {user_id}")
        eprint("=" * 40)
        eprint(f"User Type: {user_context.user_type}")
        eprint(f"Experience Level: {user_context.experience_level}")
        eprint(f"Primary Use Cases: {', '.join(user_context.primary_use_cases)}")
        eprint(f"Data Sensitivity: {user_context.data_sensitivity}")
        eprint(f"Performance Priority: {user_context.performance_priority}")
        if user_context.compliance_requirements:
            eprint(f"Compliance Requirements: {', '.join(user_context.compliance_requirements)}")
        if user_context.preferred_algorithms:
            eprint(f"Preferred Algorithms: {', '.join(user_context.preferred_algorithms)}")
        if user_context.avoided_algorithms:
            eprint(f"Avoided Algorithms: {', '.join(user_context.avoided_algorithms)}")
        eprint()


def _handle_recommendations_feedback(engine, args):
    """Handle feedback submission."""
    user_id = getattr(args, "user_id", "default")
    rec_id = args.recommendation_id
    accepted = args.accepted
    feedback_text = getattr(args, "comment", None)

    engine.record_feedback(user_id, rec_id, accepted, feedback_text)

    status = "accepted" if accepted else "rejected"
    eprint(f"✅ Feedback recorded: Recommendation {rec_id} was {status}")
    if feedback_text:
        eprint(f"Comment: {feedback_text}")


def _recommendation_to_dict(rec):
    """Convert a SmartRecommendation dataclass to a JSON-serialisable dict.

    Its category/priority/confidence fields are enums; everything else is
    already a primitive/list/dict (gitlab#162).
    """
    from dataclasses import asdict

    d = asdict(rec)
    for key in ("category", "priority", "confidence"):
        value = d.get(key)
        if hasattr(value, "value"):
            d[key] = value.value
        elif hasattr(value, "name"):
            d[key] = value.name
    return d


def _handle_recommendations_quick(engine, args):
    """Handle quick recommendations command."""
    use_case = args.use_case
    experience_level = getattr(args, "experience_level", "intermediate")

    quick_recs = engine.get_quick_recommendations(use_case, experience_level)

    # Machine-readable document on stdout so a GUI reads the recommendation
    # list instead of scraping the unversioned human report (gitlab#162).
    if getattr(args, "output_format", "text") == "json":
        import json

        print(
            json.dumps(
                {
                    "use_case": use_case,
                    "experience_level": experience_level,
                    "recommendations": quick_recs,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return

    eprint(f"⚡ QUICK RECOMMENDATIONS FOR {use_case.upper()}")
    eprint("=" * 50)
    eprint()

    for rec in quick_recs:
        eprint(rec)
        eprint()

    eprint("💬 For detailed recommendations with explanations, use 'smart-recommendations get'")


def _display_recommendation(rec, number: int):
    """Display a single recommendation with formatting."""
    # Priority icon
    priority_icons = {
        "info": "ℹ️",
        "low": "🔷",
        "medium": "🔶",
        "high": "🔺",
        "critical": "🚨",
    }

    # Confidence indicator
    confidence_indicators = {
        1: "⭐",
        2: "⭐⭐",
        3: "⭐⭐⭐",
        4: "⭐⭐⭐⭐",
        5: "⭐⭐⭐⭐⭐",
    }

    priority_icon = priority_icons.get(rec.priority.value, "🔷")
    confidence_stars = confidence_indicators.get(rec.confidence.value, "⭐⭐⭐")

    eprint(f"{number}. {priority_icon} {rec.title}")
    eprint(f"   📝 {rec.description}")
    eprint(f"   💡 Action: {rec.action}")
    eprint(
        f"   🎯 Confidence: {confidence_stars} | Difficulty: {rec.implementation_difficulty} | Impact: {rec.estimated_impact}"
    )

    if rec.reasoning:
        eprint(f"   🤔 Reasoning: {rec.reasoning}")

    if rec.evidence:
        eprint("   📊 Evidence:")
        for evidence in rec.evidence:
            eprint(f"      • {evidence}")

    if rec.trade_offs:
        eprint("   ⚖️  Trade-offs:")
        for aspect, impact in rec.trade_offs.items():
            eprint(f"      • {aspect.title()}: {impact}")

    eprint(f"   🏷️  Category: {rec.category.value} | ID: {rec.id}")
    eprint()


def run_security_tests(args):
    """Run security test suites."""
    try:
        from .testing import SecurityTestRunner, TestExecutionPlan, TestSuiteType

        # Create test runner
        runner = SecurityTestRunner()

        # Get test action
        test_action = getattr(args, "test_action", None)

        if not test_action:
            eprint("No test action specified. Use --help for available options.")
            return

        # Build execution plan
        suite_types = []

        if test_action == "fuzz":
            suite_types = [TestSuiteType.FUZZ]
        elif test_action == "side-channel":
            suite_types = [TestSuiteType.SIDE_CHANNEL]
        elif test_action == "kat":
            suite_types = [TestSuiteType.KAT]
        elif test_action == "benchmark":
            suite_types = [TestSuiteType.BENCHMARK]
        elif test_action == "memory":
            suite_types = [TestSuiteType.MEMORY]
        elif test_action == "all":
            suite_types = [TestSuiteType.ALL]
        else:
            eprint(f"Unknown test action: {test_action}")
            return

        # Build configuration from arguments
        config = {}

        # Common configuration
        if hasattr(args, "algorithm") and args.algorithm:
            config["algorithm"] = args.algorithm

        if hasattr(args, "iterations") and args.iterations:
            config["benchmark_iterations"] = args.iterations

        if hasattr(args, "seed") and args.seed:
            config["seed"] = args.seed

        if hasattr(args, "timing_threshold") and args.timing_threshold:
            config["timing_threshold"] = args.timing_threshold

        if hasattr(args, "test_iterations") and args.test_iterations:
            config["memory_test_iterations"] = args.test_iterations

        if hasattr(args, "leak_threshold") and args.leak_threshold:
            config["leak_threshold"] = args.leak_threshold

        if hasattr(args, "test_category") and args.test_category:
            config["test_category"] = args.test_category

        if hasattr(args, "algorithms") and args.algorithms:
            config["algorithms"] = args.algorithms

        if hasattr(args, "file_sizes") and args.file_sizes:
            config["file_sizes"] = args.file_sizes

        if hasattr(args, "save_baseline") and args.save_baseline:
            config["save_baseline"] = True

        # Output configuration
        output_formats = getattr(args, "output_format", ["json", "html"])
        output_dir = getattr(args, "output_dir", None)

        # Parallel execution for "all" tests
        parallel = getattr(args, "parallel", False) if test_action == "all" else False
        max_workers = getattr(args, "max_workers", 3)

        # Create execution plan
        execution_plan = TestExecutionPlan(
            suite_types=suite_types,
            parallel_execution=parallel,
            max_workers=max_workers,
            config=config,
            output_formats=output_formats,
            output_directory=output_dir,
        )

        # Set up logging
        if not getattr(args, "quiet", False):
            import logging

            logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

        # Run tests
        eprint(f"🔒 Starting OpenSSL Encrypt Security Tests - {test_action.upper()}")
        eprint("=" * 60)
        eprint()

        report = runner.run_tests(execution_plan)

        # Display summary
        eprint("\n" + "=" * 60)
        eprint("📊 TEST SUMMARY")
        eprint("=" * 60)

        summary = report.overall_summary
        eprint(f"Total Suites: {summary['total_suites']}")
        eprint(f"Successful Suites: {summary['successful_suites']}")
        eprint(f"Suite Success Rate: {summary['suite_success_rate']:.1f}%")
        eprint(f"Total Tests: {summary['total_tests']}")
        eprint(f"Passed Tests: {summary['passed_tests']}")
        eprint(f"Warning Tests: {summary['warning_tests']}")
        eprint(f"Failed Tests: {summary['error_tests']}")
        eprint(f"Test Success Rate: {summary['test_success_rate']:.1f}%")
        eprint(f"Total Duration: {report.total_duration:.1f} seconds")

        # Show report locations
        if output_dir:
            eprint(f"\n📁 Reports saved to: {output_dir}")
            for fmt in output_formats:
                filename = f"security_test_report_{report.run_id}.{fmt}"
                eprint(f"   • {fmt.upper()}: {filename}")

        eprint("\n✅ Testing completed!")

    except ImportError as e:
        eprint(f"Error: Testing framework not available: {e}")
        sys.exit(1)
    except Exception as e:
        eprint(f"Error running security tests: {e}")
        if hasattr(args, "debug") and args.debug:
            import traceback

            traceback.print_exc()
        sys.exit(1)


def _template_list_payload(templates):
    """Build the `template list --format json` entries.

    Every string here originates in a template file, which is any .json/.yaml
    a local process can drop into the template directory, so each field is
    coerced to the expected type and bounded. One malformed file must not fail
    the whole listing -- list_templates() already skips files it cannot load,
    and this keeps that property.
    """

    def _text(value, limit=256):
        return str(value)[:limit] if isinstance(value, (str, int, float)) else ""

    def _texts(value, limit=32):
        return [_text(v, 64) for v in value[:limit]] if isinstance(value, list) else []

    payload = []
    for template in templates[:256]:
        try:
            payload.append(
                {
                    "name": _text(template.metadata.name),
                    "description": _text(template.metadata.description, 1024),
                    "use_cases": _texts(template.metadata.use_cases),
                    "tags": _texts(template.metadata.tags),
                    "built_in": bool(template.is_built_in),
                }
            )
        except Exception:  # noqa: BLE001 - one bad file must not kill the list
            continue
    return payload


def _template_compare_payload(comparison):
    """Build the `template compare --format json` document.

    Same file-origin discipline as `_template_list_payload`: every
    template-declared string comes from a file any local process can drop in,
    so each is coerced and bounded. The self-asserted `security_score` /
    `security_level` and their raw difference are NOT published -- they are read
    verbatim from the file, and handing an untrusted number to an automated
    consumer as an authoritative rating is the wrong direction (gitlab#169). The
    derived verdicts answer the comparison instead (the performance verdict is
    analyzer-computed, not self-asserted).
    """

    def _text(value, limit=512):
        return str(value)[:limit] if isinstance(value, (str, int, float)) else ""

    def _texts(value, limit=32):
        return [str(v)[:64] for v in value[:limit]] if isinstance(value, list) else []

    comparison = comparison if isinstance(comparison, dict) else {}
    templates = comparison.get("templates", {})
    templates = templates if isinstance(templates, dict) else {}

    def _tmpl(key):
        entry = templates.get(key, {})
        entry = entry if isinstance(entry, dict) else {}
        return {"name": _text(entry.get("name"), 256), "use_cases": _texts(entry.get("use_cases"))}

    sec = comparison.get("security_comparison", {})
    sec = sec if isinstance(sec, dict) else {}
    perf = comparison.get("performance_comparison", {})
    perf = perf if isinstance(perf, dict) else {}
    # Each verdict is labelled with its trust basis so a machine consumer can
    # tell them apart: the security verdict is DERIVED from the templates'
    # self-asserted (file-declared) scores -- no raw number is published, but
    # the verdict must not read as an authoritative rating (gitlab#169) -- while
    # the performance verdict is analyzer-computed.
    return {
        "template1": _tmpl("template1"),
        "template2": _tmpl("template2"),
        "security_comparison": {
            "verdict": _text(sec.get("verdict")),
            "basis": "template_declared",
        },
        "performance_comparison": {
            "verdict": _text(perf.get("verdict")),
            "basis": "analyzer_computed",
        },
    }


def _handle_template_list(template_mgr: TemplateManager, args):
    """Handle template list command."""
    # `template list` declares --use-case (personal/business/compliance/archival),
    # not --category; the handler read a `category` attribute the parser never
    # sets, so the filter was silently ignored (gitlab#169). Filter by the
    # template's declared use-cases instead -- TemplateCategory is a disjoint
    # domain (built_in/user_created/...), so it cannot be the filter here.
    use_case = getattr(args, "use_case", None)
    templates = template_mgr.list_templates()
    if use_case:
        templates = [t for t in templates if use_case in (t.metadata.use_cases or [])]

    if getattr(args, "format", "table") == "json":
        # --format was declared on this parser and never read, so a caller could
        # ask for JSON, get exit 0, and receive nothing (gitlab#167). stdout
        # carries the document; the human report stays on stderr.
        #
        # security_score / security_level are deliberately NOT published here.
        # For the metadata-bearing template format they are taken verbatim from
        # the file and never recomputed, and list_templates() sorts by that
        # value -- so a planted template claiming a top score would rank first
        # and be handed to an automated consumer as an authoritative rating
        # (gitlab#169). Publishing an untrusted number as a security rating is
        # the wrong direction to fix that in.
        print(json.dumps({"templates": _template_list_payload(templates)}, indent=2))
        try:
            sys.stdout.flush()
        except BrokenPipeError:  # pragma: no cover - `| head` and friends
            pass
        return

    if not templates:
        eprint("No templates found.")
        return

    eprint("📋 AVAILABLE TEMPLATES")
    eprint("=" * 50)
    eprint()

    current_category = None
    for template in templates:
        # Group by category
        if template.metadata.category != current_category:
            current_category = template.metadata.category
            eprint(f"\n🏷️  {current_category.value.upper().replace('_', ' ')}")
            eprint("-" * 30)

        # Display template info
        security_icon = _get_security_icon(template.metadata.security_level)
        eprint(f"\n{security_icon} {template.metadata.name}")
        eprint(f"   Description: {template.metadata.description}")
        eprint(
            f"   Security: {template.metadata.security_level} ({template.metadata.security_score:.1f}/10)"
        )
        if template.metadata.use_cases:
            eprint(f"   Use Cases: {', '.join(template.metadata.use_cases)}")
        if template.metadata.tags:
            eprint(f"   Tags: {', '.join(template.metadata.tags)}")

        if hasattr(args, "verbose") and args.verbose:
            eprint(f"   Author: {template.metadata.author}")
            eprint(f"   Created: {template.metadata.created_date}")
            if not template.is_built_in and template.file_path:
                eprint(f"   File: {template.file_path}")


def _handle_template_create(template_mgr: TemplateManager, args):
    """Handle template creation from current configuration."""
    # Parser dest is `name` (positional), not `template_name` -- reading the
    # wrong attribute made `template create` always exit 1 (gitlab#169).
    name = getattr(args, "name", None)
    if not name:
        eprint("Error: Template name is required for creation.")
        sys.exit(1)

    description = getattr(args, "description", "")
    use_cases = getattr(args, "use_cases", [])

    # Create template from current CLI args
    template = template_mgr.create_template_from_args(args, name, description, use_cases)

    # Validate template
    is_valid, errors = template_mgr.validate_template(template)
    if not is_valid:
        eprint("❌ Template validation failed:")
        for error in errors:
            eprint(f"   • {error}")
        sys.exit(1)

    # Save template
    try:
        output_format = TemplateFormat(getattr(args, "format", "json"))
        filepath = template_mgr.save_template(template, format=output_format)

        eprint("✅ Template created successfully!")
        eprint(f"📁 Saved to: {filepath}")
        eprint(
            f"🔒 Security Level: {template.metadata.security_level} ({template.metadata.security_score:.1f}/10)"
        )

        if use_cases:
            eprint(f"🎯 Use Cases: {', '.join(use_cases)}")

    except FileExistsError as e:
        eprint(f"❌ {e}")
        eprint("Use --overwrite to replace existing template.")
        sys.exit(1)


def _handle_template_analyze(template_mgr: TemplateManager, args):
    """Handle template analysis command."""
    # Parser dest is `template` (positional), not `template_name` -- reading the
    # wrong attribute made this subcommand always exit 1 (gitlab#169).
    template_name = getattr(args, "template", None)
    if not template_name:
        eprint("Error: Template name is required for analysis.")
        sys.exit(1)

    template = template_mgr.get_template_by_name(template_name)
    if not template:
        eprint(f"❌ Template '{template_name}' not found.")
        sys.exit(1)

    report = template_mgr.generate_template_report(template)

    eprint("🔍 TEMPLATE ANALYSIS REPORT")
    eprint("=" * 50)
    eprint(f"\n📋 Template: {template.metadata.name}")
    eprint(f"📝 Description: {template.metadata.description}")
    eprint(f"👤 Author: {template.metadata.author}")
    eprint(f"📅 Created: {template.metadata.created_date}")

    # Validation status
    validation = report["validation"]
    if validation["is_valid"]:
        eprint("\n✅ VALIDATION: PASSED")
    else:
        eprint("\n❌ VALIDATION: FAILED")
        for error in validation["errors"]:
            eprint(f"   • {error}")

    # Analysis results
    if "analysis" in report and "overall_score" in report["analysis"]:
        analysis = report["analysis"]
        security_icon = _get_security_icon(analysis["security_level"])

        eprint("\n🔒 SECURITY ANALYSIS")
        eprint(f"   {security_icon} Overall Score: {analysis['overall_score']:.1f}/10")
        eprint(f"   🛡️  Security Level: {analysis['security_level']}")

        if "performance" in analysis:
            perf = analysis["performance"]
            eprint("\n🚀 PERFORMANCE ANALYSIS")
            eprint(
                f"   ⚡ Speed Rating: {perf['estimated_relative_speed'].replace('_', ' ').title()}"
            )
            eprint(f"   💾 Memory Usage: {perf['memory_requirements']['estimated_peak_mb']}MB")
            eprint(f"   🖥️  CPU Intensity: {perf['cpu_intensity'].replace('_', ' ').title()}")

        if "recommendations" in analysis and analysis["recommendations"]:
            eprint("\n💡 RECOMMENDATIONS:")
            for i, rec in enumerate(analysis["recommendations"][:3], 1):  # Show top 3
                priority_icon = (
                    "🚨"
                    if rec["priority"] == "critical"
                    else "⚠️" if rec["priority"] == "high" else "💡"
                )
                eprint(f"   {i}. {priority_icon} {rec['title']}")
                eprint(f"      {rec['description']}")
                eprint(f"      Action: {rec['action']}")


def _handle_template_compare(template_mgr: TemplateManager, args):
    """Handle template comparison command."""
    template1_name = getattr(args, "template1", None)
    template2_name = getattr(args, "template2", None)

    if not template1_name or not template2_name:
        eprint("Error: Both template names are required for comparison.")
        sys.exit(1)

    template1 = template_mgr.get_template_by_name(template1_name)
    template2 = template_mgr.get_template_by_name(template2_name)

    if not template1:
        eprint(f"❌ Template '{template1_name}' not found.")
        sys.exit(1)
    if not template2:
        eprint(f"❌ Template '{template2_name}' not found.")
        sys.exit(1)

    comparison = template_mgr.compare_templates(template1, template2)

    if getattr(args, "format", "table") == "json":
        # --format was declared on this parser and never read, so a caller could
        # ask for JSON, get exit 0, and receive nothing (gitlab#167). stdout
        # carries the document; the human report stays on stderr.
        print(json.dumps(_template_compare_payload(comparison), indent=2))
        try:
            sys.stdout.flush()
        except BrokenPipeError:  # pragma: no cover - `| head` and friends
            pass
        return

    eprint("🔄 TEMPLATE COMPARISON")
    eprint("=" * 50)

    t1_data = comparison["templates"]["template1"]
    t2_data = comparison["templates"]["template2"]

    eprint("\n📊 OVERVIEW")
    eprint(
        f"   Template 1: {t1_data['name']} ({t1_data['security_level']}, {t1_data['security_score']:.1f}/10)"
    )
    eprint(
        f"   Template 2: {t2_data['name']} ({t2_data['security_level']}, {t2_data['security_score']:.1f}/10)"
    )

    eprint("\n🔒 SECURITY COMPARISON")
    eprint(f"   {comparison['security_comparison']['verdict']}")

    if "performance_comparison" in comparison:
        eprint("\n🚀 PERFORMANCE COMPARISON")
        eprint(f"   {comparison['performance_comparison']['verdict']}")

    # Use case comparison
    common_use_cases = set(t1_data["use_cases"]) & set(t2_data["use_cases"])
    if common_use_cases:
        eprint(f"\n🎯 COMMON USE CASES: {', '.join(common_use_cases)}")


def _handle_template_recommend(template_mgr: TemplateManager, args):
    """Handle template recommendation command."""
    use_case = getattr(args, "use_case", None)
    if not use_case:
        eprint("Error: Use case is required for recommendations.")
        sys.exit(1)

    recommendations = template_mgr.recommend_templates(use_case)

    if not recommendations:
        eprint(f"No template recommendations found for use case: {use_case}")
        return

    eprint(f"💡 TEMPLATE RECOMMENDATIONS FOR '{use_case.upper()}'")
    eprint("=" * 50)

    for i, (template, reason) in enumerate(recommendations, 1):
        security_icon = _get_security_icon(template.metadata.security_level)
        eprint(f"\n{i}. {security_icon} {template.metadata.name}")
        eprint(f"   📝 {template.metadata.description}")
        eprint(
            f"   🔒 Security: {template.metadata.security_level} ({template.metadata.security_score:.1f}/10)"
        )
        eprint(f"   ✨ Reason: {reason}")

        if template.is_built_in:
            eprint("   📦 Type: Built-in template")
        else:
            eprint(f"   📁 Type: {template.metadata.category.value.replace('_', ' ').title()}")


def _handle_template_delete(template_mgr: TemplateManager, args):
    """Handle template deletion command."""
    # Parser dest is `template` (positional), not `template_name` -- reading the
    # wrong attribute made this subcommand always exit 1 (gitlab#169).
    template_name = getattr(args, "template", None)
    if not template_name:
        eprint("Error: Template name is required for deletion.")
        sys.exit(1)

    template = template_mgr.get_template_by_name(template_name)
    if not template:
        eprint(f"❌ Template '{template_name}' not found.")
        sys.exit(1)

    if template.is_built_in:
        eprint(f"❌ Cannot delete built-in template '{template_name}'.")
        sys.exit(1)

    # Confirm deletion unless forced
    if not getattr(args, "force", False):
        confirm = prompt_and_read(
            f"⚠️  Are you sure you want to delete template '{template_name}'? [y/N]: "
        )
        if confirm.lower() != "y":
            eprint("Deletion cancelled.")
            return

    if template_mgr.delete_template(template):
        eprint(f"✅ Template '{template_name}' deleted successfully.")
    else:
        eprint(f"❌ Failed to delete template '{template_name}'.")
        sys.exit(1)


def _get_security_icon(security_level: str) -> str:
    """Get icon for security level."""
    icons = {
        "MINIMAL": "🟡",
        "LOW": "🟠",
        "MODERATE": "🟢",
        "GOOD": "🔵",
        "HIGH": "🟣",
        "VERY_HIGH": "🔴",
        "MAXIMUM": "⚫",
        "OVERKILL": "⚪",
        "THEORETICAL": "🌟",
        "EXTREME": "💎",
    }
    return icons.get(security_level, "🔒")


def handle_hsm_command(args):
    """
    Handle HSM (Hardware Security Module) management commands.

    Args:
        args: Parsed command-line arguments
    """
    import getpass
    import secrets

    # Determine action first so non-FIDO2 actions (e.g. onlykey-*) don't
    # require the fido2 library to be installed.
    action = args.hsm_action

    # FIDO2 plugin is only needed for fido2-* actions. Lazy-import to keep
    # onlykey-* actions usable on machines without fido2.
    plugin = None
    if action.startswith("fido2-"):
        try:
            from ..plugins.hsm.fido2_pepper import FIDO2_AVAILABLE, FIDO2HSMPlugin
        except ImportError:
            eprint("❌ Error: FIDO2 library not available")
            eprint("Install with: pip install fido2>=1.1.0")
            sys.exit(1)

        if not FIDO2_AVAILABLE:
            eprint("❌ Error: FIDO2 library not available")
            eprint("Install with: pip install fido2>=1.1.0")
            sys.exit(1)

        # Get optional rp_id
        rp_id = getattr(args, "rp_id", None)

        # Initialize plugin
        plugin = FIDO2HSMPlugin(rp_id=rp_id) if rp_id else FIDO2HSMPlugin()

    if action == "fido2-register":
        # Register new FIDO2 credential
        eprint("\n🔐 FIDO2 Credential Registration")
        eprint("=" * 50)

        description = getattr(args, "description", None)
        backup = getattr(args, "backup", False)

        if backup:
            eprint("📦 Registering backup credential...")
        else:
            eprint("🔑 Registering primary credential...")

        if description:
            eprint(f"Description: {description}")

        eprint("\nPlease insert your FIDO2 security key and follow the prompts.")
        eprint("You will need to:")
        eprint("  1. Touch your security key")
        eprint("  2. Enter your security key PIN (if configured)\n")

        # Initialize plugin
        init_result = plugin.initialize()
        if not init_result.success:
            eprint(f"❌ Error: {init_result.message}")
            sys.exit(1)

        # Register credential
        result = plugin.register_credential(description=description, is_backup=backup)

        if result.success:
            eprint(f"\n✅ {result.message}")
            eprint(f"\nCredential ID: {result.data.get('credential_id')}")
            eprint(f"Configuration saved to: {plugin.credential_file}")
            eprint("\nYou can now use this credential with:")
            eprint("  openssl_encrypt encrypt --hsm fido2 <file>")
        else:
            eprint(f"\n❌ Registration failed: {result.message}")
            sys.exit(1)

    elif action == "fido2-status":
        # Show FIDO2 registration status
        eprint("\n🔐 FIDO2 Registration Status")
        eprint("=" * 50)

        if not plugin.is_registered():
            eprint("❌ No FIDO2 credentials registered")
            eprint("\nTo register a credential, run:")
            eprint("  openssl_encrypt hsm fido2-register --description 'My Security Key'")
            sys.exit(0)

        # Load credentials
        credentials = plugin._load_credentials()

        eprint(f"✅ {len(credentials)} credential(s) registered")
        eprint(f"Configuration file: {plugin.credential_file}")
        eprint(f"Relying Party ID: {plugin.rp_id}\n")

        # Display each credential
        for i, cred in enumerate(credentials, 1):
            eprint(f"Credential #{i}:")
            eprint(f"  ID: {cred['id']}")
            eprint(f"  Description: {cred.get('description', 'N/A')}")
            eprint(f"  Created: {cred.get('created_at', 'N/A')}")
            eprint(f"  AAGUID: {cred.get('authenticator_aaguid', 'N/A')}")
            eprint(f"  Backup: {'Yes' if cred.get('is_backup', False) else 'No'}")
            eprint()

    elif action == "fido2-test":
        # Test FIDO2 pepper derivation
        eprint("\n🔐 FIDO2 Pepper Derivation Test")
        eprint("=" * 50)

        # Initialize plugin
        init_result = plugin.initialize()
        if not init_result.success:
            eprint(f"❌ Error: {init_result.message}")
            sys.exit(1)

        if not plugin.is_registered():
            eprint("❌ No FIDO2 credentials registered")
            eprint("\nRegister a credential first:")
            eprint("  openssl_encrypt hsm fido2-register")
            sys.exit(1)

        # Generate random test salt
        test_salt = secrets.token_bytes(16)
        eprint(f"Test salt: {test_salt.hex()}")
        eprint("\nPlease insert your FIDO2 security key and follow the prompts.")
        eprint("You will need to:")
        eprint("  1. Touch your security key")
        eprint("  2. Enter your security key PIN (if configured)\n")

        # Create dummy security context
        from ..modules.plugin_system.plugin_base import PluginSecurityContext

        context = PluginSecurityContext(
            plugin_id=plugin.plugin_id, capabilities=plugin.get_required_capabilities()
        )

        # Test pepper derivation
        result = plugin.get_hsm_pepper(test_salt, context)

        if result.success:
            pepper = result.data.get("hsm_pepper")
            eprint("\n✅ Test successful!")
            # Do NOT print the pepper itself — it is key material / a KDF
            # intermediate (H1 [HSM-1], gitlab#121). The length + success
            # confirm the derivation works; the value must never reach output.
            eprint(f"Pepper length: {len(pepper)} bytes")
            eprint("\nYour FIDO2 credential is working correctly.")
        else:
            eprint(f"\n❌ Test failed: {result.message}")
            sys.exit(1)

    elif action == "fido2-list":
        # List connected FIDO2 devices
        eprint("\n🔐 Connected FIDO2 Devices")
        eprint("=" * 50)

        devices = plugin.list_devices()

        if not devices:
            eprint("❌ No FIDO2 devices found")
            eprint("\nPlease connect a FIDO2 security key (YubiKey, Nitrokey, etc.)")
            sys.exit(0)

        eprint(f"Found {len(devices)} device(s):\n")

        for i, device in enumerate(devices, 1):
            if "error" in device:
                eprint(f"Device #{i}: {device.get('product_name', 'Unknown')}")
                eprint(f"  Error: {device['error']}\n")
                continue

            eprint(f"Device #{i}: {device.get('product_name', 'Unknown')}")
            eprint(f"  Manufacturer: {device.get('manufacturer', 'Unknown')}")
            eprint(f"  AAGUID: {device.get('aaguid', 'Unknown')}")
            eprint(f"  Versions: {', '.join(device.get('versions', []))}")
            eprint(f"  Extensions: {', '.join(device.get('extensions', []))}")

            # Highlight hmac-secret support
            hmac_support = device.get("hmac_secret_support", False)
            if hmac_support:
                eprint("  hmac-secret: ✅ Supported")
            else:
                eprint("  hmac-secret: ❌ Not supported")

            eprint()

    elif action == "fido2-unregister":
        # Remove FIDO2 credential(s)
        eprint("\n🔐 FIDO2 Credential Removal")
        eprint("=" * 50)

        if not plugin.is_registered():
            eprint("❌ No FIDO2 credentials registered")
            sys.exit(0)

        credential_id = getattr(args, "credential_id", None)
        remove_all = getattr(args, "remove_all", False)
        skip_confirmation = getattr(args, "yes", False)

        # Confirmation prompt (unless --yes flag is used)
        if not skip_confirmation:
            if remove_all:
                prompt = "Are you sure you want to remove ALL FIDO2 credentials? This cannot be undone. (y/N): "
            else:
                target = credential_id or "primary"
                prompt = f"Are you sure you want to remove credential '{target}'? This cannot be undone. (y/N): "

            confirmation = prompt_and_read(prompt).strip().lower()
            if confirmation != "y":
                eprint("Operation cancelled.")
                sys.exit(0)

        # Unregister
        result = plugin.unregister(credential_id=credential_id, remove_all=remove_all)

        if result.success:
            eprint(f"\n✅ {result.message}")

            if remove_all:
                eprint(f"Configuration file removed: {plugin.credential_file}")
            else:
                eprint(f"Configuration updated: {plugin.credential_file}")
        else:
            eprint(f"\n❌ Removal failed: {result.message}")
            sys.exit(1)

    elif action == "onlykey-list":
        # List connected OnlyKey devices (USB VID 0x1d50:0x60fc).
        from ..plugins.hsm.onlykey_challenge_response import OnlykeyHSMPlugin

        ok_plugin = OnlykeyHSMPlugin()

        eprint("\n🔐 Connected OnlyKey Devices")
        eprint("=" * 50)

        try:
            devices = ok_plugin._list_onlykey_devices()
        except Exception as e:
            eprint(f"❌ Error enumerating OnlyKey devices: {e}")
            sys.exit(1)

        if not devices:
            eprint("❌ No OnlyKey devices found")
            eprint(
                "\nPlease connect an OnlyKey and ensure it is unlocked "
                "(enter PIN on device buttons)."
            )
            eprint(
                f"\nExpected USB IDs: VID 0x{ok_plugin.ONLYKEY_VID:04x}, "
                f"PID 0x{ok_plugin.ONLYKEY_PID:04x}"
            )
            sys.exit(0)

        eprint(f"Found {len(devices)} OnlyKey device(s):\n")
        for i, device in enumerate(devices, 1):
            # OtpYubiKeyDevice exposes .path on Linux/macOS/Windows
            path = getattr(device, "path", "<unknown>")
            eprint(f"Device #{i}: {path}")
            eprint(
                f"  USB IDs: VID 0x{ok_plugin.ONLYKEY_VID:04x}, "
                f"PID 0x{ok_plugin.ONLYKEY_PID:04x}"
            )
            eprint()

    elif action == "onlykey-test":
        # Test OnlyKey Challenge-Response pepper derivation.
        from ..plugins.hsm.onlykey_challenge_response import OnlykeyHSMPlugin
        from .plugin_system.plugin_base import PluginSecurityContext

        ok_plugin = OnlykeyHSMPlugin()

        eprint("\n🔐 OnlyKey Pepper Derivation Test")
        eprint("=" * 50)

        # Optional manual slot override via --hsm-slot
        slot_override = getattr(args, "hsm_slot", None)

        test_salt = secrets.token_bytes(16)
        eprint(f"Test salt: {test_salt.hex()}")
        eprint(
            "\nPlease connect your OnlyKey. If the device is locked, enter "
            "your PIN on the OnlyKey buttons before continuing."
        )
        if slot_override:
            eprint(f"Using manual slot: {slot_override}")
        else:
            eprint("Auto-detecting Challenge-Response slot (1..12)...")

        context = PluginSecurityContext(
            plugin_id=ok_plugin.plugin_id,
            capabilities=ok_plugin.get_required_capabilities(),
        )
        if slot_override:
            context.config["slot"] = slot_override

        result = ok_plugin.get_hsm_pepper(test_salt, context)

        if result.success:
            pepper = result.data.get("hsm_pepper")
            slot = result.data.get("slot")
            eprint("\n✅ Test successful!")
            eprint(f"Slot: {slot}")
            # Do NOT print the pepper itself — it is key material / a KDF
            # intermediate (H1 [HSM-1], gitlab#121). The length + success
            # confirm the derivation works; the value must never reach output.
            eprint(f"Pepper length: {len(pepper)} bytes")
            eprint("\nYour OnlyKey Challenge-Response is working correctly.")
        else:
            eprint(f"\n❌ Test failed: {result.message}")
            sys.exit(1)

    else:
        eprint(f"❌ Unknown HSM action: {action}")
        sys.exit(1)


def handle_keyserver_command(args):
    """
    Handle keyserver management commands.

    Args:
        args: Parsed command-line arguments
    """
    import json

    # Import keyserver components
    try:
        from ..plugins.keyserver import KeyserverConfig, KeyserverPlugin
        from .identity import IdentityStore
    except ImportError as e:
        eprint(f"Error: Keyserver plugin not available: {e}")
        return

    # Get configuration
    try:
        config = KeyserverConfig.from_file()
    except Exception as e:
        eprint(f"Error: Failed to load keyserver configuration: {e}")
        return

    # Handle subcommands
    action = args.keyserver_action

    if action == "enable":
        # Enable keyserver
        config.enabled = True
        try:
            config.to_file()
            eprint("✓ Keyserver plugin enabled")
            eprint(f"  Servers: {', '.join(config.servers)}")
            eprint("  Use 'openssl-encrypt keyserver status' to verify configuration")
        except Exception as e:
            eprint(f"✗ Failed to enable keyserver: {e}")

    elif action == "disable":
        # Disable keyserver
        config.enabled = False
        try:
            config.to_file()
            eprint("✓ Keyserver plugin disabled")
        except Exception as e:
            eprint(f"✗ Failed to disable keyserver: {e}")

    elif action == "status":
        # Show keyserver status
        plugin = KeyserverPlugin(config)
        cache_stats = plugin.get_cache_stats()

        eprint("\nKEYSERVER STATUS")
        eprint("=" * 60)
        eprint(f"Enabled: {'Yes' if config.enabled else 'No'}")
        eprint(f"Servers: {', '.join(config.servers)}")
        eprint(
            f"Cache TTL: {config.cache_ttl_seconds} seconds ({config.cache_ttl_seconds // 3600} hours)"
        )
        eprint(f"Cache Max Entries: {config.cache_max_entries}")
        eprint(f"Upload Enabled: {'Yes' if config.upload_enabled else 'No'}")
        eprint(f"API Token: {'Present' if config.load_api_token() else 'Not set'}")
        eprint()
        eprint("CACHE STATISTICS")
        eprint("-" * 60)
        eprint(f"Total Entries: {cache_stats['total_entries']}")
        eprint(f"Valid Entries: {cache_stats['valid_entries']}")
        eprint(f"Expired Entries: {cache_stats['expired_entries']}")
        eprint(f"Total Accesses: {cache_stats['total_accesses']}")
        if cache_stats["most_accessed"]:
            eprint(
                f"Most Accessed: {cache_stats['most_accessed']['name']} ({cache_stats['most_accessed']['count']} times)"
            )
        eprint("=" * 60)

    elif action == "register":
        # Register with keyserver and obtain API token
        if not config.enabled:
            eprint("✗ Keyserver plugin is disabled. Enable with: openssl-encrypt keyserver enable")
            return

        plugin = KeyserverPlugin(config)

        # Use custom server if specified
        server_url = args.server if hasattr(args, "server") and args.server else None
        email = args.email if hasattr(args, "email") and args.email else None

        try:
            if email:
                # Email-confirmed registration with polling
                eprint(f"Registering with email: {email}")
                eprint("A confirmation email will be sent to this address.")
                eprint("Please click the link in the email to complete registration.\n")
                eprint("Waiting for email confirmation... (press Ctrl+C to cancel)")

                result = plugin.register_with_email(email, server_url=server_url)

                eprint("\n✓ Email confirmed! Registration complete.")
                eprint("=" * 60)
                eprint(f"Client ID:   {sanitize_for_display(result['client_id'])}")
                eprint(f"Token Type:  {sanitize_for_display(result.get('token_type', 'Bearer'))}")
                eprint(f"Token File:  {config.api_token_file}")
                eprint("=" * 60)
            else:
                # Anonymous registration (existing flow)
                eprint("Registering with keyserver...")
                result = plugin.register(server_url=server_url)

                eprint("\n✓ Successfully registered with keyserver")
                eprint("=" * 60)
                eprint(f"Client ID:   {sanitize_for_display(result['client_id'])}")
                eprint(f"Expires:     {sanitize_for_display(result['expires_at'])}")
                eprint(f"Token Type:  {sanitize_for_display(result['token_type'])}")
                eprint(f"Token File:  {config.api_token_file}")
                eprint("=" * 60)

            eprint("\nAPI token has been securely saved.")
            eprint("You can now upload and revoke keys using:")
            eprint("  openssl-encrypt keyserver upload <identity>")
            eprint("  openssl-encrypt keyserver revoke <fingerprint>")

        except KeyboardInterrupt:
            eprint("\n\n✗ Registration cancelled.")
        except Exception as e:
            eprint(f"\n✗ Registration failed: {sanitize_for_display(e)}")
            eprint("\nTroubleshooting:")
            eprint("  - Check network connectivity")
            eprint("  - Verify keyserver URL is correct")
            eprint(
                f"  - Server: {server_url or config.servers[0] if config.servers else 'Not configured'}"
            )

    elif action == "login":
        # Login with client_id to obtain JWT tokens
        if not config.enabled:
            eprint("✗ Keyserver plugin is disabled. Enable with: openssl-encrypt keyserver enable")
            return

        plugin = KeyserverPlugin(config)
        client_id = args.client_id
        server_url = args.server if hasattr(args, "server") and args.server else None

        try:
            eprint("Logging in to keyserver...")
            result = plugin.login(client_id, server_url=server_url)

            eprint("\n✓ Login successful")
            eprint("=" * 60)
            eprint(f"Client ID:     {sanitize_for_display(result['client_id'])}")
            eprint(f"Token Type:    {sanitize_for_display(result.get('token_type', 'Bearer'))}")
            eprint(f"Token File:    {config.api_token_file}")
            eprint(f"Refresh File:  {config.refresh_token_file}")
            eprint("=" * 60)
            eprint("\nAPI tokens have been securely saved.")
            eprint("You can now upload and revoke keys using:")
            eprint("  openssl-encrypt keyserver upload <identity>")
            eprint("  openssl-encrypt keyserver revoke <fingerprint>")

        except Exception as e:
            eprint(f"\n✗ Login failed: {sanitize_for_display(e)}")
            eprint("\nTroubleshooting:")
            eprint("  - Verify your client ID is correct (from registration email)")
            eprint("  - Check network connectivity")
            eprint(
                f"  - Server: {server_url or config.servers[0] if config.servers else 'Not configured'}"
            )

    elif action == "search":
        # Search for key on keyserver
        if not config.enabled:
            eprint("✗ Keyserver plugin is disabled. Enable with: openssl-encrypt keyserver enable")
            return

        plugin = KeyserverPlugin(config)
        identifier = args.identifier

        eprint(f"Searching for '{identifier}' on keyserver...")
        bundle = plugin.fetch_key(identifier)

        if bundle:
            if args.json:
                print(json.dumps(bundle.to_dict(), indent=2))
            else:
                # Sanitized like the trust prompt in key_resolver
                # (gitlab#172): the bundle is remote attacker input, and
                # cached bundles predate __post_init__ content validation.
                eprint("\n✓ Key found")
                eprint("-" * 60)
                eprint(f"Name:        {sanitize_for_display(bundle.name)}")
                eprint(
                    f"Email:       {sanitize_for_display(bundle.email) if bundle.email else 'N/A'}"
                )
                eprint(f"Fingerprint: {sanitize_for_display(bundle.fingerprint)}")
                eprint(
                    f"Algorithms:  {sanitize_for_display(bundle.encryption_algorithm)} / "
                    f"{sanitize_for_display(bundle.signing_algorithm)}"
                )
                eprint(f"Created:     {sanitize_for_display(bundle.created_at)}")
                eprint("-" * 60)
        else:
            eprint(f"✗ Key not found for '{identifier}'")

    elif action == "import":
        # Import key from keyserver
        if not config.enabled:
            eprint("✗ Keyserver plugin is disabled. Enable with: openssl-encrypt keyserver enable")
            return

        from .key_resolver import (
            KeyNotFoundError,
            KeyResolver,
            TrustDeclinedError,
            silent_trust_callback,
        )

        plugin = KeyserverPlugin(config)
        store = IdentityStore(resolve_identity_store_path(args))

        # Use silent trust if --no-trust-prompt is set
        trust_callback = silent_trust_callback if args.no_trust_prompt else None
        resolver = KeyResolver(store, plugin, trust_callback)

        try:
            identity = resolver.resolve(args.identifier, load_private_keys=False)
            eprint(
                f"✓ Successfully imported "
                f"'{sanitize_for_display(identity.name)}' to local store"
            )
            eprint(f"  Fingerprint: {sanitize_for_display(identity.fingerprint)}")
        except KeyNotFoundError:
            eprint(f"✗ Key not found for '{args.identifier}'")
        except TrustDeclinedError:
            eprint("✗ Import cancelled (user declined to trust key)")
        except Exception as e:
            eprint(f"✗ Failed to import key: {sanitize_for_display(e)}")

    elif action == "upload":
        # Upload key to keyserver
        if not config.enabled:
            eprint("✗ Keyserver plugin is disabled. Enable with: openssl-encrypt keyserver enable")
            return

        from .key_bundle import PublicKeyBundle

        plugin = KeyserverPlugin(config)
        store = IdentityStore(resolve_identity_store_path(args))

        # Load identity (with private keys for signing)
        identity_name = args.identity_name

        # Prompt for passphrase
        import getpass

        passphrase = getpass.getpass(f"Enter passphrase for '{identity_name}': ")

        try:
            identity = store.get_by_name(
                identity_name, passphrase=passphrase, load_private_keys=True
            )

            if not identity:
                eprint(f"✗ Identity '{identity_name}' not found")
                return

            if not identity.is_own_identity:
                eprint(
                    f"✗ Cannot upload '{identity_name}': not your own identity (no private keys)"
                )
                return

            # Create bundle
            bundle = PublicKeyBundle.from_identity(identity)

            # Upload
            eprint(f"Uploading '{identity_name}' to keyserver...")
            success = plugin.upload_key(bundle)

            if success:
                eprint(f"✓ Successfully uploaded '{sanitize_for_display(identity_name)}'")
                eprint(f"  Fingerprint: {sanitize_for_display(bundle.fingerprint)}")
            else:
                eprint(f"✗ Failed to upload '{identity_name}'")

        except Exception as e:
            eprint(f"✗ Failed to upload key: {sanitize_for_display(e)}")

    elif action == "revoke":
        # Revoke key on keyserver
        eprint("✗ Key revocation not yet implemented")
        eprint("  (Requires revocation signature generation)")

    elif action == "set-token":
        # Set API token
        token = args.token
        try:
            config.save_api_token(token)
            eprint("✓ API token saved securely")
            eprint(f"  Token file: {config.api_token_file}")
            eprint("  Permissions: 0600 (owner read/write only)")
        except Exception as e:
            eprint(f"✗ Failed to save API token: {e}")

    elif action == "show-token":
        token = config.load_api_token()
        if token:
            # Through the redaction chokepoint, not a private masking rule.
            # This used to print the first 8 and last 4 characters, and 12
            # characters of a bearer token is still key material: stderr
            # reaches terminal scrollback, is merged by 2>&1, and the desktop
            # GUI keeps a persistent debug log (gitlab#178). Reading the token
            # back deliberately goes through the same explicit opt-in as every
            # other secret.
            eprint(debug_secret("API Token", token))
            eprint(f"Token file: {config.api_token_file}")
            if not show_secrets_enabled():
                eprint("  Run with --debug --unsafe-show-secrets to display it.")
        else:
            eprint("✗ No API token set")
            eprint("  Use: openssl-encrypt keyserver set-token <token>")

    elif action == "clear-token":
        # Delete API token
        try:
            if config.clear_api_token():
                eprint("✓ API token deleted")
            else:
                eprint("No API token to delete")
        except Exception as e:
            eprint(f"✗ Failed to delete API token: {e}")

    elif action == "cache-clear":
        # Clear cache
        plugin = KeyserverPlugin(config)
        count = plugin.cache.get_pending_count()

        if count == 0:
            eprint("Cache is already empty")
            return

        if not args.force:
            response = prompt_and_read(f"Clear {count} cached keys? (yes/no): ")
            if response.lower() not in ["yes", "y"]:
                eprint("Cancelled")
                return

        cleared = plugin.clear_cache()
        eprint(f"✓ Cleared {cleared} cached keys")

    elif action == "cache-stats":
        # Show cache statistics
        plugin = KeyserverPlugin(config)
        stats = plugin.get_cache_stats()

        eprint("\nKEYSERVER CACHE STATISTICS")
        eprint("=" * 60)
        eprint(f"Total Entries: {stats['total_entries']}")
        eprint(f"Valid Entries: {stats['valid_entries']}")
        eprint(f"Expired Entries: {stats['expired_entries']}")
        eprint(f"Max Entries: {stats['max_entries']}")
        eprint(f"TTL: {stats['ttl_seconds']} seconds ({stats['ttl_seconds'] // 3600} hours)")
        eprint(f"Total Accesses: {stats['total_accesses']}")

        if stats["most_accessed"]:
            eprint(
                f"Most Accessed Key: {sanitize_for_display(stats['most_accessed']['name'])} "
                f"({stats['most_accessed']['count']} times)"
            )

        eprint(f"Cache Path: {stats['cache_path']}")
        eprint("=" * 60)

    else:
        eprint(f"Unknown keyserver action: {action}")


def handle_telemetry_command(args):
    """
    Handle telemetry management commands.

    Args:
        args: Parsed command-line arguments
    """
    try:
        # Import telemetry plugin
        from ..plugins.telemetry import OpenSSLEncryptTelemetryPlugin
    except ImportError as e:
        eprint("Error: Telemetry plugin not available.")
        eprint(f"Details: {e}")
        return 1

    # Get or create telemetry plugin instance
    try:
        plugin = OpenSSLEncryptTelemetryPlugin()
    except Exception as e:
        eprint(f"Error: Failed to initialize telemetry plugin: {e}")
        return 1

    # Handle subcommands
    action = args.telemetry_action

    if action == "status":
        # Show telemetry status
        status = plugin.get_status()
        if getattr(args, "json", False):
            # Machine-readable document on stdout so a GUI reads the real state
            # instead of scraping the unversioned human report (gitlab#162).
            import json

            print(json.dumps(status, indent=2))
        else:
            eprint("\nTELEMETRY STATUS")
            eprint("=" * 60)
            eprint(f"Enabled: {'Yes' if status['enabled'] else 'No'}")
            eprint(f"Pending Events: {status['pending_events']}")
            eprint(f"Server URL: {status['server_url']}")
            eprint(f"API Key: {'Present' if status['has_api_key'] else 'Not registered'}")
            eprint(
                f"Upload Interval: {status['upload_interval']} seconds ({status['upload_interval'] // 3600} hours)"
            )
            eprint(
                f"Background Upload: {'Running' if status['upload_thread_alive'] else 'Stopped'}"
            )
            eprint("=" * 60)

    elif action == "show-pending":
        # Show pending events (transparency)
        events = plugin.get_pending_events(limit=args.limit)

        if not events:
            eprint("No pending telemetry events.")
            return

        if args.json:
            # JSON output
            import json

            print(json.dumps(events, indent=2))
        else:
            # Human-readable output
            eprint(f"\nPENDING TELEMETRY EVENTS (showing {min(len(events), args.limit)} events)")
            eprint("=" * 80)

            for i, event in enumerate(events[: args.limit], 1):
                eprint(f"\n--- Event {i} (ID: {event.get('id', 'N/A')}) ---")
                eprint(f"  Timestamp: {event.get('timestamp', 'N/A')}")
                eprint(f"  Operation: {event.get('operation', 'N/A')}")
                eprint(f"  Mode: {event.get('mode', 'N/A')}")
                eprint(f"  Format Version: {event.get('format_version', 'N/A')}")
                eprint(f"  Encryption: {event.get('encryption_algorithm', 'N/A')}")
                eprint(f"  Hash Algorithms: {', '.join(event.get('hash_algorithms', []))}")
                eprint(f"  KDF Algorithms: {', '.join(event.get('kdf_algorithms', []))}")

                if event.get("cascade_enabled"):
                    eprint(f"  Cascade: Enabled ({event.get('cascade_cipher_count', 0)} ciphers)")

                if event.get("pqc_kem_algorithm"):
                    eprint(f"  PQC KEM: {event.get('pqc_kem_algorithm')}")

                if event.get("pqc_signing_algorithm"):
                    eprint(f"  PQC Signing: {event.get('pqc_signing_algorithm')}")

                if event.get("hsm_plugin_used"):
                    eprint(f"  HSM Plugin: {event.get('hsm_plugin_used')}")

                eprint(f"  Success: {event.get('success', True)}")

                if event.get("error_category"):
                    eprint(f"  Error Category: {event.get('error_category')}")

                eprint(f"  Retry Count: {event.get('retry_count', 0)}")

            eprint("\n" + "=" * 80)
            eprint(f"Total pending events: {plugin.buffer.get_pending_count()}")

    elif action == "flush":
        # Upload all pending events immediately
        eprint("Uploading pending telemetry events...")
        result = plugin.flush()

        if result.success:
            eprint(f"✓ {result.message}")
        else:
            eprint(f"✗ {result.message}")
            # A wrapper may clear local state believing the events were
            # uploaded; a failed flush has to reach the exit status.
            return 1

    elif action == "clear":
        # Delete all pending events without uploading
        pending_count = plugin.buffer.get_pending_count()

        if pending_count == 0:
            eprint("No pending events to clear.")
            return

        if not args.force:
            try:
                response = prompt_and_read(
                    f"Delete {pending_count} pending events without uploading? (yes/no): "
                )
            except (EOFError, KeyboardInterrupt):
                # No usable stdin (a GUI or CI caller) or an interrupt: treat as
                # a decline rather than a traceback outside the status contract.
                eprint("\nCancelled.")
                return 3
            if response.lower() not in ["yes", "y"]:
                eprint("Cancelled.")
                # Distinct from both success and failure: nothing was changed, and
                # a caller must not read a decline as a completed action.
                return 3

        deleted = plugin.buffer.clear_all()
        eprint(f"✓ Deleted {deleted} pending events.")

    elif action == "opt-out":
        # Complete opt-out: disable telemetry and delete all data
        pending_count = plugin.buffer.get_pending_count()

        if not args.force:
            eprint("\n⚠️  OPT-OUT WARNING ⚠️")
            eprint("This will:")
            eprint("  1. Disable telemetry collection")
            eprint(f"  2. Delete {pending_count} pending events")
            eprint("  3. Delete your API key")
            eprint("  4. Stop background uploads")
            eprint()
            try:
                response = prompt_and_read("Are you sure you want to opt out? (yes/no): ")
            except (EOFError, KeyboardInterrupt):
                # No usable stdin (a GUI or CI caller) or an interrupt: treat as
                # a decline rather than a traceback outside the status contract.
                eprint("\nCancelled.")
                return 3
            if response.lower() not in ["yes", "y"]:
                eprint("Cancelled.")
                # Distinct from both success and failure: nothing was changed, and
                # a caller must not read a decline as a completed action.
                return 3

        result = plugin.opt_out()

        if result.success:
            eprint(f"✓ {result.message}")
            eprint("\nTelemetry collection is disabled and the stored data is deleted.")
            eprint(
                "This does not write a persistent setting: telemetry can be switched "
                "on again by OPENSSL_ENCRYPT_TELEMETRY=1 or a config file, which "
                "would register a new key."
            )
        else:
            eprint(f"✗ {result.message}")
            # Opt-out is destructive. A caller that cannot tell a refusal from a
            # completed deletion may tell the user their data is gone when it is
            # not, so the failure has to reach the exit status.
            return 1

    else:
        eprint(f"Unknown telemetry action: {action}")
        return 1

    return 0


def main():
    """
    Main function that handles the command-line interface.
    """
    # Preprocess arguments to move global flags to the front
    import sys

    # Handle --keyring-remove early (before argparse) since it's a standalone action
    # Deliberately not a bare `"--keyring-remove" in sys.argv` membership
    # test (security review of gitlab#177). That scan ran before any parsing,
    # over the WHOLE of argv, so `crypt shred -- --keyring-remove label`
    # deleted the stored password and exited 0 having shredded nothing --
    # when what the user described was two files with those names. It also
    # missed the `--keyring-remove=LABEL` spelling entirely, so that form
    # silently did nothing.
    label = _keyring_remove_label(sys.argv)
    if label is not None:
        try:
            import keyring as _keyring
        except ImportError:
            eprint("Error: keyring package not installed. Install with: pip install keyring")
            sys.exit(1)

        # "Not found" and "the backend failed" are different answers, and a
        # caller that cannot tell them apart may believe a credential is gone
        # when it is still there -- the same reasoning the telemetry opt-out
        # applies (follow-up review of gitlab#177). Exit 0 only on a
        # confirmed deletion or a confirmed absence.
        not_found = getattr(getattr(_keyring, "errors", None), "PasswordDeleteError", ())
        try:
            _keyring.delete_password("openssl_encrypt", label)
            eprint(f"Password removed from keyring: '{label}'")
        except not_found:
            eprint(f"No password found in keyring for label '{label}'")
        except Exception as error:
            eprint(f"Error: could not remove '{label}' from the keyring: {error}")
            eprint("  The password may still be stored.")
            sys.exit(1)
        sys.exit(0)

    sys.argv = preprocess_global_args(sys.argv)

    # After preprocessing, global flags are moved to the front when they appear after the command.
    # Check if position 1 is a subcommand to decide which parser to use.
    # This allows backward compatibility: when global flags are BEFORE the command,
    # the monolithic parser is used (which has all arguments).
    # Read off the real subparser, not a list beside it (gitlab#179): a name
    # that has no subparser registered must fall through to the monolithic
    # parser below, which declares every command and holds their handlers.
    # Routing it to the subparser turns a working command into `invalid
    # choice`, which is how create-usb, verify-usb and the five *-plugin
    # commands were unreachable while still being listed in --help.
    subparser_commands = _subparser_choices()

    # Use subparser only if a subcommand is present, after
    # preprocess_global_args has moved the global flags to the front.
    #
    # The SAME scan the relocation gate uses (gitlab#177). This was a third
    # hand-maintained copy of "which flags carry a value", and the copies had
    # already drifted twice: it once omitted -q, and its value-skip once
    # `continue`d without consuming the value, so `--kdf-workers N` made the
    # scan read "N" as the command and silently fall back to the monolithic
    # parser (gitlab#171). Sharing one implementation means the relocation
    # gate and the routing decision cannot disagree about where the command
    # is -- and disagreement is exactly how the flags end up moved for one
    # parser and interpreted by the other.
    first_command = _first_command_token(sys.argv)

    if first_command in subparser_commands:
        # Use subparser for all command-specific operations
        from .crypt_cli_subparser import create_subparser_main

        parser, args = create_subparser_main()

        # If it's just help, return after displaying help
        if "--help" in sys.argv or "-h" in sys.argv:
            return

        # Otherwise, continue with the parsed args from subparser
        # We need to call the main logic with the subparser args
        return main_with_args(args)
    else:
        # Use original argument parsing for non-command operations
        return main_with_args()


def _get_steganography_plugin(quiet=False):
    """
    Get steganography plugin from plugin system.

    Args:
        quiet: If True, suppress error messages

    Returns:
        Plugin instance or None if not available
    """
    try:
        # Import steganography plugin directly
        from ..plugins.steganography import plugin_instance

        return plugin_instance

    except ImportError:
        if not quiet:
            eprint("Error: Steganography requires additional dependencies.")
            eprint("Install with: pip install Pillow numpy")
        return None
    except Exception as e:
        if not quiet:
            eprint(f"Error loading steganography plugin: {e}")
        return None


def _run_dice_generation(args):
    """
    Generate a Diceware passphrase from parsed CLI args.

    Bridges the argparse layer to the :mod:`diceware` module. Loads the
    requested wordlist (custom path from ``--dice-list`` or the bundled
    EFF Large Wordlist if None), generates a passphrase of
    ``--dice-count`` words joined by ``--dice-sep``, and returns the
    passphrase together with its computed entropy in bits.

    The caller is responsible for any policy/length checks and for
    output formatting; this helper has no side effects beyond reading
    the wordlist file.

    Args:
        args: An object exposing the attributes ``dice_list``,
            ``dice_count``, ``dice_sep``, ``force_wordlist``.

    Returns:
        Tuple ``(passphrase: str, entropy_bits: float)``.
    """
    from .diceware import generate_passphrase, load_wordlist, passphrase_entropy

    wordlist = load_wordlist(
        path=getattr(args, "dice_list", None),
        force_small=getattr(args, "force_wordlist", False),
    )
    phrase = generate_passphrase(
        count=args.dice_count,
        sep=args.dice_sep,
        wordlist=wordlist,
    )
    bits = passphrase_entropy(count=args.dice_count, wordlist_size=len(wordlist))
    return phrase, bits


def _validate_generate_password_args(
    *,
    dice: bool,
    use_lowercase: bool,
    use_uppercase: bool,
    use_digits: bool,
    use_special: bool,
    dice_count: int,
    dice_sep: str,
    dice_list,
    force_wordlist: bool,
) -> None:
    """
    Validate the flag combination passed to ``generate-password``.

    Enforces two rules:

    1. ``--dice`` is mutually exclusive with any character-class flag
       (``--use-lowercase``, ``--use-uppercase``, ``--use-digits``,
       ``--use-special``). A passphrase is shaped by its source wordlist,
       not by character classes.

    2. The Diceware-specific options (``--dice-count``, ``--dice-sep``,
       ``--dice-list``, ``--force-wordlist``) are only meaningful when
       ``--dice`` is set. Using them without ``--dice`` is a user error
       and we reject loudly so the user notices.

    Raises:
        ValueError with a human-readable, actionable message on any rule
        violation. The caller prints the message and exits.
    """
    if dice:
        char_flags = []
        if use_lowercase:
            char_flags.append("--use-lowercase")
        if use_uppercase:
            char_flags.append("--use-uppercase")
        if use_digits:
            char_flags.append("--use-digits")
        if use_special:
            char_flags.append("--use-special")
        if char_flags:
            raise ValueError(
                f"--dice is mutually exclusive with character-class flags "
                f"({', '.join(char_flags)}). A Diceware passphrase is "
                f"defined by its wordlist, not by character classes — drop "
                f"the character-class flags, or drop --dice."
            )
        return

    # --dice is not set; check that no Diceware-only options were passed.
    leaked: list = []
    if dice_count != 10:
        leaked.append("--dice-count")
    if dice_sep != "":
        leaked.append("--dice-sep")
    if dice_list is not None:
        leaked.append("--dice-list")
    if force_wordlist:
        leaked.append("--force-wordlist")
    if leaked:
        raise ValueError(
            f"the following flags require --dice: {', '.join(leaked)}. "
            f"Add --dice to use Diceware passphrase generation, or drop "
            f"these flags to use the default character-based generator."
        )


def _consume_encrypt_signer_passphrase(args):
    """Consume ``$OPENSSL_ENCRYPT_SIGNER_PASSPHRASE`` up front on the encrypt
    ``--sign-with`` path.

    ``sign`` consumes it as its very first statement so the value is gone from
    ``os.environ`` before anything -- an identity-load path, a plugin -- can
    spawn a child that would inherit it. The encrypt path reaches the same
    signing code only after the plugin system, HSM/pepper plugins and keyserver
    connections have come up, all with the variable still live. Consuming it
    here, before that machinery runs, restores the read-once-and-remove
    guarantee; the value is handed to :func:`resolve_credential` as ``explicit``
    (gitlab#180).

    A non-signing encrypt, or any other action, returns ``None`` and touches
    nothing. When signing is requested the variable is consumed (removed)
    whether or not it is ultimately needed -- an unneeded value not left in the
    environment is the point.

    Args:
        args: Parsed command-line arguments.

    Returns:
        The consumed passphrase, or ``None``.
    """
    if getattr(args, "action", None) == "encrypt" and getattr(args, "sign_with", None):
        from .file_signature import SIGNER_PASSPHRASE_ENV

        return consume_env(SIGNER_PASSPHRASE_ENV)
    return None


def _resolve_second_password(args):
    """Resolve the optional second password (keyed hidden mode) to bytes or None.

    Priority: ``--second-password-fd`` > ``--second-password`` >
    ``$OPENSSL_ENCRYPT_SECOND_PASSWORD`` > ``--second-password-prompt``.
    Returns ``None`` when none is supplied (the keyless / non-hidden case).
    The trailing newline from fd/prompt sources is stripped, mirroring the
    primary-password handling.

    The environment variable exists because the prompt reads /dev/tty, which
    the desktop GUI and any CI caller cannot answer, while ``--second-password``
    puts the credential in world-readable ``/proc/PID/cmdline`` (gitlab#154).
    It is consumed on every call, even when a higher-priority source wins, so
    it is never inherited by a later child process.

    An environment value alone does NOT enable keyed hidden mode. A non-None
    return here makes `_hidden_for_encrypt` turn hidden mode on, so if the
    variable could supply a value unasked, an exported variable would silently
    write every file with a keyed hidden header under a value the user never
    chose and cannot reproduce -- readable by whoever planted it, and locking
    the user out of their own metadata. The variable is therefore only read
    when a flag has actually requested the credential: the environment
    supplies a value, an explicit flag still selects the path.
    """
    # Consumed unconditionally, before the branches and regardless of whether
    # it is wanted: a value left behind is inherited by any child process, and
    # several call sites run subprocess.run() with no env=.
    env_value = consume_env(SECOND_PASSWORD_ENV)

    # A blank credential is a hard error when ENCRYPTING -- wrapping metadata
    # under a secret anyone can guess is the actual harm. When decrypting it
    # is allowed through: a file encrypted on an earlier release with a
    # whitespace-only value must stay decryptable, and the same
    # data-preservation reasoning that motivates reject_newline=False applies.
    encrypting = getattr(args, "action", None) not in ("decrypt", "info")

    fd = getattr(args, "second_password_fd", None)
    if fd is not None:
        with os.fdopen(os.dup(fd), "rb") as f:
            from_fd = f.read().split(b"\n", 1)[0]
        # The fd path used to skip validation entirely, so an empty or
        # EOF-closed descriptor yielded b"", which hidden_header maps back to
        # "keyless" -- silently giving a keyless header to a caller who asked
        # for a keyed one. That is exactly what `--second-password ""` now
        # errors on, so it errors here too.
        #
        # Route through the same canonical rule the flag and env channels use
        # (credential_env.validated) instead of a bytes-only `.strip()`, which
        # strips ASCII whitespace only: a U+00A0-only credential was rejected
        # via --second-password but accepted here, and a future change to the
        # blank rule would silently not reach this channel (gitlab#180). The fd
        # already stops at the first newline, so reject_newline is moot; match
        # the flag's reject_newline=False. surrogateescape keeps arbitrary
        # bytes round-trippable so binary credentials behave as before while
        # Unicode whitespace is still recognised as blank.
        if encrypting:
            credential_validated(
                from_fd.decode("utf-8", "surrogateescape"),
                "--second-password-fd",
                reject_newline=False,
            )
        return from_fd
    val = getattr(args, "second_password", None)
    if val is not None:
        # `is not None`, not truthiness: `--second-password ""` used to fall
        # through to the next source and silently produce a keyless header.
        # reject_newline=False: this flag predates that rule, and a file
        # already encrypted with a newline-bearing value must stay
        # decryptable. Only the new environment channel enforces it.
        if encrypting:
            credential_validated(val, "--second-password", reject_newline=False)
        return val.encode("utf-8")

    requested = bool(
        getattr(args, "hidden_header", False) or getattr(args, "second_password_prompt", False)
    )
    if env_value is not None and not requested:
        # Silently dropping it would leave a GUI or CI caller believing the
        # metadata is keyed when the file was written in plain legacy format.
        # The NAME only -- never the value.
        eprint(
            f"WARNING: ${SECOND_PASSWORD_ENV} was set but ignored. Keyed "
            f"hidden mode must be requested with --hidden-header or "
            f"--second-password-prompt; the variable supplies the value, it "
            f"does not enable the mode."
        )
    if requested and env_value is not None:
        # reject_newline only when ENCRYPTING, matching the fd and flag channels
        # (gitlab#180): now that `info`/`decrypt` reach the env channel, a keyed
        # hidden file written through fd/flag with a newline-bearing second
        # password must stay readable through the environment too. On encrypt the
        # new-channel strictness stays -- a GUI's trailing newline would derive an
        # unreproducible key. (A blank value is still refused on every path, since
        # a blank env variable is almost always an unset one.)
        return credential_validated(
            env_value, f"${SECOND_PASSWORD_ENV}", reject_newline=encrypting
        ).encode("utf-8")
    if getattr(args, "second_password_prompt", False):
        import getpass

        return getpass.getpass("Enter second password (hidden keyed mode): ").encode("utf-8")
    return None


def _hidden_for_encrypt(args, second_password):
    """Decide encrypt-time hidden mode: legacy override wins, else hidden if the
    flag is set or a second password was provided."""
    if getattr(args, "legacy_format", False):
        return False
    return bool(getattr(args, "hidden_header", False) or second_password is not None)


def _can_prompt_on_tty():
    """Return True if an interactive password prompt can be shown.

    The second-password prompt uses :func:`getpass.getpass`, which reads from
    the controlling terminal (``/dev/tty``) rather than ``stdin``. So a prompt
    is possible even when ``stdin`` carries piped ciphertext — e.g.
    ``armor file | decrypt -i /dev/stdin`` — as long as a controlling terminal
    exists. Genuinely headless contexts (cron, CI, daemons) have neither an
    openable ``/dev/tty`` nor a tty on any std stream, so the prompt stays
    suppressed there (no automation hang, no behavioural oracle).
    """
    try:
        fd = os.open("/dev/tty", os.O_RDWR)
        os.close(fd)
        return True
    except OSError:
        pass
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
            if stream.isatty():
                return True
        except Exception:
            pass
    return False


def _hidden_for_decrypt(args):
    """Decide decrypt-time hidden handling as a tri-state: True (force), False
    (force legacy), or None (auto-detect)."""
    if getattr(args, "hidden_header", False):
        return True
    if getattr(args, "legacy_format", False):
        return False
    return None


def _resolve_second_password_with_fallback(args, explicit_second_password):
    """Resolve the decrypt-time second password, with an interactive fallback.

    An explicit ``--second-password*`` always wins. Otherwise, on a bare
    decrypt, peek the input: if it is a hidden file that does NOT peel keyless
    (i.e. keyed, or just random/corrupt), and the session is interactive, prompt
    once for a second password. The prompt is deliberately:

    * **terminal-gated** -- fires only when a controlling terminal is reachable
      for getpass (``/dev/tty``); headless runs (cron/CI, no tty anywhere) keep
      the silent generic-error behavior (no behavioral oracle, no automation
      hang). It DOES fire when stdin is a pipe but a terminal is present, so
      ``armor ... | decrypt -i /dev/stdin`` can prompt;
    * **suppressible** with ``--no-second-password-prompt`` (and skipped under
      ``--legacy-format``);
    * **neutrally worded** -- it fires on any non-keyless-peelable input, so it
      never asserts "this is one of our files".

    The keyless peek is cheap (a single HKDF over the public salt + a small
    header), so there is no double-decrypt and no expensive keyed KDF here.

    Args:
        args: Parsed CLI namespace.
        explicit_second_password: Result of :func:`_resolve_second_password`.

    Returns:
        The second password as ``bytes``, or ``None``.
    """
    if explicit_second_password is not None:
        return explicit_second_password
    if getattr(args, "no_second_password_prompt", False) or getattr(args, "legacy_format", False):
        return None
    # Gate on whether a controlling terminal is reachable for getpass (/dev/tty),
    # not on stdin being a tty: the ciphertext may itself arrive on stdin via a
    # pipe (armor ... | decrypt -i /dev/stdin) while a terminal is still present.
    if not _can_prompt_on_tty():
        return None

    input_file = getattr(args, "input", None)
    if not input_file:
        return None
    if (
        input_file == "/dev/stdin"
        or input_file.startswith("/proc/")
        or input_file.startswith("/dev/")
    ):
        return None

    from .crypt_errors import AuthenticationError, ValidationError
    from .hidden_header import is_hidden_format, read_hidden_header

    try:
        with open(input_file, "rb") as f:
            prefix = f.read(65536)
    except OSError:
        return None
    if not is_hidden_format(prefix):
        return None  # legacy file -> normal path, no prompt

    # Hidden file: a cheap keyless header peel. If it succeeds, the file is
    # keyless and needs no second password.
    try:
        with open(input_file, "rb") as f:
            read_hidden_header(f, second_password=None)
        return None
    except (ValidationError, AuthenticationError):
        pass  # keyed (or random/corrupt) -> offer the prompt
    except OSError:
        return None

    entered = getpass.getpass("Enter second password (blank to abort): ")
    return entered.encode("utf-8") if entered else None


def main_with_args(args=None):
    """Main logic with pre-parsed arguments (or None to parse from command line)"""
    # Original main function continues below...
    # Global variable to track temporary files that need cleanup
    temp_files_to_cleanup = []

    def cleanup_temp_files():
        """Clean up any temporary files that were created but not deleted"""
        for temp_file in temp_files_to_cleanup:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    if not args.quiet:
                        eprint(f"Cleaned up temporary file: {temp_file}")
            except Exception:
                pass

    def cleanup_all():
        """Clean up temporary files and environment variables"""
        cleanup_temp_files()
        clear_password_environment()

    # Register cleanup function to run on normal exit
    atexit.register(cleanup_all)

    # gitlab#223: orphan-password NOTE state, initialized before any code that
    # could write the --random-password-out file so the signal handler and the
    # dispatch finally can always read it. _ciphertext_on_disk: a usable (or
    # possibly usable) encrypted output exists, so the password file is a live
    # credential -- the NOTE must tell the user to verify, never "you can
    # remove it". _encrypt_completed: the run reached its normal end -- no
    # NOTE at all (delivery was announced at write time).
    _ciphertext_on_disk = False
    _encrypt_completed = False

    # Register signal handlers for common termination signals
    def signal_handler(signum, frame):
        cleanup_temp_files()
        # gitlab#223 review f5: a signal death runs neither the dispatch
        # finally nor atexit (SIG_DFL re-kill below), and Ctrl-C during a
        # memory-hard KDF is the most likely incomplete encrypt exit. The
        # NOTE is advisory: it must never change the outcome, so failures
        # are swallowed.
        try:
            if not _encrypt_completed:
                _warn_orphan_random_password(args, ciphertext_maybe_written=_ciphertext_on_disk)
        except Exception:
            pass
        # Re-raise the signal to allow the default handler to run
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    # Register handlers for common termination signals
    _sigs = [signal.SIGINT, signal.SIGTERM]
    if hasattr(signal, "SIGHUP"):
        _sigs.append(signal.SIGHUP)
    for sig in _sigs:
        try:
            signal.signal(sig, signal_handler)
        except AttributeError:
            # Some signals might not be available on all platforms
            pass

    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt a file with a password\n\n"
        "USAGE PATTERN:\n"
        "  %(prog)s COMMAND [OPTIONS] [GLOBAL_FLAGS]\n"
        "  %(prog)s [GLOBAL_FLAGS] COMMAND [OPTIONS]\n\n"
        "GLOBAL FLAGS (can be placed anywhere):\n"
        "  --progress, --verbose, --debug, --quiet\n\n"
        "COMMAND-SPECIFIC FLAGS:\n"
        "  --template, --quick, --standard, --paranoid (encryption only)\n\n"
        "SIMPLIFIED ALIASES:\n"
        "  --fast, --secure, --max-security (security levels)\n"
        "  --crypto-family aes|chacha|xchacha|fernet (algorithms)\n"
        "  --quantum-safe pq-standard|pq-high|pq-alternative (post-quantum)\n"
        "  --for-personal | --for-business | --for-archival | --for-compliance (use cases)\n\n"
        "COMMANDS:\n"
        "  encrypt, decrypt, shred, generate-password, security-info, analyze-security, config-wizard, analyze-config, template, smart-recommendations, check-argon2, check-pqc, version\n\n"
        "EXAMPLES:\n"
        "  %(prog)s encrypt --input file.txt --debug --output file.enc\n"
        "  %(prog)s --quiet decrypt --input file.enc --progress --output file.txt\n"
        "  %(prog)s encrypt --verbose --input file.txt --paranoid --algorithm aes-gcm\n"
        "  %(prog)s encrypt --input file.txt --fast (quick encryption)\n"
        "  %(prog)s encrypt --input file.txt --secure --crypto-family xchacha\n"
        "  %(prog)s encrypt --input file.txt --for-archival --quantum-safe pq-high\n\n"
        "Environment Variables:\n"
        "  CRYPT_PASSWORD    Password for encryption/decryption (alternative to -p)",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Global options group
    global_group = parser.add_argument_group(
        "Global Options (can be specified anywhere in command line)"
    )
    global_group.add_argument("--progress", action="store_true", help="Show progress bar")
    global_group.add_argument(
        "--parallel-kdf",
        action="store_true",
        help="Derive the independent KDF components concurrently on a thread pool. "
        "Applies to every producible format (the derived key is byte-identical, so "
        "the flag is never needed to decrypt). Speeds up configs with several "
        "memory-hard KDFs (Argon2, Scrypt); pure hash-round components gain "
        "little (they serialize on the Python GIL).",
    )
    global_group.add_argument(
        "--kdf-workers",
        type=int,
        default=None,
        metavar="N",
        help="Number of parallel workers for KDF (default: auto-detect; capped at CPU "
        "count, component count and a concurrent-memory safety ceiling). "
        "Only used with --parallel-kdf.",
    )
    global_group.add_argument("--verbose", action="store_true", help="Show hash/kdf details")
    global_group.add_argument(
        "--debug",
        action="store_true",
        help="Show detailed debug information. Secret values (passwords, key material, "
        "KDF intermediates, hardware peppers) are redacted to length + SHA-256 "
        "fingerprint by default; combine with --unsafe-show-secrets to log them "
        "in cleartext (test files only!)",
    )
    global_group.add_argument(
        "--unsafe-show-secrets",
        action="store_true",
        help="UNSAFE: show secret values in cleartext in --debug output instead of "
        "redacting them. Only valid together with --debug.",
    )
    global_group.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Automatic yes to prompts (for install-dependencies command)",
    )
    global_group.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress all output except decrypted content and exit code",
    )
    global_group.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output in JSON format (for info action)",
    )
    global_group.add_argument(
        "-t",
        "--template",
        help="Specify a template name (built-in or from ./template directory)",
    )

    # Keyring integration (optional dependency)
    keyring_group = parser.add_argument_group("Keyring options (requires 'keyring' package)")
    keyring_group.add_argument(
        "--keyring-store",
        metavar="LABEL",
        help="Store the password in the OS keyring under LABEL after successful operation",
    )
    keyring_group.add_argument(
        "--keyring-load",
        metavar="LABEL",
        help="Load password from the OS keyring by LABEL instead of prompting",
    )
    keyring_group.add_argument(
        "--keyring-remove",
        metavar="LABEL",
        help="Remove a stored password from the OS keyring and exit",
    )

    # Template selection group (global options)
    template_group = global_group.add_mutually_exclusive_group()
    template_group.add_argument(
        "--quick", action="store_true", help="Use quick but secure configuration"
    )
    template_group.add_argument(
        "--standard",
        action="store_true",
        help="Use standard security configuration (default)",
    )
    template_group.add_argument(
        "--paranoid", action="store_true", help="Use maximum security configuration"
    )

    # Define core actions
    parser.add_argument(
        "action",
        choices=[
            "encrypt",
            "decrypt",
            "info",
            "rekey",
            "shred",
            "generate-password",
            "derive-password",
            "security-info",
            "analyze-security",
            "config-wizard",
            "check-argon2",
            "check-pqc",
            "check-password",
            "version",
            "show-version-file",
            "create-usb",
            "verify-usb",
            "list-plugins",
            "plugin-info",
            "enable-plugin",
            "disable-plugin",
            "reload-plugin",
            "plugin",
        ],
        help="Action to perform: encrypt/decrypt/info files, shred data, generate/derive passwords, "
        "show security recommendations, analyze security configuration, configuration wizard, analyze configuration details, check Argon2 support, check post-quantum cryptography support, "
        "create/verify portable USB drives, manage plugins",
    )

    # Get all available algorithms, marking deprecated ones
    all_algorithms = [algo.value for algo in EncryptionAlgorithm]
    recommended_algorithms = [
        algo.value for algo in EncryptionAlgorithm.get_recommended_algorithms()
    ]

    # Build help text with deprecated warnings
    algorithm_help_text = "Encryption algorithm to use:\n"
    for algo in sorted(all_algorithms):
        if algo == EncryptionAlgorithm.FERNET.value:
            description = "default, AES-128-CBC with authentication"
        elif algo == EncryptionAlgorithm.AES_GCM.value:
            description = "AES-256 in GCM mode, high security, widely trusted"
        elif algo == EncryptionAlgorithm.AES_GCM_SIV.value:
            description = "AES-256 in GCM-SIV mode, resistant to nonce reuse"
        elif algo == EncryptionAlgorithm.AES_OCB3.value:
            description = "AES-256 in OCB3 mode, faster than GCM (DEPRECATED)"
        elif algo == EncryptionAlgorithm.AES_SIV.value:
            description = "AES in SIV mode, synthetic IV"
        elif algo == EncryptionAlgorithm.CHACHA20_POLY1305.value:
            description = "modern AEAD cipher with 12-byte nonce"
        elif algo == EncryptionAlgorithm.XCHACHA20_POLY1305.value:
            description = "ChaCha20-Poly1305 with 24-byte nonce, safer for high-volume encryption"
        elif algo == EncryptionAlgorithm.CAMELLIA.value:
            description = "Camellia in CBC mode (DEPRECATED)"
        elif algo == EncryptionAlgorithm.ML_KEM_512_HYBRID.value:
            description = "post-quantum key exchange with AES-256-GCM, NIST level 1 (NIST FIPS 203)"
        elif algo == EncryptionAlgorithm.ML_KEM_768_HYBRID.value:
            description = "post-quantum key exchange with AES-256-GCM, NIST level 3 (NIST FIPS 203)"
        elif algo == EncryptionAlgorithm.ML_KEM_1024_HYBRID.value:
            description = "post-quantum key exchange with AES-256-GCM, NIST level 5 (NIST FIPS 203)"
        elif algo == EncryptionAlgorithm.KYBER512_HYBRID.value:
            description = "post-quantum key exchange with AES-256-GCM, NIST level 1 (DEPRECATED - use ml-kem-512-hybrid)"
        elif algo == EncryptionAlgorithm.KYBER768_HYBRID.value:
            description = "post-quantum key exchange with AES-256-GCM, NIST level 3 (DEPRECATED - use ml-kem-768-hybrid)"
        elif algo == EncryptionAlgorithm.KYBER1024_HYBRID.value:
            description = "post-quantum key exchange with AES-256-GCM, NIST level 5 (DEPRECATED - use ml-kem-1024-hybrid)"
        elif algo == EncryptionAlgorithm.THREEFISH_512.value:
            description = "Threefish-512 with Poly1305 (256-bit PQ security, high security)"
        elif algo == EncryptionAlgorithm.THREEFISH_1024.value:
            description = "Threefish-1024 with Poly1305 (512-bit PQ security, paranoid)"
        else:
            description = "encryption algorithm"

        algorithm_help_text += f"  {algo}: {description}\n"

    parser.add_argument(
        "--algorithm",
        type=str,
        choices=all_algorithms,
        default=EncryptionAlgorithm.FERNET.value,
        help=algorithm_help_text,
    )

    # Add extended algorithm help
    add_extended_algorithm_help(parser)

    # Data encryption algorithm to use with Kyber/ML-KEM
    # Build help text with deprecated warnings
    data_algorithms = [
        "aes-gcm",
        "aes-gcm-siv",
        "aes-ocb3",
        "aes-siv",
        "chacha20-poly1305",
        "xchacha20-poly1305",
    ]
    data_algo_help = (
        "Symmetric encryption algorithm to use for data encryption when using Kyber/ML-KEM:\n"
    )

    for algo in data_algorithms:
        if algo == "aes-gcm":
            description = "default, AES-256 in GCM mode"
        elif algo == "aes-gcm-siv":
            description = "AES-256 in GCM-SIV mode, resistant to nonce reuse"
        elif algo == "aes-ocb3":
            description = "AES-256 in OCB3 mode, faster than GCM (DEPRECATED - security concerns with short nonces)"
        elif algo == "aes-siv":
            description = "AES in SIV mode, synthetic IV"
        elif algo == "chacha20-poly1305":
            description = "modern AEAD cipher with 12-byte nonce"
        elif algo == "xchacha20-poly1305":
            description = "ChaCha20-Poly1305 with 24-byte nonce, safer for high-volume encryption"
        else:
            description = "encryption algorithm"

        data_algo_help += f"  {algo}: {description}\n"

    parser.add_argument(
        "--encryption-data",
        type=str,
        choices=data_algorithms,
        default="aes-gcm",
        help=data_algo_help,
    )
    # Define common options
    parser.add_argument(
        "--password",
        "-p",
        help="Password (will prompt if not provided, or use CRYPT_PASSWORD environment variable)",
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="(derive-password only) Prompt for the password twice and verify "
        "they match before deriving — guards against typos that would yield "
        "a silent, irreproducible output.",
    )
    parser.add_argument(
        "--random",
        type=int,
        metavar="LENGTH",
        help="Generate a random password of specified length for encryption",
    )
    parser.add_argument(
        "--input",
        "-i",
        help="Input file or directory (supports glob patterns for shred action)",
    )
    parser.add_argument("--output", "-o", help="Output file (optional for decrypt)")
    # Hidden-format second password (for reading a keyed hidden file's metadata
    # with `info`). The interactive fallback also applies on a TTY.
    parser.add_argument(
        "--second-password",
        metavar="PW",
        help="Second password to read a keyed hidden file (DEPRECATED: visible "
        "in process list; prefer --second-password-fd or --second-password-prompt).",
    )
    parser.add_argument(
        "--second-password-fd",
        type=int,
        metavar="FD",
        help="Read the second password from file descriptor FD.",
    )
    parser.add_argument(
        "--second-password-prompt",
        action="store_true",
        help="Prompt interactively for the second password.",
    )
    parser.add_argument(
        "--no-second-password-prompt",
        action="store_true",
        help="Never prompt for a second password, even at an interactive terminal.",
    )
    # `info` reaches this monolithic parser (it has no dedicated subparser), and
    # it passes the second password to print_file_info to read a keyed hidden
    # file's metadata. Without this flag `requested` was always False for info,
    # so $OPENSSL_ENCRYPT_SECOND_PASSWORD was never read and the ignored-variable
    # warning told the user to pass --hidden-header -- a flag argparse then
    # rejected on this route, leaving only the tty prompt that the env channel
    # exists to replace for GUI/CI callers (gitlab#180). Same flag/semantics as
    # the encrypt/decrypt subparsers' --hidden-header: it REQUESTS the second
    # password so the environment value is read only when it is present.
    parser.add_argument(
        "--hidden-header",
        action="store_true",
        help="Expect the hidden (whitened) format and request the second password "
        "for a keyed hidden file; $OPENSSL_ENCRYPT_SECOND_PASSWORD is read only "
        "when this (or --second-password-prompt) is present.",
    )
    parser.add_argument(
        "--overwrite",
        "-f",
        action="store_true",
        help="Overwrite the input file with the output",
    )
    parser.add_argument(
        "--shred",
        "-s",
        action="store_true",
        help="Securely delete the original file after encryption/decryption",
    )
    parser.add_argument(
        "--shred-passes",
        type=int,
        default=3,
        help="Number of passes for secure deletion (default: 3)",
    )
    parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        help="Process directories recursively when shredding",
    )
    parser.add_argument(
        "--no-estimate",
        action="store_true",
        help="Suppress decryption time/memory estimation display (useful when you trust the file)",
    )

    # # Add memory security option
    # parser.add_argument(
    #     '--disable-secure-memory',
    #     action='store_true',
    #     help='Disable secure memory handling (not recommended)'
    # )

    # Group hash configuration arguments for better organization
    hash_group = parser.add_argument_group(
        "Hash Options", "Configure hashing algorithms for key derivation"
    )

    # Add global KDF rounds parameter
    hash_group.add_argument(
        "--kdf-rounds",
        type=int,
        default=0,
        help="Default number of rounds for all KDFs when enabled without specific rounds (overrides the default of 10)",
    )

    # SHA family arguments - updated to match the template naming
    hash_group.add_argument(
        "--sha512-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA-512 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--sha384-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA-384 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--sha256-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA-256 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--sha224-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA-224 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--sha3-256-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA3-256 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--sha3-512-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA3-512 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--sha3-384-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA3-384 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--sha3-224-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHA3-224 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--blake2b-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of BLAKE2b iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--blake3-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of BLAKE3 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--shake256-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHAKE-256 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--shake128-rounds",
        type=int,
        nargs="?",
        const=1,
        default=0,
        help="Number of SHAKE-128 iterations (default: 1,000,000 if flag provided without value)",
    )
    hash_group.add_argument(
        "--whirlpool-rounds",
        type=int,
        default=0,
        help="Number of Whirlpool iterations (default: 0, not used)",
    )

    # PBKDF2 option - renamed for consistency
    hash_group.add_argument(
        "--pbkdf2-iterations",
        type=int,
        default=0,
        help="Number of PBKDF2 iterations (default: 100000)",
    )

    # Scrypt parameters group - updated to match the template naming
    scrypt_group = parser.add_argument_group(
        "Scrypt Options", "Configure Scrypt memory-hard function parameters"
    )
    scrypt_group.add_argument(
        "--enable-scrypt",
        action="store_true",
        help="Use Scrypt password hashing (requires scrypt package)",
        default=False,
    )
    scrypt_group.add_argument(
        "--scrypt-rounds",
        type=int,
        default=0,  # Changed from 1 to 0 to make the implicit setting work
        help="Use scrypt rounds for iterating (default when enabled: 10)",
    )
    scrypt_group.add_argument(
        "--scrypt-n",
        type=int,
        default=0,
        help="Scrypt CPU/memory cost factor N (default: 16384 when scrypt is enabled. Must be power of 2)",
    )
    scrypt_group.add_argument(
        "--scrypt-r",
        type=int,
        default=8,
        help="Scrypt block size parameter r (default: 8)",
    )
    scrypt_group.add_argument(
        "--scrypt-p",
        type=int,
        default=1,
        help="Scrypt parallelization parameter p (default: 1)",
    )

    # Add legacy option for backward compatibility
    scrypt_group.add_argument(
        "--scrypt-cost",
        type=int,
        default=0,
        help=argparse.SUPPRESS,  # Hidden legacy option
    )

    # HKDF options
    hkdf_group = parser.add_argument_group(
        "HKDF Options", "Configure HMAC-based Key Derivation Function"
    )
    hkdf_group.add_argument(
        "--enable-hkdf",
        action="store_true",
        help="Enable HKDF key derivation",
        default=False,
    )
    hkdf_group.add_argument(
        "--hkdf-rounds",
        type=int,
        default=1,
        help="Number of HKDF chained rounds (default: 1)",
    )
    hkdf_group.add_argument(
        "--hkdf-algorithm",
        choices=["sha224", "sha256", "sha384", "sha512"],
        default="sha256",
        help="Hash algorithm for HKDF (default: sha256)",
    )
    hkdf_group.add_argument(
        "--hkdf-info",
        type=str,
        default="openssl_encrypt_hkdf",
        help="HKDF info string for context (default: openssl_encrypt_hkdf)",
    )

    # RandomX options
    randomx_group = parser.add_argument_group(
        "RandomX Options", "Configure RandomX Key Derivation Function"
    )
    randomx_group.add_argument(
        "--enable-randomx",
        action="store_true",
        help="Enable RandomX key derivation (disabled by default, requires pyrx package)",
        default=False,
    )
    randomx_group.add_argument(
        "--randomx-rounds",
        type=int,
        default=0,  # Changed from 1 to 0 to make the implicit setting work
        help="Number of RandomX rounds (default when enabled: 10)",
    )
    randomx_group.add_argument(
        "--randomx-mode",
        choices=["light", "fast"],
        default="light",
        help="RandomX mode: light (256MB RAM) or fast (2GB RAM, default: light)",
    )
    randomx_group.add_argument(
        "--randomx-height",
        type=int,
        default=1,
        help="RandomX block height parameter (default: 1)",
    )
    randomx_group.add_argument(
        "--randomx-hash-len",
        type=int,
        default=32,
        help="RandomX output hash length in bytes (default: 32)",
    )

    # Add Keystore options
    keystore_group = parser.add_argument_group(
        "Keystore Options", "Configure keystore integration for key management"
    )
    keystore_group.add_argument("--keystore", help="Path to the keystore file")
    keystore_group.add_argument(
        "--keystore-path",
        dest="keystore",
        help="Path to the keystore file (alias for --keystore)",
    )
    keystore_group.add_argument(
        "--keystore-password",
        help="Password for the keystore (will prompt if not provided)",
    )
    keystore_group.add_argument(
        "--keystore-password-file", help="File containing the keystore password"
    )
    keystore_group.add_argument("--key-id", help="ID of the key to use from keystore")
    keystore_group.add_argument(
        "--dual-encrypt-key",
        action="store_true",
        help="Use dual encryption for the key (requires both keystore and file passwords)",
    )
    keystore_group.add_argument(
        "--auto-generate-key",
        action="store_true",
        help="Explicitly request to generate and store a PQC key in the keystore (happens automatically for PQC algorithms)",
    )
    keystore_group.add_argument(
        "--auto-create-keystore",
        action="store_true",
        help="Automatically create keystore if it does not exist",
    )

    # Add Post-Quantum Cryptography options
    pqc_group = parser.add_argument_group("Post-Quantum Cryptography Options")
    pqc_group.add_argument("--pqc-keyfile", help="Path to store or load post-quantum key pair")
    pqc_group.add_argument(
        "--pqc-store-key",
        action="store_true",
        help="Store the post-quantum private key in the encrypted file (less secure but enables self-decryption)",
    )
    pqc_group.add_argument(
        "--pqc-gen-key",
        action="store_true",
        help="Generate a new post-quantum key pair and store in the path specified by --pqc-keyfile",
    )

    # Argon2 parameters group - updated for consistency
    argon2_group = parser.add_argument_group(
        "Argon2 Options", "Configure Argon2 memory-hard function parameters"
    )
    argon2_group.add_argument(
        "--enable-argon2",
        action="store_true",
        help="Use Argon2 password hashing (requires argon2-cffi package)",
        default=False,
    )
    argon2_group.add_argument(
        "--argon2-rounds",
        type=int,
        default=0,  # Changed from 1 to 0 to make the implicit setting work
        help="Argon2 time cost parameter (default when enabled: 10)",
    )
    argon2_group.add_argument(
        "--argon2-time",
        type=int,
        default=3,
        help="Argon2 time cost parameter (default: 3)",
    )
    argon2_group.add_argument(
        "--argon2-memory",
        type=int,
        default=65536,
        help="Argon2 memory cost in KB (default: 65536 - 64MB)",
    )
    argon2_group.add_argument(
        "--argon2-parallelism",
        type=int,
        default=4,
        help="Argon2 parallelism factor (default: 4)",
    )
    argon2_group.add_argument(
        "--argon2-hash-len",
        type=int,
        default=32,
        help="Argon2 hash length in bytes (default: 32)",
    )
    argon2_group.add_argument(
        "--argon2-type",
        choices=["id", "i", "d"],
        default="id",
        help="Argon2 variant to use: id (recommended), i, or d",
    )
    argon2_group.add_argument(
        "--argon2-preset",
        choices=["low", "medium", "high", "paranoid"],
        help="Use predefined Argon2 parameters (overrides other Argon2 settings)",
    )

    # Add legacy option for backward compatibility
    argon2_group.add_argument(
        "--use-argon2",
        action="store_true",
        help=argparse.SUPPRESS,  # Hidden legacy option
    )

    balloon_group = parser.add_argument_group("Balloon Hashing options")
    balloon_group.add_argument(
        "--enable-balloon",
        action="store_true",
        help="Enable Balloon Hashing KDF",  # Hidden legacy option''
    )
    balloon_group.add_argument(
        "--balloon-time-cost",
        type=int,
        default=3,
        help="Time cost parameter for Balloon hashing - controls computational complexity. Higher values increase security but also processing time.",
    )
    balloon_group.add_argument(
        "--balloon-space-cost",
        type=int,
        default=65536,
        help="Space cost parameter for Balloon hashing in bytes - controls memory usage. Higher values increase security but require more memory.",
    )
    balloon_group.add_argument(
        "--balloon-parallelism",
        type=int,
        default=4,
        help="Parallelism parameter for Balloon hashing - controls number of parallel threads. Higher values can improve performance on multi-core systems.",
    )
    balloon_group.add_argument(
        "--balloon-rounds",
        type=int,
        default=0,  # Changed from 2 to 0 to make the implicit setting work
        help="Number of rounds for Balloon hashing (default when enabled: 10). More rounds increase security but also processing time.",
    )
    balloon_group.add_argument(
        "--balloon-hash-len",
        type=int,
        default=32,
        help="Length of the final hash output in bytes for Balloon hashing.",
    )
    balloon_group.add_argument(
        "--use-balloon",
        action="store_true",
        help=argparse.SUPPRESS,  # Hidden legacy option'
    )

    # Legacy options for backward compatibility
    hash_group.add_argument(
        "--sha512", type=int, nargs="?", const=1, default=0, help=argparse.SUPPRESS
    )
    hash_group.add_argument(
        "--sha256", type=int, nargs="?", const=1, default=0, help=argparse.SUPPRESS
    )
    hash_group.add_argument(
        "--sha3-256", type=int, nargs="?", const=1, default=0, help=argparse.SUPPRESS
    )
    hash_group.add_argument(
        "--sha3-512", type=int, nargs="?", const=1, default=0, help=argparse.SUPPRESS
    )
    hash_group.add_argument(
        "--blake2b", type=int, nargs="?", const=1, default=0, help=argparse.SUPPRESS
    )
    hash_group.add_argument(
        "--shake256", type=int, nargs="?", const=1, default=0, help=argparse.SUPPRESS
    )
    hash_group.add_argument("--pbkdf2", type=int, default=100000, help=argparse.SUPPRESS)

    # Password generation options
    password_group = parser.add_argument_group("Password Generation Options")
    password_group.add_argument(
        "--length",
        type=int,
        default=16,
        help="Length of generated password (default: 16)",
    )
    password_group.add_argument(
        "--use-digits",
        action="store_true",
        # default=None, not the implicit False: _charclass then treats both
        # parser routes alike (gitlab#181). With False the monolithic route
        # fell into generate_strong_password's empty-pool fallback and
        # produced a 62-char alphabet while the subparser route produced 94.
        default=None,
        help="Include digits in generated password",
    )
    password_group.add_argument(
        "--use-lowercase",
        action="store_true",
        default=None,
        help="Include lowercase letters in generated password",
    )
    password_group.add_argument(
        "--use-uppercase",
        action="store_true",
        default=None,
        help="Include uppercase letters in generated password",
    )
    password_group.add_argument(
        "--use-special",
        action="store_true",
        default=None,
        help="Include special characters in generated password",
    )

    # Diceware mode (mutually exclusive with the character-based flags
    # above; mutex enforced at runtime in the handler).
    dice_group = parser.add_argument_group(
        "Diceware Mode",
        "Generate a passphrase by drawing words from a wordlist (use with generate-password). "
        "Mutually exclusive with the character-based generation flags.",
    )
    dice_group.add_argument(
        "--dice",
        action="store_true",
        help="Generate a Diceware-style passphrase instead of a character-based password",
    )
    dice_group.add_argument(
        "--dice-count",
        type=int,
        default=10,
        metavar="N",
        help="Number of words in the Diceware passphrase (default: 10, ~129 bits with the bundled EFF list)",
    )
    dice_group.add_argument(
        "--dice-sep",
        type=str,
        default="",
        metavar="SEP",
        help='Separator between Diceware words (default: "" for maximum compatibility)',
    )
    dice_group.add_argument(
        "--dice-list",
        type=str,
        default=None,
        metavar="PATH",
        help="Path to a custom wordlist (EFF format or plain). Default: bundled EFF Large Wordlist",
    )
    dice_group.add_argument(
        "--force-wordlist",
        action="store_true",
        help="Allow wordlists below the 1024-word minimum (otherwise rejected)",
    )

    # Password policy options
    policy_group = parser.add_argument_group(
        "Password Policy Options", "Configure password strength validation"
    )
    policy_group.add_argument(
        "--password-policy",
        choices=["minimal", "basic", "standard", "paranoid", "none"],
        default="standard",
        help="Password policy level to enforce (default: standard)",
    )
    policy_group.add_argument(
        "--min-password-length",
        type=int,
        help="Minimum password length (overrides policy level)",
    )
    policy_group.add_argument(
        "--min-password-entropy",
        type=float,
        help="Minimum password entropy in bits (overrides policy level)",
    )
    policy_group.add_argument(
        "--strict-strength",
        action="store_true",
        help=(
            "Gate on the pattern-aware strength estimate instead of raw entropy, "
            "so predictable passwords (dictionary words, sequences, keyboard walks) "
            "are rejected. Enabled automatically by the paranoid policy."
        ),
    )
    policy_group.add_argument(
        "--disable-common-password-check",
        action="store_true",
        help="Disable checking against common password lists",
    )
    policy_group.add_argument(
        "--force-password",
        action="store_true",
        help="Force acceptance of weak passwords (use with caution)",
    )
    policy_group.add_argument(
        "--custom-password-list", help="Path to custom common password list file"
    )

    # USB/Portable Media Options
    usb_group = parser.add_argument_group("USB/Portable Media Options")
    usb_group.add_argument(
        "--usb-path", help="Path to USB drive for create-usb/verify-usb operations"
    )
    usb_group.add_argument(
        "--security-profile",
        choices=["standard", "high-security", "paranoid"],
        default="standard",
        help="Security profile for USB drive (default: standard)",
    )
    usb_group.add_argument(
        "--executable-path", help="Path to OpenSSL Encrypt executable to include on USB"
    )
    usb_group.add_argument("--keystore-to-include", help="Path to keystore file to include on USB")
    usb_group.add_argument(
        "--include-logs", action="store_true", help="Enable logging on USB drive"
    )
    usb_group.add_argument(
        "--manifest-password",
        help="Separate password for integrity manifest (enhances security by separating file access from integrity verification)",
    )
    usb_group.add_argument(
        "--manifest-security-profile",
        choices=["standard", "high-security", "paranoid"],
        help="Security profile for manifest encryption (uses main profile if not specified)",
    )

    # Plugin system options group
    plugin_group = parser.add_argument_group("Plugin Options", "Configure plugin system behavior")
    plugin_group.add_argument(
        "--enable-plugins",
        action="store_true",
        default=True,
        help="Enable plugin system (default: True)",
    )
    plugin_group.add_argument(
        "--disable-plugins", action="store_true", help="Disable plugin system"
    )
    plugin_group.add_argument("--plugin-dir", help="Directory to scan for plugins")
    plugin_group.add_argument("--plugin-config-dir", help="Directory for plugin configurations")
    plugin_group.add_argument("--plugin-id", help="Plugin ID for plugin-specific operations")

    # HSM plugin arguments
    plugin_group.add_argument(
        "--hsm",
        metavar="PLUGIN",
        help="Enable HSM (Hardware Security Module) plugin for hardware-bound key derivation. "
        "Supported: 'yubikey' (YubiKey Challenge-Response, slots 1..2), "
        "'onlykey' (OnlyKey Challenge-Response, slots 1..12), "
        "'fido2' (FIDO2 hmac-secret). "
        "The HSM adds a hardware-specific pepper to the key derivation, requiring the device "
        "for both encryption and decryption.",
    )
    plugin_group.add_argument(
        "--hsm-slot",
        type=int,
        metavar="SLOT",
        help="Manually specify the Challenge-Response slot. Valid range is plugin-specific: "
        "YubiKey 1..2, OnlyKey 1..12. "
        "If not specified, the plugin will auto-detect the configured slot.",
    )

    # Streaming encryption options
    streaming_group = parser.add_argument_group(
        "Streaming Options", "Configure streaming encryption for large files"
    )
    streaming_group.add_argument(
        "--chunk-size",
        type=str,
        default=None,
        metavar="SIZE",
        help="Chunk size for streaming encryption (e.g., '512K', '1M', '4M'). "
        "Default: 1M. Only used for files above the streaming threshold.",
    )
    streaming_group.add_argument(
        "--no-streaming",
        action="store_true",
        help="Disable streaming mode and load entire file into memory.",
    )
    streaming_group.add_argument(
        "--streaming-threshold",
        type=str,
        default=None,
        metavar="SIZE",
        help="File size threshold for automatic streaming mode (e.g., '10M', '100M'). "
        "Default: 10M. Files below this size use one-shot encryption.",
    )

    parser.add_argument(
        "--envelope",
        action="store_true",
        help="Envelope mode: encrypt the data under a random data key (DEK) that is "
        "wrapped with your password-derived key. A future 'rekey' then only rewraps "
        "the small DEK instead of re-encrypting the whole file. Decryption "
        "auto-detects envelope files; default off.",
    )

    # Add CLI aliases for simplified user experience
    alias_processor = add_cli_aliases(parser)

    # Don't parse args again if they're already provided from subparser
    # This avoids the "unrecognized arguments" error for steganography options
    if args is None:
        args = parser.parse_args()

        # Process CLI aliases and apply overrides
        args, alias_errors = process_cli_aliases(args, alias_processor)
        if alias_errors:
            # No `sys.` here: the local `import sys` further down makes the
            # name local to this whole function, so touching it above that
            # line raises UnboundLocalError -- this path would have crashed
            # with a traceback instead of reporting the alias errors.
            for error in alias_errors:
                eprint(f"Error: {error}")
            raise SystemExit(1)

    # Add compatibility layer for subparser args - set missing attributes to defaults
    default_attrs = {
        "password_policy": "none",
        "argon2_preset": None,
        "sha512": None,
        "sha256": None,
        "sha3_256": None,
        "sha3_512": None,
        "blake2b": None,
        "shake256": None,
        "pbkdf2": 100000,
        "use_argon2": False,
        "enable_balloon": False,
        "use_balloon": False,
        "scrypt_cost": 0,
        "scrypt_n": 0,
        "scrypt_r": 8,
        "scrypt_p": 1,
        "whirlpool_rounds": 0,
        "tiger_rounds": 0,
        "ripemd160_rounds": 0,
        "sha1_rounds": 0,
        "md5_rounds": 0,
        "md4_rounds": 0,
        "custom_password_list": None,
        "password_length": 64,
        "password_charset": None,
        "password_file": None,
        "show_password_policy": False,
        "balloon_cost": 14,
        "sha512_rounds": None,
        "sha256_rounds": None,
        "sha3_256_rounds": None,
        "sha3_512_rounds": None,
        "blake2b_rounds": None,
        "shake256_rounds": None,
        "sha384_rounds": None,
        "sha224_rounds": None,
        "sha3_384_rounds": None,
        "sha3_224_rounds": None,
        "blake3_rounds": None,
        "shake128_rounds": None,
        "pbkdf2_iterations": 0,
        "enable_argon2": False,
        "argon2_type": "id",
        "argon2_memory": 65536,
        "argon2_time": 3,
        "argon2_parallelism": 1,
        "argon2_hash_len": 32,
        "argon2_rounds": 1,
        "balloon_time_cost": 1,
        "balloon_space_cost": 1024,
        "balloon_parallelism": 1,
        "balloon_hash_len": 32,
        "hkdf_rounds": 1,
        "hkdf_algorithm": "sha256",
        "hkdf_info": "openssl_encrypt_hkdf",
        "enable_hkdf": False,
        "algorithm": None,
        "random": None,
        "overwrite": False,
        "shred": False,
        "shred_passes": 3,
        "pqc_keyfile": None,
        "pqc_store_key": False,
        "pqc_gen_key": False,
        "kdf_rounds": 0,
        "enable_scrypt": False,
        "scrypt_rounds": 0,
        "balloon_rounds": 0,
        "keystore_path": None,
        "keystore_password": None,
        "dual_encrypt_key": None,
        "encryption_data": None,
        "enable_plugins": False,
        "disable_plugins": False,
        "plugin_dir": None,
        "plugin_config_dir": None,
        "plugin_id": None,
        "quick": False,
        "standard": False,
        "paranoid": False,
        "template": None,
        "force_password": False,
        # CLI alias defaults
        "fast": False,
        "secure": False,
        "max_security": False,
        "crypto_family": None,
        "quantum_safe": None,
        "for_personal": False,
        "for_business": False,
        "for_archival": False,
        "for_compliance": False,
        # Analyze-config specific defaults
        "use_case": None,
        "compliance_frameworks": None,
        "output_format": "text",
        # Rekey-specific defaults
        "rekey_password": None,
        "rekey_password_file": None,
        "rekey_password_fd": None,
        "min_password_length": None,
        "min_password_entropy": None,
        "disable_common_password_check": False,
        # Streaming defaults
        "chunk_size": None,
        "no_streaming": False,
        "streaming_threshold": None,
        # Hidden-header (whitened format) defaults
        "hidden_header": False,
        "legacy_format": False,
        "second_password": None,
        "second_password_fd": None,
        "second_password_prompt": False,
        "no_second_password_prompt": False,
    }

    for attr, default_val in default_attrs.items():
        if not hasattr(args, attr):
            setattr(args, attr, default_val)

    # Resolve the optional second password (hidden keyed mode) exactly once, so
    # an interactive prompt is shown at most a single time per invocation.
    # NOTE: only the *explicit* forms (--second-password / -fd / -prompt) are
    # resolved here. The auto-detect fallback (keyless peek + prompt) runs later,
    # AFTER stdin buffering and de-armoring, so it can peek a seekable file even
    # when the ciphertext arrives on stdin (e.g. armor ... | decrypt -i /dev/stdin).
    # This runs for EVERY subcommand, well outside the main try/except, so an
    # unhandled CredentialError here would be a raw traceback out of an
    # unrelated command (`shred`, `list-algorithms`, ...) merely because a
    # blank variable was exported.
    try:
        _hidden_second_password = _resolve_second_password(args)
    except CredentialError as e:
        # No `sys.` here: main_with_args has a local `import sys` further down,
        # which makes the name local to the whole function, so touching it
        # before that line raises UnboundLocalError. eprint already writes to
        # stderr, and SystemExit is sys.exit's underlying mechanism.
        eprint(f"ERROR: {e}")
        raise SystemExit(2)

    # Consume $OPENSSL_ENCRYPT_SIGNER_PASSPHRASE here, right after argument
    # handling and alongside the second-password consume above -- BEFORE the
    # plugin system, HSM/pepper plugins and keyserver connections come up on the
    # `encrypt --sign-with` path (gitlab#180). `sign` consumes it as its first
    # statement for the same reason; consuming it this early (rather than just
    # before the plugin block) keeps the read-once-and-remove guarantee robust
    # against future code being added ahead of that block. Passed to
    # resolve_credential below as explicit=.
    _early_signer_passphrase = _consume_encrypt_signer_passphrase(args)

    # Store the original user-provided algorithm name from command line
    import sys

    original_algorithm = None
    for i, arg in enumerate(sys.argv):
        if arg == "--algorithm" and i + 1 < len(sys.argv):
            original_algorithm = sys.argv[i + 1]
            break

    # --unsafe-show-secrets is only meaningful (and only safe to accept)
    # together with --debug. Validate before doing any work.
    unsafe_show_secrets = getattr(args, "unsafe_show_secrets", False)
    if unsafe_show_secrets and not args.debug:
        eprint("Error: --unsafe-show-secrets is only valid in combination with --debug")
        sys.exit(2)

    # Configure logging level based on debug flag
    if args.debug:
        import logging

        # Cleartext secrets in debug output are an explicit opt-in; the
        # default is redaction via the debug_secret() chokepoint.
        set_show_secrets(unsafe_show_secrets)

        # Configure the root logger to DEBUG level
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)

        # Also configure this module's logger explicitly
        logger.setLevel(logging.DEBUG)

        # Keep third-party HTTP libraries out of DEBUG. urllib3 logs the full
        # request line, and the keyserver interpolates the identifier -- a
        # fingerprint or an email address -- into the request path, so DEBUG
        # would put contact metadata on stderr and into the desktop GUI's
        # persistent debug log, entirely outside the debug_secret()
        # chokepoint. This matters since gitlab#171: --debug now actually
        # reaches `keyserver` and `telemetry`, where argparse used to reject
        # it before any of this ran.
        for _noisy in ("urllib3", "requests", "httpx", "httpcore", "asyncio"):
            logging.getLogger(_noisy).setLevel(logging.WARNING)

        # Try to configure basic config for new handlers, but don't fail if handlers exist
        try:
            logging.basicConfig(
                level=logging.DEBUG, format="%(levelname)s - %(name)s - %(message)s"
            )
        except Exception:
            pass

        # Debug notice. The loud "SENSITIVE DATA" banner is reserved for the
        # path that actually leaks secrets (--unsafe-show-secrets). Plain
        # --debug redacts every secret via the debug_secret() chokepoint, so it
        # only gets a calm, accurate note — an alarming banner there would both
        # overstate the risk and desensitise users to the real warning.
        if unsafe_show_secrets:
            eprint("\n" + "=" * 78)
            eprint("⚠️  WARNING: DEBUG MODE ENABLED - SENSITIVE DATA LOGGING ACTIVE")
            eprint("=" * 78)
            eprint("Debug mode logs sensitive information including:")
            eprint("  ❗ SECRETS IN CLEARTEXT (--unsafe-show-secrets is active):")
            eprint("     passwords, key material, KDF intermediates and hardware")
            eprint("     peppers ARE BEING SHOWN in this output")
            eprint("  • Detailed cryptographic operation traces")
            eprint("  • Internal state information")
            eprint()
            eprint("SECURITY NOTICE:")
            eprint("  ❌ DO NOT use --unsafe-show-secrets with production data or real passwords")
            eprint("  ✅ Only use for testing with dummy/test data")
            eprint("  ⚠️  Debug logs may be stored in log files or terminal history")
            eprint("=" * 78 + "\n")
        else:
            eprint("DEBUG: Debug logging enabled. Secret values (passwords, key material,")
            eprint("       KDF intermediates, hardware peppers) are REDACTED to length + a")
            eprint("       keyed SHA-256 fingerprint; secret lengths and public values")
            eprint("       (nonces, salts, ciphertext) are shown. Add --unsafe-show-secrets")
            eprint("       to reveal secrets in cleartext.")
            eprint("       Note: secret LENGTHS and public values are written to stderr and")
            eprint("       may persist in log files or shell history.\n")

        # The argv dump must not leak any secret passed as a CLI option value.
        eprint(f"DEBUG: sys.argv = {sanitize_argv_for_debug(sys.argv)}")

        # Enable raw exception passthrough in debug mode
        set_debug_mode(True)
        eprint("DEBUG: Raw exception passthrough enabled")

    # Enhance the args with better defaults for extended algorithms
    args = enhance_cli_args(args)

    # Configure algorithm warnings based on verbose and debug flags
    AlgorithmWarningConfig.configure(verbose_mode=args.verbose or args.debug)

    # Handle legacy options and map to new names
    # SHA family mappings - use getattr for safety with subparser args
    if not getattr(args, "sha512_rounds", None) and getattr(args, "sha512", None):
        args.sha512_rounds = args.sha512
    if not getattr(args, "sha256_rounds", None) and getattr(args, "sha256", None):
        args.sha256_rounds = args.sha256
    if not getattr(args, "sha3_256_rounds", None) and getattr(args, "sha3_256", None):
        args.sha3_256_rounds = args.sha3_256
    if not getattr(args, "sha3_512_rounds", None) and getattr(args, "sha3_512", None):
        args.sha3_512_rounds = args.sha3_512
    if not getattr(args, "blake2b_rounds", None) and getattr(args, "blake2b", None):
        args.blake2b_rounds = args.blake2b
    if not getattr(args, "shake256_rounds", None) and getattr(args, "shake256", None):
        args.shake256_rounds = args.shake256

    # PBKDF2 mapping
    pbkdf2_val = getattr(args, "pbkdf2", 100000)
    if pbkdf2_val != 100000:  # Only override if not the default
        args.pbkdf2_iterations = pbkdf2_val

    # Argon2 mapping
    if getattr(args, "use_argon2", False):
        args.enable_argon2 = True

    if getattr(args, "enable_balloon", False):
        args.use_balloon = True

    if args.action == "version":
        eprint(show_version_info())
        return 0

    if args.action == "show-version-file":
        try:
            from openssl_encrypt.version import get_version_info, print_version_info

            # Call print_version_info function to show detailed version information
            print_version_info()

            # Additionally, show the full version info dictionary
            version_info = get_version_info()
            eprint("\nComplete Version Information:")
            eprint("----------------------------")
            for key, value in version_info.items():
                if key == "history":
                    # Skip history as it was already printed by print_version_info
                    continue
                eprint(f"{key}: {value}")

            return 0
        except ImportError:
            eprint("Version module not found. Run 'pip install -e .' to generate the version file.")
            return 1

    # Handle USB operations
    if args.action == "create-usb":
        try:
            from .portable_media import create_portable_usb

            # Validate required arguments
            if not getattr(args, "usb_path", None):
                eprint("Error: --usb-path is required for create-usb operation")
                return 1

            if not args.password:
                args.password = getpass.getpass("Enter master password for USB encryption: ")

            # Build hash config from current args (using correct key format for create)
            hash_config = {}
            if hasattr(args, "sha512_rounds") and args.sha512_rounds:
                hash_config["sha512"] = args.sha512_rounds
            if hasattr(args, "sha384_rounds") and args.sha384_rounds:
                hash_config["sha384"] = args.sha384_rounds
            if hasattr(args, "sha256_rounds") and args.sha256_rounds:
                hash_config["sha256"] = args.sha256_rounds
            if hasattr(args, "sha224_rounds") and args.sha224_rounds:
                hash_config["sha224"] = args.sha224_rounds
            if hasattr(args, "sha3_512_rounds") and args.sha3_512_rounds:
                hash_config["sha3_512"] = args.sha3_512_rounds
            if hasattr(args, "sha3_384_rounds") and args.sha3_384_rounds:
                hash_config["sha3_384"] = args.sha3_384_rounds
            if hasattr(args, "sha3_256_rounds") and args.sha3_256_rounds:
                hash_config["sha3_256"] = args.sha3_256_rounds
            if hasattr(args, "sha3_224_rounds") and args.sha3_224_rounds:
                hash_config["sha3_224"] = args.sha3_224_rounds
            if hasattr(args, "blake2b_rounds") and args.blake2b_rounds:
                hash_config["blake2b"] = args.blake2b_rounds
            if hasattr(args, "blake3_rounds") and args.blake3_rounds:
                hash_config["blake3"] = args.blake3_rounds
            if hasattr(args, "shake256_rounds") and args.shake256_rounds:
                hash_config["shake256"] = args.shake256_rounds
            if hasattr(args, "shake128_rounds") and args.shake128_rounds:
                hash_config["shake128"] = args.shake128_rounds
            if hasattr(args, "whirlpool_rounds") and args.whirlpool_rounds:
                hash_config["whirlpool"] = args.whirlpool_rounds

            # --pbkdf2-iterations is refused rather than recorded (gitlab#205).
            # multi_hash_password never reads it -- 100k and 5M derive the
            # identical key -- but it WAS written into hash_config.json and
            # .integrity, so the drive advertised a work factor that was never
            # applied. Recording a control that was not applied is the same
            # defect as gitlab#199; say so instead.
            if getattr(args, "pbkdf2_iterations", 0):
                eprint(
                    "Error: --pbkdf2-iterations has no effect on USB drives and "
                    "would be recorded without being applied."
                )
                eprint(
                    "  Use the hash round options instead, e.g. --sha512-rounds, "
                    "which are applied and stored on the drive."
                )
                return 1

            # No rounds named at all: record a strong default rather than
            # falling through to the PBKDF2-100k fallback (gitlab#205). It has
            # to be RECORDED, not just used, because verification re-derives
            # from whatever the drive stores.
            if not hash_config:
                from .portable_media.usb_creator import default_usb_hash_config

                hash_config = default_usb_hash_config()

            # Build manifest hash config if manifest security profile specified
            manifest_hash_config = None
            if getattr(args, "manifest_security_profile", None):
                # Build separate hash config for manifest based on manifest security profile
                manifest_hash_config = {}
                # Use same hash rounds as main config, but apply to manifest profile
                if hasattr(args, "sha512_rounds") and args.sha512_rounds:
                    manifest_hash_config["sha512"] = args.sha512_rounds
                if hasattr(args, "sha384_rounds") and args.sha384_rounds:
                    manifest_hash_config["sha384"] = args.sha384_rounds
                if hasattr(args, "sha256_rounds") and args.sha256_rounds:
                    manifest_hash_config["sha256"] = args.sha256_rounds
                if hasattr(args, "sha224_rounds") and args.sha224_rounds:
                    manifest_hash_config["sha224"] = args.sha224_rounds
                if hasattr(args, "sha3_512_rounds") and args.sha3_512_rounds:
                    manifest_hash_config["sha3_512"] = args.sha3_512_rounds
                if hasattr(args, "sha3_384_rounds") and args.sha3_384_rounds:
                    manifest_hash_config["sha3_384"] = args.sha3_384_rounds
                if hasattr(args, "sha3_256_rounds") and args.sha3_256_rounds:
                    manifest_hash_config["sha3_256"] = args.sha3_256_rounds
                if hasattr(args, "sha3_224_rounds") and args.sha3_224_rounds:
                    manifest_hash_config["sha3_224"] = args.sha3_224_rounds
                if hasattr(args, "blake2b_rounds") and args.blake2b_rounds:
                    manifest_hash_config["blake2b"] = args.blake2b_rounds
                if hasattr(args, "blake3_rounds") and args.blake3_rounds:
                    manifest_hash_config["blake3"] = args.blake3_rounds
                if hasattr(args, "shake256_rounds") and args.shake256_rounds:
                    manifest_hash_config["shake256"] = args.shake256_rounds
                if hasattr(args, "shake128_rounds") and args.shake128_rounds:
                    manifest_hash_config["shake128"] = args.shake128_rounds
                if hasattr(args, "whirlpool_rounds") and args.whirlpool_rounds:
                    manifest_hash_config["whirlpool"] = args.whirlpool_rounds
                if hasattr(args, "pbkdf2_iterations") and args.pbkdf2_iterations:
                    manifest_hash_config["pbkdf2_iterations"] = args.pbkdf2_iterations

            # Create USB
            security_profile = getattr(args, "security_profile", "standard")
            # The interactive gate lives here, not in the library: a
            # function that prompts is unusable from a script (gitlab#207).
            # _is_removable_drive only ever logged a warning, so a mistyped
            # path went ahead and wrote a drive into e.g. the home directory.
            from .portable_media.usb_creator import USBDriveCreator as _USBDriveCreator

            forced = bool(getattr(args, "yes", False))
            # args.usb_path, not Path(args.usb_path): `Path` is imported
            # function-locally further down main_with_args, which makes the
            # name function-local for the WHOLE function -- using it here
            # raises UnboundLocalError. _is_removable_drive only does
            # str(path) anyway.
            if not forced and not _USBDriveCreator()._is_removable_drive(args.usb_path):
                eprint(f"Warning: {args.usb_path} does not look like a removable drive.")
                eprint("  Creating a portable installation there will write into that")
                eprint("  directory and replace any autorun files it already contains.")
                if not sys.stdin.isatty():
                    eprint("Refusing to continue without --yes.")
                    return 1
                answer = prompt_and_read("Continue? [y/N]: ").strip().lower()
                if answer not in ("y", "yes"):
                    eprint("Aborted.")
                    return 1
                forced = True

            result = create_portable_usb(
                usb_path=args.usb_path,
                password=args.password,
                force=forced,
                security_profile=security_profile,
                executable_path=getattr(args, "executable_path", None),
                keystore_path=getattr(args, "keystore_to_include", None),
                include_logs=getattr(args, "include_logs", False),
                hash_config=hash_config if hash_config else None,
                algorithm=args.algorithm,  # Pass algorithm from CLI
                manifest_password=getattr(args, "manifest_password", None),
                manifest_security_profile=getattr(args, "manifest_security_profile", None),
                manifest_hash_config=manifest_hash_config,
            )

            if result.get("success"):
                eprint(f"✓ Successfully created portable USB at: {result['usb_path']}")
                eprint(f"  Security Profile: {result['security_profile']}")
                eprint(f"  Portable Root: {result['portable_root']}")
                if result["executable"]["included"]:
                    eprint(f"  Executable: {result['executable']['path']}")
                if result["keystore"]["included"]:
                    eprint("  Keystore: Encrypted and included")
                eprint(f"  Auto-run files: {', '.join(result['autorun']['files_created'])}")
                if result.get("manifest", {}).get("created"):
                    manifest_info = result["manifest"]
                    eprint(
                        f"  Hash Manifest: {manifest_info['files_covered']} files, {manifest_info['hash_algorithm']}"
                    )
                    eprint(
                        f"    Password: {manifest_info['password_type']}, Profile: {manifest_info.get('security_profile', 'default')}"
                    )
                    eprint("    Manual verification: VERIFY_INTEGRITY.md")
                return 0
            else:
                eprint("✗ Failed to create portable USB")
                return 1

        except ImportError:
            eprint("Error: Portable media module not available")
            return 1
        except Exception as e:
            eprint(f"Error creating USB: {e}")
            return 1

    elif args.action == "verify-usb":
        try:
            from .portable_media import verify_usb_integrity

            # Validate required arguments
            if not getattr(args, "usb_path", None):
                eprint("Error: --usb-path is required for verify-usb operation")
                return 1

            if not args.password:
                args.password = getpass.getpass("Enter master password for USB verification: ")

            # Build hash config from current args (using correct key format for verify)
            hash_config = {}
            if hasattr(args, "sha512_rounds") and args.sha512_rounds:
                hash_config["sha512"] = args.sha512_rounds
            if hasattr(args, "sha384_rounds") and args.sha384_rounds:
                hash_config["sha384"] = args.sha384_rounds
            if hasattr(args, "sha256_rounds") and args.sha256_rounds:
                hash_config["sha256"] = args.sha256_rounds
            if hasattr(args, "sha224_rounds") and args.sha224_rounds:
                hash_config["sha224"] = args.sha224_rounds
            if hasattr(args, "sha3_512_rounds") and args.sha3_512_rounds:
                hash_config["sha3_512"] = args.sha3_512_rounds
            if hasattr(args, "sha3_384_rounds") and args.sha3_384_rounds:
                hash_config["sha3_384"] = args.sha3_384_rounds
            if hasattr(args, "sha3_256_rounds") and args.sha3_256_rounds:
                hash_config["sha3_256"] = args.sha3_256_rounds
            if hasattr(args, "sha3_224_rounds") and args.sha3_224_rounds:
                hash_config["sha3_224"] = args.sha3_224_rounds
            if hasattr(args, "blake2b_rounds") and args.blake2b_rounds:
                hash_config["blake2b"] = args.blake2b_rounds
            if hasattr(args, "blake3_rounds") and args.blake3_rounds:
                hash_config["blake3"] = args.blake3_rounds
            if hasattr(args, "shake256_rounds") and args.shake256_rounds:
                hash_config["shake256"] = args.shake256_rounds
            if hasattr(args, "shake128_rounds") and args.shake128_rounds:
                hash_config["shake128"] = args.shake128_rounds
            if hasattr(args, "whirlpool_rounds") and args.whirlpool_rounds:
                hash_config["whirlpool"] = args.whirlpool_rounds
            if hasattr(args, "pbkdf2_iterations") and args.pbkdf2_iterations:
                hash_config["pbkdf2_iterations"] = args.pbkdf2_iterations

            result = verify_usb_integrity(
                usb_path=args.usb_path,
                password=args.password,
                hash_config=hash_config if hash_config else None,
            )

            if result.get("integrity_ok"):
                eprint("✓ USB integrity verification PASSED")
                eprint(f"  Files verified: {result['verified_files']}")
                eprint(
                    f"  Created at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result['created_at']))}"
                )
                return 0
            else:
                eprint("✗ USB integrity verification FAILED")
                eprint(f"  Files verified: {result['verified_files']}")
                eprint(f"  Failed files: {result['failed_files']}")
                eprint(f"  Missing files: {result['missing_files']}")
                # gitlab#132 F13: report files added to the drive after creation.
                eprint(f"  Added files: {result.get('added_files', 0)}")
                if result["tampered_files"]:
                    eprint(f"  Tampered files: {', '.join(result['tampered_files'])}")
                if result["missing_file_list"]:
                    eprint(f"  Missing files: {', '.join(result['missing_file_list'])}")
                if result.get("added_file_list"):
                    eprint(f"  Added files: {', '.join(result['added_file_list'])}")
                return 1

        except ImportError:
            eprint("Error: Portable media module not available")
            return 1
        except Exception as e:
            eprint(f"Error verifying USB: {e}")
            return 1

    # Handle scrypt_cost conversion to scrypt_n
    scrypt_cost = getattr(args, "scrypt_cost", 0)
    scrypt_n = getattr(args, "scrypt_n", 0)
    if scrypt_cost > 0 and scrypt_n == 0:
        args.scrypt_n = 2**scrypt_cost

    # Check for utility and information actions first
    if args.action == "security-info":
        show_security_recommendations()
        sys.exit(0)

    elif args.action == "analyze-security":
        analyze_current_security_configuration(args)
        sys.exit(0)

    elif args.action == "config-wizard":
        run_config_wizard(args)
        sys.exit(0)

    elif args.action == "analyze-config":
        run_config_analyzer(args)
        sys.exit(0)

    elif args.action == "template":
        _status = run_template_manager(args)
        sys.exit(0 if _status is None else _status)

    elif args.action == "smart-recommendations":
        run_smart_recommendations(args)
        sys.exit(0)

    elif args.action == "test":
        run_security_tests(args)
        sys.exit(0)

    elif args.action == "identity":
        from .identity_cli import main as identity_main

        sys.exit(identity_main(args))

    elif args.action == "plugin":
        from .plugin_system.plugin_cli import main as plugin_main

        sys.exit(plugin_main(args))

    elif args.action == "telemetry":
        _status = handle_telemetry_command(args)
        # Explicit: `or 0` would silently turn a future falsy status into
        # success, and sys.exit(None) exits 0.
        sys.exit(0 if _status is None else _status)

    elif args.action == "keyserver":
        handle_keyserver_command(args)
        sys.exit(0)

    elif args.action == "hsm":
        handle_hsm_command(args)
        sys.exit(0)

    elif args.action in ("armor", "dearmor"):
        from .armor import run_armor_cli

        sys.exit(run_armor_cli(args))

    elif args.action == "verify-integrity":
        from pathlib import Path

        from ..integrity.verify_cli import verify_integrity

        sys.exit(
            verify_integrity(
                manifest_path=Path(args.manifest) if args.manifest else None,
                signature_path=Path(args.signature) if args.signature else None,
                pubkey_path=Path(args.pubkey) if args.pubkey else None,
                installed=args.vi_installed,
                quiet=args.quiet,
                as_json=args.json,
            )
        )

    elif args.action == "sign":
        # Create a detached post-quantum signature for a file (feature #1)
        try:
            from .file_signature import sign_file_cli

            sign_file_cli(args)
            sys.exit(0)
        except Exception as e:
            print(f"Error: {sanitize_for_display(e)}", file=sys.stderr)
            sys.exit(1)

    elif args.action == "verify-signature":
        # Verify a detached signature for a file (feature #1)
        try:
            from .file_signature import verify_signature_cli

            verify_signature_cli(args)
            sys.exit(0)
        except Exception as e:
            print(f"Error: {sanitize_for_display(e)}", file=sys.stderr)
            sys.exit(1)

    elif args.action in ("list-recovery", "recover", "add-recovery", "remove-recovery"):
        try:
            from .recovery_slots import (
                add_recovery_cli,
                list_recovery_cli,
                recover_cli,
                remove_recovery_cli,
            )

            {
                "list-recovery": list_recovery_cli,
                "recover": recover_cli,
                "add-recovery": add_recovery_cli,
                "remove-recovery": remove_recovery_cli,
            }[args.action](args)
            sys.exit(0)
        except Exception as e:
            # Sanitized like its sibling handlers: these messages interpolate
            # untrusted header fields and filesystem paths, and one of them
            # now carries a data-recovery instruction -- exactly the line an
            # escape sequence would want to forge (gitlab#172 class).
            print(f"Error: {sanitize_for_display(e)}", file=sys.stderr)
            sys.exit(1)

    elif args.action == "list-algorithms":
        show_algorithm_registry(args)
        sys.exit(0)

    elif args.action == "list-available-algorithms":
        output_available_algorithms_json(args)
        sys.exit(0)

    elif args.action == "install-dependencies":
        install_optional_dependencies(args)
        sys.exit(0)

    elif args.action == "check-argon2":
        argon2_available, version, supported_types = check_argon2_support()
        eprint("\nARGON2 SUPPORT CHECK")
        eprint("====================")
        if argon2_available:
            eprint(f"✓ Argon2 is AVAILABLE (version {version})")
            variants = ", ".join("Argon2" + t for t in supported_types)
            eprint(f"✓ Supported variants: {variants}")

            # Try a test hash to verify functionality
            try:
                import argon2

                test_hash = argon2.low_level.hash_secret_raw(
                    b"test_password",
                    b"testsalt12345678",
                    time_cost=1,
                    memory_cost=8,
                    parallelism=1,
                    hash_len=16,
                    type=argon2.low_level.Type.ID,
                )
                if len(test_hash) == 16:
                    eprint("✓ Argon2 functionality test: PASSED")
                else:
                    eprint("✗ Argon2 functionality test: FAILED (unexpected hash length)")
            except Exception as e:
                eprint(f"✗ Argon2 functionality test: FAILED with error: {e}")
        else:
            eprint("✗ Argon2 is NOT AVAILABLE")
            eprint("\nTo enable Argon2 support, install the argon2-cffi package:")
            eprint("    pip install argon2-cffi")
        sys.exit(0)

    elif args.action == "check-pqc":
        from .pqc import PQCAlgorithm, check_pqc_support

        pqc_available, version, supported_algorithms = check_pqc_support(quiet=args.quiet)
        if not args.quiet:
            eprint("\nPOST-QUANTUM CRYPTOGRAPHY SUPPORT CHECK")
            eprint("======================================")
        if pqc_available:
            if not args.quiet:
                eprint(f"✓ Post-quantum cryptography is AVAILABLE (liboqs version {version})")
                eprint("✓ Supported algorithms:")

                # Organize algorithms by type
                kems = [algo for algo in supported_algorithms if "Kyber" in algo]
                sigs = [algo for algo in supported_algorithms if "Kyber" not in algo]

                if kems:
                    eprint("\n  Key Encapsulation Mechanisms (KEMs):")
                    for algo in kems:
                        eprint(f"    - {algo}")

                if sigs:
                    eprint("\n  Digital Signature Algorithms:")
                    for algo in sigs:
                        eprint(f"    - {algo}")

            # Try a test encryption to verify functionality
            try:
                from .pqc import PQCipher

                test_cipher = PQCipher(PQCAlgorithm.KYBER768, quiet=args.quiet)
                public_key, private_key = test_cipher.generate_keypair()
                test_data = b"Test post-quantum encryption"
                encrypted = test_cipher.encrypt(test_data, public_key)
                decrypted = test_cipher.decrypt(encrypted, private_key)

                if decrypted == test_data:
                    eprint("\n✓ Post-quantum encryption functionality test: PASSED")
                else:
                    eprint(
                        "\n✗ Post-quantum encryption functionality test: FAILED (decryption mismatch)"
                    )
            except Exception as e:
                eprint(f"\n✗ Post-quantum encryption functionality test: FAILED with error: {e}")
        else:
            eprint("✗ Post-quantum cryptography is NOT AVAILABLE")
            eprint(
                "\nTo enable post-quantum cryptography support, install the liboqs-python package:"
            )
            eprint("    pip install liboqs-python")

        eprint("\nUsage examples:")
        eprint("  Encrypt with Kyber-768 (NIST Level 3):")
        eprint(
            "    python -m openssl_encrypt.crypt encrypt -i file.txt --algorithm kyber768-hybrid"
        )
        eprint("\n  Generate and save a key pair:")
        eprint(
            "    python -m openssl_encrypt.crypt encrypt -i file.txt --algorithm kyber768-hybrid --pqc-gen-key --pqc-keyfile key.pqc"
        )
        eprint("\n  Decrypt using a saved key pair:")
        eprint(
            "    python -m openssl_encrypt.crypt decrypt -i file.txt.enc -o file.txt --pqc-keyfile key.pqc"
        )

        sys.exit(0)

    # Plugin management commands
    elif args.action == "list-plugins":
        try:
            from .plugin_system import create_default_plugin_manager

            plugin_manager = create_default_plugin_manager(args.plugin_config_dir)
            if args.plugin_dir:
                plugin_manager.add_plugin_directory(args.plugin_dir)

            # Discover and load plugins
            discovered = plugin_manager.discover_plugins()
            if not args.quiet:
                eprint(f"Discovered {len(discovered)} plugin files")

            # Load plugins
            for plugin_file in discovered:
                load_result = plugin_manager.load_plugin(plugin_file)
                if not load_result.success and not args.quiet:
                    eprint(f"⚠️  Failed to load {plugin_file}: {load_result.message}")

            # List loaded plugins
            plugins = plugin_manager.list_plugins()
            if not plugins:
                eprint("No plugins loaded")
            else:
                eprint("\nLoaded Plugins:")
                eprint("=" * 50)
                for plugin in plugins:
                    status = "🟢 Enabled" if plugin["enabled"] else "🔴 Disabled"
                    eprint(f"{status} {plugin['name']} (v{plugin['version']})")
                    eprint(f"    ID: {plugin['id']}")
                    eprint(f"    Type: {plugin['type']}")
                    eprint(f"    Description: {plugin['description']}")
                    eprint(f"    Capabilities: {', '.join(plugin['capabilities'])}")
                    if plugin.get("usage_count", 0) > 0:
                        eprint(
                            f"    Usage: {plugin['usage_count']} executions, {plugin.get('error_count', 0)} errors"
                        )
                    eprint()

            sys.exit(0)

        except ImportError:
            eprint("❌ Plugin system not available")
            sys.exit(1)
        except Exception as e:
            eprint(f"❌ Error listing plugins: {e}")
            sys.exit(1)

    elif args.action == "plugin-info":
        if not args.plugin_id:
            eprint("❌ Plugin ID required for plugin-info command (use --plugin-id)")
            sys.exit(1)

        try:
            from .plugin_system import create_default_plugin_manager

            plugin_manager = create_default_plugin_manager(args.plugin_config_dir)
            if args.plugin_dir:
                plugin_manager.add_plugin_directory(args.plugin_dir)

            # Discover and load plugins
            discovered = plugin_manager.discover_plugins()
            for plugin_file in discovered:
                load_result = plugin_manager.load_plugin(plugin_file)

            plugin_info = plugin_manager.get_plugin_info(args.plugin_id)
            if not plugin_info:
                eprint(f"❌ Plugin not found: {args.plugin_id}")
                sys.exit(1)

            # Show detailed plugin information
            eprint(f"\nPlugin Information: {args.plugin_id}")
            eprint("=" * 50)
            eprint(f"Name: {plugin_info['name']}")
            eprint(f"Version: {plugin_info['version']}")
            eprint(f"Type: {plugin_info['type']}")
            eprint(f"Description: {plugin_info['description']}")
            eprint(f"Status: {'🟢 Enabled' if plugin_info['enabled'] else '🔴 Disabled'}")
            eprint(f"File: {plugin_info['file_path']}")
            eprint(f"Capabilities: {', '.join(plugin_info['capabilities'])}")
            eprint(
                f"Load Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(plugin_info['load_time']))}"
            )

            if plugin_info.get("last_used"):
                eprint(
                    f"Last Used: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(plugin_info['last_used']))}"
                )

            if plugin_info.get("usage_count", 0) > 0:
                eprint("Usage Statistics:")
                eprint(f"  - Total executions: {plugin_info['usage_count']}")
                eprint(f"  - Errors: {plugin_info.get('error_count', 0)}")
                success_rate = (
                    (plugin_info["usage_count"] - plugin_info.get("error_count", 0))
                    / plugin_info["usage_count"]
                ) * 100
                eprint(f"  - Success rate: {success_rate:.1f}%")

            sys.exit(0)

        except ImportError:
            eprint("❌ Plugin system not available")
            sys.exit(1)
        except Exception as e:
            eprint(f"❌ Error getting plugin info: {e}")
            sys.exit(1)

    elif args.action == "enable-plugin":
        if not args.plugin_id:
            eprint("❌ Plugin ID required for enable-plugin command (use --plugin-id)")
            sys.exit(1)

        try:
            from .plugin_system import create_default_plugin_manager

            plugin_manager = create_default_plugin_manager(args.plugin_config_dir)
            if args.plugin_dir:
                plugin_manager.add_plugin_directory(args.plugin_dir)

            # Discover and load plugins
            discovered = plugin_manager.discover_plugins()
            for plugin_file in discovered:
                load_result = plugin_manager.load_plugin(plugin_file)

            result = plugin_manager.enable_plugin(args.plugin_id)
            if result.success:
                eprint(f"✅ Plugin {args.plugin_id} enabled successfully")
            else:
                eprint(f"❌ Failed to enable plugin: {result.message}")
                sys.exit(1)

            sys.exit(0)

        except ImportError:
            eprint("❌ Plugin system not available")
            sys.exit(1)
        except Exception as e:
            eprint(f"❌ Error enabling plugin: {e}")
            sys.exit(1)

    elif args.action == "disable-plugin":
        if not args.plugin_id:
            eprint("❌ Plugin ID required for disable-plugin command (use --plugin-id)")
            sys.exit(1)

        try:
            from .plugin_system import create_default_plugin_manager

            plugin_manager = create_default_plugin_manager(args.plugin_config_dir)
            if args.plugin_dir:
                plugin_manager.add_plugin_directory(args.plugin_dir)

            # Discover and load plugins
            discovered = plugin_manager.discover_plugins()
            for plugin_file in discovered:
                load_result = plugin_manager.load_plugin(plugin_file)

            result = plugin_manager.disable_plugin(args.plugin_id)
            if result.success:
                eprint(f"✅ Plugin {args.plugin_id} disabled successfully")
            else:
                eprint(f"❌ Failed to disable plugin: {result.message}")
                sys.exit(1)

            sys.exit(0)

        except ImportError:
            eprint("❌ Plugin system not available")
            sys.exit(1)
        except Exception as e:
            eprint(f"❌ Error disabling plugin: {e}")
            sys.exit(1)

    elif args.action == "reload-plugin":
        if not args.plugin_id:
            eprint("❌ Plugin ID required for reload-plugin command (use --plugin-id)")
            sys.exit(1)

        try:
            from .plugin_system import create_default_plugin_manager

            plugin_manager = create_default_plugin_manager(args.plugin_config_dir)
            if args.plugin_dir:
                plugin_manager.add_plugin_directory(args.plugin_dir)

            # Discover and load plugins
            discovered = plugin_manager.discover_plugins()
            for plugin_file in discovered:
                load_result = plugin_manager.load_plugin(plugin_file)

            result = plugin_manager.reload_plugin(args.plugin_id)
            if result.success:
                eprint(f"✅ Plugin {args.plugin_id} reloaded successfully")
            else:
                eprint(f"❌ Failed to reload plugin: {result.message}")
                sys.exit(1)

            sys.exit(0)

        except ImportError:
            eprint("❌ Plugin system not available")
            sys.exit(1)
        except Exception as e:
            eprint(f"❌ Error reloading plugin: {e}")
            sys.exit(1)

    elif args.action == "check-password":
        # Read-only strength/policy report for a supplied password. Source order:
        # -p/--password (discouraged), then CRYPT_PASSWORD, then a non-tty stdin
        # pipe, then an interactive prompt. The safer sources avoid leaking the
        # password via shell history / the process list.
        # NB: getpass is used module-wide in main_with_args; do not import it
        # locally here or it becomes a function-local name and unbinds
        # elsewhere. json is the opposite case: several branches of this
        # function import it locally, which makes `json` function-local
        # THROUGHOUT, so every branch that uses it needs its own import.
        import json

        from .password_policy import build_strength_report, format_strength_report

        if getattr(args, "password", None) is not None:
            eprint(
                "Warning: passing the password via -p leaves it in your shell "
                "history and the process list; prefer stdin or CRYPT_PASSWORD."
            )
            _pw = args.password
        elif "CRYPT_PASSWORD" in os.environ:
            _pw = os.environ["CRYPT_PASSWORD"]
        elif not sys.stdin.isatty():
            _pw = sys.stdin.readline().rstrip("\n")
        else:
            _pw = getpass.getpass("Password to check: ")

        _report = build_strength_report(
            _pw,
            policy_level=getattr(args, "password_policy", "standard"),
            strict_strength=getattr(args, "strict_strength", False),
        )
        if getattr(args, "json", False):
            print(json.dumps(_report, indent=2))
        else:
            eprint(format_strength_report(_report))

        # Exit non-zero when a policy was applied and the password failed it,
        # so the command is usable as a scriptable gate.
        sys.exit(0 if _report["valid"] else 1)

    elif args.action == "generate-password":
        # Validate --dice mutual exclusion with character-class flags and
        # reject --dice-* options used without --dice. The handler-level
        # check (vs argparse mutex) lets us produce more actionable error
        # messages and keeps the character flags freely combinable.
        try:
            _validate_generate_password_args(
                dice=getattr(args, "dice", False),
                use_lowercase=args.use_lowercase,
                use_uppercase=args.use_uppercase,
                use_digits=args.use_digits,
                use_special=args.use_special,
                dice_count=getattr(args, "dice_count", 10),
                dice_sep=getattr(args, "dice_sep", ""),
                dice_list=getattr(args, "dice_list", None),
                force_wordlist=getattr(args, "force_wordlist", False),
            )
        except ValueError as e:
            eprint(f"Error: {e}")
            sys.exit(1)

        # --dice mode: skip the character-based pipeline entirely.
        # Per Q15, we apply only entropy-/length-based policy checks (not
        # character-class or common-password checks, which are orthogonal
        # to passphrase security).
        if getattr(args, "dice", False):
            try:
                passphrase, entropy_bits = _run_dice_generation(args)
            except Exception as e:
                eprint(f"Error generating passphrase: {e}")
                sys.exit(1)

            # The audit log's shape heuristic cannot catch this: it needs a
            # 32-char run of [A-Za-z0-9+_=], which punctuation breaks and a
            # diceware phrase of lowercase words never has. Registered so any
            # path that logs it redacts it (same reasoning as gitlab#152).
            register_consumed_secret("generated_password", passphrase)

            min_entropy = getattr(args, "min_password_entropy", None)
            if min_entropy is not None and entropy_bits < min_entropy:
                eprint(
                    f"Error: passphrase entropy {entropy_bits:.1f} bits < "
                    f"required minimum {min_entropy} bits. Increase "
                    f"--dice-count or pick a larger wordlist."
                )
                sys.exit(1)

            min_length = getattr(args, "min_password_length", None)
            if min_length is not None and len(passphrase) < min_length:
                eprint(
                    f"Error: passphrase length {len(passphrase)} chars < "
                    f"required minimum {min_length} chars. Increase "
                    f"--dice-count or pick longer words."
                )
                sys.exit(1)

            if getattr(args, "json", False):
                # Local import: `json` is function-local throughout
                # main_with_args (see the check-password branch).
                import json

                # stdout IS the delivery channel here: the passphrase is the
                # payload. It must not also go to stderr, which 2>&1 merges,
                # which lands in scrollback, and which the GUI writes to its
                # persistent debug log -- the reasoning applied to
                # `encrypt --random` (gitlab#152). The human display below is
                # skipped entirely rather than merely duplicated.
                password_json = json.dumps(
                    {
                        "password": passphrase,
                        "entropy_bits": round(entropy_bits, 1),
                        "mode": "diceware",
                        "word_count": args.dice_count,
                    },
                    indent=2,
                    ensure_ascii=True,
                )
                print(password_json)
                sys.exit(0)

            eprint(f"\nPassphrase entropy: {entropy_bits:.1f} bits " f"({args.dice_count} words)")
            display_password_with_timeout(passphrase)
            sys.exit(0)

        # If no character sets are explicitly selected, use all by default
        if not (args.use_lowercase or args.use_uppercase or args.use_digits or args.use_special):
            args.use_lowercase = True
            args.use_uppercase = True
            args.use_digits = True
            args.use_special = True

        # Reported in the JSON document below. A machine caller cannot see
        # the stderr warning, so the verdict has to travel in the payload.
        policy_valid = True
        policy_warnings: list = []

        # Apply password policy if specified
        if args.password_policy != "none" and not args.force_password:
            # Create policy to get minimum required length
            policy_params = {}
            if args.min_password_length is not None:
                policy_params["min_length"] = args.min_password_length

            policy = PasswordPolicy(policy_level=args.password_policy, **policy_params)

            # Ensure length meets policy requirements
            if args.length < policy.min_length:
                eprint(
                    f"\nIncreasing password length from {args.length} to {policy.min_length} to meet policy requirements"
                )
                args.length = policy.min_length

        # Generate password
        password = generate_strong_password(
            args.length,
            args.use_lowercase,
            args.use_uppercase,
            args.use_digits,
            args.use_special,
        )

        register_consumed_secret("generated_password", password)

        # Check password strength
        entropy, strength = get_password_strength(password)
        if not getattr(args, "json", False):
            eprint(f"\nPassword strength: {strength} (entropy: {entropy:.1f} bits)")

        # Validate against policy
        if args.password_policy != "none":
            policy_params = {}
            if args.min_password_entropy is not None:
                policy_params["min_entropy"] = args.min_password_entropy
            policy_params["strict_strength"] = getattr(args, "strict_strength", False)

            if args.disable_common_password_check:
                policy_params["check_common_passwords"] = False

            if args.custom_password_list:
                policy_params["common_passwords_path"] = args.custom_password_list

            # Create policy
            policy = PasswordPolicy(policy_level=args.password_policy, **policy_params)

            # Check if generated password meets policy (it should, but verify)
            valid, policy_messages = policy.validate_password(password, quiet=True)
            policy_valid = valid
            policy_warnings = list(policy_messages or []) if not valid else []
            if not valid:
                # This is rare but could happen with specific combinations of constraints
                eprint("Warning: Generated password does not meet policy requirements.")
                eprint("Consider adjusting character requirements or using a longer length.")

        if getattr(args, "json", False):
            import json

            # The policy check on this path WARNS rather than rejects (unlike
            # the diceware gate above, which exits). Human mode shows that
            # warning next to the password; a machine caller reads stderr
            # only on a non-zero exit, so the verdict travels in the document
            # instead of being lost. Mode parity is deliberate: JSON must not
            # be stricter than the human path, and must not claim a guarantee
            # the code does not provide.
            password_json = json.dumps(
                {
                    "password": password,
                    "entropy_bits": round(entropy, 1),
                    "mode": "character",
                    "strength": strength,
                    "length": len(password),
                    "policy_valid": policy_valid,
                    "policy_warnings": policy_warnings,
                },
                indent=2,
                ensure_ascii=True,
            )
            print(password_json)
            sys.exit(0)

        # Display the password
        display_password_with_timeout(password)
        # Exit after generating password
        sys.exit(0)

    elif args.action == "derive-password":
        # Belt-and-suspenders: reject forbidden args even via monolithic parser
        forbidden_attrs = {
            "input": "--input/-i",
            "output": "--output/-o",
            "algorithm": "--algorithm/-a",
            "cascade": "--cascade",
        }
        for attr, flag_name in forbidden_attrs.items():
            val = getattr(args, attr, None)
            if val is not None:
                eprint(f"Error: {flag_name} is not allowed with derive-password")
                sys.exit(1)

        # Resolve password
        derive_password = None
        if not getattr(args, "password", None):
            password_file = getattr(args, "password_file", None)
            password_fd = getattr(args, "password_fd", None)
            env_pw = os.environ.get("OPENSSL_ENCRYPT_PASSWORD")

            if password_file:
                try:
                    if password_file == "-":
                        args.password = sys.stdin.readline().rstrip("\n")
                    else:
                        with open(password_file, "r") as f:
                            args.password = f.readline().rstrip("\n")
                except OSError as e:
                    eprint(f"Error reading password file: {e}")
                    sys.exit(1)
            elif password_fd is not None:
                try:
                    with os.fdopen(password_fd, "r", closefd=False) as f:
                        args.password = f.readline().rstrip("\n")
                except OSError as e:
                    eprint(f"Error reading from fd {password_fd}: {e}")
                    sys.exit(1)
            elif env_pw:
                args.password = env_pw
                # Register before delete so redaction survives the variable's
                # removal (gitlab#147).
                register_consumed_secret("OPENSSL_ENCRYPT_PASSWORD", env_pw)
                try:
                    del os.environ["OPENSSL_ENCRYPT_PASSWORD"]
                except KeyError:
                    pass

        # Try keyring if no password resolved yet
        if not getattr(args, "password", None) and getattr(args, "keyring_load", None):
            try:
                import keyring as _keyring

                stored_pw = _keyring.get_password("openssl_encrypt", args.keyring_load)
                if stored_pw:
                    args.password = stored_pw
                else:
                    eprint(f"No password found in keyring for label '{args.keyring_load}'")
            except ImportError:
                eprint("Error: keyring package not installed. Install with: pip install keyring")
                sys.exit(1)

        if not getattr(args, "password", None):
            # Prompt for password. With --confirm, prompt twice and reject
            # on mismatch — guards against typos that would silently produce
            # a different (wrong-but-valid-looking) derived value.
            args.password = getpass.getpass("Password for key derivation: ")
            if getattr(args, "confirm", False):
                confirm_pw = getpass.getpass("Confirm password: ")
                if confirm_pw != args.password:
                    eprint(
                        "Error: passwords do not match. Re-run without typos; "
                        "derive-password produces a different output for every "
                        "distinct input, so a typo would silently waste your "
                        "downstream use."
                    )
                    sys.exit(1)

        if not args.password:
            eprint("Error: password is required for derive-password")
            sys.exit(1)

        derive_password = args.password

        # Resolve salt
        salt_hex = getattr(args, "salt", None)
        salt_was_auto_generated = False
        if salt_hex:
            try:
                salt = bytes.fromhex(salt_hex)
            except ValueError:
                eprint(f"Error: invalid hex salt: {salt_hex}")
                sys.exit(1)
        else:
            salt_length = getattr(args, "salt_length", 16) or 16
            salt = secrets.token_bytes(salt_length)
            salt_was_auto_generated = True
            # Always show auto-generated salt so user can reproduce
            eprint(f"Salt (hex): {salt.hex()}")

        if getattr(args, "show_salt", False):
            eprint(f"Salt (hex): {salt.hex()}")

        # When --hsm is set without an explicit --salt, reproducing the
        # output needs THREE inputs to match: password, the auto-generated
        # salt (echoed above), AND the 20-byte secret loaded on the
        # hardware token. The token-secret leg isn't visible from the host,
        # so re-provisioning the device would silently change future
        # outputs — emit a stderr reminder per Q17.
        if getattr(args, "hsm", None) and salt_was_auto_generated:
            eprint(
                "Note: reproducing this output requires the same password, "
                "the same salt (echoed above), AND the same HMAC-SHA1 secret "
                "loaded on the hardware token. Re-provisioning the token will "
                "silently change the output."
            )

        # Build hash_config from args
        hash_config = {}
        if hasattr(args, "sha512_rounds") and args.sha512_rounds:
            hash_config["sha512"] = args.sha512_rounds
        if hasattr(args, "sha384_rounds") and args.sha384_rounds:
            hash_config["sha384"] = args.sha384_rounds
        if hasattr(args, "sha256_rounds") and args.sha256_rounds:
            hash_config["sha256"] = args.sha256_rounds
        if hasattr(args, "sha224_rounds") and args.sha224_rounds:
            hash_config["sha224"] = args.sha224_rounds
        if hasattr(args, "sha3_512_rounds") and args.sha3_512_rounds:
            hash_config["sha3_512"] = args.sha3_512_rounds
        if hasattr(args, "sha3_384_rounds") and args.sha3_384_rounds:
            hash_config["sha3_384"] = args.sha3_384_rounds
        if hasattr(args, "sha3_256_rounds") and args.sha3_256_rounds:
            hash_config["sha3_256"] = args.sha3_256_rounds
        if hasattr(args, "sha3_224_rounds") and args.sha3_224_rounds:
            hash_config["sha3_224"] = args.sha3_224_rounds
        if hasattr(args, "blake2b_rounds") and args.blake2b_rounds:
            hash_config["blake2b"] = args.blake2b_rounds
        if hasattr(args, "blake3_rounds") and args.blake3_rounds:
            hash_config["blake3"] = args.blake3_rounds
        if hasattr(args, "shake256_rounds") and args.shake256_rounds:
            hash_config["shake256"] = args.shake256_rounds
        if hasattr(args, "shake128_rounds") and args.shake128_rounds:
            hash_config["shake128"] = args.shake128_rounds

        # Add KDF parameters to hash_config
        if getattr(args, "enable_argon2", False):
            hash_config["argon2"] = {
                "enabled": True,
                "rounds": getattr(args, "argon2_rounds", 0) or 0,
                "time": getattr(args, "argon2_time", 3),
                "memory": getattr(args, "argon2_memory", 65536),
                "parallelism": getattr(args, "argon2_parallelism", 4),
                "hash_len": getattr(args, "argon2_hash_len", 32),
                "type": getattr(args, "argon2_type", "id"),
            }
        if getattr(args, "enable_scrypt", False):
            hash_config["scrypt"] = {
                "enabled": True,
                "rounds": getattr(args, "scrypt_rounds", 0) or 0,
                "n": getattr(args, "scrypt_n", None),
                "r": getattr(args, "scrypt_r", 8),
                "p": getattr(args, "scrypt_p", 1),
            }
        if getattr(args, "enable_balloon", False):
            hash_config["balloon"] = {
                "enabled": True,
                "rounds": getattr(args, "balloon_rounds", 0) or 0,
                "time_cost": getattr(args, "balloon_time_cost", 3),
                "space_cost": getattr(args, "balloon_space_cost", 65536),
                "parallelism": getattr(args, "balloon_parallelism", 4),
            }
        if getattr(args, "enable_hkdf", False):
            hash_config["hkdf"] = {
                "enabled": True,
                "rounds": getattr(args, "hkdf_rounds", 1),
                "algorithm": getattr(args, "hkdf_algorithm", "sha256"),
                "info": getattr(args, "hkdf_info", "openssl_encrypt_hkdf"),
            }
        if getattr(args, "enable_randomx", False):
            hash_config["randomx"] = {
                "enabled": True,
                "rounds": getattr(args, "randomx_rounds", 0) or 0,
                "mode": getattr(args, "randomx_mode", "light"),
                "height": getattr(args, "randomx_height", 1),
                "hash_len": getattr(args, "randomx_hash_len", 32),
            }

        # Optional HSM pepper: when --hsm is set, load the corresponding
        # plugin and derive a pepper from the salt. The pepper feeds into
        # generate_key the same way the encrypt path uses it, so the
        # derived value is reproducible iff the password, the salt AND the
        # hardware-loaded secret all match.
        hsm_pepper: bytearray = None
        if getattr(args, "hsm", None):
            hsm_value = args.hsm.lower()
            try:
                if hsm_value == "yubikey":
                    from ..plugins.hsm.yubikey_challenge_response import YubikeyHSMPlugin

                    hsm_plugin_instance = YubikeyHSMPlugin()
                elif hsm_value == "onlykey":
                    from ..plugins.hsm.onlykey_challenge_response import OnlykeyHSMPlugin

                    hsm_plugin_instance = OnlykeyHSMPlugin()
                elif hsm_value == "piv":
                    from ..plugins.hsm.piv_card import PIVHSMPlugin

                    hsm_plugin_instance = PIVHSMPlugin()
                else:
                    eprint(
                        f"Error: Unknown --hsm value '{args.hsm}'. "
                        f"Supported: yubikey, onlykey, piv"
                    )
                    sys.exit(1)
            except ImportError as e:
                eprint(
                    f"Error: HSM plugin import failed: {e}. "
                    f"Install with: pip install -r requirements-hsm.txt"
                )
                sys.exit(1)

            init_result = hsm_plugin_instance.initialize({})
            if not init_result.success:
                eprint(f"Error initializing HSM plugin: {init_result.message}")
                sys.exit(1)

            from .plugin_system.plugin_base import PluginSecurityContext

            hsm_ctx = PluginSecurityContext(
                plugin_id=hsm_plugin_instance.plugin_id,
                capabilities=hsm_plugin_instance.get_required_capabilities(),
            )
            if getattr(args, "hsm_slot", None):
                hsm_ctx.config["slot"] = args.hsm_slot
            if hsm_value == "piv":
                if getattr(args, "hsm_pkcs11_lib", None):
                    hsm_ctx.config["pkcs11_lib_path"] = args.hsm_pkcs11_lib
                hsm_ctx.config["piv_slot"] = getattr(args, "hsm_piv_slot", 0x9A)
                hsm_ctx.config["biometric"] = bool(getattr(args, "hsm_biometric", False))
            hsm_result = hsm_plugin_instance.get_hsm_pepper(salt, hsm_ctx)
            if not hsm_result.success:
                eprint(f"Error obtaining HSM pepper: {hsm_result.message}")
                sys.exit(1)
            hsm_pepper_value = hsm_result.data.get("hsm_pepper")
            if not hsm_pepper_value:
                eprint("Error: HSM plugin returned no pepper")
                sys.exit(1)
            # gitlab#123: hold the pepper in a wipeable buffer. A mutable
            # plugin buffer is reused in place so the wipe below also clears
            # the plugin's copy.
            hsm_pepper = (
                hsm_pepper_value
                if isinstance(hsm_pepper_value, bytearray)
                else bytearray(hsm_pepper_value)
            )

        # Call generate_key to derive the key
        from .crypt_core import generate_key
        from .secure_memory import secure_memzero

        output_length = getattr(args, "output_length", 32) or 32

        # Choose a synthetic algorithm that produces enough key material
        if output_length <= 32:
            synth_algorithm = "aes-gcm"  # 32 bytes
        elif output_length <= 64:
            synth_algorithm = "threefish-512"  # 64 bytes
        else:
            synth_algorithm = "threefish-1024"  # 128 bytes

        pbkdf2_iters = getattr(args, "pbkdf2_iterations", 0) or 0

        derived: bytearray = None
        try:
            try:
                key, _, _ = generate_key(
                    password=(
                        derive_password.encode("utf-8")
                        if isinstance(derive_password, str)
                        else derive_password
                    ),
                    salt=salt,
                    hash_config=hash_config,
                    pbkdf2_iterations=pbkdf2_iters,
                    quiet=True,
                    algorithm=synth_algorithm,
                    progress=getattr(args, "progress", False),
                    debug=getattr(args, "debug", False),
                    hsm_pepper=hsm_pepper,
                    format_version=9,
                )
            except Exception as e:
                eprint(f"Error during key derivation: {e}")
                sys.exit(1)

            # Truncate to requested length in a wipeable buffer; the
            # memoryview avoids an intermediate immutable slice copy.
            derived = bytearray(memoryview(key)[:output_length])

            # Output the derived key
            output_format = getattr(args, "output_format", "hex") or "hex"
            if output_format == "hex":
                print(derived.hex())
            elif output_format == "base64":
                import base64 as _b64

                print(_b64.b64encode(derived).decode("ascii"))
            elif output_format == "raw":
                sys.stdout.buffer.write(derived)
        finally:
            # gitlab#123: wipe the pepper and the output buffer on all exit
            # paths. The immutable bytes returned by generate_key cannot be
            # wiped from here (M10 - secure_memzero refuses immutable input).
            if hsm_pepper is not None:
                secure_memzero(hsm_pepper)
            if derived is not None:
                secure_memzero(derived)

        sys.exit(0)

    # For other actions, input file is required
    if getattr(args, "input", None) is None and args.action not in [
        "generate-password",
        "derive-password",
        "security-info",
        "analyze-security",
        "config-wizard",
        "analyze-config",
        "template",
        "smart-recommendations",
        "check-argon2",
        "check-pqc",
        "check-password",
        "version",
        "show-version-file",
    ]:
        parser.error("the following arguments are required: --input/-i")

    # Handle stdin input FIRST - convert to temp file to avoid multiple reads
    # This must happen BEFORE detect_encryption_type() which would consume stdin
    if args.action in ("decrypt", "info") and getattr(args, "input", None) == "/dev/stdin":
        import tempfile

        # Read stdin once into a temp file
        stdin_temp_file_early = tempfile.NamedTemporaryFile(delete=False)
        os.chmod(stdin_temp_file_early.name, 0o600)  # Security: Restrict to user read/write only
        temp_files_to_cleanup.append(stdin_temp_file_early.name)

        # Copy all data from stdin to temp file
        stdin_data = sys.stdin.buffer.read()
        if args.debug:
            eprint(
                f"DEBUG: Read {len(stdin_data)} bytes from stdin (early)",
                file=sys.stderr,
            )
        stdin_temp_file_early.write(stdin_data)
        stdin_temp_file_early.close()

        # Update args.input to point to the temp file for all subsequent operations
        args.input = stdin_temp_file_early.name
        if args.debug:
            eprint(f"DEBUG: Converted stdin to temp file: {args.input}", file=sys.stderr)

    # Feature #2: transparently de-armor ASCII-armored input before any
    # decrypt/info/verify path reads it. Detection is content-based (the PEM
    # BEGIN marker), so no flag is required. The de-armored bytes are written
    # to an owner-only temp file that all downstream readers (auto-detection,
    # keystore, asymmetric, symmetric) consume like any encrypted file.
    if args.action in ("decrypt", "info", "verify", "rekey") and getattr(args, "input", None):
        import tempfile

        from .armor import ArmorError, dearmor_file, is_armored_file

        if is_armored_file(args.input):
            try:
                dearmored_bytes = dearmor_file(args.input)
            except ArmorError as armor_err:
                eprint(f"Error: input is ASCII-armored but malformed: {armor_err}")
                sys.exit(1)
            else:
                with tempfile.NamedTemporaryFile(
                    delete=False, suffix=".dearmored"
                ) as dearmored_file:
                    dearmored_file.write(dearmored_bytes)
                    dearmored_path = dearmored_file.name
                os.chmod(dearmored_path, 0o600)  # owner-only
                temp_files_to_cleanup.append(dearmored_path)
                args.input = dearmored_path
                if getattr(args, "debug", False):
                    eprint(f"DEBUG: De-armored input to temp file: {args.input}")

    # Auto-detect second password for a keyed hidden file (terminal-gated,
    # suppressible with --no-second-password-prompt). Run AFTER stdin buffering
    # and de-armoring so args.input is a seekable file even when the ciphertext
    # arrived on stdin — only then can the cheap keyless peek decide whether a
    # prompt is warranted. A no-op when an explicit second password was given.
    if args.action in ("decrypt", "info"):
        _hidden_second_password = _resolve_second_password_with_fallback(
            args, _hidden_second_password
        )

    # Auto-detect encryption type for decrypt operations
    # Only run auto-detection if user didn't explicitly provide --with-key
    # This avoids potential interference with symmetric HSM decryption
    encryption_info = None
    if (
        args.action == "decrypt"
        and getattr(args, "input", None)
        and not getattr(args, "key_identity", None)
    ):
        try:
            encryption_info = detect_encryption_type(args.input)
        except Exception as e:
            # If detection fails, assume symmetric and continue
            if args.debug:
                eprint(f"DEBUG: Auto-detection failed: {e}")
            encryption_info = {"type": "symmetric", "format_version": 0}

        if encryption_info and encryption_info["type"] == "asymmetric":
            # Find matching identity in keystore
            from .identity_cli import get_identity_store

            store_path = resolve_identity_store_path(args)
            store = get_identity_store(store_path)

            matching = store.find_by_fingerprints(encryption_info["recipient_fingerprints"])

            if len(matching) == 0:
                # No matching identity found
                eprint(
                    "ERROR: This file is encrypted asymmetrically but no matching identity found.",
                    file=sys.stderr,
                )
                eprint("\nFile was encrypted for:", file=sys.stderr)
                for fp in encryption_info["recipient_fingerprints"]:
                    eprint(f"  • {fp}", file=sys.stderr)
                eprint(
                    "\nTo decrypt, you need one of these identities in your keystore.",
                    file=sys.stderr,
                )
                eprint(
                    "Import the private key or use --with-key to specify an identity.",
                    file=sys.stderr,
                )
                sys.exit(1)
            else:
                # Use first matching identity
                args.key_identity = matching[0].name
                if not args.quiet:
                    eprint(f"Using identity '{args.key_identity}' for decryption")

    # Get password (only for encrypt/decrypt actions)
    # Skip password prompt for asymmetric encryption/decryption (uses identity-based keys)
    is_asymmetric_encrypt = (
        args.action == "encrypt" and hasattr(args, "for_identity") and args.for_identity
    )

    # Check if this is asymmetric decryption
    is_asymmetric_decrypt = False
    if args.action == "decrypt":
        # Explicit --with-key provided OR auto-detected asymmetric file
        if (hasattr(args, "key_identity") and args.key_identity) or (
            encryption_info and encryption_info.get("type") == "asymmetric"
        ):
            is_asymmetric_decrypt = True

    # Validate algorithm availability before encryption/decryption
    if args.action in ["encrypt", "decrypt", "rekey"]:
        validation_warnings = validate_algorithm_availability(args)
        if validation_warnings and not args.quiet:
            eprint("\nWARNING: Some requested algorithms are not available:")
            for warning in validation_warnings:
                eprint(f"  ⚠ {warning}")
            eprint("\nUse 'list-algorithms' command to see available algorithms.")
            eprint("Install required packages or choose different algorithms.\n")

    # Validated ABOVE the asymmetric gate below: --for-identity sets
    # is_asymmetric_encrypt, which skips the whole password-resolution block --
    # so a guard placed inside it silently ignored both --random and
    # --random-password-out for asymmetric runs, which is the very
    # "stale file read back as this run's password" hazard it exists to stop
    # (gitlab#152).
    if getattr(args, "random_password_out", None):
        if is_asymmetric_encrypt or is_asymmetric_decrypt:
            eprint(
                "ERROR: --random-password-out does not apply to asymmetric "
                "encryption: --for-identity encrypts to a recipient's public "
                "key, so no password is generated."
            )
            raise SystemExit(2)
        if not (args.action == "encrypt" and args.random and not args.password):
            eprint(
                "ERROR: --random-password-out has no effect without --random "
                "on an encrypt with no explicit password. Refusing rather "
                "than leaving a stale file that looks like this run's "
                "password."
            )
            raise SystemExit(2)

    if args.action in ["encrypt", "decrypt", "rekey"] and not (
        is_asymmetric_encrypt or is_asymmetric_decrypt
    ):
        password = None
        generated_password = None

        try:
            from .secure_memory import secure_memzero, secure_string

            # Resolve password from --password-file, --password-fd, or
            # OPENSSL_ENCRYPT_PASSWORD before entering the secure block.
            if not args.password:
                password_file = getattr(args, "password_file", None)
                password_fd = getattr(args, "password_fd", None)
                env_pw = os.environ.get("OPENSSL_ENCRYPT_PASSWORD")

                if password_file:
                    try:
                        if password_file == "-":
                            args.password = sys.stdin.readline().rstrip("\n")
                        else:
                            with open(password_file, "r") as f:
                                args.password = f.readline().rstrip("\n")
                    except OSError as e:
                        eprint(f"Error reading password file: {e}", file=sys.stderr)
                        sys.exit(1)
                elif password_fd is not None:
                    try:
                        with os.fdopen(password_fd, "r", closefd=False) as f:
                            args.password = f.readline().rstrip("\n")
                    except OSError as e:
                        eprint(f"Error reading from fd {password_fd}: {e}", file=sys.stderr)
                        sys.exit(1)
                elif env_pw:
                    args.password = env_pw
                    # Register before delete so redaction survives the variable's
                    # removal (gitlab#147).
                    register_consumed_secret("OPENSSL_ENCRYPT_PASSWORD", env_pw)
                    try:
                        del os.environ["OPENSSL_ENCRYPT_PASSWORD"]
                    except KeyError:
                        pass

            # Try keyring if no password resolved yet
            if not args.password and getattr(args, "keyring_load", None):
                try:
                    import keyring as _keyring

                    stored_pw = _keyring.get_password("openssl_encrypt", args.keyring_load)
                    if stored_pw:
                        args.password = stored_pw
                    else:
                        eprint(f"No password found in keyring for label '{args.keyring_load}'")
                except ImportError:
                    eprint(
                        "Error: keyring package not installed. Install with: pip install keyring"
                    )
                    sys.exit(1)

            if (
                args.password
                and not getattr(args, "password_file", None)
                and not getattr(args, "password_fd", None)
                and not getattr(args, "keyring_load", None)
            ):
                # Warn about --password being visible in process list. A security
                # warning must not be silenced by the output-verbosity flag (#67).
                eprint(
                    "WARNING: --password is visible in process list. "
                    "Use --password-file or OPENSSL_ENCRYPT_PASSWORD env var instead.",
                    file=sys.stderr,
                )

            # The actual store happens AFTER the password is resolved (see
            # below): it used to be gated on args.password, which only
            # -p/--password sets. CRYPT_PASSWORD is consumed straight into
            # the secure buffer and never assigned there, so for every
            # caller using the environment -- the recommended way, and the
            # only one the desktop GUI uses -- --keyring-store stored
            # nothing AND printed nothing, because the confirmation lived
            # inside the same `if` (gitlab#156).
            #
            # Reported here rather than later only when the package is
            # missing, so the user learns before the operation runs.
            if getattr(args, "keyring_store", None):
                try:
                    import keyring as _keyring  # noqa: F401
                except ImportError:
                    if not args.quiet:
                        eprint("Warning: keyring package not installed, password not stored")

            # Initialize a secure string to hold the password
            with secure_string() as password_secure:
                # Handle random password generation for encryption
                if args.action == "encrypt" and args.random and not args.password:
                    # Determine character sets based on args or defaults
                    # getattr, not attribute access: the character-class flags
                    # are declared on `generate-password` and on the monolithic
                    # parser, but NOT on the `encrypt` subparser -- so
                    # `encrypt --random` raised AttributeError and the feature
                    # was unusable on the only route `encrypt` takes
                    # (gitlab#181). All four default to enabled, which is the
                    # strongest generation setting.
                    def _charclass(name):
                        value = getattr(args, name, None)
                        return True if value is None else value

                    use_lowercase = _charclass("use_lowercase")
                    use_uppercase = _charclass("use_uppercase")
                    use_digits = _charclass("use_digits")
                    use_special = _charclass("use_special")

                    # Ensure length meets policy requirements
                    if args.password_policy != "none" and not args.force_password:
                        # Create policy to get minimum required length
                        policy_params = {}
                        if args.min_password_length is not None:
                            policy_params["min_length"] = args.min_password_length

                        policy = PasswordPolicy(policy_level=args.password_policy, **policy_params)

                        # Ensure random password length meets policy requirements
                        if args.random < policy.min_length:
                            if not args.quiet:
                                eprint(
                                    f"\nIncreasing random password length from {args.random} to {policy.min_length} to meet policy requirements"
                                )
                            args.random = policy.min_length

                    # Generate password with requested settings
                    generated_password = generate_strong_password(
                        args.random,
                        use_lowercase=use_lowercase,
                        use_uppercase=use_uppercase,
                        use_digits=use_digits,
                        use_special=use_special,
                    )

                    # Validate the generated password against policy
                    if args.password_policy != "none":
                        policy_params = {}
                        if args.min_password_entropy is not None:
                            policy_params["min_entropy"] = args.min_password_entropy
                        policy_params["strict_strength"] = getattr(args, "strict_strength", False)

                        if args.disable_common_password_check:
                            policy_params["check_common_passwords"] = False

                        if args.custom_password_list:
                            policy_params["common_passwords_path"] = args.custom_password_list

                        # Create policy
                        policy = PasswordPolicy(policy_level=args.password_policy, **policy_params)

                        # Check if generated password meets policy (it should, but verify)
                        valid, msgs = policy.validate_password(generated_password, quiet=args.quiet)

                        # Print strength information
                        if not args.quiet:
                            for msg in msgs:
                                if "Password strength:" in msg:
                                    eprint(f"\n{msg}")

                    password_secure.extend(generated_password.encode())

                    # Deliver the password BEFORE encrypting (gitlab#152).
                    #
                    # Order matters and only one order is safe: if the write
                    # failed after the file were encrypted, the file would be
                    # sealed under a password nobody has -- unrecoverable data
                    # loss. Writing first means a failure costs at most a
                    # not-yet-encrypted file, and the user still has nothing to
                    # lose. This mirrors the recovery-code channel (gitlab#146),
                    # where the code is likewise written before the envelope is
                    # modified.
                    # The generated password is not reliably caught by the
                    # audit log's shape heuristic: _SECRET_TOKEN_RE needs a
                    # 32-char run of [A-Za-z0-9+_=], which a shorter password
                    # never has and which punctuation breaks. Register it
                    # explicitly so any path that logs it redacts it.
                    register_consumed_secret("generated_random_password", generated_password)

                    _random_out = getattr(args, "random_password_out", None)

                    # A destination the run would then destroy is refused:
                    # equal to --output, it would be truncated by the
                    # ciphertext write moments later, sealing the file under a
                    # password that no longer exists anywhere. O_EXCL does not
                    # catch it -- the destination does not exist yet.
                    try:
                        _check_random_password_destination(
                            _random_out,
                            args.input,
                            _effective_encrypt_output(args),
                        )
                    except ValueError as _e:
                        eprint(f"ERROR: {_e}")
                        raise SystemExit(2)

                    try:
                        _stderr_isatty = sys.stderr.isatty()
                    except (AttributeError, ValueError):
                        # Replaced or closed stream: fail closed, so a
                        # destination is required rather than assumed.
                        _stderr_isatty = False
                    if not _random_password_destination_ok(
                        isatty=_stderr_isatty,
                        out_path=_random_out,
                        quiet=args.quiet,
                    ):
                        eprint(
                            "ERROR: --random has nowhere to deliver the "
                            "generated password: stderr is not a terminal, or "
                            "--quiet suppresses the display. Encrypting anyway "
                            "would seal the file under a password nobody "
                            "holds. Name a destination with "
                            "--random-password-out PATH."
                        )
                        raise SystemExit(2)

                    # Deliver BEFORE encrypting -- both channels, not just the
                    # file (gitlab#152).
                    #
                    # Only one order is safe. Disclosing after the ciphertext
                    # is written means any later failure (armor, stego, the
                    # permissions call, the audit log) leaves an encrypted file
                    # on disk whose password was never disclosed --
                    # unrecoverable. Disclosing first costs, at worst,
                    # over-disclosing a password for a file that was never
                    # created, which is harmless. Mirrors the recovery-code
                    # channel (gitlab#146), where the code is likewise written
                    # before the envelope is modified.
                    if _random_out:
                        try:
                            _write_generated_password_file(_random_out, generated_password)
                        except Exception as _e:
                            # Never echo the password itself in the message.
                            if isinstance(_e, FileExistsError):
                                # gitlab#223 review f3: a pre-existing
                                # destination is NOT this run's orphan -- it
                                # may hold the password of an earlier,
                                # successful encryption. The removable-orphan
                                # NOTE would be dangerously wrong here.
                                eprint(
                                    f"ERROR: {sanitize_for_display(_random_out)} "
                                    f"already exists; refusing to overwrite it. "
                                    f"It may hold the password for an earlier "
                                    f"encryption -- verify before removing it, "
                                    f"or choose another path."
                                )
                                raise SystemExit(1)
                            eprint(
                                f"ERROR: could not write the generated "
                                f"password to {sanitize_for_display(_random_out)}: {_e}"
                            )
                            # create_secure_file may have created the 0600 file
                            # before os.write/os.fsync failed, leaving a partial
                            # orphan a retry would refuse; no ciphertext exists
                            # (gitlab#182).
                            _warn_orphan_random_password(args, ciphertext_maybe_written=False)
                            raise SystemExit(1)
                        if not args.quiet:
                            eprint(
                                f"\nGenerated password written to "
                                f"{sanitize_for_display(_random_out)} (mode 0600)."
                            )
                    else:
                        _display_generated_password(generated_password)

                    if not args.quiet:
                        eprint("\nGenerated a random password for encryption.")

                # Check for password from environment variable first
                elif os.environ.get("CRYPT_PASSWORD"):
                    # Get password from environment variable
                    env_password = os.environ.get("CRYPT_PASSWORD")

                    # Register before delete so redaction survives the variable's
                    # removal (gitlab#147).
                    register_consumed_secret("CRYPT_PASSWORD", env_password)
                    # Immediately clear the environment variable for security
                    try:
                        del os.environ["CRYPT_PASSWORD"]
                    except KeyError:
                        pass  # Already cleared

                    # Skip validation in test mode
                    in_test_mode = os.environ.get("PYTEST_CURRENT_TEST") is not None

                    # Validate password strength if policy is enabled, not in force mode, and not in test mode
                    if (
                        args.password_policy != "none"
                        and not args.force_password
                        and not in_test_mode
                    ):
                        try:
                            # Create policy with user-specified parameters
                            policy_params = {}

                            # Override policy settings with custom parameters if provided
                            if args.min_password_length is not None:
                                policy_params["min_length"] = args.min_password_length

                            if args.min_password_entropy is not None:
                                policy_params["min_entropy"] = args.min_password_entropy
                            policy_params["strict_strength"] = getattr(
                                args, "strict_strength", False
                            )

                            if args.disable_common_password_check:
                                policy_params["check_common_passwords"] = False

                            if args.custom_password_list:
                                policy_params["common_passwords_path"] = args.custom_password_list

                            # Create policy
                            policy = PasswordPolicy(
                                policy_level=args.password_policy, **policy_params
                            )

                            # Validate the password (will raise ValidationError if invalid)
                            policy.validate_password_or_raise(env_password, quiet=args.quiet)

                        except crypt_errors.ValidationError as e:
                            # Always display password strength information before validation failure
                            if not args.quiet:
                                # Calculate and display password strength
                                entropy, strength = get_password_strength(env_password)
                                eprint(
                                    f"\nPassword strength: {strength} (entropy: {entropy:.1f} bits)"
                                )
                                eprint(f"Password validation failed: {str(e)}")
                                eprint(
                                    "Use --force-password to bypass validation (not recommended)"
                                )
                            sys.exit(1)

                    password_secure.extend(env_password.encode())

                # If password provided as argument
                elif args.password:
                    # Skip validation in test mode
                    in_test_mode = os.environ.get("PYTEST_CURRENT_TEST") is not None

                    # Validate password strength if policy is enabled, not in force mode, and not in test mode
                    if (
                        args.password_policy != "none"
                        and not args.force_password
                        and not in_test_mode
                    ):
                        try:
                            # Create policy with user-specified parameters
                            policy_params = {}

                            # Override policy settings with custom parameters if provided
                            if args.min_password_length is not None:
                                policy_params["min_length"] = args.min_password_length

                            if args.min_password_entropy is not None:
                                policy_params["min_entropy"] = args.min_password_entropy
                            policy_params["strict_strength"] = getattr(
                                args, "strict_strength", False
                            )

                            if args.disable_common_password_check:
                                policy_params["check_common_passwords"] = False

                            if args.custom_password_list:
                                policy_params["common_passwords_path"] = args.custom_password_list

                            # Create policy
                            policy = PasswordPolicy(
                                policy_level=args.password_policy, **policy_params
                            )

                            # Validate the password (will raise ValidationError if invalid)
                            policy.validate_password_or_raise(args.password, quiet=args.quiet)

                        except crypt_errors.ValidationError as e:
                            # Always display password strength information before validation failure
                            if not args.quiet:
                                # Calculate and display password strength
                                entropy, strength = get_password_strength(args.password)
                                eprint(
                                    f"\nPassword strength: {strength} (entropy: {entropy:.1f} bits)"
                                )
                                eprint(f"Password validation failed: {str(e)}")
                                eprint(
                                    "Use --force-password to bypass validation (not recommended)"
                                )
                            sys.exit(1)

                    password_secure.extend(args.password.encode())

                # If no password provided yet, prompt the user
                else:
                    # For encryption, require password confirmation to
                    # prevent typos
                    if args.action == "encrypt" and not args.quiet:
                        match = False
                        while not match:
                            # Mutable buffers so they can be wiped in place after
                            # use. The transient str returned by getpass (and its
                            # encoding) is immutable and cannot be wiped — an
                            # inherent Python limitation (#81/#89).
                            pwd1 = bytearray(getpass.getpass("Enter password: ").encode())
                            pwd2 = bytearray(getpass.getpass("Confirm password: ").encode())

                            if pwd1 == pwd2:
                                # Validate password if policy is enabled, not forced, and not in test mode
                                valid_password = True
                                in_test_mode = os.environ.get("PYTEST_CURRENT_TEST") is not None

                                if (
                                    args.password_policy != "none"
                                    and not args.force_password
                                    and not in_test_mode
                                ):
                                    try:
                                        # Create policy with user-specified parameters
                                        policy_params = {}

                                        # Override policy settings with custom parameters if provided
                                        if args.min_password_length is not None:
                                            policy_params["min_length"] = args.min_password_length

                                        if args.min_password_entropy is not None:
                                            policy_params["min_entropy"] = args.min_password_entropy
                                        policy_params["strict_strength"] = getattr(
                                            args, "strict_strength", False
                                        )

                                        if args.disable_common_password_check:
                                            policy_params["check_common_passwords"] = False

                                        if args.custom_password_list:
                                            policy_params["common_passwords_path"] = (
                                                args.custom_password_list
                                            )

                                        # Create policy and validate password
                                        policy = PasswordPolicy(
                                            policy_level=args.password_policy,
                                            **policy_params,
                                        )
                                        policy.validate_password_or_raise(
                                            pwd1.decode("utf-8", errors="ignore")
                                        )

                                    except crypt_errors.ValidationError as e:
                                        # Calculate and display password strength
                                        entropy, strength = get_password_strength(
                                            pwd1.decode("utf-8", errors="ignore")
                                        )
                                        eprint(
                                            f"\nPassword strength: {strength} (entropy: {entropy:.1f} bits)"
                                        )
                                        eprint(f"Password validation failed: {str(e)}")
                                        eprint(
                                            "Use --force-password to bypass validation (not recommended)"
                                        )
                                        valid_password = False

                                if valid_password:
                                    password_secure.extend(pwd1)
                                    match = True

                                # Wipe the mutable prompt buffers in place
                                secure_memzero(pwd1)
                                secure_memzero(pwd2)
                            else:
                                # Wipe the mutable prompt buffers in place
                                secure_memzero(pwd1)
                                secure_memzero(pwd2)
                                eprint("Passwords do not match. Please try again.")
                    # For decryption or quiet mode, just ask once
                    else:
                        # Always prompt for a password, even in quiet mode
                        # We need to show the prompt but we can hide any extra text
                        pwd = getpass.getpass("Enter password: ")

                        # In quiet or progress mode, move up one line and clear it after
                        # getting the password.
                        if args.quiet or getattr(args, "progress", False):
                            tty_clear_line()

                        password_secure.extend(pwd.encode("utf-8"))
                        # 'pwd' is an immutable str from getpass and cannot be
                        # overwritten in place (#81/#89); rebinding it to zeros
                        # would only pretend to wipe. Drop the reference instead.
                        del pwd

                # Convert to bytes for the rest of the code
                password = bytes(password_secure)

                # Store in the keyring from the RESOLVED password, whatever
                # source it came from -- command line, environment, file, fd
                # or prompt (gitlab#156). A user who believes the password is
                # now recoverable from the keyring may discard their only
                # copy of it, so this must never fail silently.
                if getattr(args, "keyring_store", None) and password:
                    try:
                        import keyring as _keyring

                        _keyring.set_password(
                            "openssl_encrypt", args.keyring_store, password.decode("utf-8")
                        )
                        if not args.quiet:
                            eprint(f"Password stored in keyring as '{args.keyring_store}'")
                    except ImportError:
                        pass  # already reported above
                    except Exception as error:
                        eprint(f"Error: could not store the password in the keyring: {error}")
                        eprint("  Do not discard your only copy of it.")

            # Handle rekey password (new password for re-encryption)
            if args.action == "rekey":
                rekey_password = None

                # Resolve rekey password from --rekey-password-file, --rekey-password-fd,
                # or OPENSSL_ENCRYPT_REKEY_PASSWORD env var
                rekey_pw_arg = getattr(args, "rekey_password", None)
                rekey_pw_file = getattr(args, "rekey_password_file", None)
                rekey_pw_fd = getattr(args, "rekey_password_fd", None)

                if not rekey_pw_arg:
                    if rekey_pw_file:
                        try:
                            if rekey_pw_file == "-":
                                rekey_pw_arg = sys.stdin.readline().rstrip("\n")
                            else:
                                with open(rekey_pw_file, "r") as f:
                                    rekey_pw_arg = f.readline().rstrip("\n")
                        except OSError as e:
                            eprint(
                                f"Error reading rekey password file: {e}",
                                file=sys.stderr,
                            )
                            sys.exit(1)
                    elif rekey_pw_fd is not None:
                        try:
                            with os.fdopen(rekey_pw_fd, "r", closefd=False) as f:
                                rekey_pw_arg = f.readline().rstrip("\n")
                        except OSError as e:
                            eprint(
                                f"Error reading from rekey fd {rekey_pw_fd}: {e}",
                                file=sys.stderr,
                            )
                            sys.exit(1)
                    else:
                        env_rekey_pw = os.environ.get("OPENSSL_ENCRYPT_REKEY_PASSWORD")
                        if env_rekey_pw:
                            rekey_pw_arg = env_rekey_pw
                            # Register the fingerprint before deleting, or the
                            # live-environment redaction check goes inert the
                            # moment the variable is gone and a later log_event
                            # could write it unredacted (gitlab#147).
                            register_consumed_secret("OPENSSL_ENCRYPT_REKEY_PASSWORD", env_rekey_pw)
                            try:
                                del os.environ["OPENSSL_ENCRYPT_REKEY_PASSWORD"]
                            except KeyError:
                                pass

                if rekey_pw_arg:
                    # Security warning: not silenced by --quiet (#67).
                    if not rekey_pw_file and rekey_pw_fd is None:
                        eprint(
                            "WARNING: --rekey-password is visible in process list. "
                            "Use --rekey-password-file or OPENSSL_ENCRYPT_REKEY_PASSWORD env var instead.",
                            file=sys.stderr,
                        )
                    # surrogateescape round-trips bytes os.environ/argv decoded
                    # the same way; a strict encode would raise UnicodeEncodeError,
                    # whose message embeds a byte of the password and is printed
                    # verbatim by the generic handler (gitlab#147). A lone HIGH
                    # surrogate still raises and is refused without echoing bytes.
                    try:
                        rekey_password = rekey_pw_arg.encode("utf-8", "surrogateescape")
                    except UnicodeEncodeError:
                        eprint(
                            "ERROR: rekey password could not be encoded "
                            "(contains an unpaired surrogate)"
                        )
                        sys.exit(1)
                else:
                    # Interactive double-prompt for new password
                    match = False
                    while not match:
                        # Mutable buffers so they can be wiped in place (#89);
                        # the transient getpass str itself cannot be (#81).
                        pwd1 = bytearray(getpass.getpass("Enter new password: ").encode())
                        pwd2 = bytearray(getpass.getpass("Confirm new password: ").encode())

                        if pwd1 == pwd2:
                            # Copy before wiping — rekey_password must outlive
                            # the wiped prompt buffers
                            rekey_password = bytes(pwd1)
                            match = True
                        else:
                            eprint("Passwords do not match. Please try again.")

                        # Wipe the mutable prompt buffers in place
                        secure_memzero(pwd1)
                        secure_memzero(pwd2)

        except ImportError:
            # Fall back to standard method if secure_memory is not
            # available
            if not args.quiet:
                eprint("Warning: secure_memory module not available")
            sys.exit(1)

    # Check for Whirlpool availability if needed and not in quiet mode
    if args.whirlpool_rounds > 0 and not WHIRLPOOL_AVAILABLE and not args.quiet:
        eprint("Warning: pywhirlpool module not found. SHA-512 will be used instead.")

    # Check for Argon2 availability if needed
    if (args.enable_argon2 or args.argon2_preset) and not ARGON2_AVAILABLE:
        if not args.quiet:
            eprint("Warning: argon2-cffi module not found. Argon2 will be disabled.")
            eprint("Install with: pip install argon2-cffi")
        args.enable_argon2 = False
        args.argon2_preset = None

    # Check for post-quantum cryptography availability if needed
    if args.algorithm in ["kyber512-hybrid", "kyber768-hybrid", "kyber1024-hybrid"]:
        try:
            # Attempt direct import to ensure module is truly available
            import oqs  # noqa: F401

            pqc_available = True
        except ImportError:
            pqc_available = False

        if not pqc_available:
            if not args.quiet:
                eprint(
                    "Warning: liboqs-python module not found. Post-quantum cryptography will not be available."
                )
                eprint("Install with: pip install liboqs-python")
                eprint("Falling back to aes-gcm algorithm.")
            args.algorithm = "aes-gcm"

    # Validate random password parameter
    if args.random is not None:
        if args.action != "encrypt":
            parser.error("--random can only be used with the encrypt action")
        if args.password:
            parser.error("--password and --random cannot be used together")
        if args.random < 12:
            if not args.quiet:
                eprint("Warning: Random password length increased to 12 (minimum secure length)")
            args.random = 12

    # Set default iterations if SHA algorithms are requested but no iterations
    # provided
    MIN_SHA_ITERATIONS = 1000000

    # If user specified to use SHA-256, SHA-512, or SHA3 but didn't provide
    # iterations
    if args.sha512_rounds == 1:  # When flag is provided without value
        args.sha512_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            eprint(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA-512")

    if args.sha384_rounds == 1:  # When flag is provided without value
        args.sha384_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            eprint(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA-384")

    if args.sha256_rounds == 1:  # When flag is provided without value
        args.sha256_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            eprint(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA-256")

    if args.sha224_rounds == 1:  # When flag is provided without value
        args.sha224_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            eprint(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA-224")

    if args.sha3_512_rounds == 1:  # When flag is provided without value
        args.sha3_512_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            eprint(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA3-512")

    if args.sha3_384_rounds == 1:  # When flag is provided without value
        args.sha3_384_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            eprint(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA3-384")

    if args.sha3_256_rounds == 1:  # When flag is provided without value
        args.sha3_256_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            eprint(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA3-256")

    if args.sha3_224_rounds == 1:  # When flag is provided without value
        args.sha3_224_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            eprint(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA3-224")

    if args.blake2b_rounds == 1:  # When flag is provided without value
        args.blake2b_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            eprint(f"Using default of {MIN_SHA_ITERATIONS} iterations for BLAKE2b")

    if args.blake3_rounds == 1:  # When flag is provided without value
        args.blake3_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            eprint(f"Using default of {MIN_SHA_ITERATIONS} iterations for BLAKE3")

    if args.shake256_rounds == 1:  # When flag is provided without value
        args.shake256_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            eprint(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHAKE-256")

    if args.shake128_rounds == 1:  # When flag is provided without value
        args.shake128_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            eprint(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHAKE-128")

    # Determine default rounds value to use - either from --kdf-rounds or default of 10
    default_rounds = args.kdf_rounds if args.kdf_rounds > 0 else 10

    # Implicitly set --enable-XXX if --XXX-rounds is provided
    # Scrypt
    if args.scrypt_rounds > 0 and not args.enable_scrypt:
        if not args.quiet:
            logger.debug(
                f"Setting --enable-scrypt since --scrypt-rounds={args.scrypt_rounds} was provided"
            )
        args.enable_scrypt = True
    elif args.enable_scrypt and args.scrypt_rounds <= 0:
        if not args.quiet:
            rounds_src = (
                f"--kdf-rounds={default_rounds}" if args.kdf_rounds > 0 else "default of 10"
            )
            logger.debug(
                f"Setting --scrypt-rounds={default_rounds} ({rounds_src}) since --enable-scrypt was provided without rounds"
            )
        args.scrypt_rounds = default_rounds

    # Argon2
    if args.argon2_rounds > 0 and not args.enable_argon2:
        if not args.quiet:
            logger.debug(
                f"Setting --enable-argon2 since --argon2-rounds={args.argon2_rounds} was provided"
            )
        args.enable_argon2 = True
    elif args.enable_argon2 and args.argon2_rounds <= 0:
        if not args.quiet:
            rounds_src = (
                f"--kdf-rounds={default_rounds}" if args.kdf_rounds > 0 else "default of 10"
            )
            logger.debug(
                f"Setting --argon2-rounds={default_rounds} ({rounds_src}) since --enable-argon2 was provided without rounds"
            )
        args.argon2_rounds = default_rounds

    # Balloon
    if args.balloon_rounds > 0 and not args.enable_balloon:
        if not args.quiet:
            logger.debug(
                f"Setting --enable-balloon since --balloon-rounds={args.balloon_rounds} was provided"
            )
        args.enable_balloon = True
    elif args.enable_balloon and args.balloon_rounds <= 0:
        if not args.quiet:
            rounds_src = (
                f"--kdf-rounds={default_rounds}" if args.kdf_rounds > 0 else "default of 10"
            )
            logger.debug(
                f"Setting --balloon-rounds={default_rounds} ({rounds_src}) since --enable-balloon was provided without rounds"
            )
        args.balloon_rounds = default_rounds

    # RandomX implicit enable from parameters
    if (
        getattr(args, "randomx_rounds", 0) > 0
        or getattr(args, "randomx_mode", "light") != "light"
        or getattr(args, "randomx_height", 1) != 1
        or getattr(args, "randomx_hash_len", 32) != 32
    ) and not getattr(args, "enable_randomx", False):
        if not args.quiet:
            logger.debug("Setting --enable-randomx since RandomX parameters were provided")
        args.enable_randomx = True
    elif getattr(args, "enable_randomx", False) and getattr(args, "randomx_rounds", 0) <= 0:
        if not args.quiet:
            rounds_src = (
                f"--kdf-rounds={default_rounds}" if args.kdf_rounds > 0 else "default of 10"
            )
            logger.debug(
                f"Setting --randomx-rounds={default_rounds} ({rounds_src}) since --enable-randomx was provided without rounds"
            )
        args.randomx_rounds = default_rounds

    # Debug output to verify parameter values (uncomment for debugging)
    # if args.verbose:
    #     print(f"DEBUG - Parameter values after implicit settings:")
    #     print(f"DEBUG - Scrypt: enabled={args.enable_scrypt}, rounds={args.scrypt_rounds}")
    #     print(f"DEBUG - Argon2: enabled={args.enable_argon2}, rounds={args.argon2_rounds}")
    #     print(f"DEBUG - Balloon: enabled={args.enable_balloon}, rounds={args.balloon_rounds}")
    #     print(f"DEBUG - RandomX: enabled={getattr(args, 'enable_randomx', False)}, rounds={getattr(args, 'randomx_rounds', 1)}")

    # Handle Argon2 presets if specified
    if args.argon2_preset and ARGON2_AVAILABLE:
        args.enable_argon2 = True

        # Define the presets with increasingly stronger parameters
        argon2_presets = {
            "low": {
                "time_cost": 2,
                "memory_cost": 32768,  # 32 MB
                "parallelism": 2,
                "hash_len": 32,
                "type": "id",
            },
            "medium": {
                "time_cost": 3,
                "memory_cost": 65536,  # 64 MB
                "parallelism": 4,
                "hash_len": 32,
                "type": "id",
            },
            "high": {
                "time_cost": 4,
                "memory_cost": 131072,  # 128 MB
                "parallelism": 6,
                "hash_len": 32,
                "type": "id",
            },
            "paranoid": {
                "time_cost": 6,
                "memory_cost": 262144,  # 256 MB
                "parallelism": 8,
                "hash_len": 64,
                "type": "id",
            },
        }

        # Apply the selected preset
        preset = argon2_presets[args.argon2_preset]
        args.argon2_time = preset["time_cost"]
        args.argon2_memory = preset["memory_cost"]
        args.argon2_parallelism = preset["parallelism"]
        args.argon2_hash_len = preset["hash_len"]
        args.argon2_type = preset["type"]

        if not args.quiet:
            eprint(f"Using Argon2 preset '{args.argon2_preset}' with parameters:")
            eprint(f"  - Time cost: {args.argon2_time}")
            eprint(f"  - Memory: {args.argon2_memory} KB")
            eprint(f"  - Parallelism: {args.argon2_parallelism}")
            eprint(f"  - Hash length: {args.argon2_hash_len} bytes")
            eprint(f"  - Type: Argon2{args.argon2_type}")

    # Create the hash configuration dictionary
    if args.paranoid or args.quick or args.standard:
        if args.paranoid:
            hash_config = get_template_config(SecurityTemplate.PARANOID)
            hash_config["hash_config"]["algorithm"] = "xchacha20-poly1305"
        elif args.quick:
            hash_config = get_template_config(SecurityTemplate.QUICK)
            hash_config["hash_config"]["algorithm"] = "aes-ocb3"
        elif args.standard:
            hash_config = get_template_config(SecurityTemplate.STANDARD)
            hash_config["hash_config"]["algorithm"] = "aes-gcm-siv"
        # Only apply template's algorithm if user didn't explicitly provide one
        if args.algorithm == "fernet":  # Default value, user didn't provide --algorithm
            setattr(args, "algorithm", hash_config["hash_config"]["algorithm"])
        # Apply cascade mode from template if present
        if "cascade" in hash_config and not getattr(args, "cascade", None):
            setattr(args, "cascade", hash_config["cascade"])
        hash_config = hash_config["hash_config"]
        # Enable independent XOR (v11) for standard and paranoid templates
        # unless user explicitly chose --use-xor-composition
        if (args.standard or args.paranoid) and not getattr(args, "use_xor_composition", False):
            setattr(args, "independent_xor", True)
    elif args.template:
        hash_config = get_template_config(args.template)
        # Only apply template's algorithm if user didn't explicitly provide one
        if args.algorithm == "fernet":  # Default value, user didn't provide --algorithm
            if hash_config["hash_config"]["algorithm"]:
                setattr(args, "algorithm", hash_config["hash_config"]["algorithm"])
            else:
                hash_config["hash_config"]["algorithm"] = "fernet"
                setattr(args, "algorithm", "fernet")
        hash_config = hash_config["hash_config"]
    else:
        # Check if all values are at their defaults (no arguments provided)
        all_hash_rounds_zero = (
            args.sha512_rounds == 0
            and args.sha384_rounds == 0
            and args.sha256_rounds == 0
            and args.sha224_rounds == 0
            and args.sha3_512_rounds == 0
            and args.sha3_384_rounds == 0
            and args.sha3_256_rounds == 0
            and args.sha3_224_rounds == 0
            and args.blake2b_rounds == 0
            and args.blake3_rounds == 0
            and args.shake256_rounds == 0
            and args.shake128_rounds == 0
            and getattr(args, "whirlpool_rounds", 0) == 0
        )

        all_kdfs_disabled = (
            not args.enable_scrypt
            and not args.enable_argon2
            and not args.enable_balloon
            and not args.enable_hkdf
            and not getattr(args, "enable_randomx", False)
        )

        # If no arguments are provided, use the standard template as default
        if all_hash_rounds_zero and all_kdfs_disabled:
            hash_config = get_template_config(SecurityTemplate.STANDARD)
            hash_config["hash_config"]["algorithm"] = "aes-gcm-siv"
            # Only apply template's algorithm if user didn't explicitly provide one
            if args.algorithm == "fernet":  # Default value, user didn't provide --algorithm
                setattr(args, "algorithm", hash_config["hash_config"]["algorithm"])
            # Apply cascade mode from template if present
            if "cascade" in hash_config and not getattr(args, "cascade", None):
                setattr(args, "cascade", hash_config["cascade"])
            hash_config = hash_config["hash_config"]
            # Enable independent XOR (v11) by default with standard template
            if not getattr(args, "use_xor_composition", False):
                setattr(args, "independent_xor", True)
        else:
            # User provided specific arguments, build custom configuration
            hash_config = {
                "sha512": args.sha512_rounds,
                "sha384": args.sha384_rounds,
                "sha256": args.sha256_rounds,
                "sha224": args.sha224_rounds,
                "sha3_512": args.sha3_512_rounds,
                "sha3_384": args.sha3_384_rounds,
                "sha3_256": args.sha3_256_rounds,
                "sha3_224": args.sha3_224_rounds,
                "blake2b": args.blake2b_rounds,
                "blake3": args.blake3_rounds,
                "shake256": args.shake256_rounds,
                "shake128": args.shake128_rounds,
                "whirlpool": getattr(args, "whirlpool_rounds", 0),
                "scrypt": {
                    "enabled": args.enable_scrypt,
                    "n": (args.scrypt_n if args.scrypt_n and args.scrypt_n > 0 else 16384),
                    "r": args.scrypt_r if args.scrypt_r is not None else 8,
                    "p": args.scrypt_p if args.scrypt_p is not None else 1,
                    "rounds": args.scrypt_rounds,
                },
                "argon2": {
                    "enabled": args.enable_argon2,
                    "time_cost": args.argon2_time,
                    "memory_cost": args.argon2_memory,
                    "parallelism": args.argon2_parallelism,
                    "hash_len": args.argon2_hash_len,
                    # Store integer value for JSON serialization
                    "type": ARGON2_TYPE_INT_MAP.get(
                        args.argon2_type, 2
                    ),  # Default to 'id' type (2)
                    "rounds": args.argon2_rounds,
                },
                "balloon": {
                    "enabled": args.enable_balloon,
                    "time_cost": args.balloon_time_cost,
                    "space_cost": args.balloon_space_cost,
                    "parallelism": args.balloon_parallelism,
                    "rounds": args.balloon_rounds,
                },
                "hkdf": {
                    "enabled": args.enable_hkdf,
                    "rounds": args.hkdf_rounds,
                    "algorithm": args.hkdf_algorithm,
                    "info": args.hkdf_info,
                },
                "randomx": {
                    "enabled": getattr(args, "enable_randomx", False),
                    "rounds": getattr(args, "randomx_rounds", 1),
                    "mode": getattr(args, "randomx_mode", "light"),
                    "height": getattr(args, "randomx_height", 1),
                    "hash_len": getattr(args, "randomx_hash_len", 32),
                },
                "pbkdf2_iterations": getattr(args, "pbkdf2_iterations", 0),
            }

    # Debug the hash configuration if debug mode is enabled
    if args.debug:
        debug_hash_config(args, hash_config, "Hash configuration after setup")

    exit_code = 0
    try:
        # Initialize plugin system if not disabled
        plugin_manager = None
        # Auto-enable plugins if HSM is requested
        if hasattr(args, "hsm") and args.hsm:
            enable_plugins = True
        else:
            enable_plugins = args.enable_plugins and not args.disable_plugins
        if enable_plugins:
            try:
                from .plugin_system import create_default_plugin_manager

                plugin_manager = create_default_plugin_manager(args.plugin_config_dir)
                if args.plugin_dir:
                    plugin_manager.add_plugin_directory(args.plugin_dir)

                # Discover and load plugins quietly
                discovered = plugin_manager.discover_plugins()
                for plugin_file in discovered:
                    load_result = plugin_manager.load_plugin(plugin_file)
                    if not load_result.success and args.verbose and not args.quiet:
                        eprint(f"⚠️  Failed to load plugin {plugin_file}: {load_result.message}")

                if args.verbose and not args.quiet:
                    loaded_count = len(plugin_manager.list_plugins())
                    if loaded_count > 0:
                        eprint(f"🔌 Plugin system initialized with {loaded_count} plugins")

            except ImportError:
                if args.verbose and not args.quiet:
                    eprint("⚠️  Plugin system not available")
                plugin_manager = None
                enable_plugins = False
            except Exception as e:
                if not args.quiet:
                    eprint(f"⚠️  Plugin system error: {e}")
                plugin_manager = None
                enable_plugins = False

        # Load HSM plugin if requested
        hsm_plugin_instance = None
        if hasattr(args, "hsm") and args.hsm:
            try:
                # Direct import of HSM plugins (avoids dynamic loading issues)
                if args.hsm.lower() == "yubikey":
                    from ..plugins.hsm.yubikey_challenge_response import YubikeyHSMPlugin

                    hsm_plugin_instance = YubikeyHSMPlugin()

                    # Initialize plugin
                    init_result = hsm_plugin_instance.initialize({})
                    if not init_result.success:
                        eprint(f"Error initializing HSM plugin: {init_result.message}")
                        sys.exit(1)

                    if not args.quiet:
                        eprint(f"✅ Loaded HSM plugin: {hsm_plugin_instance.name}")
                        if hasattr(args, "hsm_slot") and args.hsm_slot:
                            eprint(f"   Using manual slot: {args.hsm_slot}")
                        else:
                            eprint("   Auto-detecting Challenge-Response slot")

                elif args.hsm.lower() == "onlykey":
                    from ..plugins.hsm.onlykey_challenge_response import OnlykeyHSMPlugin

                    hsm_plugin_instance = OnlykeyHSMPlugin()

                    # Initialize plugin
                    init_result = hsm_plugin_instance.initialize({})
                    if not init_result.success:
                        eprint(f"Error initializing HSM plugin: {init_result.message}")
                        sys.exit(1)

                    if not args.quiet:
                        eprint(f"✅ Loaded HSM plugin: {hsm_plugin_instance.name}")
                        if hasattr(args, "hsm_slot") and args.hsm_slot:
                            eprint(f"   Using manual slot: {args.hsm_slot}")
                        else:
                            eprint("   Auto-detecting Challenge-Response slot (1..12)")

                elif args.hsm.lower() == "fido2":
                    from ..plugins.hsm.fido2_pepper import FIDO2HSMPlugin

                    hsm_plugin_instance = FIDO2HSMPlugin()

                    # Initialize plugin
                    init_result = hsm_plugin_instance.initialize({})
                    if not init_result.success:
                        eprint(f"Error initializing HSM plugin: {init_result.message}")
                        sys.exit(1)

                    if not args.quiet:
                        eprint(f"✅ Loaded HSM plugin: {hsm_plugin_instance.name}")
                        eprint(f"   RP ID: {hsm_plugin_instance.rp_id}")
                        if not hsm_plugin_instance.is_registered():
                            eprint(
                                "   ⚠️  No credentials registered. Run: openssl_encrypt hsm fido2-register"
                            )

                elif args.hsm.lower() == "piv":
                    from ..plugins.hsm.piv_card import PIVHSMPlugin

                    pkcs11_lib = getattr(args, "hsm_pkcs11_lib", None)
                    if not pkcs11_lib:
                        eprint(
                            "Error: --hsm piv requires --hsm-pkcs11-lib PATH "
                            "(e.g. /usr/lib/opensc-pkcs11.so or the ykcs11 module)."
                        )
                        sys.exit(1)

                    # crypt_core builds its own security context for the encrypt/
                    # decrypt path, so the PIV config must live on the instance.
                    hsm_plugin_instance = PIVHSMPlugin(
                        pkcs11_lib_path=pkcs11_lib,
                        slot_index=(getattr(args, "hsm_slot", None) or 0),
                        piv_slot=getattr(args, "hsm_piv_slot", 0x9A),
                        biometric=bool(getattr(args, "hsm_biometric", False)),
                    )

                    init_result = hsm_plugin_instance.initialize({})
                    if not init_result.success:
                        eprint(f"Error initializing HSM plugin: {init_result.message}")
                        sys.exit(1)

                    if not args.quiet:
                        eprint(f"✅ Loaded HSM plugin: {hsm_plugin_instance.name}")
                        eprint(f"   PIV slot: {getattr(args, 'hsm_piv_slot', 0x9A):#x}")

                else:
                    eprint(
                        f"Error: Unknown HSM plugin '{args.hsm}'. Supported: yubikey, onlykey, fido2, piv"
                    )
                    sys.exit(1)

            except ImportError as e:
                eprint(f"Error: Could not import HSM plugin: {e}")
                if args.hsm.lower() == "yubikey":
                    eprint(
                        "Make sure yubikey-manager is installed: pip install -r requirements-hsm.txt"
                    )
                elif args.hsm.lower() == "onlykey":
                    eprint(
                        "Make sure yubikey-manager is installed: pip install -r requirements-hsm.txt"
                    )
                elif args.hsm.lower() == "fido2":
                    eprint("Make sure fido2 library is installed: pip install fido2>=1.1.0")
                elif args.hsm.lower() == "piv":
                    eprint(
                        "Make sure python-pkcs11 is installed: pip install -r requirements-hsm.txt"
                    )
                sys.exit(1)
            except Exception as e:
                eprint(f"Error initializing HSM plugin: {e}")
                sys.exit(1)

        # Load pepper plugin if requested
        pepper_plugin_instance = None
        pepper_name_to_use = None
        if hasattr(args, "pepper") and args.pepper:
            try:
                from ..plugins.pepper import PepperConfig, PepperError, PepperPlugin

                config = PepperConfig.from_file()
                if not config.enabled:
                    eprint("ERROR: --pepper flag used but pepper plugin not configured")
                    eprint(f"Configure at: {PepperConfig.get_default_config_path()}")
                    sys.exit(1)

                pepper_plugin_instance = PepperPlugin(config)

                # Auto-generate mode: don't set pepper_name_to_use (leave as None)
                # The core encryption logic will generate a new pepper and determine the name
                pepper_name_to_use = None

                if not args.quiet:
                    eprint("Pepper plugin enabled (auto-generate mode)")

            except ImportError as e:
                eprint(f"ERROR: Could not import pepper plugin: {e}")
                eprint("Make sure pepper plugin is properly installed")
                sys.exit(1)
            except Exception as e:
                eprint(f"ERROR: Pepper plugin initialization failed: {e}")
                sys.exit(1)

        elif hasattr(args, "pepper_name") and args.pepper_name:
            try:
                from ..plugins.pepper import PepperConfig, PepperError, PepperPlugin

                config = PepperConfig.from_file()
                if not config.enabled:
                    eprint("ERROR: --pepper-name flag used but pepper plugin not configured")
                    eprint(f"Configure at: {PepperConfig.get_default_config_path()}")
                    sys.exit(1)

                pepper_plugin_instance = PepperPlugin(config)
                pepper_name_to_use = args.pepper_name

                if not args.quiet:
                    eprint(f"Pepper plugin enabled (using existing pepper: {pepper_name_to_use})")

            except ImportError as e:
                eprint(f"ERROR: Could not import pepper plugin: {e}")
                eprint("Make sure pepper plugin is properly installed")
                sys.exit(1)
            except Exception as e:
                eprint(f"ERROR: Pepper plugin initialization failed: {e}")
                sys.exit(1)

        if args.action == "encrypt":
            # Parse streaming size arguments
            _streaming_chunk_size = None
            _streaming_threshold = None
            if getattr(args, "chunk_size", None):
                from .streaming import parse_size_string

                try:
                    _streaming_chunk_size = parse_size_string(args.chunk_size)
                except ValueError as e:
                    eprint(f"ERROR: Invalid --chunk-size: {e}", file=sys.stderr)
                    sys.exit(1)
            if getattr(args, "streaming_threshold", None):
                from .streaming import parse_size_string

                try:
                    _streaming_threshold = parse_size_string(args.streaming_threshold)
                except ValueError as e:
                    eprint(f"ERROR: Invalid --streaming-threshold: {e}", file=sys.stderr)
                    sys.exit(1)

            # Check if asymmetric mode (--for flag present)
            if hasattr(args, "for_identity") and args.for_identity:
                # Asymmetric encryption mode
                from .crypt_core import encrypt_file_asymmetric
                from .identity_cli import get_identity_store

                store = get_identity_store(resolve_identity_store_path(args))

                # Initialize KeyResolver for keyserver support (if enabled)
                keyserver_plugin = None
                if hasattr(args, "use_keyserver") and args.use_keyserver:
                    try:
                        from ..plugins.keyserver import KeyserverConfig, KeyserverPlugin

                        config = KeyserverConfig.from_file()
                        if config.enabled:
                            keyserver_plugin = KeyserverPlugin(config)
                            if not args.quiet:
                                eprint(
                                    "🔑 Keyserver enabled: will fetch public keys from remote if not found locally"
                                )
                        else:
                            if not args.quiet:
                                eprint(
                                    "⚠️  Keyserver is disabled. Enable with: openssl-encrypt keyserver enable"
                                )
                    except ImportError:
                        if not args.quiet:
                            eprint("⚠️  Keyserver plugin not available")
                    except Exception as e:
                        if not args.quiet:
                            eprint(f"⚠️  Failed to initialize keyserver: {e}")

                # Load recipients (with KeyResolver support)
                recipients = []
                for recipient_name in args.for_identity:
                    try:
                        if keyserver_plugin:
                            # Use KeyResolver for keyserver support
                            from .key_resolver import (
                                KeyNotFoundError,
                                KeyResolver,
                                TrustDeclinedError,
                            )

                            resolver = KeyResolver(store, keyserver_plugin)
                            recipient = resolver.resolve(recipient_name, load_private_keys=False)
                        else:
                            # Use direct store lookup (legacy behavior)
                            recipient = store.get_by_name(
                                recipient_name, passphrase=None, load_private_keys=False
                            )
                            if recipient is None:
                                raise KeyError(f"Recipient identity '{recipient_name}' not found")

                        recipients.append(recipient)

                    except KeyNotFoundError:
                        eprint(
                            f"ERROR: Recipient identity '{recipient_name}' not found ❌",
                            file=sys.stderr,
                        )
                        sys.exit(1)
                    except TrustDeclinedError:
                        eprint(
                            f"ERROR: Trust declined for '{recipient_name}' ❌",
                            file=sys.stderr,
                        )
                        sys.exit(1)
                    except KeyError as e:
                        eprint(f"ERROR: {e} ❌", file=sys.stderr)
                        sys.exit(1)
                    except Exception as e:
                        error_msg = f"ERROR: Failed to load identity '{recipient_name}'"
                        if str(e):
                            error_msg += f": {e}"
                        error_msg += " ❌"
                        eprint(error_msg, file=sys.stderr)
                        sys.exit(1)

                # Load sender
                if not hasattr(args, "sign_with") or not args.sign_with:
                    eprint(
                        "ERROR: --sign-with required for asymmetric encryption",
                        file=sys.stderr,
                    )
                    sys.exit(1)

                # First load identity metadata to check protection level
                sender_metadata = store.get_by_name(args.sign_with, load_private_keys=False)
                if sender_metadata is None:
                    eprint(
                        f"ERROR: Sender identity '{args.sign_with}' not found ❌",
                        file=sys.stderr,
                    )
                    sys.exit(1)

                # Determine if passphrase is needed
                # Same environment channel as `sign` (gitlab#159): this path
                # signs with the same identity and reached only a /dev/tty
                # prompt, so a GUI or CI caller could not use --sign-with at
                # all -- and the variable would have survived the whole run,
                # contradicting the read-once-and-remove guarantee.
                from .file_signature import SIGNER_PASSPHRASE_ENV
                from .identity_protection import ProtectionLevel

                _sender_needs_passphrase = (
                    not sender_metadata.protection
                    or sender_metadata.protection.level != ProtectionLevel.HSM_ONLY
                )
                try:
                    # explicit=: the variable was consumed up front, before the
                    # plugin/HSM/pepper/keyserver machinery ran, so it is no
                    # longer live in os.environ here (gitlab#180). resolve_credential
                    # still calls consume_env internally (a harmless no-op now)
                    # and validates the explicit value like every other channel.
                    sender_passphrase = resolve_credential(
                        requested=_sender_needs_passphrase,
                        env_name=SIGNER_PASSPHRASE_ENV,
                        prompt=f"Passphrase for sender identity " f"'{args.sign_with}': ",
                        explicit=_early_signer_passphrase,
                        explicit_source=f"${SIGNER_PASSPHRASE_ENV}",
                    )
                except CredentialError as e:
                    eprint(f"ERROR: {e} ❌")
                    raise SystemExit(1)
                except EOFError:
                    # Matches `sign`: name the variable rather than surfacing
                    # an empty message from the generic handler.
                    eprint(
                        f"ERROR: no passphrase supplied and no terminal to "
                        f"prompt on; set ${SIGNER_PASSPHRASE_ENV} ❌"
                    )
                    raise SystemExit(1)
                except KeyboardInterrupt:
                    # Also matches `sign`. KeyboardInterrupt is a
                    # BaseException, so without this it escapes the outer
                    # `except Exception` as a raw traceback.
                    eprint("Aborted.")
                    raise SystemExit(130)

                try:
                    sender = store.get_by_name(
                        args.sign_with,
                        passphrase=sender_passphrase,
                        load_private_keys=True,
                    )
                    if sender is None:
                        eprint(
                            f"ERROR: Sender identity '{args.sign_with}' not found ❌",
                            file=sys.stderr,
                        )
                        sys.exit(1)
                except Exception as e:
                    error_msg = f"ERROR: Failed to load identity '{args.sign_with}'"
                    if str(e):
                        error_msg += f": {e}"
                    error_msg += " ❌"
                    eprint(error_msg, file=sys.stderr)
                    sys.exit(1)
                finally:
                    # Clean up passphrase from memory
                    if "sender_passphrase" in locals() and sender_passphrase:
                        from .secure_memory import secure_memzero

                        secure_memzero(sender_passphrase)

                # Feature #6: encrypt-to-self. Add the sender as an additional
                # recipient (unless already listed or opted out) so the sender
                # can decrypt their own outbound file.
                from .identity import resolve_recipients_with_self

                encrypt_to_self = getattr(args, "encrypt_to_self", True)
                recipients_before = len(recipients)
                recipients = resolve_recipients_with_self(
                    recipients, sender, enabled=encrypt_to_self
                )
                if not args.quiet and len(recipients) > recipients_before:
                    eprint(f"Encrypt-to-self: added sender '{sender.name}' as a recipient")

                # Build hash config from CLI arguments
                # Use the same hash_config building logic as symmetric encryption (around line 4009)
                hash_config = {
                    "sha512": getattr(args, "sha512_rounds", 0) or 0,
                    "sha384": getattr(args, "sha384_rounds", 0) or 0,
                    "sha256": getattr(args, "sha256_rounds", 0) or 0,
                    "sha224": getattr(args, "sha224_rounds", 0) or 0,
                    "sha3_512": getattr(args, "sha3_512_rounds", 0) or 0,
                    "sha3_384": getattr(args, "sha3_384_rounds", 0) or 0,
                    "sha3_256": getattr(args, "sha3_256_rounds", 0) or 0,
                    "sha3_224": getattr(args, "sha3_224_rounds", 0) or 0,
                    "blake2b": getattr(args, "blake2b_rounds", 0) or 0,
                    "blake3": getattr(args, "blake3_rounds", 0) or 0,
                    "shake256": getattr(args, "shake256_rounds", 0) or 0,
                    "shake128": getattr(args, "shake128_rounds", 0) or 0,
                    "whirlpool": 0,
                    "scrypt": {
                        "enabled": getattr(args, "enable_scrypt", False),
                        "n": getattr(args, "scrypt_n", 0) or 0,
                        "r": (getattr(args, "scrypt_r", 8) if hasattr(args, "scrypt_r") else 8),
                        "p": (getattr(args, "scrypt_p", 1) if hasattr(args, "scrypt_p") else 1),
                        "rounds": (
                            getattr(args, "scrypt_rounds", 1)
                            if hasattr(args, "scrypt_rounds")
                            else 1
                        ),
                    },
                    "argon2": {
                        "enabled": getattr(args, "enable_argon2", False),
                        "time_cost": (
                            getattr(args, "argon2_time", 3) if hasattr(args, "argon2_time") else 3
                        ),
                        "memory_cost": (
                            getattr(args, "argon2_memory", 65536)
                            if hasattr(args, "argon2_memory")
                            else 65536
                        ),
                        "parallelism": (
                            getattr(args, "argon2_parallelism", 4)
                            if hasattr(args, "argon2_parallelism")
                            else 4
                        ),
                        "hash_len": (
                            getattr(args, "argon2_hash_len", 32)
                            if hasattr(args, "argon2_hash_len")
                            else 32
                        ),
                        "type": ARGON2_TYPE_INT_MAP.get(getattr(args, "argon2_type", "id"), 2),
                        "rounds": getattr(args, "argon2_rounds", 0) or 0,
                    },
                    "balloon": {
                        "enabled": getattr(args, "enable_balloon", False)
                        or getattr(args, "use_balloon", False),
                        "space_cost": (
                            getattr(args, "balloon_space_cost", 1024)
                            if hasattr(args, "balloon_space_cost")
                            else 1024
                        ),
                        "time_cost": (
                            getattr(args, "balloon_time_cost", 1)
                            if hasattr(args, "balloon_time_cost")
                            else 1
                        ),
                        "parallelism": (
                            getattr(args, "balloon_parallelism", 1)
                            if hasattr(args, "balloon_parallelism")
                            else 1
                        ),
                        "rounds": (
                            getattr(args, "balloon_rounds", 1)
                            if hasattr(args, "balloon_rounds")
                            else 1
                        ),
                    },
                    "hkdf": {
                        "enabled": getattr(args, "enable_hkdf", False),
                        "rounds": (
                            getattr(args, "hkdf_rounds", 1) if hasattr(args, "hkdf_rounds") else 1
                        ),
                    },
                    "randomx": {
                        "enabled": getattr(args, "enable_randomx", False),
                        "mode": (
                            getattr(args, "randomx_mode", "light")
                            if hasattr(args, "randomx_mode")
                            else "light"
                        ),
                        "height": (
                            getattr(args, "randomx_height", 1)
                            if hasattr(args, "randomx_height")
                            else 1
                        ),
                        "hash_len": (
                            getattr(args, "randomx_hash_len", 32)
                            if hasattr(args, "randomx_hash_len")
                            else 32
                        ),
                        "rounds": (
                            getattr(args, "randomx_rounds", 1)
                            if hasattr(args, "randomx_rounds")
                            else 1
                        ),
                    },
                }

                # Add pbkdf2_iterations separately
                if hasattr(args, "pbkdf2_iterations") and args.pbkdf2_iterations > 0:
                    hash_config["pbkdf2_iterations"] = args.pbkdf2_iterations

                # Determine output file
                if args.overwrite:
                    output_file = args.input
                    temp_dir = os.path.dirname(os.path.abspath(args.input))
                    temp_suffix = f".{__import__('uuid').uuid4().hex[:12]}.tmp"
                    temp_output = os.path.join(temp_dir, os.path.basename(args.input) + temp_suffix)
                elif args.output:
                    output_file = args.output
                    temp_output = output_file
                else:
                    output_file = args.input + ".enc"
                    temp_output = output_file

                # Encrypt
                try:
                    result = encrypt_file_asymmetric(
                        input_file=args.input,
                        output_file=temp_output,
                        recipients=recipients,
                        sender=sender,
                        hash_config=hash_config if hash_config else None,
                        algorithm=getattr(args, "encryption_data", "aes-gcm"),
                        quiet=args.quiet,
                        progress=args.progress,
                        verbose=args.verbose,
                        hidden_header=_hidden_for_encrypt(args, _hidden_second_password),
                        second_password=_hidden_second_password,
                    )

                    # Handle temp file if overwrite mode
                    if args.overwrite and temp_output != output_file:
                        import shutil

                        shutil.move(temp_output, output_file)

                    # Feature #2: wrap the finished recipient file in ASCII armor.
                    if getattr(args, "armor", False) and os.path.isfile(output_file):
                        from .armor import armor_file

                        armor_file(output_file)

                    if not args.quiet:
                        eprint("\nAsymmetric encryption successful! ✅")
                        eprint(
                            f"File size: {result['original_size']} bytes → {result['encrypted_size']} bytes (encrypted)"
                        )
                        eprint(f"Encrypted file: {output_file}")

                    # Shred original if requested
                    if args.shred:
                        from .crypt_utils import shred_file

                        shred_file(args.input, passes=args.shred_passes)

                    # Defense-in-depth (gitlab#223 review f4): the guard that
                    # refuses --random-password-out for asymmetric runs makes
                    # this unreachable with an orphan today, but a relaxed
                    # guard must not turn every successful asymmetric encrypt
                    # into a false orphan NOTE.
                    _encrypt_completed = True
                    sys.exit(0)

                except Exception as e:
                    eprint(f"ERROR: Asymmetric encryption failed: {e}", file=sys.stderr)
                    if args.debug:
                        import traceback

                        traceback.print_exc()
                    sys.exit(1)

            # DEPRECATED: Whirlpool is no longer supported for new encryptions
            if hasattr(args, "whirlpool_rounds") and getattr(args, "whirlpool_rounds", 0) > 0:
                eprint("ERROR: Whirlpool is deprecated for new encryptions.")
                eprint("Please use BLAKE2b, BLAKE3, or SHA-3 instead.")
                eprint("Existing files encrypted with Whirlpool can still be decrypted.")
                sys.exit(1)

            # DEPRECATED: PBKDF2 is no longer supported for new encryptions
            if hasattr(args, "pbkdf2_iterations") and getattr(args, "pbkdf2_iterations", 0) > 0:
                eprint("ERROR: PBKDF2 is deprecated for new encryptions.")
                eprint("Please use Argon2, Scrypt, or Balloon hashing instead.")
                eprint("Existing files encrypted with PBKDF2 can still be decrypted.")
                sys.exit(1)

            # DEPRECATED: Kyber algorithms are no longer supported for new encryptions
            # Only warn if user actually used the old Kyber names, not if they used ML-KEM names
            kyber_algorithms = [
                "kyber512-hybrid",
                "kyber768-hybrid",
                "kyber1024-hybrid",
            ]
            ml_kem_algorithms = [
                "ml-kem-512-hybrid",
                "ml-kem-768-hybrid",
                "ml-kem-1024-hybrid",
            ]

            # Check if this algorithm was originally an ML-KEM name that got converted
            original_ml_kem_algorithm = os.environ.get("OPENSSL_ENCRYPT_ORIGINAL_MLKEM_ALGORITHM")

            # Check the original user input, not the mapped algorithm
            user_provided_algorithm = original_algorithm or args.algorithm
            if args.debug:
                eprint(f"DEBUG: args.algorithm = {args.algorithm}")
                eprint(f"DEBUG: original_algorithm = {original_algorithm}")
                eprint(f"DEBUG: original_ml_kem_algorithm = {original_ml_kem_algorithm}")
                eprint(f"DEBUG: user_provided_algorithm = {user_provided_algorithm}")
                eprint(
                    f"DEBUG: user_provided_algorithm in ml_kem_algorithms = {user_provided_algorithm in ml_kem_algorithms}"
                )

            # Don't warn if the user originally provided an ML-KEM name that got converted to kyber
            if (
                hasattr(args, "algorithm")
                and args.algorithm in kyber_algorithms
                and user_provided_algorithm not in ml_kem_algorithms
                and not original_ml_kem_algorithm
            ):
                ml_kem_mapping = {
                    "kyber512-hybrid": "ml-kem-512-hybrid",
                    "kyber768-hybrid": "ml-kem-768-hybrid",
                    "kyber1024-hybrid": "ml-kem-1024-hybrid",
                }
                recommended = ml_kem_mapping[args.algorithm]
                eprint(f"ERROR: {args.algorithm} is deprecated for new encryptions.")
                eprint(f"Please use {recommended} instead (NIST standardized equivalent).")
                eprint(f"Existing files encrypted with {args.algorithm} can still be decrypted.")
                sys.exit(1)

            # Enforce deprecation policy: Block encryption with deprecated algorithms in version 1.2.0
            # ml_kem_patch rewrites ML-KEM names in sys.argv to legacy kyber names before main()
            # runs, so judge the name the user actually typed (preserved in the env var by the
            # patch), not the synthetic converted one — otherwise ml-kem-*-hybrid is unusable.
            blocked_check_name = original_ml_kem_algorithm or args.algorithm
            if is_encryption_blocked_for_algorithm(blocked_check_name):
                error_message = get_encryption_block_message(blocked_check_name)
                eprint(f"ERROR: {error_message}")
                sys.exit(1)

            # Check if main algorithm is deprecated and issue warning
            if is_deprecated(args.algorithm):
                replacement = get_recommended_replacement(args.algorithm)
                warn_deprecated_algorithm(args.algorithm, "command-line encryption")
                if (
                    not args.quiet
                    and replacement
                    and (args.verbose or not args.algorithm.startswith(("kyber", "ml-kem")))
                ):
                    eprint(f"Warning: The algorithm '{args.algorithm}' is deprecated.")
                    eprint(f"Consider using '{replacement}' instead for better security.")

            # Enforce deprecation policy for PQC data encryption algorithms
            if args.algorithm.endswith("-hybrid") and is_encryption_blocked_for_algorithm(
                args.encryption_data
            ):
                data_error_message = get_encryption_block_message(args.encryption_data)
                eprint(f"ERROR: PQC data encryption - {data_error_message}")
                sys.exit(1)

            # Check if data encryption algorithm is deprecated for PQC
            if args.algorithm.endswith("-hybrid") and is_deprecated(args.encryption_data):
                data_replacement = get_recommended_replacement(args.encryption_data)
                warn_deprecated_algorithm(args.encryption_data, "PQC data encryption")
                if (
                    not args.quiet
                    and data_replacement
                    and (args.verbose or not args.encryption_data.startswith(("kyber", "ml-kem")))
                ):
                    eprint(
                        f"Warning: The data encryption algorithm '{args.encryption_data}' is deprecated."
                    )
                    eprint(f"Consider using '{data_replacement}' instead for better security.")

            # Handle output file path
            # Resolved ONCE, before the overwrite branch, so both output
            # paths use the same keypair. This used to be duplicated: the
            # overwrite branch had its own copy (which wrote the private key
            # in the clear and could not read a wrapped keyfile), and this
            # one was labelled "for non-overwriting case". Deleting the
            # duplicate without moving this left the overwrite path with no
            # keyfile handling at all -- it encrypted with an ephemeral key
            # and only reached this block afterwards, so a bad keyfile was
            # reported after the input had already been replaced (gitlab#157).
            # Handle PQC key operations (for non-overwriting case)
            pqc_keypair = None
            if args.algorithm in [
                "kyber512-hybrid",
                "kyber768-hybrid",
                "kyber1024-hybrid",
                "hqc-128-hybrid",
                "hqc-192-hybrid",
                "hqc-256-hybrid",
                "ml-kem-512-hybrid",
                "ml-kem-768-hybrid",
                "ml-kem-1024-hybrid",
                "ml-kem-512-chacha20",
                "ml-kem-768-chacha20",
                "ml-kem-1024-chacha20",
            ]:
                # Check if we should generate and save a new key pair
                if args.pqc_gen_key and args.pqc_keyfile:
                    from .pqc import PQCAlgorithm, PQCipher, check_pqc_support

                    # Map algorithm name to PQCAlgorithm with fallbacks
                    pqc_algorithms = check_pqc_support(quiet=args.quiet)[2]

                    # Determine which variants are available
                    kyber512_options = [
                        alg
                        for alg in pqc_algorithms
                        if alg.lower().replace("-", "").replace("_", "") in ["kyber512", "mlkem512"]
                    ]
                    kyber768_options = [
                        alg
                        for alg in pqc_algorithms
                        if alg.lower().replace("-", "").replace("_", "") in ["kyber768", "mlkem768"]
                    ]
                    kyber1024_options = [
                        alg
                        for alg in pqc_algorithms
                        if alg.lower().replace("-", "").replace("_", "")
                        in ["kyber1024", "mlkem1024"]
                    ]
                    hqc128_options = [
                        alg
                        for alg in pqc_algorithms
                        if alg.lower().replace("-", "").replace("_", "") in ["hqc128"]
                    ]
                    hqc192_options = [
                        alg
                        for alg in pqc_algorithms
                        if alg.lower().replace("-", "").replace("_", "") in ["hqc192"]
                    ]
                    hqc256_options = [
                        alg
                        for alg in pqc_algorithms
                        if alg.lower().replace("-", "").replace("_", "") in ["hqc256"]
                    ]

                    # Choose first available or fall back to default name
                    kyber512_algo = kyber512_options[0] if kyber512_options else "Kyber512"
                    kyber768_algo = kyber768_options[0] if kyber768_options else "Kyber768"
                    kyber1024_algo = kyber1024_options[0] if kyber1024_options else "Kyber1024"
                    hqc128_algo = hqc128_options[0] if hqc128_options else "HQC-128"
                    hqc192_algo = hqc192_options[0] if hqc192_options else "HQC-192"
                    hqc256_algo = hqc256_options[0] if hqc256_options else "HQC-256"

                    if not args.quiet:
                        eprint(
                            f"Using algorithm mappings: kyber512-hybrid → {kyber512_algo}, kyber768-hybrid → {kyber768_algo}, kyber1024-hybrid → {kyber1024_algo}, hqc-128-hybrid → {hqc128_algo}, hqc-192-hybrid → {hqc192_algo}, hqc-256-hybrid → {hqc256_algo}"
                        )

                    # Create direct string mapping
                    algo_map = {
                        "kyber512-hybrid": kyber512_algo,
                        "kyber768-hybrid": kyber768_algo,
                        "kyber1024-hybrid": kyber1024_algo,
                        "hqc-128-hybrid": hqc128_algo,
                        "hqc-192-hybrid": hqc192_algo,
                        "hqc-256-hybrid": hqc256_algo,
                        "ml-kem-512-hybrid": kyber512_algo,
                        "ml-kem-768-hybrid": kyber768_algo,
                        "ml-kem-1024-hybrid": kyber1024_algo,
                        "ml-kem-512-chacha20": kyber512_algo,
                        "ml-kem-768-chacha20": kyber768_algo,
                        "ml-kem-1024-chacha20": kyber1024_algo,
                    }

                    # Generate key pair
                    cipher = PQCipher(algo_map[args.algorithm], quiet=args.quiet)
                    public_key, private_key = cipher.generate_keypair()

                    # Save key pair to file
                    import base64
                    import json

                    # Get password for encrypting the private key in the keyfile
                    keyfile_password = None
                    if "password" in locals() and password:
                        # Use the same password as for the file encryption
                        keyfile_password = password
                    else:
                        # Get a separate password for the keyfile
                        keyfile_password = getpass.getpass(
                            "Enter password to encrypt the private key in keyfile: "
                        ).encode()

                    # Encrypt the private key with the password.
                    # gitlab#131 (F16): derive the wrapping key with Argon2id and
                    # record a self-describing descriptor. Legacy keyfiles used
                    # PBKDF2-SHA256 100k (below the OWASP floor); they still
                    # decrypt via the no-"key_kdf" branch of
                    # _derive_pqc_keyfile_key.
                    key_salt = secrets.token_bytes(16)
                    keyfile_kdf = _new_pqc_keyfile_kdf()
                    encryption_key = _derive_pqc_keyfile_key(
                        keyfile_password, key_salt, keyfile_kdf
                    )

                    # Use AES-GCM to encrypt the private key
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                    aes_cipher = AESGCM(encryption_key)
                    nonce = secrets.token_bytes(12)  # 12 bytes for AES-GCM
                    encrypted_private_key = nonce + aes_cipher.encrypt(nonce, private_key, None)

                    key_data = {
                        "algorithm": args.algorithm,
                        "public_key": base64.b64encode(public_key).decode("utf-8"),
                        "private_key": base64.b64encode(encrypted_private_key).decode("utf-8"),
                        "key_salt": base64.b64encode(key_salt).decode("utf-8"),
                        "key_kdf": keyfile_kdf,  # F16: Argon2id descriptor
                        "key_encrypted": True,  # Mark that the key is encrypted
                    }

                    # 0600 via create_secure_file, not a bare open(): this file
                    # holds the long-lived post-quantum private key. It is
                    # wrapped with Argon2id + AES-GCM, so a world-readable copy
                    # is not an immediate break, but it hands anyone on the host
                    # an offline target and the mode was whatever the umask
                    # said -- typically 0644 (gitlab#157). The same primitive
                    # the recovery-code writer uses: O_NOFOLLOW and O_EXCL, so a
                    # pre-planted symlink or FIFO is refused rather than
                    # followed, and the mode is pinned with fchmod.
                    from .file_permissions import PermissionLevel, create_secure_file

                    try:
                        fd = create_secure_file(
                            args.pqc_keyfile, PermissionLevel.OWNER_ONLY, exclusive=True
                        )
                    except FileExistsError:
                        # Unconditional eprint: the generic handler's message is
                        # suppressed by --quiet, which would leave a bare exit 1.
                        eprint(
                            f"Error: {sanitize_for_display(args.pqc_keyfile)} already exists; "
                            "refusing to overwrite a key file."
                        )
                        eprint(
                            "  Remove it or choose another path. Overwriting would "
                            "destroy the private key it holds, and anything encrypted "
                            "to that key with it."
                        )
                        raise
                    # fdopen rather than a bare os.write: os.write may write
                    # fewer bytes than asked (a small tmpfs hitting ENOSPC),
                    # and an unchecked short write would report a truncated
                    # keyfile as saved.
                    with os.fdopen(fd, "wb") as keyfile_handle:
                        keyfile_handle.write(json.dumps(key_data).encode("utf-8"))
                        keyfile_handle.flush()
                        os.fsync(keyfile_handle.fileno())

                    # Commit the directory entry too, the same way the
                    # recovery-code writer does: the key must survive a crash
                    # that the file encrypted to it also survives. Best effort
                    # -- the key is already written, so a directory that
                    # cannot be opened must not fail the run.
                    try:
                        keyfile_dir_fd = os.open(
                            os.path.dirname(os.path.abspath(args.pqc_keyfile)), os.O_RDONLY
                        )
                    except OSError:
                        keyfile_dir_fd = None
                    if keyfile_dir_fd is not None:
                        try:
                            os.fsync(keyfile_dir_fd)
                        except OSError:
                            pass
                        finally:
                            os.close(keyfile_dir_fd)

                    if not args.quiet:
                        eprint(f"Post-quantum key pair saved to {args.pqc_keyfile}")

                    pqc_keypair = (public_key, private_key)

                # Check if we should load an existing key pair
                elif args.pqc_keyfile and os.path.exists(args.pqc_keyfile):
                    import base64
                    import json

                    with open(args.pqc_keyfile, "r") as f:
                        # MED-8 Security fix: Use secure JSON validation for PQC key file loading
                        json_content = f.read()
                        try:
                            from .json_validator import (
                                JSONSecurityError,
                                JSONValidationError,
                                secure_json_loads,
                            )

                            key_data = secure_json_loads(json_content)
                        except (JSONSecurityError, JSONValidationError) as e:
                            eprint(f"Error: PQC key file validation failed: {e}")
                            sys.exit(1)
                        except ImportError:
                            # Fallback to basic JSON loading if validator not available
                            try:
                                key_data = json.loads(json_content)
                            except json.JSONDecodeError as e:
                                eprint(f"Error: Invalid JSON in PQC key file: {e}")
                                sys.exit(1)

                    if "public_key" in key_data and "private_key" in key_data:
                        public_key = base64.b64decode(key_data["public_key"])
                        encrypted_private_key = base64.b64decode(key_data["private_key"])

                        # Check if key is encrypted (will be for keys created after our fix)
                        if key_data.get("key_encrypted", False):
                            if not args.quiet:
                                eprint("Found encrypted private key in keyfile")

                            # Get password to decrypt the private key
                            keyfile_password = None
                            if "password" in locals() and password:
                                # Try the same password as for the file
                                keyfile_password = password
                            else:
                                # Ask for the keyfile password
                                keyfile_password = getpass.getpass(
                                    "Enter password to decrypt the private key in keyfile: "
                                ).encode()

                            # Import what we need to decrypt
                            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                            # Derive the wrapping key. New keyfiles carry a "key_kdf"
                            # Argon2id descriptor (gitlab#131 F16); legacy keyfiles
                            # have none and use the PBKDF2-SHA256 100k path inside
                            # _derive_pqc_keyfile_key.
                            try:
                                # key_salt is read INSIDE the try for the same
                                # reason key_kdf is: a keyfile marked
                                # key_encrypted but missing key_salt raised a
                                # bare KeyError past this handler and aborted
                                # with `Error: 'key_salt'` (gitlab#157 review).
                                key_salt = base64.b64decode(key_data["key_salt"])
                                # A malformed/tampered key_kdf raises ValueError;
                                # keep it inside the try so it surfaces as the
                                # graceful "Wrong password?" path, not a traceback.
                                encryption_key = _derive_pqc_keyfile_key(
                                    keyfile_password, key_salt, key_data.get("key_kdf")
                                )
                                # Format: nonce (12 bytes) + encrypted_key
                                nonce = encrypted_private_key[:12]
                                encrypted_key_data = encrypted_private_key[12:]

                                # Decrypt the private key with the password-derived key
                                aes_cipher = AESGCM(encryption_key)
                                private_key = aes_cipher.decrypt(nonce, encrypted_key_data, None)

                                if not args.quiet:
                                    eprint("Successfully decrypted private key from keyfile")
                            except Exception as e:
                                eprint(f"Error decrypting private key: {e}. Wrong password?")
                                eprint("Will proceed with only the public key.")
                                private_key = None
                        else:
                            # Legacy support for non-encrypted keys (created before our fix)
                            private_key = encrypted_private_key
                            if not args.quiet:
                                eprint("WARNING: Using legacy unencrypted private key from keyfile")

                        pqc_keypair = (
                            (public_key, private_key) if private_key else (public_key, None)
                        )

                        if not args.quiet:
                            eprint(f"Loaded post-quantum key pair from {args.pqc_keyfile}")
                elif args.pqc_gen_key:
                    # The mirror image, and newly reachable because this change
                    # exposes the flag: --pqc-gen-key with nowhere to save to
                    # matched no branch, generated an ephemeral key and saved
                    # nothing -- the same silent-ignore this issue exists to
                    # remove (gitlab#157).
                    from .crypt_errors import ValidationError

                    eprint("Error: --pqc-gen-key needs --pqc-keyfile to say where to save.")
                    raise ValidationError("--pqc-gen-key without --pqc-keyfile")
                elif args.pqc_keyfile:
                    # Named a path that does not exist, without --pqc-gen-key.
                    # Neither branch above ran and no error was raised, so the
                    # flag was silently ignored: the user asked for a keyfile,
                    # got an ephemeral key instead, and could never decrypt with
                    # the keyfile they thought they had made (gitlab#157).
                    from .crypt_errors import ValidationError

                    # eprint first: ValidationError is a SecureError, which
                    # replaces the message it is given with a generic
                    # "Security validation check failed" unless DEBUG=1 is set,
                    # so the instruction would otherwise reach test runs and
                    # nobody else.
                    eprint(
                        f"Error: --pqc-keyfile {sanitize_for_display(args.pqc_keyfile)} "
                        "does not exist."
                    )
                    eprint(
                        "  Pass --pqc-gen-key to generate and save a new key pair "
                        "there, or point --pqc-keyfile at an existing key file."
                    )
                    raise ValidationError("--pqc-keyfile does not exist")
                else:
                    # No keyfile specified - generate an ephemeral keypair for this encryption
                    from .pqc import PQCipher, check_pqc_support

                    # Map algorithm name to available algorithms
                    pqc_algorithms = check_pqc_support(quiet=args.quiet)[2]
                    kyber512_options = [
                        alg
                        for alg in pqc_algorithms
                        if alg.lower().replace("-", "").replace("_", "") in ["kyber512", "mlkem512"]
                    ]
                    kyber768_options = [
                        alg
                        for alg in pqc_algorithms
                        if alg.lower().replace("-", "").replace("_", "") in ["kyber768", "mlkem768"]
                    ]
                    kyber1024_options = [
                        alg
                        for alg in pqc_algorithms
                        if alg.lower().replace("-", "").replace("_", "")
                        in ["kyber1024", "mlkem1024"]
                    ]
                    hqc128_options = [
                        alg
                        for alg in pqc_algorithms
                        if alg.lower().replace("-", "").replace("_", "") in ["hqc128"]
                    ]
                    hqc192_options = [
                        alg
                        for alg in pqc_algorithms
                        if alg.lower().replace("-", "").replace("_", "") in ["hqc192"]
                    ]
                    hqc256_options = [
                        alg
                        for alg in pqc_algorithms
                        if alg.lower().replace("-", "").replace("_", "") in ["hqc256"]
                    ]

                    # Choose first available algorithm
                    algo_map = {
                        "kyber512-hybrid": (
                            kyber512_options[0] if kyber512_options else "Kyber512"
                        ),
                        "kyber768-hybrid": (
                            kyber768_options[0] if kyber768_options else "Kyber768"
                        ),
                        "kyber1024-hybrid": (
                            kyber1024_options[0] if kyber1024_options else "Kyber1024"
                        ),
                        "hqc-128-hybrid": (hqc128_options[0] if hqc128_options else "HQC-128"),
                        "hqc-192-hybrid": (hqc192_options[0] if hqc192_options else "HQC-192"),
                        "hqc-256-hybrid": (hqc256_options[0] if hqc256_options else "HQC-256"),
                        "ml-kem-512-hybrid": (
                            kyber512_options[0] if kyber512_options else "Kyber512"
                        ),
                        "ml-kem-768-hybrid": (
                            kyber768_options[0] if kyber768_options else "Kyber768"
                        ),
                        "ml-kem-1024-hybrid": (
                            kyber1024_options[0] if kyber1024_options else "Kyber1024"
                        ),
                        "ml-kem-512-chacha20": (
                            kyber512_options[0] if kyber512_options else "Kyber512"
                        ),
                        "ml-kem-768-chacha20": (
                            kyber768_options[0] if kyber768_options else "Kyber768"
                        ),
                        "ml-kem-1024-chacha20": (
                            kyber1024_options[0] if kyber1024_options else "Kyber1024"
                        ),
                    }

                    # Generate a new ephemeral keypair
                    if not args.quiet:
                        eprint(f"Generating ephemeral post-quantum key pair for {args.algorithm}")
                        if args.pqc_store_key:
                            # Only log this message with INFO level so it only appears in verbose mode
                            logger.info(
                                "Private key will be stored in the encrypted file for self-decryption"
                            )
                        else:
                            # Keep this as a print since it's a warning
                            eprint(
                                "WARNING: Private key will NOT be stored - you must use a key file for decryption"
                            )

                    cipher = PQCipher(algo_map[args.algorithm], quiet=args.quiet)
                    public_key, private_key = cipher.generate_keypair()
                    pqc_keypair = (public_key, private_key)

            if args.overwrite:
                output_file = args.input
                # Create a temporary file for the encryption to enable atomic
                # replacement
                temp_dir = os.path.dirname(os.path.abspath(args.input))
                temp_suffix = f".{uuid.uuid4().hex[:12]}.tmp"
                temp_output = os.path.join(
                    temp_dir, f".{os.path.basename(args.input)}{temp_suffix}"
                )

                # Add to cleanup list in case process is interrupted
                temp_files_to_cleanup.append(temp_output)

                try:
                    # Get original file permissions before doing anything
                    original_permissions = get_file_permissions(args.input)
                    # pqc_keypair is deliberately NOT reset here: it is
                    # resolved once above, before this branch, so an
                    # --overwrite run uses the same keyfile the non-overwrite
                    # path would. A second copy of the keyfile logic used to
                    # live here and wrote `private_key` as bare base64 with no
                    # key_encrypted marker -- reintroduced by a
                    # file-reconstruction commit after the wrapping fix had
                    # landed, and missed by the later Argon2id upgrade, whose
                    # message says it touched "the one write site". Its loader
                    # read `private_key` unconditionally too, so given a
                    # properly wrapped keyfile it would have base64-decoded the
                    # AES-GCM ciphertext and used it as the key (gitlab#157).

                    # For PQC algorithms, we may need to generate a keypair if not specified
                    if (
                        args.algorithm
                        in [
                            "kyber512-hybrid",
                            "kyber768-hybrid",
                            "kyber1024-hybrid",
                            "hqc-128-hybrid",
                            "hqc-192-hybrid",
                            "hqc-256-hybrid",
                            "ml-kem-512-hybrid",
                            "ml-kem-768-hybrid",
                            "ml-kem-1024-hybrid",
                            "ml-kem-512-chacha20",
                            "ml-kem-768-chacha20",
                            "ml-kem-1024-chacha20",
                        ]
                        and not pqc_keypair
                    ):
                        # No keypair provided, generate an ephemeral one
                        from .pqc import PQCipher, check_pqc_support

                        # Map algorithm name to available algorithms
                        pqc_algorithms = check_pqc_support(quiet=args.quiet)[2]
                        kyber512_options = [
                            alg
                            for alg in pqc_algorithms
                            if alg.lower().replace("-", "").replace("_", "")
                            in ["kyber512", "mlkem512"]
                        ]
                        kyber768_options = [
                            alg
                            for alg in pqc_algorithms
                            if alg.lower().replace("-", "").replace("_", "")
                            in ["kyber768", "mlkem768"]
                        ]
                        kyber1024_options = [
                            alg
                            for alg in pqc_algorithms
                            if alg.lower().replace("-", "").replace("_", "")
                            in ["kyber1024", "mlkem1024"]
                        ]
                        hqc128_options = [
                            alg
                            for alg in pqc_algorithms
                            if alg.lower().replace("-", "").replace("_", "") in ["hqc128"]
                        ]
                        hqc192_options = [
                            alg
                            for alg in pqc_algorithms
                            if alg.lower().replace("-", "").replace("_", "") in ["hqc192"]
                        ]
                        hqc256_options = [
                            alg
                            for alg in pqc_algorithms
                            if alg.lower().replace("-", "").replace("_", "") in ["hqc256"]
                        ]

                        # Choose first available algorithm
                        algo_map = {
                            "kyber512-hybrid": (
                                kyber512_options[0] if kyber512_options else "Kyber512"
                            ),
                            "kyber768-hybrid": (
                                kyber768_options[0] if kyber768_options else "Kyber768"
                            ),
                            "kyber1024-hybrid": (
                                kyber1024_options[0] if kyber1024_options else "Kyber1024"
                            ),
                            "hqc-128-hybrid": (hqc128_options[0] if hqc128_options else "HQC-128"),
                            "hqc-192-hybrid": (hqc192_options[0] if hqc192_options else "HQC-192"),
                            "hqc-256-hybrid": (hqc256_options[0] if hqc256_options else "HQC-256"),
                            "ml-kem-512-hybrid": (
                                kyber512_options[0] if kyber512_options else "Kyber512"
                            ),
                            "ml-kem-768-hybrid": (
                                kyber768_options[0] if kyber768_options else "Kyber768"
                            ),
                            "ml-kem-1024-hybrid": (
                                kyber1024_options[0] if kyber1024_options else "Kyber1024"
                            ),
                            "ml-kem-512-chacha20": (
                                kyber512_options[0] if kyber512_options else "Kyber512"
                            ),
                            "ml-kem-768-chacha20": (
                                kyber768_options[0] if kyber768_options else "Kyber768"
                            ),
                            "ml-kem-1024-chacha20": (
                                kyber1024_options[0] if kyber1024_options else "Kyber1024"
                            ),
                        }

                        if not args.quiet:
                            eprint(
                                f"Generating ephemeral post-quantum key pair for {args.algorithm}"
                            )
                            if args.pqc_store_key:
                                # Only log this message with INFO level so it only appears in verbose mode
                                logger.info(
                                    "Private key will be stored in the encrypted file for self-decryption"
                                )
                            else:
                                # Keep this as a print since it's a warning
                                eprint(
                                    "WARNING: Private key will NOT be stored - you must use a key file for decryption"
                                )

                        cipher = PQCipher(algo_map[args.algorithm], quiet=args.quiet)
                        public_key, private_key = cipher.generate_keypair()
                        pqc_keypair = (public_key, private_key)

                    # Check if we should use keystore integration
                    if hasattr(args, "keystore") and args.keystore:
                        # First, check if the keystore exists
                        if not os.path.exists(args.keystore):
                            # Keystore doesn't exist
                            create_new = False
                            if getattr(args, "auto_create_keystore", False):
                                # Auto-create keystore is enabled
                                if not args.quiet:
                                    eprint(
                                        f"Keystore not found at {args.keystore}, creating a new one"
                                    )
                                create_new = True
                            else:
                                # Prompt the user if they want to create a new keystore or abort
                                if not args.quiet:
                                    eprint(f"Keystore not found at {args.keystore}")
                                    eprint(
                                        "Use --auto-create-keystore option to automatically create keystore"
                                    )
                                    create_prompt = (
                                        prompt_and_read(
                                            "Would you like to create a new keystore? (y/n): "
                                        )
                                        .lower()
                                        .strip()
                                    )
                                    create_new = create_prompt.startswith("y")

                            if create_new:
                                # Create a new keystore
                                from .keystore_cli import KeystoreSecurityLevel, PQCKeystore

                                # Get keystore password
                                keystore_password = None
                                if hasattr(args, "keystore_password") and args.keystore_password:
                                    keystore_password = args.keystore_password
                                elif (
                                    hasattr(args, "keystore_password_file")
                                    and args.keystore_password_file
                                ):
                                    try:
                                        with open(args.keystore_password_file, "r") as f:
                                            keystore_password = f.read().strip()
                                    except Exception as e:
                                        if not args.quiet:
                                            eprint(
                                                f"Warning: Failed to read keystore password from file: {e}"
                                            )
                                            keystore_password = getpass.getpass(
                                                "Enter keystore password: "
                                            )
                                else:
                                    keystore_password = getpass.getpass(
                                        "Enter new keystore password: "
                                    )
                                    confirm = getpass.getpass("Confirm new keystore password: ")
                                    if keystore_password != confirm:
                                        if not args.quiet:
                                            eprint("Passwords do not match")
                                        raise ValueError("Keystore passwords do not match")

                                # Create the keystore
                                keystore = PQCKeystore(args.keystore)
                                keystore.create_keystore(
                                    keystore_password, KeystoreSecurityLevel.STANDARD
                                )
                                if not args.quiet:
                                    eprint(f"Created new keystore at {args.keystore}")
                            else:
                                # Abort
                                if not args.quiet:
                                    eprint(
                                        f"Encryption aborted: Keystore not found at {args.keystore}"
                                    )
                                return 1

                        # Get keystore password if needed
                        keystore_password = None
                        if hasattr(args, "keystore_password") and args.keystore_password:
                            keystore_password = args.keystore_password
                        elif (
                            hasattr(args, "keystore_password_file") and args.keystore_password_file
                        ):
                            try:
                                with open(args.keystore_password_file, "r") as f:
                                    keystore_password = f.read().strip()
                            except Exception as e:
                                if not args.quiet:
                                    eprint(
                                        f"Warning: Failed to read keystore password from file: {e}"
                                    )
                                    keystore_password = getpass.getpass("Enter keystore password: ")
                        else:
                            keystore_password = getpass.getpass("Enter keystore password: ")

                        # Check if we should auto-generate a key
                        key_id = getattr(args, "key_id", None)
                        # Always auto-generate a key if we're using a keystore with PQC algorithm
                        # and no key_id is provided, or explicitly requested with --auto-generate-key
                        if (key_id is None and args.algorithm.startswith("kyber")) or getattr(
                            args, "auto_generate_key", False
                        ):
                            # Set the auto_generate_key flag for the auto_generate_pqc_key function
                            if not hasattr(args, "auto_generate_key") or not args.auto_generate_key:
                                if not args.quiet:
                                    eprint("Auto-generating key for keystore")
                                setattr(args, "auto_generate_key", True)
                            # Auto-generate key
                            # This will update hash_config with key_id
                            auto_generate_pqc_key(args, hash_config)

                        # Encrypt using keystore integration
                        success = encrypt_file_with_keystore(
                            args.input,
                            temp_output,
                            password,
                            hash_config=hash_config,
                            pbkdf2_iterations=getattr(args, "pbkdf2_iterations", 0),
                            quiet=args.quiet,
                            algorithm=args.algorithm,
                            pqc_keypair=(pqc_keypair if "pqc_keypair" in locals() else None),
                            keystore_file=args.keystore,
                            keystore_password=keystore_password,
                            key_id=key_id,
                            dual_encryption=getattr(args, "dual_encrypt_key", False),
                            progress=args.progress,
                            verbose=args.verbose,
                            pqc_store_private_key=args.pqc_store_key,
                            pqc_dual_encryption=getattr(args, "pqc_dual_encrypt_key", False),
                            hidden_header=_hidden_for_encrypt(args, _hidden_second_password),
                            second_password=_hidden_second_password,
                        )
                    else:
                        # Handle cascade encryption parameters
                        cascade_mode = False
                        cipher_names = None
                        cascade_hash_func = "sha256"

                        if hasattr(args, "cascade") and args.cascade is not None:
                            from .crypt_cli_subparser import CASCADE_PRESETS

                            cascade_mode = True

                            # Import registry to check cipher availability
                            try:
                                from .registry import CipherRegistry

                                registry = CipherRegistry.default()
                            except ImportError:
                                if not args.quiet:
                                    eprint(
                                        "Error: Cipher registry not available for cascade mode",
                                        file=sys.stderr,
                                    )
                                return 1

                            # Determine cipher chain (preset or custom)
                            if args.cascade is True:
                                # Boolean flag: parse comma-separated algorithms from --algorithm
                                if "," in args.algorithm:
                                    cipher_names = [c.strip() for c in args.algorithm.split(",")]
                                else:
                                    if not args.quiet:
                                        eprint(
                                            "Error: --cascade requires comma-separated algorithms "
                                            "(e.g., --cascade --algorithm aes-256-gcm,chacha20-poly1305) "
                                            "or a preset (e.g., --cascade=standard)",
                                            file=sys.stderr,
                                        )
                                    return 1
                            elif args.cascade in CASCADE_PRESETS:
                                # Preset mode
                                cipher_names = CASCADE_PRESETS[args.cascade]
                                if not args.quiet:
                                    eprint(
                                        f"Using cascade preset '{args.cascade}': {' → '.join(cipher_names)}"
                                    )
                            else:
                                if not args.quiet:
                                    available_presets = ", ".join(CASCADE_PRESETS.keys())
                                    eprint(
                                        f"Error: Unknown cascade preset '{args.cascade}'. "
                                        f"Available: {available_presets}",
                                        file=sys.stderr,
                                    )
                                return 1

                            # Validate minimum 2 ciphers
                            if len(cipher_names) < 2:
                                if not args.quiet:
                                    eprint(
                                        "Error: Cascade mode requires at least 2 ciphers",
                                        file=sys.stderr,
                                    )
                                return 1

                            # Validate that all ciphers exist and are available
                            for cipher_name in cipher_names:
                                if not registry.exists(cipher_name):
                                    available = ", ".join(registry.list_names())
                                    if not args.quiet:
                                        eprint(
                                            f"Error: Unknown cipher '{cipher_name}'. "
                                            f"Available: {available}",
                                            file=sys.stderr,
                                        )
                                    return 1

                                if not registry.is_available(cipher_name):
                                    if not args.quiet:
                                        eprint(
                                            f"Error: Cipher '{cipher_name}' not available. "
                                            "Install required dependencies.",
                                            file=sys.stderr,
                                        )
                                    return 1

                            # Run diversity validation (if not disabled)
                            if not getattr(args, "no_diversity_check", False):
                                try:
                                    from .cascade_validator import (
                                        CascadeDiversityValidator,
                                        DiversityWarningLevel,
                                    )

                                    strict_mode = getattr(args, "strict_diversity", False)
                                    validator = CascadeDiversityValidator(strict=strict_mode)
                                    diversity_warnings = validator.validate(cipher_names)

                                    # Display warnings
                                    has_error = False
                                    has_warning = False

                                    for warning in diversity_warnings:
                                        if warning.level == DiversityWarningLevel.ERROR:
                                            has_error = True
                                            if not args.quiet:
                                                eprint(
                                                    f"\033[91mERROR:\033[0m {warning.message}",
                                                    file=sys.stderr,
                                                )
                                        elif warning.level == DiversityWarningLevel.WARNING:
                                            has_warning = True
                                            if not args.quiet:
                                                eprint(
                                                    f"\033[93mWARNING:\033[0m {warning.message}",
                                                    file=sys.stderr,
                                                )
                                        else:  # INFO
                                            if not args.quiet:
                                                eprint(
                                                    f"\033[94mINFO:\033[0m {warning.message}",
                                                    file=sys.stderr,
                                                )

                                        # Display suggestion if available
                                        if warning.suggestion and not args.quiet:
                                            eprint(
                                                f"  → {warning.suggestion}",
                                                file=sys.stderr,
                                            )

                                    # Abort if errors or strict mode with warnings
                                    if has_error or (strict_mode and has_warning):
                                        if not args.quiet:
                                            eprint(
                                                "\nCascade diversity validation failed. "
                                                "Use --no-diversity-check to bypass.",
                                                file=sys.stderr,
                                            )
                                        # Pre-encryption abort: the dispatch
                                        # finally announces the orphan (gitlab#223).
                                        return 1

                                except ImportError:
                                    # Validator not available, skip
                                    pass

                            # Get cascade hash function
                            if hasattr(args, "cascade_hash"):
                                cascade_hash_func = args.cascade_hash

                        # Use standard encryption
                        # Determine format version based on XOR composition flags
                        use_xor = getattr(args, "use_xor_composition", False)
                        use_independent_xor = getattr(args, "independent_xor", False)

                        # Check mutual exclusivity
                        if use_xor and use_independent_xor:
                            eprint(
                                "Error: Cannot use both --use-xor-composition and --independent-xor. "
                                "Choose one XOR mode.",
                                file=sys.stderr,
                            )
                            sys.exit(1)

                        if use_xor:
                            # Sequential XOR stays pinned at v13 (M2 decision 2026-07-10);
                            # v14+ is independent-XOR only.
                            format_version = 13
                        else:
                            # Default and --independent-xor: latest independent-XOR-only
                            # format (encrypt_file resolves None to it).
                            format_version = None

                        success = encrypt_file(
                            args.input,
                            temp_output,
                            password,
                            hash_config,
                            args.pbkdf2_iterations,
                            args.quiet,
                            algorithm="cascade" if cascade_mode else args.algorithm,
                            progress=args.progress,
                            verbose=args.verbose,
                            debug=args.debug,
                            pqc_keypair=(pqc_keypair if "pqc_keypair" in locals() else None),
                            pqc_store_private_key=args.pqc_store_key,
                            encryption_data=args.encryption_data,
                            enable_plugins=enable_plugins,
                            plugin_manager=plugin_manager,
                            hsm_plugin=hsm_plugin_instance,
                            cascade=cascade_mode,
                            cipher_names=cipher_names,
                            cascade_hash=cascade_hash_func,
                            integrity=getattr(args, "integrity", False),
                            pepper_plugin=pepper_plugin_instance,
                            pepper_name=pepper_name_to_use,
                            format_version=format_version,
                            xor_mode=("sequential" if use_xor else None),
                            parallel_kdf=getattr(args, "parallel_kdf", False),
                            kdf_workers=getattr(args, "kdf_workers", None),
                            chunk_size=_streaming_chunk_size,
                            no_streaming=getattr(args, "no_streaming", False),
                            streaming_threshold=_streaming_threshold,
                            envelope=getattr(args, "envelope", False),
                            hidden_header=_hidden_for_encrypt(args, _hidden_second_password),
                            second_password=_hidden_second_password,
                        )

                    if success:
                        # Apply the original permissions to the temp file
                        os.chmod(temp_output, original_permissions)

                        # Handle steganography if requested
                        if hasattr(args, "stego_hide") and args.stego_hide:
                            try:
                                # Get steganography plugin
                                stego_plugin = _get_steganography_plugin(quiet=args.quiet)
                                if stego_plugin:
                                    # Read encrypted data from temp file
                                    with open(temp_output, "rb") as f:
                                        encrypted_data = f.read()

                                    # Extract steganography options from args
                                    method = getattr(args, "stego_method", "lsb")
                                    bits_per_channel = getattr(args, "stego_bits_per_channel", 1)
                                    stego_password = getattr(args, "stego_password", None)

                                    options = {
                                        "randomize_pixels": getattr(
                                            args, "stego_randomize_pixels", False
                                        ),
                                        "decoy_data": getattr(args, "stego_decoy_data", False),
                                        "preserve_stats": True,
                                        "jpeg_quality": getattr(args, "jpeg_quality", 85),
                                    }

                                    # Hide data using plugin
                                    result = stego_plugin.hide_data(
                                        cover_path=args.stego_hide,
                                        data=encrypted_data,
                                        output_path=output_file,
                                        method=method,
                                        bits_per_channel=bits_per_channel,
                                        password=stego_password,
                                        **options,
                                    )

                                    if result.success:
                                        _ciphertext_on_disk = True
                                        if not args.quiet:
                                            eprint(
                                                f"Data successfully hidden in image: {output_file}"
                                            )
                                    else:
                                        eprint(f"Steganography error: {result.message}")
                                        # Stego failed: no usable encrypted output
                                        # survives; the dispatch finally announces
                                        # the orphan (gitlab#223).
                                        return 1
                                else:
                                    # Fallback to normal file output
                                    os.replace(temp_output, output_file)
                                    _ciphertext_on_disk = True
                            except Exception as e:
                                eprint(f"Steganography error: {e}")
                                # Stego failed: the dispatch finally announces
                                # the orphan (gitlab#223).
                                return 1
                        else:
                            # Normal file output
                            os.replace(temp_output, output_file)
                            _ciphertext_on_disk = True

                        # Successful operation means we don't need to clean up the temp file
                        temp_files_to_cleanup.remove(temp_output)
                    else:
                        # Clean up the temp file if it exists
                        if os.path.exists(temp_output):
                            os.remove(temp_output)
                            temp_files_to_cleanup.remove(temp_output)
                except Exception as e:
                    # Clean up the temp file in case of any error
                    if os.path.exists(temp_output):
                        os.remove(temp_output)
                        if temp_output in temp_files_to_cleanup:
                            temp_files_to_cleanup.remove(temp_output)
                    raise e
            elif not args.output:
                # Default output file name if not specified
                if args.input == "/dev/stdin":
                    # When input is stdin and no output specified, we'll output to stdout
                    # This will be handled in a separate code path below
                    output_file = None
                else:
                    # For regular files, append .encrypted extension
                    output_file = args.input + ".encrypted"
            else:
                if args.debug:
                    eprint(f"FLOW-DEBUG: Using normal output path: {args.output}")
                output_file = args.output

            # Handle stdout output for stdin input
            if output_file is None:
                # Encrypt stdin to stdout - create temporary output file first
                import tempfile

                with tempfile.NamedTemporaryFile(
                    mode="w+b", delete=False, suffix=".encrypted"
                ) as temp_file:
                    temp_output_file = temp_file.name

                # Handle cascade encryption parameters for stdout path
                cascade_mode = False
                cipher_names = None
                cascade_hash_func = "sha256"

                if hasattr(args, "cascade") and args.cascade is not None:
                    from .crypt_cli_subparser import CASCADE_PRESETS

                    cascade_mode = True

                    # Import registry to check cipher availability
                    try:
                        from .registry import CipherRegistry

                        registry = CipherRegistry.default()
                    except ImportError:
                        eprint(
                            "Error: Cipher registry not available for cascade mode",
                            file=sys.stderr,
                        )
                        sys.exit(1)

                    # Determine cipher chain (preset or custom)
                    if args.cascade is True:
                        # Boolean flag: parse comma-separated algorithms from --algorithm
                        if "," in args.algorithm:
                            cipher_names = [c.strip() for c in args.algorithm.split(",")]
                        else:
                            eprint(
                                "Error: --cascade requires comma-separated algorithms "
                                "(e.g., --cascade --algorithm aes-256-gcm,chacha20-poly1305) "
                                "or a preset (e.g., --cascade=standard)",
                                file=sys.stderr,
                            )
                            sys.exit(1)
                    elif args.cascade in CASCADE_PRESETS:
                        # Preset mode
                        cipher_names = CASCADE_PRESETS[args.cascade]
                    else:
                        available_presets = ", ".join(CASCADE_PRESETS.keys())
                        eprint(
                            f"Error: Unknown cascade preset '{args.cascade}'. "
                            f"Available: {available_presets}",
                            file=sys.stderr,
                        )
                        sys.exit(1)

                    # Validate minimum 2 ciphers
                    if len(cipher_names) < 2:
                        eprint(
                            "Error: Cascade mode requires at least 2 ciphers",
                            file=sys.stderr,
                        )
                        sys.exit(1)

                    # Validate that all ciphers exist and are available
                    for cipher_name in cipher_names:
                        if not registry.exists(cipher_name):
                            available = ", ".join(registry.list_names())
                            eprint(
                                f"Error: Unknown cipher '{cipher_name}'. "
                                f"Available: {available}",
                                file=sys.stderr,
                            )
                            sys.exit(1)

                        if not registry.is_available(cipher_name):
                            eprint(
                                f"Error: Cipher '{cipher_name}' not available. "
                                "Install required dependencies.",
                                file=sys.stderr,
                            )
                            sys.exit(1)

                    # Run diversity validation (if not disabled)
                    if not getattr(args, "no_diversity_check", False):
                        try:
                            from .cascade_validator import (
                                CascadeDiversityValidator,
                                DiversityWarningLevel,
                            )

                            strict_mode = getattr(args, "strict_diversity", False)
                            validator = CascadeDiversityValidator(strict=strict_mode)
                            diversity_warnings = validator.validate(cipher_names)

                            # Display warnings
                            has_error = False
                            has_warning = False

                            for warning in diversity_warnings:
                                if warning.level == DiversityWarningLevel.ERROR:
                                    has_error = True
                                    eprint(
                                        f"\033[91mERROR:\033[0m {warning.message}",
                                        file=sys.stderr,
                                    )
                                elif warning.level == DiversityWarningLevel.WARNING:
                                    has_warning = True
                                    eprint(
                                        f"\033[93mWARNING:\033[0m {warning.message}",
                                        file=sys.stderr,
                                    )
                                else:  # INFO
                                    eprint(
                                        f"\033[94mINFO:\033[0m {warning.message}",
                                        file=sys.stderr,
                                    )

                                # Display suggestion if available
                                if warning.suggestion:
                                    eprint(f"  → {warning.suggestion}", file=sys.stderr)

                            # Abort if errors or strict mode with warnings
                            if has_error or (strict_mode and has_warning):
                                eprint(
                                    "\nCascade diversity validation failed. "
                                    "Use --no-diversity-check to bypass.",
                                    file=sys.stderr,
                                )
                                sys.exit(1)

                        except ImportError:
                            # Validator not available, skip
                            pass

                    # Get cascade hash function
                    if hasattr(args, "cascade_hash"):
                        cascade_hash_func = args.cascade_hash

                # Use standard encryption to temporary file
                # Determine format version based on XOR composition flags
                use_xor = getattr(args, "use_xor_composition", False)
                use_independent_xor = getattr(args, "independent_xor", False)

                # Check mutual exclusivity
                if use_xor and use_independent_xor:
                    eprint(
                        "Error: Cannot use both --use-xor-composition and --independent-xor. "
                        "Choose one XOR mode.",
                        file=sys.stderr,
                    )
                    sys.exit(1)

                if use_xor:
                    # Sequential XOR stays pinned at v13 (M2 decision 2026-07-10);
                    # v14+ is independent-XOR only.
                    format_version = 13
                else:
                    # Default and --independent-xor: latest independent-XOR-only
                    # format (encrypt_file resolves None to it).
                    format_version = None

                success = encrypt_file(
                    args.input,
                    temp_output_file,
                    password,
                    hash_config,
                    args.pbkdf2_iterations,
                    quiet=True,  # Suppress normal output for stdout
                    algorithm="cascade" if cascade_mode else args.algorithm,
                    progress=False,  # No progress bar for stdout
                    verbose=False,  # No verbose output for stdout
                    debug=args.debug,
                    encryption_data=args.encryption_data,
                    enable_plugins=enable_plugins,
                    plugin_manager=plugin_manager,
                    hsm_plugin=hsm_plugin_instance,
                    cascade=cascade_mode,
                    cipher_names=cipher_names,
                    cascade_hash=cascade_hash_func,
                    integrity=getattr(args, "integrity", False),
                    pepper_plugin=pepper_plugin_instance,
                    pepper_name=pepper_name_to_use,
                    format_version=format_version,
                    xor_mode=("sequential" if use_xor else None),
                    chunk_size=_streaming_chunk_size,
                    no_streaming=getattr(args, "no_streaming", False),
                    streaming_threshold=_streaming_threshold,
                    envelope=getattr(args, "envelope", False),
                    hidden_header=_hidden_for_encrypt(args, _hidden_second_password),
                    second_password=_hidden_second_password,
                )

                if success:
                    # Output the encrypted content to stdout
                    try:
                        with open(temp_output_file, "rb") as f:
                            encrypted_stdout_bytes = f.read()
                        # Feature #2: armor the stream when requested so it is
                        # safe to pipe into clipboards, chat or email.
                        if getattr(args, "armor", False):
                            from .armor import armor as _armor_bytes

                            encrypted_stdout_bytes = _armor_bytes(encrypted_stdout_bytes)
                        sys.stdout.buffer.write(encrypted_stdout_bytes)
                        sys.stdout.buffer.flush()
                    except Exception as e:
                        if not args.quiet:
                            eprint(f"Error writing to stdout: {e}", file=sys.stderr)
                        success = False
                    finally:
                        # Clean up temporary file
                        try:
                            os.unlink(temp_output_file)
                        except OSError:
                            pass

                # Skip the normal encryption logic
                if success:
                    # Delivered to stdout: the run is complete and the
                    # password file is the live credential for output the
                    # caller now holds (gitlab#223).
                    _encrypt_completed = True
                    return
                else:
                    sys.exit(1)

            # Direct encryption to output file (when not overwriting)
            if not args.overwrite:
                # Check if we should use keystore integration
                if hasattr(args, "keystore") and args.keystore:
                    # First, check if the keystore exists
                    if not os.path.exists(args.keystore):
                        # Keystore doesn't exist
                        create_new = False
                        if getattr(args, "auto_create_keystore", False):
                            # Auto-create keystore is enabled
                            if not args.quiet:
                                eprint(f"Keystore not found at {args.keystore}, creating a new one")
                            create_new = True
                        else:
                            # Prompt the user if they want to create a new keystore or abort
                            if not args.quiet:
                                eprint(f"Keystore not found at {args.keystore}")
                                eprint(
                                    "Use --auto-create-keystore option to automatically create keystore"
                                )
                                create_prompt = (
                                    prompt_and_read(
                                        "Would you like to create a new keystore? (y/n): "
                                    )
                                    .lower()
                                    .strip()
                                )
                                create_new = create_prompt.startswith("y")

                        if create_new:
                            # Create a new keystore
                            from .keystore_cli import KeystoreSecurityLevel, PQCKeystore

                            # Get keystore password
                            keystore_password = None
                            if hasattr(args, "keystore_password") and args.keystore_password:
                                keystore_password = args.keystore_password
                            elif (
                                hasattr(args, "keystore_password_file")
                                and args.keystore_password_file
                            ):
                                try:
                                    with open(args.keystore_password_file, "r") as f:
                                        keystore_password = f.read().strip()
                                except Exception as e:
                                    if not args.quiet:
                                        eprint(
                                            f"Warning: Failed to read keystore password from file: {e}"
                                        )
                                        keystore_password = getpass.getpass(
                                            "Enter keystore password: "
                                        )
                            else:
                                keystore_password = getpass.getpass("Enter new keystore password: ")
                                confirm = getpass.getpass("Confirm new keystore password: ")
                                if keystore_password != confirm:
                                    if not args.quiet:
                                        eprint("Passwords do not match")
                                    raise ValueError("Keystore passwords do not match")

                            # Create the keystore
                            keystore = PQCKeystore(args.keystore)
                            keystore.create_keystore(
                                keystore_password, KeystoreSecurityLevel.STANDARD
                            )
                            if not args.quiet:
                                eprint(f"Created new keystore at {args.keystore}")
                        else:
                            # Abort
                            if not args.quiet:
                                eprint(f"Encryption aborted: Keystore not found at {args.keystore}")
                            return 1

                    # Get keystore password if needed
                    keystore_password = None
                    if hasattr(args, "keystore_password") and args.keystore_password:
                        keystore_password = args.keystore_password
                    elif hasattr(args, "keystore_password_file") and args.keystore_password_file:
                        try:
                            with open(args.keystore_password_file, "r") as f:
                                keystore_password = f.read().strip()
                        except Exception as e:
                            if not args.quiet:
                                eprint(f"Warning: Failed to read keystore password from file: {e}")
                                keystore_password = getpass.getpass("Enter keystore password: ")
                    else:
                        keystore_password = getpass.getpass("Enter keystore password: ")

                    # Check if we should auto-generate a key
                    key_id = getattr(args, "key_id", None)
                    # Always auto-generate a key if we're using a keystore with PQC algorithm
                    # and no key_id is provided, or explicitly requested with --auto-generate-key
                    if (key_id is None and args.algorithm.startswith("kyber")) or getattr(
                        args, "auto_generate_key", False
                    ):
                        # Set the auto_generate_key flag for the auto_generate_pqc_key function
                        if not hasattr(args, "auto_generate_key") or not args.auto_generate_key:
                            if not args.quiet:
                                eprint("Auto-generating key for keystore")
                            setattr(args, "auto_generate_key", True)
                        # Auto-generate key
                        # This will update hash_config with key_id
                        auto_generate_pqc_key(args, hash_config)

                    # Encrypt using keystore integration
                    success = encrypt_file_with_keystore(
                        args.input,
                        output_file,
                        password,
                        hash_config=hash_config,
                        pbkdf2_iterations=args.pbkdf2_iterations,
                        quiet=args.quiet,
                        algorithm=args.algorithm,
                        pqc_keypair=pqc_keypair if "pqc_keypair" in locals() else None,
                        keystore_file=args.keystore,
                        keystore_password=keystore_password,
                        key_id=key_id,
                        dual_encryption=getattr(args, "dual_encrypt_key", False),
                        progress=args.progress,
                        verbose=args.verbose,
                        pqc_store_private_key=args.pqc_store_key,
                        hidden_header=_hidden_for_encrypt(args, _hidden_second_password),
                        second_password=_hidden_second_password,
                    )
                else:
                    # Handle cascade encryption parameters
                    cascade_mode = False
                    cipher_names = None
                    cascade_hash_func = "sha256"

                    if hasattr(args, "cascade") and args.cascade is not None:
                        from .crypt_cli_subparser import CASCADE_PRESETS

                        cascade_mode = True

                        # Import registry to check cipher availability
                        try:
                            from .registry import CipherRegistry

                            registry = CipherRegistry.default()
                        except ImportError:
                            if not args.quiet:
                                eprint(
                                    "Error: Cipher registry not available for cascade mode",
                                    file=sys.stderr,
                                )
                            return 1

                        # Determine cipher chain (preset or custom)
                        if args.cascade is True:
                            # Boolean flag: parse comma-separated algorithms from --algorithm
                            if "," in args.algorithm:
                                cipher_names = [c.strip() for c in args.algorithm.split(",")]
                            else:
                                if not args.quiet:
                                    eprint(
                                        "Error: --cascade requires comma-separated algorithms "
                                        "(e.g., --cascade --algorithm aes-256-gcm,chacha20-poly1305) "
                                        "or a preset (e.g., --cascade=standard)",
                                        file=sys.stderr,
                                    )
                                return 1
                        elif args.cascade in CASCADE_PRESETS:
                            # Preset mode
                            cipher_names = CASCADE_PRESETS[args.cascade]
                            if not args.quiet:
                                eprint(
                                    f"Using cascade preset '{args.cascade}': {' → '.join(cipher_names)}"
                                )
                        else:
                            if not args.quiet:
                                available_presets = ", ".join(CASCADE_PRESETS.keys())
                                eprint(
                                    f"Error: Unknown cascade preset '{args.cascade}'. "
                                    f"Available: {available_presets}",
                                    file=sys.stderr,
                                )
                            return 1

                        # Validate minimum 2 ciphers
                        if len(cipher_names) < 2:
                            if not args.quiet:
                                eprint(
                                    "Error: Cascade mode requires at least 2 ciphers",
                                    file=sys.stderr,
                                )
                            return 1

                        # Validate that all ciphers exist and are available
                        for cipher_name in cipher_names:
                            if not registry.exists(cipher_name):
                                available = ", ".join(registry.list_names())
                                if not args.quiet:
                                    eprint(
                                        f"Error: Unknown cipher '{cipher_name}'. "
                                        f"Available: {available}",
                                        file=sys.stderr,
                                    )
                                return 1

                            if not registry.is_available(cipher_name):
                                if not args.quiet:
                                    eprint(
                                        f"Error: Cipher '{cipher_name}' not available. "
                                        "Install required dependencies.",
                                        file=sys.stderr,
                                    )
                                return 1

                        # Run diversity validation (if not disabled)
                        if not getattr(args, "no_diversity_check", False):
                            try:
                                from .cascade_validator import (
                                    CascadeDiversityValidator,
                                    DiversityWarningLevel,
                                )

                                strict_mode = getattr(args, "strict_diversity", False)
                                validator = CascadeDiversityValidator(strict=strict_mode)
                                diversity_warnings = validator.validate(cipher_names)

                                # Display warnings
                                has_error = False
                                has_warning = False

                                for warning in diversity_warnings:
                                    if warning.level == DiversityWarningLevel.ERROR:
                                        has_error = True
                                        if not args.quiet:
                                            eprint(
                                                f"\033[91mERROR:\033[0m {warning.message}",
                                                file=sys.stderr,
                                            )
                                    elif warning.level == DiversityWarningLevel.WARNING:
                                        has_warning = True
                                        if not args.quiet:
                                            eprint(
                                                f"\033[93mWARNING:\033[0m {warning.message}",
                                                file=sys.stderr,
                                            )
                                    else:  # INFO
                                        if not args.quiet:
                                            eprint(
                                                f"\033[94mINFO:\033[0m {warning.message}",
                                                file=sys.stderr,
                                            )

                                    # Display suggestion if available
                                    if warning.suggestion and not args.quiet:
                                        eprint(f"  → {warning.suggestion}", file=sys.stderr)

                                # Abort if errors or strict mode with warnings
                                if has_error or (strict_mode and has_warning):
                                    if not args.quiet:
                                        eprint(
                                            "\nCascade diversity validation failed. "
                                            "Use --no-diversity-check to bypass.",
                                            file=sys.stderr,
                                        )
                                    return 1

                            except ImportError:
                                # Validator not available, skip
                                pass

                        # Get cascade hash function
                        if hasattr(args, "cascade_hash"):
                            cascade_hash_func = args.cascade_hash

                    # Use standard encryption
                    # Determine format version based on XOR composition flags
                    use_xor = getattr(args, "use_xor_composition", False)
                    use_independent_xor = getattr(args, "independent_xor", False)

                    # Check mutual exclusivity
                    if use_xor and use_independent_xor:
                        eprint(
                            "Error: Cannot use both --use-xor-composition and --independent-xor. "
                            "Choose one XOR mode.",
                            file=sys.stderr,
                        )
                        sys.exit(1)

                    if use_xor:
                        # Sequential XOR stays pinned at v13 (M2 decision 2026-07-10);
                        # v14+ is independent-XOR only.
                        format_version = 13
                    else:
                        # Default and --independent-xor: latest independent-XOR-only
                        # format (encrypt_file resolves None to it).
                        format_version = None

                    success = encrypt_file(
                        args.input,
                        output_file,
                        password,
                        hash_config,
                        args.pbkdf2_iterations,
                        args.quiet,
                        algorithm="cascade" if cascade_mode else args.algorithm,
                        progress=args.progress,
                        verbose=args.verbose,
                        debug=args.debug,
                        pqc_keypair=pqc_keypair if "pqc_keypair" in locals() else None,
                        pqc_store_private_key=args.pqc_store_key,
                        encryption_data=args.encryption_data,
                        enable_plugins=enable_plugins,
                        plugin_manager=plugin_manager,
                        hsm_plugin=hsm_plugin_instance,
                        cascade=cascade_mode,
                        cipher_names=cipher_names,
                        cascade_hash=cascade_hash_func,
                        integrity=getattr(args, "integrity", False),
                        pepper_plugin=pepper_plugin_instance,
                        pepper_name=pepper_name_to_use,
                        format_version=format_version,
                        xor_mode=("sequential" if use_xor else None),
                        chunk_size=_streaming_chunk_size,
                        no_streaming=getattr(args, "no_streaming", False),
                        streaming_threshold=_streaming_threshold,
                        envelope=getattr(args, "envelope", False),
                        hidden_header=_hidden_for_encrypt(args, _hidden_second_password),
                        second_password=_hidden_second_password,
                    )

                if success:
                    # A usable ciphertext already sits at output_file (the
                    # non-overwrite branch writes it directly); a stego or
                    # armor post-processing failure below must not claim
                    # otherwise (gitlab#223 review f1).
                    _ciphertext_on_disk = True

                # Handle steganography if requested
                if success and hasattr(args, "stego_hide") and args.stego_hide:
                    try:
                        # Get steganography plugin
                        stego_plugin = _get_steganography_plugin(quiet=args.quiet)
                        if stego_plugin:
                            # Read encrypted data from output file
                            with open(output_file, "rb") as f:
                                encrypted_data = f.read()

                            # Extract steganography options from args
                            method = getattr(args, "stego_method", "lsb")
                            bits_per_channel = getattr(args, "stego_bits_per_channel", 1)
                            stego_password = getattr(args, "stego_password", None)

                            options = {
                                "randomize_pixels": getattr(args, "stego_randomize_pixels", False),
                                "decoy_data": getattr(args, "stego_decoy_data", False),
                                "preserve_stats": True,
                                "jpeg_quality": getattr(args, "jpeg_quality", 85),
                            }

                            # Hide data using plugin
                            result = stego_plugin.hide_data(
                                cover_path=args.stego_hide,
                                data=encrypted_data,
                                output_path=output_file,
                                method=method,
                                bits_per_channel=bits_per_channel,
                                password=stego_password,
                                **options,
                            )

                            if result.success:
                                if not args.quiet:
                                    eprint(f"Data successfully hidden in image: {output_file}")
                            else:
                                eprint(f"Steganography error: {result.message}")
                                return 1
                    except Exception as e:
                        eprint(f"Steganography error: {e}")
                        return 1

            if success:
                # Feature #2: wrap the finished file in ASCII armor if requested.
                # Done as post-processing so it composes with every encryption
                # path (symmetric, keystore) and does not disturb the binary
                # format on disk before this point.
                if getattr(args, "armor", False) and output_file and os.path.isfile(output_file):
                    from .armor import armor_file

                    armor_file(output_file)

                # Security audit log for successful encryption
                if security_logger:
                    security_logger.log_event(
                        "encryption_completed",
                        "info",
                        {
                            "input_file": str(args.input),
                            "output_file": str(output_file),
                            "algorithm": (
                                args.algorithm.value
                                if hasattr(args.algorithm, "value")
                                else str(args.algorithm)
                            ),
                            "service": "cli",
                        },
                    )

                if not args.quiet:
                    # Skip leading newline for stdout/stderr to avoid blank line
                    prefix = "" if output_file in ("/dev/stdout", "/dev/stderr") else "\n"
                    eprint(f"{prefix}File encrypted successfully: {output_file}")

                    # The generated password was disclosed BEFORE the
                    # encryption ran (gitlab#152). Disclosing it here, as
                    # this code used to, meant any failure after the
                    # ciphertext was written left an encrypted file whose
                    # password had never been shown. The 10-second
                    # countdown and the screen-clear claim went with it:
                    # they repainted the visible screen and removed
                    # nothing from scrollback, a pipe, or a log.

                # If shredding was requested and encryption was successful
                if args.shred and not args.overwrite:
                    if not args.quiet:
                        eprint("Shredding the original file as requested...")
                    secure_shred_file(args.input, args.shred_passes, args.quiet)

                # Keep LAST in this block: post-processing above (armor
                # rewrite, audit log, shred) can still fail, and those
                # failures must reach the finally with completed unset so
                # the check-decryptability NOTE fires (gitlab#223 review f2).
                _encrypt_completed = True

        elif args.action == "info":
            # Display encrypted file metadata without decrypting
            try:
                from .crypt_core import print_file_info

                json_output = getattr(args, "json", False)
                print_file_info(
                    args.input,
                    json_output=json_output,
                    second_password=_hidden_second_password,
                )
                sys.exit(0)
            except ValueError as e:
                eprint(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

        elif args.action == "decrypt":
            # Check if asymmetric mode by reading metadata
            try:
                import base64
                import json

                with open(args.input, "rb") as f:
                    content = f.read()
                    # Check if it's the new format: base64(metadata):base64(data)
                    if b":" in content:
                        colon_pos = content.index(b":")
                        metadata_b64 = content[:colon_pos]
                        try:
                            metadata_json = base64.b64decode(metadata_b64)
                            metadata = json.loads(metadata_json)
                            format_version = metadata.get("format_version", 0)

                            if format_version == 7 and metadata.get("mode") == "asymmetric":
                                # Asymmetric decryption mode (new format)
                                from .crypt_core import decrypt_file_asymmetric
                                from .identity_cli import get_identity_store

                                store = get_identity_store(resolve_identity_store_path(args))

                                # Load recipient (decrypt with this identity)
                                # Note: key_identity should already be set by auto-detection
                                if not hasattr(args, "key_identity") or not args.key_identity:
                                    eprint(
                                        "ERROR: No matching identity found. This should not happen after auto-detection.",
                                        file=sys.stderr,
                                    )
                                    sys.exit(1)

                                # First load identity metadata to check protection level
                                recipient_metadata = store.get_by_name(
                                    args.key_identity, load_private_keys=False
                                )
                                if recipient_metadata is None:
                                    eprint(
                                        f"ERROR: Identity '{args.key_identity}' not found ❌",
                                        file=sys.stderr,
                                    )
                                    sys.exit(1)

                                # Determine if passphrase is needed
                                from .identity_protection import ProtectionLevel

                                recipient_passphrase = None
                                if (
                                    not recipient_metadata.protection
                                    or recipient_metadata.protection.level
                                    != ProtectionLevel.HSM_ONLY
                                ):
                                    recipient_passphrase = getpass.getpass(
                                        f"Passphrase for identity '{args.key_identity}': "
                                    )

                                # Clear passphrase prompt line immediately in quiet mode
                                if args.quiet and recipient_passphrase:
                                    sys.stderr.write("\033[F\033[K")
                                    sys.stderr.flush()

                                try:
                                    recipient = store.get_by_name(
                                        args.key_identity,
                                        passphrase=recipient_passphrase,
                                        load_private_keys=True,
                                    )
                                    if recipient is None:
                                        eprint(
                                            f"ERROR: Identity '{args.key_identity}' not found ❌",
                                            file=sys.stderr,
                                        )
                                        sys.exit(1)
                                except Exception as e:
                                    error_msg = (
                                        f"ERROR: Failed to load identity '{args.key_identity}'"
                                    )
                                    if str(e):
                                        error_msg += f": {e}"
                                    error_msg += " ❌"
                                    eprint(error_msg, file=sys.stderr)
                                    sys.exit(1)
                                finally:
                                    # Clean up passphrase from memory
                                    if "recipient_passphrase" in locals() and recipient_passphrase:
                                        from .secure_memory import secure_memzero

                                        secure_memzero(recipient_passphrase)

                                # Load sender public key for verification
                                sender_public_key = None
                                skip_verification = getattr(args, "skip_verification", False)

                                if not skip_verification:
                                    if hasattr(args, "verify_from") and args.verify_from:
                                        sender = store.get_by_name(
                                            args.verify_from,
                                            passphrase=None,
                                            load_private_keys=False,
                                        )
                                        if sender is None:
                                            eprint(
                                                f"ERROR: Sender identity '{args.verify_from}' not found ❌",
                                                file=sys.stderr,
                                            )
                                            sys.exit(1)
                                        sender_public_key = sender.signing_public_key
                                    else:
                                        # Try to load sender from metadata
                                        sender_key_id = (
                                            metadata.get("asymmetric", {})
                                            .get("sender", {})
                                            .get("key_id")
                                        )
                                        if sender_key_id:
                                            sender = store.get_by_fingerprint(
                                                sender_key_id,
                                                passphrase=None,
                                                load_private_keys=False,
                                            )
                                            if sender:
                                                sender_public_key = sender.signing_public_key

                                # Determine output file
                                if args.overwrite:
                                    output_file = args.input
                                elif args.output:
                                    output_file = args.output
                                else:
                                    output_file = (
                                        args.input.rsplit(".", 1)[0]
                                        if "." in args.input
                                        else args.input + ".dec"
                                    )

                                # Decrypt
                                try:
                                    plaintext = decrypt_file_asymmetric(
                                        input_file=args.input,
                                        output_file=output_file,
                                        recipient=recipient,
                                        sender_public_key=sender_public_key,
                                        skip_verification=skip_verification,
                                        quiet=args.quiet,
                                        progress=args.progress,
                                        verbose=args.verbose,
                                        hidden_header=_hidden_for_decrypt(args),
                                        second_password=_hidden_second_password,
                                        allow_high_kdf_cost=getattr(
                                            args, "allow_high_kdf_cost", False
                                        ),
                                    )

                                    try:
                                        if not args.quiet:
                                            eprint("\nAsymmetric decryption successful! ✅")
                                            # Show decrypted content as last line with blank line before
                                            eprint()
                                            print(plaintext.decode("utf-8", errors="replace"))
                                        else:
                                            # In quiet mode, show only decrypted content
                                            print(plaintext.decode("utf-8", errors="replace"))

                                        # Shred original if requested
                                        if args.shred:
                                            secure_shred_file(
                                                args.input,
                                                args.shred_passes,
                                                args.quiet,
                                            )
                                    finally:
                                        # Clean up plaintext from memory
                                        from .secure_memory import secure_memzero

                                        secure_memzero(plaintext)

                                    sys.exit(0)
                                except Exception as e:
                                    eprint(
                                        f"ERROR: Asymmetric decryption failed: {e}",
                                        file=sys.stderr,
                                    )
                                    sys.exit(1)
                        except Exception:
                            # Not asymmetric format, continue with normal decryption
                            pass
                    # Also check old format for backward compatibility (deprecated)
                    elif b"---ENCRYPTED_DATA---" in content:
                        content_str = content.decode("utf-8", errors="ignore")
                        metadata_str = content_str.split("---ENCRYPTED_DATA---")[0]
                        metadata = json.loads(metadata_str)
                        format_version = metadata.get("format_version", 0)

                        if format_version == 7 and metadata.get("mode") == "asymmetric":
                            # Asymmetric decryption mode (old format)
                            from .crypt_core import decrypt_file_asymmetric
                            from .identity_cli import get_identity_store

                            store = get_identity_store(resolve_identity_store_path(args))

                            # Load recipient (decrypt with this identity)
                            # Note: key_identity should already be set by auto-detection
                            if not hasattr(args, "key_identity") or not args.key_identity:
                                eprint(
                                    "ERROR: No matching identity found. This should not happen after auto-detection.",
                                    file=sys.stderr,
                                )
                                sys.exit(1)

                            # First load identity metadata to check protection level
                            recipient_metadata = store.get_by_name(
                                args.key_identity, load_private_keys=False
                            )
                            if recipient_metadata is None:
                                eprint(
                                    f"ERROR: Identity '{args.key_identity}' not found ❌",
                                    file=sys.stderr,
                                )
                                sys.exit(1)

                            # Determine if passphrase is needed
                            from .identity_protection import ProtectionLevel

                            recipient_passphrase = None
                            if (
                                not recipient_metadata.protection
                                or recipient_metadata.protection.level != ProtectionLevel.HSM_ONLY
                            ):
                                recipient_passphrase = getpass.getpass(
                                    f"Passphrase for identity '{args.key_identity}': "
                                )

                            # Clear passphrase prompt line immediately in quiet mode
                            if args.quiet and recipient_passphrase:
                                sys.stderr.write("\033[F\033[K")
                                sys.stderr.flush()

                            try:
                                recipient = store.get_by_name(
                                    args.key_identity,
                                    passphrase=recipient_passphrase,
                                    load_private_keys=True,
                                )
                                if recipient is None:
                                    eprint(
                                        f"ERROR: Identity '{args.key_identity}' not found ❌",
                                        file=sys.stderr,
                                    )
                                    sys.exit(1)
                            except Exception as e:
                                error_msg = f"ERROR: Failed to load identity '{args.key_identity}'"
                                if str(e):
                                    error_msg += f": {e}"
                                error_msg += " ❌"
                                eprint(error_msg, file=sys.stderr)
                                sys.exit(1)
                            finally:
                                # Clean up passphrase from memory
                                if "recipient_passphrase" in locals() and recipient_passphrase:
                                    from .secure_memory import secure_memzero

                                    secure_memzero(recipient_passphrase)

                            # Load sender public key for verification
                            sender_public_key = None
                            skip_verification = getattr(args, "skip_verification", False)

                            if not skip_verification:
                                if hasattr(args, "verify_from") and args.verify_from:
                                    sender = store.get_by_name(
                                        args.verify_from,
                                        passphrase=None,
                                        load_private_keys=False,
                                    )
                                    if sender is None:
                                        eprint(
                                            f"ERROR: Sender identity '{args.verify_from}' not found ❌",
                                            file=sys.stderr,
                                        )
                                        sys.exit(1)
                                    sender_public_key = sender.signing_public_key
                                else:
                                    # Try to load sender from metadata
                                    sender_key_id = (
                                        metadata.get("asymmetric", {})
                                        .get("sender", {})
                                        .get("key_id")
                                    )
                                    if sender_key_id:
                                        sender = store.get_by_fingerprint(
                                            sender_key_id,
                                            passphrase=None,
                                            load_private_keys=False,
                                        )
                                        if sender:
                                            sender_public_key = sender.signing_public_key
                                        else:
                                            eprint(
                                                f"WARNING: Sender with fingerprint {sender_key_id} not found in store",
                                                file=sys.stderr,
                                            )
                                            eprint(
                                                "Use --verify-from to specify sender or --no-verify to skip verification",
                                                file=sys.stderr,
                                            )
                                            sys.exit(1)

                            # Determine output file
                            if args.overwrite:
                                output_file = args.input
                                temp_dir = os.path.dirname(os.path.abspath(args.input))
                                temp_suffix = f".{__import__('uuid').uuid4().hex[:12]}.tmp"
                                temp_output = os.path.join(
                                    temp_dir, os.path.basename(args.input) + temp_suffix
                                )
                            elif args.output:
                                output_file = args.output
                                temp_output = output_file
                            else:
                                # Remove .enc extension if present
                                if args.input.endswith(".enc"):
                                    output_file = args.input[:-4]
                                else:
                                    output_file = args.input + ".dec"
                                temp_output = output_file

                            # Decrypt
                            try:
                                plaintext = decrypt_file_asymmetric(
                                    input_file=args.input,
                                    output_file=temp_output,
                                    recipient=recipient,
                                    sender_public_key=sender_public_key,
                                    skip_verification=skip_verification,
                                    quiet=args.quiet,
                                    progress=args.progress,
                                    verbose=args.verbose,
                                    hidden_header=_hidden_for_decrypt(args),
                                    second_password=_hidden_second_password,
                                    allow_high_kdf_cost=getattr(args, "allow_high_kdf_cost", False),
                                )

                                # Handle temp file if overwrite mode
                                if args.overwrite and temp_output != output_file:
                                    import shutil

                                    shutil.move(temp_output, output_file)

                                try:
                                    if not args.quiet:
                                        eprint("\nAsymmetric decryption successful! ✅")
                                        # Show decrypted content as last line with blank line before
                                        eprint()
                                        print(plaintext.decode("utf-8", errors="replace"))
                                    else:
                                        # In quiet mode, show only decrypted content
                                        print(plaintext.decode("utf-8", errors="replace"))

                                    # Shred original if requested
                                    if args.shred:
                                        from .crypt_utils import shred_file

                                        shred_file(args.input, passes=args.shred_passes)
                                finally:
                                    # Clean up plaintext from memory
                                    from .secure_memory import secure_memzero

                                    secure_memzero(plaintext)

                                sys.exit(0)

                            except Exception as e:
                                eprint(
                                    f"ERROR: Asymmetric decryption failed: {e}",
                                    file=sys.stderr,
                                )
                                if args.debug:
                                    import traceback

                                    traceback.print_exc()
                                sys.exit(1)

            except (json.JSONDecodeError, FileNotFoundError, KeyError):
                # Not asymmetric or can't read metadata - continue with symmetric decryption
                pass

            # Extract metadata early to check for deprecated algorithms
            stdin_temp_file = None
            if args.input == "/dev/stdin":
                # Use precise metadata extraction for stdin
                try:
                    extractor = StdinMetadataExtractor(sys.stdin.buffer)
                    file_metadata, stdin_stream = extractor.extract_metadata_and_create_stream()
                    algorithm = file_metadata["algorithm"]
                    encryption_data = file_metadata.get("encryption_data", "aes-gcm")

                    # Check and warn about deprecated algorithms for stdin
                    if is_deprecated(algorithm):
                        replacement = get_recommended_replacement(algorithm)
                        warn_deprecated_algorithm(algorithm, "stdin decryption")
                        if (
                            not args.quiet
                            and replacement
                            and (args.verbose or not algorithm.startswith(("kyber", "ml-kem")))
                        ):
                            eprint(
                                f"Warning: The algorithm '{algorithm}' used in this file is deprecated."
                            )
                            eprint(
                                f"Consider re-encrypting with '{replacement}' for better security."
                            )

                    # Check if data encryption algorithm is deprecated for PQC
                    if algorithm.endswith("-hybrid") and is_deprecated(encryption_data):
                        data_replacement = get_recommended_replacement(encryption_data)
                        warn_deprecated_algorithm(encryption_data, "PQC stdin decryption")
                        if (
                            not args.quiet
                            and data_replacement
                            and (
                                args.verbose or not encryption_data.startswith(("kyber", "ml-kem"))
                            )
                        ):
                            eprint(
                                f"Warning: The data encryption algorithm '{encryption_data}' used in this file is deprecated."
                            )
                            eprint(
                                f"Consider re-encrypting with '{data_replacement}' for better security."
                            )

                    # Immediately convert reconstructed stream to temp file to avoid multiple reads
                    import tempfile

                    stdin_temp_file = tempfile.NamedTemporaryFile(delete=False)
                    os.chmod(
                        stdin_temp_file.name, 0o600
                    )  # Security: Restrict to user read/write only
                    temp_files_to_cleanup.append(stdin_temp_file.name)

                    # Copy all data from reconstructed stream to temp file
                    while True:
                        chunk = stdin_stream.read(8192)
                        if not chunk:
                            break
                        stdin_temp_file.write(chunk)
                    stdin_temp_file.close()

                    # Update args.input to point to the temp file
                    args.input = stdin_temp_file.name

                except Exception as e:
                    # If we can't extract metadata from stdin, continue with decryption
                    if args.verbose:
                        eprint(f"Warning: Could not check stdin for deprecated algorithms: {e}")
                    stdin_temp_file = None
            else:
                # Use file-based metadata extraction for regular files
                try:
                    file_metadata = extract_file_metadata(
                        args.input, second_password=_hidden_second_password
                    )
                    algorithm = file_metadata["algorithm"]
                    encryption_data = file_metadata.get("encryption_data", "aes-gcm")

                    # Check if main algorithm is deprecated and issue warning
                    if is_deprecated(algorithm):
                        replacement = get_recommended_replacement(algorithm)
                        warn_deprecated_algorithm(algorithm, "file decryption")
                        if (
                            not args.quiet
                            and replacement
                            and (args.verbose or not algorithm.startswith(("kyber", "ml-kem")))
                        ):
                            eprint(
                                f"Warning: The algorithm '{algorithm}' used in this file is deprecated."
                            )
                            eprint(
                                f"Consider re-encrypting with '{replacement}' for better security."
                            )

                    # Check if data encryption algorithm is deprecated for PQC
                    if algorithm.endswith("-hybrid") and is_deprecated(encryption_data):
                        data_replacement = get_recommended_replacement(encryption_data)
                        warn_deprecated_algorithm(encryption_data, "PQC data decryption")
                        if (
                            not args.quiet
                            and data_replacement
                            and (
                                args.verbose or not encryption_data.startswith(("kyber", "ml-kem"))
                            )
                        ):
                            eprint(
                                f"Warning: The data encryption algorithm '{encryption_data}' used in this file is deprecated."
                            )
                            eprint(
                                f"Consider re-encrypting with '{data_replacement}' for better security."
                            )
                except Exception as e:
                    # If we can't read metadata, continue with decryption (it will fail with proper error)
                    if args.verbose:
                        eprint(f"Warning: Could not check file for deprecated algorithms: {e}")
            if args.overwrite:
                output_file = args.input
                # Create a temporary file for the decryption
                temp_dir = os.path.dirname(os.path.abspath(args.input))
                temp_suffix = f".{uuid.uuid4().hex[:12]}.tmp"
                temp_output = os.path.join(
                    temp_dir, f".{os.path.basename(args.input)}{temp_suffix}"
                )

                # Add to cleanup list
                temp_files_to_cleanup.append(temp_output)

                try:
                    # Handle steganography extraction if requested
                    actual_input_file = args.input
                    temp_extracted_file = None

                    if hasattr(args, "stego_extract") and args.stego_extract:
                        try:
                            import tempfile

                            if not args.quiet:
                                eprint("Extracting encrypted data from steganographic image...")

                            # Get steganography plugin
                            stego_plugin = _get_steganography_plugin(quiet=args.quiet)
                            if stego_plugin:
                                # Extract steganography options from args
                                method = getattr(args, "stego_method", "lsb")
                                bits_per_channel = getattr(args, "stego_bits_per_channel", 1)
                                stego_password = getattr(args, "stego_password", None)

                                options = {
                                    "randomize_pixels": getattr(
                                        args, "stego_randomize_pixels", False
                                    ),
                                    "decoy_data": getattr(args, "stego_decoy_data", False),
                                    "preserve_stats": True,
                                    "jpeg_quality": getattr(args, "jpeg_quality", 85),
                                }

                                # Extract data using plugin
                                result = stego_plugin.extract_data(
                                    stego_path=args.input,
                                    method=method,
                                    bits_per_channel=bits_per_channel,
                                    password=stego_password,
                                    **options,
                                )

                                if result.success:
                                    encrypted_data = result.data.get("extracted_data", b"")

                                    # Create temporary file for extracted data
                                    with tempfile.NamedTemporaryFile(
                                        delete=False, suffix=".enc"
                                    ) as temp_file:
                                        temp_extracted_file = temp_file.name
                                        temp_file.write(encrypted_data)

                                    # Use extracted file as input for decryption
                                    actual_input_file = temp_extracted_file
                                    temp_files_to_cleanup.append(temp_extracted_file)

                                    if not args.quiet:
                                        eprint(f"Extracted {len(encrypted_data)} bytes from image")
                                else:
                                    eprint(f"Steganography extraction error: {result.message}")
                                    return 1
                        except Exception as e:
                            eprint(f"Steganography extraction error: {e}")
                            return 1

                    # Get original file permissions before doing anything
                    original_permissions = get_file_permissions(actual_input_file)

                    # Handle PQC key operations for decryption
                    pqc_private_key = None
                    if args.pqc_keyfile and os.path.exists(args.pqc_keyfile):
                        import base64
                        import json

                        try:
                            with open(args.pqc_keyfile, "r") as f:
                                # MED-8 Security fix: Use secure JSON validation for PQC key file loading
                                json_content = f.read()
                                try:
                                    from .json_validator import (
                                        JSONSecurityError,
                                        JSONValidationError,
                                        secure_json_loads,
                                    )

                                    key_data = secure_json_loads(json_content)
                                except (JSONSecurityError, JSONValidationError) as e:
                                    eprint(f"Error: PQC key file validation failed: {e}")
                                    sys.exit(1)
                                except ImportError:
                                    # Fallback to basic JSON loading if validator not available
                                    try:
                                        key_data = json.loads(json_content)
                                    except json.JSONDecodeError as e:
                                        eprint(f"Error: Invalid JSON in PQC key file: {e}")
                                        sys.exit(1)

                            if "private_key" in key_data:
                                encrypted_private_key = base64.b64decode(key_data["private_key"])

                                # Check if key is encrypted (will be for keys created after our fix)
                                if key_data.get("key_encrypted", False):
                                    if not args.quiet:
                                        eprint("Found encrypted private key in keyfile")

                                    # Get password to decrypt the private key
                                    keyfile_password = None
                                    if "password" in locals() and password:
                                        # Try the same password as for the file
                                        keyfile_password = password
                                    else:
                                        # Ask for the keyfile password
                                        keyfile_password = getpass.getpass(
                                            "Enter password to decrypt the private key in keyfile: "
                                        ).encode()

                                    # Import what we need to decrypt
                                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                                    # Derive the wrapping key. New keyfiles carry a
                                    # "key_kdf" Argon2id descriptor (gitlab#131 F16);
                                    # legacy keyfiles have none and use the
                                    # PBKDF2-SHA256 100k path inside
                                    # _derive_pqc_keyfile_key.
                                    key_salt = base64.b64decode(key_data["key_salt"])

                                    try:
                                        # A malformed/tampered key_kdf raises
                                        # ValueError; derive inside the try so it
                                        # surfaces gracefully, not as a traceback.
                                        encryption_key = _derive_pqc_keyfile_key(
                                            keyfile_password, key_salt, key_data.get("key_kdf")
                                        )
                                        # Format: nonce (12 bytes) + encrypted_key
                                        nonce = encrypted_private_key[:12]
                                        encrypted_key_data = encrypted_private_key[12:]

                                        # Decrypt the private key with the password-derived key
                                        aes_cipher = AESGCM(encryption_key)
                                        pqc_private_key = aes_cipher.decrypt(
                                            nonce, encrypted_key_data, None
                                        )

                                        if not args.quiet:
                                            eprint(
                                                "Successfully decrypted private key from keyfile"
                                            )
                                    except Exception as e:
                                        eprint(
                                            f"Error decrypting private key: {e}. Wrong password?"
                                        )
                                        eprint("Decryption may fail without a valid private key.")
                                        pqc_private_key = None
                                else:
                                    # Legacy support for non-encrypted keys (created before our fix)
                                    pqc_private_key = encrypted_private_key
                                    if not args.quiet:
                                        eprint(
                                            "WARNING: Using legacy unencrypted private key from keyfile"
                                        )

                                if not args.quiet and pqc_private_key:
                                    eprint(
                                        f"Loaded post-quantum private key from {args.pqc_keyfile}"
                                    )
                        except Exception as e:
                            if not args.quiet:
                                eprint(f"Warning: Failed to load PQC key file: {e}")

                    # Check if we should use keystore integration
                    if hasattr(args, "keystore") and args.keystore:
                        # Get keystore password if needed
                        keystore_password = None
                        if hasattr(args, "keystore_password") and args.keystore_password:
                            keystore_password = args.keystore_password
                        elif (
                            hasattr(args, "keystore_password_file") and args.keystore_password_file
                        ):
                            try:
                                with open(args.keystore_password_file, "r") as f:
                                    keystore_password = f.read().strip()
                            except Exception as e:
                                if not args.quiet:
                                    eprint(
                                        f"Warning: Failed to read keystore password from file: {e}"
                                    )
                                    keystore_password = getpass.getpass("Enter keystore password: ")
                        else:
                            keystore_password = getpass.getpass("Enter keystore password: ")

                        # Determine key ID if not provided
                        key_id = getattr(args, "key_id", None)

                        # Double-check: If no key ID provided or extracted from metadata,
                        # print a warning and suggest user to provide key ID manually
                        if key_id is None and not args.quiet:
                            eprint(
                                "\nWarning: No key ID found in metadata and --key-id not provided."
                            )
                            eprint(
                                "If decryption fails, please specify the key ID with --key-id parameter."
                            )

                        # Decrypt using keystore integration
                        success = decrypt_file_with_keystore(
                            actual_input_file,
                            temp_output,
                            password,
                            quiet=args.quiet,
                            pqc_private_key=pqc_private_key,
                            keystore_file=args.keystore,
                            keystore_password=keystore_password,
                            key_id=key_id,
                            dual_encryption=getattr(args, "dual_encrypt_key", False),
                            progress=args.progress,
                            verbose=args.verbose,
                            hidden_header=_hidden_for_decrypt(args),
                            second_password=_hidden_second_password,
                        )
                    else:
                        # Use standard decryption
                        success = decrypt_file(
                            actual_input_file,
                            temp_output,
                            password,
                            args.quiet,
                            progress=args.progress,
                            verbose=args.verbose,
                            debug=args.debug,
                            pqc_private_key=pqc_private_key,
                            enable_plugins=enable_plugins,
                            plugin_manager=plugin_manager,
                            hsm_plugin=hsm_plugin_instance,
                            hsm_slot=getattr(args, "hsm_slot", None),
                            no_estimate=getattr(args, "no_estimate", False),
                            allow_high_kdf_cost=getattr(args, "allow_high_kdf_cost", False),
                            verify_integrity=getattr(args, "verify_integrity", False),
                            parallel_kdf=getattr(args, "parallel_kdf", False),
                            kdf_workers=getattr(args, "kdf_workers", None),
                            hidden_header=_hidden_for_decrypt(args),
                            second_password=_hidden_second_password,
                        )
                    if success:
                        # Apply the original permissions to the temp file
                        os.chmod(temp_output, original_permissions)

                        # Replace the original file with the decrypted file
                        os.replace(temp_output, output_file)

                        # Successful replacement means we don't need to clean
                        # up the temp file
                        temp_files_to_cleanup.remove(temp_output)
                    else:
                        # Clean up the temp file if it exists
                        if os.path.exists(temp_output):
                            os.remove(temp_output)
                            temp_files_to_cleanup.remove(temp_output)
                except Exception as e:
                    # Clean up the temp file in case of any error
                    if os.path.exists(temp_output):
                        os.remove(temp_output)
                        if temp_output in temp_files_to_cleanup:
                            temp_files_to_cleanup.remove(temp_output)
                    raise e
            elif args.output:
                # Handle PQC key operations for decryption
                pqc_private_key = None
                if args.pqc_keyfile and os.path.exists(args.pqc_keyfile):
                    import base64
                    import json

                    try:
                        with open(args.pqc_keyfile, "r") as f:
                            # MED-8 Security fix: Use secure JSON validation for PQC key file loading
                            json_content = f.read()
                            try:
                                from .json_validator import (
                                    JSONSecurityError,
                                    JSONValidationError,
                                    secure_json_loads,
                                )

                                key_data = secure_json_loads(json_content)
                            except (JSONSecurityError, JSONValidationError) as e:
                                eprint(f"Error: PQC key file validation failed: {e}")
                                sys.exit(1)
                            except ImportError:
                                # Fallback to basic JSON loading if validator not available
                                try:
                                    key_data = json.loads(json_content)
                                except json.JSONDecodeError as e:
                                    eprint(f"Error: Invalid JSON in PQC key file: {e}")
                                    sys.exit(1)

                        if "private_key" in key_data:
                            encrypted_private_key = base64.b64decode(key_data["private_key"])

                            # Check if key is encrypted (will be for keys created after our fix)
                            if key_data.get("key_encrypted", False):
                                if not args.quiet:
                                    eprint("Found encrypted private key in keyfile")

                                # Get password to decrypt the private key
                                keyfile_password = None
                                if "password" in locals() and password:
                                    # Try the same password as for the file
                                    keyfile_password = password
                                else:
                                    # Ask for the keyfile password
                                    keyfile_password = getpass.getpass(
                                        "Enter password to decrypt the private key in keyfile: "
                                    ).encode()

                                # Import what we need to decrypt
                                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                                # Derive the wrapping key. New keyfiles carry a
                                # "key_kdf" Argon2id descriptor (gitlab#131 F16);
                                # legacy keyfiles have none and use the
                                # PBKDF2-SHA256 100k path inside
                                # _derive_pqc_keyfile_key.
                                key_salt = base64.b64decode(key_data["key_salt"])

                                try:
                                    # A malformed/tampered key_kdf raises
                                    # ValueError; derive inside the try so it
                                    # surfaces gracefully, not as a traceback.
                                    encryption_key = _derive_pqc_keyfile_key(
                                        keyfile_password, key_salt, key_data.get("key_kdf")
                                    )
                                    # Format: nonce (12 bytes) + encrypted_key
                                    nonce = encrypted_private_key[:12]
                                    encrypted_key_data = encrypted_private_key[12:]

                                    # Decrypt the private key with the password-derived key
                                    aes_cipher = AESGCM(encryption_key)
                                    pqc_private_key = aes_cipher.decrypt(
                                        nonce, encrypted_key_data, None
                                    )

                                    if not args.quiet:
                                        eprint("Successfully decrypted private key from keyfile")
                                except Exception as e:
                                    eprint(f"Error decrypting private key: {e}. Wrong password?")
                                    eprint("Decryption may fail without a valid private key.")
                                    pqc_private_key = None
                            else:
                                # Legacy support for non-encrypted keys (created before our fix)
                                pqc_private_key = encrypted_private_key
                                if not args.quiet:
                                    eprint(
                                        "WARNING: Using legacy unencrypted private key from keyfile"
                                    )

                            if not args.quiet and pqc_private_key:
                                eprint(f"Loaded post-quantum private key from {args.pqc_keyfile}")
                    except Exception as e:
                        if not args.quiet:
                            eprint(f"Warning: Failed to load PQC key file: {e}")

                # Handle steganography extraction if requested
                actual_input_file = args.input
                temp_extracted_file = None

                if hasattr(args, "stego_extract") and args.stego_extract:
                    try:
                        import tempfile

                        if not args.quiet:
                            eprint("Extracting encrypted data from steganographic image...")

                        # Get steganography plugin
                        stego_plugin = _get_steganography_plugin(quiet=args.quiet)
                        if stego_plugin:
                            # Extract steganography options from args
                            method = getattr(args, "stego_method", "lsb")
                            bits_per_channel = getattr(args, "stego_bits_per_channel", 1)
                            stego_password = getattr(args, "stego_password", None)

                            options = {
                                "randomize_pixels": getattr(args, "stego_randomize_pixels", False),
                                "decoy_data": getattr(args, "stego_decoy_data", False),
                                "preserve_stats": True,
                                "jpeg_quality": getattr(args, "jpeg_quality", 85),
                            }

                            # Extract data using plugin
                            result = stego_plugin.extract_data(
                                stego_path=args.input,
                                method=method,
                                bits_per_channel=bits_per_channel,
                                password=stego_password,
                                **options,
                            )

                            if result.success:
                                encrypted_data = result.data.get("extracted_data", b"")

                                # Create temporary file for extracted data
                                with tempfile.NamedTemporaryFile(
                                    delete=False, suffix=".enc"
                                ) as temp_file:
                                    temp_extracted_file = temp_file.name
                                    temp_file.write(encrypted_data)

                                # Use extracted file as input for decryption
                                actual_input_file = temp_extracted_file
                                temp_files_to_cleanup.append(temp_extracted_file)

                                if not args.quiet:
                                    eprint(f"Extracted {len(encrypted_data)} bytes from image")
                            else:
                                eprint(f"Steganography extraction error: {result.message}")
                                return 1
                    except Exception as e:
                        eprint(f"Steganography extraction error: {e}")
                        return 1

                # Check if we should use keystore integration
                if hasattr(args, "keystore") and args.keystore:
                    # Get keystore password if needed
                    keystore_password = None
                    if hasattr(args, "keystore_password") and args.keystore_password:
                        keystore_password = args.keystore_password
                    elif hasattr(args, "keystore_password_file") and args.keystore_password_file:
                        try:
                            with open(args.keystore_password_file, "r") as f:
                                keystore_password = f.read().strip()
                        except Exception as e:
                            if not args.quiet:
                                eprint(f"Warning: Failed to read keystore password from file: {e}")
                                keystore_password = getpass.getpass("Enter keystore password: ")
                    else:
                        keystore_password = getpass.getpass("Enter keystore password: ")

                    # Determine key ID if not provided
                    key_id = getattr(args, "key_id", None)

                    # The keystore_wrapper.py will now handle cases with no key ID,
                    # including trying the only key in the keystore

                    # Decrypt using keystore integration
                    success = decrypt_file_with_keystore(
                        args.input,
                        args.output,
                        password,
                        quiet=args.quiet,
                        pqc_private_key=pqc_private_key,
                        keystore_file=args.keystore,
                        keystore_password=keystore_password,
                        key_id=key_id,
                        dual_encryption=getattr(args, "dual_encrypt_key", False),
                        progress=args.progress,
                        verbose=args.verbose,
                        hidden_header=_hidden_for_decrypt(args),
                        second_password=_hidden_second_password,
                    )
                else:
                    # Use standard decryption
                    success = decrypt_file(
                        actual_input_file,
                        args.output,
                        password,
                        args.quiet,
                        progress=args.progress,
                        verbose=args.verbose,
                        debug=args.debug,
                        pqc_private_key=pqc_private_key,
                        enable_plugins=enable_plugins,
                        plugin_manager=plugin_manager,
                        hsm_plugin=hsm_plugin_instance,
                        hsm_slot=getattr(args, "hsm_slot", None),
                        no_estimate=getattr(args, "no_estimate", False),
                        allow_high_kdf_cost=getattr(args, "allow_high_kdf_cost", False),
                        verify_integrity=getattr(args, "verify_integrity", False),
                        hidden_header=_hidden_for_decrypt(args),
                        second_password=_hidden_second_password,
                    )
                if success:
                    # Security audit log for successful decryption
                    if security_logger:
                        security_logger.log_event(
                            "decryption_completed",
                            "info",
                            {
                                "input_file": str(args.input),
                                "output_file": str(args.output),
                                "service": "cli",
                            },
                        )

                    if not args.quiet:
                        # Skip leading newline for stdout/stderr to avoid blank line
                        prefix = "" if args.output in ("/dev/stdout", "/dev/stderr") else "\n"
                        eprint(f"{prefix}File decrypted successfully: {args.output}")

                # If shredding was requested and decryption was successful
                if args.shred and success:
                    if not args.quiet:
                        eprint("Shredding the encrypted file as requested...")
                    secure_shred_file(args.input, args.shred_passes, args.quiet)
            else:
                # Handle PQC key operations for decryption to screen
                pqc_private_key = None
                if args.pqc_keyfile and os.path.exists(args.pqc_keyfile):
                    import base64
                    import json

                    try:
                        with open(args.pqc_keyfile, "r") as f:
                            # MED-8 Security fix: Use secure JSON validation for PQC key file loading
                            json_content = f.read()
                            try:
                                from .json_validator import (
                                    JSONSecurityError,
                                    JSONValidationError,
                                    secure_json_loads,
                                )

                                key_data = secure_json_loads(json_content)
                            except (JSONSecurityError, JSONValidationError) as e:
                                eprint(f"Error: PQC key file validation failed: {e}")
                                sys.exit(1)
                            except ImportError:
                                # Fallback to basic JSON loading if validator not available
                                try:
                                    key_data = json.loads(json_content)
                                except json.JSONDecodeError as e:
                                    eprint(f"Error: Invalid JSON in PQC key file: {e}")
                                    sys.exit(1)

                        if "private_key" in key_data:
                            encrypted_private_key = base64.b64decode(key_data["private_key"])

                            # Check if key is encrypted (will be for keys created after our fix)
                            if key_data.get("key_encrypted", False):
                                if not args.quiet:
                                    eprint("Found encrypted private key in keyfile")

                                # Get password to decrypt the private key
                                keyfile_password = None
                                if "password" in locals() and password:
                                    # Try the same password as for the file
                                    keyfile_password = password
                                else:
                                    # Ask for the keyfile password
                                    keyfile_password = getpass.getpass(
                                        "Enter password to decrypt the private key in keyfile: "
                                    ).encode()

                                # Import what we need to decrypt
                                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                                # Derive the wrapping key. New keyfiles carry a
                                # "key_kdf" Argon2id descriptor (gitlab#131 F16);
                                # legacy keyfiles have none and use the
                                # PBKDF2-SHA256 100k path inside
                                # _derive_pqc_keyfile_key.
                                key_salt = base64.b64decode(key_data["key_salt"])

                                try:
                                    # A malformed/tampered key_kdf raises
                                    # ValueError; derive inside the try so it
                                    # surfaces gracefully, not as a traceback.
                                    encryption_key = _derive_pqc_keyfile_key(
                                        keyfile_password, key_salt, key_data.get("key_kdf")
                                    )
                                    # Format: nonce (12 bytes) + encrypted_key
                                    nonce = encrypted_private_key[:12]
                                    encrypted_key_data = encrypted_private_key[12:]

                                    # Decrypt the private key with the password-derived key
                                    cipher = AESGCM(encryption_key)
                                    pqc_private_key = cipher.decrypt(
                                        nonce, encrypted_key_data, None
                                    )

                                    if not args.quiet:
                                        eprint("Successfully decrypted private key from keyfile")
                                except Exception as e:
                                    eprint(f"Error decrypting private key: {e}. Wrong password?")
                                    eprint("Decryption may fail without a valid private key.")
                                    pqc_private_key = None
                            else:
                                # Legacy support for non-encrypted keys (created before our fix)
                                pqc_private_key = encrypted_private_key
                                if not args.quiet:
                                    eprint(
                                        "WARNING: Using legacy unencrypted private key from keyfile"
                                    )

                            if not args.quiet and pqc_private_key:
                                eprint(f"Loaded post-quantum private key from {args.pqc_keyfile}")
                    except Exception as e:
                        if not args.quiet:
                            eprint(f"Warning: Failed to load PQC key file: {e}")

                # Decrypt to screen if no output file specified (useful for
                # text files)

                # Check if we should use keystore integration
                if hasattr(args, "keystore") and args.keystore:
                    # Get keystore password if needed
                    keystore_password = None
                    if hasattr(args, "keystore_password") and args.keystore_password:
                        keystore_password = args.keystore_password
                    elif hasattr(args, "keystore_password_file") and args.keystore_password_file:
                        try:
                            with open(args.keystore_password_file, "r") as f:
                                keystore_password = f.read().strip()
                        except Exception as e:
                            if not args.quiet:
                                eprint(f"Warning: Failed to read keystore password from file: {e}")
                                keystore_password = getpass.getpass("Enter keystore password: ")
                    else:
                        keystore_password = getpass.getpass("Enter keystore password: ")

                    # Determine key ID if not provided
                    key_id = getattr(args, "key_id", None)

                    # The keystore_wrapper.py will now handle cases with no key ID,
                    # including trying the only key in the keystore

                    # Decrypt using keystore integration
                    decrypted = decrypt_file_with_keystore(
                        args.input,
                        None,
                        password,
                        quiet=args.quiet,
                        pqc_private_key=pqc_private_key,
                        keystore_file=args.keystore,
                        keystore_password=keystore_password,
                        key_id=key_id,
                        dual_encryption=getattr(args, "dual_encrypt_key", False),
                        progress=args.progress,
                        verbose=args.verbose,
                        hidden_header=_hidden_for_decrypt(args),
                        second_password=_hidden_second_password,
                    )
                else:
                    # Use standard decryption
                    decrypted = decrypt_file(
                        args.input,
                        None,
                        password,
                        args.quiet,
                        progress=args.progress,
                        verbose=args.verbose,
                        debug=args.debug,
                        pqc_private_key=pqc_private_key,
                        enable_plugins=enable_plugins,
                        plugin_manager=plugin_manager,
                        hsm_plugin=hsm_plugin_instance,
                        hsm_slot=getattr(args, "hsm_slot", None),
                        no_estimate=getattr(args, "no_estimate", False),
                        allow_high_kdf_cost=getattr(args, "allow_high_kdf_cost", False),
                        verify_integrity=getattr(args, "verify_integrity", False),
                        hidden_header=_hidden_for_decrypt(args),
                        second_password=_hidden_second_password,
                    )
                try:
                    # Try to decode as text
                    if not args.quiet:
                        eprint("\nDecrypted content:")
                    print(decrypted.decode().rstrip())
                except UnicodeDecodeError:
                    if not args.quiet:
                        eprint(
                            "\nDecrypted successfully, but content is binary and cannot be displayed."
                        )

        elif args.action == "rekey":
            # Re-encrypt file with a new password
            from .crypt_core import rekey_file as _rekey_file

            try:
                # Determine new algorithm if specified
                new_algorithm = None
                if getattr(args, "algorithm", None):
                    new_algorithm = args.algorithm

                # Handle cascade encryption parameters for re-encryption
                rekey_cascade_mode = False
                rekey_cipher_names = None
                rekey_cascade_hash = "sha256"

                if hasattr(args, "cascade") and args.cascade is not None:
                    from .crypt_cli_subparser import CASCADE_PRESETS

                    rekey_cascade_mode = True

                    if isinstance(args.cascade, str) and args.cascade in CASCADE_PRESETS:
                        rekey_cipher_names = CASCADE_PRESETS[args.cascade]
                    elif new_algorithm and "," in str(new_algorithm):
                        rekey_cipher_names = [c.strip() for c in str(new_algorithm).split(",")]
                        new_algorithm = "cascade"
                    else:
                        rekey_cipher_names = CASCADE_PRESETS.get("standard")

                    if hasattr(args, "cascade_hash"):
                        rekey_cascade_hash = args.cascade_hash

                # Determine format version for re-encryption
                use_xor = getattr(args, "use_xor_composition", False)
                use_independent_xor = getattr(args, "independent_xor", False)

                if use_independent_xor:
                    # Latest independent-XOR-only format (M2 decision 2026-07-10).
                    rekey_format_version = LATEST_STABLE_FORMAT_VERSION
                elif use_xor:
                    rekey_format_version = 13  # Sequential XOR stays pinned at v13
                else:
                    rekey_format_version = None  # Inherit from file

                success = _rekey_file(
                    input_file=args.input,
                    output_file=getattr(args, "output", None),
                    old_password=password,
                    new_password=rekey_password,
                    quiet=args.quiet,
                    progress=args.progress,
                    verbose=args.verbose,
                    debug=args.debug,
                    enable_plugins=enable_plugins,
                    plugin_manager=plugin_manager,
                    hsm_plugin=hsm_plugin_instance,
                    hsm_slot=getattr(args, "hsm_slot", None),
                    no_estimate=getattr(args, "no_estimate", False),
                    allow_high_kdf_cost=getattr(args, "allow_high_kdf_cost", False),
                    verify_integrity=getattr(args, "verify_integrity", False),
                    parallel_kdf=getattr(args, "parallel_kdf", False),
                    kdf_workers=getattr(args, "kdf_workers", None),
                    new_algorithm="cascade" if rekey_cascade_mode else new_algorithm,
                    new_format_version=rekey_format_version,
                    cascade=rekey_cascade_mode,
                    cipher_names=rekey_cipher_names,
                    cascade_hash=rekey_cascade_hash,
                    integrity=getattr(args, "integrity", False),
                    pepper_plugin=pepper_plugin_instance,
                    pepper_name=pepper_name_to_use,
                    hash_config=hash_config,
                    pbkdf2_iterations=getattr(args, "pbkdf2_iterations", 0),
                )

                if success:
                    exit_code = 0
                else:
                    exit_code = 1
                    if not args.quiet:
                        eprint("Rekey operation failed.", file=sys.stderr)

            except Exception as e:
                exit_code = 1
                if not args.quiet:
                    if args.debug:
                        import traceback

                        traceback.print_exc()
                    else:
                        eprint(f"Rekey failed: {e}", file=sys.stderr)

        elif args.action == "shred":
            # Direct shredding of files or directories without
            # encryption/decryption

            # Expand any glob patterns in the input path
            matched_paths = expand_glob_patterns(args.input)

            if not matched_paths:
                if not args.quiet:
                    eprint(f"No files or directories match the pattern: {args.input}")
                exit_code = 1
            else:
                # If there are multiple files/dirs to shred, inform the user
                if len(matched_paths) > 1 and not args.quiet:
                    eprint(f"Found {len(matched_paths)} files/directories matching the pattern.")

                overall_success = True

                # Process each matched path
                for path in matched_paths:
                    # Special handling for directories without recursive flag
                    if os.path.isdir(path) and not args.recursive:
                        # Directory detected but recursive flag not provided
                        if args.quiet:
                            # In quiet mode, fail immediately without
                            # confirmation
                            if not args.quiet:
                                eprint(
                                    f"Error: {path} is a directory. "
                                    f"Use --recursive to shred directories."
                                )
                            overall_success = False
                            continue
                        else:
                            # Ask for confirmation since this is potentially
                            # dangerous
                            confirm_message = (
                                f"WARNING: {path} is a directory but --recursive flag is not specified. "
                                f"Only empty directories will be removed. Continue?"
                            )
                            if request_confirmation(confirm_message):
                                success = secure_shred_file(path, args.shred_passes, args.quiet)
                                if not success:
                                    overall_success = False
                            else:
                                eprint(f"Skipping directory: {path}")
                                continue
                    else:
                        # File or directory with recursive flag
                        if not args.quiet:
                            eprint(
                                f"Securely shredding {'directory' if os.path.isdir(path) else 'file'}: {path}"
                            )

                        success = secure_shred_file(path, args.shred_passes, args.quiet)
                        if not success:
                            overall_success = False

                # Set exit code to failure if any operation failed
                if not overall_success:
                    exit_code = 1

    except Exception as e:
        if not args.quiet:
            eprint(f"\nError: {e}")
        # A --random-password-out orphan is announced by the finally below
        # (gitlab#223), which also covers the SystemExit/return-1 sites this
        # handler cannot see.
        exit_code = 1

    finally:
        # gitlab#223: the orphan-password NOTE must fire on EVERY incomplete
        # encrypt exit. The sys.exit(1)/return-1 sites (XOR mutual-exclusivity,
        # keystore-branch failures, validation aborts) bypass the `except
        # Exception` above by language rule (SystemExit), and wiring each site
        # individually proved incomplete twice (#182, the #222 review). The
        # helper no-ops unless --random-password-out actually left a file; a
        # completed run stays silent (its file is the live credential, already
        # announced at write time); and _ciphertext_on_disk picks the accurate
        # wording -- "verify before removing" when a usable output may exist,
        # "you can remove it" only when provably none does. The NOTE is
        # advisory and must never change the outcome (a raising eprint in a
        # finally would replace the propagating SystemExit -- review f6).
        # Known window: the password file exists from the write in the
        # password-delivery block above, but this try starts a few hundred
        # lines later; every exit in between is either pre-write or handled
        # at the write site (verified in the #223 confirmation review). Any
        # NEW sys.exit/raise added between the delivery block and this try
        # must call the helper itself.
        if not _encrypt_completed:
            try:
                _warn_orphan_random_password(args, ciphertext_maybe_written=_ciphertext_on_disk)
            except Exception:
                pass

    # Exit with appropriate code
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
