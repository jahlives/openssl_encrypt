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
    expand_glob_patterns,
    generate_strong_password,
    request_confirmation,
    secure_shred_file,
    show_security_recommendations,
)

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
from .keystore_utils import auto_generate_pqc_key

# Import keystore-related modules
from .keystore_wrapper import decrypt_file_with_keystore, encrypt_file_with_keystore
from .password_policy import PasswordPolicy, get_password_strength
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
            # MED-8 Security fix: Use secure JSON validation for metadata parsing
            try:
                from .json_validator import (
                    JSONSecurityError,
                    JSONValidationError,
                    secure_metadata_loads,
                )

                metadata = secure_metadata_loads(metadata_json)
            except (JSONSecurityError, JSONValidationError) as e:
                print(f"Error: Invalid metadata JSON: {e}")
                return None
            except ImportError:
                # Fallback to basic JSON loading if validator not available
                try:
                    metadata = json.loads(metadata_json)
                except json.JSONDecodeError as e:
                    print(f"Error: Invalid JSON in metadata: {e}")
                    return None

            # Extract algorithm info based on format version
            format_version = metadata.get("format_version", 1)

            if format_version in [4, 5, 6, 9]:
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
        print("Error: Invalid template name provided")
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
        print(
            f"Error: Invalid template name '{template_name}'. Template names cannot contain path separators or parent directory references."
        )
        sys.exit(1)

    # Ensure the cleaned name is not empty
    if not safe_template_name:
        print("Error: Empty template name after security validation")
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Move up one level from the modules directory to the project root
    project_root = os.path.dirname(script_dir)

    # Templates are in project root
    template_dir = os.path.join(project_root, "templates")

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
                print(
                    f"Error: Security violation - template path '{template_path}' is outside allowed directory"
                )
                sys.exit(1)
        except ValueError:
            # Different drives/roots on Windows - definitely not under template_dir
            print(
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
                            print(f"Error: Invalid template JSON in {template_path}: {e}")
                            sys.exit(1)
                        except ImportError:
                            # Fallback to basic JSON loading if validator not available
                            try:
                                return json.loads(json_content)
                            except json.JSONDecodeError as e:
                                print(f"Error: Invalid JSON in template {template_path}: {e}")
                                sys.exit(1)
                    else:
                        return yaml.safe_load(f)
            except Exception as e:
                print(f"Error loading template {template_path}: {e}")
                sys.exit(1)

    print(f"Template {safe_template_name} not found in {template_dir}")
    sys.exit(1)


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
                "sha512": 10000,
                "sha256": 0,
                "sha3_256": 10000,
                "sha3_512": 0,
                "blake2b": 0,
                "shake256": 0,
                "whirlpool": 0,
                "scrypt": {"enabled": True, "n": 128, "r": 8, "p": 1, "rounds": 5},
                "argon2": {
                    "enabled": True,
                    "time_cost": 3,
                    "memory_cost": 65536,
                    "parallelism": 4,
                    "hash_len": 32,
                    "type": 2,
                    "rounds": 5,
                },
                "pbkdf2_iterations": 0,
                "type": "id",
                "algorithm": "aes-gcm-siv",
            }
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
                    return custom_template
                else:
                    print("Invalid template format: missing 'hash_config' key")
                    sys.exit(1)
        except Exception as e:
            print(f"Error loading template file: {e}")
            sys.exit(1)


def preprocess_global_args(argv):
    """Preprocess sys.argv to move truly global flags to the front for subparser compatibility.

    This allows global flags like --debug, --verbose, --quiet, --progress to be specified
    anywhere in the command line, maintaining backward compatibility with v1.2.1 behavior.
    """
    # Flags that are truly global and can appear anywhere
    TRULY_GLOBAL_FLAGS = {"--debug", "--verbose", "--quiet", "-q", "--progress"}

    # Find the command position
    commands = {
        "encrypt",
        "decrypt",
        "shred",
        "generate-password",
        "security-info",
        "analyze-security",
        "config-wizard",
        "analyze-config",
        "template",
        "smart-recommendations",
        "check-argon2",
        "check-pqc",
        "version",
        "show-version-file",
        "create-usb",
        "verify-usb",
    }

    command_pos = None
    for i, arg in enumerate(argv[1:], 1):  # Skip argv[0] (script name)
        if arg in commands:
            command_pos = i
            break

    if command_pos is None:
        return argv  # No command found, return as-is

    # Extract global flags and their values from anywhere in the command line
    global_args = []
    other_args = [argv[0]]  # Keep script name
    i = 1

    while i < len(argv):
        arg = argv[i]

        if arg in TRULY_GLOBAL_FLAGS:
            global_args.append(arg)
            # Check if this flag takes a value (currently none of our global flags do, but future-proof)
            if (
                arg in ["--template", "-t"]
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
    print("\nSECURITY CONFIGURATION ANALYSIS")
    print("===============================")

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

        # Display analysis results
        print(f"\nOVERALL SECURITY SCORE: {analysis['overall']['score']}/10")
        print(f"Security Level: {analysis['overall']['level'].name}")
        print(f"Description: {analysis['overall']['description']}")

        print("\nCOMPONENT ANALYSIS:")
        print("─────────────────────")
        print(
            f"Hash Security: {analysis['hash_analysis']['score']:.1f}/10 ({analysis['hash_analysis']['description']})"
        )
        if analysis["hash_analysis"]["algorithms"]:
            print(f"  Active algorithms: {', '.join(analysis['hash_analysis']['algorithms'])}")
            print(f"  Total rounds: {analysis['hash_analysis']['total_rounds']:,}")

        print(
            f"KDF Security: {analysis['kdf_analysis']['score']:.1f}/10 ({analysis['kdf_analysis']['description']})"
        )
        if analysis["kdf_analysis"]["algorithms"]:
            print(f"  Active algorithms: {', '.join(analysis['kdf_analysis']['algorithms'])}")

        print(
            f"Encryption: {analysis['cipher_analysis']['score']:.1f}/10 ({analysis['cipher_analysis']['description']})"
        )
        print(f"  Algorithm: {analysis['cipher_analysis']['algorithm']}")
        print(f"  Authenticated: {'Yes' if analysis['cipher_analysis']['authenticated'] else 'No'}")

        if analysis["pqc_analysis"]["enabled"]:
            print(f"Post-Quantum: {analysis['pqc_analysis']['score']:.1f}/10 (Quantum-resistant)")
        else:
            print("Post-Quantum: Not enabled")

        print("\nSECURITY ESTIMATES:")
        print("─────────────────────")
        print(f"Estimated brute-force time: {analysis['estimates']['brute_force_time']}")
        print(f"Note: {analysis['estimates']['note']}")
        print(f"Disclaimer: {analysis['estimates']['disclaimer']}")

        if analysis["suggestions"]:
            print("\nRECOMMENDATIONS:")
            print("─────────────────")
            for i, suggestion in enumerate(analysis["suggestions"], 1):
                print(f"{i}. {suggestion}")

        print()

    except Exception as e:
        print(f"Error analyzing security configuration: {e}")
        print("Please check your configuration parameters.")


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
                print(format_algorithm_help(cat))
                print()  # Blank line between categories
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
                    print(f"\n{title}:")
                    print("=" * len(title))
                    for algo in algorithms:
                        print(f"  {algo}")

    except ImportError:
        print("Error: Registry system not available.")
        print("The algorithm registry module could not be imported.")
        sys.exit(1)
    except Exception as e:
        print(f"Error displaying algorithms: {e}")
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
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
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

    print("\n" + "=" * 70)
    print("OpenSSL-Encrypt: Optional Dependencies Installer")
    print("=" * 70)
    print("\nThis will install:")
    print("  • liboqs 0.12.0 (post-quantum cryptography)")
    print("  • liboqs-python 0.12.0 (Python bindings)")
    print("  • threefish_native (large-block cipher)")
    print("\nRequirements:")
    print("  • cmake, ninja (or make), gcc, g++, git")
    print("  • Rust toolchain (rustc, cargo) for threefish")
    print("  • ~500MB disk space, ~10-15 minutes build time")
    print("=" * 70 + "\n")

    if not args.yes:
        response = input("Continue? [y/N]: ").strip().lower()
        if response not in ("y", "yes"):
            print("Installation cancelled.")
            return

    success_count = 0
    failed = []

    # Check for required build tools
    print("\n[1/4] Checking build tools...")
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
            print(f"  ✓ {tool_name} found")
        else:
            print(f"  ✗ {tool_name} NOT found")
            missing_tools.append(tool_name)

    if missing_tools:
        print(f"\n✗ Missing required tools: {', '.join(missing_tools)}")
        print("\nPlease install them first:")
        print("  Ubuntu/Debian: sudo apt-get install cmake ninja-build gcc g++ git cargo")
        print("  Fedora: sudo dnf install cmake ninja-build gcc g++ git cargo")
        print("  macOS: brew install cmake ninja gcc git rust")
        sys.exit(1)

    # Get package root directory
    try:
        import openssl_encrypt

        package_dir = os.path.dirname(os.path.abspath(openssl_encrypt.__file__))
        repo_root = os.path.dirname(package_dir)  # Go up one level
    except Exception as e:
        print(f"✗ Could not locate package directory: {e}")
        sys.exit(1)

    # [2/4] Build liboqs
    print("\n[2/4] Building liboqs 0.12.0...")
    try:
        # Check if already installed
        result = subprocess.run(
            ["pkg-config", "--modversion", "liboqs"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip() == "0.12.0":
            print("  ✓ liboqs 0.12.0 already installed")
            success_count += 1
        else:
            # Try using the build script if available
            build_script = os.path.join(repo_root, "scripts", "build_local_deps.sh")
            if not os.path.exists(build_script):
                # Build manually
                print("  Building from source...")
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

                print("  ✓ liboqs 0.12.0 built and installed to ~/.local")
                success_count += 1
            else:
                # Use build script
                env = os.environ.copy()
                env["LIBOQS_INSTALL_PREFIX"] = os.path.expanduser("~/.local")
                env["LIBOQS_VERSION"] = "0.12.0"
                env["LIBOQS_PYTHON_VERSION"] = "0.12.0"

                bash_cmd = shutil.which("bash") or "/bin/bash"
                subprocess.run([bash_cmd, build_script], env=env, check=True)
                print("  ✓ liboqs 0.12.0 built and installed")
                success_count += 1
    except Exception as e:
        print(f"  ✗ Failed to build liboqs: {e}")
        failed.append("liboqs")

    # [3/4] Install liboqs-python
    print("\n[3/4] Installing liboqs-python 0.12.0...")
    try:
        # Check if already installed
        result = subprocess.run(
            [sys.executable, "-c", "import oqs; print(oqs.oqs_python_version())"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip() == "0.12.0":
            print("  ✓ liboqs-python 0.12.0 already installed")
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
            print("  ✓ liboqs-python 0.12.0 installed")
            success_count += 1
    except Exception as e:
        print(f"  ✗ Failed to install liboqs-python: {e}")
        failed.append("liboqs-python")

    # [4/4] Build threefish_native
    print("\n[4/4] Building threefish_native...")
    try:
        # Check if already installed
        try:
            import threefish_native

            print(
                f"  ✓ threefish_native already installed (version {getattr(threefish_native, '__version__', 'unknown')})"
            )
            success_count += 1
        except ImportError:
            # Try to build it
            threefish_dir = os.path.join(repo_root, "threefish_native")
            if not os.path.exists(threefish_dir):
                print("  ✗ threefish_native source not found")
                print("     This is only available when installing from source repository")
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
                    ["maturin", "build", "--release"], cwd=threefish_dir, env=env, check=True
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
                    print("  ✓ threefish_native built and installed")
                    success_count += 1
                else:
                    print("  ✗ No wheel file found after build")
                    failed.append("threefish_native")
    except Exception as e:
        print(f"  ✗ Failed to build threefish_native: {e}")
        failed.append("threefish_native")

    # Summary
    print("\n" + "=" * 70)
    print("Installation Summary")
    print("=" * 70)
    print(f"  Successfully installed: {success_count}/3 components")
    if failed:
        print(f"  Failed: {', '.join(failed)}")
    else:
        print("  All components installed successfully!")

    print("\nTo verify installation, run:")
    print("  openssl-encrypt list-available-algorithms")
    print("=" * 70 + "\n")

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
            print("Starting Configuration Wizard...")
            print("This will help you create secure encryption settings.\n")

        # Run the wizard
        config = run_configuration_wizard(quiet=quiet)

        if not quiet:
            # Generate CLI arguments for the configuration
            cli_args = generate_cli_arguments(config)

            print("\nTo use this configuration, run:")
            print("─" * 40)
            print(f"crypt_cli encrypt --input <file> {' '.join(cli_args)}")
            print("\nOr save these settings to a template file for reuse.")

        return config

    except KeyboardInterrupt:
        if not quiet:
            print("\n\nConfiguration wizard cancelled.")
        return None
    except Exception as e:
        print(f"Error running configuration wizard: {e}")
        return None


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
            print("Analyzing Configuration...")
            print("Performing comprehensive security and performance analysis.\n")

        # Convert args to configuration dictionary
        config = vars(args)

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
        print(f"Error analyzing configuration: {e}")
        sys.exit(1)


def _display_analysis_results(analysis):
    """Display formatted analysis results."""

    print("=" * 60)
    print("CONFIGURATION ANALYSIS RESULTS")
    print("=" * 60)
    print()

    # Overall Summary
    print("📊 OVERALL ASSESSMENT")
    print("─" * 30)
    print(f"Security Score: {analysis.overall_score:.1f}/10.0")
    print(f"Security Level: {analysis.security_level.name}")
    print(f"Analysis Time: {analysis.analysis_timestamp}")
    print()

    # Configuration Summary
    print("⚙️  CONFIGURATION SUMMARY")
    print("─" * 30)
    summary = analysis.configuration_summary
    print(f"Algorithm: {summary['algorithm']}")
    print(f"Hash Functions: {', '.join(summary['active_hash_functions']) or 'None'}")
    print(f"Key Derivation: {', '.join(summary['active_kdfs']) or 'None'}")
    print(f"Post-Quantum: {'Yes' if summary['post_quantum_enabled'] else 'No'}")
    print(f"Complexity: {summary['configuration_complexity'].title()}")
    print(f"Suitable For: {', '.join(summary['suitable_for'])}")
    print()

    # Performance Assessment
    print("🚀 PERFORMANCE ASSESSMENT")
    print("─" * 30)
    perf = analysis.performance_assessment
    print(f"Overall Score: {perf['overall_score']:.1f}/10.0")
    print(f"Speed Rating: {perf['estimated_relative_speed'].replace('_', ' ').title()}")
    print(
        f"Memory Usage: {perf['memory_requirements']['estimated_peak_mb']}MB ({perf['memory_requirements']['classification']})"
    )
    print(f"CPU Intensity: {perf['cpu_intensity'].replace('_', ' ').title()}")
    print()

    # Compatibility
    print("🔗 COMPATIBILITY")
    print("─" * 30)
    compat = analysis.compatibility_matrix
    print(f"Overall Score: {compat['overall_compatibility_score']:.1f}/10.0")

    platform_issues = [p for p, status in compat["platform_compatibility"].items() if not status]
    if platform_issues:
        print(f"Platform Limitations: {', '.join(platform_issues)}")
    else:
        print("Platform Support: Universal")

    library_issues = [lib for lib, status in compat["library_compatibility"].items() if not status]
    if library_issues:
        print(f"Library Limitations: {', '.join(library_issues)}")
    else:
        print("Library Support: Excellent")
    print()

    # Future Proofing
    print("🔮 FUTURE PROOFING")
    print("─" * 30)
    future = analysis.future_proofing
    print(f"Algorithm Longevity: {future['algorithm_longevity_score']:.1f}/10.0")
    print(f"Key Size Adequacy: {future['key_size_adequacy_score']:.1f}/10.0")
    print(f"Quantum Resistant: {'Yes' if future['post_quantum_ready'] else 'No'}")
    print(f"Estimated Secure: {future['estimated_secure_years']}")
    print()

    # Compliance Status
    if analysis.compliance_status:
        print("📋 COMPLIANCE STATUS")
        print("─" * 30)
        for framework, status in analysis.compliance_status.items():
            framework_name = framework.replace("_", " ").title()
            compliance_status = "✅ Compliant" if status["compliant"] else "❌ Non-Compliant"
            print(f"{framework_name}: {compliance_status}")

            if status.get("issues"):
                for issue in status["issues"]:
                    print(f"  • {issue}")
        print()

    # Recommendations
    if analysis.recommendations:
        print("💡 RECOMMENDATIONS")
        print("─" * 30)

        # Group recommendations by priority
        by_priority = {}
        for rec in analysis.recommendations:
            priority = rec.priority.value
            if priority not in by_priority:
                by_priority[priority] = []
            by_priority[priority].append(rec)

        # Display by priority
        priority_icons = {"critical": "🚨", "high": "⚠️", "medium": "💡", "low": "ℹ️", "info": "📝"}

        for priority in ["critical", "high", "medium", "low", "info"]:
            if priority in by_priority:
                recommendations = by_priority[priority]
                print(f"\n{priority_icons[priority]} {priority.upper()} PRIORITY:")

                for i, rec in enumerate(recommendations, 1):
                    print(f"\n{i}. {rec.title}")
                    print(f"   Category: {rec.category.value.replace('_', ' ').title()}")
                    print(f"   Issue: {rec.description}")
                    print(f"   Action: {rec.action}")
                    print(f"   Impact: {rec.impact}")

                    if rec.applies_to and rec.applies_to != ["all"]:
                        print(f"   Applies To: {', '.join(rec.applies_to)}")
    else:
        print("💡 RECOMMENDATIONS")
        print("─" * 30)
        print("✅ No specific recommendations - configuration looks good!")

    print()
    print("=" * 60)
    print("Analysis complete. Use recommendations above to enhance your configuration.")
    print("=" * 60)


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
            print("Invalid template subcommand. Use --help for available options.")

    except Exception as e:
        print(f"Error in template management: {e}")
        sys.exit(1)


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
            print("Invalid smart recommendations subcommand. Use --help for available options.")

    except Exception as e:
        print(f"Error in smart recommendations: {e}")
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

    # Display recommendations
    print("🧠 SMART RECOMMENDATIONS")
    print("=" * 50)
    print()

    if not recommendations:
        print("No specific recommendations at this time.")
        print("Your current configuration appears to be well-optimized!")
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

        print("Creating new user profile...")
        print("Please answer the following questions to personalize your recommendations:")
        print()

        # Interactive profile creation
        user_context.user_type = (
            input("User type [personal/business/developer/compliance]: ").strip() or "personal"
        )
        user_context.experience_level = (
            input("Experience level [beginner/intermediate/advanced/expert]: ").strip()
            or "intermediate"
        )

        use_cases_str = input(
            "Primary use cases (comma-separated) [personal/business/compliance/archival]: "
        ).strip()
        if use_cases_str:
            user_context.primary_use_cases = [uc.strip() for uc in use_cases_str.split(",")]
        else:
            user_context.primary_use_cases = ["personal"]

        user_context.data_sensitivity = (
            input("Data sensitivity [low/medium/high/top_secret]: ").strip() or "medium"
        )
        user_context.performance_priority = (
            input("Performance priority [speed/security/balanced]: ").strip() or "balanced"
        )

        compliance_str = input(
            "Compliance requirements (comma-separated) [fips_140_2/common_criteria/nist_guidelines]: "
        ).strip()
        if compliance_str:
            user_context.compliance_requirements = [
                req.strip() for req in compliance_str.split(",")
            ]

        engine.save_user_context(user_id, user_context)
        print(f"\n✅ Profile '{user_id}' created successfully!")

    elif hasattr(args, "show") and args.show:
        # Show existing profile
        user_context = engine.load_user_context(user_id)
        if not user_context:
            print(f"❌ No profile found for user '{user_id}'")
            return

        print(f"👤 USER PROFILE: {user_id}")
        print("=" * 40)
        print(f"User Type: {user_context.user_type}")
        print(f"Experience Level: {user_context.experience_level}")
        print(f"Primary Use Cases: {', '.join(user_context.primary_use_cases)}")
        print(f"Data Sensitivity: {user_context.data_sensitivity}")
        print(f"Performance Priority: {user_context.performance_priority}")
        if user_context.compliance_requirements:
            print(f"Compliance Requirements: {', '.join(user_context.compliance_requirements)}")
        if user_context.preferred_algorithms:
            print(f"Preferred Algorithms: {', '.join(user_context.preferred_algorithms)}")
        if user_context.avoided_algorithms:
            print(f"Avoided Algorithms: {', '.join(user_context.avoided_algorithms)}")
        print()


def _handle_recommendations_feedback(engine, args):
    """Handle feedback submission."""
    user_id = getattr(args, "user_id", "default")
    rec_id = args.recommendation_id
    accepted = args.accepted
    feedback_text = getattr(args, "comment", None)

    engine.record_feedback(user_id, rec_id, accepted, feedback_text)

    status = "accepted" if accepted else "rejected"
    print(f"✅ Feedback recorded: Recommendation {rec_id} was {status}")
    if feedback_text:
        print(f"Comment: {feedback_text}")


def _handle_recommendations_quick(engine, args):
    """Handle quick recommendations command."""
    use_case = args.use_case
    experience_level = getattr(args, "experience_level", "intermediate")

    quick_recs = engine.get_quick_recommendations(use_case, experience_level)

    print(f"⚡ QUICK RECOMMENDATIONS FOR {use_case.upper()}")
    print("=" * 50)
    print()

    for rec in quick_recs:
        print(rec)
        print()

    print("💬 For detailed recommendations with explanations, use 'smart-recommendations get'")


def _display_recommendation(rec, number: int):
    """Display a single recommendation with formatting."""
    # Priority icon
    priority_icons = {"info": "ℹ️", "low": "🔷", "medium": "🔶", "high": "🔺", "critical": "🚨"}

    # Confidence indicator
    confidence_indicators = {1: "⭐", 2: "⭐⭐", 3: "⭐⭐⭐", 4: "⭐⭐⭐⭐", 5: "⭐⭐⭐⭐⭐"}

    priority_icon = priority_icons.get(rec.priority.value, "🔷")
    confidence_stars = confidence_indicators.get(rec.confidence.value, "⭐⭐⭐")

    print(f"{number}. {priority_icon} {rec.title}")
    print(f"   📝 {rec.description}")
    print(f"   💡 Action: {rec.action}")
    print(
        f"   🎯 Confidence: {confidence_stars} | Difficulty: {rec.implementation_difficulty} | Impact: {rec.estimated_impact}"
    )

    if rec.reasoning:
        print(f"   🤔 Reasoning: {rec.reasoning}")

    if rec.evidence:
        print("   📊 Evidence:")
        for evidence in rec.evidence:
            print(f"      • {evidence}")

    if rec.trade_offs:
        print("   ⚖️  Trade-offs:")
        for aspect, impact in rec.trade_offs.items():
            print(f"      • {aspect.title()}: {impact}")

    print(f"   🏷️  Category: {rec.category.value} | ID: {rec.id}")
    print()


def run_security_tests(args):
    """Run security test suites."""
    try:
        from .testing import SecurityTestRunner, TestExecutionPlan, TestSuiteType

        # Create test runner
        runner = SecurityTestRunner()

        # Get test action
        test_action = getattr(args, "test_action", None)

        if not test_action:
            print("No test action specified. Use --help for available options.")
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
            print(f"Unknown test action: {test_action}")
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
        print(f"🔒 Starting OpenSSL Encrypt Security Tests - {test_action.upper()}")
        print("=" * 60)
        print()

        report = runner.run_tests(execution_plan)

        # Display summary
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)

        summary = report.overall_summary
        print(f"Total Suites: {summary['total_suites']}")
        print(f"Successful Suites: {summary['successful_suites']}")
        print(f"Suite Success Rate: {summary['suite_success_rate']:.1f}%")
        print(f"Total Tests: {summary['total_tests']}")
        print(f"Passed Tests: {summary['passed_tests']}")
        print(f"Warning Tests: {summary['warning_tests']}")
        print(f"Failed Tests: {summary['error_tests']}")
        print(f"Test Success Rate: {summary['test_success_rate']:.1f}%")
        print(f"Total Duration: {report.total_duration:.1f} seconds")

        # Show report locations
        if output_dir:
            print(f"\n📁 Reports saved to: {output_dir}")
            for fmt in output_formats:
                filename = f"security_test_report_{report.run_id}.{fmt}"
                print(f"   • {fmt.upper()}: {filename}")

        print("\n✅ Testing completed!")

    except ImportError as e:
        print(f"Error: Testing framework not available: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error running security tests: {e}")
        if hasattr(args, "debug") and args.debug:
            import traceback

            traceback.print_exc()
        sys.exit(1)


def _handle_template_list(template_mgr: TemplateManager, args):
    """Handle template list command."""
    category = getattr(args, "category", None)
    if category:
        category = TemplateCategory(category)

    templates = template_mgr.list_templates(category)

    if not templates:
        print("No templates found.")
        return

    print("📋 AVAILABLE TEMPLATES")
    print("=" * 50)
    print()

    current_category = None
    for template in templates:
        # Group by category
        if template.metadata.category != current_category:
            current_category = template.metadata.category
            print(f"\n🏷️  {current_category.value.upper().replace('_', ' ')}")
            print("-" * 30)

        # Display template info
        security_icon = _get_security_icon(template.metadata.security_level)
        print(f"\n{security_icon} {template.metadata.name}")
        print(f"   Description: {template.metadata.description}")
        print(
            f"   Security: {template.metadata.security_level} ({template.metadata.security_score:.1f}/10)"
        )
        if template.metadata.use_cases:
            print(f"   Use Cases: {', '.join(template.metadata.use_cases)}")
        if template.metadata.tags:
            print(f"   Tags: {', '.join(template.metadata.tags)}")

        if hasattr(args, "verbose") and args.verbose:
            print(f"   Author: {template.metadata.author}")
            print(f"   Created: {template.metadata.created_date}")
            if not template.is_built_in and template.file_path:
                print(f"   File: {template.file_path}")


def _handle_template_create(template_mgr: TemplateManager, args):
    """Handle template creation from current configuration."""
    name = getattr(args, "template_name", None)
    if not name:
        print("Error: Template name is required for creation.")
        sys.exit(1)

    description = getattr(args, "description", "")
    use_cases = getattr(args, "use_cases", [])

    # Create template from current CLI args
    template = template_mgr.create_template_from_args(args, name, description, use_cases)

    # Validate template
    is_valid, errors = template_mgr.validate_template(template)
    if not is_valid:
        print("❌ Template validation failed:")
        for error in errors:
            print(f"   • {error}")
        sys.exit(1)

    # Save template
    try:
        output_format = TemplateFormat(getattr(args, "format", "json"))
        filepath = template_mgr.save_template(template, format=output_format)

        print("✅ Template created successfully!")
        print(f"📁 Saved to: {filepath}")
        print(
            f"🔒 Security Level: {template.metadata.security_level} ({template.metadata.security_score:.1f}/10)"
        )

        if use_cases:
            print(f"🎯 Use Cases: {', '.join(use_cases)}")

    except FileExistsError as e:
        print(f"❌ {e}")
        print("Use --overwrite to replace existing template.")
        sys.exit(1)


def _handle_template_analyze(template_mgr: TemplateManager, args):
    """Handle template analysis command."""
    template_name = getattr(args, "template_name", None)
    if not template_name:
        print("Error: Template name is required for analysis.")
        sys.exit(1)

    template = template_mgr.get_template_by_name(template_name)
    if not template:
        print(f"❌ Template '{template_name}' not found.")
        sys.exit(1)

    report = template_mgr.generate_template_report(template)

    print("🔍 TEMPLATE ANALYSIS REPORT")
    print("=" * 50)
    print(f"\n📋 Template: {template.metadata.name}")
    print(f"📝 Description: {template.metadata.description}")
    print(f"👤 Author: {template.metadata.author}")
    print(f"📅 Created: {template.metadata.created_date}")

    # Validation status
    validation = report["validation"]
    if validation["is_valid"]:
        print("\n✅ VALIDATION: PASSED")
    else:
        print("\n❌ VALIDATION: FAILED")
        for error in validation["errors"]:
            print(f"   • {error}")

    # Analysis results
    if "analysis" in report and "overall_score" in report["analysis"]:
        analysis = report["analysis"]
        security_icon = _get_security_icon(analysis["security_level"])

        print("\n🔒 SECURITY ANALYSIS")
        print(f"   {security_icon} Overall Score: {analysis['overall_score']:.1f}/10")
        print(f"   🛡️  Security Level: {analysis['security_level']}")

        if "performance" in analysis:
            perf = analysis["performance"]
            print("\n🚀 PERFORMANCE ANALYSIS")
            print(
                f"   ⚡ Speed Rating: {perf['estimated_relative_speed'].replace('_', ' ').title()}"
            )
            print(f"   💾 Memory Usage: {perf['memory_requirements']['estimated_peak_mb']}MB")
            print(f"   🖥️  CPU Intensity: {perf['cpu_intensity'].replace('_', ' ').title()}")

        if "recommendations" in analysis and analysis["recommendations"]:
            print("\n💡 RECOMMENDATIONS:")
            for i, rec in enumerate(analysis["recommendations"][:3], 1):  # Show top 3
                priority_icon = (
                    "🚨"
                    if rec["priority"] == "critical"
                    else "⚠️"
                    if rec["priority"] == "high"
                    else "💡"
                )
                print(f"   {i}. {priority_icon} {rec['title']}")
                print(f"      {rec['description']}")
                print(f"      Action: {rec['action']}")


def _handle_template_compare(template_mgr: TemplateManager, args):
    """Handle template comparison command."""
    template1_name = getattr(args, "template1", None)
    template2_name = getattr(args, "template2", None)

    if not template1_name or not template2_name:
        print("Error: Both template names are required for comparison.")
        sys.exit(1)

    template1 = template_mgr.get_template_by_name(template1_name)
    template2 = template_mgr.get_template_by_name(template2_name)

    if not template1:
        print(f"❌ Template '{template1_name}' not found.")
        sys.exit(1)
    if not template2:
        print(f"❌ Template '{template2_name}' not found.")
        sys.exit(1)

    comparison = template_mgr.compare_templates(template1, template2)

    print("🔄 TEMPLATE COMPARISON")
    print("=" * 50)

    t1_data = comparison["templates"]["template1"]
    t2_data = comparison["templates"]["template2"]

    print("\n📊 OVERVIEW")
    print(
        f"   Template 1: {t1_data['name']} ({t1_data['security_level']}, {t1_data['security_score']:.1f}/10)"
    )
    print(
        f"   Template 2: {t2_data['name']} ({t2_data['security_level']}, {t2_data['security_score']:.1f}/10)"
    )

    print("\n🔒 SECURITY COMPARISON")
    print(f"   {comparison['security_comparison']['verdict']}")

    if "performance_comparison" in comparison:
        print("\n🚀 PERFORMANCE COMPARISON")
        print(f"   {comparison['performance_comparison']['verdict']}")

    # Use case comparison
    common_use_cases = set(t1_data["use_cases"]) & set(t2_data["use_cases"])
    if common_use_cases:
        print(f"\n🎯 COMMON USE CASES: {', '.join(common_use_cases)}")


def _handle_template_recommend(template_mgr: TemplateManager, args):
    """Handle template recommendation command."""
    use_case = getattr(args, "use_case", None)
    if not use_case:
        print("Error: Use case is required for recommendations.")
        sys.exit(1)

    recommendations = template_mgr.recommend_templates(use_case)

    if not recommendations:
        print(f"No template recommendations found for use case: {use_case}")
        return

    print(f"💡 TEMPLATE RECOMMENDATIONS FOR '{use_case.upper()}'")
    print("=" * 50)

    for i, (template, reason) in enumerate(recommendations, 1):
        security_icon = _get_security_icon(template.metadata.security_level)
        print(f"\n{i}. {security_icon} {template.metadata.name}")
        print(f"   📝 {template.metadata.description}")
        print(
            f"   🔒 Security: {template.metadata.security_level} ({template.metadata.security_score:.1f}/10)"
        )
        print(f"   ✨ Reason: {reason}")

        if template.is_built_in:
            print("   📦 Type: Built-in template")
        else:
            print(f"   📁 Type: {template.metadata.category.value.replace('_', ' ').title()}")


def _handle_template_delete(template_mgr: TemplateManager, args):
    """Handle template deletion command."""
    template_name = getattr(args, "template_name", None)
    if not template_name:
        print("Error: Template name is required for deletion.")
        sys.exit(1)

    template = template_mgr.get_template_by_name(template_name)
    if not template:
        print(f"❌ Template '{template_name}' not found.")
        sys.exit(1)

    if template.is_built_in:
        print(f"❌ Cannot delete built-in template '{template_name}'.")
        sys.exit(1)

    # Confirm deletion unless forced
    if not getattr(args, "force", False):
        confirm = input(f"⚠️  Are you sure you want to delete template '{template_name}'? [y/N]: ")
        if confirm.lower() != "y":
            print("Deletion cancelled.")
            return

    if template_mgr.delete_template(template):
        print(f"✅ Template '{template_name}' deleted successfully.")
    else:
        print(f"❌ Failed to delete template '{template_name}'.")
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

    # Import FIDO2 plugin
    try:
        from ..plugins.hsm.fido2_pepper import FIDO2_AVAILABLE, FIDO2HSMPlugin
    except ImportError:
        print("❌ Error: FIDO2 library not available")
        print("Install with: pip install fido2>=1.1.0")
        sys.exit(1)

    if not FIDO2_AVAILABLE:
        print("❌ Error: FIDO2 library not available")
        print("Install with: pip install fido2>=1.1.0")
        sys.exit(1)

    # Get HSM action
    action = args.hsm_action

    # Get optional rp_id
    rp_id = getattr(args, "rp_id", None)

    # Initialize plugin
    plugin = FIDO2HSMPlugin(rp_id=rp_id) if rp_id else FIDO2HSMPlugin()

    if action == "fido2-register":
        # Register new FIDO2 credential
        print("\n🔐 FIDO2 Credential Registration")
        print("=" * 50)

        description = getattr(args, "description", None)
        backup = getattr(args, "backup", False)

        if backup:
            print("📦 Registering backup credential...")
        else:
            print("🔑 Registering primary credential...")

        if description:
            print(f"Description: {description}")

        print("\nPlease insert your FIDO2 security key and follow the prompts.")
        print("You will need to:")
        print("  1. Touch your security key")
        print("  2. Enter your security key PIN (if configured)\n")

        # Initialize plugin
        init_result = plugin.initialize()
        if not init_result.success:
            print(f"❌ Error: {init_result.message}")
            sys.exit(1)

        # Register credential
        result = plugin.register_credential(description=description, is_backup=backup)

        if result.success:
            print(f"\n✅ {result.message}")
            print(f"\nCredential ID: {result.data.get('credential_id')}")
            print(f"Configuration saved to: {plugin.credential_file}")
            print("\nYou can now use this credential with:")
            print("  openssl_encrypt encrypt --hsm fido2 <file>")
        else:
            print(f"\n❌ Registration failed: {result.message}")
            sys.exit(1)

    elif action == "fido2-status":
        # Show FIDO2 registration status
        print("\n🔐 FIDO2 Registration Status")
        print("=" * 50)

        if not plugin.is_registered():
            print("❌ No FIDO2 credentials registered")
            print("\nTo register a credential, run:")
            print("  openssl_encrypt hsm fido2-register --description 'My Security Key'")
            sys.exit(0)

        # Load credentials
        credentials = plugin._load_credentials()

        print(f"✅ {len(credentials)} credential(s) registered")
        print(f"Configuration file: {plugin.credential_file}")
        print(f"Relying Party ID: {plugin.rp_id}\n")

        # Display each credential
        for i, cred in enumerate(credentials, 1):
            print(f"Credential #{i}:")
            print(f"  ID: {cred['id']}")
            print(f"  Description: {cred.get('description', 'N/A')}")
            print(f"  Created: {cred.get('created_at', 'N/A')}")
            print(f"  AAGUID: {cred.get('authenticator_aaguid', 'N/A')}")
            print(f"  Backup: {'Yes' if cred.get('is_backup', False) else 'No'}")
            print()

    elif action == "fido2-test":
        # Test FIDO2 pepper derivation
        print("\n🔐 FIDO2 Pepper Derivation Test")
        print("=" * 50)

        # Initialize plugin
        init_result = plugin.initialize()
        if not init_result.success:
            print(f"❌ Error: {init_result.message}")
            sys.exit(1)

        if not plugin.is_registered():
            print("❌ No FIDO2 credentials registered")
            print("\nRegister a credential first:")
            print("  openssl_encrypt hsm fido2-register")
            sys.exit(1)

        # Generate random test salt
        test_salt = secrets.token_bytes(16)
        print(f"Test salt: {test_salt.hex()}")
        print("\nPlease insert your FIDO2 security key and follow the prompts.")
        print("You will need to:")
        print("  1. Touch your security key")
        print("  2. Enter your security key PIN (if configured)\n")

        # Create dummy security context
        from ..modules.plugin_system.plugin_base import PluginSecurityContext

        context = PluginSecurityContext(
            plugin_id=plugin.plugin_id, capabilities=plugin.get_required_capabilities()
        )

        # Test pepper derivation
        result = plugin.get_hsm_pepper(test_salt, context)

        if result.success:
            pepper = result.data.get("hsm_pepper")
            print(f"\n✅ Test successful!")
            print(f"Pepper length: {len(pepper)} bytes")
            print(f"Pepper (hex): {pepper.hex()}")
            print("\nYour FIDO2 credential is working correctly.")
        else:
            print(f"\n❌ Test failed: {result.message}")
            sys.exit(1)

    elif action == "fido2-list":
        # List connected FIDO2 devices
        print("\n🔐 Connected FIDO2 Devices")
        print("=" * 50)

        devices = plugin.list_devices()

        if not devices:
            print("❌ No FIDO2 devices found")
            print("\nPlease connect a FIDO2 security key (YubiKey, Nitrokey, etc.)")
            sys.exit(0)

        print(f"Found {len(devices)} device(s):\n")

        for i, device in enumerate(devices, 1):
            if "error" in device:
                print(f"Device #{i}: {device.get('product_name', 'Unknown')}")
                print(f"  Error: {device['error']}\n")
                continue

            print(f"Device #{i}: {device.get('product_name', 'Unknown')}")
            print(f"  Manufacturer: {device.get('manufacturer', 'Unknown')}")
            print(f"  AAGUID: {device.get('aaguid', 'Unknown')}")
            print(f"  Versions: {', '.join(device.get('versions', []))}")
            print(f"  Extensions: {', '.join(device.get('extensions', []))}")

            # Highlight hmac-secret support
            hmac_support = device.get("hmac_secret_support", False)
            if hmac_support:
                print(f"  hmac-secret: ✅ Supported")
            else:
                print(f"  hmac-secret: ❌ Not supported")

            print()

    elif action == "fido2-unregister":
        # Remove FIDO2 credential(s)
        print("\n🔐 FIDO2 Credential Removal")
        print("=" * 50)

        if not plugin.is_registered():
            print("❌ No FIDO2 credentials registered")
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

            confirmation = input(prompt).strip().lower()
            if confirmation != "y":
                print("Operation cancelled.")
                sys.exit(0)

        # Unregister
        result = plugin.unregister(credential_id=credential_id, remove_all=remove_all)

        if result.success:
            print(f"\n✅ {result.message}")

            if remove_all:
                print(f"Configuration file removed: {plugin.credential_file}")
            else:
                print(f"Configuration updated: {plugin.credential_file}")
        else:
            print(f"\n❌ Removal failed: {result.message}")
            sys.exit(1)

    else:
        print(f"❌ Unknown HSM action: {action}")
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
        print(f"Error: Keyserver plugin not available: {e}")
        return

    # Get configuration
    try:
        config = KeyserverConfig.from_file()
    except Exception as e:
        print(f"Error: Failed to load keyserver configuration: {e}")
        return

    # Handle subcommands
    action = args.keyserver_action

    if action == "enable":
        # Enable keyserver
        config.enabled = True
        try:
            config.to_file()
            print("✓ Keyserver plugin enabled")
            print(f"  Servers: {', '.join(config.servers)}")
            print("  Use 'openssl-encrypt keyserver status' to verify configuration")
        except Exception as e:
            print(f"✗ Failed to enable keyserver: {e}")

    elif action == "disable":
        # Disable keyserver
        config.enabled = False
        try:
            config.to_file()
            print("✓ Keyserver plugin disabled")
        except Exception as e:
            print(f"✗ Failed to disable keyserver: {e}")

    elif action == "status":
        # Show keyserver status
        plugin = KeyserverPlugin(config)
        cache_stats = plugin.get_cache_stats()

        print("\nKEYSERVER STATUS")
        print("=" * 60)
        print(f"Enabled: {'Yes' if config.enabled else 'No'}")
        print(f"Servers: {', '.join(config.servers)}")
        print(
            f"Cache TTL: {config.cache_ttl_seconds} seconds ({config.cache_ttl_seconds // 3600} hours)"
        )
        print(f"Cache Max Entries: {config.cache_max_entries}")
        print(f"Upload Enabled: {'Yes' if config.upload_enabled else 'No'}")
        print(f"API Token: {'Present' if config.load_api_token() else 'Not set'}")
        print()
        print("CACHE STATISTICS")
        print("-" * 60)
        print(f"Total Entries: {cache_stats['total_entries']}")
        print(f"Valid Entries: {cache_stats['valid_entries']}")
        print(f"Expired Entries: {cache_stats['expired_entries']}")
        print(f"Total Accesses: {cache_stats['total_accesses']}")
        if cache_stats["most_accessed"]:
            print(
                f"Most Accessed: {cache_stats['most_accessed']['name']} ({cache_stats['most_accessed']['count']} times)"
            )
        print("=" * 60)

    elif action == "register":
        # Register with keyserver and obtain API token
        if not config.enabled:
            print("✗ Keyserver plugin is disabled. Enable with: openssl-encrypt keyserver enable")
            return

        plugin = KeyserverPlugin(config)

        # Use custom server if specified
        server_url = args.server if hasattr(args, "server") and args.server else None

        try:
            print("Registering with keyserver...")
            result = plugin.register(server_url=server_url)

            print("\n✓ Successfully registered with keyserver")
            print("=" * 60)
            print(f"Client ID:   {result['client_id']}")
            print(f"Expires:     {result['expires_at']}")
            print(f"Token Type:  {result['token_type']}")
            print(f"Token File:  {config.api_token_file}")
            print("=" * 60)
            print("\nAPI token has been securely saved.")
            print("You can now upload and revoke keys using:")
            print("  openssl-encrypt keyserver upload <identity>")
            print("  openssl-encrypt keyserver revoke <fingerprint>")

        except Exception as e:
            print(f"\n✗ Registration failed: {e}")
            print("\nTroubleshooting:")
            print("  - Check network connectivity")
            print("  - Verify keyserver URL is correct")
            print(
                f"  - Server: {server_url or config.servers[0] if config.servers else 'Not configured'}"
            )

    elif action == "search":
        # Search for key on keyserver
        if not config.enabled:
            print("✗ Keyserver plugin is disabled. Enable with: openssl-encrypt keyserver enable")
            return

        plugin = KeyserverPlugin(config)
        identifier = args.identifier

        print(f"Searching for '{identifier}' on keyserver...")
        bundle = plugin.fetch_key(identifier)

        if bundle:
            if args.json:
                print(json.dumps(bundle.to_dict(), indent=2))
            else:
                print("\n✓ Key found")
                print("-" * 60)
                print(f"Name:        {bundle.name}")
                print(f"Email:       {bundle.email or 'N/A'}")
                print(f"Fingerprint: {bundle.fingerprint}")
                print(f"Algorithms:  {bundle.encryption_algorithm} / {bundle.signing_algorithm}")
                print(f"Created:     {bundle.created_at}")
                print("-" * 60)
        else:
            print(f"✗ Key not found for '{identifier}'")

    elif action == "import":
        # Import key from keyserver
        if not config.enabled:
            print("✗ Keyserver plugin is disabled. Enable with: openssl-encrypt keyserver enable")
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
            print(f"✓ Successfully imported '{identity.name}' to local store")
            print(f"  Fingerprint: {identity.fingerprint}")
        except KeyNotFoundError:
            print(f"✗ Key not found for '{args.identifier}'")
        except TrustDeclinedError:
            print("✗ Import cancelled (user declined to trust key)")
        except Exception as e:
            print(f"✗ Failed to import key: {e}")

    elif action == "upload":
        # Upload key to keyserver
        if not config.enabled:
            print("✗ Keyserver plugin is disabled. Enable with: openssl-encrypt keyserver enable")
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
                print(f"✗ Identity '{identity_name}' not found")
                return

            if not identity.is_own_identity:
                print(f"✗ Cannot upload '{identity_name}': not your own identity (no private keys)")
                return

            # Create bundle
            bundle = PublicKeyBundle.from_identity(identity)

            # Upload
            print(f"Uploading '{identity_name}' to keyserver...")
            success = plugin.upload_key(bundle)

            if success:
                print(f"✓ Successfully uploaded '{identity_name}'")
                print(f"  Fingerprint: {bundle.fingerprint}")
            else:
                print(f"✗ Failed to upload '{identity_name}'")

        except Exception as e:
            print(f"✗ Failed to upload key: {e}")

    elif action == "revoke":
        # Revoke key on keyserver
        print("✗ Key revocation not yet implemented")
        print("  (Requires revocation signature generation)")

    elif action == "set-token":
        # Set API token
        token = args.token
        try:
            config.save_api_token(token)
            print("✓ API token saved securely")
            print(f"  Token file: {config.api_token_file}")
            print("  Permissions: 0600 (owner read/write only)")
        except Exception as e:
            print(f"✗ Failed to save API token: {e}")

    elif action == "show-token":
        # Show API token (masked)
        token = config.load_api_token()
        if token:
            # Mask token (show first 8 and last 4 characters)
            if len(token) > 12:
                masked = token[:8] + "*" * (len(token) - 12) + token[-4:]
            else:
                masked = "*" * len(token)
            print(f"API Token: {masked}")
            print(f"Token file: {config.api_token_file}")
        else:
            print("✗ No API token set")
            print("  Use: openssl-encrypt keyserver set-token <token>")

    elif action == "clear-token":
        # Delete API token
        try:
            if config.clear_api_token():
                print("✓ API token deleted")
            else:
                print("No API token to delete")
        except Exception as e:
            print(f"✗ Failed to delete API token: {e}")

    elif action == "cache-clear":
        # Clear cache
        plugin = KeyserverPlugin(config)
        count = plugin.cache.get_pending_count()

        if count == 0:
            print("Cache is already empty")
            return

        if not args.force:
            response = input(f"Clear {count} cached keys? (yes/no): ")
            if response.lower() not in ["yes", "y"]:
                print("Cancelled")
                return

        cleared = plugin.clear_cache()
        print(f"✓ Cleared {cleared} cached keys")

    elif action == "cache-stats":
        # Show cache statistics
        plugin = KeyserverPlugin(config)
        stats = plugin.get_cache_stats()

        print("\nKEYSERVER CACHE STATISTICS")
        print("=" * 60)
        print(f"Total Entries: {stats['total_entries']}")
        print(f"Valid Entries: {stats['valid_entries']}")
        print(f"Expired Entries: {stats['expired_entries']}")
        print(f"Max Entries: {stats['max_entries']}")
        print(f"TTL: {stats['ttl_seconds']} seconds ({stats['ttl_seconds'] // 3600} hours)")
        print(f"Total Accesses: {stats['total_accesses']}")

        if stats["most_accessed"]:
            print(
                f"Most Accessed Key: {stats['most_accessed']['name']} ({stats['most_accessed']['count']} times)"
            )

        print(f"Cache Path: {stats['cache_path']}")
        print("=" * 60)

    else:
        print(f"Unknown keyserver action: {action}")


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
        print("Error: Telemetry plugin not available.")
        print(f"Details: {e}")
        return

    # Get or create telemetry plugin instance
    try:
        plugin = OpenSSLEncryptTelemetryPlugin()
    except Exception as e:
        print(f"Error: Failed to initialize telemetry plugin: {e}")
        return

    # Handle subcommands
    action = args.telemetry_action

    if action == "status":
        # Show telemetry status
        status = plugin.get_status()
        print("\nTELEMETRY STATUS")
        print("=" * 60)
        print(f"Enabled: {'Yes' if status['enabled'] else 'No'}")
        print(f"Pending Events: {status['pending_events']}")
        print(f"Server URL: {status['server_url']}")
        print(f"API Key: {'Present' if status['has_api_key'] else 'Not registered'}")
        print(
            f"Upload Interval: {status['upload_interval']} seconds ({status['upload_interval'] // 3600} hours)"
        )
        print(f"Background Upload: {'Running' if status['upload_thread_alive'] else 'Stopped'}")
        print("=" * 60)

    elif action == "show-pending":
        # Show pending events (transparency)
        events = plugin.get_pending_events(limit=args.limit)

        if not events:
            print("No pending telemetry events.")
            return

        if args.json:
            # JSON output
            import json

            print(json.dumps(events, indent=2))
        else:
            # Human-readable output
            print(f"\nPENDING TELEMETRY EVENTS (showing {min(len(events), args.limit)} events)")
            print("=" * 80)

            for i, event in enumerate(events[: args.limit], 1):
                print(f"\n--- Event {i} (ID: {event.get('id', 'N/A')}) ---")
                print(f"  Timestamp: {event.get('timestamp', 'N/A')}")
                print(f"  Operation: {event.get('operation', 'N/A')}")
                print(f"  Mode: {event.get('mode', 'N/A')}")
                print(f"  Format Version: {event.get('format_version', 'N/A')}")
                print(f"  Encryption: {event.get('encryption_algorithm', 'N/A')}")
                print(f"  Hash Algorithms: {', '.join(event.get('hash_algorithms', []))}")
                print(f"  KDF Algorithms: {', '.join(event.get('kdf_algorithms', []))}")

                if event.get("cascade_enabled"):
                    print(f"  Cascade: Enabled ({event.get('cascade_cipher_count', 0)} ciphers)")

                if event.get("pqc_kem_algorithm"):
                    print(f"  PQC KEM: {event.get('pqc_kem_algorithm')}")

                if event.get("pqc_signing_algorithm"):
                    print(f"  PQC Signing: {event.get('pqc_signing_algorithm')}")

                if event.get("hsm_plugin_used"):
                    print(f"  HSM Plugin: {event.get('hsm_plugin_used')}")

                print(f"  Success: {event.get('success', True)}")

                if event.get("error_category"):
                    print(f"  Error Category: {event.get('error_category')}")

                print(f"  Retry Count: {event.get('retry_count', 0)}")

            print("\n" + "=" * 80)
            print(f"Total pending events: {plugin.buffer.get_pending_count()}")

    elif action == "flush":
        # Upload all pending events immediately
        print("Uploading pending telemetry events...")
        result = plugin.flush()

        if result.success:
            print(f"✓ {result.message}")
        else:
            print(f"✗ {result.message}")

    elif action == "clear":
        # Delete all pending events without uploading
        pending_count = plugin.buffer.get_pending_count()

        if pending_count == 0:
            print("No pending events to clear.")
            return

        if not args.force:
            response = input(f"Delete {pending_count} pending events without uploading? (yes/no): ")
            if response.lower() not in ["yes", "y"]:
                print("Cancelled.")
                return

        deleted = plugin.buffer.clear_all()
        print(f"✓ Deleted {deleted} pending events.")

    elif action == "opt-out":
        # Complete opt-out: disable telemetry and delete all data
        pending_count = plugin.buffer.get_pending_count()

        if not args.force:
            print("\n⚠️  OPT-OUT WARNING ⚠️")
            print("This will:")
            print("  1. Disable telemetry collection")
            print(f"  2. Delete {pending_count} pending events")
            print("  3. Delete your API key")
            print("  4. Stop background uploads")
            print()
            response = input("Are you sure you want to opt out? (yes/no): ")
            if response.lower() not in ["yes", "y"]:
                print("Cancelled.")
                return

        result = plugin.opt_out()

        if result.success:
            print(f"✓ {result.message}")
            print("\nTelemetry has been completely disabled.")
            print("To re-enable, use: --telemetry flag or set OPENSSL_ENCRYPT_TELEMETRY=1")
        else:
            print(f"✗ {result.message}")

    else:
        print(f"Unknown telemetry action: {action}")


def main():
    """
    Main function that handles the command-line interface.
    """
    # Preprocess arguments to move global flags to the front
    import sys

    sys.argv = preprocess_global_args(sys.argv)

    # After preprocessing, global flags are moved to the front when they appear after the command.
    # Check if position 1 is a subcommand to decide which parser to use.
    # This allows backward compatibility: when global flags are BEFORE the command,
    # the monolithic parser is used (which has all arguments).
    subparser_commands = [
        "encrypt",
        "decrypt",
        "shred",
        "generate-password",
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
        "version",
        "show-version-file",
        "create-usb",
        "verify-usb",
        "list-plugins",
        "plugin-info",
        "enable-plugin",
        "disable-plugin",
        "reload-plugin",
        "telemetry",
        "keyserver",
        "hsm",
    ]

    # Use subparser only if a subcommand is present
    # (after global flags have been moved to the front by preprocess_global_args)
    # Find the first non-flag argument (skip global flags)
    global_flags = {"--progress", "--verbose", "--debug", "--quiet", "--yes", "-y"}
    first_command = None
    for i in range(1, len(sys.argv)):
        arg = sys.argv[i]
        # Skip global flags
        if arg in global_flags:
            continue
        # Found a non-flag argument
        if not arg.startswith("-"):
            first_command = arg
            break

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
            print("Error: Steganography requires additional dependencies.")
            print("Install with: pip install Pillow numpy")
        return None
    except Exception as e:
        if not quiet:
            print(f"Error loading steganography plugin: {e}")
        return None


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
                        print(f"Cleaned up temporary file: {temp_file}")
            except Exception:
                pass

    def cleanup_all():
        """Clean up temporary files and environment variables"""
        cleanup_temp_files()
        clear_password_environment()

    # Register cleanup function to run on normal exit
    atexit.register(cleanup_all)

    # Register signal handlers for common termination signals
    def signal_handler(signum, frame):
        cleanup_temp_files()
        # Re-raise the signal to allow the default handler to run
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    # Register handlers for common termination signals
    for sig in [signal.SIGINT, signal.SIGTERM, signal.SIGHUP]:
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
    global_group.add_argument("--verbose", action="store_true", help="Show hash/kdf details")
    global_group.add_argument(
        "--debug",
        action="store_true",
        help="Show detailed debug information (WARNING: logs passwords and sensitive data - test files only!)",
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
        "-t",
        "--template",
        help="Specify a template name (built-in or from ./template directory)",
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
            "shred",
            "generate-password",
            "security-info",
            "analyze-security",
            "config-wizard",
            "check-argon2",
            "check-pqc",
            "version",
            "show-version-file",
            "create-usb",
            "verify-usb",
            "list-plugins",
            "plugin-info",
            "enable-plugin",
            "disable-plugin",
            "reload-plugin",
        ],
        help="Action to perform: encrypt/decrypt files, shred data, generate passwords, "
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
        default=128,
        help="Scrypt CPU/memory cost factor N (default: 0, not used. Use power of 2 like 16384)",
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
        "--keystore-path", dest="keystore", help="Path to the keystore file (alias for --keystore)"
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
        "--use-digits", action="store_true", help="Include digits in generated password"
    )
    password_group.add_argument(
        "--use-lowercase",
        action="store_true",
        help="Include lowercase letters in generated password",
    )
    password_group.add_argument(
        "--use-uppercase",
        action="store_true",
        help="Include uppercase letters in generated password",
    )
    password_group.add_argument(
        "--use-special",
        action="store_true",
        help="Include special characters in generated password",
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
        "Supported: 'yubikey' (YubiKey Challenge-Response), 'fido2' (FIDO2 hmac-secret). "
        "The HSM adds a hardware-specific pepper to the key derivation, requiring the device "
        "for both encryption and decryption.",
    )
    plugin_group.add_argument(
        "--hsm-slot",
        type=int,
        choices=[1, 2],
        metavar="SLOT",
        help="Manually specify Yubikey slot (1 or 2) for Challenge-Response. "
        "If not specified, the plugin will auto-detect the configured slot.",
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
            for error in alias_errors:
                print(f"Error: {error}", file=sys.stderr)
            sys.exit(1)

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
    }

    for attr, default_val in default_attrs.items():
        if not hasattr(args, attr):
            setattr(args, attr, default_val)

    # Store the original user-provided algorithm name from command line
    import sys

    original_algorithm = None
    for i, arg in enumerate(sys.argv):
        if arg == "--algorithm" and i + 1 < len(sys.argv):
            original_algorithm = sys.argv[i + 1]
            break

    # Configure logging level based on debug flag
    if args.debug:
        import logging

        # Configure the root logger to DEBUG level
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)

        # Also configure this module's logger explicitly
        logger.setLevel(logging.DEBUG)

        # Try to configure basic config for new handlers, but don't fail if handlers exist
        try:
            logging.basicConfig(
                level=logging.DEBUG, format="%(levelname)s - %(name)s - %(message)s"
            )
        except Exception:
            pass

        # Security warning for debug mode
        print("\n" + "=" * 78)
        print("⚠️  WARNING: DEBUG MODE ENABLED - SENSITIVE DATA LOGGING ACTIVE")
        print("=" * 78)
        print("Debug mode logs sensitive information including:")
        print("  • Password hex dumps during key derivation")
        print("  • Detailed cryptographic operation traces")
        print("  • Internal state information")
        print()
        print("SECURITY NOTICE:")
        print("  ❌ DO NOT use --debug with production data or real passwords")
        print("  ✅ Only use for testing with dummy/test data")
        print("  ⚠️  Debug logs may be stored in log files or terminal history")
        print("=" * 78 + "\n")

        print(f"DEBUG: sys.argv = {sys.argv}")

        # Enable raw exception passthrough in debug mode
        set_debug_mode(True)
        print("DEBUG: Raw exception passthrough enabled")

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
        print(show_version_info())
        return 0

    if args.action == "show-version-file":
        try:
            from openssl_encrypt.version import get_version_info, print_version_info

            # Call print_version_info function to show detailed version information
            print_version_info()

            # Additionally, show the full version info dictionary
            version_info = get_version_info()
            print("\nComplete Version Information:")
            print("----------------------------")
            for key, value in version_info.items():
                if key == "history":
                    # Skip history as it was already printed by print_version_info
                    continue
                print(f"{key}: {value}")

            return 0
        except ImportError:
            print("Version module not found. Run 'pip install -e .' to generate the version file.")
            return 1

    # Handle USB operations
    if args.action == "create-usb":
        try:
            from .portable_media import create_portable_usb

            # Validate required arguments
            if not getattr(args, "usb_path", None):
                print("Error: --usb-path is required for create-usb operation")
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
            if hasattr(args, "pbkdf2_iterations") and args.pbkdf2_iterations:
                hash_config["pbkdf2_iterations"] = args.pbkdf2_iterations

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
            result = create_portable_usb(
                usb_path=args.usb_path,
                password=args.password,
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
                print(f"✓ Successfully created portable USB at: {result['usb_path']}")
                print(f"  Security Profile: {result['security_profile']}")
                print(f"  Portable Root: {result['portable_root']}")
                if result["executable"]["included"]:
                    print(f"  Executable: {result['executable']['path']}")
                if result["keystore"]["included"]:
                    print("  Keystore: Encrypted and included")
                print(f"  Auto-run files: {', '.join(result['autorun']['files_created'])}")
                if result.get("manifest", {}).get("created"):
                    manifest_info = result["manifest"]
                    print(
                        f"  Hash Manifest: {manifest_info['files_covered']} files, {manifest_info['hash_algorithm']}"
                    )
                    print(
                        f"    Password: {manifest_info['password_type']}, Profile: {manifest_info.get('security_profile', 'default')}"
                    )
                    print("    Manual verification: VERIFY_INTEGRITY.md")
                return 0
            else:
                print("✗ Failed to create portable USB")
                return 1

        except ImportError:
            print("Error: Portable media module not available")
            return 1
        except Exception as e:
            print(f"Error creating USB: {e}")
            return 1

    elif args.action == "verify-usb":
        try:
            from .portable_media import verify_usb_integrity

            # Validate required arguments
            if not getattr(args, "usb_path", None):
                print("Error: --usb-path is required for verify-usb operation")
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
                print("✓ USB integrity verification PASSED")
                print(f"  Files verified: {result['verified_files']}")
                print(
                    f"  Created at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result['created_at']))}"
                )
                return 0
            else:
                print("✗ USB integrity verification FAILED")
                print(f"  Files verified: {result['verified_files']}")
                print(f"  Failed files: {result['failed_files']}")
                print(f"  Missing files: {result['missing_files']}")
                if result["tampered_files"]:
                    print(f"  Tampered files: {', '.join(result['tampered_files'])}")
                if result["missing_file_list"]:
                    print(f"  Missing files: {', '.join(result['missing_file_list'])}")
                return 1

        except ImportError:
            print("Error: Portable media module not available")
            return 1
        except Exception as e:
            print(f"Error verifying USB: {e}")
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
        run_template_manager(args)
        sys.exit(0)

    elif args.action == "smart-recommendations":
        run_smart_recommendations(args)
        sys.exit(0)

    elif args.action == "test":
        run_security_tests(args)
        sys.exit(0)

    elif args.action == "identity":
        from .identity_cli import main as identity_main

        sys.exit(identity_main(args))

    elif args.action == "telemetry":
        handle_telemetry_command(args)
        sys.exit(0)

    elif args.action == "keyserver":
        handle_keyserver_command(args)
        sys.exit(0)

    elif args.action == "hsm":
        handle_hsm_command(args)
        sys.exit(0)

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
        print("\nARGON2 SUPPORT CHECK")
        print("====================")
        if argon2_available:
            print(f"✓ Argon2 is AVAILABLE (version {version})")
            variants = ", ".join("Argon2" + t for t in supported_types)
            print(f"✓ Supported variants: {variants}")

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
                    print("✓ Argon2 functionality test: PASSED")
                else:
                    print("✗ Argon2 functionality test: FAILED (unexpected hash length)")
            except Exception as e:
                print(f"✗ Argon2 functionality test: FAILED with error: {e}")
        else:
            print("✗ Argon2 is NOT AVAILABLE")
            print("\nTo enable Argon2 support, install the argon2-cffi package:")
            print("    pip install argon2-cffi")
        sys.exit(0)

    elif args.action == "check-pqc":
        from .pqc import PQCAlgorithm, check_pqc_support

        pqc_available, version, supported_algorithms = check_pqc_support(quiet=args.quiet)
        if not args.quiet:
            print("\nPOST-QUANTUM CRYPTOGRAPHY SUPPORT CHECK")
            print("======================================")
        if pqc_available:
            if not args.quiet:
                print(f"✓ Post-quantum cryptography is AVAILABLE (liboqs version {version})")
                print("✓ Supported algorithms:")

                # Organize algorithms by type
                kems = [algo for algo in supported_algorithms if "Kyber" in algo]
                sigs = [algo for algo in supported_algorithms if "Kyber" not in algo]

                if kems:
                    print("\n  Key Encapsulation Mechanisms (KEMs):")
                    for algo in kems:
                        print(f"    - {algo}")

                if sigs:
                    print("\n  Digital Signature Algorithms:")
                    for algo in sigs:
                        print(f"    - {algo}")

            # Try a test encryption to verify functionality
            try:
                from .pqc import PQCipher

                test_cipher = PQCipher(PQCAlgorithm.KYBER768, quiet=args.quiet)
                public_key, private_key = test_cipher.generate_keypair()
                test_data = b"Test post-quantum encryption"
                encrypted = test_cipher.encrypt(test_data, public_key)
                decrypted = test_cipher.decrypt(encrypted, private_key)

                if decrypted == test_data:
                    print("\n✓ Post-quantum encryption functionality test: PASSED")
                else:
                    print(
                        "\n✗ Post-quantum encryption functionality test: FAILED (decryption mismatch)"
                    )
            except Exception as e:
                print(f"\n✗ Post-quantum encryption functionality test: FAILED with error: {e}")
        else:
            print("✗ Post-quantum cryptography is NOT AVAILABLE")
            print(
                "\nTo enable post-quantum cryptography support, install the liboqs-python package:"
            )
            print("    pip install liboqs-python")

        print("\nUsage examples:")
        print("  Encrypt with Kyber-768 (NIST Level 3):")
        print("    python -m openssl_encrypt.crypt encrypt -i file.txt --algorithm kyber768-hybrid")
        print("\n  Generate and save a key pair:")
        print(
            "    python -m openssl_encrypt.crypt encrypt -i file.txt --algorithm kyber768-hybrid --pqc-gen-key --pqc-keyfile key.pqc"
        )
        print("\n  Decrypt using a saved key pair:")
        print(
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
                print(f"Discovered {len(discovered)} plugin files")

            # Load plugins
            for plugin_file in discovered:
                load_result = plugin_manager.load_plugin(plugin_file)
                if not load_result.success and not args.quiet:
                    print(f"⚠️  Failed to load {plugin_file}: {load_result.message}")

            # List loaded plugins
            plugins = plugin_manager.list_plugins()
            if not plugins:
                print("No plugins loaded")
            else:
                print("\nLoaded Plugins:")
                print("=" * 50)
                for plugin in plugins:
                    status = "🟢 Enabled" if plugin["enabled"] else "🔴 Disabled"
                    print(f"{status} {plugin['name']} (v{plugin['version']})")
                    print(f"    ID: {plugin['id']}")
                    print(f"    Type: {plugin['type']}")
                    print(f"    Description: {plugin['description']}")
                    print(f"    Capabilities: {', '.join(plugin['capabilities'])}")
                    if plugin.get("usage_count", 0) > 0:
                        print(
                            f"    Usage: {plugin['usage_count']} executions, {plugin.get('error_count', 0)} errors"
                        )
                    print()

            sys.exit(0)

        except ImportError:
            print("❌ Plugin system not available")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error listing plugins: {e}")
            sys.exit(1)

    elif args.action == "plugin-info":
        if not args.plugin_id:
            print("❌ Plugin ID required for plugin-info command (use --plugin-id)")
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
                print(f"❌ Plugin not found: {args.plugin_id}")
                sys.exit(1)

            # Show detailed plugin information
            print(f"\nPlugin Information: {args.plugin_id}")
            print("=" * 50)
            print(f"Name: {plugin_info['name']}")
            print(f"Version: {plugin_info['version']}")
            print(f"Type: {plugin_info['type']}")
            print(f"Description: {plugin_info['description']}")
            print(f"Status: {'🟢 Enabled' if plugin_info['enabled'] else '🔴 Disabled'}")
            print(f"File: {plugin_info['file_path']}")
            print(f"Capabilities: {', '.join(plugin_info['capabilities'])}")
            print(
                f"Load Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(plugin_info['load_time']))}"
            )

            if plugin_info.get("last_used"):
                print(
                    f"Last Used: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(plugin_info['last_used']))}"
                )

            if plugin_info.get("usage_count", 0) > 0:
                print("Usage Statistics:")
                print(f"  - Total executions: {plugin_info['usage_count']}")
                print(f"  - Errors: {plugin_info.get('error_count', 0)}")
                success_rate = (
                    (plugin_info["usage_count"] - plugin_info.get("error_count", 0))
                    / plugin_info["usage_count"]
                ) * 100
                print(f"  - Success rate: {success_rate:.1f}%")

            sys.exit(0)

        except ImportError:
            print("❌ Plugin system not available")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error getting plugin info: {e}")
            sys.exit(1)

    elif args.action == "enable-plugin":
        if not args.plugin_id:
            print("❌ Plugin ID required for enable-plugin command (use --plugin-id)")
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
                print(f"✅ Plugin {args.plugin_id} enabled successfully")
            else:
                print(f"❌ Failed to enable plugin: {result.message}")
                sys.exit(1)

            sys.exit(0)

        except ImportError:
            print("❌ Plugin system not available")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error enabling plugin: {e}")
            sys.exit(1)

    elif args.action == "disable-plugin":
        if not args.plugin_id:
            print("❌ Plugin ID required for disable-plugin command (use --plugin-id)")
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
                print(f"✅ Plugin {args.plugin_id} disabled successfully")
            else:
                print(f"❌ Failed to disable plugin: {result.message}")
                sys.exit(1)

            sys.exit(0)

        except ImportError:
            print("❌ Plugin system not available")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error disabling plugin: {e}")
            sys.exit(1)

    elif args.action == "reload-plugin":
        if not args.plugin_id:
            print("❌ Plugin ID required for reload-plugin command (use --plugin-id)")
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
                print(f"✅ Plugin {args.plugin_id} reloaded successfully")
            else:
                print(f"❌ Failed to reload plugin: {result.message}")
                sys.exit(1)

            sys.exit(0)

        except ImportError:
            print("❌ Plugin system not available")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error reloading plugin: {e}")
            sys.exit(1)

    elif args.action == "generate-password":
        # If no character sets are explicitly selected, use all by default
        if not (args.use_lowercase or args.use_uppercase or args.use_digits or args.use_special):
            args.use_lowercase = True
            args.use_uppercase = True
            args.use_digits = True
            args.use_special = True

        # Apply password policy if specified
        if args.password_policy != "none" and not args.force_password:
            # Create policy to get minimum required length
            policy_params = {}
            if args.min_password_length is not None:
                policy_params["min_length"] = args.min_password_length

            policy = PasswordPolicy(policy_level=args.password_policy, **policy_params)

            # Ensure length meets policy requirements
            if args.length < policy.min_length:
                print(
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

        # Check password strength
        entropy, strength = get_password_strength(password)
        print(f"\nPassword strength: {strength} (entropy: {entropy:.1f} bits)")

        # Validate against policy
        if args.password_policy != "none":
            policy_params = {}
            if args.min_password_entropy is not None:
                policy_params["min_entropy"] = args.min_password_entropy

            if args.disable_common_password_check:
                policy_params["check_common_passwords"] = False

            if args.custom_password_list:
                policy_params["common_passwords_path"] = args.custom_password_list

            # Create policy
            policy = PasswordPolicy(policy_level=args.password_policy, **policy_params)

            # Check if generated password meets policy (it should, but verify)
            valid, _ = policy.validate_password(password, quiet=True)
            if not valid:
                # This is rare but could happen with specific combinations of constraints
                print("Warning: Generated password does not meet policy requirements.")
                print("Consider adjusting character requirements or using a longer length.")

        # Display the password
        display_password_with_timeout(password)
        # Exit after generating password
        sys.exit(0)

    # For other actions, input file is required
    if getattr(args, "input", None) is None and args.action not in [
        "generate-password",
        "security-info",
        "analyze-security",
        "config-wizard",
        "analyze-config",
        "template",
        "smart-recommendations",
        "check-argon2",
        "check-pqc",
        "version",
        "show-version-file",
    ]:
        parser.error("the following arguments are required: --input/-i")

    # Handle stdin input FIRST - convert to temp file to avoid multiple reads
    # This must happen BEFORE detect_encryption_type() which would consume stdin
    if args.action == "decrypt" and getattr(args, "input", None) == "/dev/stdin":
        import tempfile

        # Read stdin once into a temp file
        stdin_temp_file_early = tempfile.NamedTemporaryFile(delete=False)
        os.chmod(stdin_temp_file_early.name, 0o600)  # Security: Restrict to user read/write only
        temp_files_to_cleanup.append(stdin_temp_file_early.name)

        # Copy all data from stdin to temp file
        stdin_data = sys.stdin.buffer.read()
        if args.debug:
            print(f"DEBUG: Read {len(stdin_data)} bytes from stdin (early)", file=sys.stderr)
        stdin_temp_file_early.write(stdin_data)
        stdin_temp_file_early.close()

        # Update args.input to point to the temp file for all subsequent operations
        args.input = stdin_temp_file_early.name
        if args.debug:
            print(f"DEBUG: Converted stdin to temp file: {args.input}", file=sys.stderr)

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
                print(f"DEBUG: Auto-detection failed: {e}")
            encryption_info = {"type": "symmetric", "format_version": 0}

        if encryption_info and encryption_info["type"] == "asymmetric":
            # Find matching identity in keystore
            from .identity_cli import get_identity_store

            store_path = resolve_identity_store_path(args)
            store = get_identity_store(store_path)

            matching = store.find_by_fingerprints(encryption_info["recipient_fingerprints"])

            if len(matching) == 0:
                # No matching identity found
                print(
                    "ERROR: This file is encrypted asymmetrically but no matching identity found.",
                    file=sys.stderr,
                )
                print("\nFile was encrypted for:", file=sys.stderr)
                for fp in encryption_info["recipient_fingerprints"]:
                    print(f"  • {fp}", file=sys.stderr)
                print(
                    "\nTo decrypt, you need one of these identities in your keystore.",
                    file=sys.stderr,
                )
                print(
                    "Import the private key or use --with-key to specify an identity.",
                    file=sys.stderr,
                )
                sys.exit(1)
            else:
                # Use first matching identity
                args.key_identity = matching[0].name
                if not args.quiet:
                    print(f"Using identity '{args.key_identity}' for decryption")

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
    if args.action in ["encrypt", "decrypt"]:
        validation_warnings = validate_algorithm_availability(args)
        if validation_warnings and not args.quiet:
            print("\nWARNING: Some requested algorithms are not available:")
            for warning in validation_warnings:
                print(f"  ⚠ {warning}")
            print("\nUse 'list-algorithms' command to see available algorithms.")
            print("Install required packages or choose different algorithms.\n")

    if args.action in ["encrypt", "decrypt"] and not (
        is_asymmetric_encrypt or is_asymmetric_decrypt
    ):
        password = None
        generated_password = None

        try:
            from .secure_memory import secure_string

            # Initialize a secure string to hold the password
            with secure_string() as password_secure:
                # Handle random password generation for encryption
                if args.action == "encrypt" and args.random and not args.password:
                    # Determine character sets based on args or defaults
                    use_lowercase = args.use_lowercase if args.use_lowercase is not None else True
                    use_uppercase = args.use_uppercase if args.use_uppercase is not None else True
                    use_digits = args.use_digits if args.use_digits is not None else True
                    use_special = args.use_special if args.use_special is not None else True

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
                                print(
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
                                    print(f"\n{msg}")

                    password_secure.extend(generated_password.encode())
                    if not args.quiet:
                        print("\nGenerated a random password for encryption.")

                # Check for password from environment variable first
                elif os.environ.get("CRYPT_PASSWORD"):
                    # Get password from environment variable
                    env_password = os.environ.get("CRYPT_PASSWORD")

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
                                print(
                                    f"\nPassword strength: {strength} (entropy: {entropy:.1f} bits)"
                                )
                                print(f"Password validation failed: {str(e)}")
                                print("Use --force-password to bypass validation (not recommended)")
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
                                print(
                                    f"\nPassword strength: {strength} (entropy: {entropy:.1f} bits)"
                                )
                                print(f"Password validation failed: {str(e)}")
                                print("Use --force-password to bypass validation (not recommended)")
                            sys.exit(1)

                    password_secure.extend(args.password.encode())

                # If no password provided yet, prompt the user
                else:
                    # For encryption, require password confirmation to
                    # prevent typos
                    if args.action == "encrypt" and not args.quiet:
                        match = False
                        while not match:
                            pwd1 = getpass.getpass("Enter password: ").encode()
                            pwd2 = getpass.getpass("Confirm password: ").encode()

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

                                        if args.disable_common_password_check:
                                            policy_params["check_common_passwords"] = False

                                        if args.custom_password_list:
                                            policy_params[
                                                "common_passwords_path"
                                            ] = args.custom_password_list

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
                                        print(
                                            f"\nPassword strength: {strength} (entropy: {entropy:.1f} bits)"
                                        )
                                        print(f"Password validation failed: {str(e)}")
                                        print(
                                            "Use --force-password to bypass validation (not recommended)"
                                        )
                                        valid_password = False

                                if valid_password:
                                    password_secure.extend(pwd1)
                                    match = True

                                # Securely clear the temporary buffers
                                pwd1 = "\x00" * len(pwd1)
                                pwd2 = "\x00" * len(pwd2)
                            else:
                                # Securely clear the temporary buffers
                                pwd1 = "\x00" * len(pwd1)
                                pwd2 = "\x00" * len(pwd2)
                                print("Passwords do not match. Please try again.")
                    # For decryption or quiet mode, just ask once
                    else:
                        # Always prompt for a password, even in quiet mode
                        # We need to show the prompt but we can hide any extra text
                        pwd = getpass.getpass("Enter password: ")

                        # In quiet mode, move up one line and clear it after getting the password
                        if args.quiet:
                            sys.stdout.write("\033[A\033[K")
                            sys.stdout.flush()

                        password_secure.extend(pwd.encode("utf-8"))
                        # Securely clear the temporary buffer
                        pwd = "\x00" * len(pwd)

                # Convert to bytes for the rest of the code
                password = bytes(password_secure)

        except ImportError:
            # Fall back to standard method if secure_memory is not
            # available
            if not args.quiet:
                print("Warning: secure_memory module not available")
            sys.exit(1)

    # Check for Whirlpool availability if needed and not in quiet mode
    if args.whirlpool_rounds > 0 and not WHIRLPOOL_AVAILABLE and not args.quiet:
        print("Warning: pywhirlpool module not found. SHA-512 will be used instead.")

    # Check for Argon2 availability if needed
    if (args.enable_argon2 or args.argon2_preset) and not ARGON2_AVAILABLE:
        if not args.quiet:
            print("Warning: argon2-cffi module not found. Argon2 will be disabled.")
            print("Install with: pip install argon2-cffi")
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
                print(
                    "Warning: liboqs-python module not found. Post-quantum cryptography will not be available."
                )
                print("Install with: pip install liboqs-python")
                print("Falling back to aes-gcm algorithm.")
            args.algorithm = "aes-gcm"

    # Validate random password parameter
    if args.random is not None:
        if args.action != "encrypt":
            parser.error("--random can only be used with the encrypt action")
        if args.password:
            parser.error("--password and --random cannot be used together")
        if args.random < 12:
            if not args.quiet:
                print("Warning: Random password length increased to 12 (minimum secure length)")
            args.random = 12

    # Set default iterations if SHA algorithms are requested but no iterations
    # provided
    MIN_SHA_ITERATIONS = 1000000

    # If user specified to use SHA-256, SHA-512, or SHA3 but didn't provide
    # iterations
    if args.sha512_rounds == 1:  # When flag is provided without value
        args.sha512_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA-512")

    if args.sha384_rounds == 1:  # When flag is provided without value
        args.sha384_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA-384")

    if args.sha256_rounds == 1:  # When flag is provided without value
        args.sha256_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA-256")

    if args.sha224_rounds == 1:  # When flag is provided without value
        args.sha224_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA-224")

    if args.sha3_512_rounds == 1:  # When flag is provided without value
        args.sha3_512_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA3-512")

    if args.sha3_384_rounds == 1:  # When flag is provided without value
        args.sha3_384_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA3-384")

    if args.sha3_256_rounds == 1:  # When flag is provided without value
        args.sha3_256_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA3-256")

    if args.sha3_224_rounds == 1:  # When flag is provided without value
        args.sha3_224_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHA3-224")

    if args.blake2b_rounds == 1:  # When flag is provided without value
        args.blake2b_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(f"Using default of {MIN_SHA_ITERATIONS} iterations for BLAKE2b")

    if args.blake3_rounds == 1:  # When flag is provided without value
        args.blake3_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(f"Using default of {MIN_SHA_ITERATIONS} iterations for BLAKE3")

    if args.shake256_rounds == 1:  # When flag is provided without value
        args.shake256_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHAKE-256")

    if args.shake128_rounds == 1:  # When flag is provided without value
        args.shake128_rounds = MIN_SHA_ITERATIONS
        if not args.quiet:
            print(f"Using default of {MIN_SHA_ITERATIONS} iterations for SHAKE-128")

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
            print(f"Using Argon2 preset '{args.argon2_preset}' with parameters:")
            print(f"  - Time cost: {args.argon2_time}")
            print(f"  - Memory: {args.argon2_memory} KB")
            print(f"  - Parallelism: {args.argon2_parallelism}")
            print(f"  - Hash length: {args.argon2_hash_len} bytes")
            print(f"  - Type: Argon2{args.argon2_type}")

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
        hash_config = hash_config["hash_config"]
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
            hash_config = hash_config["hash_config"]
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
                    "n": args.scrypt_n if args.scrypt_n is not None else 0,
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
                        print(f"⚠️  Failed to load plugin {plugin_file}: {load_result.message}")

                if args.verbose and not args.quiet:
                    loaded_count = len(plugin_manager.list_plugins())
                    if loaded_count > 0:
                        print(f"🔌 Plugin system initialized with {loaded_count} plugins")

            except ImportError:
                if args.verbose and not args.quiet:
                    print("⚠️  Plugin system not available")
                plugin_manager = None
                enable_plugins = False
            except Exception as e:
                if not args.quiet:
                    print(f"⚠️  Plugin system error: {e}")
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
                        print(f"Error initializing HSM plugin: {init_result.message}")
                        sys.exit(1)

                    if not args.quiet:
                        print(f"✅ Loaded HSM plugin: {hsm_plugin_instance.name}")
                        if hasattr(args, "hsm_slot") and args.hsm_slot:
                            print(f"   Using manual slot: {args.hsm_slot}")
                        else:
                            print("   Auto-detecting Challenge-Response slot")

                elif args.hsm.lower() == "fido2":
                    from ..plugins.hsm.fido2_pepper import FIDO2HSMPlugin

                    hsm_plugin_instance = FIDO2HSMPlugin()

                    # Initialize plugin
                    init_result = hsm_plugin_instance.initialize({})
                    if not init_result.success:
                        print(f"Error initializing HSM plugin: {init_result.message}")
                        sys.exit(1)

                    if not args.quiet:
                        print(f"✅ Loaded HSM plugin: {hsm_plugin_instance.name}")
                        print(f"   RP ID: {hsm_plugin_instance.rp_id}")
                        if not hsm_plugin_instance.is_registered():
                            print(
                                "   ⚠️  No credentials registered. Run: openssl_encrypt hsm fido2-register"
                            )

                else:
                    print(f"Error: Unknown HSM plugin '{args.hsm}'. Supported: yubikey, fido2")
                    sys.exit(1)

            except ImportError as e:
                print(f"Error: Could not import HSM plugin: {e}")
                if args.hsm.lower() == "yubikey":
                    print(
                        "Make sure yubikey-manager is installed: pip install -r requirements-hsm.txt"
                    )
                elif args.hsm.lower() == "fido2":
                    print("Make sure fido2 library is installed: pip install fido2>=1.1.0")
                sys.exit(1)
            except Exception as e:
                print(f"Error initializing HSM plugin: {e}")
                sys.exit(1)

        # Load pepper plugin if requested
        pepper_plugin_instance = None
        pepper_name_to_use = None
        if hasattr(args, "pepper") and args.pepper:
            try:
                from ..plugins.pepper import PepperConfig, PepperError, PepperPlugin

                config = PepperConfig.from_file()
                if not config.enabled:
                    print("ERROR: --pepper flag used but pepper plugin not configured")
                    print(f"Configure at: {PepperConfig.get_default_config_path()}")
                    sys.exit(1)

                pepper_plugin_instance = PepperPlugin(config)

                # Auto-generate mode: don't set pepper_name_to_use (leave as None)
                # The core encryption logic will generate a new pepper and determine the name
                pepper_name_to_use = None

                if not args.quiet:
                    print(f"Pepper plugin enabled (auto-generate mode)")

            except ImportError as e:
                print(f"ERROR: Could not import pepper plugin: {e}")
                print("Make sure pepper plugin is properly installed")
                sys.exit(1)
            except Exception as e:
                print(f"ERROR: Pepper plugin initialization failed: {e}")
                sys.exit(1)

        elif hasattr(args, "pepper_name") and args.pepper_name:
            try:
                from ..plugins.pepper import PepperConfig, PepperError, PepperPlugin

                config = PepperConfig.from_file()
                if not config.enabled:
                    print("ERROR: --pepper-name flag used but pepper plugin not configured")
                    print(f"Configure at: {PepperConfig.get_default_config_path()}")
                    sys.exit(1)

                pepper_plugin_instance = PepperPlugin(config)
                pepper_name_to_use = args.pepper_name

                if not args.quiet:
                    print(f"Pepper plugin enabled (using existing pepper: {pepper_name_to_use})")

            except ImportError as e:
                print(f"ERROR: Could not import pepper plugin: {e}")
                print("Make sure pepper plugin is properly installed")
                sys.exit(1)
            except Exception as e:
                print(f"ERROR: Pepper plugin initialization failed: {e}")
                sys.exit(1)

        if args.action == "encrypt":
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
                                print(
                                    "🔑 Keyserver enabled: will fetch public keys from remote if not found locally"
                                )
                        else:
                            if not args.quiet:
                                print(
                                    "⚠️  Keyserver is disabled. Enable with: openssl-encrypt keyserver enable"
                                )
                    except ImportError:
                        if not args.quiet:
                            print("⚠️  Keyserver plugin not available")
                    except Exception as e:
                        if not args.quiet:
                            print(f"⚠️  Failed to initialize keyserver: {e}")

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
                        print(
                            f"ERROR: Recipient identity '{recipient_name}' not found ❌",
                            file=sys.stderr,
                        )
                        sys.exit(1)
                    except TrustDeclinedError:
                        print(f"ERROR: Trust declined for '{recipient_name}' ❌", file=sys.stderr)
                        sys.exit(1)
                    except KeyError as e:
                        print(f"ERROR: {e} ❌", file=sys.stderr)
                        sys.exit(1)
                    except Exception as e:
                        error_msg = f"ERROR: Failed to load identity '{recipient_name}'"
                        if str(e):
                            error_msg += f": {e}"
                        error_msg += " ❌"
                        print(error_msg, file=sys.stderr)
                        sys.exit(1)

                # Load sender
                if not hasattr(args, "sign_with") or not args.sign_with:
                    print("ERROR: --sign-with required for asymmetric encryption", file=sys.stderr)
                    sys.exit(1)

                # First load identity metadata to check protection level
                sender_metadata = store.get_by_name(args.sign_with, load_private_keys=False)
                if sender_metadata is None:
                    print(f"ERROR: Sender identity '{args.sign_with}' not found ❌", file=sys.stderr)
                    sys.exit(1)

                # Determine if passphrase is needed
                from .identity_protection import ProtectionLevel

                sender_passphrase = None
                if (
                    not sender_metadata.protection
                    or sender_metadata.protection.level != ProtectionLevel.HSM_ONLY
                ):
                    sender_passphrase = getpass.getpass(
                        f"Passphrase for sender identity '{args.sign_with}': "
                    )

                try:
                    sender = store.get_by_name(
                        args.sign_with, passphrase=sender_passphrase, load_private_keys=True
                    )
                    if sender is None:
                        print(
                            f"ERROR: Sender identity '{args.sign_with}' not found ❌",
                            file=sys.stderr,
                        )
                        sys.exit(1)
                except Exception as e:
                    error_msg = f"ERROR: Failed to load identity '{args.sign_with}'"
                    if str(e):
                        error_msg += f": {e}"
                    error_msg += " ❌"
                    print(error_msg, file=sys.stderr)
                    sys.exit(1)
                finally:
                    # Clean up passphrase from memory
                    if "sender_passphrase" in locals() and sender_passphrase:
                        from .secure_memory import secure_memzero

                        secure_memzero(sender_passphrase)

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
                        "r": getattr(args, "scrypt_r", 8) if hasattr(args, "scrypt_r") else 8,
                        "p": getattr(args, "scrypt_p", 1) if hasattr(args, "scrypt_p") else 1,
                        "rounds": getattr(args, "scrypt_rounds", 1)
                        if hasattr(args, "scrypt_rounds")
                        else 1,
                    },
                    "argon2": {
                        "enabled": getattr(args, "enable_argon2", False),
                        "time_cost": getattr(args, "argon2_time", 3)
                        if hasattr(args, "argon2_time")
                        else 3,
                        "memory_cost": getattr(args, "argon2_memory", 65536)
                        if hasattr(args, "argon2_memory")
                        else 65536,
                        "parallelism": getattr(args, "argon2_parallelism", 4)
                        if hasattr(args, "argon2_parallelism")
                        else 4,
                        "hash_len": getattr(args, "argon2_hash_len", 32)
                        if hasattr(args, "argon2_hash_len")
                        else 32,
                        "type": ARGON2_TYPE_INT_MAP.get(getattr(args, "argon2_type", "id"), 2),
                        "rounds": getattr(args, "argon2_rounds", 0) or 0,
                    },
                    "balloon": {
                        "enabled": getattr(args, "enable_balloon", False)
                        or getattr(args, "use_balloon", False),
                        "space_cost": getattr(args, "balloon_space_cost", 1024)
                        if hasattr(args, "balloon_space_cost")
                        else 1024,
                        "time_cost": getattr(args, "balloon_time_cost", 1)
                        if hasattr(args, "balloon_time_cost")
                        else 1,
                        "parallelism": getattr(args, "balloon_parallelism", 1)
                        if hasattr(args, "balloon_parallelism")
                        else 1,
                        "rounds": getattr(args, "balloon_rounds", 1)
                        if hasattr(args, "balloon_rounds")
                        else 1,
                    },
                    "hkdf": {
                        "enabled": getattr(args, "enable_hkdf", False),
                        "rounds": getattr(args, "hkdf_rounds", 1)
                        if hasattr(args, "hkdf_rounds")
                        else 1,
                    },
                    "randomx": {
                        "enabled": getattr(args, "enable_randomx", False),
                        "mode": getattr(args, "randomx_mode", "light")
                        if hasattr(args, "randomx_mode")
                        else "light",
                        "height": getattr(args, "randomx_height", 1)
                        if hasattr(args, "randomx_height")
                        else 1,
                        "hash_len": getattr(args, "randomx_hash_len", 32)
                        if hasattr(args, "randomx_hash_len")
                        else 32,
                        "rounds": getattr(args, "randomx_rounds", 1)
                        if hasattr(args, "randomx_rounds")
                        else 1,
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
                    )

                    # Handle temp file if overwrite mode
                    if args.overwrite and temp_output != output_file:
                        import shutil

                        shutil.move(temp_output, output_file)

                    if not args.quiet:
                        print("\nAsymmetric encryption successful! ✅")
                        print(
                            f"File size: {result['original_size']} bytes → {result['encrypted_size']} bytes (encrypted)"
                        )
                        print(f"Encrypted file: {output_file}")

                    # Shred original if requested
                    if args.shred:
                        from .crypt_utils import shred_file

                        shred_file(args.input, passes=args.shred_passes)

                    sys.exit(0)

                except Exception as e:
                    print(f"ERROR: Asymmetric encryption failed: {e}", file=sys.stderr)
                    if args.debug:
                        import traceback

                        traceback.print_exc()
                    sys.exit(1)

            # DEPRECATED: Whirlpool is no longer supported for new encryptions
            if hasattr(args, "whirlpool_rounds") and getattr(args, "whirlpool_rounds", 0) > 0:
                print("ERROR: Whirlpool is deprecated for new encryptions.")
                print("Please use BLAKE2b, BLAKE3, or SHA-3 instead.")
                print("Existing files encrypted with Whirlpool can still be decrypted.")
                sys.exit(1)

            # DEPRECATED: PBKDF2 is no longer supported for new encryptions
            if hasattr(args, "pbkdf2_iterations") and getattr(args, "pbkdf2_iterations", 0) > 0:
                print("ERROR: PBKDF2 is deprecated for new encryptions.")
                print("Please use Argon2, Scrypt, or Balloon hashing instead.")
                print("Existing files encrypted with PBKDF2 can still be decrypted.")
                sys.exit(1)

            # DEPRECATED: Kyber algorithms are no longer supported for new encryptions
            # Only warn if user actually used the old Kyber names, not if they used ML-KEM names
            kyber_algorithms = ["kyber512-hybrid", "kyber768-hybrid", "kyber1024-hybrid"]
            ml_kem_algorithms = ["ml-kem-512-hybrid", "ml-kem-768-hybrid", "ml-kem-1024-hybrid"]

            # Check if this algorithm was originally an ML-KEM name that got converted
            original_ml_kem_algorithm = os.environ.get("OPENSSL_ENCRYPT_ORIGINAL_MLKEM_ALGORITHM")

            # Check the original user input, not the mapped algorithm
            user_provided_algorithm = original_algorithm or args.algorithm
            if args.debug:
                print(f"DEBUG: args.algorithm = {args.algorithm}")
                print(f"DEBUG: original_algorithm = {original_algorithm}")
                print(f"DEBUG: original_ml_kem_algorithm = {original_ml_kem_algorithm}")
                print(f"DEBUG: user_provided_algorithm = {user_provided_algorithm}")
                print(
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
                print(f"ERROR: {args.algorithm} is deprecated for new encryptions.")
                print(f"Please use {recommended} instead (NIST standardized equivalent).")
                print(f"Existing files encrypted with {args.algorithm} can still be decrypted.")
                sys.exit(1)

            # Enforce deprecation policy: Block encryption with deprecated algorithms in version 1.2.0
            if is_encryption_blocked_for_algorithm(args.algorithm):
                error_message = get_encryption_block_message(args.algorithm)
                print(f"ERROR: {error_message}")
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
                    print(f"Warning: The algorithm '{args.algorithm}' is deprecated.")
                    print(f"Consider using '{replacement}' instead for better security.")

            # Enforce deprecation policy for PQC data encryption algorithms
            if args.algorithm.endswith("-hybrid") and is_encryption_blocked_for_algorithm(
                args.encryption_data
            ):
                data_error_message = get_encryption_block_message(args.encryption_data)
                print(f"ERROR: PQC data encryption - {data_error_message}")
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
                    print(
                        f"Warning: The data encryption algorithm '{args.encryption_data}' is deprecated."
                    )
                    print(f"Consider using '{data_replacement}' instead for better security.")

            # Handle output file path
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
                    # Handle PQC key operations
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

                            # Choose first available or fall back to default name
                            kyber512_algo = kyber512_options[0] if kyber512_options else "Kyber512"
                            kyber768_algo = kyber768_options[0] if kyber768_options else "Kyber768"
                            kyber1024_algo = (
                                kyber1024_options[0] if kyber1024_options else "Kyber1024"
                            )
                            hqc128_algo = hqc128_options[0] if hqc128_options else "HQC-128"
                            hqc192_algo = hqc192_options[0] if hqc192_options else "HQC-192"
                            hqc256_algo = hqc256_options[0] if hqc256_options else "HQC-256"

                            if not args.quiet:
                                print(
                                    f"Using algorithm mappings: kyber512-hybrid → {kyber512_algo}, kyber768-hybrid → {kyber768_algo}, kyber1024-hybrid → {kyber1024_algo}, hqc-128-hybrid → {hqc128_algo}, hqc-192-hybrid → {hqc192_algo}, hqc-256-hybrid → {hqc256_algo}"
                                )

                            # Create direct string mapping instead of using enum
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

                            key_data = {
                                "algorithm": args.algorithm,
                                "public_key": base64.b64encode(public_key).decode("utf-8"),
                                "private_key": base64.b64encode(private_key).decode("utf-8"),
                            }

                            with open(args.pqc_keyfile, "w") as f:
                                json.dump(key_data, f)

                            if not args.quiet:
                                print(f"Post-quantum key pair saved to {args.pqc_keyfile}")

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
                                    print(f"Error: PQC key file validation failed: {e}")
                                    sys.exit(1)
                                except ImportError:
                                    # Fallback to basic JSON loading if validator not available
                                    try:
                                        key_data = json.loads(json_content)
                                    except json.JSONDecodeError as e:
                                        print(f"Error: Invalid JSON in PQC key file: {e}")
                                        sys.exit(1)

                            if "public_key" in key_data and "private_key" in key_data:
                                public_key = base64.b64decode(key_data["public_key"])
                                private_key = base64.b64decode(key_data["private_key"])
                                pqc_keypair = (public_key, private_key)

                                if not args.quiet:
                                    print(f"Loaded post-quantum key pair from {args.pqc_keyfile}")

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
                            print(
                                f"Generating ephemeral post-quantum key pair for {args.algorithm}"
                            )
                            if args.pqc_store_key:
                                # Only log this message with INFO level so it only appears in verbose mode
                                logger.info(
                                    "Private key will be stored in the encrypted file for self-decryption"
                                )
                            else:
                                # Keep this as a print since it's a warning
                                print(
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
                                    print(
                                        f"Keystore not found at {args.keystore}, creating a new one"
                                    )
                                create_new = True
                            else:
                                # Prompt the user if they want to create a new keystore or abort
                                if not args.quiet:
                                    print(f"Keystore not found at {args.keystore}")
                                    print(
                                        "Use --auto-create-keystore option to automatically create keystore"
                                    )
                                    create_prompt = (
                                        input("Would you like to create a new keystore? (y/n): ")
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
                                            print(
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
                                            print("Passwords do not match")
                                        raise ValueError("Keystore passwords do not match")

                                # Create the keystore
                                keystore = PQCKeystore(args.keystore)
                                keystore.create_keystore(
                                    keystore_password, KeystoreSecurityLevel.STANDARD
                                )
                                if not args.quiet:
                                    print(f"Created new keystore at {args.keystore}")
                            else:
                                # Abort
                                if not args.quiet:
                                    print(
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
                                    print(
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
                                    print("Auto-generating key for keystore")
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
                                    print(
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
                                        print(
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
                                    print(
                                        f"Using cascade preset '{args.cascade}': {' → '.join(cipher_names)}"
                                    )
                            else:
                                if not args.quiet:
                                    available_presets = ", ".join(CASCADE_PRESETS.keys())
                                    print(
                                        f"Error: Unknown cascade preset '{args.cascade}'. "
                                        f"Available: {available_presets}",
                                        file=sys.stderr,
                                    )
                                return 1

                            # Validate minimum 2 ciphers
                            if len(cipher_names) < 2:
                                if not args.quiet:
                                    print(
                                        "Error: Cascade mode requires at least 2 ciphers",
                                        file=sys.stderr,
                                    )
                                return 1

                            # Validate that all ciphers exist and are available
                            for cipher_name in cipher_names:
                                if not registry.exists(cipher_name):
                                    available = ", ".join(registry.list_names())
                                    if not args.quiet:
                                        print(
                                            f"Error: Unknown cipher '{cipher_name}'. "
                                            f"Available: {available}",
                                            file=sys.stderr,
                                        )
                                    return 1

                                if not registry.is_available(cipher_name):
                                    if not args.quiet:
                                        print(
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
                                                print(
                                                    f"\033[91mERROR:\033[0m {warning.message}",
                                                    file=sys.stderr,
                                                )
                                        elif warning.level == DiversityWarningLevel.WARNING:
                                            has_warning = True
                                            if not args.quiet:
                                                print(
                                                    f"\033[93mWARNING:\033[0m {warning.message}",
                                                    file=sys.stderr,
                                                )
                                        else:  # INFO
                                            if not args.quiet:
                                                print(
                                                    f"\033[94mINFO:\033[0m {warning.message}",
                                                    file=sys.stderr,
                                                )

                                        # Display suggestion if available
                                        if warning.suggestion and not args.quiet:
                                            print(f"  → {warning.suggestion}", file=sys.stderr)

                                    # Abort if errors or strict mode with warnings
                                    if has_error or (strict_mode and has_warning):
                                        if not args.quiet:
                                            print(
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
                                        if not args.quiet:
                                            print(
                                                f"Data successfully hidden in image: {output_file}"
                                            )
                                    else:
                                        print(f"Steganography error: {result.message}")
                                        return 1
                                else:
                                    # Fallback to normal file output
                                    os.replace(temp_output, output_file)
                            except Exception as e:
                                print(f"Steganography error: {e}")
                                return 1
                        else:
                            # Normal file output
                            os.replace(temp_output, output_file)

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
                    print(f"FLOW-DEBUG: Using normal output path: {args.output}")
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
                        print(
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
                            print(
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
                        print(
                            f"Error: Unknown cascade preset '{args.cascade}'. "
                            f"Available: {available_presets}",
                            file=sys.stderr,
                        )
                        sys.exit(1)

                    # Validate minimum 2 ciphers
                    if len(cipher_names) < 2:
                        print(
                            "Error: Cascade mode requires at least 2 ciphers",
                            file=sys.stderr,
                        )
                        sys.exit(1)

                    # Validate that all ciphers exist and are available
                    for cipher_name in cipher_names:
                        if not registry.exists(cipher_name):
                            available = ", ".join(registry.list_names())
                            print(
                                f"Error: Unknown cipher '{cipher_name}'. "
                                f"Available: {available}",
                                file=sys.stderr,
                            )
                            sys.exit(1)

                        if not registry.is_available(cipher_name):
                            print(
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
                                    print(
                                        f"\033[91mERROR:\033[0m {warning.message}",
                                        file=sys.stderr,
                                    )
                                elif warning.level == DiversityWarningLevel.WARNING:
                                    has_warning = True
                                    print(
                                        f"\033[93mWARNING:\033[0m {warning.message}",
                                        file=sys.stderr,
                                    )
                                else:  # INFO
                                    print(
                                        f"\033[94mINFO:\033[0m {warning.message}",
                                        file=sys.stderr,
                                    )

                                # Display suggestion if available
                                if warning.suggestion:
                                    print(f"  → {warning.suggestion}", file=sys.stderr)

                            # Abort if errors or strict mode with warnings
                            if has_error or (strict_mode and has_warning):
                                print(
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
                )

                if success:
                    # Output the encrypted content to stdout
                    try:
                        with open(temp_output_file, "rb") as f:
                            sys.stdout.buffer.write(f.read())
                        sys.stdout.buffer.flush()
                    except Exception as e:
                        if not args.quiet:
                            print(f"Error writing to stdout: {e}", file=sys.stderr)
                        success = False
                    finally:
                        # Clean up temporary file
                        try:
                            os.unlink(temp_output_file)
                        except OSError:
                            pass

                # Skip the normal encryption logic
                if success:
                    return
                else:
                    sys.exit(1)

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
                        print(
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

                    # Encrypt the private key with the password
                    # We generate a key derived from the password
                    key_salt = secrets.token_bytes(16)
                    key_derivation = hashlib.pbkdf2_hmac(
                        "sha256", keyfile_password, key_salt, 100000
                    )
                    encryption_key = hashlib.sha256(key_derivation).digest()

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
                        "key_encrypted": True,  # Mark that the key is encrypted
                    }

                    with open(args.pqc_keyfile, "w") as f:
                        json.dump(key_data, f)

                    if not args.quiet:
                        print(f"Post-quantum key pair saved to {args.pqc_keyfile}")

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
                            print(f"Error: PQC key file validation failed: {e}")
                            sys.exit(1)
                        except ImportError:
                            # Fallback to basic JSON loading if validator not available
                            try:
                                key_data = json.loads(json_content)
                            except json.JSONDecodeError as e:
                                print(f"Error: Invalid JSON in PQC key file: {e}")
                                sys.exit(1)

                    if "public_key" in key_data and "private_key" in key_data:
                        public_key = base64.b64decode(key_data["public_key"])
                        encrypted_private_key = base64.b64decode(key_data["private_key"])

                        # Check if key is encrypted (will be for keys created after our fix)
                        if key_data.get("key_encrypted", False):
                            if not args.quiet:
                                print("Found encrypted private key in keyfile")

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

                            # Key derivation using the same method as when encrypting
                            key_salt = base64.b64decode(key_data["key_salt"])
                            key_derivation = hashlib.pbkdf2_hmac(
                                "sha256", keyfile_password, key_salt, 100000
                            )
                            encryption_key = hashlib.sha256(key_derivation).digest()

                            try:
                                # Format: nonce (12 bytes) + encrypted_key
                                nonce = encrypted_private_key[:12]
                                encrypted_key_data = encrypted_private_key[12:]

                                # Decrypt the private key with the password-derived key
                                aes_cipher = AESGCM(encryption_key)
                                private_key = aes_cipher.decrypt(nonce, encrypted_key_data, None)

                                if not args.quiet:
                                    print("Successfully decrypted private key from keyfile")
                            except Exception as e:
                                print(f"Error decrypting private key: {e}. Wrong password?")
                                print("Will proceed with only the public key.")
                                private_key = None
                        else:
                            # Legacy support for non-encrypted keys (created before our fix)
                            private_key = encrypted_private_key
                            if not args.quiet:
                                print("WARNING: Using legacy unencrypted private key from keyfile")

                        pqc_keypair = (
                            (public_key, private_key) if private_key else (public_key, None)
                        )

                        if not args.quiet:
                            print(f"Loaded post-quantum key pair from {args.pqc_keyfile}")
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
                        print(f"Generating ephemeral post-quantum key pair for {args.algorithm}")
                        if args.pqc_store_key:
                            # Only log this message with INFO level so it only appears in verbose mode
                            logger.info(
                                "Private key will be stored in the encrypted file for self-decryption"
                            )
                        else:
                            # Keep this as a print since it's a warning
                            print(
                                "WARNING: Private key will NOT be stored - you must use a key file for decryption"
                            )

                    cipher = PQCipher(algo_map[args.algorithm], quiet=args.quiet)
                    public_key, private_key = cipher.generate_keypair()
                    pqc_keypair = (public_key, private_key)

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
                                print(f"Keystore not found at {args.keystore}, creating a new one")
                            create_new = True
                        else:
                            # Prompt the user if they want to create a new keystore or abort
                            if not args.quiet:
                                print(f"Keystore not found at {args.keystore}")
                                print(
                                    "Use --auto-create-keystore option to automatically create keystore"
                                )
                                create_prompt = (
                                    input("Would you like to create a new keystore? (y/n): ")
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
                                        print(
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
                                        print("Passwords do not match")
                                    raise ValueError("Keystore passwords do not match")

                            # Create the keystore
                            keystore = PQCKeystore(args.keystore)
                            keystore.create_keystore(
                                keystore_password, KeystoreSecurityLevel.STANDARD
                            )
                            if not args.quiet:
                                print(f"Created new keystore at {args.keystore}")
                        else:
                            # Abort
                            if not args.quiet:
                                print(f"Encryption aborted: Keystore not found at {args.keystore}")
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
                                print(f"Warning: Failed to read keystore password from file: {e}")
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
                                print("Auto-generating key for keystore")
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
                                print(
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
                                    print(
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
                                print(
                                    f"Using cascade preset '{args.cascade}': {' → '.join(cipher_names)}"
                                )
                        else:
                            if not args.quiet:
                                available_presets = ", ".join(CASCADE_PRESETS.keys())
                                print(
                                    f"Error: Unknown cascade preset '{args.cascade}'. "
                                    f"Available: {available_presets}",
                                    file=sys.stderr,
                                )
                            return 1

                        # Validate minimum 2 ciphers
                        if len(cipher_names) < 2:
                            if not args.quiet:
                                print(
                                    "Error: Cascade mode requires at least 2 ciphers",
                                    file=sys.stderr,
                                )
                            return 1

                        # Validate that all ciphers exist and are available
                        for cipher_name in cipher_names:
                            if not registry.exists(cipher_name):
                                available = ", ".join(registry.list_names())
                                if not args.quiet:
                                    print(
                                        f"Error: Unknown cipher '{cipher_name}'. "
                                        f"Available: {available}",
                                        file=sys.stderr,
                                    )
                                return 1

                            if not registry.is_available(cipher_name):
                                if not args.quiet:
                                    print(
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
                                            print(
                                                f"\033[91mERROR:\033[0m {warning.message}",
                                                file=sys.stderr,
                                            )
                                    elif warning.level == DiversityWarningLevel.WARNING:
                                        has_warning = True
                                        if not args.quiet:
                                            print(
                                                f"\033[93mWARNING:\033[0m {warning.message}",
                                                file=sys.stderr,
                                            )
                                    else:  # INFO
                                        if not args.quiet:
                                            print(
                                                f"\033[94mINFO:\033[0m {warning.message}",
                                                file=sys.stderr,
                                            )

                                    # Display suggestion if available
                                    if warning.suggestion and not args.quiet:
                                        print(f"  → {warning.suggestion}", file=sys.stderr)

                                # Abort if errors or strict mode with warnings
                                if has_error or (strict_mode and has_warning):
                                    if not args.quiet:
                                        print(
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
                    )

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
                                    print(f"Data successfully hidden in image: {output_file}")
                            else:
                                print(f"Steganography error: {result.message}")
                                return 1
                    except Exception as e:
                        print(f"Steganography error: {e}")
                        return 1

            if success:
                # Security audit log for successful encryption
                if security_logger:
                    security_logger.log_event(
                        "encryption_completed",
                        "info",
                        {
                            "input_file": str(args.input),
                            "output_file": str(output_file),
                            "algorithm": args.algorithm.value
                            if hasattr(args.algorithm, "value")
                            else str(args.algorithm),
                            "service": "cli",
                        },
                    )

                if not args.quiet:
                    # Skip leading newline for stdout/stderr to avoid blank line
                    prefix = "" if output_file in ("/dev/stdout", "/dev/stderr") else "\n"
                    print(f"{prefix}File encrypted successfully: {output_file}")

                    # If we used a generated password, display it with a
                    # warning
                    if generated_password:
                        # Store the original signal handler
                        original_sigint = signal.getsignal(signal.SIGINT)

                        # Flag to track if Ctrl+C was pressed
                        interrupted = False

                        # Custom signal handler for SIGINT
                        def sigint_handler(signum, frame):
                            nonlocal interrupted
                            interrupted = True
                            # Restore original handler immediately
                            signal.signal(signal.SIGINT, original_sigint)

                        try:
                            # Set our custom handler
                            signal.signal(signal.SIGINT, sigint_handler)

                            print("\n" + "!" * 80)
                            print("IMPORTANT: SAVE THIS PASSWORD NOW".center(80))
                            print("!" * 80)
                            print(f"\nGenerated Password: {generated_password}")
                            print(
                                "\nWARNING: This is the ONLY time this password will be displayed."
                            )
                            print("         If you lose it, your data CANNOT be recovered.")
                            print(
                                "         Please write it down or save it in a password manager now."
                            )
                            print("\nThis message will disappear in 10 seconds...")

                            # Wait for 10 seconds or until keyboard interrupt
                            for remaining in range(10, 0, -1):
                                if interrupted:
                                    break
                                # Overwrite the line with updated countdown
                                print(
                                    f"\rTime remaining: {remaining} seconds...",
                                    end="",
                                    flush=True,
                                )
                                # Sleep in small increments to check for
                                # interruption more frequently
                                for _ in range(10):
                                    if interrupted:
                                        break
                                    time.sleep(0.1)

                        finally:
                            # Restore original signal handler no matter what
                            signal.signal(signal.SIGINT, original_sigint)

                            # Give an indication that we're clearing the screen
                            if interrupted:
                                print("\n\nClearing password from screen (interrupted by user)...")
                            else:
                                print("\n\nClearing password from screen...")

                            # Clear screen using ANSI escape sequences (safer than os.system)
                            # \033[2J clears the entire screen, \033[H moves cursor to home position
                            sys.stdout.write("\033[2J\033[H")
                            sys.stdout.flush()

                            print("Password has been cleared from screen.")
                            print(
                                "For additional security, consider clearing your terminal history."
                            )

                # If shredding was requested and encryption was successful
                if args.shred and not args.overwrite:
                    if not args.quiet:
                        print("Shredding the original file as requested...")
                    secure_shred_file(args.input, args.shred_passes, args.quiet)

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
                                    print(
                                        "ERROR: No matching identity found. This should not happen after auto-detection.",
                                        file=sys.stderr,
                                    )
                                    sys.exit(1)

                                # First load identity metadata to check protection level
                                recipient_metadata = store.get_by_name(
                                    args.key_identity, load_private_keys=False
                                )
                                if recipient_metadata is None:
                                    print(
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
                                    sys.stdout.write("\033[F\033[K")
                                    sys.stdout.flush()

                                try:
                                    recipient = store.get_by_name(
                                        args.key_identity,
                                        passphrase=recipient_passphrase,
                                        load_private_keys=True,
                                    )
                                    if recipient is None:
                                        print(
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
                                    print(error_msg, file=sys.stderr)
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
                                            print(
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
                                    )

                                    try:
                                        if not args.quiet:
                                            print("\nAsymmetric decryption successful! ✅")
                                            # Show decrypted content as last line with blank line before
                                            print()
                                            print(plaintext.decode("utf-8", errors="replace"))
                                        else:
                                            # In quiet mode, show only decrypted content
                                            print(plaintext.decode("utf-8", errors="replace"))

                                        # Shred original if requested
                                        if args.shred:
                                            secure_shred_file(
                                                args.input, args.shred_passes, args.quiet
                                            )
                                    finally:
                                        # Clean up plaintext from memory
                                        from .secure_memory import secure_memzero

                                        secure_memzero(plaintext)

                                    sys.exit(0)
                                except Exception as e:
                                    print(
                                        f"ERROR: Asymmetric decryption failed: {e}", file=sys.stderr
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
                                print(
                                    "ERROR: No matching identity found. This should not happen after auto-detection.",
                                    file=sys.stderr,
                                )
                                sys.exit(1)

                            # First load identity metadata to check protection level
                            recipient_metadata = store.get_by_name(
                                args.key_identity, load_private_keys=False
                            )
                            if recipient_metadata is None:
                                print(
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
                                sys.stdout.write("\033[F\033[K")
                                sys.stdout.flush()

                            try:
                                recipient = store.get_by_name(
                                    args.key_identity,
                                    passphrase=recipient_passphrase,
                                    load_private_keys=True,
                                )
                                if recipient is None:
                                    print(
                                        f"ERROR: Identity '{args.key_identity}' not found ❌",
                                        file=sys.stderr,
                                    )
                                    sys.exit(1)
                            except Exception as e:
                                error_msg = f"ERROR: Failed to load identity '{args.key_identity}'"
                                if str(e):
                                    error_msg += f": {e}"
                                error_msg += " ❌"
                                print(error_msg, file=sys.stderr)
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
                                        args.verify_from, passphrase=None, load_private_keys=False
                                    )
                                    if sender is None:
                                        print(
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
                                            sender_key_id, passphrase=None, load_private_keys=False
                                        )
                                        if sender:
                                            sender_public_key = sender.signing_public_key
                                        else:
                                            print(
                                                f"WARNING: Sender with fingerprint {sender_key_id} not found in store",
                                                file=sys.stderr,
                                            )
                                            print(
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
                                )

                                # Handle temp file if overwrite mode
                                if args.overwrite and temp_output != output_file:
                                    import shutil

                                    shutil.move(temp_output, output_file)

                                try:
                                    if not args.quiet:
                                        print("\nAsymmetric decryption successful! ✅")
                                        # Show decrypted content as last line with blank line before
                                        print()
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
                                print(f"ERROR: Asymmetric decryption failed: {e}", file=sys.stderr)
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
                            print(
                                f"Warning: The algorithm '{algorithm}' used in this file is deprecated."
                            )
                            print(
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
                            print(
                                f"Warning: The data encryption algorithm '{encryption_data}' used in this file is deprecated."
                            )
                            print(
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
                        print(f"Warning: Could not check stdin for deprecated algorithms: {e}")
                    stdin_temp_file = None
            else:
                # Use file-based metadata extraction for regular files
                try:
                    file_metadata = extract_file_metadata(args.input)
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
                            print(
                                f"Warning: The algorithm '{algorithm}' used in this file is deprecated."
                            )
                            print(
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
                            print(
                                f"Warning: The data encryption algorithm '{encryption_data}' used in this file is deprecated."
                            )
                            print(
                                f"Consider re-encrypting with '{data_replacement}' for better security."
                            )
                except Exception as e:
                    # If we can't read metadata, continue with decryption (it will fail with proper error)
                    if args.verbose:
                        print(f"Warning: Could not check file for deprecated algorithms: {e}")
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
                                print("Extracting encrypted data from steganographic image...")

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
                                        print(f"Extracted {len(encrypted_data)} bytes from image")
                                else:
                                    print(f"Steganography extraction error: {result.message}")
                                    return 1
                        except Exception as e:
                            print(f"Steganography extraction error: {e}")
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
                                    print(f"Error: PQC key file validation failed: {e}")
                                    sys.exit(1)
                                except ImportError:
                                    # Fallback to basic JSON loading if validator not available
                                    try:
                                        key_data = json.loads(json_content)
                                    except json.JSONDecodeError as e:
                                        print(f"Error: Invalid JSON in PQC key file: {e}")
                                        sys.exit(1)

                            if "private_key" in key_data:
                                encrypted_private_key = base64.b64decode(key_data["private_key"])

                                # Check if key is encrypted (will be for keys created after our fix)
                                if key_data.get("key_encrypted", False):
                                    if not args.quiet:
                                        print("Found encrypted private key in keyfile")

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

                                    # Key derivation using the same method as when encrypting
                                    key_salt = base64.b64decode(key_data["key_salt"])
                                    key_derivation = hashlib.pbkdf2_hmac(
                                        "sha256", keyfile_password, key_salt, 100000
                                    )
                                    encryption_key = hashlib.sha256(key_derivation).digest()

                                    try:
                                        # Format: nonce (12 bytes) + encrypted_key
                                        nonce = encrypted_private_key[:12]
                                        encrypted_key_data = encrypted_private_key[12:]

                                        # Decrypt the private key with the password-derived key
                                        aes_cipher = AESGCM(encryption_key)
                                        pqc_private_key = aes_cipher.decrypt(
                                            nonce, encrypted_key_data, None
                                        )

                                        if not args.quiet:
                                            print("Successfully decrypted private key from keyfile")
                                    except Exception as e:
                                        print(f"Error decrypting private key: {e}. Wrong password?")
                                        print("Decryption may fail without a valid private key.")
                                        pqc_private_key = None
                                else:
                                    # Legacy support for non-encrypted keys (created before our fix)
                                    pqc_private_key = encrypted_private_key
                                    if not args.quiet:
                                        print(
                                            "WARNING: Using legacy unencrypted private key from keyfile"
                                        )

                                if not args.quiet and pqc_private_key:
                                    print(
                                        f"Loaded post-quantum private key from {args.pqc_keyfile}"
                                    )
                        except Exception as e:
                            if not args.quiet:
                                print(f"Warning: Failed to load PQC key file: {e}")

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
                                    print(
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
                            print(
                                "\nWarning: No key ID found in metadata and --key-id not provided."
                            )
                            print(
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
                            no_estimate=getattr(args, "no_estimate", False),
                            verify_integrity=getattr(args, "verify_integrity", False),
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
                                print(f"Error: PQC key file validation failed: {e}")
                                sys.exit(1)
                            except ImportError:
                                # Fallback to basic JSON loading if validator not available
                                try:
                                    key_data = json.loads(json_content)
                                except json.JSONDecodeError as e:
                                    print(f"Error: Invalid JSON in PQC key file: {e}")
                                    sys.exit(1)

                        if "private_key" in key_data:
                            encrypted_private_key = base64.b64decode(key_data["private_key"])

                            # Check if key is encrypted (will be for keys created after our fix)
                            if key_data.get("key_encrypted", False):
                                if not args.quiet:
                                    print("Found encrypted private key in keyfile")

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

                                # Key derivation using the same method as when encrypting
                                key_salt = base64.b64decode(key_data["key_salt"])
                                key_derivation = hashlib.pbkdf2_hmac(
                                    "sha256", keyfile_password, key_salt, 100000
                                )
                                encryption_key = hashlib.sha256(key_derivation).digest()

                                try:
                                    # Format: nonce (12 bytes) + encrypted_key
                                    nonce = encrypted_private_key[:12]
                                    encrypted_key_data = encrypted_private_key[12:]

                                    # Decrypt the private key with the password-derived key
                                    aes_cipher = AESGCM(encryption_key)
                                    pqc_private_key = aes_cipher.decrypt(
                                        nonce, encrypted_key_data, None
                                    )

                                    if not args.quiet:
                                        print("Successfully decrypted private key from keyfile")
                                except Exception as e:
                                    print(f"Error decrypting private key: {e}. Wrong password?")
                                    print("Decryption may fail without a valid private key.")
                                    pqc_private_key = None
                            else:
                                # Legacy support for non-encrypted keys (created before our fix)
                                pqc_private_key = encrypted_private_key
                                if not args.quiet:
                                    print(
                                        "WARNING: Using legacy unencrypted private key from keyfile"
                                    )

                            if not args.quiet and pqc_private_key:
                                print(f"Loaded post-quantum private key from {args.pqc_keyfile}")
                    except Exception as e:
                        if not args.quiet:
                            print(f"Warning: Failed to load PQC key file: {e}")

                # Handle steganography extraction if requested
                actual_input_file = args.input
                temp_extracted_file = None

                if hasattr(args, "stego_extract") and args.stego_extract:
                    try:
                        import tempfile

                        if not args.quiet:
                            print("Extracting encrypted data from steganographic image...")

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
                                    print(f"Extracted {len(encrypted_data)} bytes from image")
                            else:
                                print(f"Steganography extraction error: {result.message}")
                                return 1
                    except Exception as e:
                        print(f"Steganography extraction error: {e}")
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
                                print(f"Warning: Failed to read keystore password from file: {e}")
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
                        no_estimate=getattr(args, "no_estimate", False),
                        verify_integrity=getattr(args, "verify_integrity", False),
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
                        print(f"{prefix}File decrypted successfully: {args.output}")

                # If shredding was requested and decryption was successful
                if args.shred and success:
                    if not args.quiet:
                        print("Shredding the encrypted file as requested...")
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
                                print(f"Error: PQC key file validation failed: {e}")
                                sys.exit(1)
                            except ImportError:
                                # Fallback to basic JSON loading if validator not available
                                try:
                                    key_data = json.loads(json_content)
                                except json.JSONDecodeError as e:
                                    print(f"Error: Invalid JSON in PQC key file: {e}")
                                    sys.exit(1)

                        if "private_key" in key_data:
                            encrypted_private_key = base64.b64decode(key_data["private_key"])

                            # Check if key is encrypted (will be for keys created after our fix)
                            if key_data.get("key_encrypted", False):
                                if not args.quiet:
                                    print("Found encrypted private key in keyfile")

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

                                # Key derivation using the same method as when encrypting
                                key_salt = base64.b64decode(key_data["key_salt"])
                                key_derivation = hashlib.pbkdf2_hmac(
                                    "sha256", keyfile_password, key_salt, 100000
                                )
                                encryption_key = hashlib.sha256(key_derivation).digest()

                                try:
                                    # Format: nonce (12 bytes) + encrypted_key
                                    nonce = encrypted_private_key[:12]
                                    encrypted_key_data = encrypted_private_key[12:]

                                    # Decrypt the private key with the password-derived key
                                    cipher = AESGCM(encryption_key)
                                    pqc_private_key = cipher.decrypt(
                                        nonce, encrypted_key_data, None
                                    )

                                    if not args.quiet:
                                        print("Successfully decrypted private key from keyfile")
                                except Exception as e:
                                    print(f"Error decrypting private key: {e}. Wrong password?")
                                    print("Decryption may fail without a valid private key.")
                                    pqc_private_key = None
                            else:
                                # Legacy support for non-encrypted keys (created before our fix)
                                pqc_private_key = encrypted_private_key
                                if not args.quiet:
                                    print(
                                        "WARNING: Using legacy unencrypted private key from keyfile"
                                    )

                            if not args.quiet and pqc_private_key:
                                print(f"Loaded post-quantum private key from {args.pqc_keyfile}")
                    except Exception as e:
                        if not args.quiet:
                            print(f"Warning: Failed to load PQC key file: {e}")

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
                                print(f"Warning: Failed to read keystore password from file: {e}")
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
                        no_estimate=getattr(args, "no_estimate", False),
                        verify_integrity=getattr(args, "verify_integrity", False),
                    )
                try:
                    # Try to decode as text
                    if not args.quiet:
                        print("\nDecrypted content:")
                    print(decrypted.decode().rstrip())
                except UnicodeDecodeError:
                    if not args.quiet:
                        print(
                            "\nDecrypted successfully, but content is binary and cannot be displayed."
                        )

        elif args.action == "shred":
            # Direct shredding of files or directories without
            # encryption/decryption

            # Expand any glob patterns in the input path
            matched_paths = expand_glob_patterns(args.input)

            if not matched_paths:
                if not args.quiet:
                    print(f"No files or directories match the pattern: {args.input}")
                exit_code = 1
            else:
                # If there are multiple files/dirs to shred, inform the user
                if len(matched_paths) > 1 and not args.quiet:
                    print(f"Found {len(matched_paths)} files/directories matching the pattern.")

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
                                print(
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
                                print(f"Skipping directory: {path}")
                                continue
                    else:
                        # File or directory with recursive flag
                        if not args.quiet:
                            print(
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
            print(f"\nError: {e}")
        exit_code = 1

    # Exit with appropriate code
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
