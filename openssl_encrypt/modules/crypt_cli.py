#!/usr/bin/env python3
"""
Secure File Encryption Tool - Command Line Interface

This module provides the command-line interface for the encryption tool,
handling user input, parsing arguments, and calling the appropriate
functionality from the core and utils modules.
"""

import argparse
import atexit
import base64
import getpass
import hashlib
import logging
import os
import signal
import sys
import tempfile
import time
import uuid

# Set up module-level logger
logger = logging.getLogger(__name__)
import json
import secrets
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
    PQC_AVAILABLE,
    WHIRLPOOL_AVAILABLE,
    EncryptionAlgorithm,
    check_argon2_support,
    decrypt_file,
    encrypt_file,
    extract_file_metadata,
    get_file_permissions,
    string_entropy,
)
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
        return args

    def add_extended_algorithm_help(parser):
        pass


from . import crypt_errors
from .keystore_utils import (
    auto_generate_pqc_key,
    extract_key_id_from_metadata,
    get_keystore_password,
    get_pqc_key_for_decryption,
)

# Import keystore-related modules
from .keystore_wrapper import decrypt_file_with_keystore, encrypt_file_with_keystore
from .password_policy import (
    PasswordPolicy,
    get_password_strength,
    validate_password,
    validate_password_or_raise,
)


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
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
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

            if format_version in [4, 5]:
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
    """Securely clear password from environment variables with multiple overwrites"""
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
    """Debug output for hash configuration"""
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
    STANDARD = "standard"
    PARANOID = "paranoid"
    QUICK = "quick"


def show_version_info():
    """Display version information including git commit hash, Python version and dependencies."""
    import os
    import platform
    import sys
    from importlib.metadata import version as pkg_version

    # Import version information from version.py
    try:
        from openssl_encrypt.version import __git_commit__, __version__

        version_module_path = sys.modules["openssl_encrypt.version"].__file__
    except ImportError:
        __version__ = "unknown"
        __git_commit__ = "unknown"
        version_module_path = None

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
                "sha512": 0,
                "sha256": 0,
                "sha3_256": 0,
                "sha3_512": 600000,
                "blake2b": 200000,
                "shake256": 200000,
                "whirlpool": 0,
                "scrypt": {"enabled": True, "n": 128, "r": 8, "p": 1, "rounds": 10},
                "argon2": {
                    "enabled": True,
                    "time_cost": 3,
                    "memory_cost": 65536,
                    "parallelism": 4,
                    "hash_len": 32,
                    "type": 2,
                    "rounds": 100,
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
                    print(f"Invalid template format: missing 'hash_config' key")
                    sys.exit(1)
        except Exception as e:
            print(f"Error loading template file: {e}")
            sys.exit(1)


def preprocess_global_args(argv):
    """
    Preprocess sys.argv to move truly global flags to the front for subparser compatibility.
    This allows global flags like --debug, --verbose, --quiet, --progress to be specified
    anywhere in the command line, maintaining backward compatibility with v1.2.1 behavior.
    """
    # Flags that are truly global and can appear anywhere
    TRULY_GLOBAL_FLAGS = {
        '--debug', '--verbose', '--quiet', '-q', '--progress'
    }
    
    # Find the command position
    commands = {
        'encrypt', 'decrypt', 'shred', 'generate-password', 
        'security-info', 'check-argon2', 'check-pqc', 'version', 'show-version-file'
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
            if arg in ['--template', '-t'] and i + 1 < len(argv) and not argv[i + 1].startswith('-'):
                i += 1
                global_args.append(argv[i])
        else:
            other_args.append(arg)
        i += 1
    
    # Rebuild argv: script_name + global_args + other_args
    return [argv[0]] + global_args + other_args[1:]


def main():
    """
    Main function that handles the command-line interface.
    """
    # Preprocess arguments to move global flags to the front
    import sys
    sys.argv = preprocess_global_args(sys.argv)

    if (
        len(sys.argv) > 1
        and sys.argv[1]
        in [
            "encrypt",
            "decrypt",
            "shred",
            "generate-password",
            "security-info",
            "check-argon2",
            "check-pqc",
            "version",
            "show-version-file",
        ]
    ):
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
                   "COMMANDS:\n"
                   "  encrypt, decrypt, shred, generate-password, security-info, check-argon2, check-pqc, version\n\n"
                   "EXAMPLES:\n"
                   "  %(prog)s encrypt --input file.txt --debug --output file.enc\n"
                   "  %(prog)s --quiet decrypt --input file.enc --progress --output file.txt\n"
                   "  %(prog)s encrypt --verbose --input file.txt --paranoid --algorithm aes-gcm\n\n"
                   "Environment Variables:\n"
                   "  CRYPT_PASSWORD    Password for encryption/decryption (alternative to -p)",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Global options group
    global_group = parser.add_argument_group('Global Options (can be specified anywhere in command line)')
    global_group.add_argument("--progress", action="store_true", help="Show progress bar")
    global_group.add_argument("--verbose", action="store_true", help="Show hash/kdf details")
    global_group.add_argument("--debug", action="store_true", help="Show detailed debug information")
    global_group.add_argument("--quiet", "-q", action="store_true", help="Suppress all output except decrypted content and exit code")
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
            "check-argon2",
            "check-pqc",
            "version",
            "show-version-file",
        ],
        help="Action to perform: encrypt/decrypt files, shred data, generate passwords, "
        "show security recommendations, check Argon2 support, check post-quantum cryptography support",
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

    # Don't parse args again if they're already provided from subparser
    # This avoids the "unrecognized arguments" error for steganography options  
    if args is None:
        args = parser.parse_args()
    
    # Add compatibility layer for subparser args - set missing attributes to defaults
    default_attrs = {
        'password_policy': 'none', 'argon2_preset': None,
        'sha512': None, 'sha256': None, 'sha3_256': None, 'sha3_512': None,
        'blake2b': None, 'shake256': None, 'pbkdf2': 100000,
        'use_argon2': False, 'enable_balloon': False, 'use_balloon': False,
        'scrypt_cost': 0, 'scrypt_n': 0, 'scrypt_r': 8, 'scrypt_p': 1,
        'whirlpool_rounds': 0, 'tiger_rounds': 0, 'ripemd160_rounds': 0,
        'sha1_rounds': 0, 'md5_rounds': 0, 'md4_rounds': 0,
        'custom_password_list': None, 'password_length': 64,
        'password_charset': None, 'password_file': None,
        'show_password_policy': False, 'balloon_cost': 14,
        'sha512_rounds': None, 'sha256_rounds': None, 'sha3_256_rounds': None,
        'sha3_512_rounds': None, 'blake2b_rounds': None, 'shake256_rounds': None,
        'sha384_rounds': None, 'sha224_rounds': None, 'sha3_384_rounds': None, 'sha3_224_rounds': None,
        'blake3_rounds': None, 'shake128_rounds': None,
        'pbkdf2_iterations': 0, 'enable_argon2': False,
        'argon2_type': 'id', 'argon2_memory': 65536, 'argon2_time': 3, 'argon2_parallelism': 1,
        'argon2_hash_len': 32, 'argon2_rounds': 1, 'balloon_time_cost': 1, 'balloon_space_cost': 1024,
        'balloon_parallelism': 1, 'balloon_hash_len': 32, 'hkdf_rounds': 1, 'hkdf_algorithm': 'sha256',
        'hkdf_info': 'openssl_encrypt_hkdf', 'enable_hkdf': False,
        'algorithm': None, 'random': None, 'overwrite': False, 'shred': False,
        'shred_passes': 3, 'pqc_keyfile': None, 'pqc_store_key': False,
        'kdf_rounds': 0, 'enable_scrypt': False, 'scrypt_rounds': 0,
        'balloon_rounds': 0, 'keystore_path': None, 'keystore_password': None,
        'dual_encrypt_key': None, 'encryption_data': None,
        'quick': False, 'standard': False, 'paranoid': False, 'template': None,
        'force_password': False,
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
            logging.basicConfig(level=logging.DEBUG, format="%(levelname)s - %(name)s - %(message)s")
        except:
            pass
        
        print(f"DEBUG: sys.argv = {sys.argv}")

    # Enhance the args with better defaults for extended algorithms
    args = enhance_cli_args(args)

    # Configure algorithm warnings based on verbose and debug flags
    AlgorithmWarningConfig.configure(verbose_mode=args.verbose or args.debug)

    # Handle legacy options and map to new names
    # SHA family mappings - use getattr for safety with subparser args
    if not getattr(args, 'sha512_rounds', None) and getattr(args, 'sha512', None):
        args.sha512_rounds = args.sha512
    if not getattr(args, 'sha256_rounds', None) and getattr(args, 'sha256', None):
        args.sha256_rounds = args.sha256
    if not getattr(args, 'sha3_256_rounds', None) and getattr(args, 'sha3_256', None):
        args.sha3_256_rounds = args.sha3_256
    if not getattr(args, 'sha3_512_rounds', None) and getattr(args, 'sha3_512', None):
        args.sha3_512_rounds = args.sha3_512
    if not getattr(args, 'blake2b_rounds', None) and getattr(args, 'blake2b', None):
        args.blake2b_rounds = args.blake2b
    if not getattr(args, 'shake256_rounds', None) and getattr(args, 'shake256', None):
        args.shake256_rounds = args.shake256

    # PBKDF2 mapping
    pbkdf2_val = getattr(args, 'pbkdf2', 100000)
    if pbkdf2_val != 100000:  # Only override if not the default
        args.pbkdf2_iterations = pbkdf2_val

    # Argon2 mapping
    if getattr(args, 'use_argon2', False):
        args.enable_argon2 = True

    if getattr(args, 'enable_balloon', False):
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


    # Handle scrypt_cost conversion to scrypt_n
    scrypt_cost = getattr(args, 'scrypt_cost', 0)
    scrypt_n = getattr(args, 'scrypt_n', 0)
    if scrypt_cost > 0 and scrypt_n == 0:
        args.scrypt_n = 2**scrypt_cost

    # Check for utility and information actions first
    if args.action == "security-info":
        show_security_recommendations()
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
    if getattr(args, 'input', None) is None and args.action not in [
        "generate-password",
        "security-info",
        "check-argon2",
        "check-pqc",
        "version",
        "show-version-file",
    ]:
        parser.error("the following arguments are required: --input/-i")

    # Get password (only for encrypt/decrypt actions)
    if args.action in ["encrypt", "decrypt"]:
        password = None
        generated_password = None

        try:
            from .secure_memory import SecureBytes, secure_input, secure_string

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
            import oqs

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
                print(f"Warning: Random password length increased to 12 (minimum secure length)")
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
        if not args.quiet and ARGON2_AVAILABLE:
            logger.debug(
                f"Setting --enable-argon2 since --argon2-rounds={args.argon2_rounds} was provided"
            )
        args.enable_argon2 = True
    elif args.enable_argon2 and args.argon2_rounds <= 0:
        if not args.quiet and ARGON2_AVAILABLE:
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

    # Debug output to verify parameter values (uncomment for debugging)
    # if args.verbose:
    #     print(f"DEBUG - Parameter values after implicit settings:")
    #     print(f"DEBUG - Scrypt: enabled={args.enable_scrypt}, rounds={args.scrypt_rounds}")
    #     print(f"DEBUG - Argon2: enabled={args.enable_argon2}, rounds={args.argon2_rounds}")
    #     print(f"DEBUG - Balloon: enabled={args.enable_balloon}, rounds={args.balloon_rounds}")

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
        setattr(args, "algorithm", hash_config["hash_config"]["algorithm"])
        hash_config = hash_config["hash_config"]
    elif args.template:
        hash_config = get_template_config(args.template)
        if hash_config["hash_config"]["algorithm"]:
            setattr(args, "algorithm", hash_config["hash_config"]["algorithm"])
        else:
            hash_config["hash_config"]["algorithm"] = "fernet"
            setattr(args, "algorithm", "fernet")
        hash_config = hash_config["hash_config"]
    else:
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
                "n": args.scrypt_n,
                "r": args.scrypt_r,
                "p": args.scrypt_p,
                "rounds": args.scrypt_rounds,
            },
            "argon2": {
                "enabled": args.enable_argon2,
                "time_cost": args.argon2_time,
                "memory_cost": args.argon2_memory,
                "parallelism": args.argon2_parallelism,
                "hash_len": args.argon2_hash_len,
                # Store integer value for JSON serialization
                "type": ARGON2_TYPE_INT_MAP.get(args.argon2_type, 2),  # Default to 'id' type (2)
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
            "pbkdf2_iterations": getattr(args, "pbkdf2_iterations", 0),
        }

    # Debug the hash configuration if debug mode is enabled
    if args.debug:
        debug_hash_config(args, hash_config, "Hash configuration after setup")

    exit_code = 0
    try:
        if args.action == "encrypt":
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
                        # Use standard encryption
                        success = encrypt_file(
                                args.input,
                                temp_output,
                                password,
                                hash_config,
                                args.pbkdf2_iterations,
                                args.quiet,
                                algorithm=args.algorithm,
                                progress=args.progress,
                                verbose=args.verbose,
                                debug=args.debug,
                                pqc_keypair=(pqc_keypair if "pqc_keypair" in locals() else None),
                                pqc_store_private_key=args.pqc_store_key,
                                encryption_data=args.encryption_data,
                            )

                    if success:
                        # Apply the original permissions to the temp file
                        os.chmod(temp_output, original_permissions)

                        # Handle steganography if requested
                        if hasattr(args, 'stego_hide') and args.stego_hide:
                            try:
                                from .steganography.stego_transport import create_steganography_transport
                                
                                # Create steganography transport with dedicated password
                                stego_transport = create_steganography_transport(args)
                                if stego_transport:
                                    # Read encrypted data from temp file
                                    with open(temp_output, 'rb') as f:
                                        encrypted_data = f.read()
                                    
                                    # Hide in cover image and save to output file
                                    stego_transport.hide_data_in_image(
                                        encrypted_data, 
                                        args.stego_hide,  # cover image path
                                        output_file       # output path
                                    )
                                    
                                    if not args.quiet:
                                        print(f"Data successfully hidden in image: {output_file}")
                                else:
                                    # Fallback to normal file output
                                    os.replace(temp_output, output_file)
                            except ImportError:
                                print("Error: Steganography requires additional dependencies.")
                                print("Install with: pip install Pillow numpy")
                                return 1
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

                # Use standard encryption to temporary file
                success = encrypt_file(
                    args.input,
                    temp_output_file,
                    password,
                    hash_config,
                    args.pbkdf2_iterations,
                    quiet=True,  # Suppress normal output for stdout
                    algorithm=args.algorithm,
                    progress=False,  # No progress bar for stdout
                    verbose=False,  # No verbose output for stdout
                    debug=args.debug,
                    encryption_data=args.encryption_data,
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
                        except:
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
                    import random

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
                    # Use standard encryption
                    success = encrypt_file(
                        args.input,
                        output_file,
                        password,
                        hash_config,
                        args.pbkdf2_iterations,
                        args.quiet,
                        algorithm=args.algorithm,
                        progress=args.progress,
                        verbose=args.verbose,
                        debug=args.debug,
                        pqc_keypair=pqc_keypair if "pqc_keypair" in locals() else None,
                        pqc_store_private_key=args.pqc_store_key,
                        encryption_data=args.encryption_data,
                    )
                
                # Handle steganography if requested
                if success and hasattr(args, 'stego_hide') and args.stego_hide:
                    try:
                        from .steganography.stego_transport import create_steganography_transport
                        
                        # Create steganography transport
                        stego_transport = create_steganography_transport(args)
                        if stego_transport:
                            # Read encrypted data from output file
                            with open(output_file, 'rb') as f:
                                encrypted_data = f.read()
                            
                            # Hide in cover image and overwrite output file
                            stego_transport.hide_data_in_image(
                                encrypted_data, 
                                args.stego_hide,  # cover image path
                                output_file       # output path (will be overwritten with stego image)
                            )
                            
                            if not args.quiet:
                                print(f"Data successfully hidden in image: {output_file}")
                    except ImportError:
                        print("Error: Steganography requires additional dependencies.")
                        print("Install with: pip install Pillow numpy")
                        return 1
                    except Exception as e:
                        print(f"Steganography error: {e}")
                        return 1

            if success:
                if not args.quiet:
                    print(f"\nFile encrypted successfully: {output_file}")

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

                            # Use system command to clear the screen
                            if sys.platform == "win32":
                                os.system("cls")  # Windows
                            else:
                                os.system("clear")  # Unix/Linux/MacOS

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
                    
                    if hasattr(args, 'stego_extract') and args.stego_extract:
                        try:
                            from .steganography.stego_transport import create_steganography_transport
                            import tempfile
                            
                            if not args.quiet:
                                print("Extracting encrypted data from steganographic image...")
                            
                            # Create steganography transport
                            stego_transport = create_steganography_transport(args)
                            if stego_transport:
                                # Extract encrypted data from image
                                encrypted_data = stego_transport.extract_data_from_image(args.input)
                                
                                # Create temporary file for extracted data
                                with tempfile.NamedTemporaryFile(delete=False, suffix='.enc') as temp_file:
                                    temp_extracted_file = temp_file.name
                                    temp_file.write(encrypted_data)
                                
                                # Use extracted file as input for decryption
                                actual_input_file = temp_extracted_file
                                temp_files_to_cleanup.append(temp_extracted_file)
                                
                                if not args.quiet:
                                    print(f"Extracted {len(encrypted_data)} bytes from image")
                        except ImportError:
                            print("Error: Steganography requires additional dependencies.")
                            print("Install with: pip install Pillow numpy")
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
                
                if hasattr(args, 'stego_extract') and args.stego_extract:
                    try:
                        from .steganography.stego_transport import create_steganography_transport
                        import tempfile
                        
                        if not args.quiet:
                            print("Extracting encrypted data from steganographic image...")
                        
                        # Create steganography transport
                        stego_transport = create_steganography_transport(args)
                        if stego_transport:
                            # Extract encrypted data from image
                            encrypted_data = stego_transport.extract_data_from_image(args.input)
                            
                            # Create temporary file for extracted data
                            with tempfile.NamedTemporaryFile(delete=False, suffix='.enc') as temp_file:
                                temp_extracted_file = temp_file.name
                                temp_file.write(encrypted_data)
                            
                            # Use extracted file as input for decryption
                            actual_input_file = temp_extracted_file
                            temp_files_to_cleanup.append(temp_extracted_file)
                            
                            if not args.quiet:
                                print(f"Extracted {len(encrypted_data)} bytes from image")
                    except ImportError:
                        print("Error: Steganography requires additional dependencies.")
                        print("Install with: pip install Pillow numpy")
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
                    )
                if success and not args.quiet:
                    print(f"\nFile decrypted successfully: {args.output}")

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
