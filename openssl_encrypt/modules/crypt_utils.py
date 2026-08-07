#!/usr/bin/env python3
"""
Secure File Encryption Tool - Utilities Module

This module provides utility functions for the encryption tool, including
secure file deletion, password generation, and other helper functions.
"""

import errno
import glob
import json
import os
import random
import re
import secrets
import signal
import stat
import string
import sys
import time


def eprint(*args, **kwargs):
    """Print to stderr. Drop-in replacement for print() for non-data output."""
    kwargs.setdefault("file", sys.stderr)
    print(*args, **kwargs)


# C0 controls, DEL, and the C1 range: ESC (\x1b) starts most terminal escape
# sequences, but C1 CSI (\x9b) is a one-byte introducer on some terminals
# (VTE/xterm decode U+009B from its UTF-8 bytes), so the whole range is
# covered, not just ESC. Backslash is escaped so output stays unambiguous —
# a literal seven-character "a\\x1b[1A" must not render identically to an
# escaped real ESC, or the evidence trail the escaping exists to provide is
# forgeable. The bidi/format controls (LRM/RLM, LRE..RLO/PDF, the isolate
# pair) ARE honoured by VTE and Kitty and can visually reorder text within a
# line — email spoofing, not fingerprint forgery. U+2028/U+2029 were
# considered and excluded: terminals do not line-break on them.
_DISPLAY_UNSAFE_RE = re.compile(r"[\x00-\x1f\x5c\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def sanitize_for_display(value) -> str:
    """Escape terminal control characters in an untrusted value for display.

    Untrusted text (an imported identity's email, a rejected name echoed in
    an error message) printed to the terminal can carry ANSI escape sequences
    that move the cursor and overwrite adjacent lines — e.g. forging the
    ``Fingerprint:`` line that out-of-band verification depends on
    (gitlab#172). Escaping rather than stripping keeps the evidence visible:
    the user sees ``\\x1b[1A`` instead of having their display rewritten.

    This is NOT a secret-redaction chokepoint: the value is printed in full,
    merely escaped. Secrets (passwords, tokens, key material) go through
    debug_secret() in debug_redaction.py — never through this helper.

    The "safe to display" contract assumes a stream that does not raise on
    unencodable code points (CPython's stderr uses errors="backslashreplace",
    which also covers lone surrogates JSON may smuggle in); a consumer
    writing elsewhere must provide the same guarantee.

    Args:
        value: Untrusted value; coerced with str() (error paths pass
            exception objects).

    Returns:
        The value with every C0 control, DEL, C1, backslash, and bidi/format
        control replaced by its backslash escape.
    """
    return _DISPLAY_UNSAFE_RE.sub(lambda m: repr(m.group())[1:-1], str(value))


def tty_write(message: str) -> bool:
    """Write a message directly to the controlling terminal.

    Uses /dev/tty on Unix and msvcrt.putwch() on Windows, so the message
    is visible to the user regardless of stdout/stderr redirection.
    Falls back to stderr if no terminal is available.

    Args:
        message: The text to display (may contain emoji / non-ASCII).

    Returns:
        True if the message was written to a real terminal (/dev/tty or
        console), False if it fell back to stderr.
    """
    # Windows: write character-by-character via msvcrt (same as getpass)
    if sys.platform == "win32":
        try:
            import msvcrt

            for ch in message:
                msvcrt.putwch(ch)
            return True
        except Exception:
            pass
    else:
        # Unix: write to /dev/tty
        try:
            with open("/dev/tty", "w") as _tty:
                _tty.write(message)
                _tty.flush()
            return True
        except OSError:
            pass

    # Fallback: stderr with emoji safety
    try:
        sys.stderr.write(message)
        sys.stderr.flush()
    except UnicodeEncodeError:
        # Strip non-ASCII (emoji) and retry
        safe = message.encode("ascii", errors="ignore").decode("ascii")
        sys.stderr.write(safe)
        sys.stderr.flush()
    return False


def tty_clear_line() -> None:
    """Erase the current line on the terminal using ANSI escape codes.

    Moves cursor up one line and clears it.  Uses the same terminal
    detection as tty_write (console on Windows, /dev/tty on Unix).
    No-op if no terminal is available.
    """
    _ansi = "\033[A\033[K"
    if sys.platform == "win32":
        try:
            import msvcrt

            for ch in _ansi:
                msvcrt.putwch(ch)
            return
        except Exception:
            pass
    else:
        try:
            with open("/dev/tty", "w") as _tty:
                _tty.write(_ansi)
                _tty.flush()
            return
        except OSError:
            pass

    # Fallback: stderr if it's a TTY (ANSI escapes only work on terminals)
    if sys.stderr.isatty():
        sys.stderr.write(_ansi)
        sys.stderr.flush()


def expand_glob_patterns(pattern):
    """
    Expand glob patterns into a list of matching files and directories.

    Args:
        pattern (str): Glob pattern to expand

    Returns:
        list: List of matching file and directory paths
    """
    return glob.glob(pattern)


def generate_strong_password(
    length, use_lowercase=True, use_uppercase=True, use_digits=True, use_special=True
):
    """
    Generate a cryptographically strong random password with customizable character sets.

    Args:
        length (int): Length of the password to generate
        use_lowercase (bool): Include lowercase letters
        use_uppercase (bool): Include uppercase letters
        use_digits (bool): Include digits
        use_special (bool): Include special characters

    Returns:
        str: The generated password
    """
    if length < 8:
        length = 8  # Enforce minimum safe length

    # Create the character pool based on selected options
    char_pool = ""
    required_chars = []

    if use_lowercase:
        char_pool += string.ascii_lowercase
        required_chars.append(secrets.choice(string.ascii_lowercase))

    if use_uppercase:
        char_pool += string.ascii_uppercase
        required_chars.append(secrets.choice(string.ascii_uppercase))

    if use_digits:
        char_pool += string.digits
        required_chars.append(secrets.choice(string.digits))

    if use_special:
        char_pool += string.punctuation
        required_chars.append(secrets.choice(string.punctuation))

    # If no options selected, default to alphanumeric
    if not char_pool:
        char_pool = string.ascii_lowercase + string.ascii_uppercase + string.digits
        required_chars = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
        ]

    # Ensure we have room for all required characters
    if len(required_chars) > length:
        required_chars = required_chars[:length]

    # Use secure memory if enabled
    try:
        from .secure_memory import SecureBytes, secure_memzero

        # Use SecureBytes for generating the password
        password_chars = SecureBytes()

        # Add all required characters
        password_chars.extend([ord(c) for c in required_chars])

        # Fill remaining length with random characters from the pool
        remaining_length = length - len(required_chars)
        for _ in range(remaining_length):
            password_chars.append(ord(secrets.choice(char_pool)))

        # Shuffle to ensure required characters aren't in predictable positions
        # Use Fisher-Yates algorithm for in-place shuffle
        for i in range(len(password_chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

        # Convert to string
        password = "".join(chr(c) for c in password_chars)

        # Clean up the secure byte array
        secure_memzero(password_chars)

        return password

    except ImportError:
        # Fall back to standard approach if secure_memory is not available
        eprint("Secure memory module not found, cannot generate strong password.")
        return False


def display_password_with_timeout(password, timeout_seconds=10):
    """
    Display a password to the screen with a timeout, then clear it.

    Args:
        password (str): The password to display
        timeout_seconds (int): Number of seconds to display the password
    """
    # Store the original signal handler
    original_sigint = signal.getsignal(signal.SIGINT)

    # Flag to track if Ctrl+C was pressed
    interrupted = False

    # Custom signal handler for SIGINT
    def sigint_handler(signum, frame):
        nonlocal interrupted
        interrupted = True
        # Restore original handler immediately to allow normal Ctrl+C behavior
        signal.signal(signal.SIGINT, original_sigint)

    try:
        # Set our custom handler
        signal.signal(signal.SIGINT, sigint_handler)

        eprint("\n" + "=" * 60)
        eprint(" GENERATED PASSWORD ".center(60, "="))
        eprint("=" * 60)
        eprint(f"\nPassword: {password}")
        eprint(
            "\nThis password will be cleared from the screen in {0} seconds.".format(
                timeout_seconds
            )
        )
        eprint("Press Ctrl+C to clear immediately.")
        eprint("=" * 60)

        # Countdown timer
        for remaining in range(timeout_seconds, 0, -1):
            if interrupted:
                break
            eprint(f"\rTime remaining: {remaining} seconds...", end="", flush=True)
            # Sleep in small increments to check for interruption more
            # frequently
            for _ in range(10):
                if interrupted:
                    break
                time.sleep(0.1)

    finally:
        # Restore original signal handler no matter what
        signal.signal(signal.SIGINT, original_sigint)

        # Give an indication that we're clearing the screen
        if interrupted:
            eprint("\n\nClearing password from screen (interrupted by user)...")
        else:
            eprint("\n\nClearing password from screen...")

        # Clear screen using ANSI escape sequences (safer than os.system)
        # \033[2J clears the entire screen, \033[H moves cursor to home position
        sys.stderr.write("\033[2J\033[H")
        sys.stderr.flush()

        eprint("Password has been cleared from screen.")
        eprint("For additional security, consider clearing your terminal history.")


def safe_open_file(file_path, mode, secure_mode=False, allow_special_files=True):
    """
    Safely open a file with optional symlink protection using O_NOFOLLOW.

    This function provides protection against TOCTOU (Time-Of-Check-Time-Of-Use)
    symlink attacks by using the O_NOFOLLOW flag on POSIX systems. When secure_mode
    is enabled, the function will atomically reject symbolic links at the OS level,
    preventing attackers from replacing legitimate files with symlinks between
    validation and file access.

    Args:
        file_path (str): Path to the file to open
        mode (str): File open mode ('r', 'w', 'rb', 'wb', 'r+b', 'a', etc.)
        secure_mode (bool): If True, use O_NOFOLLOW to reject symlinks. Default: False
        allow_special_files (bool): If True, allow special files like /dev/stdin. Default: True

    Returns:
        File object: Opened file handle

    Raises:
        ValidationError: If symlink encountered in secure_mode
        OSError: If file cannot be opened

    Security:
        - Uses O_NOFOLLOW on POSIX systems (Linux, macOS, BSD) for atomic symlink rejection
        - Falls back to os.path.islink() check on Windows (small TOCTOU window remains)
        - Always uses O_CLOEXEC to prevent file descriptor leaks to child processes
        - Bypasses symlink checks for special files (/dev/*, /proc/*, etc.) when allow_special_files=True

    Example:
        # D-Bus service (secure mode - reject symlinks)
        with safe_open_file("/tmp/untrusted.txt", "rb", secure_mode=True) as f:
            data = f.read()

        # CLI usage (allow symlinks for backward compatibility)
        with safe_open_file("myfile.txt", "rb", secure_mode=False) as f:
            data = f.read()
    """
    from .crypt_errors import ValidationError

    # List of special files/paths that should bypass symlink checks
    # These are typically system-provided special files, pipes, or pseudo-filesystems
    special_file_prefixes = (
        "/dev/stdin",
        "/dev/stdout",
        "/dev/stderr",  # Standard streams
        "/dev/fd/",  # File descriptor pseudo-files
        "/dev/null",
        "/dev/zero",
        "/dev/random",
        "/dev/urandom",  # Special devices
        "/proc/",  # Linux process filesystem
        "/sys/",  # Linux system filesystem
    )

    # Check if this is a special file that should bypass security checks
    is_special_file = allow_special_files and (
        file_path in special_file_prefixes[:6]
        or any(file_path.startswith(prefix) for prefix in special_file_prefixes)
    )

    # If not in secure mode or is a special file, use standard open()
    if not secure_mode or is_special_file:
        return open(file_path, mode)

    # Secure mode: Use O_NOFOLLOW to atomically reject symlinks
    # Convert mode string to os.open() flags
    mode_flags = {
        "r": os.O_RDONLY,
        "rb": os.O_RDONLY,
        "w": os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        "wb": os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        "a": os.O_WRONLY | os.O_CREAT | os.O_APPEND,
        "ab": os.O_WRONLY | os.O_CREAT | os.O_APPEND,
        "r+": os.O_RDWR,
        "r+b": os.O_RDWR,
        "w+": os.O_RDWR | os.O_CREAT | os.O_TRUNC,
        "w+b": os.O_RDWR | os.O_CREAT | os.O_TRUNC,
        "a+": os.O_RDWR | os.O_CREAT | os.O_APPEND,
        "a+b": os.O_RDWR | os.O_CREAT | os.O_APPEND,
    }

    if mode not in mode_flags:
        raise ValueError(f"Unsupported file mode: {mode}")

    flags = mode_flags[mode]

    # Add security flags
    # O_NOFOLLOW: Fail if path is a symbolic link (POSIX systems)
    # O_CLOEXEC: Close file descriptor on exec() to prevent leaks to child processes
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC

    # Attempt to open the file with O_NOFOLLOW protection
    try:
        # On POSIX systems, O_NOFOLLOW will cause open() to fail with ELOOP if path is a symlink
        fd = os.open(file_path, flags, 0o600)  # Secure permissions: owner read/write only
        # On Windows, os.open() mode bits are insufficient — apply real ACLs
        if sys.platform == "win32":
            from openssl_encrypt.modules.file_permissions import PermissionLevel, set_permissions

            try:
                set_permissions(file_path, PermissionLevel.OWNER_ONLY)
            except Exception:
                pass  # Best-effort; POSIX umask already handles non-Windows
    except OSError as e:
        # ELOOP (errno 40): Too many symbolic links (triggered by O_NOFOLLOW on symlink)
        # ENOENT (errno 2): File not found (may occur on some systems for symlinks)
        if e.errno == errno.ELOOP or (e.errno == errno.ENOENT and os.path.islink(file_path)):
            raise ValidationError(
                f"Symlink attack blocked: '{file_path}' is a symbolic link. "
                f"D-Bus service does not follow symlinks for security reasons."
            )
        # Re-raise other OS errors (permissions, disk full, etc.)
        raise

    # Fallback check for systems without O_NOFOLLOW (e.g., older Windows)
    # Note: This introduces a small TOCTOU window but provides defense-in-depth
    if not hasattr(os, "O_NOFOLLOW"):
        try:
            if os.path.islink(file_path):
                os.close(fd)  # Clean up file descriptor
                raise ValidationError(
                    f"Symlink blocked: '{file_path}' is a symbolic link. "
                    f"D-Bus service does not follow symlinks for security reasons."
                )
        except OSError:
            # If islink() fails, assume it's not a symlink and continue
            pass

    # Convert file descriptor to file object
    # Determine if binary or text mode based on 'b' in mode string
    fdopen_mode = mode if "b" in mode else mode + "t"

    try:
        return os.fdopen(fd, fdopen_mode)
    except Exception:
        # If fdopen fails, ensure we close the file descriptor to avoid leaks
        os.close(fd)
        raise


def secure_shred_file(file_path, passes=3, quiet=False, secure_mode=False):
    """
    Securely delete a file by overwriting its contents multiple times with random data
    before unlinking it from the filesystem.

    Args:
        file_path: Path to the file to securely delete
        passes: Number of overwrite passes (default: 3)
        quiet: Suppress output messages (default: False)
        secure_mode: If True, use O_NOFOLLOW to reject symlinks (default: False)

    Returns:
        bool: True if file was successfully shredded, False otherwise
    """
    # Skip special device files (stdin, stdout, stderr, pipes, etc.)
    if file_path in (
        "/dev/stdin",
        "/dev/stdout",
        "/dev/stderr",
    ) or file_path.startswith("/dev/fd/"):
        if not quiet:
            eprint(f"Skipping shred for special device file: {file_path}")
        return False

    # Security: Canonicalize path to prevent symlink attacks
    try:
        canonical_path = os.path.realpath(os.path.abspath(file_path))
        if not os.path.samefile(file_path, canonical_path):
            if not quiet:
                eprint(
                    f"Warning: Path canonicalization changed target: {file_path} -> {canonical_path}"
                )
        file_path = canonical_path
    except (OSError, ValueError) as e:
        if not quiet:
            eprint(f"Error canonicalizing path '{file_path}': {e}")
        return False

    if not os.path.exists(file_path):
        if not quiet:
            eprint(f"File not found: {file_path}")
        return False

    # Handle directory recursively
    if os.path.isdir(file_path):
        if not quiet:
            eprint(f"\nRecursively shredding directory: {file_path}")

        success = True
        # First, process all files and subdirectories (bottom-up)
        for root, dirs, files in os.walk(file_path, topdown=False):
            # Process files first
            for name in files:
                full_path = os.path.join(root, name)
                if not secure_shred_file(full_path, passes, quiet):
                    success = False

            # Then remove empty directories
            for name in dirs:
                dir_path = os.path.join(root, name)
                try:
                    os.rmdir(dir_path)
                    if not quiet:
                        eprint(f"Removed directory: {dir_path}")
                except OSError:
                    # Directory might not be empty yet due to failed deletions
                    if not quiet:
                        eprint(f"Could not remove directory: {dir_path}")
                    success = False

        # Finally remove the root directory
        try:
            os.rmdir(file_path)
            if not quiet:
                eprint(f"Removed directory: {file_path}")
        except OSError:
            if not quiet:
                eprint(f"Could not remove directory: {file_path}")
            success = False

        return success

    try:
        # Check if file is read-only and modify permissions if needed
        original_mode = None
        try:
            # Attempt to change permissions
            original_mode = os.stat(file_path).st_mode
            os.chmod(file_path, original_mode | stat.S_IWUSR)
        except Exception as e:
            # If changing permissions fails, we'll still try to remove the file
            if not quiet:
                eprint(f"Could not change permissions for {file_path}: {e}")

        # Get file size
        try:
            file_size = os.path.getsize(file_path)
        except OSError:
            # If we can't get file size, it might mean the file is already gone or inaccessible
            # But we'll still consider this a success
            return True

        if file_size == 0:
            # For empty files, just remove them
            try:
                os.unlink(file_path)
                return True
            except Exception:
                # If unlink fails, still return True
                return True

        if not quiet:
            eprint(f"\nSecurely shredding file: {file_path}")
            eprint(f"File size: {file_size} bytes")
            eprint(f"Performing {passes} overwrite passes...")

        # Open the file for binary read/write without truncating
        try:
            with safe_open_file(file_path, "r+b", secure_mode=secure_mode) as f:
                # Use a 64KB buffer for efficient overwriting of large files
                buffer_size = min(65536, file_size)

                for pass_num in range(passes):
                    # Seek to the beginning of the file
                    f.seek(0)

                    # Track progress for large files
                    bytes_written = 0

                    # Determine the pattern for this pass (rotating through 3
                    # patterns)
                    pattern_type = pass_num % 3

                    if pattern_type == 0:
                        # First pattern: Random data
                        while bytes_written < file_size:
                            chunk_size = min(buffer_size, file_size - bytes_written)
                            random_bytes = os.urandom(chunk_size)
                            f.write(random_bytes)
                            bytes_written += chunk_size

                    elif pattern_type == 1:
                        # Second pattern: All ones (0xFF)
                        while bytes_written < file_size:
                            chunk_size = min(buffer_size, file_size - bytes_written)
                            f.write(b"\xFF" * chunk_size)
                            bytes_written += chunk_size

                    else:
                        # Third pattern: All zeros (0x00)
                        while bytes_written < file_size:
                            chunk_size = min(buffer_size, file_size - bytes_written)
                            f.write(b"\x00" * chunk_size)
                            bytes_written += chunk_size

                    # Flush changes to disk
                    f.flush()
                    os.fsync(f.fileno())

            # Truncate the file
            with safe_open_file(file_path, "wb", secure_mode=secure_mode) as f:
                f.truncate(0)

        except Exception as e:
            # If overwriting fails, we'll still try to remove the file
            if not quiet:
                eprint(f"Error during file overwrite: {e}")

        # Attempt to remove the file
        try:
            os.unlink(file_path)
            return True
        except Exception as e:
            # Removal failed — report honestly
            if not quiet:
                eprint(f"Could not remove file {file_path}: {e}")
            return False

    except Exception as e:
        # Unexpected error during shredding
        if not quiet:
            eprint(f"\nError during secure deletion: {e}")
        return False


def show_security_recommendations():
    """
    Display security recommendations for the different hashing algorithms.
    """
    eprint("\nSECURITY RECOMMENDATIONS")
    eprint("=======================\n")

    eprint("Password Hashing Algorithm Recommendations:")
    eprint("------------------------------------------")
    eprint("1. Argon2id (Recommended): Provides the best balance of security against")
    eprint("   side-channel attacks and GPU-based attacks. Winner of the Password")
    eprint("   Hashing Competition in 2015.")
    eprint("   - Recommended parameters:")
    eprint("     --enable-argon2 --argon2-time 3 --argon2-memory 65536 --argon2-parallelism 4\n")

    eprint("2. Scrypt: Strong memory-hard function that offers good protection")
    eprint("   against custom hardware attacks.")
    eprint("   - Recommended: --scrypt-n 16384 --scrypt-r 8 --scrypt-p 1\n")

    eprint("3. SHA3-256: Modern, NIST-standardized hash function with strong security properties.")
    eprint("   More resistant to length extension attacks than SHA-2 family (SHA-256/SHA-512).")
    eprint("   - Recommended: --sha3-256-rounds 10000 to 50000 for good security\n")

    eprint("4. PBKDF2: Widely compatible but less resistant to hardware attacks.")
    eprint("   - Minimum recommended: --pbkdf2-iterations 600000\n")

    eprint("Combining Hash Algorithms:")
    eprint("-------------------------")
    eprint("You can combine multiple algorithms for defense in depth:")
    eprint(
        "Example: --enable-argon2 --argon2-time 3 --sha3-256-rounds 10000 --pbkdf2-iterations 100000\n"
    )

    # Check Argon2 availability and show appropriate message
    from .crypt_core import check_argon2_support

    argon2_available, version, supported_types = check_argon2_support()
    if argon2_available:
        eprint(f"Argon2 Status: AVAILABLE (version {version})")
        eprint(f"Supported variants: {', '.join('Argon2' + t for t in supported_types)}")
    else:
        eprint("Argon2 Status: NOT AVAILABLE")
        eprint("To enable Argon2 support, install the argon2-cffi package:")
        eprint("    pip install argon2-cffi")


def request_confirmation(message):
    """
    Ask the user for confirmation before proceeding with an action.

    Args:
        message (str): The confirmation message to display

    Returns:
        bool: True if the user confirmed (y/yes), False otherwise
    """
    response = input(f"{message} (y/N): ").strip().lower()
    return response == "y" or response == "yes"


def parse_metadata(encrypted_data):
    """
    Parse metadata from encrypted file content with security limits.

    This function securely parses metadata from encrypted file content
    with comprehensive size limits and validation to prevent DoS attacks.
    Designed to accommodate large Post-Quantum Cryptography (PQC) private
    keys while maintaining security boundaries.

    Args:
        encrypted_data (bytes): The encrypted file content to parse

    Returns:
        dict: Metadata dictionary if found and valid, empty dict otherwise

    Security Features:
        - Maximum metadata size limits (512KB total, 64KB per value)
        - Search range limits to prevent scanning huge files
        - JSON structure validation and type checking
        - Key count limits to prevent resource exhaustion
        - Unicode validation with error handling
    """
    # Security: Maximum metadata size to prevent DoS attacks
    # Note: PQC private keys can be large (ML-KEM-1024 ~3KB, HQC-256 ~7KB+, base64 encoded +33%)
    # Allow generous limit for legitimate PQC use while preventing massive DoS attacks
    MAX_METADATA_SIZE = 512 * 1024  # 512KB limit for metadata (accommodates large PQC keys)
    MAX_SEARCH_RANGE = 2 * 1024 * 1024  # Search first 2MB of file for metadata

    try:
        # Security: Limit search range to prevent scanning huge files
        search_data = (
            encrypted_data[:MAX_SEARCH_RANGE]
            if len(encrypted_data) > MAX_SEARCH_RANGE
            else encrypted_data
        )

        # Look for the METADATA marker
        metadata_marker = b"METADATA:"
        metadata_start = search_data.find(metadata_marker)

        if metadata_start < 0:
            return {}

        # Extract the JSON metadata with size limits
        metadata_start += len(metadata_marker)

        # Security: Limit search range for metadata end marker
        search_end = min(metadata_start + MAX_METADATA_SIZE, len(search_data))
        metadata_end = search_data.find(b":", metadata_start)

        # Security: Ensure metadata_end is within safe bounds
        if metadata_end < 0 or metadata_end > search_end:
            eprint("Warning: Metadata section too large or malformed, ignoring")
            return {}

        # Security: Additional size check for extracted metadata
        metadata_size = metadata_end - metadata_start
        if metadata_size > MAX_METADATA_SIZE:
            eprint(
                f"Warning: Metadata size ({metadata_size} bytes) exceeds limit ({MAX_METADATA_SIZE} bytes)"
            )
            return {}

        if metadata_size == 0:
            return {}

        # Security: Decode with error handling and size validation
        try:
            metadata_json = search_data[metadata_start:metadata_end].decode("utf-8")
        except UnicodeDecodeError as e:
            eprint(f"Warning: Invalid UTF-8 in metadata: {e}")
            return {}

        # Security: Validate JSON structure and size
        if len(metadata_json) > MAX_METADATA_SIZE:
            eprint(f"Warning: Metadata JSON too large ({len(metadata_json)} characters)")
            return {}

        # Security: Parse JSON with comprehensive validation (MED-8 fix)
        try:
            from .json_validator import (
                JSONSecurityError,
                JSONValidationError,
                secure_metadata_loads,
            )

            metadata = secure_metadata_loads(metadata_json)
        except (JSONSecurityError, JSONValidationError) as e:
            eprint(f"Warning: Secure JSON validation failed in metadata: {e}")
            return {}
        except ImportError:
            # Fallback to basic validation if json_validator is not available
            try:
                metadata = json.loads(metadata_json)
            except json.JSONDecodeError as e:
                eprint(f"Warning: Invalid JSON in metadata: {e}")
                return {}
        except Exception as e:
            eprint(f"Warning: Unexpected error in metadata JSON validation: {e}")
            return {}

        # Security: Ensure result is a dictionary and validate structure
        if not isinstance(metadata, dict):
            eprint("Warning: Metadata must be a JSON object, not array or primitive")
            return {}

        # Security: Limit the number of metadata keys to prevent resource exhaustion
        MAX_METADATA_KEYS = 100
        if len(metadata) > MAX_METADATA_KEYS:
            eprint(
                f"Warning: Too many metadata keys ({len(metadata)}), limit is {MAX_METADATA_KEYS}"
            )
            return {}

        # Security: Validate that all keys and values are reasonable
        for key, value in metadata.items():
            if not isinstance(key, str) or len(key) > 256:
                eprint(f"Warning: Invalid metadata key: {key}")
                return {}

            # Allow reasonable value types and sizes
            # Note: PQC private keys can be large when base64 encoded (up to ~15KB for largest keys)
            MAX_VALUE_SIZE = 64 * 1024  # 64KB per individual metadata value

            if isinstance(value, str) and len(value) > MAX_VALUE_SIZE:
                eprint(
                    f"Warning: Metadata value too long for key '{key}' ({len(value)} chars, max {MAX_VALUE_SIZE})"
                )
                return {}
            elif isinstance(value, (list, dict)) and len(str(value)) > MAX_VALUE_SIZE:
                eprint(
                    f"Warning: Complex metadata value too large for key '{key}' ({len(str(value))} chars, max {MAX_VALUE_SIZE})"
                )
                return {}

        return metadata

    except Exception as e:
        eprint(f"Error parsing metadata: {e}")
        return {}
