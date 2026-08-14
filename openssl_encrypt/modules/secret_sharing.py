#!/usr/bin/env python3
"""
Shamir's Secret Sharing over GF(256).

Provides K-of-N threshold secret sharing for splitting secrets (passwords,
keys) into shares such that any K shares can reconstruct the original but
fewer than K shares reveal no information.

Uses GF(2^8) with irreducible polynomial x^8+x^4+x^3+x+1 (0x11B) with
log/exp table-lookup arithmetic. The lookups are secret-indexed, so the
arithmetic is NOT strictly constant-time (cache-timing observable); this is
acceptable for the local-CLI threat model but must not be relied on across
a shared-cache trust boundary. No external dependencies.
"""

import datetime
import json
import os
import secrets
import stat
import uuid
from dataclasses import asdict, dataclass
from typing import List, Optional, Tuple, Union

from .crypt_errors import SecretSharingError
from .crypt_utils import eprint, sanitize_for_display
from .secure_memory import SecureBytes, secure_memzero

# ──────────────────────────────────────────────────
# GF(256) Arithmetic
# ──────────────────────────────────────────────────


class GF256:
    """Galois Field GF(2^8) arithmetic with pre-computed lookup tables.

    Uses irreducible polynomial x^8+x^4+x^3+x+1 (0x11B, AES polynomial).
    Operations are table-lookup based; the lookups are secret-indexed, so
    timing is NOT strictly constant (see module docstring).
    """

    _MODULUS = 0x11B  # x^8 + x^4 + x^3 + x + 1

    # Pre-compute EXP and LOG tables
    EXP_TABLE = [0] * 512  # Double-size for convenience
    LOG_TABLE = [0] * 256

    @classmethod
    def _init_tables(cls) -> None:
        """Initialize EXP and LOG tables using generator 3 (x+1).

        The element 3 is a primitive root of the multiplicative group of
        GF(2^8) with the AES polynomial x^8+x^4+x^3+x+1.
        """
        x = 1
        for i in range(255):
            cls.EXP_TABLE[i] = x
            cls.LOG_TABLE[x] = i
            # Multiply x by generator 3: x*3 = x*2 XOR x (since 3 = 2+1 in GF(2^8))
            x2 = (x << 1) ^ (cls._MODULUS if x & 0x80 else 0)
            x = (x2 ^ x) & 0xFF
        # Fill the second half of EXP table for easy modular lookup
        for i in range(255, 512):
            cls.EXP_TABLE[i] = cls.EXP_TABLE[i - 255]

    @classmethod
    def mul(cls, a: int, b: int) -> int:
        """Multiply two elements in GF(256).

        Args:
            a: First element (0-255).
            b: Second element (0-255).

        Returns:
            Product in GF(256).
        """
        if a == 0 or b == 0:
            return 0
        return cls.EXP_TABLE[cls.LOG_TABLE[a] + cls.LOG_TABLE[b]]

    @classmethod
    def inv(cls, a: int) -> int:
        """Multiplicative inverse in GF(256).

        Args:
            a: Element to invert (1-255). Must not be 0.

        Returns:
            Inverse such that mul(a, inv(a)) == 1.

        Raises:
            SecretSharingError: If a is 0.
        """
        if a == 0:
            raise SecretSharingError("Cannot invert zero in GF(256)")
        return cls.EXP_TABLE[255 - cls.LOG_TABLE[a]]

    @classmethod
    def evaluate_polynomial(cls, coeffs: List[int], x: int) -> int:
        """Evaluate a polynomial at point x in GF(256).

        Uses Horner's method: p(x) = c0 + x*(c1 + x*(c2 + ...))

        Args:
            coeffs: Coefficients [c0, c1, ..., c_{k-1}] where c0 is the secret.
            x: Point at which to evaluate (1-255).

        Returns:
            Polynomial value at x in GF(256).
        """
        result = 0
        for coeff in reversed(coeffs):
            result = cls.mul(result, x) ^ coeff
        return result

    @classmethod
    def lagrange_interpolate(cls, points: List[Tuple[int, int]]) -> int:
        """Lagrange interpolation at x=0 in GF(256).

        Given points [(x1,y1), (x2,y2), ...], recovers the secret (f(0)).

        Args:
            points: List of (x, y) coordinate pairs.

        Returns:
            Interpolated value at x=0 (the secret byte).
        """
        result = 0
        for i, (xi, yi) in enumerate(points):
            # Compute Lagrange basis polynomial L_i(0) = prod_{j!=i} (0-xj)/(xi-xj)
            # In GF(256): subtraction is XOR, so 0-xj = xj and xi-xj = xi^xj
            numerator = 1
            denominator = 1
            for j, (xj, _) in enumerate(points):
                if i == j:
                    continue
                numerator = cls.mul(numerator, xj)  # 0 ^ xj = xj
                denominator = cls.mul(denominator, xi ^ xj)
            lagrange_coeff = cls.mul(numerator, cls.inv(denominator))
            result ^= cls.mul(yi, lagrange_coeff)
        return result


# Initialize tables at import time
GF256._init_tables()


# ──────────────────────────────────────────────────
# Share Data Types
# ──────────────────────────────────────────────────

SHARE_FILE_HEADER = "ossl_encrypt_share"

# Upper bound for the byte-list length accepted from an (untrusted) share
# file. Shares are as long as the secret they split; no legitimate password
# or key comes anywhere near this. Enforced symmetrically at split time so
# every share this tool writes is also readable back.
MAX_SHARE_DATA_LEN = 4096

# On-disk size bound checked BEFORE a share file is read/parsed: a share of
# MAX_SHARE_DATA_LEN bytes serializes (indent=2, ~7 chars per byte) to well
# under this, while a hostile multi-GB file is refused without being read.
MAX_SHARE_FILE_BYTES = 256 * 1024


@dataclass
class ShareMetadata:
    """Metadata for a secret share."""

    threshold: int
    total_shares: int
    share_index: int
    key_id: str
    algorithm: str = "shamir-gf256"
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()


class Share:
    """A single share of a split secret.

    Attributes:
        metadata: Share metadata (threshold, index, key_id, etc.).
        data: The share data bytes.
    """

    def __init__(self, metadata: ShareMetadata, data: bytes):
        self.metadata = metadata
        self.data = data

    def to_json(self) -> str:
        """Serialize share to JSON string."""
        obj = {
            "header": SHARE_FILE_HEADER,
            "version": 1,
            "metadata": asdict(self.metadata),
            "data": list(self.data),
        }
        return json.dumps(obj, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "Share":
        """Deserialize share from JSON string.

        Args:
            json_str: JSON string representation.

        Returns:
            Share instance.

        Raises:
            SecretSharingError: If JSON is invalid or has wrong header.
        """
        try:
            obj = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise SecretSharingError(f"Invalid share JSON: {e}")

        if not isinstance(obj, dict):
            raise SecretSharingError("Invalid share file: not a JSON object")
        if obj.get("header") != SHARE_FILE_HEADER:
            raise SecretSharingError(f"Invalid share header: expected '{SHARE_FILE_HEADER}'")

        # Share files are handed to other people and handed back, so this is
        # an untrusted boundary: validate types and ranges before use. A bare
        # int "data" would make bytes(n) allocate n zero bytes (DoS), and
        # non-int metadata surfaces later as confusing TypeErrors.
        meta_dict = obj.get("metadata", {})
        if not isinstance(meta_dict, dict):
            raise SecretSharingError("Invalid share file: metadata is not an object")
        try:
            threshold = meta_dict["threshold"]
            total_shares = meta_dict["total_shares"]
            share_index = meta_dict["share_index"]
            key_id = meta_dict["key_id"]
        except KeyError as e:
            raise SecretSharingError(f"Invalid share file: missing metadata field {e}")
        for name, value in (
            ("threshold", threshold),
            ("total_shares", total_shares),
            ("share_index", share_index),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 255:
                raise SecretSharingError(
                    f"Invalid share file: {name} must be an integer in [1, 255]"
                )
        if not isinstance(key_id, str):
            raise SecretSharingError("Invalid share file: key_id must be a string")
        raw_data = obj.get("data")
        if (
            not isinstance(raw_data, list)
            or len(raw_data) > MAX_SHARE_DATA_LEN
            or not all(
                isinstance(b, int) and not isinstance(b, bool) and 0 <= b <= 255 for b in raw_data
            )
        ):
            raise SecretSharingError(
                "Invalid share file: data must be a list of bytes "
                f"(at most {MAX_SHARE_DATA_LEN} entries)"
            )
        algorithm = meta_dict.get("algorithm", "shamir-gf256")
        created_at = meta_dict.get("created_at", "")
        if not isinstance(algorithm, str) or not isinstance(created_at, str):
            raise SecretSharingError("Invalid share file: algorithm/created_at must be strings")
        metadata = ShareMetadata(
            threshold=threshold,
            total_shares=total_shares,
            share_index=share_index,
            key_id=key_id,
            algorithm=algorithm,
            created_at=created_at,
        )
        return cls(metadata, bytes(raw_data))

    def to_file(self, filepath: str) -> None:
        """Write share to a new file with restrictive permissions (0o600).

        The file is created exclusively (O_CREAT|O_EXCL|O_NOFOLLOW) at 0600
        from the first byte, so the share content is never readable through
        a permission window, a planted symlink is never followed, and an
        existing file (e.g. a previous share set) is never clobbered.

        Args:
            filepath: Path to write the share file.

        Raises:
            SecretSharingError: If the path already exists or is a symlink.
        """
        from .file_permissions import PermissionLevel, create_secure_file

        try:
            fd = create_secure_file(filepath, PermissionLevel.OWNER_ONLY, exclusive=True)
        except FileExistsError:
            raise SecretSharingError(
                f"Refusing to overwrite existing share file: {sanitize_for_display(filepath)}"
            )
        except OSError as e:
            raise SecretSharingError(f"Cannot write share file: {sanitize_for_display(str(e))}")
        try:
            f = os.fdopen(fd, "w")
            fd = -1  # ownership transferred to the file object
            with f:
                f.write(self.to_json())
                f.flush()
                # A share is a durability-critical escrow artifact: make sure
                # it reaches disk before reporting success.
                os.fsync(f.fileno())
        except OSError as e:
            raise SecretSharingError(f"Cannot write share file: {sanitize_for_display(str(e))}")
        finally:
            if fd >= 0:
                os.close(fd)

    @classmethod
    def from_file(cls, filepath: str) -> "Share":
        """Read share from a file.

        Args:
            filepath: Path to the share file.

        Returns:
            Share instance.

        Raises:
            SecretSharingError: If file cannot be read, is not a regular
                file, exceeds the size bound, or cannot be parsed.
        """
        # Share files are untrusted input: refuse symlinks and non-regular
        # files (FIFOs would block, device files misbehave) and bound the
        # size BEFORE reading, so a hostile multi-GB "share" is rejected
        # instead of being read and json-parsed into memory. A legitimate
        # share of MAX_SHARE_DATA_LEN bytes serializes to well under this.
        try:
            fd = os.open(filepath, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as e:
            raise SecretSharingError(f"Cannot read share file: {sanitize_for_display(str(e))}")
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise SecretSharingError(f"Not a regular file: {sanitize_for_display(filepath)}")
            if st.st_size > MAX_SHARE_FILE_BYTES:
                raise SecretSharingError(
                    f"Share file too large (>{MAX_SHARE_FILE_BYTES} bytes): "
                    f"{sanitize_for_display(filepath)}"
                )
            with os.fdopen(fd, "r") as f:
                fd = -1  # ownership transferred to the file object
                return cls.from_json(f.read())
        except OSError as e:
            raise SecretSharingError(f"Cannot read share file: {sanitize_for_display(str(e))}")
        finally:
            if fd >= 0:
                os.close(fd)


# ──────────────────────────────────────────────────
# Split / Combine
# ──────────────────────────────────────────────────


def split_secret(
    secret: Union[bytes, bytearray],
    threshold: int,
    num_shares: int,
    key_id: Optional[str] = None,
) -> List[Share]:
    """Split a secret into shares using Shamir's Secret Sharing.

    Args:
        secret: The secret to split (any bytes-like; only iterated, so a
            wipeable bytearray/SecureBytes is accepted and never copied).
        threshold: Minimum shares needed to reconstruct (k).
        num_shares: Total number of shares to create (n).
        key_id: Optional UUID to identify the share set. Auto-generated if None.

    Returns:
        List of Share objects.

    Raises:
        SecretSharingError: If parameters are invalid.
    """
    if not secret:
        raise SecretSharingError("Secret cannot be empty")
    if threshold < 2:
        raise SecretSharingError("Threshold must be at least 2")
    if num_shares < threshold:
        raise SecretSharingError("Number of shares must be >= threshold")
    if num_shares > 255:
        raise SecretSharingError("Number of shares cannot exceed 255")
    if len(secret) > MAX_SHARE_DATA_LEN:
        # Symmetric with the from_json read-side cap: never write a share
        # set this tool would refuse to read back.
        raise SecretSharingError(f"Secret too long to split (max {MAX_SHARE_DATA_LEN} bytes)")

    if key_id is None:
        key_id = str(uuid.uuid4())

    # For each byte of the secret, create a random polynomial of degree (k-1)
    # and evaluate at x=1..n
    share_data = [bytearray() for _ in range(num_shares)]

    for byte_val in secret:
        # coeffs[0] = secret byte, coeffs[1..k-1] = random
        coeffs = [byte_val] + [secrets.randbelow(256) for _ in range(threshold - 1)]

        for i in range(num_shares):
            x = i + 1  # x values are 1..n
            y = GF256.evaluate_polynomial(coeffs, x)
            share_data[i].append(y)

        # Drop the references to the random coefficients (they contain partial
        # secret info). Best effort only: CPython cannot scrub the original
        # int objects' memory, rebinding just makes them collectable sooner.
        for j in range(len(coeffs)):
            coeffs[j] = 0

    shares = []
    for i in range(num_shares):
        metadata = ShareMetadata(
            threshold=threshold,
            total_shares=num_shares,
            share_index=i + 1,  # 1-based index
            key_id=key_id,
        )
        shares.append(Share(metadata, bytes(share_data[i])))

    return shares


def combine_shares(shares: List[Share]) -> SecureBytes:
    """Combine shares to reconstruct the original secret.

    Args:
        shares: List of Share objects (must have at least threshold shares).

    Returns:
        The reconstructed secret as a wipeable SecureBytes buffer; the
        caller must secure_memzero it when done.

    Raises:
        SecretSharingError: If shares are invalid or insufficient.
    """
    if not shares:
        raise SecretSharingError("No shares provided")

    # Validate all shares have matching key_ids
    key_ids = {s.metadata.key_id for s in shares}
    if len(key_ids) > 1:
        raise SecretSharingError("Shares have mismatched key_ids")

    # Cross-validate threshold and total_shares across all shares (M3)
    thresholds = {s.metadata.threshold for s in shares}
    if len(thresholds) > 1:
        raise SecretSharingError("Shares have mismatched threshold values")
    total_shares_set = {s.metadata.total_shares for s in shares}
    if len(total_shares_set) > 1:
        raise SecretSharingError("Shares have mismatched total_shares values")

    # Check threshold
    threshold = shares[0].metadata.threshold
    if len(shares) < threshold:
        raise SecretSharingError(f"Insufficient shares: need {threshold}, have {len(shares)}")

    # Validate share_index values are in valid GF(256) range [1, 255] (M2)
    indices = [s.metadata.share_index for s in shares]
    for idx in indices:
        if not isinstance(idx, int) or idx < 1 or idx > 255:
            raise SecretSharingError(f"Invalid share_index {idx}: must be an integer in [1, 255]")

    # Check for duplicate indices
    if len(set(indices)) != len(indices):
        raise SecretSharingError("Duplicate share indices detected")

    # All shares must have same data length
    lengths = {len(s.data) for s in shares}
    if len(lengths) > 1:
        raise SecretSharingError("Shares have inconsistent data lengths")

    secret_len = len(shares[0].data)
    # Use SecureBytes so the reconstructed secret is auto-wiped on GC
    result = SecureBytes(secret_len)

    for byte_idx in range(secret_len):
        points = []
        for share in shares:
            x = share.metadata.share_index
            y = share.data[byte_idx]
            points.append((x, y))
        result[byte_idx] = GF256.lagrange_interpolate(points)

    # Return the SecureBytes itself (a bytearray subclass): converting to
    # bytes here would leave an unwipeable immutable copy of the secret in
    # the heap, defeating the wipeable buffer above. Callers wipe it via
    # secure_memzero when done.
    return result


# ──────────────────────────────────────────────────
# CLI helpers
# ──────────────────────────────────────────────────


def split_secret_cli(args) -> None:
    """CLI handler for split-secret action.

    Reads the password, splits it into shares, and writes share files.

    Args:
        args: Parsed CLI arguments.
    """
    import getpass

    quiet = getattr(args, "quiet", False)
    password_secure = None

    # Validate the sharing arguments before any password handling, so bad
    # invocations fail fast without prompting or touching secret material.
    # --shares arrives as a list from the shared nargs="+" definition
    # (gitlab#276); split-secret needs exactly one integer.
    shares_raw = getattr(args, "shares", None)
    if shares_raw is None:
        raise ValueError("split-secret requires --shares <N> (total number of shares to create)")
    if isinstance(shares_raw, list):
        if len(shares_raw) != 1:
            raise ValueError("split-secret takes a single integer for --shares")
        shares_raw = shares_raw[0]
    try:
        num_shares = int(shares_raw)
    except (TypeError, ValueError):
        # Deliberately does not echo the rejected token: a mis-ordered argv
        # can put a password where the count belongs (gitlab#276 review).
        raise ValueError("--shares must be a single integer for split-secret")
    threshold_raw = getattr(args, "threshold", None)
    if threshold_raw is None:
        raise ValueError(
            "split-secret requires --threshold <K> (minimum shares needed to reconstruct)"
        )
    try:
        threshold = int(threshold_raw)
    except (TypeError, ValueError):
        # The parser keeps --threshold a raw string precisely so this error
        # never echoes the token (a mis-ordered argv can put a password here).
        raise ValueError("--threshold must be a single integer for split-secret")
    # Range/relationship checks duplicated from split_secret() so that a bad
    # invocation fails before the password is prompted for or read.
    if threshold < 2:
        raise ValueError("--threshold must be at least 2")
    if num_shares < threshold:
        raise ValueError(f"--shares ({num_shares}) must be at least the --threshold ({threshold})")
    if num_shares > 255:
        raise ValueError("--shares must be at most 255")

    # Pre-flight the destination before any password handling: refuse an
    # --output-dir that names a non-directory, and refuse if ANY target share
    # name already exists — writing incrementally into a partially colliding
    # set would otherwise abort midway, leaving a mixed/partial share set
    # (the per-file O_EXCL create remains the race-proof backstop).
    output_dir = getattr(args, "output_dir", None) or "."
    if os.path.exists(output_dir) and not os.path.isdir(output_dir):
        raise ValueError(f"--output-dir is not a directory: {sanitize_for_display(output_dir)}")
    if os.path.isdir(output_dir):
        existing = [
            f"share_{i}.json"
            for i in range(1, num_shares + 1)
            if os.path.lexists(os.path.join(output_dir, f"share_{i}.json"))
        ]
        if existing:
            raise ValueError(
                f"Share file(s) already exist in {sanitize_for_display(output_dir)}: "
                f"{', '.join(existing)} — choose a different --output-dir or move them away"
            )

    try:
        # Get password
        password = getattr(args, "password", None)
        if password is None:
            env_password = os.environ.get("CRYPT_PASSWORD")
            if env_password is not None:
                # Same hygiene as the encrypt path (gitlab#147): register the
                # fingerprint for log redaction, then clear the variable so
                # child processes cannot inherit it.
                from .crypt_cli import clear_password_environment
                from .security_logger import register_consumed_secret

                register_consumed_secret("CRYPT_PASSWORD", env_password)
                password = env_password
                clear_password_environment()
        if password is None:
            # Nothing verifies this password against anything (split-secret
            # deliberately takes no input file), so a typo would silently
            # produce shares of an unusable password: confirm interactively.
            password = getpass.getpass("Password to split into shares: ")
            confirm = getpass.getpass("Confirm password: ")
            if not secrets.compare_digest(password.encode("utf-8"), confirm.encode("utf-8")):
                raise ValueError("Passwords do not match")
            confirm = None

        if isinstance(password, str):
            password = password.encode("utf-8")

        # Store password in SecureBytes for auto-wipe on scope exit
        password_secure = SecureBytes(password)
        # Wipe the original password variable
        if isinstance(password, bytearray):
            secure_memzero(password)
        password = None

        if not os.path.isdir(output_dir):
            # 0700 from the first component: the directory holds a key-escrow
            # set. A pre-existing directory is deliberately left untouched
            # (chmod'ing the user's cwd — the default — would be hostile).
            from .file_permissions import create_secure_directory

            create_secure_directory(output_dir)

        # split_secret only iterates the buffer, so hand it the wipeable
        # SecureBytes instead of an immutable copy (gitlab#276 review).
        shares = split_secret(password_secure, threshold, num_shares)

        for share in shares:
            filename = f"share_{share.metadata.share_index}.json"
            filepath = os.path.join(output_dir, filename)
            share.to_file(filepath)
            if not quiet:
                eprint(f"  Written: {filepath}")

        if not quiet:
            eprint(f"\nSplit into {num_shares} shares (threshold: {threshold})")
            eprint(f"Key ID: {sanitize_for_display(shares[0].metadata.key_id)}")
            eprint(f"Any {threshold} of {num_shares} shares can reconstruct the secret.")
    finally:
        # Securely wipe password from memory
        if password_secure is not None:
            secure_memzero(password_secure)


def combine_secrets_cli(args) -> None:
    """CLI handler for combine-secrets action.

    Reads share files, reconstructs the password, and decrypts the file.

    Args:
        args: Parsed CLI arguments.
    """
    from .crypt_core import decrypt_file

    quiet = getattr(args, "quiet", False)
    share_paths = getattr(args, "shares", None)
    if not share_paths:
        raise ValueError(
            "combine-secrets requires --shares <share-file> [<share-file> ...] "
            "(paths of the share files to combine)"
        )
    if isinstance(share_paths, str):
        share_paths = [share_paths]
    input_file = getattr(args, "input", None)
    if not input_file:
        raise ValueError("combine-secrets requires --input <encrypted-file>")
    output_file = getattr(args, "output", None)
    if not output_file:
        raise ValueError("combine-secrets requires --output <decrypted-file>")
    password_secure = None

    try:
        # Load shares
        shares = []
        for path in share_paths:
            share = Share.from_file(path)
            shares.append(share)

        if not quiet:
            eprint(f"Loaded {len(shares)} shares")
            eprint(f"Key ID: {sanitize_for_display(shares[0].metadata.key_id)}")
            eprint(f"Threshold: {shares[0].metadata.threshold}")

        # combine_shares returns a wipeable SecureBytes: use it directly
        # instead of copying through immutable bytes (gitlab#276 review),
        # and wipe it in the finally below.
        password_secure = combine_shares(shares)

        if not quiet:
            eprint("Secret reconstructed successfully")
            eprint(f"Decrypting {input_file}...")

        # Decrypt file
        # Pass the wipeable buffer itself; decrypt_file only special-cases
        # str and treats bytes-like input uniformly.
        decrypt_file(
            input_file=input_file,
            output_file=output_file,
            password=password_secure,
            quiet=quiet,
        )

        if not quiet:
            eprint(f"Decrypted to: {output_file}")
    finally:
        # Securely wipe reconstructed password from memory
        if password_secure is not None:
            secure_memzero(password_secure)
