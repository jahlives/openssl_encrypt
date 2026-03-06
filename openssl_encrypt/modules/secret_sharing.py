#!/usr/bin/env python3
"""
Shamir's Secret Sharing over GF(256).

Provides K-of-N threshold secret sharing for splitting secrets (passwords,
keys) into shares such that any K shares can reconstruct the original but
fewer than K shares reveal no information.

Uses GF(2^8) with irreducible polynomial x^8+x^4+x^3+x+1 (0x11B) for
constant-time table-lookup arithmetic. No external dependencies.
"""

import datetime
import json
import os
import secrets
import uuid
from dataclasses import asdict, dataclass
from typing import List, Optional, Tuple

from .crypt_errors import SecretSharingError
from .secure_memory import SecureBytes, secure_memzero

# ──────────────────────────────────────────────────
# GF(256) Arithmetic
# ──────────────────────────────────────────────────


class GF256:
    """Galois Field GF(2^8) arithmetic with pre-computed lookup tables.

    Uses irreducible polynomial x^8+x^4+x^3+x+1 (0x11B, AES polynomial).
    All operations are table-lookup based for consistent timing.
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

        if obj.get("header") != SHARE_FILE_HEADER:
            raise SecretSharingError(f"Invalid share header: expected '{SHARE_FILE_HEADER}'")

        meta_dict = obj.get("metadata", {})
        metadata = ShareMetadata(
            threshold=meta_dict["threshold"],
            total_shares=meta_dict["total_shares"],
            share_index=meta_dict["share_index"],
            key_id=meta_dict["key_id"],
            algorithm=meta_dict.get("algorithm", "shamir-gf256"),
            created_at=meta_dict.get("created_at", ""),
        )
        data = bytes(obj["data"])
        return cls(metadata, data)

    def to_file(self, filepath: str) -> None:
        """Write share to a file with restrictive permissions (0o600).

        Args:
            filepath: Path to write the share file.
        """
        with open(filepath, "w") as f:
            f.write(self.to_json())
        os.chmod(filepath, 0o600)

    @classmethod
    def from_file(cls, filepath: str) -> "Share":
        """Read share from a file.

        Args:
            filepath: Path to the share file.

        Returns:
            Share instance.

        Raises:
            SecretSharingError: If file cannot be read or parsed.
        """
        try:
            with open(filepath, "r") as f:
                return cls.from_json(f.read())
        except OSError as e:
            raise SecretSharingError(f"Cannot read share file: {e}")


# ──────────────────────────────────────────────────
# Split / Combine
# ──────────────────────────────────────────────────


def split_secret(
    secret: bytes,
    threshold: int,
    num_shares: int,
    key_id: Optional[str] = None,
) -> List[Share]:
    """Split a secret into shares using Shamir's Secret Sharing.

    Args:
        secret: The secret bytes to split.
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

        # Securely wipe the random coefficients (they contain partial secret info)
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


def combine_shares(shares: List[Share]) -> bytes:
    """Combine shares to reconstruct the original secret.

    Args:
        shares: List of Share objects (must have at least threshold shares).

    Returns:
        The reconstructed secret bytes.

    Raises:
        SecretSharingError: If shares are invalid or insufficient.
    """
    if not shares:
        raise SecretSharingError("No shares provided")

    # Validate all shares have matching key_ids
    key_ids = {s.metadata.key_id for s in shares}
    if len(key_ids) > 1:
        raise SecretSharingError("Shares have mismatched key_ids")

    # Check threshold
    threshold = shares[0].metadata.threshold
    if len(shares) < threshold:
        raise SecretSharingError(f"Insufficient shares: need {threshold}, have {len(shares)}")

    # Check for duplicate indices
    indices = [s.metadata.share_index for s in shares]
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

    return bytes(result)


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

    try:
        # Get password
        password = getattr(args, "password", None)
        if password is None:
            password = os.environ.get("CRYPT_PASSWORD")
        if password is None:
            password = getpass.getpass("Password for the encrypted file: ")

        if isinstance(password, str):
            password = password.encode("utf-8")

        # Store password in SecureBytes for auto-wipe on scope exit
        password_secure = SecureBytes(password)
        # Wipe the original password variable
        if isinstance(password, bytearray):
            secure_memzero(password)
        password = None

        threshold = args.threshold
        num_shares = args.shares
        output_dir = getattr(args, "output_dir", ".")

        if not os.path.isdir(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        shares = split_secret(bytes(password_secure), threshold, num_shares)

        for share in shares:
            filename = f"share_{share.metadata.share_index}.json"
            filepath = os.path.join(output_dir, filename)
            share.to_file(filepath)
            if not quiet:
                print(f"  Written: {filepath}")

        if not quiet:
            print(f"\nSplit into {num_shares} shares (threshold: {threshold})")
            print(f"Key ID: {shares[0].metadata.key_id}")
            print(f"Any {threshold} of {num_shares} shares can reconstruct the secret.")
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
    share_paths = args.shares
    input_file = args.input
    output_file = args.output
    password_secure = None

    try:
        # Load shares
        shares = []
        for path in share_paths:
            share = Share.from_file(path)
            shares.append(share)

        if not quiet:
            print(f"Loaded {len(shares)} shares")
            print(f"Key ID: {shares[0].metadata.key_id}")
            print(f"Threshold: {shares[0].metadata.threshold}")

        # Reconstruct password into SecureBytes
        password_raw = combine_shares(shares)
        password_secure = SecureBytes(password_raw)
        # Wipe the intermediate bytearray
        if isinstance(password_raw, bytearray):
            secure_memzero(password_raw)
        password_raw = None

        if not quiet:
            print("Secret reconstructed successfully")
            print(f"Decrypting {input_file}...")

        # Decrypt file
        decrypt_file(
            input_file=input_file,
            output_file=output_file,
            password=bytes(password_secure),
            quiet=quiet,
        )

        if not quiet:
            print(f"Decrypted to: {output_file}")
    finally:
        # Securely wipe reconstructed password from memory
        if password_secure is not None:
            secure_memzero(password_secure)
