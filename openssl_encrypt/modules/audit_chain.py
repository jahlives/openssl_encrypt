#!/usr/bin/env python3
"""
Tamper-evident audit chain primitives.

Provides forward-secure HMAC keys, per-record sequence + prev_hash linking,
canonical JSON encoding, and atomic state-file persistence. Layered on top
of the existing ``security_logger`` so any silent modification, deletion,
or reordering of audit records is detectable by an offline verifier.

Design notes (see docs/AUDIT_CHAIN.md for the full spec):

* Record MAC: HMAC-SHA256 over the canonical encoding of the record minus
  the ``mac`` field, keyed with K_seq.
* prev_hash: BLAKE2b-256 over the canonical encoding of the *full* prior
  record (including its MAC), so the chain commits to MACs.
* Forward-secure keys: K_0 = HKDF(seed, info=b"ssle-audit-mac-v1"),
  K_{n+1} = HKDF(K_n, info=b"ssle-audit-evolve-v1"). After writing record n
  the state retains only K_{n+1}; K_n is wiped via ``secure_memzero``.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .file_permissions import PermissionLevel, create_secure_file
from .secure_memory import secure_memzero

_logger = logging.getLogger(__name__)

# --- Domain-separation constants (versioned; bump suffix to migrate) ---

_GENESIS_INPUT = b"ssle-audit-genesis-v1"
_HKDF_INFO_INIT = b"ssle-audit-mac-v1"
_HKDF_INFO_EVOLVE = b"ssle-audit-evolve-v1"

GENESIS_PREV_HASH: str = (
    "blake2b-256:" + hashlib.blake2b(_GENESIS_INPUT, digest_size=32).hexdigest()
)

STATE_FILE_VERSION = 1


# --- Canonical encoding ---


def canonical_encode(record: Dict[str, Any]) -> bytes:
    """Encode a record as canonical UTF-8 JSON: sorted keys, no whitespace.

    The encoding is the input to both the MAC and the chain hash, so it must
    be byte-for-byte stable across Python versions and platforms. We rely on
    ``json.dumps`` with ``sort_keys=True``, ``ensure_ascii=False``, and tight
    separators — non-ASCII strings round-trip via UTF-8 rather than ``\\uXXXX``
    escapes (deterministic; spec is locked by the test suite).
    """
    return json.dumps(
        record,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


# --- Forward-secure key evolution ---


def derive_initial_key(seed: bytes) -> bytes:
    """K_0 = HKDF-SHA256(seed, info=ssle-audit-mac-v1, L=32)."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO_INIT,
    ).derive(bytes(seed))


def evolve_key(current_key: bytes) -> bytes:
    """K_{n+1} = HKDF-SHA256(K_n, info=ssle-audit-evolve-v1, L=32)."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO_EVOLVE,
    ).derive(bytes(current_key))


# --- Record-level primitives ---


def compute_record_mac(record_without_mac: Dict[str, Any], key: bytes) -> str:
    """HMAC-SHA256 over the canonical encoding of the record (minus MAC)."""
    digest = hmac.new(bytes(key), canonical_encode(record_without_mac), hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def compute_record_hash(record_with_mac: Dict[str, Any]) -> str:
    """BLAKE2b-256 over the canonical encoding of the full record (incl. MAC)."""
    digest = hashlib.blake2b(canonical_encode(record_with_mac), digest_size=32).hexdigest()
    return f"blake2b-256:{digest}"


# --- Chain state ---


@dataclass
class ChainState:
    """Mutable state advanced by ``append_record`` and persisted atomically.

    Holds K_n (the key that will MAC the *next* record) plus the running
    sequence number, the hash of the most recently emitted record, and the
    list of chain-hashes accumulated since the last anchor (used by
    ``audit_anchor.merkle_root`` when the next anchor is emitted).
    """

    current_seq: int
    current_key: bytes
    last_record_hash: str
    last_anchor_seq: int = -1
    pending_leaves: List[str] = field(default_factory=list)
    version: int = field(default=STATE_FILE_VERSION)

    @classmethod
    def initial(cls, seed: bytes) -> "ChainState":
        return cls(
            current_seq=0,
            current_key=bytearray(derive_initial_key(seed)),
            last_record_hash=GENESIS_PREV_HASH,
            last_anchor_seq=-1,
            pending_leaves=[],
        )

    def append_record(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Augment ``payload`` with seq/prev_hash/mac and advance internal state.

        Returns a *new* dict ready for JSON-line serialization; the caller's
        payload is left untouched.
        """
        record = dict(payload)
        record["seq"] = self.current_seq
        record["prev_hash"] = self.last_record_hash
        record["mac"] = compute_record_mac(record, self.current_key)

        new_key = evolve_key(self.current_key)
        try:
            secure_memzero(self.current_key)
        except Exception as exc:
            # Best-effort wipe; if memzero refuses (e.g. on a platform that
            # cannot mlock) we still drop the reference below.
            _logger.debug("audit_chain: secure_memzero of stale MAC key failed: %s", exc)
        self.current_key = bytearray(new_key)
        self.current_seq += 1
        self.last_record_hash = compute_record_hash(record)
        self.pending_leaves.append(self.last_record_hash)
        return record

    # --- Serialization ---

    def _to_json_obj(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "current_seq": self.current_seq,
            "current_key_b64": base64.b64encode(bytes(self.current_key)).decode("ascii"),
            "last_record_hash": self.last_record_hash,
            "last_anchor_seq": self.last_anchor_seq,
            "pending_leaves": list(self.pending_leaves),
        }

    def save_atomic(self, path: Path) -> None:
        """Atomic write via tempfile + ``os.replace`` with 0600 permissions.

        The tempfile is created next to ``path`` so ``os.replace`` is atomic
        on the same filesystem. fsyncs both the file and the directory.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        data = json.dumps(self._to_json_obj(), sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )

        # Use mkstemp in the target directory so os.replace is atomic.
        fd, tmp_path = tempfile.mkstemp(prefix=".audit-state.", dir=str(path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
            # fsync the directory so the rename is durable.
            dir_fd = os.open(str(path.parent), os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except Exception:
            # Clean up the tempfile if we failed before replace().
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except OSError:
                pass
            raise

    @classmethod
    def load(cls, path: Path) -> "ChainState":
        path = Path(path)
        with open(path, "rb") as f:
            data = json.loads(f.read())
        if data.get("version") != STATE_FILE_VERSION:
            raise ValueError(
                f"unsupported audit state version: {data.get('version')!r}; "
                f"expected {STATE_FILE_VERSION}"
            )
        return cls(
            current_seq=int(data["current_seq"]),
            current_key=bytearray(base64.b64decode(data["current_key_b64"])),
            last_record_hash=str(data["last_record_hash"]),
            last_anchor_seq=int(data.get("last_anchor_seq", -1)),
            pending_leaves=[str(x) for x in data.get("pending_leaves", [])],
            version=int(data["version"]),
        )


def create_secure_state_file(path: Path) -> None:
    """Create an empty state file with 0600 permissions (used on first init).

    Provided as a helper for callers that want to pre-create the file before
    the first ``save_atomic``; ``save_atomic`` itself creates the file.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not path.exists():
        fd = create_secure_file(path, PermissionLevel.OWNER_ONLY)
        os.close(fd)


__all__ = [
    "GENESIS_PREV_HASH",
    "STATE_FILE_VERSION",
    "canonical_encode",
    "derive_initial_key",
    "evolve_key",
    "compute_record_mac",
    "compute_record_hash",
    "ChainState",
    "create_secure_state_file",
]
