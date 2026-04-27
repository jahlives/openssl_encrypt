#!/usr/bin/env python3
"""
Offline verifier for the tamper-evident audit chain.

Walks one or more JSONL audit log files (oldest → newest, supporting log
rotation) and produces a structured ``VerificationReport``. The verifier
re-derives the forward-secure key sequence K_0, K_1, ... directly from the
seed and checks each record's HMAC, prev_hash linkage, and seq monotonicity.

Optionally accepts a ``ChainState`` to detect tail-truncation (records lost
between the last flush of state and the most recent log line).
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

from .audit_anchor import ANCHOR_EVENT_TYPE, verify_anchor_payload
from .audit_chain import (
    GENESIS_PREV_HASH,
    ChainState,
    canonical_encode,
    compute_record_hash,
    compute_record_mac,
    derive_initial_key,
    evolve_key,
)

# Reasons reported in VerificationFailure. Stable strings — surfaced by CLI.
REASON_MAC_MISMATCH = "mac_mismatch"
REASON_PREV_HASH_MISMATCH = "prev_hash_mismatch"
REASON_SEQ_GAP = "seq_gap"
REASON_MISSING_FIELD = "missing_field"
REASON_DECODE_ERROR = "decode_error"
REASON_TAIL_TRUNCATED = "tail_truncated"
REASON_ANCHOR_INVALID = "anchor_invalid"
REASON_ANCHOR_PUBKEY_MISMATCH = "anchor_pubkey_mismatch"
REASON_ANCHOR_WINDOW_INCOMPLETE = "anchor_window_incomplete"

_REQUIRED_FIELDS = ("seq", "prev_hash", "mac")


@dataclass
class VerificationFailure:
    seq: int
    reason: str
    message: str


@dataclass
class VerificationReport:
    intact: bool
    records_verified: int
    first_seq: int
    last_seq: int
    failures: List[VerificationFailure] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.intact


def _iter_lines(paths: Sequence[Path]) -> Iterable[tuple]:
    """Yield (path, line_no, raw_line) across an ordered list of files."""
    for path in paths:
        if not path.exists():
            continue
        with open(path, "r", encoding="utf-8") as f:
            for line_no, raw in enumerate(f, start=1):
                stripped = raw.strip()
                if not stripped:
                    continue
                yield path, line_no, stripped


def verify_chain(
    log_paths: Union[Path, str, Sequence[Union[Path, str]]],
    seed: bytes,
    *,
    expected_first_seq: int = 0,
    state: Optional[ChainState] = None,
    anchor_pubkey: Optional[bytes] = None,
    skip_anchors: bool = False,
) -> VerificationReport:
    """Verify an audit chain spanning one or more log files.

    Args:
        log_paths: Path or ordered sequence of paths (oldest first).
        seed: The 32-byte seed used to derive the initial MAC key.
        expected_first_seq: Sequence number expected for the first record;
            defaults to 0. Set higher for partial verification (e.g. when an
            anchor seals records [0, N) and you're verifying the tail only).
        state: If supplied, the verifier additionally checks that the on-disk
            chain reaches state.current_seq - 1 (catches tail truncation).
        anchor_pubkey: If supplied, every anchor's embedded pubkey must match
            this byte-for-byte (trust-root pinning). Catches the case where an
            attacker replaces both the anchor signature and the pubkey field.
        skip_anchors: If True, audit.anchor records are still chained-verified
            (seq/prev_hash/mac) but their Merkle/signature payload is not
            re-validated. Useful when liboqs is unavailable on the verifier.

    Returns:
        ``VerificationReport`` with ``intact`` set to True iff every check
        passed. Failures are appended in encounter order.
    """
    if isinstance(log_paths, (str, Path)):
        paths: Sequence[Path] = [Path(log_paths)]
    else:
        paths = [Path(p) for p in log_paths]

    failures: List[VerificationFailure] = []
    records_verified = 0
    first_seq_seen = -1
    last_seq_seen = -1

    expected_seq = expected_first_seq
    expected_prev_hash = GENESIS_PREV_HASH if expected_first_seq == 0 else None
    current_key = derive_initial_key(seed)
    # Skip evolution for any sealed records the caller said to start past.
    for _ in range(expected_first_seq):
        current_key = evolve_key(current_key)

    # Buffer chain hashes by seq so anchor verification can recompute the
    # Merkle root over its sealed window. We drop entries up to anchor_seq_end
    # after a successful anchor to keep memory bounded.
    chain_hashes_by_seq: dict = {}

    for path, line_no, raw in _iter_lines(paths):
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as exc:
            failures.append(
                VerificationFailure(
                    seq=expected_seq,
                    reason=REASON_DECODE_ERROR,
                    message=f"{path}:{line_no}: invalid JSON: {exc.msg}",
                )
            )
            return VerificationReport(
                intact=False,
                records_verified=records_verified,
                first_seq=first_seq_seen,
                last_seq=last_seq_seen,
                failures=failures,
            )

        if not isinstance(record, dict):
            failures.append(
                VerificationFailure(
                    seq=expected_seq,
                    reason=REASON_DECODE_ERROR,
                    message=f"{path}:{line_no}: top-level value is not an object",
                )
            )
            return _finalize(failures, records_verified, first_seq_seen, last_seq_seen)

        # Structural checks.
        missing = [f for f in _REQUIRED_FIELDS if f not in record]
        if missing:
            failures.append(
                VerificationFailure(
                    seq=record.get("seq", expected_seq),
                    reason=REASON_MISSING_FIELD,
                    message=f"{path}:{line_no}: missing chain fields: {missing}",
                )
            )
            return _finalize(failures, records_verified, first_seq_seen, last_seq_seen)

        seq = record["seq"]

        # Sequence-gap check.
        if seq != expected_seq:
            failures.append(
                VerificationFailure(
                    seq=expected_seq,
                    reason=REASON_SEQ_GAP,
                    message=(f"{path}:{line_no}: expected seq={expected_seq}, " f"got seq={seq}"),
                )
            )
            return _finalize(failures, records_verified, first_seq_seen, last_seq_seen)

        # prev_hash linkage check.
        if expected_prev_hash is not None and record["prev_hash"] != expected_prev_hash:
            failures.append(
                VerificationFailure(
                    seq=seq,
                    reason=REASON_PREV_HASH_MISMATCH,
                    message=(
                        f"{path}:{line_no}: prev_hash mismatch at seq={seq}: "
                        f"expected {expected_prev_hash}, got {record['prev_hash']}"
                    ),
                )
            )
            return _finalize(failures, records_verified, first_seq_seen, last_seq_seen)

        # MAC check.
        record_without_mac = {k: v for k, v in record.items() if k != "mac"}
        recomputed_mac = compute_record_mac(record_without_mac, current_key)
        if not _const_time_str_eq(recomputed_mac, record["mac"]):
            failures.append(
                VerificationFailure(
                    seq=seq,
                    reason=REASON_MAC_MISMATCH,
                    message=f"{path}:{line_no}: MAC verification failed at seq={seq}",
                )
            )
            return _finalize(failures, records_verified, first_seq_seen, last_seq_seen)

        # All checks passed; advance.
        if first_seq_seen == -1:
            first_seq_seen = seq
        last_seq_seen = seq
        records_verified += 1
        expected_seq = seq + 1
        record_hash = compute_record_hash(record)
        expected_prev_hash = record_hash
        chain_hashes_by_seq[seq] = record_hash
        current_key = evolve_key(current_key)

        # Anchor validation (Merkle root + ML-DSA-65 signature).
        if not skip_anchors and record.get("event_type") == ANCHOR_EVENT_TYPE:
            anchor_failure = _verify_anchor_record(record, chain_hashes_by_seq, anchor_pubkey)
            if anchor_failure is not None:
                failures.append(anchor_failure)
                return _finalize(failures, records_verified, first_seq_seen, last_seq_seen)
            # Drop sealed window from the buffer to bound memory.
            try:
                end = int(record["details"]["anchor_seq_end"])
            except (KeyError, TypeError, ValueError):
                end = seq - 1
            for sealed_seq in list(chain_hashes_by_seq.keys()):
                if sealed_seq <= end:
                    chain_hashes_by_seq.pop(sealed_seq, None)

    # Tail-truncation check (only if caller passed a state snapshot).
    if state is not None:
        on_disk_next_seq = last_seq_seen + 1 if last_seq_seen >= 0 else expected_first_seq
        if on_disk_next_seq < state.current_seq:
            failures.append(
                VerificationFailure(
                    seq=on_disk_next_seq,
                    reason=REASON_TAIL_TRUNCATED,
                    message=(
                        f"state has current_seq={state.current_seq} but log "
                        f"ends at seq={last_seq_seen}; "
                        f"{state.current_seq - on_disk_next_seq} record(s) missing"
                    ),
                )
            )

    return _finalize(failures, records_verified, first_seq_seen, last_seq_seen)


def _verify_anchor_record(
    record: Dict[str, Any],
    chain_hashes_by_seq: Dict[int, str],
    anchor_pubkey: Optional[bytes],
) -> Optional[VerificationFailure]:
    """Validate one audit.anchor record. Returns a failure or None."""
    try:
        details = record["details"]
        start = int(details["anchor_seq_start"])
        end = int(details["anchor_seq_end"])
    except (KeyError, TypeError, ValueError):
        return VerificationFailure(
            seq=int(record.get("seq", -1)),
            reason=REASON_ANCHOR_INVALID,
            message=f"anchor at seq={record.get('seq')} has malformed details",
        )

    # Reconstruct the leaf set the anchor claims to seal.
    missing = [s for s in range(start, end + 1) if s not in chain_hashes_by_seq]
    if missing:
        return VerificationFailure(
            seq=int(record["seq"]),
            reason=REASON_ANCHOR_WINDOW_INCOMPLETE,
            message=(
                f"anchor at seq={record['seq']} seals window [{start}..{end}] but "
                f"records for seqs {missing[:5]}{'...' if len(missing) > 5 else ''} "
                f"are not present in the verifier's window buffer"
            ),
        )

    # Optional pubkey pinning before the more expensive cryptographic check.
    if anchor_pubkey is not None:
        try:
            import base64

            embedded_pubkey = base64.b64decode(details["signature"]["pubkey_b64"])
        except (KeyError, ValueError, TypeError):
            return VerificationFailure(
                seq=int(record["seq"]),
                reason=REASON_ANCHOR_INVALID,
                message=f"anchor at seq={record['seq']} has malformed signature block",
            )
        if embedded_pubkey != anchor_pubkey:
            return VerificationFailure(
                seq=int(record["seq"]),
                reason=REASON_ANCHOR_PUBKEY_MISMATCH,
                message=(
                    f"anchor at seq={record['seq']} embeds a pubkey that does not "
                    f"match the pinned trust root"
                ),
            )

    leaves = [chain_hashes_by_seq[s] for s in range(start, end + 1)]
    if not verify_anchor_payload(record, leaves):
        return VerificationFailure(
            seq=int(record["seq"]),
            reason=REASON_ANCHOR_INVALID,
            message=(
                f"anchor at seq={record['seq']} failed Merkle/signature "
                f"verification (window [{start}..{end}])"
            ),
        )
    return None


def _finalize(
    failures: List[VerificationFailure],
    records_verified: int,
    first_seq: int,
    last_seq: int,
) -> VerificationReport:
    return VerificationReport(
        intact=not failures,
        records_verified=records_verified,
        first_seq=first_seq,
        last_seq=last_seq,
        failures=failures,
    )


def _const_time_str_eq(a: str, b: str) -> bool:
    """Constant-time hex/string comparison."""
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a.encode("ascii", "replace"), b.encode("ascii", "replace")):
        diff |= x ^ y
    return diff == 0


__all__ = [
    "VerificationFailure",
    "VerificationReport",
    "verify_chain",
    "REASON_MAC_MISMATCH",
    "REASON_PREV_HASH_MISMATCH",
    "REASON_SEQ_GAP",
    "REASON_MISSING_FIELD",
    "REASON_DECODE_ERROR",
    "REASON_TAIL_TRUNCATED",
    "REASON_ANCHOR_INVALID",
    "REASON_ANCHOR_PUBKEY_MISMATCH",
    "REASON_ANCHOR_WINDOW_INCOMPLETE",
]
