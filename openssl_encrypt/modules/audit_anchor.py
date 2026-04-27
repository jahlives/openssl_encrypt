#!/usr/bin/env python3
"""
Merkle anchors for the tamper-evident audit chain.

An anchor seals a window of regular chain records by:
  1. Building a binary Merkle tree over the per-record chain hashes, with
     RFC 6962-style domain separation (0x00 prefix for leaves, 0x01 for
     internal nodes; odd levels duplicate the trailing leaf).
  2. Signing the resulting Merkle root with ML-DSA-65 (FIPS 204).

Anchors are emitted as ``audit.anchor`` records and travel through the same
chain machinery (seq, prev_hash, mac), so an attacker who tampers with an
anchor after the fact still breaks the chain at the anchor's seq. The
signature gives non-repudiation against a future compromise of the live
forward-secure MAC key.
"""

import base64
import hashlib
from typing import Any, Dict, List, Sequence, Union

from .pqc_signing import PQCSigner, SignatureAlgorithm

ANCHOR_EVENT_TYPE = "audit.anchor"
ANCHOR_SEVERITY = "info"
DEFAULT_ANCHOR_ALG = SignatureAlgorithm.ML_DSA_65

# RFC 6962-style domain separators.
_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"

# Sentinel returned when an anchor is requested over zero leaves; the chain
# never actually emits anchors over an empty window, but having a stable
# value avoids a special case in the verifier.
EMPTY_MERKLE_ROOT: str = "blake2b-256:" + hashlib.blake2b(b"\x00empty", digest_size=32).hexdigest()


def _to_bytes(leaf: Union[bytes, str]) -> bytes:
    if isinstance(leaf, bytes):
        return leaf
    return leaf.encode("utf-8")


def merkle_root(leaves: Sequence[Union[bytes, str]]) -> str:
    """Compute the Merkle root over ``leaves``.

    Each leaf is hashed with ``blake2b(0x00 || leaf, 32)``. Internal nodes
    are ``blake2b(0x01 || left || right, 32)``. Odd levels duplicate the
    trailing node before pairing.

    Returns ``"blake2b-256:<hex>"``. Returns ``EMPTY_MERKLE_ROOT`` if the
    leaves list is empty.
    """
    if not leaves:
        return EMPTY_MERKLE_ROOT

    nodes: List[bytes] = [
        hashlib.blake2b(_LEAF_PREFIX + _to_bytes(leaf), digest_size=32).digest() for leaf in leaves
    ]
    while len(nodes) > 1:
        next_level: List[bytes] = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
            next_level.append(hashlib.blake2b(_NODE_PREFIX + left + right, digest_size=32).digest())
        nodes = next_level
    return f"blake2b-256:{nodes[0].hex()}"


class AnchorSigner:
    """Thin wrapper over ``PQCSigner`` that pins the algorithm to ML-DSA-65.

    Kept as a class so future seed-rotation / HSM-backed signing can swap
    in alternative implementations without changing call sites.
    """

    def __init__(self, algorithm: str = DEFAULT_ANCHOR_ALG):
        self.algorithm = algorithm
        self._signer = PQCSigner(algorithm)

    def generate_keypair(self):
        return self._signer.generate_keypair()

    def sign(self, message: bytes, privkey: bytes) -> bytes:
        return self._signer.sign(message, privkey)

    def verify(self, message: bytes, signature: bytes, pubkey: bytes) -> bool:
        return self._signer.verify(message, signature, pubkey)


def build_anchor_payload(
    *,
    anchor_seq_start: int,
    anchor_seq_end: int,
    leaves: Sequence[Union[bytes, str]],
    signer: AnchorSigner,
    privkey: bytes,
    pubkey: bytes,
) -> Dict[str, Any]:
    """Produce an unsigned event-shaped dict ready to be appended to the chain.

    The returned dict has ``event_type=audit.anchor`` and a ``details`` block
    containing the anchor metadata + ML-DSA-65 signature over the Merkle
    root. The caller is expected to pass it through ``ChainState.append_record``
    so the anchor inherits seq/prev_hash/mac like any other record.
    """
    root = merkle_root(leaves)
    signature = signer.sign(root.encode("ascii"), privkey)
    return {
        "event_type": ANCHOR_EVENT_TYPE,
        "severity": ANCHOR_SEVERITY,
        "details": {
            "anchor_seq_start": int(anchor_seq_start),
            "anchor_seq_end": int(anchor_seq_end),
            "merkle_root": root,
            "signature": {
                "alg": signer.algorithm,
                "value_b64": base64.b64encode(signature).decode("ascii"),
                "pubkey_b64": base64.b64encode(pubkey).decode("ascii"),
            },
        },
    }


def verify_anchor_payload(
    payload: Dict[str, Any],
    leaves: Sequence[Union[bytes, str]],
) -> bool:
    """Verify a sealed anchor.

    Returns True iff:
      * the embedded Merkle root matches the one recomputed over ``leaves``;
      * the embedded ML-DSA signature verifies against the embedded pubkey.

    The pubkey is *also* verified against an external trust root by the
    caller (the verifier compares it to the keystore-pinned anchor pubkey;
    here we only validate that the anchor is internally consistent).
    """
    try:
        details = payload["details"]
        claimed_root = details["merkle_root"]
        sig_block = details["signature"]
        signature = base64.b64decode(sig_block["value_b64"])
        pubkey = base64.b64decode(sig_block["pubkey_b64"])
        algorithm = sig_block.get("alg", DEFAULT_ANCHOR_ALG)
    except (KeyError, ValueError, TypeError):
        return False

    if merkle_root(leaves) != claimed_root:
        return False

    signer = AnchorSigner(algorithm=algorithm)
    try:
        return signer.verify(claimed_root.encode("ascii"), signature, pubkey)
    except Exception:
        return False


__all__ = [
    "ANCHOR_EVENT_TYPE",
    "ANCHOR_SEVERITY",
    "DEFAULT_ANCHOR_ALG",
    "EMPTY_MERKLE_ROOT",
    "AnchorSigner",
    "merkle_root",
    "build_anchor_payload",
    "verify_anchor_payload",
]
