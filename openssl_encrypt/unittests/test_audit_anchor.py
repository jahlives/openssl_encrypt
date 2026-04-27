#!/usr/bin/env python3
"""
Tests for the Merkle anchor module (audit_anchor.py).

Anchors seal a window of audit-chain records by:
  1. Hashing each record's chain-hash into the leaves of a binary Merkle tree
     with RFC 6962-style domain separation (0x00 for leaves, 0x01 for nodes).
  2. Signing the resulting Merkle root with ML-DSA-65.

The signed anchor is itself appended as a regular chain record, so
tampering with it after the fact still breaks the chain at its seq.
"""

import base64
import hashlib
import unittest


class TestMerkleRoot(unittest.TestCase):
    """Reference vectors for the Merkle construction."""

    def _leaf(self, data: bytes) -> bytes:
        return hashlib.blake2b(b"\x00" + data, digest_size=32).digest()

    def _node(self, left: bytes, right: bytes) -> bytes:
        return hashlib.blake2b(b"\x01" + left + right, digest_size=32).digest()

    def test_empty_leaves_returns_sentinel(self):
        from openssl_encrypt.modules.audit_anchor import EMPTY_MERKLE_ROOT, merkle_root

        self.assertEqual(merkle_root([]), EMPTY_MERKLE_ROOT)

    def test_single_leaf_root(self):
        from openssl_encrypt.modules.audit_anchor import merkle_root

        leaf_bytes = b"hello"
        expected = "blake2b-256:" + self._leaf(leaf_bytes).hex()
        self.assertEqual(merkle_root([leaf_bytes]), expected)

    def test_two_leaves_reference_vector(self):
        from openssl_encrypt.modules.audit_anchor import merkle_root

        l0 = self._leaf(b"a")
        l1 = self._leaf(b"b")
        expected = "blake2b-256:" + self._node(l0, l1).hex()
        self.assertEqual(merkle_root([b"a", b"b"]), expected)

    def test_three_leaves_duplicate_last_for_odd_count(self):
        from openssl_encrypt.modules.audit_anchor import merkle_root

        l0 = self._leaf(b"a")
        l1 = self._leaf(b"b")
        l2 = self._leaf(b"c")
        n_left = self._node(l0, l1)
        n_right = self._node(l2, l2)  # last leaf duplicated to balance.
        expected = "blake2b-256:" + self._node(n_left, n_right).hex()
        self.assertEqual(merkle_root([b"a", b"b", b"c"]), expected)

    def test_root_format(self):
        from openssl_encrypt.modules.audit_anchor import merkle_root

        root = merkle_root([b"x", b"y", b"z"])
        self.assertTrue(root.startswith("blake2b-256:"))
        self.assertEqual(len(root.split(":", 1)[1]), 64)

    def test_root_deterministic(self):
        from openssl_encrypt.modules.audit_anchor import merkle_root

        leaves = [bytes([i]) * 8 for i in range(7)]
        self.assertEqual(merkle_root(leaves), merkle_root(leaves))

    def test_root_changes_when_leaf_changes(self):
        from openssl_encrypt.modules.audit_anchor import merkle_root

        a = merkle_root([b"a", b"b", b"c"])
        b = merkle_root([b"a", b"X", b"c"])
        self.assertNotEqual(a, b)

    def test_root_accepts_string_leaves(self):
        """The audit chain emits chain-hash strings ("blake2b-256:..."); the
        Merkle root function must accept str OR bytes leaves."""
        from openssl_encrypt.modules.audit_anchor import merkle_root

        leaves_bytes = [b"blake2b-256:dead", b"blake2b-256:beef"]
        leaves_str = ["blake2b-256:dead", "blake2b-256:beef"]
        self.assertEqual(merkle_root(leaves_bytes), merkle_root(leaves_str))


class TestAnchorSigner(unittest.TestCase):
    """ML-DSA-65 wrapper used for anchor signatures."""

    def test_generate_keypair_returns_expected_sizes(self):
        from openssl_encrypt.modules.audit_anchor import AnchorSigner

        signer = AnchorSigner()
        pubkey, privkey = signer.generate_keypair()
        # ML-DSA-65 sizes: pk=1952, sk=4032 (per FIPS 204).
        self.assertEqual(len(pubkey), 1952)
        self.assertGreater(len(privkey), 1000)  # exact size varies by lib

    def test_sign_then_verify_round_trip(self):
        from openssl_encrypt.modules.audit_anchor import AnchorSigner

        signer = AnchorSigner()
        pubkey, privkey = signer.generate_keypair()

        message = b"blake2b-256:" + b"a" * 64
        signature = signer.sign(message, privkey)
        self.assertTrue(signer.verify(message, signature, pubkey))

    def test_verify_fails_with_wrong_pubkey(self):
        from openssl_encrypt.modules.audit_anchor import AnchorSigner

        signer = AnchorSigner()
        _, privkey = signer.generate_keypair()
        wrong_pubkey, _ = signer.generate_keypair()

        message = b"hello"
        signature = signer.sign(message, privkey)
        self.assertFalse(signer.verify(message, signature, wrong_pubkey))

    def test_verify_fails_with_modified_message(self):
        from openssl_encrypt.modules.audit_anchor import AnchorSigner

        signer = AnchorSigner()
        pubkey, privkey = signer.generate_keypair()

        signature = signer.sign(b"original", privkey)
        self.assertFalse(signer.verify(b"tampered", signature, pubkey))


class TestAnchorPayload(unittest.TestCase):
    """High-level helpers used by security_logger and the verifier."""

    def setUp(self):
        from openssl_encrypt.modules.audit_anchor import AnchorSigner

        self.signer = AnchorSigner()
        self.pubkey, self.privkey = self.signer.generate_keypair()

    def test_build_anchor_payload_includes_required_fields(self):
        from openssl_encrypt.modules.audit_anchor import build_anchor_payload

        leaves = [f"blake2b-256:{i:064x}" for i in range(5)]
        payload = build_anchor_payload(
            anchor_seq_start=0,
            anchor_seq_end=4,
            leaves=leaves,
            signer=self.signer,
            privkey=self.privkey,
            pubkey=self.pubkey,
        )

        self.assertEqual(payload["event_type"], "audit.anchor")
        self.assertEqual(payload["severity"], "info")
        details = payload["details"]
        self.assertEqual(details["anchor_seq_start"], 0)
        self.assertEqual(details["anchor_seq_end"], 4)
        self.assertTrue(details["merkle_root"].startswith("blake2b-256:"))
        sig = details["signature"]
        self.assertEqual(sig["alg"], "ML-DSA-65")
        self.assertIn("value_b64", sig)
        self.assertIn("pubkey_b64", sig)

    def test_verify_anchor_payload_succeeds_for_valid(self):
        from openssl_encrypt.modules.audit_anchor import (
            build_anchor_payload,
            verify_anchor_payload,
        )

        leaves = [f"blake2b-256:{i:064x}" for i in range(10)]
        payload = build_anchor_payload(
            anchor_seq_start=0,
            anchor_seq_end=9,
            leaves=leaves,
            signer=self.signer,
            privkey=self.privkey,
            pubkey=self.pubkey,
        )
        self.assertTrue(verify_anchor_payload(payload, leaves))

    def test_verify_anchor_payload_fails_when_root_modified(self):
        from openssl_encrypt.modules.audit_anchor import (
            build_anchor_payload,
            verify_anchor_payload,
        )

        leaves = [f"blake2b-256:{i:064x}" for i in range(5)]
        payload = build_anchor_payload(
            anchor_seq_start=0,
            anchor_seq_end=4,
            leaves=leaves,
            signer=self.signer,
            privkey=self.privkey,
            pubkey=self.pubkey,
        )
        # Tamper with the merkle_root field (signature still references the
        # original root, so verification should fail).
        payload["details"]["merkle_root"] = "blake2b-256:" + "0" * 64
        self.assertFalse(verify_anchor_payload(payload, leaves))

    def test_verify_anchor_payload_fails_when_leaves_changed(self):
        """Recomputed root from `leaves` must match the anchor's claim."""
        from openssl_encrypt.modules.audit_anchor import (
            build_anchor_payload,
            verify_anchor_payload,
        )

        leaves = [f"blake2b-256:{i:064x}" for i in range(5)]
        payload = build_anchor_payload(
            anchor_seq_start=0,
            anchor_seq_end=4,
            leaves=leaves,
            signer=self.signer,
            privkey=self.privkey,
            pubkey=self.pubkey,
        )
        bad_leaves = list(leaves)
        bad_leaves[2] = "blake2b-256:" + "f" * 64
        self.assertFalse(verify_anchor_payload(payload, bad_leaves))

    def test_verify_anchor_payload_fails_when_signature_modified(self):
        from openssl_encrypt.modules.audit_anchor import (
            build_anchor_payload,
            verify_anchor_payload,
        )

        leaves = [f"blake2b-256:{i:064x}" for i in range(5)]
        payload = build_anchor_payload(
            anchor_seq_start=0,
            anchor_seq_end=4,
            leaves=leaves,
            signer=self.signer,
            privkey=self.privkey,
            pubkey=self.pubkey,
        )
        # Flip a byte in the signature.
        sig_bytes = bytearray(base64.b64decode(payload["details"]["signature"]["value_b64"]))
        sig_bytes[0] ^= 0xFF
        payload["details"]["signature"]["value_b64"] = base64.b64encode(bytes(sig_bytes)).decode(
            "ascii"
        )
        self.assertFalse(verify_anchor_payload(payload, leaves))


if __name__ == "__main__":
    unittest.main()
