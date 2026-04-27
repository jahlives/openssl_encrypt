#!/usr/bin/env python3
"""
Tests for the tamper-evident audit chain primitives (audit_chain.py).

The audit chain provides:
  - Forward-secure HMAC keys (HKDF-SHA256 evolution).
  - Per-record sequence number, prev_hash linking, and HMAC.
  - Atomic state-file persistence (current key, current seq, last record hash).

These tests pin the cryptographic shape of the chain so that drift in the
canonical encoding, evolution KDF, or chaining rules is caught immediately.
"""

import hashlib
import hmac
import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path


class TestCanonicalEncoding(unittest.TestCase):
    """Stable JSON encoding is the foundation of the chain."""

    def test_canonical_encoding_sorts_keys(self):
        from openssl_encrypt.modules.audit_chain import canonical_encode

        a = canonical_encode({"b": 1, "a": 2})
        b = canonical_encode({"a": 2, "b": 1})
        self.assertEqual(a, b)

    def test_canonical_encoding_no_whitespace(self):
        from openssl_encrypt.modules.audit_chain import canonical_encode

        encoded = canonical_encode({"a": 1, "b": [1, 2, 3]})
        self.assertNotIn(b" ", encoded)

    def test_canonical_encoding_is_utf8_bytes(self):
        from openssl_encrypt.modules.audit_chain import canonical_encode

        encoded = canonical_encode({"msg": "héllo 中文"})
        self.assertIsInstance(encoded, bytes)
        # Must round-trip through UTF-8 without escaping non-ASCII to \uXXXX
        # (deterministic across Python versions).
        decoded = encoded.decode("utf-8")
        self.assertIn("héllo", decoded)
        self.assertIn("中文", decoded)

    def test_canonical_encoding_stable_with_nested_structures(self):
        from openssl_encrypt.modules.audit_chain import canonical_encode

        record_a = {"outer": {"z": 1, "a": 2}, "list": [{"k2": 2, "k1": 1}]}
        record_b = {"list": [{"k1": 1, "k2": 2}], "outer": {"a": 2, "z": 1}}
        self.assertEqual(canonical_encode(record_a), canonical_encode(record_b))


class TestForwardSecureKey(unittest.TestCase):
    """HKDF-SHA256 forward-secure key evolution."""

    def test_derive_initial_key_is_32_bytes(self):
        from openssl_encrypt.modules.audit_chain import derive_initial_key

        seed = b"\x01" * 32
        k0 = derive_initial_key(seed)
        self.assertIsInstance(k0, (bytes, bytearray))
        self.assertEqual(len(k0), 32)

    def test_derive_initial_key_deterministic(self):
        from openssl_encrypt.modules.audit_chain import derive_initial_key

        seed = b"\x42" * 32
        self.assertEqual(derive_initial_key(seed), derive_initial_key(seed))

    def test_derive_initial_key_different_seeds_differ(self):
        from openssl_encrypt.modules.audit_chain import derive_initial_key

        self.assertNotEqual(derive_initial_key(b"\x01" * 32), derive_initial_key(b"\x02" * 32))

    def test_evolve_key_changes_value(self):
        from openssl_encrypt.modules.audit_chain import derive_initial_key, evolve_key

        k0 = derive_initial_key(b"\x01" * 32)
        k1 = evolve_key(k0)
        self.assertEqual(len(k1), 32)
        self.assertNotEqual(bytes(k0), bytes(k1))

    def test_evolve_key_deterministic(self):
        from openssl_encrypt.modules.audit_chain import derive_initial_key, evolve_key

        k0 = derive_initial_key(b"\x01" * 32)
        self.assertEqual(evolve_key(k0), evolve_key(k0))

    def test_forward_security_old_key_cannot_recover_new(self):
        """Knowing K_n must not let you compute K_{n-1} (one-wayness via HKDF)."""
        from openssl_encrypt.modules.audit_chain import derive_initial_key, evolve_key

        k0 = derive_initial_key(b"\x01" * 32)
        k1 = evolve_key(k0)
        k2 = evolve_key(k1)
        # We can't *prove* one-wayness in a unit test, but we can pin
        # asymmetry: applying evolve to k2 should not yield k1.
        self.assertNotEqual(evolve_key(k2), k1)


class TestRecordHashAndMac(unittest.TestCase):
    """Record-level cryptographic primitives."""

    def test_compute_record_mac_format(self):
        from openssl_encrypt.modules.audit_chain import compute_record_mac

        key = b"\x00" * 32
        record = {"seq": 0, "event_type": "x", "prev_hash": "blake2b-256:0" * 1}
        mac = compute_record_mac(record, key)
        self.assertIsInstance(mac, str)
        self.assertTrue(mac.startswith("hmac-sha256:"))
        # 32-byte HMAC -> 64 hex chars
        self.assertEqual(len(mac.split(":", 1)[1]), 64)

    def test_compute_record_mac_matches_reference(self):
        """Pin against a hand-computed HMAC-SHA256 reference."""
        from openssl_encrypt.modules.audit_chain import canonical_encode, compute_record_mac

        key = b"\x11" * 32
        record = {"seq": 7, "event_type": "test"}
        expected = hmac.new(key, canonical_encode(record), hashlib.sha256).hexdigest()
        self.assertEqual(compute_record_mac(record, key), f"hmac-sha256:{expected}")

    def test_compute_record_mac_changes_when_record_changes(self):
        from openssl_encrypt.modules.audit_chain import compute_record_mac

        key = b"\x00" * 32
        a = compute_record_mac({"seq": 0, "x": 1}, key)
        b = compute_record_mac({"seq": 0, "x": 2}, key)
        self.assertNotEqual(a, b)

    def test_compute_record_mac_changes_when_key_changes(self):
        from openssl_encrypt.modules.audit_chain import compute_record_mac

        record = {"seq": 0, "x": 1}
        a = compute_record_mac(record, b"\x00" * 32)
        b = compute_record_mac(record, b"\xff" * 32)
        self.assertNotEqual(a, b)

    def test_compute_record_hash_format(self):
        from openssl_encrypt.modules.audit_chain import compute_record_hash

        record = {"seq": 0, "mac": "hmac-sha256:" + "0" * 64}
        h = compute_record_hash(record)
        self.assertTrue(h.startswith("blake2b-256:"))
        self.assertEqual(len(h.split(":", 1)[1]), 64)

    def test_compute_record_hash_includes_mac(self):
        """prev_hash must commit to the MAC, otherwise an attacker could swap MACs."""
        from openssl_encrypt.modules.audit_chain import compute_record_hash

        h_with = compute_record_hash({"seq": 0, "mac": "hmac-sha256:" + "a" * 64})
        h_without = compute_record_hash({"seq": 0, "mac": "hmac-sha256:" + "b" * 64})
        self.assertNotEqual(h_with, h_without)


class TestChainStateAppend(unittest.TestCase):
    """Behaviour of ChainState.append_record."""

    def test_initial_state_starts_at_seq_zero(self):
        from openssl_encrypt.modules.audit_chain import ChainState

        state = ChainState.initial(seed=b"\x01" * 32)
        self.assertEqual(state.current_seq, 0)
        self.assertEqual(state.last_anchor_seq, -1)

    def test_initial_state_uses_genesis_prev_hash(self):
        from openssl_encrypt.modules.audit_chain import GENESIS_PREV_HASH, ChainState

        state = ChainState.initial(seed=b"\x01" * 32)
        self.assertEqual(state.last_record_hash, GENESIS_PREV_HASH)

    def test_genesis_prev_hash_pinned_constant(self):
        """Pin the genesis hash against the spec constant (catches accidental rebrand)."""
        from openssl_encrypt.modules.audit_chain import GENESIS_PREV_HASH

        expected = hashlib.blake2b(b"ssle-audit-genesis-v1", digest_size=32).hexdigest()
        self.assertEqual(GENESIS_PREV_HASH, f"blake2b-256:{expected}")

    def test_first_appended_record_has_seq_zero_and_genesis_link(self):
        from openssl_encrypt.modules.audit_chain import GENESIS_PREV_HASH, ChainState

        state = ChainState.initial(seed=b"\x01" * 32)
        record = state.append_record({"event_type": "boot", "severity": "info"})
        self.assertEqual(record["seq"], 0)
        self.assertEqual(record["prev_hash"], GENESIS_PREV_HASH)
        self.assertIn("mac", record)
        self.assertTrue(record["mac"].startswith("hmac-sha256:"))

    def test_append_increments_seq_and_advances_state(self):
        from openssl_encrypt.modules.audit_chain import ChainState

        state = ChainState.initial(seed=b"\x01" * 32)
        r0 = state.append_record({"event_type": "a"})
        r1 = state.append_record({"event_type": "b"})
        r2 = state.append_record({"event_type": "c"})
        self.assertEqual([r0["seq"], r1["seq"], r2["seq"]], [0, 1, 2])
        self.assertEqual(state.current_seq, 3)

    def test_prev_hash_links_to_prior_record(self):
        from openssl_encrypt.modules.audit_chain import ChainState, compute_record_hash

        state = ChainState.initial(seed=b"\x01" * 32)
        r0 = state.append_record({"event_type": "a"})
        r1 = state.append_record({"event_type": "b"})
        self.assertEqual(r1["prev_hash"], compute_record_hash(r0))

    def test_append_evolves_key_so_stale_key_cannot_forge_next_record(self):
        """After appending record n, state must hold K_{n+1}, not K_n."""
        from openssl_encrypt.modules.audit_chain import (
            ChainState,
            compute_record_mac,
            derive_initial_key,
        )

        seed = b"\x01" * 32
        k0 = derive_initial_key(seed)
        state = ChainState.initial(seed=seed)
        r0 = state.append_record({"event_type": "a"})

        # The MAC on r0 must verify under K_0 (not under the post-append key).
        rebuilt = {k: v for k, v in r0.items() if k != "mac"}
        self.assertEqual(compute_record_mac(rebuilt, k0), r0["mac"])

        # State must no longer hold K_0.
        self.assertNotEqual(bytes(state.current_key), bytes(k0))

    def test_appended_record_mac_verifies_under_seq_indexed_key(self):
        """Verifier reproduces K_seq from seed; record n MAC must verify under K_n."""
        from openssl_encrypt.modules.audit_chain import (
            ChainState,
            compute_record_mac,
            derive_initial_key,
            evolve_key,
        )

        seed = b"\x01" * 32
        state = ChainState.initial(seed=seed)
        records = [state.append_record({"event_type": f"e{i}"}) for i in range(5)]

        key = derive_initial_key(seed)
        for rec in records:
            rebuilt = {k: v for k, v in rec.items() if k != "mac"}
            self.assertEqual(compute_record_mac(rebuilt, key), rec["mac"])
            key = evolve_key(key)

    def test_append_does_not_mutate_caller_payload(self):
        from openssl_encrypt.modules.audit_chain import ChainState

        state = ChainState.initial(seed=b"\x01" * 32)
        payload = {"event_type": "a", "severity": "info"}
        original = dict(payload)
        state.append_record(payload)
        self.assertEqual(payload, original)


class TestChainStatePersistence(unittest.TestCase):
    """Atomic state-file IO."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_round_trip_serialization(self):
        from openssl_encrypt.modules.audit_chain import ChainState

        state = ChainState.initial(seed=b"\x01" * 32)
        state.append_record({"event_type": "a"})
        state.append_record({"event_type": "b"})

        path = self.dir / "audit-state.json"
        state.save_atomic(path)

        loaded = ChainState.load(path)
        self.assertEqual(loaded.current_seq, state.current_seq)
        self.assertEqual(loaded.last_record_hash, state.last_record_hash)
        self.assertEqual(bytes(loaded.current_key), bytes(state.current_key))
        self.assertEqual(loaded.last_anchor_seq, state.last_anchor_seq)

    def test_state_file_has_owner_only_permissions(self):
        from openssl_encrypt.modules.audit_chain import ChainState

        state = ChainState.initial(seed=b"\x01" * 32)
        path = self.dir / "audit-state.json"
        state.save_atomic(path)

        mode = path.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600, f"expected 0600, got {oct(mode)}")

    def test_save_atomic_replaces_existing_file_atomically(self):
        """A second save must not leave a partial file behind."""
        from openssl_encrypt.modules.audit_chain import ChainState

        state = ChainState.initial(seed=b"\x01" * 32)
        path = self.dir / "audit-state.json"
        state.save_atomic(path)

        state.append_record({"event_type": "a"})
        state.save_atomic(path)

        # No leftover tempfiles from the atomic-replace dance.
        leftovers = [p for p in self.dir.iterdir() if p.name != "audit-state.json"]
        self.assertEqual(leftovers, [], f"unexpected leftovers: {leftovers}")

        loaded = ChainState.load(path)
        self.assertEqual(loaded.current_seq, 1)

    def test_save_atomic_writes_valid_json(self):
        from openssl_encrypt.modules.audit_chain import ChainState

        state = ChainState.initial(seed=b"\x01" * 32)
        path = self.dir / "audit-state.json"
        state.save_atomic(path)

        with open(path, "rb") as f:
            data = json.loads(f.read())
        self.assertIn("version", data)
        self.assertIn("current_seq", data)
        self.assertIn("last_record_hash", data)
        # Key must be present but encoded (not raw bytes in JSON).
        self.assertIsInstance(data["current_key_b64"], str)

    def test_load_missing_file_raises(self):
        from openssl_encrypt.modules.audit_chain import ChainState

        with self.assertRaises(FileNotFoundError):
            ChainState.load(self.dir / "does-not-exist.json")


if __name__ == "__main__":
    unittest.main()
