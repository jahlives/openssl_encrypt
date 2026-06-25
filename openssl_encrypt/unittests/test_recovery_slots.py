#!/usr/bin/env python3
"""
Unit tests for the recovery-slot set authentication primitive
(openssl_encrypt.modules.recovery_slots).

Phase 1 scope: the pure, DEK-keyed MAC over the recovery-slot SET that lets a
decryptor detect stripping, injection, or modification of recovery slots once
the DEK has been recovered. No file-format / crypt_core integration here.

The MAC is deliberately keyed by the DEK (not the bulk AAD) so that legitimate
post-hoc slot changes (which require the DEK) can re-authenticate the set while
an attacker without the DEK cannot forge it.
"""

import base64
import secrets
import unittest

from openssl_encrypt.modules.recovery_slots import (
    SLOT_TYPES,
    canonical_slots,
    compute_slot_set_mac,
    verify_slot_set_mac,
)


def _slot(index: int, slot_type: str = "recovery_code") -> dict:
    """Build a representative recovery-slot dict in stored (metadata) shape."""
    return {
        "id": f"slot-{index}",
        "type": slot_type,
        "wrap": base64.b64encode(secrets.token_bytes(60)).decode("ascii"),
        "params": {"salt": base64.b64encode(secrets.token_bytes(16)).decode("ascii"),
                   "kdf": "argon2id"},
    }


class TestSlotTypes(unittest.TestCase):
    def test_known_slot_types(self):
        self.assertEqual(
            SLOT_TYPES, {"recovery_code", "passphrase", "shamir", "pqc"}
        )


class TestCanonicalSlots(unittest.TestCase):
    def test_deterministic_regardless_of_key_order(self):
        s = _slot(1)
        reordered = {
            "params": s["params"],
            "wrap": s["wrap"],
            "type": s["type"],
            "id": s["id"],
        }
        self.assertEqual(canonical_slots([s]), canonical_slots([reordered]))

    def test_returns_bytes(self):
        self.assertIsInstance(canonical_slots([_slot(1)]), bytes)

    def test_empty_list_is_stable(self):
        self.assertEqual(canonical_slots([]), canonical_slots([]))

    def test_order_of_slots_is_significant(self):
        a, b = _slot(1), _slot(2)
        self.assertNotEqual(canonical_slots([a, b]), canonical_slots([b, a]))


class TestSlotSetMac(unittest.TestCase):
    def setUp(self):
        self.dek = secrets.token_bytes(32)
        self.slots = [_slot(1, "recovery_code"), _slot(2, "shamir")]

    def test_mac_is_32_bytes(self):
        mac = compute_slot_set_mac(self.dek, self.slots)
        self.assertIsInstance(mac, (bytes, bytearray))
        self.assertEqual(len(mac), 32)

    def test_mac_deterministic(self):
        self.assertEqual(
            compute_slot_set_mac(self.dek, self.slots),
            compute_slot_set_mac(self.dek, self.slots),
        )

    def test_mac_changes_with_dek(self):
        other = secrets.token_bytes(32)
        self.assertNotEqual(
            compute_slot_set_mac(self.dek, self.slots),
            compute_slot_set_mac(other, self.slots),
        )

    def test_mac_changes_on_add(self):
        more = self.slots + [_slot(3, "pqc")]
        self.assertNotEqual(
            compute_slot_set_mac(self.dek, self.slots),
            compute_slot_set_mac(self.dek, more),
        )

    def test_mac_changes_on_remove(self):
        fewer = self.slots[:1]
        self.assertNotEqual(
            compute_slot_set_mac(self.dek, self.slots),
            compute_slot_set_mac(self.dek, fewer),
        )

    def test_mac_changes_on_modify(self):
        tampered = [dict(self.slots[0]), dict(self.slots[1])]
        tampered[0]["wrap"] = base64.b64encode(secrets.token_bytes(60)).decode("ascii")
        self.assertNotEqual(
            compute_slot_set_mac(self.dek, self.slots),
            compute_slot_set_mac(self.dek, tampered),
        )


class TestVerifySlotSetMac(unittest.TestCase):
    def setUp(self):
        self.dek = secrets.token_bytes(32)
        self.slots = [_slot(1), _slot(2), _slot(3, "passphrase")]
        self.mac = compute_slot_set_mac(self.dek, self.slots)

    def test_accepts_valid(self):
        self.assertTrue(verify_slot_set_mac(self.dek, self.slots, self.mac))

    def test_rejects_wrong_dek(self):
        self.assertFalse(
            verify_slot_set_mac(secrets.token_bytes(32), self.slots, self.mac)
        )

    def test_rejects_stripped_slot(self):
        self.assertFalse(verify_slot_set_mac(self.dek, self.slots[:-1], self.mac))

    def test_rejects_injected_slot(self):
        injected = self.slots + [_slot(99, "pqc")]
        self.assertFalse(verify_slot_set_mac(self.dek, injected, self.mac))

    def test_rejects_modified_slot(self):
        tampered = [dict(s) for s in self.slots]
        tampered[1]["params"] = {"salt": "evil", "kdf": "argon2id"}
        self.assertFalse(verify_slot_set_mac(self.dek, tampered, self.mac))

    def test_rejects_truncated_mac(self):
        self.assertFalse(verify_slot_set_mac(self.dek, self.slots, self.mac[:-1]))

    def test_rejects_empty_mac(self):
        self.assertFalse(verify_slot_set_mac(self.dek, self.slots, b""))


if __name__ == "__main__":
    unittest.main()
