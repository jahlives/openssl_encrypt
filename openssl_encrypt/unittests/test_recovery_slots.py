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

from openssl_encrypt.modules.crypt_errors import AuthenticationError, DecryptionError
from openssl_encrypt.modules.recovery_slots import (
    SLOT_TYPES,
    build_recovery_code_slot,
    canonical_slots,
    compute_slot_set_mac,
    generate_recovery_code,
    normalize_recovery_code,
    unlock_recovery_code_slot,
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


class TestRecoveryCode(unittest.TestCase):
    def test_generate_returns_str(self):
        self.assertIsInstance(generate_recovery_code(), str)

    def test_generated_codes_are_unique(self):
        self.assertNotEqual(generate_recovery_code(), generate_recovery_code())

    def test_normalize_is_tolerant_of_spacing_and_case(self):
        code = generate_recovery_code()
        noisy = "  " + code.lower().replace("-", " ") + "  "
        self.assertEqual(normalize_recovery_code(code), normalize_recovery_code(noisy))

    def test_normalize_yields_high_entropy(self):
        # >= 256 bits of decoded key material
        self.assertGreaterEqual(len(normalize_recovery_code(generate_recovery_code())), 32)


class TestRecoveryCodeSlot(unittest.TestCase):
    def setUp(self):
        self.dek = secrets.token_bytes(32)
        self.code = generate_recovery_code()
        self.slot = build_recovery_code_slot(self.dek, self.code, slot_id="r1")

    def test_slot_shape(self):
        self.assertEqual(self.slot["type"], "recovery_code")
        self.assertEqual(self.slot["id"], "r1")
        self.assertIn("wrap", self.slot)
        self.assertIn("salt", self.slot["params"])
        # wrap blob is the 60-byte AES-GCM envelope wrap, base64-encoded
        self.assertEqual(len(base64.b64decode(self.slot["wrap"])), 60)

    def test_wrap_is_not_plaintext_dek(self):
        self.assertNotIn(self.dek, base64.b64decode(self.slot["wrap"]))

    def test_unlock_recovers_dek(self):
        recovered = unlock_recovery_code_slot(self.slot, self.code)
        self.assertEqual(bytes(recovered), self.dek)

    def test_unlock_tolerates_formatting(self):
        recovered = unlock_recovery_code_slot(self.slot, "  " + self.code.lower() + " ")
        self.assertEqual(bytes(recovered), self.dek)

    def test_wrong_code_fails_closed(self):
        with self.assertRaises((AuthenticationError, DecryptionError)):
            unlock_recovery_code_slot(self.slot, generate_recovery_code())

    def test_each_slot_uses_fresh_salt(self):
        other = build_recovery_code_slot(self.dek, self.code, slot_id="r2")
        self.assertNotEqual(self.slot["params"]["salt"], other["params"]["salt"])
        self.assertNotEqual(self.slot["wrap"], other["wrap"])


if __name__ == "__main__":
    unittest.main()
