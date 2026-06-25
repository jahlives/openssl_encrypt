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
from unittest import mock

from openssl_encrypt.modules.crypt_errors import AuthenticationError, DecryptionError
from openssl_encrypt.modules.recovery_slots import (
    SLOT_TYPES,
    build_passphrase_slot,
    build_pqc_slot,
    build_recovery_code_slot,
    build_recovery_slots,
    canonical_slots,
    compute_slot_set_mac,
    generate_recovery_code,
    normalize_recovery_code,
    unlock_passphrase_slot,
    unlock_pqc_slot,
    unlock_recovery_code_slot,
    verify_slot_set_mac,
)

try:
    from openssl_encrypt.modules.identity import Identity
    from openssl_encrypt.modules.pqc_signing import LIBOQS_AVAILABLE
except Exception:  # pragma: no cover
    LIBOQS_AVAILABLE = False


def _priv_bytes(identity):
    with identity.encryption_private_key as pk:
        return pk.get_bytes()


def _slot(index: int, slot_type: str = "recovery_code") -> dict:
    """Build a representative recovery-slot dict in stored (metadata) shape."""
    return {
        "id": f"slot-{index}",
        "type": slot_type,
        "wrap": base64.b64encode(secrets.token_bytes(60)).decode("ascii"),
        "params": {
            "salt": base64.b64encode(secrets.token_bytes(16)).decode("ascii"),
            "kdf": "argon2id",
        },
    }


class TestSlotTypes(unittest.TestCase):
    def test_known_slot_types(self):
        self.assertEqual(SLOT_TYPES, {"recovery_code", "passphrase", "pqc"})


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
        self.slots = [_slot(1, "recovery_code"), _slot(2, "passphrase")]

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
        self.assertFalse(verify_slot_set_mac(secrets.token_bytes(32), self.slots, self.mac))

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


class TestPqcSlot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.recovery_id = Identity.generate("RecoveryEscrow", None, "escrow-pass")
        cls.other_id = Identity.generate("Other", None, "other-pass")

    def setUp(self):
        self.dek = secrets.token_bytes(32)
        self.slot = build_pqc_slot(
            self.dek,
            self.recovery_id.encryption_public_key,
            self.recovery_id.encryption_algorithm,
            slot_id="p1",
            key_id=self.recovery_id.fingerprint,
        )

    def test_slot_shape(self):
        self.assertEqual(self.slot["type"], "pqc")
        self.assertEqual(len(base64.b64decode(self.slot["wrap"])), 60)
        self.assertIn("salt", self.slot["params"])
        self.assertEqual(
            self.slot["params"]["kem_algorithm"], self.recovery_id.encryption_algorithm
        )
        self.assertIn("encapsulated_key", self.slot["params"])
        self.assertEqual(self.slot["params"]["key_id"], self.recovery_id.fingerprint)

    def test_unlock_with_private_key_recovers_dek(self):
        recovered = unlock_pqc_slot(self.slot, _priv_bytes(self.recovery_id))
        self.assertEqual(bytes(recovered), self.dek)

    def test_wrong_identity_fails_closed(self):
        from openssl_encrypt.modules.crypt_errors import DecryptionError

        with self.assertRaises((AuthenticationError, DecryptionError, Exception)):
            unlock_pqc_slot(self.slot, _priv_bytes(self.other_id))


class TestPassphraseSlot(unittest.TestCase):
    # small Argon2 params keep the test fast
    PARAMS = {"time_cost": 1, "memory_cost": 8192, "parallelism": 1}

    def setUp(self):
        self.dek = secrets.token_bytes(32)
        self.passphrase = b"a memorable backup passphrase"
        self.slot = build_passphrase_slot(self.dek, self.passphrase, slot_id="pw1", **self.PARAMS)

    def test_slot_shape(self):
        self.assertEqual(self.slot["type"], "passphrase")
        self.assertEqual(len(base64.b64decode(self.slot["wrap"])), 60)
        self.assertIn("salt", self.slot["params"])
        self.assertEqual(self.slot["params"]["argon2"]["time_cost"], 1)

    def test_unlock_recovers_dek(self):
        self.assertEqual(bytes(unlock_passphrase_slot(self.slot, self.passphrase)), self.dek)

    def test_unlock_accepts_str(self):
        self.assertEqual(
            bytes(unlock_passphrase_slot(self.slot, "a memorable backup passphrase")),
            self.dek,
        )

    def test_wrong_passphrase_fails_closed(self):
        from openssl_encrypt.modules.crypt_errors import DecryptionError

        with self.assertRaises((AuthenticationError, DecryptionError)):
            unlock_passphrase_slot(self.slot, b"wrong passphrase")

    def test_fresh_salt_per_slot(self):
        other = build_passphrase_slot(self.dek, self.passphrase, slot_id="pw2", **self.PARAMS)
        self.assertNotEqual(self.slot["params"]["salt"], other["params"]["salt"])


class TestBuildRecoverySlots(unittest.TestCase):
    def setUp(self):
        self.dek = secrets.token_bytes(32)

    def test_builds_recovery_code_slots_with_unique_ids(self):
        creds = [
            {"type": "recovery_code", "code": generate_recovery_code()},
            {"type": "recovery_code", "code": generate_recovery_code()},
        ]
        slots = build_recovery_slots(self.dek, creds)
        self.assertEqual(len(slots), 2)
        self.assertEqual(len({s["id"] for s in slots}), 2)
        for s in slots:
            self.assertEqual(s["type"], "recovery_code")

    def test_built_slots_unlock_to_same_dek(self):
        code = generate_recovery_code()
        slots = build_recovery_slots(self.dek, [{"type": "recovery_code", "code": code}])
        self.assertEqual(bytes(unlock_recovery_code_slot(slots[0], code)), self.dek)

    def test_empty_credentials_returns_empty_list(self):
        self.assertEqual(build_recovery_slots(self.dek, []), [])

    def test_unsupported_type_rejected(self):
        from openssl_encrypt.modules.crypt_errors import ValidationError

        with self.assertRaises(ValidationError):
            build_recovery_slots(self.dek, [{"type": "no_such_type"}])


class TestKeyHygiene(unittest.TestCase):
    """Per-slot KEKs must be zeroized as soon as the wrap/unwrap completes."""

    def _assert_kek_zeroized(self, build_call):
        import openssl_encrypt.modules.envelope as env

        captured = {}
        real = env.wrap_dek

        def spy(dek, kek):
            captured["kek"] = kek  # the bytearray the build site will zeroize
            return real(dek, kek)

        with mock.patch.object(env, "wrap_dek", spy):
            build_call()
        self.assertIn("kek", captured)
        self.assertEqual(len(captured["kek"]), 32)
        self.assertTrue(all(b == 0 for b in captured["kek"]), "KEK was not zeroized after wrap")

    def test_recovery_code_kek_zeroized(self):
        dek = secrets.token_bytes(32)
        self._assert_kek_zeroized(
            lambda: build_recovery_code_slot(dek, generate_recovery_code(), "r1")
        )

    def test_passphrase_kek_zeroized(self):
        dek = secrets.token_bytes(32)
        self._assert_kek_zeroized(
            lambda: build_passphrase_slot(
                dek, b"pw", "pw1", time_cost=1, memory_cost=8192, parallelism=1
            )
        )


if __name__ == "__main__":
    unittest.main()
