"""Regression tests for recovery-slot Argon2 parameter bounds (#73 / IO-3).

A passphrase recovery slot stores its Argon2 time/memory/parallelism cost
parameters in the (untrusted) file, and unlock_passphrase_slot consumes them
BEFORE the slot-set MAC can be verified (the MAC key is derived from the DEK,
which requires this very KDF -- so MAC-first is impossible). A tampered slot
could set memory_cost to gigabytes and OOM/crash the host. The fix clamps the
parameters to a sane range before invoking Argon2.
"""

import unittest
from unittest import mock

from openssl_encrypt.modules.crypt_errors import ValidationError
from openssl_encrypt.modules.recovery_slots import (
    _validate_argon2_params,
    build_passphrase_slot,
    unlock_passphrase_slot,
)


class TestRecoverySlotArgon2Bounds(unittest.TestCase):
    def test_validator_rejects_excessive_and_bad_params(self):
        with self.assertRaises(ValidationError):
            _validate_argon2_params(3, 3_000_000_000, 4)  # ~3 TiB memory
        with self.assertRaises(ValidationError):
            _validate_argon2_params(10_000, 65536, 4)  # absurd time_cost
        with self.assertRaises(ValidationError):
            _validate_argon2_params(3, 65536, 9999)  # absurd parallelism
        with self.assertRaises(ValidationError):
            _validate_argon2_params(3, "65536", 4)  # non-int
        # Legitimate defaults must pass.
        _validate_argon2_params(3, 65536, 4)

    def test_tampered_huge_memory_cost_is_rejected_before_argon2(self):
        slot = build_passphrase_slot(bytes(32), b"recovery-pass", "slot1")
        slot["params"]["argon2"]["memory_cost"] = 3_000_000_000  # ~3 TiB in KiB

        import argon2

        # Guard: if the huge param ever reaches Argon2 (i.e. the bound is absent),
        # do NOT actually allocate -- simulate the OOM the attacker intended so the
        # test fails safely rather than crashing the runner.
        with mock.patch.object(
            argon2.low_level, "hash_secret_raw", side_effect=MemoryError("would allocate ~3 TiB")
        ):
            with self.assertRaises(ValidationError):
                unlock_passphrase_slot(slot, b"recovery-pass")

    def test_legitimate_slot_still_round_trips(self):
        dek = bytes(range(32))
        slot = build_passphrase_slot(dek, b"recovery-pass", "slot1")
        recovered = unlock_passphrase_slot(slot, b"recovery-pass")
        self.assertEqual(bytes(recovered), dek)


if __name__ == "__main__":
    unittest.main()
