#!/usr/bin/env python3
"""Pre-authentication resource-exhaustion cluster (gitlab#233, scan F9/F16/F28/F29).

A crafted file must not be able to drive unbounded KDF cost past the memory
ceiling (gitlab#128) before authentication:

- F9  (CWE-1284): Balloon `parallel_cost` is bounded in balloon_m, and the
  estimator models parallelism so the ceiling sees it.
- F28 (CWE-770): the executor honors a `kdf_config` shadowed inside
  `derivation_config.hash_config` (it copies those keys into the flat dict and
  generate_key_independent_xor reads hash_config["derivation_config"]["kdf_config"]);
  the estimator now folds that shadowed config in.
- F29 (CWE-770): for legacy v1-v3 the executor honors hash_config's argon2/
  scrypt/balloon nested dicts; the estimator now models them instead of {}.
- F16 (CWE-405): the per-slot Argon2 memory cap is lowered and the decryption
  recovery path caps the slot count before running any KDF.
"""

import unittest

from openssl_encrypt.modules import decryption_estimator as de
from openssl_encrypt.modules.balloon import _MAX_PARALLEL_COST, balloon_m
from openssl_encrypt.modules.benchmark_constants import HARD_MEMORY_CEILING_KB
from openssl_encrypt.modules.crypt_errors import ValidationError

_ARGON2_1TIB_KIB = 1024 * 1024 * 1024  # 1 TiB in KiB


class TestBalloonParallelCostBounded(unittest.TestCase):
    def test_absurd_parallel_cost_is_refused(self):
        with self.assertRaises(ValueError):
            balloon_m("pw", "salt", space_cost=16, time_cost=1, parallel_cost=10**8)

    def test_at_cap_is_allowed_boundary_not_crossed(self):
        # One past the cap is refused; the cap itself is a valid (if large) value.
        with self.assertRaises(ValueError):
            balloon_m("pw", "salt", space_cost=4, time_cost=1, parallel_cost=_MAX_PARALLEL_COST + 1)

    def test_estimator_models_parallelism(self):
        low = de.estimate_balloon({"enabled": True, "space_cost": 4096, "parallelism": 1})
        high = de.estimate_balloon({"enabled": True, "space_cost": 4096, "parallelism": 64})
        self.assertGreater(high[1], low[1] * 30, "memory estimate must scale with parallelism")

    def test_crafted_balloon_parallelism_over_ceiling(self):
        # A modest space_cost with an enormous parallelism must trip the ceiling.
        est = de.estimate_decryption_cost(
            {
                "format_version": 14,
                "derivation_config": {
                    "hash_config": {},
                    "kdf_config": {
                        "balloon": {
                            "enabled": True,
                            "space_cost": 65536,
                            "time_cost": 1,
                            "rounds": 1,
                            "parallelism": 10**6,
                        }
                    },
                },
            }
        )
        self.assertGreater(est.peak_memory_kb, HARD_MEMORY_CEILING_KB)
        with self.assertRaises(ValidationError):
            de.enforce_memory_ceiling(est.peak_memory_kb, interactive=False)


class TestShadowedKdfConfigModelled(unittest.TestCase):
    """F28: a kdf_config nested inside derivation_config.hash_config is what the
    executor actually runs; the estimator must not miss it."""

    def test_shadowed_argon2_1tib_over_ceiling(self):
        est = de.estimate_decryption_cost(
            {
                "format_version": 14,
                "derivation_config": {
                    # benign outer kdf_config; the real cost hides in hash_config
                    "kdf_config": {},
                    "hash_config": {
                        "sha256": {"rounds": 1},
                        "derivation_config": {
                            "kdf_config": {
                                "argon2": {
                                    "enabled": True,
                                    "memory_cost": _ARGON2_1TIB_KIB,
                                    "time_cost": 3,
                                    "rounds": 1,
                                }
                            }
                        },
                    },
                },
            }
        )
        self.assertGreater(est.peak_memory_kb, HARD_MEMORY_CEILING_KB)
        with self.assertRaises(ValidationError):
            de.enforce_memory_ceiling(est.peak_memory_kb, interactive=False)


class TestLegacyKdfModelled(unittest.TestCase):
    """F29: v1-v3 executor honors hash_config's nested KDF dicts; estimate them."""

    def test_v3_argon2_128gib_over_ceiling(self):
        est = de.estimate_decryption_cost(
            {
                "format_version": 3,
                "hash_config": {
                    "sha256": 1,
                    "argon2": {
                        "enabled": True,
                        "memory_cost": 128 * 1024 * 1024,  # 128 GiB in KiB
                        "time_cost": 3,
                        "rounds": 1,
                    },
                },
            }
        )
        self.assertGreater(est.peak_memory_kb, HARD_MEMORY_CEILING_KB)
        with self.assertRaises(ValidationError):
            de.enforce_memory_ceiling(est.peak_memory_kb, interactive=False)

    def test_v3_without_kdf_stays_small(self):
        # A legitimate v3 file with only hash rounds must not be over-estimated.
        est = de.estimate_decryption_cost(
            {"format_version": 3, "hash_config": {"sha256": 10000}, "pbkdf2_iterations": 100000}
        )
        self.assertLess(est.peak_memory_kb, HARD_MEMORY_CEILING_KB)


class TestRecoverySlotBounds(unittest.TestCase):
    """F16: the recovery paths cap the number of slots processed before any KDF
    runs, on BOTH the decrypt path and the add/remove-slot path."""

    def test_max_dek_slots_is_small(self):
        from openssl_encrypt.modules import recovery_slots as rs

        self.assertTrue(hasattr(rs, "MAX_DEK_SLOTS"))
        self.assertLessEqual(rs.MAX_DEK_SLOTS, 64)

    def test_recover_envelope_dek_caps_slot_count_before_kdf(self):
        # A crafted envelope with more than MAX_DEK_SLOTS passphrase slots must be
        # refused cheaply, before any Argon2id unlock runs (gitlab#233 review
        # NEW-2). If the cap did not fire, unlock would run on a bogus slot and
        # raise a different error; assert the specific count-refusal message.
        from openssl_encrypt.modules import recovery_slots as rs
        from openssl_encrypt.modules.crypt_core import _recover_envelope_dek

        n = rs.MAX_DEK_SLOTS + 1
        meta = {
            "encryption": {
                "wrapped_dek": "AAAA",
                "dek_slots": [{"type": "passphrase"} for _ in range(n)],
            }
        }
        with self.assertRaises(ValidationError) as ctx:
            _recover_envelope_dek(meta, recovery_passphrase=b"x")
        self.assertIn("exceeds the maximum", str(ctx.exception))

    def test_within_cap_is_not_refused_by_the_count_guard(self):
        # A slot count at the cap gets past the count guard (and then fails to
        # match/authenticate, a different error) -- the guard itself must not fire.
        from openssl_encrypt.modules import recovery_slots as rs
        from openssl_encrypt.modules.crypt_core import _recover_envelope_dek

        meta = {
            "encryption": {
                "wrapped_dek": "AAAA",
                "dek_slots": [{"type": "recovery_code"} for _ in range(rs.MAX_DEK_SLOTS)],
            }
        }
        with self.assertRaises(Exception) as ctx:
            _recover_envelope_dek(meta, recovery_code="nope")
        self.assertNotIn("exceeds the maximum", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
