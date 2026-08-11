#!/usr/bin/env python3
"""Decrypt must refuse a crafted KDF whose estimated TIME exceeds a hard ceiling,
not only its memory (scan finding F30, gitlab#247, CWE-400).

enforce_memory_ceiling gated peak_memory_kb only; a crafted file with a huge
iteration count and tiny memory (e.g. argon2 time_cost=2**31, memory_cost=8, or
sha256 rounds=2**31) slipped under the 8 GiB memory ceiling but pinned a CPU core
before the password was checked. A hard time ceiling, enforced independently of
the --quiet/--no-estimate display flags and overridable like the memory ceiling,
closes it.
"""

import unittest

from openssl_encrypt.modules.crypt_errors import ValidationError
from openssl_encrypt.modules.decryption_estimator import (
    enforce_time_ceiling,
    estimate_decryption_cost,
)

try:
    from openssl_encrypt.modules.benchmark_constants import HARD_TIME_CEILING_SECONDS
except ImportError:  # pragma: no cover
    HARD_TIME_CEILING_SECONDS = None


@unittest.skipIf(HARD_TIME_CEILING_SECONDS is None, "time ceiling constant missing")
class TestKdfTimeCeiling(unittest.TestCase):
    def test_under_ceiling_passes(self):
        # A tiny cost must not be refused.
        enforce_time_ceiling(0.5, allow_high_kdf_cost=False, interactive=False)

    def test_over_ceiling_refused_noninteractive(self):
        with self.assertRaises(ValidationError):
            enforce_time_ceiling(
                HARD_TIME_CEILING_SECONDS + 1, allow_high_kdf_cost=False, interactive=False
            )

    def test_override_bypasses(self):
        # --allow-high-kdf-cost proceeds regardless (explicit user choice).
        enforce_time_ceiling(1e18, allow_high_kdf_cost=True, interactive=False)

    def test_infinite_estimate_refused(self):
        # Fail-closed marker (mirrors the memory path's float('inf')).
        with self.assertRaises(ValidationError):
            enforce_time_ceiling(float("inf"), allow_high_kdf_cost=False, interactive=False)

    def test_ceiling_is_well_above_heaviest_preset(self):
        # The heaviest shipped preset (paranoid) estimates to a few seconds; the
        # ceiling must sit far above it so no legitimate file is refused.
        self.assertGreaterEqual(HARD_TIME_CEILING_SECONDS, 60)

    def test_crafted_argon2_rounds_estimate_exceeds_ceiling(self):
        # The concrete F30 attack: huge argon2 iteration count, tiny memory.
        meta = {
            "format_version": 14,
            "derivation_config": {
                "hash_config": {},
                "kdf_config": {
                    "argon2": {
                        "enabled": True,
                        "time_cost": 2**31,
                        "memory_cost": 8,
                        "parallelism": 1,
                        "rounds": 2**31,
                    }
                },
            },
        }
        est = estimate_decryption_cost(meta)
        self.assertGreater(est.total_time_seconds, HARD_TIME_CEILING_SECONDS)
        with self.assertRaises(ValidationError):
            enforce_time_ceiling(
                est.total_time_seconds, allow_high_kdf_cost=False, interactive=False
            )

    def test_argon2_memory_cost_scales_time_estimate(self):
        # F30 review: a large memory_cost (under the 8 GiB memory ceiling) with a
        # modest round count must NOT slip under the time ceiling. The estimator
        # was memory-blind, so this estimated ~106s (passing) while really running
        # for ~1.9h. Time must now scale linearly with memory_cost.
        meta = {
            "format_version": 14,
            "derivation_config": {
                "hash_config": {},
                "kdf_config": {
                    "argon2": {
                        "enabled": True,
                        "time_cost": 3,
                        "memory_cost": 4 * 1024 * 1024,  # 4 GiB (< 8 GiB ceiling)
                        "parallelism": 1,
                        "rounds": 3000,
                    }
                },
            },
        }
        est = estimate_decryption_cost(meta)
        self.assertGreater(est.total_time_seconds, HARD_TIME_CEILING_SECONDS)
        with self.assertRaises(ValidationError):
            enforce_time_ceiling(
                est.total_time_seconds, allow_high_kdf_cost=False, interactive=False
            )

    def test_argon2_reference_memory_estimate_unchanged(self):
        # At the benchmark reference memory (64 MiB), a normal round count must
        # still estimate well under the ceiling (no false refusal).
        meta = {
            "format_version": 14,
            "derivation_config": {
                "hash_config": {},
                "kdf_config": {
                    "argon2": {
                        "enabled": True,
                        "time_cost": 3,
                        "memory_cost": 65536,  # 64 MiB reference
                        "parallelism": 4,
                        "rounds": 10,
                    }
                },
            },
        }
        est = estimate_decryption_cost(meta)
        self.assertLess(est.total_time_seconds, HARD_TIME_CEILING_SECONDS)

    def test_scrypt_r_p_scale_time_estimate(self):
        # F30 review: scrypt work is N*r*p, but the estimate was blind to r/p.
        # n=16384, r=256, p=16 sits at the 8 GiB memory ceiling yet does ~512x
        # the reference work; it must be refused, not estimated at seconds.
        meta = {
            "format_version": 14,
            "derivation_config": {
                "hash_config": {},
                "kdf_config": {
                    "scrypt": {
                        "enabled": True,
                        "n": 16384,
                        "r": 256,
                        "p": 16,
                        "rounds": 100,
                    }
                },
            },
        }
        est = estimate_decryption_cost(meta)
        self.assertGreater(est.total_time_seconds, HARD_TIME_CEILING_SECONDS)
        with self.assertRaises(ValidationError):
            enforce_time_ceiling(
                est.total_time_seconds, allow_high_kdf_cost=False, interactive=False
            )

    def test_scrypt_reference_params_estimate_unchanged(self):
        # At the benchmark reference (n=16384, r=8, p=1), a normal round count
        # must still estimate well under the ceiling (no false refusal).
        meta = {
            "format_version": 14,
            "derivation_config": {
                "hash_config": {},
                "kdf_config": {
                    "scrypt": {"enabled": True, "n": 16384, "r": 8, "p": 1, "rounds": 10}
                },
            },
        }
        est = estimate_decryption_cost(meta)
        self.assertLess(est.total_time_seconds, HARD_TIME_CEILING_SECONDS)

    def test_crafted_hash_rounds_estimate_exceeds_ceiling(self):
        meta = {
            "format_version": 14,
            "derivation_config": {
                "hash_config": {"sha256": {"rounds": 2**31}},
                "kdf_config": {},
            },
        }
        est = estimate_decryption_cost(meta)
        self.assertGreater(est.total_time_seconds, HARD_TIME_CEILING_SECONDS)


if __name__ == "__main__":
    unittest.main()
