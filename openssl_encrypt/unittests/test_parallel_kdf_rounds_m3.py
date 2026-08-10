"""Regression test for follow-up finding M3 [KDF-1].

The sequential Independent-XOR Argon2 path (`compute_kdf_independent`) iterates
`rounds` times with salt-chaining (`round_salt = result[:32]`). The parallel
worker (`_kdf_worker`) ran Argon2 exactly once and ignored `rounds` entirely.
Since `--parallel-kdf` is a runtime flag not persisted in metadata, this meant
encrypting with parallel + Argon2 rounds>1 and decrypting without it (or vice
versa) derived a different key -> permanent silent failure to decrypt, and the
parallel path did strictly less KDF work than the recorded config.

The duplicated `_kdf_worker` was retired in gitlab#224 — the parallel entry
point now routes every format through `compute_kdf_independent` itself, so the
divergence class cannot recur by construction. This test keeps the M3
invariant pinned at the component level: `rounds` genuinely changes the
Argon2 output (salt-chaining is applied), and the full-path equivalence for
rounds>1 is pinned end-to-end in test_parallel_kdf_legacy_route_224.py.
"""

import unittest

from openssl_encrypt.modules.crypt_core import compute_kdf_independent

# Fast, deterministic Argon2 params (rounds > 1 is the point).
_ARGON2_CONFIG = {
    "time_cost": 1,
    "memory_cost": 64,
    "parallelism": 1,
    "type": "id",
    "rounds": 3,
}


class TestParallelArgon2RoundsEquivalence(unittest.TestCase):
    def test_rounds_actually_change_the_output(self):
        """A rounds=1 config must differ from rounds=3 (proves rounds are applied)."""
        password = b"\x33" * 32
        salt = b"\x44" * 16
        one = bytes(
            compute_kdf_independent(password, salt, "argon2", dict(_ARGON2_CONFIG, rounds=1), 32)
        )
        three = bytes(compute_kdf_independent(password, salt, "argon2", dict(_ARGON2_CONFIG), 32))
        self.assertNotEqual(one, three)

    def test_rounds_use_salt_chaining(self):
        """rounds=3 must equal manually chaining three rounds=1 calls with
        round_salt = previous_result[:32] — the exact M3 construction."""
        password = b"\x11" * 32
        salt = b"\x22" * 16
        chained_input = password
        chained_salt = salt
        result = None
        for _ in range(3):
            result = bytes(
                compute_kdf_independent(
                    chained_input,
                    chained_salt,
                    "argon2",
                    dict(_ARGON2_CONFIG, rounds=1),
                    32,
                )
            )
            chained_input = result
            chained_salt = result[:32]
        direct = bytes(compute_kdf_independent(password, salt, "argon2", dict(_ARGON2_CONFIG), 32))
        self.assertEqual(result, direct)


if __name__ == "__main__":
    unittest.main()
