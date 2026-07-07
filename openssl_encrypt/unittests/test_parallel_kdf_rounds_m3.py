"""Regression test for follow-up finding M3 [KDF-1].

The sequential Independent-XOR Argon2 path (`compute_kdf_independent`) iterates
`rounds` times with salt-chaining (`round_salt = result[:32]`). The parallel
worker (`_kdf_worker`) ran Argon2 exactly once and ignored `rounds` entirely.
Since `--parallel-kdf` is a runtime flag not persisted in metadata, this meant
encrypting with parallel + Argon2 rounds>1 and decrypting without it (or vice
versa) derived a different key -> permanent silent failure to decrypt, and the
parallel path did strictly less KDF work than the recorded config.

This test pins that the two paths produce byte-identical Argon2 output for
rounds > 1.
"""

import unittest

from openssl_encrypt.modules.crypt_core import compute_kdf_independent
from openssl_encrypt.modules.parallel_kdf import _kdf_worker


class _FakeQueue:
    """Minimal stand-in for the worker's progress mp.Queue."""

    def put(self, _msg):  # noqa: D401 - trivial sink
        pass


# Fast, deterministic Argon2 params (rounds > 1 is the point).
_ARGON2_CONFIG = {
    "time_cost": 1,
    "memory_cost": 64,
    "parallelism": 1,
    "type": "id",
    "rounds": 3,
}


class TestParallelArgon2RoundsEquivalence(unittest.TestCase):
    def _seq(self, password, salt, key_length):
        return bytes(
            compute_kdf_independent(password, salt, "argon2", dict(_ARGON2_CONFIG), key_length)
        )

    def _par(self, password, salt, key_length):
        _, result = _kdf_worker(
            "argon2", password, salt, "argon2", dict(_ARGON2_CONFIG), key_length, _FakeQueue()
        )
        return result

    def test_parallel_matches_sequential_for_rounds_gt_1(self):
        password = b"\x11" * 32  # stand-in for the initial SHA-256 hash
        salt = b"\x22" * 16
        key_length = 32
        self.assertEqual(
            self._par(password, salt, key_length), self._seq(password, salt, key_length)
        )

    def test_rounds_actually_change_the_output(self):
        """A rounds=1 config must differ from rounds=3 (proves rounds are applied)."""
        password = b"\x33" * 32
        salt = b"\x44" * 16
        one = dict(_ARGON2_CONFIG, rounds=1)
        _, par_one = _kdf_worker("argon2", password, salt, "argon2", one, 32, _FakeQueue())
        _, par_three = _kdf_worker(
            "argon2", password, salt, "argon2", dict(_ARGON2_CONFIG), 32, _FakeQueue()
        )
        self.assertNotEqual(par_one, par_three)


if __name__ == "__main__":
    unittest.main()
