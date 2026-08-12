"""Regression test for follow-up finding (crypto-reviewer, M2/M3 pass):
RandomX must fail CLOSED in the parallel Independent-XOR path.

The sequential path (#71) refuses to derive a key when RandomX is explicitly
enabled but unavailable, because dropping a KDF component can collapse the
derived key to a weaker value. The parallel dispatcher instead skipped RandomX
with a warning ("RandomX not available, skipping") and derived a weaker key
that also diverges from the sequential path (undecryptable). This test pins the
fail-closed behavior: with RandomX enabled + unavailable (alongside another
enabled KDF), the parallel path raises rather than silently dropping it.
"""

import unittest
from unittest import mock

from openssl_encrypt.modules.crypt_errors import ValidationError
from openssl_encrypt.modules.parallel_kdf import generate_key_independent_xor_parallel


class TestParallelRandomXFailClosed(unittest.TestCase):
    def test_randomx_unavailable_raises_not_skips(self):
        hash_config = {
            "derivation_config": {
                "kdf_config": {
                    # Another enabled component so the old code would have silently
                    # dropped RandomX and derived a weaker (argon2-only) key.
                    "argon2": {
                        "enabled": True,
                        "time_cost": 1,
                        "memory_cost": 64,
                        "parallelism": 1,
                        "rounds": 1,
                    },
                    "randomx": {"enabled": True, "rounds": 1},
                }
            }
        }
        # Since gitlab#224 the parallel entry routes through
        # compute_kdf_independent, whose RandomX thunk fail-closes with the
        # sequential path's ValidationError (not the old dispatcher's
        # pre-check ValueError). Force unavailability the way the runtime
        # actually experiences it: randomx_kdf raising ImportError/OSError.
        with mock.patch(
            "openssl_encrypt.modules.randomx.randomx_kdf",
            side_effect=ImportError("simulated: RandomX unavailable"),
        ):
            with self.assertRaises((ValueError, ValidationError)) as ctx:
                generate_key_independent_xor_parallel(
                    b"password", b"saltsaltsaltsalt", hash_config, quiet=True
                )
        # Must be the fail-closed RandomX message, not "No algorithms enabled".
        self.assertIn("RandomX", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
