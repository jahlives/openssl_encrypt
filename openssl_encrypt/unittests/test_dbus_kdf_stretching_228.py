#!/usr/bin/env python3
"""The D-Bus EncryptFile path must never derive a key without stretching (gitlab#228, F1).

CryptoService built a hash_config with key names crypt_core does not read
(sha512_iterations, argon2_time_cost, enable_hkdf, ...), so no KDF/hash was
ever enabled AND the non-empty dict defeated encrypt_file's STANDARD-template
default -- collapsing every D-Bus-encrypted file's key to a single unstretched
SHA-256 (CWE-916). These tests pin the two guarantees of the fix:

1. the hash_config the D-Bus path builds is one crypt_core actually consumes
   (a memory-hard KDF or real hash rounds are enabled), for default options
   and for the option forms the example client sends; and
2. a config that provides no key stretching is refused, fail-closed.
"""

import unittest

from openssl_encrypt.modules import crypt_core
from openssl_encrypt.modules.dbus_kdf_config import (
    build_encrypt_hash_config,
    config_provides_key_stretching,
)


def _component_labels(hash_config):
    """The component tasks generate_key_independent_xor would build for this
    config -- empty means the key collapses to the bare seed hash."""
    captured = []
    # Cheap, no crypto: just enumerate which components the derivation enables.
    kdf = hash_config.get("derivation_config", {}).get("kdf_config", hash_config)
    for algo in [
        "sha256",
        "sha512",
        "sha3_256",
        "sha3_512",
        "blake2b",
        "blake3",
        "shake256",
        "whirlpool",
    ]:
        if isinstance(hash_config.get(algo), int) and hash_config[algo] > 0:
            captured.append(algo)
    for k in ["argon2", "scrypt", "balloon", "hkdf", "randomx"]:
        if isinstance(kdf.get(k), dict) and kdf[k].get("enabled"):
            captured.append(k)
    return captured


class TestBuiltConfigIsStretched(unittest.TestCase):
    def test_default_options_enable_a_memory_hard_kdf(self):
        hc = build_encrypt_hash_config({})
        labels = _component_labels(hc)
        self.assertTrue(
            any(k in labels for k in ("argon2", "scrypt", "balloon")),
            f"default D-Bus config has no memory-hard KDF: {labels}",
        )
        self.assertTrue(config_provides_key_stretching(hc))

    def test_config_uses_keys_crypt_core_reads(self):
        # The regression: keys like 'argon2_time_cost'/'sha512_iterations' are
        # invisible to crypt_core. The built config must not be all-unknown.
        hc = build_encrypt_hash_config({"sha512_rounds": 10000, "enable_hkdf": True})
        self.assertGreater(len(_component_labels(hc)), 0)
        # sha512_rounds must map to the flat 'sha512' int crypt_core reads.
        self.assertEqual(hc.get("sha512"), 10000)

    def test_example_client_options_still_stretched(self):
        # examples/dbus_clients/python_example.py sends these.
        hc = build_encrypt_hash_config({"sha512_rounds": 10000, "enable_hkdf": True})
        self.assertTrue(config_provides_key_stretching(hc))

    def test_argon2_param_overrides_apply_to_the_right_place(self):
        hc = build_encrypt_hash_config(
            {"argon2_time_cost": 5, "argon2_memory_cost": 131072, "argon2_parallelism": 8}
        )
        self.assertTrue(hc["argon2"]["enabled"])
        self.assertEqual(hc["argon2"]["time_cost"], 5)
        self.assertEqual(hc["argon2"]["memory_cost"], 131072)
        self.assertEqual(hc["argon2"]["parallelism"], 8)


class TestFailClosed(unittest.TestCase):
    def test_all_empty_config_is_not_stretched(self):
        self.assertFalse(config_provides_key_stretching({}))
        self.assertFalse(config_provides_key_stretching({"sha256": 0, "sha512": 0}))
        # HKDF alone is extract-expand, not a work factor -> not stretching.
        self.assertFalse(config_provides_key_stretching({"hkdf": {"enabled": True}}))

    def test_a_token_single_round_hash_is_not_treated_as_stretching(self):
        # review Low: the gate must not be satisfied by {"sha256": 1}.
        self.assertFalse(config_provides_key_stretching({"sha256": 1}))
        self.assertFalse(config_provides_key_stretching({"sha512": 999}))

    def test_hash_rounds_or_memory_hard_kdf_counts_as_stretched(self):
        self.assertTrue(config_provides_key_stretching({"sha512": 10000}))
        self.assertTrue(config_provides_key_stretching({"argon2": {"enabled": True}}))
        self.assertTrue(config_provides_key_stretching({"scrypt": {"enabled": True}}))


class TestCostParamsAreBounded(unittest.TestCase):
    """review Medium: the fix makes previously-dead cost keys live, so an
    unbounded value would be a resource-exhaustion DoS (worse on the system
    bus). The D-Bus boundary clamps them down rather than passing them through."""

    def test_absurd_argon2_memory_is_clamped(self):
        hc = build_encrypt_hash_config({"argon2_memory_cost": 1 << 34})  # 16 GiB
        self.assertLessEqual(hc["argon2"]["memory_cost"], 1024 * 1024)  # <= 1 GiB

    def test_absurd_hash_rounds_are_clamped(self):
        hc = build_encrypt_hash_config({"sha3_512_rounds": 10**9})
        self.assertLessEqual(hc["sha3_512"], 5_000_000)

    def test_absurd_argon2_time_and_parallelism_clamped(self):
        hc = build_encrypt_hash_config({"argon2_time_cost": 10**6, "argon2_parallelism": 10**6})
        self.assertLessEqual(hc["argon2"]["time_cost"], 32)
        self.assertLessEqual(hc["argon2"]["parallelism"], 16)

    def test_legitimate_paranoid_level_values_pass_through(self):
        # PARANOID-scale request must NOT be clamped away.
        hc = build_encrypt_hash_config(
            {"argon2_memory_cost": 131072, "argon2_time_cost": 4, "sha3_512_rounds": 800000}
        )
        self.assertEqual(hc["argon2"]["memory_cost"], 131072)
        self.assertEqual(hc["argon2"]["time_cost"], 4)
        self.assertEqual(hc["sha3_512"], 800000)

    def test_non_int_cost_is_ignored_not_crashing(self):
        hc = build_encrypt_hash_config({"argon2_memory_cost": "lots", "sha256_rounds": None})
        self.assertTrue(config_provides_key_stretching(hc))  # baseline still stretched


class TestCostParamsCannotBeDowngraded(unittest.TestCase):
    """review re-review Medium: overrides may only RAISE cost. A client must
    not be able to weaken argon2 below the STANDARD baseline (m=65536/t=3/p=4)
    or zero out the template's hash rounds -- that would re-open #228's CWE-916
    collapse via weak-but-nonzero parameters instead of dead keys."""

    def test_argon2_downgrade_is_floored_to_standard_baseline(self):
        hc = build_encrypt_hash_config(
            {"argon2_memory_cost": 8, "argon2_time_cost": 1, "argon2_parallelism": 1}
        )
        self.assertGreaterEqual(hc["argon2"]["memory_cost"], 65536)
        self.assertGreaterEqual(hc["argon2"]["time_cost"], 3)
        self.assertGreaterEqual(hc["argon2"]["parallelism"], 4)
        self.assertTrue(config_provides_key_stretching(hc))

    def test_template_hash_rounds_cannot_be_zeroed(self):
        # STANDARD sets sha3_512=10000 and blake3=10000; a client must not
        # be able to drop them below that.
        hc = build_encrypt_hash_config({"sha3_512_rounds": 0, "blake3_rounds": 5})
        self.assertGreaterEqual(hc["sha3_512"], 10000)
        self.assertGreaterEqual(hc["blake3"], 10000)

    def test_raising_argon2_cost_still_works(self):
        hc = build_encrypt_hash_config({"argon2_memory_cost": 131072, "argon2_time_cost": 4})
        self.assertEqual(hc["argon2"]["memory_cost"], 131072)
        self.assertEqual(hc["argon2"]["time_cost"], 4)


if __name__ == "__main__":
    unittest.main()
