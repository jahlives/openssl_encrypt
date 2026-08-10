#!/usr/bin/env python3
"""Legacy (< v13) `--parallel-kdf` must route through the single component
implementation (gitlab#224 items 1/4/8).

The old multiprocessing dispatcher duplicated every component's derivation in
`_hash_worker`/`_kdf_worker` — the exact drift class behind the M3 argon2
rounds divergence and the RandomX silent drop (#71). Two live defects remained:

- the task builder silently OMITTED the whirlpool component while the
  sequential path includes it, so a v11 whirlpool config derived a different
  (weaker) key under `--parallel-kdf` than without it;
- its balloon branch imported a module that never existed
  (`openssl_encrypt.modules.balloon_hash`), so v11 balloon + `--parallel-kdf`
  always errored out.

These tests pin the fix: every format routes to
`crypt_core.generate_key_independent_xor` (sequentially proven byte-identical
in parallel mode by test_parallel_kdf_v14_220.py), whirlpool participates,
balloon works, and the all-empty-config refusal both survives the routing and
stays scoped to encryption (decryption metadata keeps deriving so any legacy
file stays readable).
"""

import unittest
from unittest import mock

from openssl_encrypt.modules.crypt_core import (
    WHIRLPOOL_AVAILABLE,
    generate_key_independent_xor,
)
from openssl_encrypt.modules.parallel_kdf import generate_key_independent_xor_parallel

PASSWORD = b"test-password-for-legacy-route"
SALT = b"0123456789abcdef"  # 16 bytes


def _seq(hash_config, fmt):
    return generate_key_independent_xor(
        PASSWORD,
        SALT,
        hash_config,
        quiet=True,
        algorithm="aes-256-gcm",
        format_version=fmt,
    )[0]


def _par(hash_config, fmt, workers=4):
    return generate_key_independent_xor_parallel(
        PASSWORD,
        SALT,
        hash_config,
        quiet=True,
        algorithm="aes-256-gcm",
        format_version=fmt,
        max_workers=workers,
    )[0]


class TestLegacyParallelByteIdentical(unittest.TestCase):
    """Data-loss safety gate: parallel v11/v12 keys must equal sequential."""

    def _multi_config(self):
        return {
            "sha256": 150,
            "sha512": 150,
            "blake2b": 150,
            "argon2": {
                "enabled": True,
                "time_cost": 1,
                "memory_cost": 512,
                "parallelism": 1,
                "rounds": 1,
                "type": "id",
            },
            "scrypt": {"enabled": True, "n": 1024, "r": 8, "p": 1},
            "hkdf": {"enabled": True},
        }

    def test_v11_parallel_key_equals_sequential(self):
        self.assertEqual(_par(self._multi_config(), 11), _seq(self._multi_config(), 11))

    def test_v12_parallel_key_equals_sequential(self):
        self.assertEqual(_par(self._multi_config(), 12), _seq(self._multi_config(), 12))

    def test_v11_argon2_multi_round_matches_sequential(self):
        # Pins the M3 invariant (argon2 rounds>1 salt-chaining) through the
        # public entry point, replacing the retired _kdf_worker-level test.
        cfg = {
            "sha256": 50,
            "argon2": {
                "enabled": True,
                "time_cost": 1,
                "memory_cost": 512,
                "parallelism": 1,
                "rounds": 3,
                "type": "id",
            },
        }
        self.assertEqual(_par(cfg, 11), _seq(cfg, 11))


class TestWhirlpoolNotDropped(unittest.TestCase):
    """The v11 whirlpool component must participate under --parallel-kdf."""

    @unittest.skipUnless(WHIRLPOOL_AVAILABLE, "whirlpool module not available")
    def test_v11_whirlpool_key_equals_sequential(self):
        cfg = {"sha256": 50, "whirlpool": 25}
        self.assertEqual(_par(cfg, 11), _seq(cfg, 11))

    def test_v11_whirlpool_component_is_computed(self):
        # Module-independent pin: the parallel path must build a whirlpool
        # task when whirlpool rounds are configured. The old dispatcher's
        # task list omitted the algorithm entirely.
        import openssl_encrypt.modules.crypt_core as cc
        from openssl_encrypt.modules.secure_memory import SecureBytes

        seen = []

        def fake_hash(password, salt, algorithm, rounds, key_length, **kwargs):
            seen.append(algorithm)
            return SecureBytes(bytes([len(algorithm)]) * key_length)

        with mock.patch.object(cc, "compute_hash_independent", fake_hash):
            generate_key_independent_xor_parallel(
                PASSWORD,
                SALT,
                {"sha256": 10, "whirlpool": 10},
                quiet=True,
                algorithm="aes-256-gcm",
                format_version=11,
                max_workers=2,
            )
        self.assertIn("whirlpool", seen)


class TestBalloonParallelWorks(unittest.TestCase):
    """v11 balloon + --parallel-kdf used to raise 'Balloon hash module not
    found' (the worker imported a module that never existed). It must now
    derive, byte-identical to the sequential path."""

    def _cfg(self):
        return {
            "sha256": 50,
            "balloon": {"enabled": True, "space_cost": 32, "time_cost": 2, "delta": 3},
        }

    def test_v11_balloon_parallel_matches_sequential(self):
        self.assertEqual(_par(self._cfg(), 11), _seq(self._cfg(), 11))


class TestEmptyConfigGuard(unittest.TestCase):
    """The all-empty-config refusal must survive the routing for parallel
    requests (it lived only in the retired dispatcher; the sequential
    function's own check was unreachable because the initial-hash component
    is always appended). The sequential path keeps deriving -- fast-test API
    callers rely on it -- but now warns instead of proceeding silently, and
    decryption metadata is fully exempt so legacy files stay readable."""

    def test_empty_config_sequential_derives_with_warning(self):
        from contextlib import redirect_stderr
        from io import StringIO

        err = StringIO()
        with redirect_stderr(err):
            key, _, _ = generate_key_independent_xor(
                PASSWORD, SALT, {}, quiet=False, format_version=11
            )
        self.assertTrue(key)
        self.assertIn("unstretched", err.getvalue())

    def test_empty_config_raises_on_encrypt_parallel(self):
        with self.assertRaises(ValueError):
            generate_key_independent_xor_parallel(PASSWORD, SALT, {}, quiet=True, format_version=11)

    def test_empty_decryption_metadata_still_derives(self):
        key, _, _ = generate_key_independent_xor(
            PASSWORD,
            SALT,
            {"_is_from_decryption_metadata": True},
            quiet=True,
            format_version=11,
        )
        self.assertTrue(key)


if __name__ == "__main__":
    unittest.main()
