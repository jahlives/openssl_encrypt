#!/usr/bin/env python3
"""Hardening of the parallel-KDF thread pool (gitlab#224 items 2/3/5).

- Worker count: the `--kdf-workers` help promises "default: auto-detect,
  max: CPU count", but the pool defaulted to one worker per component (up to
  13) regardless of cores. It must cap at CPU count, at the component count,
  and additionally at the largest count whose worst-case co-resident
  memory-hard components stay within HARD_MEMORY_CEILING_KB (concurrency
  turns peak KDF memory from max(components) into a sum, and encrypt has no
  ceiling check of its own).
- Abort: a KeyboardInterrupt in the main thread must not be captured as a
  component failure and must not wait for every remaining component.
- Diagnostics: when several components fail, the non-first failures must be
  logged instead of vanishing.
"""

import threading
import time
import unittest
from unittest import mock

from openssl_encrypt.modules.crypt_core import (
    _parallel_kdf_worker_limit,
    generate_key_independent_xor,
)
from openssl_encrypt.modules.decryption_estimator import HARD_MEMORY_CEILING_KB
from openssl_encrypt.modules.secure_memory import SecureBytes

PASSWORD = b"pool-hardening-password"
SALT = b"0123456789abcdef"

GIB_KB = 1024 * 1024


class TestWorkerLimit(unittest.TestCase):
    def _limit(self, requested, mem, cpu):
        with mock.patch("openssl_encrypt.modules.crypt_core.os.cpu_count", return_value=cpu):
            return _parallel_kdf_worker_limit(requested, mem, quiet=True)

    def test_default_capped_at_cpu(self):
        self.assertEqual(self._limit(None, [10] * 8, cpu=2), 2)

    def test_explicit_capped_at_cpu(self):
        self.assertEqual(self._limit(16, [10] * 8, cpu=4), 4)

    def test_capped_at_component_count(self):
        self.assertEqual(self._limit(None, [10] * 3, cpu=64), 3)

    def test_memory_clamp_to_single_worker(self):
        # Two 5 GiB components: any two co-resident exceed the 8 GiB ceiling.
        self.assertEqual(self._limit(None, [5 * GIB_KB, 5 * GIB_KB, 1], cpu=8), 1)

    def test_memory_clamp_partial(self):
        # Three 3 GiB components: three co-resident exceed 8 GiB, two fit.
        self.assertEqual(self._limit(None, [3 * GIB_KB] * 3, cpu=8), 2)

    def test_no_clamp_when_memory_fits(self):
        self.assertEqual(self._limit(None, [1024] * 4, cpu=4), 4)

    def test_ceiling_is_the_documented_constant(self):
        # Exactly at the ceiling is allowed; one KB over is not.
        at = [HARD_MEMORY_CEILING_KB // 2] * 2
        over = [HARD_MEMORY_CEILING_KB // 2 + 1] * 2
        self.assertEqual(self._limit(None, at, cpu=2), 2)
        self.assertEqual(self._limit(None, over, cpu=2), 1)


class TestPoolBehavior(unittest.TestCase):
    def _config(self):
        return {
            "sha256": 50,
            "argon2": {
                "enabled": True,
                "time_cost": 1,
                "memory_cost": 512,
                "parallelism": 1,
                "rounds": 1,
                "type": "id",
            },
            "scrypt": {"enabled": True, "n": 1024, "r": 8, "p": 1},
        }

    def test_single_cpu_still_derives_and_matches(self):
        with mock.patch("openssl_encrypt.modules.crypt_core.os.cpu_count", return_value=1):
            par = generate_key_independent_xor(
                PASSWORD, SALT, self._config(), quiet=True, format_version=14, parallel=True
            )[0]
        seq = generate_key_independent_xor(
            PASSWORD, SALT, self._config(), quiet=True, format_version=14
        )[0]
        self.assertEqual(par, seq)

    def test_keyboard_interrupt_is_not_swallowed_and_aborts_promptly(self):
        # First-submitted component raises KeyboardInterrupt (re-raised in the
        # main thread by future.result()); another sleeps for 5 s. The abort
        # must propagate the KeyboardInterrupt unchanged and must NOT block
        # until the sleeper finishes.
        import openssl_encrypt.modules.crypt_core as cc

        real = cc.compute_kdf_independent

        def boom_or_sleep(*a, **k):
            if k.get("kdf_type") == "argon2":
                time.sleep(0.1)
                raise KeyboardInterrupt("simulated Ctrl-C")
            if k.get("kdf_type") == "scrypt":
                time.sleep(5)
                return SecureBytes(b"\x01" * 32)
            return real(*a, **k)

        started = time.monotonic()
        with mock.patch.object(
            cc, "compute_hash_independent", lambda **k: SecureBytes(b"\x02" * 32)
        ):
            with mock.patch.object(cc, "compute_kdf_independent", boom_or_sleep):
                with self.assertRaises(KeyboardInterrupt):
                    generate_key_independent_xor(
                        PASSWORD,
                        SALT,
                        self._config(),
                        quiet=True,
                        format_version=14,
                        parallel=True,
                        max_workers=4,
                    )
        elapsed = time.monotonic() - started
        self.assertLess(
            elapsed,
            2.5,
            f"abort blocked for {elapsed:.1f}s — drained the sleeping component",
        )

    def test_secondary_component_failures_are_logged(self):
        # argon2 fails first (first_error), scrypt's failure must be logged
        # rather than silently discarded.
        import openssl_encrypt.modules.crypt_core as cc

        def boom(*a, **k):
            if k.get("kdf_type") == "argon2":
                raise ValueError("primary failure")
            if k.get("kdf_type") == "scrypt":
                raise ValueError("secondary failure")
            raise AssertionError("unexpected kdf_type")

        with mock.patch.object(
            cc, "compute_hash_independent", lambda **k: SecureBytes(b"\x03" * 32)
        ):
            with mock.patch.object(cc, "compute_kdf_independent", boom):
                with self.assertLogs("openssl_encrypt.modules.crypt_core", level="DEBUG") as logs:
                    with self.assertRaises(ValueError) as ctx:
                        generate_key_independent_xor(
                            PASSWORD,
                            SALT,
                            self._config(),
                            quiet=True,
                            format_version=14,
                            parallel=True,
                            max_workers=4,
                        )
        self.assertIn("primary failure", str(ctx.exception))
        self.assertTrue(
            any("additional component failure" in line for line in logs.output),
            f"secondary failure not logged: {logs.output}",
        )

    def test_worker_threads_are_used(self):
        # Sanity: with the cap in place the components still run off-main-thread.
        import openssl_encrypt.modules.crypt_core as cc

        seen = set()
        real = cc.compute_kdf_independent

        def spy(*a, **k):
            seen.add(threading.current_thread().name)
            return real(*a, **k)

        with mock.patch.object(cc, "compute_kdf_independent", spy):
            generate_key_independent_xor(
                PASSWORD, SALT, self._config(), quiet=True, format_version=14, parallel=True
            )
        self.assertTrue(any(name != "MainThread" for name in seen))


if __name__ == "__main__":
    unittest.main()
