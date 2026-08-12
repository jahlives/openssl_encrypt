#!/usr/bin/env python3
"""`--parallel-kdf` must actually parallelize the v13/v14 formats (gitlab#220).

On 1.5.x (and now 1.4.x) the only producible formats are v14 (default) and v13,
both format_version >= 13. `generate_key_independent_xor_parallel` used to
delegate every such call straight back to the sequential
`generate_key_independent_xor` (printing "Parallel KDF not supported for v13"),
so `--parallel-kdf` never parallelized anything a user could produce.

The independent-XOR components are mutually independent (each derives from the
same input with a domain-separated per-component salt) and are combined with
XOR, which is commutative -- so computing them concurrently yields a
byte-identical key. These tests pin BOTH properties: byte-identical output
(the data-loss safety gate) AND that the parallel path really runs the
components concurrently instead of delegating.
"""

import threading
import unittest
from contextlib import redirect_stderr
from io import StringIO
from unittest import mock

from openssl_encrypt.modules.crypt_core import generate_key_independent_xor
from openssl_encrypt.modules.parallel_kdf import generate_key_independent_xor_parallel

PASSWORD = b"test-password-for-parallel-v14"
SALT = b"0123456789abcdef0123456789abcdef"  # 32 bytes


def _multi_kdf_config():
    """A config with several independent components (hashes + two KDFs)."""
    return {
        "sha256": 200,
        "sha512": 200,
        "blake2b": 200,
        "argon2": {
            "enabled": True,
            "time_cost": 1,
            "memory_cost": 512,
            "parallelism": 1,
            "type": "id",
        },
        "scrypt": {"enabled": True, "n": 1024, "r": 8, "p": 1},
    }


class TestParallelV14ByteIdentical(unittest.TestCase):
    """Data-loss safety gate: the parallel key must equal the sequential key."""

    def _seq(self, fmt):
        return generate_key_independent_xor(
            PASSWORD,
            SALT,
            _multi_kdf_config(),
            quiet=True,
            algorithm="aes-256-gcm",
            format_version=fmt,
        )[0]

    def _par(self, fmt, workers=4):
        return generate_key_independent_xor_parallel(
            PASSWORD,
            SALT,
            _multi_kdf_config(),
            quiet=True,
            algorithm="aes-256-gcm",
            format_version=fmt,
            max_workers=workers,
        )[0]

    def test_v14_parallel_key_equals_sequential(self):
        self.assertEqual(self._par(14), self._seq(14))

    def test_v13_parallel_key_equals_sequential(self):
        self.assertEqual(self._par(13), self._seq(13))

    def test_v14_parallel_is_deterministic(self):
        self.assertEqual(self._par(14), self._par(14))


class TestParallelV14ActuallyParallelizes(unittest.TestCase):
    """Drives the implementation: for v14 the path must NOT delegate to
    sequential -- it must compute the components concurrently."""

    def test_no_downgrade_message_for_v14(self):
        err = StringIO()
        with redirect_stderr(err):
            generate_key_independent_xor_parallel(
                PASSWORD,
                SALT,
                _multi_kdf_config(),
                quiet=False,
                algorithm="aes-256-gcm",
                format_version=14,
                max_workers=4,
            )
        self.assertNotIn("not supported", err.getvalue().lower())
        self.assertNotIn("using sequential", err.getvalue().lower())

    def test_kdf_components_run_on_worker_threads(self):
        # With parallelism, the KDF components must be computed off the main
        # thread. Delegation (the old behavior) runs everything on MainThread.
        import openssl_encrypt.modules.crypt_core as cc

        seen_threads = set()
        real = cc.compute_kdf_independent

        def spy(*a, **k):
            seen_threads.add(threading.current_thread().name)
            return real(*a, **k)

        with mock.patch.object(cc, "compute_kdf_independent", spy):
            generate_key_independent_xor_parallel(
                PASSWORD,
                SALT,
                _multi_kdf_config(),
                quiet=True,
                algorithm="aes-256-gcm",
                format_version=14,
                max_workers=4,
            )
        self.assertTrue(
            any(name != "MainThread" for name in seen_threads),
            f"KDF components did not run on worker threads: {seen_threads}",
        )


class TestParallelV14RandomXFailClosed(unittest.TestCase):
    """The RandomX fail-closed guard (#71) must survive parallelisation: an
    enabled-but-unavailable RandomX component must raise, not be silently
    dropped, whether components run sequentially or on the thread pool."""

    def _cfg(self):
        return {"sha256": 100, "randomx": {"enabled": True, "rounds": 1}}

    def _run(self, parallel):
        import openssl_encrypt.modules.crypt_core as cc
        from openssl_encrypt.modules.crypt_core import (
            ValidationError,
            generate_key_independent_xor,
        )

        real = cc.compute_kdf_independent

        def boom(*a, **k):
            if k.get("kdf_type") == "randomx":
                raise OSError("simulated: RandomX shared library not loadable")
            return real(*a, **k)

        with mock.patch.object(cc, "compute_kdf_independent", boom):
            with self.assertRaises(ValidationError):
                generate_key_independent_xor(
                    PASSWORD,
                    SALT,
                    self._cfg(),
                    quiet=True,
                    format_version=14,
                    parallel=parallel,
                    max_workers=4,
                )

    def test_fail_closed_sequential(self):
        self._run(parallel=False)

    def test_fail_closed_parallel(self):
        self._run(parallel=True)


if __name__ == "__main__":
    unittest.main()
