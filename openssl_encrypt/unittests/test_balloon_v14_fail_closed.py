#!/usr/bin/env python3
"""
Regression tests for gitlab#125 (security review 2026-07-13, INFO-2).

The decrypt-side Balloon fallback ``space_cost = kdf_config.get("space_cost", 16)``
is load-bearing for v11 files written by released v1.4.0-v1.4.3 (pre-M3, see
test_balloon_defaults_m3.py::test_legacy_weak_file_still_decrypts) and must
stay. But v14 postdates the M3 fix: every released writer persists space_cost,
so a v14+ balloon config missing space_cost can only be crafted/corrupted
metadata and must be refused instead of silently deriving with the weak value.

Decision (2026-07-13): version-gated fail-closed -
- format_version >= 14 + balloon enabled + space_cost absent -> ValueError
- v11-13 and version-less callers keep the 16 fallback (legacy compat)

The parallel KDF path needs no gate of its own: every format delegates to the
gated component functions (compute_kdf_independent), which since gitlab#220/#224
run either inline or in worker threads whose exceptions re-raise through
future.result() -- an invariant guarded here.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from openssl_encrypt.modules import crypt_core
from openssl_encrypt.modules.crypt_core import (
    compute_kdf_independent,
    generate_key_independent_xor,
)

SALT = bytes.fromhex("bb" * 16)
PASSWORD = b"pw12345678"

BALLOON_FAST = {"enabled": True, "space_cost": 16, "time_cost": 1, "delta": 1}
BALLOON_NO_SPACE_COST = {"enabled": True, "time_cost": 1, "delta": 1}


def _compute(cfg, format_version=None):
    kwargs = {}
    if format_version is not None:
        kwargs["format_version"] = format_version
    return compute_kdf_independent(
        password=PASSWORD,
        salt=SALT,
        kdf_type="balloon",
        kdf_config=dict(cfg),
        key_length=32,
        quiet=True,
        debug=False,
        **kwargs,
    )


class TestBalloonV14FailClosed(unittest.TestCase):
    """v14+ balloon config without space_cost must be refused."""

    def test_v14_missing_space_cost_refused(self):
        with self.assertRaises(ValueError):
            _compute(BALLOON_NO_SPACE_COST, format_version=14)

    def test_v14_explicit_space_cost_works(self):
        result = _compute(BALLOON_FAST, format_version=14)
        self.assertEqual(len(bytes(result)), 32)

    def test_v11_missing_space_cost_keeps_weak_fallback(self):
        """Pre-M3 v11 files were really derived with 16 - must not change."""
        implicit = bytes(_compute(BALLOON_NO_SPACE_COST, format_version=11))
        explicit = bytes(_compute(BALLOON_FAST, format_version=11))
        self.assertEqual(implicit, explicit)

    def test_versionless_caller_keeps_weak_fallback(self):
        """Callers that pass no format_version keep today's behavior."""
        implicit = bytes(_compute(BALLOON_NO_SPACE_COST))
        explicit = bytes(_compute(BALLOON_FAST))
        self.assertEqual(implicit, explicit)


class TestBalloonV14FailClosedIntegration(unittest.TestCase):
    """The gate fires through the full derivation entry point."""

    def _hash_config(self, balloon):
        return {"derivation_config": {"kdf_config": {"balloon": dict(balloon)}}}

    def test_generate_key_independent_xor_v14_refused(self):
        with self.assertRaises(ValueError):
            generate_key_independent_xor(
                PASSWORD,
                SALT,
                self._hash_config(BALLOON_NO_SPACE_COST),
                quiet=True,
                algorithm="aes-gcm",
                format_version=14,
            )

    def test_generate_key_independent_xor_v11_still_works(self):
        key, _, _ = generate_key_independent_xor(
            PASSWORD,
            SALT,
            self._hash_config(BALLOON_NO_SPACE_COST),
            quiet=True,
            algorithm="aes-gcm",
            format_version=11,
        )
        self.assertTrue(len(bytes(key)) >= 32)

    def test_parallel_v14_delegates_to_sequential(self):
        """Invariant that makes a parallel-side gate unnecessary: parallel
        dispatch delegates to generate_key_independent_xor, whose gated
        component functions run in the worker threads and re-raise through
        future.result() (gitlab#224 rewording; the gate itself is exercised
        by the tests above)."""
        from openssl_encrypt.modules.parallel_kdf import generate_key_independent_xor_parallel

        sentinel = (b"k" * 32, SALT, {})
        with mock.patch.object(
            crypt_core, "generate_key_independent_xor", return_value=sentinel
        ) as delegate:
            result = generate_key_independent_xor_parallel(
                PASSWORD,
                SALT,
                self._hash_config(BALLOON_FAST),
                quiet=True,
                algorithm="aes-gcm",
                format_version=14,
            )
        delegate.assert_called_once()
        self.assertEqual(result, sentinel)


if __name__ == "__main__":
    unittest.main()
