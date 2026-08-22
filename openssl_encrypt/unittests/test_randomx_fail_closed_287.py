#!/usr/bin/env python3
"""
gitlab#287: the legacy sequential chain in generate_key must fail CLOSED on
a RandomX failure.

Historically the stage's try/except printed "continuing without RandomX" and
derived the key WITHOUT the configured stage — weaker derivation than
requested, and a key/metadata mismatch that can strand files. The branch was
nearly unreachable while the abandoned PyPI binding died with SIGILL instead
of raising; the project-owned randomx_native (gitlab#285) deliberately
raises, so the handler is now load-bearing. Same for the sibling branch that
warned-and-continued when RandomX was requested but no binding was
available.

Regression contract: a RandomX-stage failure or unavailability raises
KeyDerivationError; no key is ever derived with the stage silently dropped.
"""

import unittest
from unittest import mock

from openssl_encrypt.modules import crypt_core
from openssl_encrypt.modules.crypt_errors import KeyDerivationError

PASSWORD = b"fail-closed-test-password"
SALT = b"fail-closed-salt"  # 16 bytes
RANDOMX_CONFIG = {"randomx": {"enabled": True, "rounds": 1, "mode": "light"}}


class TestRandomXStageFailsClosed(unittest.TestCase):
    """generate_key must never continue without a requested RandomX stage."""

    @unittest.skipUnless(crypt_core.RANDOMX_AVAILABLE, "no RandomX binding")
    def test_control_succeeds_with_working_binding(self):
        key, _salt, _config = crypt_core.generate_key(
            PASSWORD, SALT, dict(RANDOMX_CONFIG), quiet=True
        )
        self.assertTrue(key)

    @unittest.skipUnless(crypt_core.RANDOMX_AVAILABLE, "no RandomX binding")
    def test_stage_failure_raises_instead_of_continuing(self):
        """A raising randomx_kdf must abort key derivation (gitlab#287)."""

        def _boom(*args, **kwargs):
            raise RuntimeError("simulated native RandomX failure")

        with mock.patch.object(crypt_core, "randomx_kdf", _boom):
            with self.assertRaises(KeyDerivationError):
                crypt_core.generate_key(PASSWORD, SALT, dict(RANDOMX_CONFIG), quiet=True)

    @unittest.skipUnless(crypt_core.RANDOMX_AVAILABLE, "no RandomX binding")
    def test_stage_failure_never_returns_stageless_key(self):
        """The fail-open bug in one assertion: the key derived on failure must
        not equal the key derived with RandomX genuinely disabled."""
        no_randomx_key, _s, _c = crypt_core.generate_key(
            PASSWORD, SALT, {"randomx": {"enabled": False}}, quiet=True
        )

        def _boom(*args, **kwargs):
            raise RuntimeError("simulated native RandomX failure")

        with mock.patch.object(crypt_core, "randomx_kdf", _boom):
            try:
                key, _s2, _c2 = crypt_core.generate_key(
                    PASSWORD, SALT, dict(RANDOMX_CONFIG), quiet=True
                )
            except Exception:
                return  # failing closed is the contract; nothing more to check
        self.assertNotEqual(
            key,
            no_randomx_key,
            msg="RandomX-stage failure silently produced the stage-dropped key "
            "(fail-open, gitlab#287)",
        )

    def test_requested_but_unavailable_raises(self):
        """RandomX requested with no binding importable must also fail closed."""
        with mock.patch.object(crypt_core, "RANDOMX_AVAILABLE", False):
            with self.assertRaises(KeyDerivationError):
                crypt_core.generate_key(PASSWORD, SALT, dict(RANDOMX_CONFIG), quiet=True)


if __name__ == "__main__":
    unittest.main()
