#!/usr/bin/env python3
"""Hash stages must fail closed instead of silently not running (gitlab#294).

1.4.x port of the 2026-08-23 fail-closed audit fixes:

- **sha384, sha224, sha3_384, sha3_224, blake2s, shake128** have live CLI
  flags and are recorded into metadata, but NO derivation path on any release
  ever applied them (empirically: recording rounds yields a byte-identical
  key to recording nothing). Decrypt must keep ignoring them (real files
  carry them); new encryption must refuse to record them.
- **Whirlpool** is a real stage on this line, but the sequential chain
  silently substituted SHA-512 when the module was missing (or errored
  mid-chain) while still recording whirlpool in metadata — the #288 class of
  fail-open. It now fails closed; the decrypt-only recovery hatch
  ``OPENSSL_ENCRYPT_ALLOW_WHIRLPOOL_SHA512_FALLBACK=1`` reproduces the
  byte-exact legacy substitution (the original fallback code is unchanged,
  only gated) so files WRITTEN with the substitution decrypt one last time.
"""

import os
import tempfile
import unittest
from unittest import mock

from openssl_encrypt.modules import crypt_core
from openssl_encrypt.modules.crypt_core import UNAPPLIED_HASH_STAGES, decrypt_file, encrypt_file


class TestUnappliedHashRefusedOnEncrypt(unittest.TestCase):
    """New encryption must refuse hash stages no derivation path executes."""

    @classmethod
    def setUpClass(cls):
        """Prepare a temp dir and a small plaintext input."""
        cls.tmp = tempfile.mkdtemp()
        cls.src = os.path.join(cls.tmp, "plain.txt")
        with open(cls.src, "wb") as f:
            f.write(b"hash stage fail closed corpus\n")

    def test_unapplied_stage_set_is_pinned(self):
        """The refused set is exactly the audited no-op stages (whirlpool is
        real on this line and stays out of it)."""
        self.assertEqual(
            UNAPPLIED_HASH_STAGES,
            frozenset({"sha384", "sha224", "sha3_384", "sha3_224", "blake2s", "shake128"}),
        )

    def test_each_unapplied_stage_refused(self):
        """Requesting any no-op stage must raise, naming the stage."""
        for name in sorted(UNAPPLIED_HASH_STAGES):
            with self.subTest(stage=name):
                out = os.path.join(self.tmp, f"{name}.enc")
                with self.assertRaises(Exception) as ctx:
                    encrypt_file(
                        self.src,
                        out,
                        b"test-password-294",
                        hash_config={name: 3, "sha256": 2},
                        quiet=True,
                    )
                self.assertIn(name, str(ctx.exception))
                self.assertFalse(os.path.exists(out), msg=f"{name}: output must not be written")

    def test_whirlpool_refused_on_encrypt_when_module_missing(self):
        """Whirlpool rounds are refused at encrypt if the module is absent."""
        out = os.path.join(self.tmp, "wp-missing.enc")
        with mock.patch.object(crypt_core, "WHIRLPOOL_AVAILABLE", False):
            with self.assertRaises(Exception) as ctx:
                encrypt_file(
                    self.src,
                    out,
                    b"test-password-294",
                    hash_config={"whirlpool": 3},
                    quiet=True,
                )
        self.assertIn("whirlpool", str(ctx.exception))
        self.assertFalse(os.path.exists(out))

    @unittest.skipUnless(crypt_core.WHIRLPOOL_AVAILABLE, "whirlpool module not installed")
    def test_whirlpool_roundtrip_still_works(self):
        """The real Whirlpool stage keeps encrypting and decrypting."""
        out = os.path.join(self.tmp, "wp.enc")
        dec = os.path.join(self.tmp, "wp.out")
        encrypt_file(
            self.src,
            out,
            b"test-password-294",
            hash_config={"whirlpool": 2, "sha256": 2},
            quiet=True,
        )
        decrypt_file(out, dec, b"test-password-294", quiet=True)
        with open(dec, "rb") as f:
            self.assertEqual(f.read(), b"hash stage fail closed corpus\n")


class TestWhirlpoolSubstitutionFailsClosed(unittest.TestCase):
    """The silent SHA-512 substitution is gated behind the recovery hatch."""

    def _derive(self, env_value=None):
        """Run multi_hash_password with whirlpool configured but unavailable."""
        environ = {k: v for k, v in os.environ.items()}
        if env_value is None:
            environ.pop(crypt_core._WHIRLPOOL_FALLBACK_ENV, None)
        else:
            environ[crypt_core._WHIRLPOOL_FALLBACK_ENV] = env_value
        with mock.patch.dict(os.environ, environ, clear=True):
            with mock.patch.object(crypt_core, "WHIRLPOOL_AVAILABLE", False):
                result = crypt_core.multi_hash_password(
                    b"test-password-294", b"0123456789abcdef", {"whirlpool": 3}, quiet=True
                )
        return bytes(result)

    def test_missing_module_fails_closed_by_default(self):
        """Without the hatch, derivation raises instead of substituting."""
        from openssl_encrypt.modules.crypt_errors import KeyDerivationError

        with self.assertRaises(KeyDerivationError) as ctx:
            self._derive()
        self.assertIn(crypt_core._WHIRLPOOL_FALLBACK_ENV, str(ctx.exception))

    @unittest.skipUnless(crypt_core.WHIRLPOOL_AVAILABLE, "whirlpool module not installed")
    def test_hatch_reproduces_legacy_substitution_deterministically(self):
        """The hatch path derives, is deterministic, and differs from real
        Whirlpool output (it reproduces the SHA-512-substituted legacy
        derivation for files written that way)."""
        substituted_1 = self._derive("1")
        substituted_2 = self._derive("1")
        self.assertEqual(substituted_1, substituted_2)
        real = bytes(
            crypt_core.multi_hash_password(
                b"test-password-294", b"0123456789abcdef", {"whirlpool": 3}, quiet=True
            )
        )
        self.assertNotEqual(substituted_1, real)
