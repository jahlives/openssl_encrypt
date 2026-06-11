#!/usr/bin/env python3
"""
Regression tests for M10 part (a): kdf_registry password handling.

Two things are checked:

1. Correctness (the critical guard): every backend must derive the EXACT same
   key whether the password is passed as bytes, bytearray, or SecureBytes -
   the wipe rework must not change any derived key.

2. Minimal-copy + effective-wipe design:
   - cryptography backends (Scrypt/HKDF), Balloon and RandomX accept a
     bytearray/SecureBytes directly, so the registry makes NO copy of the
     secret and calls secure_memzero zero times - the caller owns and zeroes
     its SecureBytes.
   - argon2 requires immutable bytes, so for a SecureBytes input the registry
     holds the secret in a wipeable bytearray and zeroes it (one
     secure_memzero call on a bytearray); for a bytes input it makes no copy
     and does not wipe (the caller owns the buffer).
   - In every case the caller's SecureBytes is left intact (the registry must
     not wipe a buffer it does not own).

See SECURITY_REVIEW_FINDINGS.md (M10).
"""

import unittest
from unittest import mock

from openssl_encrypt.modules.registry import kdf_registry as K
from openssl_encrypt.modules.secure_memory import SecureBytes

SALT = b"0123456789abcdef"
PW = b"correct horse battery staple"


def _backends():
    b = {
        "argon2id": (K.Argon2id(), K.Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)),
        "scrypt": (K.Scrypt(), K.ScryptParams(n=2048, r=8, p=1)),
        "hkdf": (K.HKDF(), K.HKDFParams()),
        "balloon": (K.Balloon(), K.BalloonParams(time_cost=1, space_cost=16)),
    }
    return b


class TestKdfDeriveKeyUnchanged(unittest.TestCase):
    """The derived key must be identical across input types (no key change)."""

    def test_bytes_securebytes_bytearray_identical(self):
        for name, (backend, params) in _backends().items():
            with self.subTest(kdf=name):
                k_bytes = bytes(backend.derive(PW, SALT, params))
                k_secure = bytes(backend.derive(SecureBytes(PW), SALT, params))
                k_barray = bytes(backend.derive(bytearray(PW), SALT, params))
                self.assertEqual(k_bytes, k_secure)
                self.assertEqual(k_bytes, k_barray)
                self.assertEqual(len(k_bytes), params.output_length)

    def test_argon2_variants_match_argon2id(self):
        params = K.Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
        base = bytes(K.Argon2id().derive(PW, SALT, params))
        # i/d delegate to Argon2id with a forced variant -> different variant,
        # but must still be deterministic and equal for bytes vs SecureBytes
        for cls in (K.Argon2i, K.Argon2d):
            kb = bytes(
                cls().derive(PW, SALT, K.Argon2Params(time_cost=1, memory_cost=8192, parallelism=1))
            )
            ks = bytes(
                cls().derive(
                    SecureBytes(PW),
                    SALT,
                    K.Argon2Params(time_cost=1, memory_cost=8192, parallelism=1),
                )
            )
            self.assertEqual(kb, ks)


class TestKdfDoesNotMutateCallerSecret(unittest.TestCase):
    """The registry must never wipe/alter a caller-owned SecureBytes."""

    def test_caller_securebytes_intact_after_derive(self):
        for name, (backend, params) in _backends().items():
            with self.subTest(kdf=name):
                sb = SecureBytes(PW)
                backend.derive(sb, SALT, params)
                self.assertEqual(bytes(sb), PW)


class TestKdfWipeDesign(unittest.TestCase):
    """Verify the copy/wipe behaviour per backend."""

    def _count_memzero(self, backend, password, params):
        calls = []
        real = K.secure_memzero

        def spy(data, *a, **k):
            calls.append(data)
            return real(data, *a, **k)

        with mock.patch.object(K, "secure_memzero", side_effect=spy):
            backend.derive(password, SALT, params)
        return calls

    def test_argon2_securebytes_wipes_one_bytearray_copy(self):
        calls = self._count_memzero(
            K.Argon2id(),
            SecureBytes(PW),
            K.Argon2Params(time_cost=1, memory_cost=8192, parallelism=1),
        )
        self.assertEqual(len(calls), 1, "argon2 should wipe exactly its one working copy")
        self.assertIsInstance(calls[0], bytearray)
        self.assertTrue(all(b == 0 for b in calls[0]), "the working copy must end zeroed")

    def test_argon2_bytes_makes_no_copy_no_wipe(self):
        calls = self._count_memzero(
            K.Argon2id(), PW, K.Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
        )
        self.assertEqual(len(calls), 0, "no wipe for a caller-owned bytes password")

    def test_copyfree_backends_do_not_wipe(self):
        # PBKDF2/Scrypt/HKDF/Balloon accept SecureBytes directly -> no copy made
        for name in ("scrypt", "hkdf", "balloon"):  # PBKDF2 removed in 1.5
            backend, params = _backends()[name]
            with self.subTest(kdf=name):
                calls = self._count_memzero(backend, SecureBytes(PW), params)
                self.assertEqual(len(calls), 0, f"{name} should not copy/wipe the secret")


if __name__ == "__main__":
    unittest.main()
