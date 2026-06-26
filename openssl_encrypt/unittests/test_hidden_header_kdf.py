#!/usr/bin/env python3
"""
Unit tests for the hidden-header outer key-derivation function.

Covers the outer KDF used by the whitened ("hidden") file format:
  - keyless mode derives a cheap, deterministic key from the *public* salt
    (whitening only -- no secret, so memory-hard work would be wasted);
  - keyed mode derives a key from a second password through a heavy, fixed
    chain (SHA3-512 iterations -> Argon2id passes -> scrypt -> HKDF).

The two modes are domain-separated so that the same salt never yields the
same key across modes. All code in English as per project requirements.
"""

import unittest

from openssl_encrypt.modules.crypt_errors import ValidationError
from openssl_encrypt.modules.hidden_header import (
    PRODUCTION_KEYED_PROFILE,
    KeyedProfile,
    derive_outer_key,
)

# A deliberately tiny profile so the keyed-mode property tests stay fast.
# The chain *structure* (and therefore its security-relevant properties:
# determinism, domain separation, sensitivity to inputs) is identical to the
# production profile; only the cost parameters are reduced.
FAST_PROFILE = KeyedProfile(
    sha3_iters=4,
    argon2_passes=2,
    argon2_time_cost=1,
    argon2_memory_kib=8,
    argon2_parallelism=1,
    scrypt_n=2,
    scrypt_r=1,
    scrypt_p=1,
)

SALT_A = bytes(range(16))
SALT_B = bytes(range(16, 32))
PW_A = b"correct horse battery staple"
PW_B = b"Tr0ub4dor&3"


class TestKeylessDerivation(unittest.TestCase):
    """Keyless mode: cheap, deterministic, derived only from the public salt."""

    def test_default_length_is_32_bytes(self):
        key = derive_outer_key(SALT_A)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)

    def test_custom_length_respected(self):
        self.assertEqual(len(derive_outer_key(SALT_A, length=64)), 64)

    def test_deterministic_for_same_salt(self):
        self.assertEqual(derive_outer_key(SALT_A), derive_outer_key(SALT_A))

    def test_different_salt_gives_different_key(self):
        self.assertNotEqual(derive_outer_key(SALT_A), derive_outer_key(SALT_B))

    def test_empty_second_password_is_treated_as_keyless(self):
        # b"" must not be ambiguously "a password"; it means "no second password".
        self.assertEqual(derive_outer_key(SALT_A, second_password=b""), derive_outer_key(SALT_A))


class TestKeyedDerivation(unittest.TestCase):
    """Keyed mode: derived from a second password via the heavy fixed chain."""

    def test_returns_requested_length(self):
        key = derive_outer_key(SALT_A, second_password=PW_A, profile=FAST_PROFILE)
        self.assertEqual(len(key), 32)
        self.assertEqual(
            len(derive_outer_key(SALT_A, second_password=PW_A, length=64, profile=FAST_PROFILE)),
            64,
        )

    def test_deterministic_for_same_salt_and_password(self):
        k1 = derive_outer_key(SALT_A, second_password=PW_A, profile=FAST_PROFILE)
        k2 = derive_outer_key(SALT_A, second_password=PW_A, profile=FAST_PROFILE)
        self.assertEqual(k1, k2)

    def test_different_password_gives_different_key(self):
        k1 = derive_outer_key(SALT_A, second_password=PW_A, profile=FAST_PROFILE)
        k2 = derive_outer_key(SALT_A, second_password=PW_B, profile=FAST_PROFILE)
        self.assertNotEqual(k1, k2)

    def test_different_salt_gives_different_key(self):
        k1 = derive_outer_key(SALT_A, second_password=PW_A, profile=FAST_PROFILE)
        k2 = derive_outer_key(SALT_B, second_password=PW_A, profile=FAST_PROFILE)
        self.assertNotEqual(k1, k2)


class TestDomainSeparation(unittest.TestCase):
    """Keyless and keyed keys must never collide, even for the same salt."""

    def test_keyless_and_keyed_keys_differ_for_same_salt(self):
        keyless = derive_outer_key(SALT_A)
        keyed = derive_outer_key(SALT_A, second_password=PW_A, profile=FAST_PROFILE)
        self.assertNotEqual(keyless, keyed)


class TestInputValidation(unittest.TestCase):
    """Reject malformed inputs rather than silently coercing them."""

    def test_none_salt_rejected(self):
        with self.assertRaises(ValidationError):
            derive_outer_key(None)

    def test_str_salt_rejected(self):
        with self.assertRaises(ValidationError):
            derive_outer_key("not-bytes")

    def test_str_second_password_rejected(self):
        # The caller is responsible for encoding; the core takes bytes only.
        with self.assertRaises(ValidationError):
            derive_outer_key(SALT_A, second_password="str-not-bytes")


class TestProductionProfileSmoke(unittest.TestCase):
    """The real (heavy) profile must run end-to-end and produce a 32-byte key."""

    def test_production_keyed_profile_runs(self):
        key = derive_outer_key(SALT_A, second_password=PW_A, profile=PRODUCTION_KEYED_PROFILE)
        self.assertEqual(len(key), 32)


if __name__ == "__main__":
    unittest.main()
