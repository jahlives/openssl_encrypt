#!/usr/bin/env python3
"""Regression tests for gitlab#129 (identity-file KDF-cost DoS).

An identity file's password-protection block carries Argon2 cost parameters
read straight from JSON (PasswordProtectionConfig.from_dict). _derive_key feeds
memory_cost/time_cost/parallelism to argon2 hash_secret_raw BEFORE the AEAD tag
authenticates the private key, so a tampered/attacker-authored identity with a
huge memory_cost OOM-crashes the host on unlock, pre-authentication (CWE-400,
same class as gitlab#128 on the identity-file surface).

Fix: clamp the Argon2 cost parameters against sane maxima before deriving.
Legitimate identities use the 64 MB default, far under the cap, so no
backward-compat impact.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from openssl_encrypt.modules.crypt_errors import ValidationError
from openssl_encrypt.modules.identity_protection import (
    IdentityKeyProtectionService,
    PasswordProtectionConfig,
)

SALT = b"\x00" * 16
HUGE_MEMORY_KB = 8 * 1024 * 1024  # 8 GiB in KiB — far over any legitimate identity
DEFAULT_MEMORY_KB = 65536  # 64 MB, the identity default


class TestIdentityKdfCeiling(unittest.TestCase):
    def _cfg(self, memory_cost=DEFAULT_MEMORY_KB, time_cost=3, parallelism=4):
        return PasswordProtectionConfig(
            memory_cost=memory_cost, time_cost=time_cost, parallelism=parallelism, salt=SALT
        )

    def test_huge_memory_cost_refused_before_derivation(self):
        ip = IdentityKeyProtectionService()
        with self.assertRaises(ValidationError):
            ip._derive_key(
                password="pw12345678", hsm_pepper=None, password_config=self._cfg(HUGE_MEMORY_KB)
            )

    def test_huge_time_cost_refused(self):
        ip = IdentityKeyProtectionService()
        with self.assertRaises(ValidationError):
            ip._derive_key(
                password="pw12345678", hsm_pepper=None, password_config=self._cfg(time_cost=10**6)
            )

    def test_default_config_still_derives(self):
        """Compat: the 64 MB identity default must derive a 32-byte key."""
        ip = IdentityKeyProtectionService()
        key = ip._derive_key(password="pw12345678", hsm_pepper=None, password_config=self._cfg())
        self.assertEqual(len(key), 32)


if __name__ == "__main__":
    unittest.main()
