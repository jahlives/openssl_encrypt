"""Regression test for RandomX fail-closed in the independent-XOR KDF (#71 / CORE-6).

In generate_key_independent_xor, an ImportError/OSError from the RandomX KDF was
swallowed and its component dropped, while every other KDF in that path aborts on
failure. Since the initial sha256(password+salt) is always the first component,
a RandomX-only configuration whose RandomX component is dropped collapses the
derived key to a single un-stretched sha256(password+salt) -- and the empty-set
guard (len == 0) does not catch it. Deterministic on hosts lacking RandomX (e.g.
musl), so such a weak file round-trips silently.

The fix makes an explicitly-enabled-but-unavailable RandomX abort key derivation
instead of silently producing a weaker key.
"""

import unittest
from unittest import mock

from openssl_encrypt.modules import crypt_core
from openssl_encrypt.modules.crypt_core import generate_key_independent_xor
from openssl_encrypt.modules.crypt_errors import ValidationError


class TestRandomXFailClosed(unittest.TestCase):
    def test_enabled_but_unavailable_randomx_aborts(self):
        # Only RandomX enabled: no hash rounds, no other KDF. If RandomX is
        # dropped, the key would collapse to sha256(password+salt).
        hash_config = {"randomx": {"enabled": True, "iterations": 1}}

        def fake_kdf(*args, **kwargs):
            if kwargs.get("kdf_type") == "randomx":
                raise OSError("RandomX library not available")
            raise AssertionError(f"unexpected KDF call: {kwargs.get('kdf_type')}")

        with mock.patch.object(crypt_core, "compute_kdf_independent", side_effect=fake_kdf):
            with self.assertRaises(ValidationError):
                generate_key_independent_xor(
                    password=b"correct horse",
                    salt=b"0123456789abcdef",
                    hash_config=hash_config,
                    quiet=True,
                )


if __name__ == "__main__":
    unittest.main()
