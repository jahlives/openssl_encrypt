"""Regression tests for zeroizing cached PQC private keys (#87 / PQC-7).

PQCKeystore cached decrypted private keys as immutable ``bytes`` in
``unlocked_keys`` for up to ``cache_timeout`` and never zeroed them on eviction
(``_clear_cached_keys`` just dropped the dict), so a private key lingered in the
heap in plaintext, defeating the module's own secure_memzero discipline.

The cached private key is now held in a wipeable ``bytearray`` and zeroized when
the entry is evicted or the cache is cleared.
"""

import time
import unittest

from openssl_encrypt.modules.pqc_keystore import PQCKeystore


class TestPqcKeystoreCacheZeroize(unittest.TestCase):
    def test_clear_cache_zeroizes_cached_private_key(self):
        ks = PQCKeystore()
        secret = bytearray(b"SUPER_SECRET_PQC_PRIVATE_KEY_123456")
        ks.unlocked_keys["k1"] = ((b"public", secret), time.time())
        self.assertTrue(any(secret), "precondition: cached key is non-zero")

        ks.clear_cache()

        self.assertFalse(any(secret), "cached private key must be zeroized on clear_cache")

    def test_evict_zeroizes_and_removes(self):
        ks = PQCKeystore()
        secret = bytearray(b"ANOTHER_SECRET_PRIVATE_KEY_ABCDEF")
        ks.unlocked_keys["k2"] = ((b"public", secret), time.time())

        ks._evict_cached_key("k2")

        self.assertNotIn("k2", ks.unlocked_keys)
        self.assertFalse(any(secret), "evicted private key must be zeroized")


if __name__ == "__main__":
    unittest.main()
