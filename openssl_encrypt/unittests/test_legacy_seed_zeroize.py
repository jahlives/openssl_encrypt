#!/usr/bin/env python3
"""
Regression tests for gitlab#124 (security review 2026-07-13, INFO-1).

On the legacy no-hash-iterations branch, generate_key built the KDF seed as
``password = password + salt + hsm_pepper`` - a fresh immutable bytes object
that secure_memzero cannot wipe (M10). The fix builds the seed in a wipeable
bytearray and zeroizes it after key derivation.

Hard constraint guarded here with golden values captured from the pre-fix
code: derived keys must remain byte-identical.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from openssl_encrypt.modules import secure_memory
from openssl_encrypt.modules.crypt_core import generate_key

FIXED_SALT = bytes.fromhex("aa" * 16)
PEPPER = b"\xab" * 20
PASSWORD = b"golden-pw"

NO_KDF_CFG = {
    "sha512": 0,
    "sha256": 0,
    "sha3_256": 0,
    "sha3_512": 0,
    "blake2b": 0,
    "shake256": 0,
    "whirlpool": 0,
    "scrypt": {"enabled": False},
    "argon2": {"enabled": False},
    "balloon": {"enabled": False},
    "pbkdf2_iterations": 0,
}

ARGON2_CFG = dict(
    NO_KDF_CFG,
    argon2={
        "enabled": True,
        "rounds": 1,
        "time_cost": 1,
        "memory_cost": 8,
        "parallelism": 1,
        "hash_len": 32,
        "type": "id",
    },
)

# Captured from the pre-fix implementation on 2026-07-13 (see gitlab#124).
GOLDEN_NO_KDF = "540c75931e308044a8eb935793ec555d7aa9085b46059247e253b54dabe48c42"
GOLDEN_ARGON2 = "6cbfca79c73a3eb6ebbf5be170d8f0e15e2fd70e565ebb44f4420eb4336c7ea0"


class _WipeRecorder:
    """Wrap the real secure_memzero, snapshotting buffers it successfully wipes.

    Snapshots are taken at call time but recorded only when the real call
    returns True: secure_memzero refuses immutable input (M10), and a refused
    wipe must not satisfy these tests.
    """

    def __init__(self):
        self.real = secure_memory.secure_memzero
        self.wiped = []

    def __call__(self, data, *args, **kwargs):
        snapshot = bytes(data) if isinstance(data, (bytes, bytearray, memoryview)) else None
        result = self.real(data, *args, **kwargs)
        if result and snapshot is not None:
            self.wiped.append(snapshot)
        return result


def _derive(cfg):
    """Run generate_key with KeyStretch pinned to its fresh-process defaults.

    KeyStretch is sticky module-global state; other tests in the same pytest
    process leave it set, which changes the final key-length normalization in
    generate_key. Pin it so the goldens are order-independent.
    """
    from openssl_encrypt.modules.crypt_core import KeyStretch

    old = (KeyStretch.key_stretch, KeyStretch.hash_stretch)
    KeyStretch.key_stretch, KeyStretch.hash_stretch = False, False
    try:
        key, _, _ = generate_key(
            PASSWORD,
            FIXED_SALT,
            dict(cfg),
            quiet=True,
            algorithm="aes-gcm",
            hsm_pepper=PEPPER,
            format_version=9,
        )
    finally:
        KeyStretch.key_stretch, KeyStretch.hash_stretch = old
    return key


class TestLegacySeedGolden(unittest.TestCase):
    """Derived keys must be byte-identical before and after the fix."""

    def test_no_kdf_golden(self):
        self.assertEqual(_derive(NO_KDF_CFG).hex(), GOLDEN_NO_KDF)

    def test_argon2_golden(self):
        try:
            import argon2  # noqa: F401
        except ImportError:
            self.skipTest("argon2-cffi not installed")
        self.assertEqual(_derive(ARGON2_CFG).hex(), GOLDEN_ARGON2)


class TestLegacySeedZeroize(unittest.TestCase):
    """The password+salt+pepper seed must be built wipeable and wiped."""

    EXPECTED_SEED = PASSWORD + FIXED_SALT + PEPPER

    def _wiped_buffers(self, cfg):
        recorder = _WipeRecorder()
        with mock.patch.object(secure_memory, "secure_memzero", recorder):
            _derive(cfg)
        return recorder.wiped

    def test_seed_wiped_no_kdf(self):
        """No-KDF branch: the concatenated seed is passed to secure_memzero."""
        self.assertIn(
            self.EXPECTED_SEED,
            self._wiped_buffers(NO_KDF_CFG),
            "password+salt+pepper seed was never passed to secure_memzero",
        )

    def test_seed_wiped_with_kdf(self):
        """KDF branch: the seed is wiped even when a KDF consumes it."""
        try:
            import argon2  # noqa: F401
        except ImportError:
            self.skipTest("argon2-cffi not installed")
        self.assertIn(
            self.EXPECTED_SEED,
            self._wiped_buffers(ARGON2_CFG),
            "password+salt+pepper seed was never passed to secure_memzero",
        )


if __name__ == "__main__":
    unittest.main()
