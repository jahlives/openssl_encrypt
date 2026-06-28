#!/usr/bin/env python3
"""
format_version 13 — Sequential XOR cancellation fix.

Sequential XOR (v8/v10) appended the chain's final value (`sequential_result`) to
the XOR accumulator *in addition to* the last stage's own snapshot — and those two
are the same value, so they XOR to zero and the **last stage cancels out of the
key**. For a single memory-hard KDF (e.g. Argon2 only), this bypasses the KDF
entirely: the key reduces to the cheap SHA256(pw+salt).

v13 (xor_mode="sequential") drops the redundant append, so every stage contributes
and the last stage's cost is paid. v8/v10 keep their (buggy) derivation so existing
files still decrypt (append-only).

The v13-sequential derivation must be byte-identical across the 1.4.x and 1.5.x
lines (golden vector below).
"""

import os
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import (
    decrypt_file,
    encrypt_file,
    extract_file_metadata,
    generate_key,
)

PASSWORD = "v13-sequential-xor-test-password"
SALT = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")  # fixed 16-byte salt

# Single memory-hard KDF — the worst case for the cancellation bug.
ARGON2_CHEAP = {
    "argon2": {"enabled": True, "time_cost": 1, "memory_cost": 512, "parallelism": 1, "type": "id"}
}
ARGON2_COSTLY = {
    "argon2": {"enabled": True, "time_cost": 5, "memory_cost": 8192, "parallelism": 1, "type": "id"}
}

# Cross-line golden vector: generate_key(format_version=13) sequential XOR with
# ARGON2_CHEAP, algorithm aes-gcm. Pinned after implementation; identical on both lines.
GOLDEN_KEY_HEX = "1a969679dc31bf8552a661345a050198c099bb88decfe57d0dbd3537150fdff3"


def _seq_key(cfg, fv):
    # Keyword args: generate_key's positional signature differs across the 1.4.x /
    # 1.5.x lines (1.4.x has an extra pbkdf2_iterations param), so pin by keyword.
    key, _, _ = generate_key(
        PASSWORD.encode(), SALT, cfg, quiet=True, algorithm="aes-gcm", format_version=fv
    )
    return bytes(key)


class TestV13SequentialDerivation(unittest.TestCase):
    def test_v13_sequential_depends_on_last_stage_cost(self):
        """THE FIX: at v13 the (last, only) Argon2 stage must affect the key."""
        self.assertNotEqual(
            _seq_key(ARGON2_CHEAP, 13),
            _seq_key(ARGON2_COSTLY, 13),
            "v13 sequential XOR must depend on Argon2 cost (last stage no longer cancels)",
        )

    def test_v10_still_cancels_last_stage(self):
        """Decrypt-compat guard: v8/v10 derivation is frozen (incl. the bug)."""
        # The bug means the key is independent of Argon2 cost at v10.
        self.assertEqual(
            _seq_key(ARGON2_CHEAP, 10),
            _seq_key(ARGON2_COSTLY, 10),
            "v10 derivation must be preserved unchanged so existing files still decrypt",
        )

    def test_v13_sequential_differs_from_v10(self):
        """v13 changes the derived key vs v10 for the same inputs (gated change)."""
        self.assertNotEqual(_seq_key(ARGON2_CHEAP, 13), _seq_key(ARGON2_CHEAP, 10))

    def test_v13_sequential_deterministic(self):
        self.assertEqual(_seq_key(ARGON2_CHEAP, 13), _seq_key(ARGON2_CHEAP, 13))

    def test_v13_sequential_golden_vector_cross_line(self):
        self.assertEqual(_seq_key(ARGON2_CHEAP, 13).hex(), GOLDEN_KEY_HEX)


class TestV13SequentialRoundTrip(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.plain = os.path.join(self.dir, "p.txt")
        with open(self.plain, "wb") as f:
            f.write(b"v13 sequential round-trip payload " * 64)

    def tearDown(self):
        for name in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def test_v13_sequential_roundtrip_and_metadata(self):
        enc = os.path.join(self.dir, "c.enc")
        dec = os.path.join(self.dir, "d.txt")
        encrypt_file(
            self.plain,
            enc,
            PASSWORD,
            hash_config=ARGON2_CHEAP,
            algorithm="aes-gcm",
            quiet=True,
            format_version=13,
            xor_mode="sequential",
        )
        md = extract_file_metadata(enc)
        self.assertEqual(md["format_version"], 13)
        self.assertEqual(md.get("xor_mode"), "sequential")
        decrypt_file(enc, dec, PASSWORD, quiet=True)
        with open(self.plain, "rb") as a, open(dec, "rb") as b:
            self.assertEqual(a.read(), b.read())


if __name__ == "__main__":
    unittest.main()
