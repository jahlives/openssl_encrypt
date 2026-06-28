#!/usr/bin/env python3
"""
format_version 13 — Independent XOR with per-component domain-separated salts.

v13 derives a **distinct** HKDF-SHA256 salt per XOR component (each enabled
hash/KDF stage) instead of feeding the same `salt_0` to all components (v11/v12).
This retires the XOR-cancellation footgun while keeping the robust-combiner
(strongest-link) design. The initial-hash component and the shared input
`SHA256(pw || salt_0)` are intentionally **unchanged** (they cannot duplicate).

The derivation MUST be byte-identical across the 1.4.x and 1.5.x lines — the
golden-vector test pins the v13 key for fixed inputs and must match on both
branches.
"""

import os
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from openssl_encrypt.modules.crypt_core import (
    decrypt_file,
    encrypt_file,
    extract_file_metadata,
    generate_key_independent_xor,
)

PASSWORD = "v13-domsep-test-password"
PASSWORD_BYTES = PASSWORD.encode("utf-8")
SALT = bytes.fromhex("000102030405060708090a0b0c0d0e0f")  # fixed 16-byte salt

# Minimal deterministic config: one hash stage + one KDF (both always available).
CONFIG = {
    "sha256": 2,
    "argon2": {
        "enabled": True,
        "time_cost": 1,
        "memory_cost": 512,
        "parallelism": 1,
        "type": "id",
    },
}

# Cross-line golden vector for CONFIG above (algorithm aes-256-gcm, format_version 13).
# Pinned after implementation; MUST be identical on feature/v1.4.x and v1.5.x.
GOLDEN_KEY_HEX = "e1b618deb5c474087222bab83bb08ec7cacd8d3685b8438af488899dfd515f72"


def _ref_component_salt(salt0: bytes, name: str, fv: int) -> bytes:
    """Independent reimplementation of the v13 per-component salt (spec check)."""
    if fv is None or fv < 13:
        return salt0
    return HKDF(
        algorithm=crypto_hashes.SHA256(),
        length=len(salt0),
        salt=None,
        info=b"openssl_encrypt.indep-xor.v13.salt:" + name.encode("ascii"),
    ).derive(salt0)


class TestV13ComponentSalt(unittest.TestCase):
    def test_helper_matches_spec_and_is_distinct(self):
        from openssl_encrypt.modules.crypt_core import _indep_xor_component_salt

        s_arg = _indep_xor_component_salt(SALT, "argon2", 13)
        s_sha = _indep_xor_component_salt(SALT, "sha256", 13)
        self.assertEqual(s_arg, _ref_component_salt(SALT, "argon2", 13))
        self.assertEqual(len(s_arg), len(SALT))
        self.assertNotEqual(s_arg, SALT)  # distinct from the base salt
        self.assertNotEqual(s_arg, s_sha)  # distinct per component -> no cancellation

    def test_helper_is_noop_below_v13(self):
        from openssl_encrypt.modules.crypt_core import _indep_xor_component_salt

        for fv in (9, 11, 12):
            self.assertEqual(_indep_xor_component_salt(SALT, "argon2", fv), SALT)


class TestV13Derivation(unittest.TestCase):
    def test_v13_key_differs_from_v11(self):
        k11, _, _ = generate_key_independent_xor(
            PASSWORD_BYTES, SALT, CONFIG, quiet=True, format_version=11
        )
        k13, _, _ = generate_key_independent_xor(
            PASSWORD_BYTES, SALT, CONFIG, quiet=True, format_version=13
        )
        self.assertNotEqual(bytes(k11), bytes(k13))

    def test_v13_is_deterministic(self):
        a, _, _ = generate_key_independent_xor(
            PASSWORD_BYTES, SALT, CONFIG, quiet=True, format_version=13
        )
        b, _, _ = generate_key_independent_xor(
            PASSWORD_BYTES, SALT, CONFIG, quiet=True, format_version=13
        )
        self.assertEqual(bytes(a), bytes(b))

    def test_v13_golden_vector_cross_line(self):
        key, _, _ = generate_key_independent_xor(
            PASSWORD_BYTES,
            SALT,
            CONFIG,
            quiet=True,
            algorithm="aes-256-gcm",
            format_version=13,
        )
        self.assertEqual(bytes(key).hex(), GOLDEN_KEY_HEX)


class TestV13RoundTrip(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.plain = os.path.join(self.dir, "p.txt")
        with open(self.plain, "wb") as f:
            f.write(b"v13 round-trip payload " * 64)

    def tearDown(self):
        for name in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def _roundtrip(self, **enc_kwargs):
        enc = os.path.join(self.dir, "c.enc")
        dec = os.path.join(self.dir, "d.txt")
        encrypt_file(
            self.plain,
            enc,
            PASSWORD,
            hash_config=CONFIG,
            quiet=True,
            format_version=13,
            **enc_kwargs,
        )
        md = extract_file_metadata(enc)
        self.assertEqual(md["format_version"], 13)
        decrypt_file(enc, dec, PASSWORD, quiet=True)
        with open(self.plain, "rb") as a, open(dec, "rb") as b:
            self.assertEqual(a.read(), b.read())

    def test_v13_roundtrip_single_cipher(self):
        self._roundtrip(algorithm="aes-gcm")

    def test_v13_roundtrip_cascade(self):
        # v13 >= 12, so this also exercises the v12 cascade hardening
        # (per-layer salts + AAD-on-every-layer) together with the v13 KDF.
        self._roundtrip(
            algorithm="cascade",
            cascade=True,
            cipher_names=["aes-gcm", "xchacha20-poly1305"],
        )


if __name__ == "__main__":
    unittest.main()
