#!/usr/bin/env python3
"""
format_version 14 — length-prefixed (TLV) KDF seed for the independent-XOR
path (finding #100, v14 implementation plan Phase 2).

Below v14 the independent-XOR path seeds every component from
`sha256(password || pepper || salt)` (pepper mixed by raw concatenation), so
different (password, pepper, salt) splits of the same byte string collide.
v14 seeds from `sha256(LP(password) || LP(salt) || LP(pepper))` with
`LP(x) = uint32_be(len(x)) || x` and an always-present pepper field
(absent -> LP(b"") = 00 00 00 00), making field boundaries unambiguous.

The derivation MUST be byte-identical across the 1.4.x and 1.5.x lines — the
golden-vector test pins the v14 key for fixed inputs and must match on both
branches. DO NOT CHANGE the pinned values.
"""

import hashlib
import unittest

from openssl_encrypt.modules.crypt_core import _v14_seed_encode, generate_key_independent_xor

PASSWORD = "v14-lengthsep-test-password"
PASSWORD_BYTES = PASSWORD.encode("utf-8")
SALT = bytes.fromhex("000102030405060708090a0b0c0d0e0f")  # fixed 16-byte salt
PEPPER = bytes.fromhex("f0e0d0c0b0a090807060504030201000")

# Minimal deterministic config (same shape as the v13 golden suite).
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

# Cross-line golden vectors for CONFIG above (algorithm aes-256-gcm).
# Pinned after implementation; MUST be identical on feature/v1.4.x and v1.5.x.
GOLDEN_V14_KEY_HEX = "ff5612696ea5a3859c79cf9d57fb05bb441584b0bbd8078822f0cddd94cd6fcf"
GOLDEN_V14_PEPPER_KEY_HEX = "b17055e6a5a8d1ffa9f2585fa53314512370a48c421d4df338bf41a0016c83f3"


def _ref_v14_seed(password: bytes, salt: bytes, pepper: bytes = None) -> bytes:
    """Independent reimplementation of the v14 TLV seed (spec cross-check)."""

    def lp(x):
        x = bytes(x) if x else b""
        return len(x).to_bytes(4, "big") + x

    return lp(password) + lp(salt) + lp(pepper)


class TestV14SeedEncode(unittest.TestCase):
    def test_layout_matches_spec(self):
        self.assertEqual(
            _v14_seed_encode(b"pw", b"salt", b"pep"),
            _ref_v14_seed(b"pw", b"salt", b"pep"),
        )
        self.assertEqual(
            _v14_seed_encode(b"pw", b"salt", b"pep"),
            b"\x00\x00\x00\x02pw" + b"\x00\x00\x00\x04salt" + b"\x00\x00\x00\x03pep",
        )

    def test_absent_pepper_emits_empty_field(self):
        self.assertEqual(
            _v14_seed_encode(b"pw", b"salt", None),
            b"\x00\x00\x00\x02pw" + b"\x00\x00\x00\x04salt" + b"\x00\x00\x00\x00",
        )
        self.assertEqual(
            _v14_seed_encode(b"pw", b"salt", None),
            _v14_seed_encode(b"pw", b"salt", b""),
        )

    def test_seed_encoder_returns_wipeable_type(self):
        # The seed contains the cleartext password and pepper: it must be a
        # mutable buffer so the caller can secure_memzero it after hashing
        # (M2 [MEM-1] standard) — never an immutable bytes object.
        self.assertIsInstance(_v14_seed_encode(b"pw", b"salt", b"pep"), bytearray)

    def test_boundary_shifts_are_distinct(self):
        # Same concatenated bytes, different field splits -> different seeds.
        self.assertNotEqual(
            _v14_seed_encode(b"AB", b"CD", None),
            _v14_seed_encode(b"ABC", b"D", None),
        )
        self.assertNotEqual(
            _v14_seed_encode(b"ABC", b"CD", b"D"),
            _v14_seed_encode(b"AB", b"CD", b"CD"),
        )


class TestV14SeedEncodeSingleAllocation(unittest.TestCase):
    """Identity pins for the single-allocation encoder (review LOW-1, gitlab#110).

    The LOW-1 fix replaces incremental ``bytearray +=`` growth (whose
    reallocations leak unwiped partial secret copies into freed heap) with one
    exact-size allocation filled in place. The encoding itself is PINNED —
    these tests assert byte-identity against the reference implementation for
    every input type and size class the encoder accepts, so the hygiene fix
    cannot drift the on-disk format.
    """

    # (password, salt, pepper) matrix: empty/None fields, 1-byte fields,
    # length-prefix byte patterns, multi-KiB fields.
    MATRIX = [
        (b"", b"", None),
        (b"", b"", b""),
        (b"p", b"s", b"x"),
        (b"pw", b"salt", None),
        (b"pw", b"salt", b"pep"),
        (b"\x00" * 4, b"\x00" * 4, b"\x00" * 4),
        (b"A" * 255, b"B" * 256, b"C" * 257),
        (b"P" * 4096, b"S" * 8192, b"X" * 3000),
        (PASSWORD_BYTES, SALT, PEPPER),
    ]

    def test_byte_identity_matrix(self):
        for pw, salt, pep in self.MATRIX:
            with self.subTest(pw_len=len(pw), salt_len=len(salt), pep=pep is not None):
                self.assertEqual(
                    bytes(_v14_seed_encode(pw, salt, pep)),
                    _ref_v14_seed(pw, salt, pep),
                )

    def test_mutable_inputs_identical_to_bytes(self):
        # Callers holding secrets in wipeable buffers (bytearray/memoryview)
        # must get the same encoding WITHOUT the encoder materializing
        # immutable copies (the old ``bytes(field)`` defeated such callers).
        pw, salt, pep = b"secret-pw", SALT, PEPPER
        expected = _ref_v14_seed(pw, salt, pep)
        for wrap in (bytearray, memoryview, lambda x: memoryview(bytearray(x))):
            with self.subTest(wrap=wrap):
                self.assertEqual(
                    bytes(_v14_seed_encode(wrap(pw), wrap(salt), wrap(pep))),
                    expected,
                )

    def test_mutable_empty_fields_alias_none(self):
        self.assertEqual(
            bytes(_v14_seed_encode(bytearray(b"pw"), bytearray(b"salt"), bytearray())),
            _ref_v14_seed(b"pw", b"salt", None),
        )

    def test_exact_size_no_spare_capacity(self):
        for pw, salt, pep in self.MATRIX:
            with self.subTest(pw_len=len(pw), salt_len=len(salt), pep=pep is not None):
                seed = _v14_seed_encode(pw, salt, pep)
                self.assertEqual(len(seed), 12 + len(pw) + len(salt) + len(pep or b""))


class TestV14DerivationSeparation(unittest.TestCase):
    def _derive(self, fv, password=PASSWORD_BYTES, salt=SALT, pepper=None):
        key, _, _ = generate_key_independent_xor(
            password,
            salt,
            CONFIG,
            quiet=True,
            algorithm="aes-256-gcm",
            hsm_pepper=pepper,
            format_version=fv,
        )
        return bytes(key)

    def test_v14_key_differs_from_v13(self):
        self.assertNotEqual(self._derive(13), self._derive(14))

    def test_v14_is_deterministic(self):
        self.assertEqual(self._derive(14), self._derive(14))
        self.assertEqual(self._derive(14, pepper=PEPPER), self._derive(14, pepper=PEPPER))

    def test_v13_pepper_boundary_ambiguity_exists_and_v14_fixes_it(self):
        # The regression this change exists for: below v14 the pepper is mixed
        # by raw concatenation, so shifting bytes between password and pepper
        # yields the SAME key; under v14 the TLV seed separates them.
        pw_a, pep_a = b"secretXY", b"Zpepper"
        pw_b, pep_b = b"secretX", b"YZpepper"
        self.assertEqual(pw_a + pep_a, pw_b + pep_b)
        self.assertEqual(
            self._derive(13, password=pw_a, pepper=pep_a),
            self._derive(13, password=pw_b, pepper=pep_b),
        )
        self.assertNotEqual(
            self._derive(14, password=pw_a, pepper=pep_a),
            self._derive(14, password=pw_b, pepper=pep_b),
        )

    def test_v14_password_salt_boundary_distinct(self):
        self.assertNotEqual(
            self._derive(14, password=b"AB", salt=b"CD" + SALT),
            self._derive(14, password=b"ABC", salt=b"D" + SALT),
        )

    def test_pepper_still_contributes_at_v14(self):
        self.assertNotEqual(self._derive(14), self._derive(14, pepper=PEPPER))

    def test_v14_golden_vector_cross_line(self):
        self.assertEqual(self._derive(14).hex(), GOLDEN_V14_KEY_HEX)

    def test_v14_pepper_golden_vector_cross_line(self):
        self.assertEqual(self._derive(14, pepper=PEPPER).hex(), GOLDEN_V14_PEPPER_KEY_HEX)

    def test_below_v14_unchanged_reference(self):
        # The < 14 seed must stay byte-identical: reproduce it independently
        # (sha256(password||pepper||salt) feeds the initial component) by
        # checking v13 derivation is invariant under the equivalent-concat
        # transformation, which is only true for the legacy seed.
        self.assertEqual(
            self._derive(13, password=b"pwXpep", pepper=None),
            self._derive(13, password=b"pwX", pepper=b"pep"),
        )


if __name__ == "__main__":
    unittest.main()
