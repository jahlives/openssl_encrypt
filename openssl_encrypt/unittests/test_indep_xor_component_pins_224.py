#!/usr/bin/env python3
"""Golden pins for the Independent-XOR component construction (gitlab#224 item 7).

The per-component salt is derived FROM the component's name string
(``_indep_xor_component_salt`` feeds ``info=b"openssl_encrypt.indep-xor.v13.salt:"
+ name``), and every construction site moved during the #220/#224 refactors. A
single typo in a name silently changes that component's derived key and makes
existing files undecryptable — and the parallel==sequential equivalence tests
cannot catch it, because both modes share the (possibly drifted) construction.

Pinned here:
- the exact ordered list of component-salt names for a config enabling every
  component (previously only sha256/argon2/scrypt were covered by goldens);
- golden keys for a one-of-each config on v13 and v14. They were computed
  from the #220/#224 implementation at a state where every pre-existing
  golden (sha256/argon2 domsep, scrypt default-flip, fixture corpus) still
  passed — i.e. the construction demonstrably matched the pre-refactor
  derivation for all previously-covered components — and they extend that
  pinning to the components that had no golden. Any later drift in labels,
  salts, seed encoding, normalization or XOR breaks loudly. These goldens are
  the cross-line pair: they must equal the whirlpool-free goldens in the
  1.4.x counterpart test (whirlpool itself does not exist on this line).
"""

import unittest
from unittest import mock

import openssl_encrypt.modules.crypt_core as cc
from openssl_encrypt.modules.crypt_core import generate_key_independent_xor

PASSWORD = b"golden-pin-224"
SALT = bytes(range(32))

# Derivation-critical: the domain-separation names, in submission order.
EXPECTED_SALT_NAMES = [
    "sha256",
    "sha512",
    "sha3_256",
    "sha3_512",
    "blake2b",
    "blake3",
    "shake256",
    "argon2",
    "scrypt",
    "balloon",
    "hkdf",
    "randomx",
]

GOLDEN = {
    # format_version: expected aes-256-gcm key hex. Cross-line pinned: these
    # MUST equal the (whirlpool-free) goldens in the 1.4.x counterpart test.
    13: "9e655e48076b78753de23b7e162bc2b697333bd7a6adf5194c89c2e1313db5e8",
    14: "58f2d50c577904dafaec5a0532ee58001a249bb9d33bbcd2612991d03cdcacfa",
}


def _config(randomx=False):
    cfg = {
        "sha256": 5,
        "sha512": 5,
        "sha3_256": 5,
        "sha3_512": 5,
        "blake2b": 5,
        "blake3": 5,
        "shake256": 5,
        "argon2": {
            "enabled": True,
            "time_cost": 1,
            "memory_cost": 512,
            "parallelism": 1,
            "rounds": 1,
            "type": "id",
        },
        "scrypt": {"enabled": True, "n": 1024, "r": 8, "p": 1},
        "balloon": {"enabled": True, "space_cost": 32, "time_cost": 2, "delta": 3},
        "hkdf": {"enabled": True},
    }
    if randomx:
        cfg["randomx"] = {"enabled": True, "rounds": 1}
    return cfg


class TestComponentSaltNames(unittest.TestCase):
    """Pin the exact ordered domain-separation names for every component."""

    def test_all_component_salt_names_in_order(self):
        from openssl_encrypt.modules.secure_memory import SecureBytes

        seen = []
        real = cc._indep_xor_component_salt

        def spy(base_salt, name, fmt):
            seen.append(name)
            return real(base_salt, name, fmt)

        fake = lambda **k: SecureBytes(b"\x01" * k["key_length"])  # noqa: E731
        with mock.patch.object(cc, "_indep_xor_component_salt", spy):
            with mock.patch.object(cc, "compute_hash_independent", fake):
                with mock.patch.object(cc, "compute_kdf_independent", fake):
                    generate_key_independent_xor(
                        PASSWORD,
                        SALT,
                        _config(randomx=True),
                        quiet=True,
                        format_version=14,
                    )
        self.assertEqual(seen, EXPECTED_SALT_NAMES)


class TestGoldenKeys(unittest.TestCase):
    """One-of-each-component golden keys, both modes, v13 and v14."""

    def _derive(self, fmt, parallel):
        return bytes(
            generate_key_independent_xor(
                PASSWORD,
                SALT,
                _config(),
                quiet=True,
                algorithm="aes-256-gcm",
                format_version=fmt,
                parallel=parallel,
            )[0]
        ).hex()

    def test_golden_v13_sequential(self):
        self.assertEqual(self._derive(13, False), GOLDEN[13])

    def test_golden_v14_sequential(self):
        self.assertEqual(self._derive(14, False), GOLDEN[14])

    def test_golden_v13_parallel(self):
        self.assertEqual(self._derive(13, True), GOLDEN[13])

    def test_golden_v14_parallel(self):
        self.assertEqual(self._derive(14, True), GOLDEN[14])


if __name__ == "__main__":
    unittest.main()
