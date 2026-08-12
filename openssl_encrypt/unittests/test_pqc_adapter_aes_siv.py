#!/usr/bin/env python3
"""
The adapter path must use AES-SIV's two-argument API (gitlab#120), and the
legacy-KDF retry must chain its cause (gitlab#119).

**gitlab#120.** pyca's `AESSIV` has a different API from every other AEAD
here: `encrypt(data, associated_data_list)` and
`decrypt(data, associated_data_list)`, with no separate nonce argument. The
native path in `pqc.py` special-cases it. `pqc_adapter.py` -- the liboqs-KEM
path -- called every cipher the same way, so an aes-siv file reaching it
raised `TypeError` instead of decrypting.

Fail-closed, so no security impact: it surfaced as a decrypt failure rather
than a silent wrong answer. Fixed on both sides, not just decrypt, because
otherwise the adapter could read a format it could not write.

**gitlab#119.** The legacy-KDF retry's failure handler re-raised a static
`ValueError` without `from e`, discarding the only diagnostic there was. No
oracle -- the message a caller sees is unchanged, and the cause appears only
in a traceback.
"""

import unittest


class TestTheAdapterUsesTheAesSivApi(unittest.TestCase):
    """Asserted against pyca's real API rather than a mock.

    A mock would accept whatever call shape the code makes, which is exactly
    the bug: the wrong shape looked fine until a real AESSIV received it.
    """

    def setUp(self):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESSIV
        except ImportError:  # pragma: no cover - dependency always present here
            self.skipTest("AESSIV unavailable")
        self.AESSIV = AESSIV

    def test_the_three_argument_form_really_is_rejected(self):
        """The premise. If pyca ever grew a nonce argument, the special case
        would be unnecessary and this test says so."""
        import os

        cipher = self.AESSIV(os.urandom(64))
        with self.assertRaises(TypeError):
            cipher.encrypt(b"nonce-here12", b"data", None)

    def test_the_two_argument_form_round_trips(self):
        import os

        key = os.urandom(64)
        nonce = os.urandom(12)
        ciphertext = self.AESSIV(key).encrypt(b"payload", [nonce])
        self.assertEqual(self.AESSIV(key).decrypt(ciphertext, [nonce]), b"payload")

    def test_the_adapter_special_cases_it_on_both_sides(self):
        """Structural: the adapter must branch on aes-siv where it builds
        both calls. Behavioural coverage needs a liboqs KEM, which is not
        guaranteed in this environment -- so this pins the shape, and the
        two tests above pin that the shape is the right one.
        """
        import inspect

        from openssl_encrypt.modules import pqc_adapter

        source = inspect.getsource(pqc_adapter)
        self.assertEqual(
            source.count('self.encryption_data == "aes-siv"'),
            4,
            "expected four aes-siv branches: cipher construction and call "
            "shape, on each of encrypt and decrypt",
        )
        self.assertIn("cipher.decrypt(ciphertext, aad_list)", source)
        self.assertIn("cipher.encrypt(data, aad_list)", source)

    def test_the_native_path_still_does_too(self):
        """The adapter was fixed by mirroring pqc.py; if that reference
        changes, they should change together."""
        import inspect

        from openssl_encrypt.modules import pqc

        source = inspect.getsource(pqc)
        self.assertIn("cipher.decrypt(ciphertext, aad_list)", source)
        self.assertIn("cipher.encrypt(data, aad_list)", source)


class TestTheLegacyRetryChainsItsCause(unittest.TestCase):
    def test_the_raise_is_chained(self):
        import inspect

        from openssl_encrypt.modules import pqc

        source = inspect.getsource(pqc)
        self.assertIn(
            "from legacy_error",
            source,
            "the legacy-KDF retry still discards the inner exception, which "
            "is the only diagnostic for a double failure",
        )

    def test_the_user_facing_message_is_unchanged(self):
        """Chaining must not become an oracle: the text a caller sees says
        nothing about which attempt failed or why."""
        import inspect

        from openssl_encrypt.modules import pqc

        source = inspect.getsource(pqc)
        self.assertIn(
            "PQC decryption failed with both the HKDF (v12+) and the ",
            source,
        )


if __name__ == "__main__":
    unittest.main()
