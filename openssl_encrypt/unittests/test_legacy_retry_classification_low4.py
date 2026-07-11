#!/usr/bin/env python3
"""Regression tests for gitlab#116 (fable-review LOW-4): legacy-retry classification.

1.4.x port. The v12/v13 legacy-KDF retry machinery had classification
gaps (all fail-closed, none attacker-usable — compatibility vs stated
intent). On this line two of the three 1.5.x findings apply:

1. The adapter retry caught only ``cryptography.exceptions.InvalidTag``,
   but the custom ``XChaCha20Poly1305.decrypt`` converts that into the
   project's ``AuthenticationError`` — adapter-path xchacha legacy files
   skipped the retry.
2. The native classifier was over-broad (``except Exception``),
   converting structural errors (e.g. "Ciphertext too short") into
   "authentication failure" and triggering a pointless retry,
   contradicting the ``decrypt()`` docstring.

(The 1.5.x finding about native Threefish classification does not apply:
Threefish is not a PQC data cipher on the 1.4.x line.)

Classification must be structural (typed exceptions), never
string-matching (M4 precedent).
"""

import unittest

from openssl_encrypt.modules.crypt_errors import ValidationError
from openssl_encrypt.modules.pqc import LIBOQS_AVAILABLE, PQCipher

PAYLOAD = b"legacy retry classification probe"


@unittest.skipUnless(LIBOQS_AVAILABLE, "liboqs not available")
class TestNativeClassifierIsStructural(unittest.TestCase):
    """Structural (non-auth) errors must not be classified as auth failures."""

    def test_truncated_xchacha_payload_raises_validation_error(self):
        cipher = PQCipher(
            "ML-KEM-768", quiet=True, encryption_data="xchacha20-poly1305", format_version=13
        )
        public_key, private_key = cipher.generate_keypair()
        encrypted = cipher.encrypt(PAYLOAD, public_key)
        # Leave fewer than 16 ciphertext bytes after the nonce: the XChaCha
        # input check raises ValidationError ("Ciphertext too short"), a
        # structural error that must propagate — not become an
        # "authentication failure" that triggers a pointless legacy retry.
        ct_len = len(PAYLOAD) + 16
        truncated = encrypted[: len(encrypted) - ct_len + 10]
        with self.assertRaises(ValidationError):
            cipher.decrypt(truncated, private_key)


@unittest.skipUnless(LIBOQS_AVAILABLE, "liboqs not available")
class TestAdapterXChaChaLegacyRetry(unittest.TestCase):
    """Adapter-path xchacha legacy files must reach the retry (AuthenticationError)."""

    def setUp(self):
        from openssl_encrypt.modules.pqc import check_pqc_support

        supported = check_pqc_support(quiet=True)[2]
        self.hqc = next((a for a in ("HQC-128", "HQC-192", "HQC-256") if a in supported), None)
        if self.hqc is None:
            self.skipTest("no HQC algorithm available for the liboqs adapter branch")

    def test_legacy_xchacha_file_decrypts_on_v13_reader(self):
        from openssl_encrypt.modules.pqc_adapter import ExtendedPQCipher

        writer = ExtendedPQCipher(self.hqc, quiet=True, encryption_data="xchacha20-poly1305")
        public_key, private_key = writer.generate_keypair()
        encrypted = writer.encrypt(PAYLOAD, public_key)

        reader = ExtendedPQCipher(
            self.hqc, quiet=True, encryption_data="xchacha20-poly1305", format_version=13
        )
        self.assertEqual(reader.decrypt(encrypted, private_key), PAYLOAD)


if __name__ == "__main__":
    unittest.main()
