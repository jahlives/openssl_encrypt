#!/usr/bin/env python3
"""PQC hybrid encryption_data must fail closed on unknown ciphers (gitlab#295).

The 2026-08-23 fail-closed audit found that PQCipher silently substituted
AES-GCM for any unrecognized ``encryption_data`` cipher name: on encrypt with
no warning at all (metadata could still record the requested name while the
bytes were AES-GCM), on decrypt with only an eprint. Real exposure: 1.4.x
supported ``aes-ocb3`` as a PQC hybrid data cipher, so such files decrypted
on 1.5.x tried AES-GCM against OCB3 ciphertext and failed with an
authentication error indistinguishable from a wrong password.

Both paths now raise a specific error. Per maintainer decision (2026-08-23),
aes-ocb3 remains decryptable via the STREAMING path only; the PQC path
refuses it with a message pointing at 1.4.x.
"""

import unittest

from openssl_encrypt.modules.pqc import LIBOQS_AVAILABLE, PQCAlgorithm, PQCipher


@unittest.skipUnless(LIBOQS_AVAILABLE, "liboqs not available")
class TestPqcEncryptionDataFailClosed(unittest.TestCase):
    """Unknown encryption_data names must raise, never substitute AES-GCM."""

    @classmethod
    def setUpClass(cls):
        """Generate one ML-KEM-512 keypair shared by all tests."""
        cipher = PQCipher(PQCAlgorithm.ML_KEM_512, quiet=True)
        cls.public_key, cls.private_key = cipher.generate_keypair()

    def test_encrypt_refuses_unknown_cipher(self):
        """Encrypting with an unknown data cipher raises and names it."""
        cipher = PQCipher(PQCAlgorithm.ML_KEM_512, quiet=True, encryption_data="aes-ocb3")
        with self.assertRaises(Exception) as ctx:
            cipher.encrypt(b"payload", self.public_key)
        self.assertIn("aes-ocb3", str(ctx.exception))

    def test_decrypt_refuses_unknown_cipher_with_guidance(self):
        """Decrypting with an unknown data cipher raises with 1.4.x guidance.

        Pre-fix this silently tried AES-GCM against the (chacha20-encrypted)
        bytes and surfaced a generic authentication error indistinguishable
        from a wrong password.
        """
        enc = PQCipher(PQCAlgorithm.ML_KEM_512, quiet=True, encryption_data="chacha20-poly1305")
        blob = enc.encrypt(b"payload", self.public_key)
        dec = PQCipher(PQCAlgorithm.ML_KEM_512, quiet=True, encryption_data="aes-ocb3")
        with self.assertRaises(Exception) as ctx:
            dec.decrypt(blob, self.private_key)
        msg = str(ctx.exception)
        self.assertIn("aes-ocb3", msg)
        self.assertIn("1.4", msg, msg="removed-cipher refusal must point at 1.4.x: " + msg)

    def test_known_ciphers_still_roundtrip(self):
        """The six real data ciphers keep working (aes-gcm spot check)."""
        enc = PQCipher(PQCAlgorithm.ML_KEM_512, quiet=True, encryption_data="aes-gcm")
        blob = enc.encrypt(b"payload", self.public_key)
        self.assertEqual(enc.decrypt(blob, self.private_key), b"payload")
