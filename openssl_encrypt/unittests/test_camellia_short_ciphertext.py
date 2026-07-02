"""Regression tests for the Camellia short-ciphertext authentication bypass.

Security background (issue #53 / CORE-1): ``CamelliaCipher.decrypt`` contained a
"might be legacy data" branch that, for any input shorter than the 32-byte HMAC
tag, performed an *unauthenticated* CBC decryption and returned the result,
raising a distinct ``DecryptionError("Invalid padding")`` on bad padding. That
is two bugs at once:

* an authentication bypass -- integrity/AAD binding is skipped, so a truncated
  or crafted ciphertext is decrypted with the real key and returned; and
* a CBC padding oracle -- the padding error is distinguishable from a MAC
  error, and the IV is stored in the file, enabling byte-by-byte plaintext
  recovery against a decryption oracle.

The fix removes the bypass: any input too short or mis-shaped to be an authentic
Camellia message (ciphertext that is a positive multiple of the block size plus
a 32-byte HMAC) fails with the *same* generic ``AuthenticationError`` used for a
genuine MAC failure, so no plaintext is released and no padding oracle exists.
"""

import os
import unittest

from openssl_encrypt.modules.crypt_core import CamelliaCipher
from openssl_encrypt.modules.crypt_errors import AuthenticationError, DecryptionError


class TestCamelliaShortCiphertextRegression(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(32)
        self.cipher = CamelliaCipher(self.key)
        self.nonce = os.urandom(16)  # 16-byte CBC IV

    def test_short_or_misshaped_input_fails_authentication(self):
        """Inputs that cannot be an authentic Camellia message must not decrypt."""
        # 0..15  -> too short for even one block; 32 -> zero-length ciphertext;
        # 40/47  -> ciphertext not a whole number of blocks (would otherwise
        #           reach CBC.finalize() and leak a ValueError).
        for length in (0, 1, 15, 16, 31, 32, 33, 40, 47):
            blob = bytes(length)  # deterministic all-zero bytes
            with self.assertRaises(AuthenticationError):
                self.cipher.decrypt(self.nonce, blob)

    def test_error_is_indistinguishable_from_mac_failure(self):
        """No padding oracle: short input yields the same error as a bad MAC."""
        # A correctly shaped ciphertext (one block + 32-byte tag) with the wrong
        # tag produces a genuine MAC failure; capture its (wrapped) message.
        valid_shape_bad_tag = bytes(16 + 32)
        with self.assertRaises(AuthenticationError) as mac_ctx:
            self.cipher.decrypt(self.nonce, valid_shape_bad_tag)
        mac_failure_message = str(mac_ctx.exception)

        # The short input, historically the bypass trigger, must raise the exact
        # same error -- never the distinct "Invalid padding" DecryptionError.
        short = bytes(16)  # single block
        try:
            self.cipher.decrypt(self.nonce, short)
            self.fail("expected AuthenticationError for short input")
        except DecryptionError:
            self.fail("short input produced a distinguishable padding error (oracle)")
        except AuthenticationError as exc:
            self.assertEqual(str(exc), mac_failure_message)

    def test_truncated_authentic_ciphertext_fails_authentication(self):
        """Truncating a real ciphertext to one block must fail auth, not decrypt."""
        ciphertext = self.cipher.encrypt(self.nonce, b"authentic secret payload!!")
        truncated = ciphertext[:16]
        with self.assertRaises(AuthenticationError):
            self.cipher.decrypt(self.nonce, truncated)

    def test_normal_roundtrip_unaffected(self):
        """The fix must not disturb genuine encrypt/decrypt round-trips."""
        for data in (b"", b"x", b"Hello World\n", os.urandom(100)):
            ciphertext = self.cipher.encrypt(self.nonce, data)
            self.assertEqual(self.cipher.decrypt(self.nonce, ciphertext), data)

    def test_roundtrip_with_associated_data(self):
        aad = b"context-binding-aad"
        ciphertext = self.cipher.encrypt(self.nonce, b"payload", aad)
        self.assertEqual(self.cipher.decrypt(self.nonce, ciphertext, aad), b"payload")


if __name__ == "__main__":
    unittest.main()
