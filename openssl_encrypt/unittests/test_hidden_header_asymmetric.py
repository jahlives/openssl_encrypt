#!/usr/bin/env python3
"""
Integration tests for the hidden-header format on the asymmetric (PQC) path.

encrypt_file_asymmetric/decrypt_file_asymmetric are buffered Format-V7 paths;
the hidden format wraps their metadata header and raw body exactly as on the
symmetric path. All code in English as per project requirements.
"""

import os
import shutil
import tempfile
import unittest

try:
    from openssl_encrypt.modules.crypt_core import (
        decrypt_file_asymmetric,
        encrypt_file_asymmetric,
    )
    from openssl_encrypt.modules.crypt_errors import AuthenticationError
    from openssl_encrypt.modules.hidden_header import is_hidden_format
    from openssl_encrypt.modules.identity import Identity
    from openssl_encrypt.modules.pqc_signing import LIBOQS_AVAILABLE
except Exception:  # pragma: no cover
    LIBOQS_AVAILABLE = False

SECOND_PW = "asym-second-password"


@unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
class TestAsymmetricHidden(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.sender = Identity.generate("Sender", "sender@example.com", "sender_pass")
        self.recipient = Identity.generate("Recipient", "rcpt@example.com", "rcpt_pass")
        self.src = os.path.join(self.dir, "msg.txt")
        self.content = b"asymmetric hidden-header payload \x00\x01\x02" * 30
        with open(self.src, "wb") as f:
            f.write(self.content)
        self.enc = os.path.join(self.dir, "out.enc")
        self.dec = os.path.join(self.dir, "out.dec")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _encrypt(self, **kw):
        encrypt_file_asymmetric(
            input_file=self.src,
            output_file=self.enc,
            recipients=[self.recipient],
            sender=self.sender,
            quiet=True,
            **kw,
        )

    def _decrypt(self, **kw):
        decrypt_file_asymmetric(
            input_file=self.enc,
            output_file=self.dec,
            recipient=self.recipient,
            sender_public_key=self.sender.signing_public_key,
            quiet=True,
            **kw,
        )
        with open(self.dec, "rb") as f:
            return f.read()

    def test_keyless_round_trip(self):
        self._encrypt(hidden_header=True)
        with open(self.enc, "rb") as f:
            self.assertTrue(is_hidden_format(f.read()))
        self.assertEqual(self._decrypt(), self.content)

    def test_keyed_round_trip(self):
        self._encrypt(hidden_header=True, second_password=SECOND_PW)
        self.assertEqual(self._decrypt(second_password=SECOND_PW), self.content)

    def test_keyed_wrong_second_password_fails(self):
        self._encrypt(hidden_header=True, second_password=SECOND_PW)
        with self.assertRaises((AuthenticationError, ValueError)):
            self._decrypt(second_password="wrong")

    def test_legacy_round_trip_regression(self):
        self._encrypt()  # legacy format
        self.assertEqual(self._decrypt(), self.content)


if __name__ == "__main__":
    unittest.main()
