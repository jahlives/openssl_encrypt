"""Regression tests for the legacy PQC TESTDATA plaintext-passthrough gate.

Security background (issue #54 / PQC-1): ``PQCipher.decrypt`` historically
detected the legacy ``TESTDATA`` / ``PQC_TEST_DATA:`` "simulation" formats by
matching attacker-controllable magic bytes *before* any KEM decapsulation or
AEAD verification, and returned the embedded bytes as plaintext. That is a
complete authentication bypass: anyone who can hand a victim a file could craft
one that "decrypts" to arbitrary attacker-chosen content with no key.

The fix gates that legacy read path behind an explicit, off-by-default opt-in
(``allow_legacy_testdata`` constructor argument or the
``OPENSSL_ENCRYPT_ALLOW_LEGACY_TESTDATA`` environment variable), so that normal
decryption never takes the passthrough branch. The opt-in is preserved solely so
1.4.x can still migrate genuine legacy simulation files.
"""

import os
import struct
import unittest

from openssl_encrypt.modules.pqc import PQCipher

# A private key is never consulted before the legacy branches / the short-input
# guard, so a dummy value is sufficient for these tests.
_DUMMY_PRIVATE_KEY = b"\x00" * 32
_ALGO = "ML-KEM-768"
_ENV = "OPENSSL_ENCRYPT_ALLOW_LEGACY_TESTDATA"


def _header_blob(payload: bytes) -> bytes:
    """A legacy ``PQC_TEST_DATA:`` blob whose passthrough would yield ``payload``."""
    return b"PQC_TEST_DATA:" + payload


def _marker_blob(payload: bytes) -> bytes:
    """A legacy ``TESTDATA`` blob whose passthrough would yield ``payload``."""
    return b"TESTDATA" + struct.pack(">I", len(payload)) + payload


class TestPqcTestdataGating(unittest.TestCase):
    def setUp(self):
        # Ensure no ambient opt-in leaks in from the environment.
        self._saved_env = os.environ.pop(_ENV, None)

    def tearDown(self):
        if self._saved_env is not None:
            os.environ[_ENV] = self._saved_env
        else:
            os.environ.pop(_ENV, None)

    # --- default (secure) behaviour: passthrough must NOT happen -------------

    def test_default_rejects_pqc_test_data_header(self):
        """A forged ``PQC_TEST_DATA:`` blob must not decrypt to attacker bytes."""
        cipher = PQCipher(_ALGO, quiet=True)
        forged = b"attacker-controlled-plaintext"
        with self.assertRaises(Exception):
            cipher.decrypt(_header_blob(forged), _DUMMY_PRIVATE_KEY)

    def test_default_rejects_testdata_marker(self):
        """A forged ``TESTDATA`` blob must not decrypt to attacker bytes."""
        cipher = PQCipher(_ALGO, quiet=True)
        forged = b"attacker-controlled-plaintext"
        with self.assertRaises(Exception):
            cipher.decrypt(_marker_blob(forged), _DUMMY_PRIVATE_KEY)

    def test_default_never_returns_the_embedded_payload(self):
        """Belt-and-suspenders: even if decrypt returned, it must not be the forgery."""
        cipher = PQCipher(_ALGO, quiet=True)
        forged = b"attacker-controlled-plaintext"
        for blob in (_header_blob(forged), _marker_blob(forged)):
            try:
                result = cipher.decrypt(blob, _DUMMY_PRIVATE_KEY)
            except Exception:
                continue  # raising is the expected, acceptable outcome
            self.assertNotEqual(result, forged)

    # --- explicit opt-in: legacy migration path still works ------------------

    def test_optin_arg_reads_pqc_test_data_header(self):
        cipher = PQCipher(_ALGO, quiet=True, allow_legacy_testdata=True)
        payload = b"legacy-simulation-payload"
        self.assertEqual(cipher.decrypt(_header_blob(payload), _DUMMY_PRIVATE_KEY), payload)

    def test_optin_arg_reads_testdata_marker(self):
        cipher = PQCipher(_ALGO, quiet=True, allow_legacy_testdata=True)
        payload = b"legacy-simulation-payload"
        self.assertEqual(cipher.decrypt(_marker_blob(payload), _DUMMY_PRIVATE_KEY), payload)

    def test_optin_env_var_reads_legacy_blob(self):
        os.environ[_ENV] = "1"
        cipher = PQCipher(_ALGO, quiet=True)
        payload = b"legacy-simulation-payload"
        self.assertEqual(cipher.decrypt(_header_blob(payload), _DUMMY_PRIVATE_KEY), payload)

    # --- the fix must not disturb genuine PQC round-trips --------------------

    def test_real_roundtrip_unaffected(self):
        cipher = PQCipher(_ALGO, quiet=True)
        public_key, private_key = cipher.generate_keypair()
        plaintext = b"genuine post-quantum encrypted content"
        encrypted = cipher.encrypt(plaintext, public_key)
        self.assertEqual(cipher.decrypt(encrypted, private_key), plaintext)


if __name__ == "__main__":
    unittest.main()
