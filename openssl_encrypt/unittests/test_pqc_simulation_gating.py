"""Regression tests for the legacy PQC SIMULATED_PQC_v1 downgrade gate.

Security background (issue #65 / PQC-2, closing out the #54 critical): after the
TESTDATA passthrough was gated, ``PQCipher.decrypt`` still detected the legacy
``SIMULATED_PQC_v1`` "simulation" format purely from attacker-controllable magic
bytes and derived a *deterministic* shared secret
``sha256(encapsulated_key || private_key[:16])`` -- an attacker-forcible
downgrade to weak, largely-public-data-derived crypto, selected on the normal
decrypt path.

The fix routes simulation detection through the same off-by-default opt-in as the
other legacy formats (``allow_legacy_testdata`` / the
``OPENSSL_ENCRYPT_ALLOW_LEGACY_TESTDATA`` env var). Without opt-in, a
``SIMULATED_PQC_v1`` blob is treated as a normal (bogus) KEM ciphertext and
fails authentication instead of silently using the weak deterministic secret.
"""

import hashlib
import os
import unittest

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from openssl_encrypt.modules.pqc import PQCipher, public_key_part

_ALGO = "ML-KEM-768"
_ENV = "OPENSSL_ENCRYPT_ALLOW_LEGACY_TESTDATA"
_SIM_HEADER = b"SIMULATED_PQC_v1"


def _build_simulated_blob(private_key: bytes, plaintext: bytes):
    """Reproduce a legacy SIMULATED_PQC_v1 aes-gcm ciphertext for `private_key`."""
    with oqs.KeyEncapsulation(_ALGO) as kem:
        ct_size = kem.length_ciphertext or kem.details.get("length_ciphertext")
        ss_len = kem.length_shared_secret or kem.details.get("length_shared_secret", 32)
    encapsulated_key = _SIM_HEADER + bytes(ct_size - len(_SIM_HEADER))
    shared_secret = hashlib.sha256(encapsulated_key + public_key_part(private_key)).digest()[
        :ss_len
    ]
    symmetric_key = hashlib.sha256(shared_secret).digest()
    nonce = bytes(12)
    ciphertext = AESGCM(symmetric_key).encrypt(nonce, plaintext, None)
    return encapsulated_key + nonce + ciphertext


class TestPqcSimulationGating(unittest.TestCase):
    def setUp(self):
        self._saved_env = os.environ.pop(_ENV, None)
        cipher = PQCipher(_ALGO, quiet=True)
        self.public_key, self.private_key = cipher.generate_keypair()
        self.plaintext = b"legacy simulation-mode plaintext"
        self.blob = _build_simulated_blob(self.private_key, self.plaintext)

    def tearDown(self):
        if self._saved_env is not None:
            os.environ[_ENV] = self._saved_env
        else:
            os.environ.pop(_ENV, None)

    def test_default_does_not_use_simulation_secret(self):
        """Without opt-in, a SIMULATED_PQC blob must fail, not use the weak secret."""
        cipher = PQCipher(_ALGO, quiet=True)
        try:
            result = cipher.decrypt(self.blob, self.private_key)
        except Exception:
            return  # failing to decrypt is the expected, secure outcome
        self.assertNotEqual(result, self.plaintext)

    def test_optin_arg_reads_simulation_blob(self):
        cipher = PQCipher(_ALGO, quiet=True, allow_legacy_testdata=True)
        self.assertEqual(cipher.decrypt(self.blob, self.private_key), self.plaintext)

    def test_optin_env_var_reads_simulation_blob(self):
        os.environ[_ENV] = "1"
        cipher = PQCipher(_ALGO, quiet=True)
        self.assertEqual(cipher.decrypt(self.blob, self.private_key), self.plaintext)

    def test_real_roundtrip_unaffected(self):
        cipher = PQCipher(_ALGO, quiet=True)
        encrypted = cipher.encrypt(b"genuine content", self.public_key)
        self.assertEqual(cipher.decrypt(encrypted, self.private_key), b"genuine content")


if __name__ == "__main__":
    unittest.main()
