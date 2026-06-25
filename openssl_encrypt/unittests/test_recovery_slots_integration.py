#!/usr/bin/env python3
"""
End-to-end tests for recovery slots wired into encrypt_file / decrypt_file.

A file encrypted with recovery credentials carries
``encryption.dek_slots`` (+ ``dek_slots_mac``) in addition to the primary
``wrapped_dek``. The file decrypts with EITHER the primary password OR any
recovery credential. Files encrypted without recovery credentials are
unchanged (no dek_slots field) and decrypt exactly as before.
"""

import base64
import json
import os
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import decrypt_file, encrypt_file
from openssl_encrypt.modules.crypt_errors import (
    AuthenticationError,
    DecryptionError,
    SecretSharingError,
    ValidationError,
)
import secrets

from openssl_encrypt.modules.recovery_slots import generate_recovery_code
from openssl_encrypt.modules.secret_sharing import split_secret

try:
    from openssl_encrypt.modules.identity import Identity
    from openssl_encrypt.modules.pqc_signing import LIBOQS_AVAILABLE
except Exception:  # pragma: no cover
    LIBOQS_AVAILABLE = False


def _priv_bytes(identity):
    with identity.encryption_private_key as pk:
        return pk.get_bytes()

PASSWORD = b"primary-password-correct-horse"
PLAINTEXT = b"recovery-slot round-trip payload, several blocks long.\n" * 8


def _encrypt(**kwargs) -> bytes:
    params = dict(
        input_file=PLAINTEXT,
        output_file=None,
        password=PASSWORD,
        algorithm="aes-gcm",
        quiet=True,
    )
    params.update(kwargs)
    return encrypt_file(**params)


def _parse_meta(file_bytes: bytes) -> dict:
    return json.loads(base64.b64decode(file_bytes.split(b":", 1)[0]))


def _decrypt(file_bytes: bytes, **kwargs):
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(file_bytes)
        params = dict(input_file=path, output_file=None, quiet=True)
        params.update(kwargs)
        return decrypt_file(**params)
    finally:
        os.unlink(path)


class TestRecoverySlotEncryptMetadata(unittest.TestCase):
    def test_recovery_credentials_add_slots(self):
        code = generate_recovery_code()
        meta = _parse_meta(
            _encrypt(envelope=True, recovery_credentials=[{"type": "recovery_code", "code": code}])
        )
        enc = meta["encryption"]
        self.assertIn("wrapped_dek", enc)  # primary slot still present
        self.assertIn("dek_slots", enc)
        self.assertEqual(len(enc["dek_slots"]), 1)
        self.assertEqual(enc["dek_slots"][0]["type"], "recovery_code")
        self.assertIn("dek_slots_mac", enc)

    def test_recovery_credentials_imply_envelope(self):
        """Passing recovery credentials without envelope=True still wraps."""
        code = generate_recovery_code()
        meta = _parse_meta(
            _encrypt(recovery_credentials=[{"type": "recovery_code", "code": code}])
        )
        self.assertIn("wrapped_dek", meta["encryption"])
        self.assertIn("dek_slots", meta["encryption"])

    def test_no_recovery_no_slots_field(self):
        """Backward-compat: plain envelope file gets NO dek_slots field."""
        meta = _parse_meta(_encrypt(envelope=True))
        self.assertIn("wrapped_dek", meta["encryption"])
        self.assertNotIn("dek_slots", meta["encryption"])
        self.assertNotIn("dek_slots_mac", meta["encryption"])


class TestRecoverySlotRoundTrip(unittest.TestCase):
    def test_password_still_decrypts_when_recovery_present(self):
        code = generate_recovery_code()
        enc = _encrypt(recovery_credentials=[{"type": "recovery_code", "code": code}])
        self.assertEqual(_decrypt(enc, password=PASSWORD), PLAINTEXT)

    def test_recovery_code_decrypts_without_password(self):
        code = generate_recovery_code()
        enc = _encrypt(recovery_credentials=[{"type": "recovery_code", "code": code}])
        self.assertEqual(_decrypt(enc, recovery_code=code), PLAINTEXT)

    def test_wrong_recovery_code_fails_closed(self):
        code = generate_recovery_code()
        enc = _encrypt(recovery_credentials=[{"type": "recovery_code", "code": code}])
        with self.assertRaises((AuthenticationError, DecryptionError, ValidationError, ValueError)):
            _decrypt(enc, recovery_code=generate_recovery_code())

    def test_recovery_on_cascade(self):
        code = generate_recovery_code()
        enc = _encrypt(
            algorithm="cascade",
            cascade=True,
            cipher_names=["aes-gcm", "chacha20-poly1305"],
            recovery_credentials=[{"type": "recovery_code", "code": code}],
        )
        self.assertEqual(_decrypt(enc, recovery_code=code), PLAINTEXT)
        self.assertEqual(_decrypt(enc, password=PASSWORD), PLAINTEXT)


class TestShamirRecoveryRoundTrip(unittest.TestCase):
    """Shamir k-of-n recovery slot, end-to-end through encrypt/decrypt_file."""

    def _encrypt_with_shamir(self, threshold=2, num_shares=3):
        secret = secrets.token_bytes(32)
        shares = split_secret(secret, threshold=threshold, num_shares=num_shares)
        enc = _encrypt(
            recovery_credentials=[
                {
                    "type": "shamir",
                    "secret": secret,
                    "threshold": threshold,
                    "num_shares": num_shares,
                }
            ]
        )
        return enc, shares

    def test_metadata_has_shamir_slot(self):
        enc, _ = self._encrypt_with_shamir()
        slot = _parse_meta(enc)["encryption"]["dek_slots"][0]
        self.assertEqual(slot["type"], "shamir")
        self.assertEqual(slot["params"]["shamir"]["threshold"], 2)
        self.assertEqual(slot["params"]["shamir"]["num_shares"], 3)

    def test_threshold_shares_decrypt(self):
        enc, shares = self._encrypt_with_shamir(threshold=2, num_shares=3)
        # any 2 of 3 shares reconstruct and decrypt
        self.assertEqual(_decrypt(enc, recovery_shares=shares[:2]), PLAINTEXT)
        self.assertEqual(_decrypt(enc, recovery_shares=[shares[0], shares[2]]), PLAINTEXT)

    def test_below_threshold_fails(self):
        enc, shares = self._encrypt_with_shamir(threshold=3, num_shares=5)
        with self.assertRaises(
            (AuthenticationError, DecryptionError, SecretSharingError, ValidationError, ValueError)
        ):
            _decrypt(enc, recovery_shares=shares[:2])

    def test_password_still_works_with_shamir_slot(self):
        enc, _ = self._encrypt_with_shamir()
        self.assertEqual(_decrypt(enc, password=PASSWORD), PLAINTEXT)


class TestPassphraseRecoveryRoundTrip(unittest.TestCase):
    RECOVERY_PW = b"my offline backup passphrase"
    # small Argon2 params keep the test fast
    A2 = {"time_cost": 1, "memory_cost": 8192, "parallelism": 1}

    def _encrypt_with_passphrase(self):
        return _encrypt(
            recovery_credentials=[
                {"type": "passphrase", "passphrase": self.RECOVERY_PW, **self.A2}
            ]
        )

    def test_metadata_has_passphrase_slot(self):
        slot = _parse_meta(self._encrypt_with_passphrase())["encryption"]["dek_slots"][0]
        self.assertEqual(slot["type"], "passphrase")
        self.assertIn("argon2", slot["params"])

    def test_recovery_passphrase_decrypts(self):
        enc = self._encrypt_with_passphrase()
        self.assertEqual(_decrypt(enc, recovery_passphrase=self.RECOVERY_PW), PLAINTEXT)

    def test_wrong_passphrase_fails(self):
        enc = self._encrypt_with_passphrase()
        with self.assertRaises((AuthenticationError, DecryptionError, ValidationError, ValueError)):
            _decrypt(enc, recovery_passphrase=b"not the recovery passphrase")

    def test_password_still_works(self):
        enc = self._encrypt_with_passphrase()
        self.assertEqual(_decrypt(enc, password=PASSWORD), PLAINTEXT)


class TestSlotSetAdversarial(unittest.TestCase):
    """The recovery-slot set is MAC-authenticated (DEK-keyed). Stripping,
    injecting, modifying, or swapping slots must fail closed on BOTH the
    password and recovery decryption paths."""

    def _two_code_file(self):
        c1, c2 = generate_recovery_code(), generate_recovery_code()
        enc = _encrypt(
            recovery_credentials=[
                {"type": "recovery_code", "code": c1},
                {"type": "recovery_code", "code": c2},
            ]
        )
        return enc, c1, c2

    @staticmethod
    def _rebuild(file_bytes, mutate):
        meta_b64, payload = file_bytes.split(b":", 1)
        meta = json.loads(base64.b64decode(meta_b64))
        mutate(meta)
        new_b64 = base64.b64encode(json.dumps(meta, separators=(",", ":")).encode("utf-8"))
        return new_b64 + b":" + payload

    def _assert_fails(self, file_bytes, **decrypt_kwargs):
        with self.assertRaises(
            (AuthenticationError, DecryptionError, SecretSharingError, ValidationError, ValueError)
        ):
            _decrypt(file_bytes, **decrypt_kwargs)

    def test_strip_slot_fails_password_path(self):
        enc, _, _ = self._two_code_file()
        tampered = self._rebuild(enc, lambda m: m["encryption"]["dek_slots"].pop())
        self._assert_fails(tampered, password=PASSWORD)

    def test_strip_slot_fails_recovery_path(self):
        enc, c1, _ = self._two_code_file()
        tampered = self._rebuild(enc, lambda m: m["encryption"]["dek_slots"].pop())
        self._assert_fails(tampered, recovery_code=c1)

    def test_inject_slot_fails(self):
        enc, _, _ = self._two_code_file()

        def inject(m):
            bogus = dict(m["encryption"]["dek_slots"][0])
            bogus["id"] = "evil"
            m["encryption"]["dek_slots"].append(bogus)

        self._assert_fails(self._rebuild(enc, inject), password=PASSWORD)

    def test_modify_slot_wrap_fails(self):
        enc, _, _ = self._two_code_file()

        def modify(m):
            blob = bytearray(base64.b64decode(m["encryption"]["dek_slots"][0]["wrap"]))
            blob[-1] ^= 0x01
            m["encryption"]["dek_slots"][0]["wrap"] = base64.b64encode(bytes(blob)).decode()

        self._assert_fails(self._rebuild(enc, modify), password=PASSWORD)

    def test_strip_mac_fails(self):
        enc, _, _ = self._two_code_file()
        self._assert_fails(
            self._rebuild(enc, lambda m: m["encryption"].pop("dek_slots_mac")),
            password=PASSWORD,
        )

    def test_swap_slots_between_files_fails(self):
        enc_a, _, _ = self._two_code_file()
        enc_b, _, _ = self._two_code_file()
        meta_b = json.loads(base64.b64decode(enc_b.split(b":", 1)[0]))

        def graft(m):
            m["encryption"]["dek_slots"] = meta_b["encryption"]["dek_slots"]
            m["encryption"]["dek_slots_mac"] = meta_b["encryption"]["dek_slots_mac"]

        # File A's DEK won't validate B's slot-set MAC.
        self._assert_fails(self._rebuild(enc_a, graft), password=PASSWORD)


@unittest.skipIf(not LIBOQS_AVAILABLE, "liboqs not available")
class TestPqcRecoveryRoundTrip(unittest.TestCase):
    """PQC recipient (escrow) recovery slot, end-to-end."""

    @classmethod
    def setUpClass(cls):
        cls.escrow = Identity.generate("Escrow", None, "escrow-pass")
        cls.stranger = Identity.generate("Stranger", None, "stranger-pass")

    def _encrypt_with_pqc(self):
        return _encrypt(
            recovery_credentials=[
                {
                    "type": "pqc",
                    "public_key": self.escrow.encryption_public_key,
                    "kem_algorithm": self.escrow.encryption_algorithm,
                    "key_id": self.escrow.fingerprint,
                }
            ]
        )

    def test_metadata_has_pqc_slot(self):
        slot = _parse_meta(self._encrypt_with_pqc())["encryption"]["dek_slots"][0]
        self.assertEqual(slot["type"], "pqc")
        self.assertEqual(slot["params"]["kem_algorithm"], self.escrow.encryption_algorithm)
        self.assertIn("encapsulated_key", slot["params"])

    def test_escrow_private_key_decrypts(self):
        enc = self._encrypt_with_pqc()
        self.assertEqual(
            _decrypt(enc, recovery_private_key=_priv_bytes(self.escrow)), PLAINTEXT
        )

    def test_stranger_key_fails_closed(self):
        enc = self._encrypt_with_pqc()
        with self.assertRaises((AuthenticationError, DecryptionError, ValidationError, ValueError, Exception)):
            _decrypt(enc, recovery_private_key=_priv_bytes(self.stranger))

    def test_password_still_works_with_pqc_slot(self):
        enc = self._encrypt_with_pqc()
        self.assertEqual(_decrypt(enc, password=PASSWORD), PLAINTEXT)


if __name__ == "__main__":
    unittest.main()
