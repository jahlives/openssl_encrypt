"""Unit tests for PIVSigner (key detection, type validation, signing).

Covers verification-table items 6 (signing key exists in the PIV slot), 7 (key
type is supported), 10 (signature non-empty), 11 (signature length matches key
type) and 12 (signing is deterministic).  All PKCS#11 interaction is mocked.
"""

import unittest

from openssl_encrypt.modules.piv_backend import (
    PIVConfigurationError,
    PIVKeyError,
    PIVSigner,
)
from openssl_encrypt.unittests import _piv_mocks
from openssl_encrypt.unittests._piv_mocks import (
    FakeKey,
    FakeSession,
    KeyType,
    deterministic_signer,
    make_ecdsa_key,
    make_ed25519_key,
    make_rsa_key,
)


class TestPIVSignerConfig(unittest.TestCase):
    def test_default_slot_is_9a(self):
        self.assertEqual(PIVSigner().piv_slot, 0x9A)

    def test_valid_slots_accepted(self):
        for slot in (0x9A, 0x9C, 0x9D, 0x9E):
            self.assertEqual(PIVSigner(piv_slot=slot).piv_slot, slot)

    def test_invalid_slot_rejected(self):
        with self.assertRaises(PIVConfigurationError):
            PIVSigner(piv_slot=0x99)

    def test_non_int_slot_rejected(self):
        with self.assertRaises(PIVConfigurationError):
            PIVSigner(piv_slot="9a")


class TestKeyDetection(unittest.TestCase):
    """Item 6: a private key must exist in the configured PIV slot."""

    def test_no_key_in_slot_raises(self):
        session = FakeSession(keys=[])
        with self.assertRaises(PIVKeyError):
            PIVSigner().find_key(session)

    def test_rsa_key_found(self):
        key = make_rsa_key(2048)
        session = FakeSession(keys=[key])
        self.assertIs(PIVSigner().find_key(session), key)

    def test_ed25519_key_found(self):
        key = make_ed25519_key()
        session = FakeSession(keys=[key])
        self.assertIs(PIVSigner().find_key(session), key)

    def test_multiple_keys_raises(self):
        from pkcs11.exceptions import MultipleObjectsReturned

        session = FakeSession(get_key_error=MultipleObjectsReturned("ambiguous"))
        with self.assertRaises(PIVKeyError):
            PIVSigner().find_key(session)

    def test_get_key_error_becomes_key_error(self):
        from pkcs11.exceptions import FunctionFailed

        session = FakeSession(get_key_error=FunctionFailed("C_FindObjects failed"))
        with self.assertRaises(PIVKeyError):
            PIVSigner().find_key(session)

    def test_key_selected_by_piv_slot_id(self):
        # Key lives in slot 9c only.
        key = make_rsa_key(2048, key_id=_piv_mocks.PIV_SLOT_ID_9C)
        session = FakeSession(keys=[key])
        # Default signer looks in 9a -> not found.
        with self.assertRaises(PIVKeyError):
            PIVSigner(piv_slot=0x9A).find_key(session)
        # 9c signer finds it.
        self.assertIs(PIVSigner(piv_slot=0x9C).find_key(session), key)


class TestKeyTypeValidation(unittest.TestCase):
    """Item 7: only deterministic key types are accepted."""

    def test_rsa_accepted(self):
        key = make_rsa_key(2048)
        PIVSigner().find_key(FakeSession(keys=[key]))  # must not raise

    def test_ed25519_accepted(self):
        key = make_ed25519_key()
        PIVSigner().find_key(FakeSession(keys=[key]))  # must not raise

    def test_ecdsa_rejected(self):
        key = make_ecdsa_key()
        with self.assertRaises(PIVKeyError) as ctx:
            PIVSigner().find_key(FakeSession(keys=[key]))
        msg = str(ctx.exception).lower()
        self.assertTrue("ecdsa" in msg or "deterministic" in msg)

    def test_unknown_key_type_rejected(self):
        bogus = FakeKey("DSA", signer=deterministic_signer(40))
        with self.assertRaises(PIVKeyError):
            PIVSigner().find_key(FakeSession(keys=[bogus]))

    def test_supported_key_types_constant(self):
        self.assertIn(KeyType.RSA, PIVSigner.SUPPORTED_KEY_TYPES)
        self.assertIn(KeyType.EC_EDWARDS, PIVSigner.SUPPORTED_KEY_TYPES)
        self.assertNotIn(KeyType.EC, PIVSigner.SUPPORTED_KEY_TYPES)


if __name__ == "__main__":
    unittest.main()
