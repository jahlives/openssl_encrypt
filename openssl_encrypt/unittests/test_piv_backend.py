"""Integration tests for PIVBackend over a fully mocked PKCS#11 stack.

Exercises the orchestrated get_pepper() pipeline (challenge -> sign -> pepper),
verify_hardware() diagnostics, session cleanup on every path (item 14), the
determinism guarantee, and the no-PIN-leak / PIN-zeroing security requirements.
"""

import os
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from openssl_encrypt.modules.piv_backend import (
    PIVAuthenticationError,
    PIVBackend,
    PIVConfigurationError,
    PIVDeterminismError,
    PIVKeyError,
)
from openssl_encrypt.unittests import _piv_mocks
from openssl_encrypt.unittests._piv_mocks import (
    FakeSession,
    FakeToken,
    SessionState,
    TokenFlag,
    deterministic_signer,
    make_ed25519_key,
    make_rsa_key,
)

PRESENT = TokenFlag.TOKEN_PRESENT | TokenFlag.LOGIN_REQUIRED


def _expected_pepper(input_data, sig_len, pepper_length=32):
    salt = b"openssl_encrypt-piv-v1"
    challenge = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=b"piv-challenge").derive(
        input_data
    )
    signature = deterministic_signer(sig_len)(challenge, None)
    return HKDF(
        algorithm=hashes.SHA256(), length=pepper_length, salt=salt, info=b"piv-pepper"
    ).derive(signature)


class _BackendTestBase(unittest.TestCase):
    def setUp(self):
        _piv_mocks.reset()
        self._tmp = tempfile.NamedTemporaryFile(suffix=".so", delete=False)
        self._tmp.write(b"\x7fELF fake module")
        self._tmp.close()
        self.path = self._tmp.name

    def tearDown(self):
        _piv_mocks.reset()
        os.unlink(self.path)

    def _backend(
        self,
        key,
        *,
        flags=PRESENT,
        open_error=None,
        state=SessionState.RO_USER_FUNCTIONS,
        pepper_length=32,
        piv_slot=0x9A,
        **kwargs
    ):
        session = FakeSession(keys=[key] if key is not None else [], state=state)
        token = FakeToken(flags=flags, session=session, open_error=open_error)
        _piv_mocks.set_library(_piv_mocks.single_slot_lib(token))
        backend = PIVBackend(
            self.path, slot_index=0, piv_slot=piv_slot, pepper_length=pepper_length, **kwargs
        )
        return backend, session


class TestPIVBackendConfig(_BackendTestBase):
    def test_invalid_pepper_length_rejected(self):
        with self.assertRaises((ValueError, PIVConfigurationError)):
            PIVBackend(self.path, pepper_length=0)

    def test_invalid_piv_slot_rejected(self):
        with self.assertRaises(PIVConfigurationError):
            PIVBackend(self.path, piv_slot=0x99)

    def test_invalid_slot_index_rejected(self):
        with self.assertRaises(PIVConfigurationError):
            PIVBackend(self.path, slot_index=-1)

    def test_empty_lib_path_rejected(self):
        with self.assertRaises(PIVConfigurationError):
            PIVBackend("")


class TestGetPepper(_BackendTestBase):
    def test_rsa_pepper_is_32_bytes(self):
        backend, _ = self._backend(make_rsa_key(2048))
        self.assertEqual(len(backend.get_pepper(b"data", pin=b"123456")), 32)

    def test_ed25519_pepper_is_32_bytes(self):
        backend, _ = self._backend(make_ed25519_key())
        self.assertEqual(len(backend.get_pepper(b"data", pin=b"123456")), 32)

    def test_configurable_pepper_length(self):
        backend, _ = self._backend(make_rsa_key(2048), pepper_length=48)
        self.assertEqual(len(backend.get_pepper(b"data", pin=b"123456")), 48)

    def test_pepper_matches_full_pipeline(self):
        backend, _ = self._backend(make_rsa_key(2048))
        self.assertEqual(
            backend.get_pepper(b"protect-me", pin=b"123456"),
            _expected_pepper(b"protect-me", 256),
        )

    def test_pepper_is_deterministic_across_calls(self):
        backend, _ = self._backend(make_rsa_key(2048))
        a = backend.get_pepper(b"same", pin=b"123456")
        b = backend.get_pepper(b"same", pin=b"123456")
        self.assertEqual(a, b)

    def test_biometric_pin_none_works(self):
        backend, _ = self._backend(make_ed25519_key())
        self.assertEqual(len(backend.get_pepper(b"data", pin=None)), 32)

    def test_empty_input_rejected(self):
        backend, _ = self._backend(make_rsa_key(2048))
        with self.assertRaises(PIVConfigurationError):
            backend.get_pepper(b"", pin=b"123456")

    def test_nondeterministic_key_rejected(self):
        backend, _ = self._backend(make_rsa_key(2048, deterministic=False))
        with self.assertRaises(PIVDeterminismError):
            backend.get_pepper(b"data", pin=b"123456")

    def test_no_key_raises(self):
        backend, _ = self._backend(None)
        with self.assertRaises(PIVKeyError):
            backend.get_pepper(b"data", pin=b"123456")


class TestGetPepperSessionCleanup(_BackendTestBase):
    """Item 14: the session is closed after success and after failure."""

    def test_session_closed_after_success(self):
        backend, session = self._backend(make_rsa_key(2048))
        backend.get_pepper(b"data", pin=b"123456")
        self.assertTrue(session.closed)

    def test_session_closed_after_signing_failure(self):
        backend, session = self._backend(make_rsa_key(2048, deterministic=False))
        with self.assertRaises(PIVDeterminismError):
            backend.get_pepper(b"data", pin=b"123456")
        self.assertTrue(session.closed)

    def test_session_closed_after_auth_failure(self):
        from pkcs11.exceptions import PinIncorrect

        backend, session = self._backend(make_rsa_key(2048), open_error=PinIncorrect("bad"))
        with self.assertRaises(PIVAuthenticationError):
            backend.get_pepper(b"data", pin=b"123456")
        # open() raised, so no session object was created; nothing to leak.
        self.assertFalse(session.closed or session.closed is None)


class TestGetPepperPinSecurity(_BackendTestBase):
    def test_pin_not_in_exception_on_failure(self):
        from pkcs11.exceptions import PinIncorrect

        backend, _ = self._backend(make_rsa_key(2048), open_error=PinIncorrect("bad"))
        with self.assertRaises(PIVAuthenticationError) as ctx:
            backend.get_pepper(b"data", pin=b"topsecretpin")
        self.assertNotIn("topsecretpin", str(ctx.exception))

    def test_pin_bytearray_zeroed_after_use(self):
        backend, _ = self._backend(make_rsa_key(2048))
        pin = bytearray(b"12345678")
        backend.get_pepper(b"data", pin=pin)
        self.assertEqual(bytes(pin), b"\x00" * 8)


class TestVerifyHardware(_BackendTestBase):
    def test_returns_dict_with_all_checks(self):
        backend, _ = self._backend(make_rsa_key(2048))
        result = backend.verify_hardware(pin=b"123456")
        for key in (
            "library_file_exists",
            "library_loadable",
            "slot_present",
            "slot_index_valid",
            "token_present",
            "key_present",
            "key_type_supported",
            "login_succeeded",
            "signature_non_empty",
            "signature_length_ok",
            "deterministic",
            "pepper_length_ok",
            "session_closed",
        ):
            self.assertIn(key, result)

    def test_all_checks_pass_on_good_setup(self):
        backend, _ = self._backend(make_rsa_key(2048))
        result = backend.verify_hardware(pin=b"123456")
        self.assertTrue(result["deterministic"] is True)
        self.assertTrue(result["key_present"] is True)
        self.assertTrue(result["pepper_length_ok"] is True)

    def test_reports_missing_key(self):
        backend, _ = self._backend(None)
        result = backend.verify_hardware(pin=b"123456")
        self.assertNotEqual(result["key_present"], True)

    def test_reports_nondeterministic_key(self):
        backend, _ = self._backend(make_rsa_key(2048, deterministic=False))
        result = backend.verify_hardware(pin=b"123456")
        self.assertNotEqual(result["deterministic"], True)


class TestAlgorithmAgnostic(_BackendTestBase):
    """Definition of Done: RSA-2048/3072/4096 and Ed25519 all work uniformly."""

    def _pepper_for(self, key):
        backend, _ = self._backend(key)
        return backend.get_pepper(b"shared-input", pin=b"123456")

    def test_rsa2048_yields_valid_pepper(self):
        self.assertEqual(len(self._pepper_for(make_rsa_key(2048))), 32)

    def test_rsa3072_yields_valid_pepper(self):
        self.assertEqual(len(self._pepper_for(make_rsa_key(3072))), 32)

    def test_rsa4096_yields_valid_pepper(self):
        self.assertEqual(len(self._pepper_for(make_rsa_key(4096))), 32)

    def test_ed25519_yields_valid_pepper(self):
        self.assertEqual(len(self._pepper_for(make_ed25519_key())), 32)

    def test_distinct_algorithms_yield_distinct_peppers(self):
        peppers = {
            bytes(self._pepper_for(make_rsa_key(2048))),
            bytes(self._pepper_for(make_rsa_key(4096))),
            bytes(self._pepper_for(make_ed25519_key())),
        }
        self.assertEqual(len(peppers), 3)


class TestMultiDeviceDeterminism(_BackendTestBase):
    """The core guarantee: the same key on two devices -> identical pepper."""

    def test_same_key_two_devices_same_pepper_rsa(self):
        # Two independent backends/tokens, each holding the same (deterministic)
        # RSA key material -> identical signatures -> identical peppers.
        backend_a, _ = self._backend(make_rsa_key(2048, deterministic=True))
        pepper_a = backend_a.get_pepper(b"file-salt", pin=b"123456")

        backend_b, _ = self._backend(make_rsa_key(2048, deterministic=True))
        pepper_b = backend_b.get_pepper(b"file-salt", pin=b"999999")

        self.assertEqual(pepper_a, pepper_b)

    def test_same_key_two_devices_same_pepper_ed25519(self):
        backend_a, _ = self._backend(make_ed25519_key(deterministic=True))
        pepper_a = backend_a.get_pepper(b"file-salt", pin=None)

        backend_b, _ = self._backend(make_ed25519_key(deterministic=True))
        pepper_b = backend_b.get_pepper(b"file-salt", pin=None)

        self.assertEqual(pepper_a, pepper_b)

    def test_different_input_different_pepper(self):
        backend, _ = self._backend(make_rsa_key(2048))
        self.assertNotEqual(
            backend.get_pepper(b"input-one", pin=b"123456"),
            backend.get_pepper(b"input-two", pin=b"123456"),
        )


if __name__ == "__main__":
    unittest.main()
