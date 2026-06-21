"""Unit tests for TokenSession (slot detection, login, PIN handling, cleanup).

Covers verification-table items 3, 4, 5 (slot/token detection), 8, 9 (login and
PIN handling), and 14 (session cleanup).  All PKCS#11 interaction is mocked.
"""

import os
import tempfile
import unittest

from openssl_encrypt.modules.piv_backend import (
    PIVAuthenticationError,
    PIVConfigurationError,
    PIVTokenError,
    PKCS11Library,
    TokenSession,
)
from openssl_encrypt.unittests import _piv_mocks
from openssl_encrypt.unittests._piv_mocks import (
    FakeSession,
    FakeSlot,
    FakeToken,
    SessionState,
    TokenFlag,
)

PRESENT = TokenFlag.TOKEN_PRESENT | TokenFlag.LOGIN_REQUIRED


class _TokenSessionTestBase(unittest.TestCase):
    """Shared temp .so + fake-library plumbing."""

    def setUp(self):
        _piv_mocks.reset()
        self._tmp = tempfile.NamedTemporaryFile(suffix=".so", delete=False)
        self._tmp.write(b"\x7fELF fake module")
        self._tmp.close()
        self.path = self._tmp.name

    def tearDown(self):
        _piv_mocks.reset()
        os.unlink(self.path)

    def _library(self, fake_lib):
        _piv_mocks.set_library(fake_lib)
        return PKCS11Library(self.path)


class TestTokenSessionConfig(_TokenSessionTestBase):
    def test_negative_slot_index_rejected(self):
        lib = self._library(_piv_mocks.make_lib())
        with self.assertRaises(PIVConfigurationError):
            TokenSession(lib, slot_index=-1)

    def test_non_int_slot_index_rejected(self):
        lib = self._library(_piv_mocks.make_lib())
        with self.assertRaises(PIVConfigurationError):
            TokenSession(lib, slot_index="0")


class TestTokenSelection(_TokenSessionTestBase):
    """Items 3, 4, 5."""

    def test_no_slot_with_token_raises(self):
        # Item 3: no slot with a token present.
        lib = self._library(_piv_mocks.make_lib())
        session = TokenSession(lib, slot_index=0)
        with self.assertRaises(PIVTokenError):
            session.select_token()

    def test_slot_index_out_of_range_raises(self):
        # Item 4: index beyond the slot list.
        token = FakeToken(flags=PRESENT)
        lib = self._library(_piv_mocks.single_slot_lib(token))
        session = TokenSession(lib, slot_index=5)
        with self.assertRaises(PIVTokenError):
            session.select_token()

    def test_token_present_flag_missing_raises(self):
        # Item 5: token object exists but TOKEN_PRESENT flag is not set.
        token = FakeToken(flags=TokenFlag.LOGIN_REQUIRED)  # no TOKEN_PRESENT bit
        lib = self._library(_piv_mocks.single_slot_lib(token))
        session = TokenSession(lib, slot_index=0)
        with self.assertRaises(PIVTokenError):
            session.select_token()

    def test_get_token_failure_becomes_token_error(self):
        from pkcs11.exceptions import TokenNotPresent

        slot = FakeSlot(token_error=TokenNotPresent("gone"), slot_id=0)
        lib = self._library(_piv_mocks.make_lib(slot))
        session = TokenSession(lib, slot_index=0)
        with self.assertRaises(PIVTokenError):
            session.select_token()

    def test_get_slots_failure_becomes_token_error(self):
        from pkcs11.exceptions import FunctionFailed

        class _BrokenLib:
            def get_slots(self, token_present=False):
                raise FunctionFailed("C_GetSlotList failed")

        lib = self._library(_BrokenLib())
        session = TokenSession(lib, slot_index=0)
        with self.assertRaises(PIVTokenError):
            session.select_token()

    def test_successful_selection_returns_token(self):
        token = FakeToken(flags=PRESENT, label="my piv token")
        lib = self._library(_piv_mocks.single_slot_lib(token))
        session = TokenSession(lib, slot_index=0)
        self.assertIs(session.select_token(), token)

    def test_selects_correct_index_among_multiple_slots(self):
        t0 = FakeToken(flags=PRESENT, label="slot0")
        t1 = FakeToken(flags=PRESENT, label="slot1")
        lib = self._library(
            _piv_mocks.make_lib(
                FakeSlot(token=t0, slot_id=0),
                FakeSlot(token=t1, slot_id=1),
            )
        )
        session = TokenSession(lib, slot_index=1)
        self.assertIs(session.select_token(), t1)


class TestLoginBiometricFlow(_TokenSessionTestBase):
    """pin=None must call C_Login with empty bytes, not None (item 8 skip path)."""

    def _session(self, token):
        lib = self._library(_piv_mocks.single_slot_lib(token))
        return TokenSession(lib, slot_index=0)

    def test_biometric_login_calls_open_with_empty_bytes(self):
        token = FakeToken(flags=PRESENT, session=FakeSession(state=SessionState.RO_USER_FUNCTIONS))
        session = self._session(token)
        session.login(pin=None)
        self.assertEqual(len(token.open_calls), 1)
        self.assertEqual(token.open_calls[0]["user_pin"], b"")

    def test_biometric_login_never_passes_none_pin(self):
        token = FakeToken(flags=PRESENT, session=FakeSession(state=SessionState.RW_USER_FUNCTIONS))
        session = self._session(token)
        session.login(pin=None)
        self.assertIsNotNone(token.open_calls[0]["user_pin"])

    def test_retry_counter_check_skipped_when_biometric(self):
        # Final-try flag set, but pin=None must NOT block (biometric has no host-side risk).
        token = FakeToken(
            flags=PRESENT | TokenFlag.USER_PIN_FINAL_TRY,
            session=FakeSession(state=SessionState.RO_USER_FUNCTIONS),
        )
        session = self._session(token)
        # Should not raise despite FINAL_TRY and no confirmation callback.
        session.login(pin=None)
        self.assertEqual(len(token.open_calls), 1)

    def test_biometric_pin_incorrect_suggests_fingerprint(self):
        from pkcs11.exceptions import PinIncorrect

        token = FakeToken(flags=PRESENT, open_error=PinIncorrect("rejected"))
        session = self._session(token)
        with self.assertRaises(PIVAuthenticationError) as ctx:
            session.login(pin=None)
        msg = str(ctx.exception).lower()
        self.assertIn("fingerprint", msg)


class TestLoginPinFlow(_TokenSessionTestBase):
    """PIN handling, zeroing, generic errors, retry guard (items 8, 9)."""

    def _session(self, token):
        lib = self._library(_piv_mocks.single_slot_lib(token))
        return TokenSession(lib, slot_index=0)

    def test_pin_passed_to_open(self):
        token = FakeToken(flags=PRESENT, session=FakeSession(state=SessionState.RO_USER_FUNCTIONS))
        session = self._session(token)
        session.login(pin=b"123456")
        self.assertEqual(token.open_calls[0]["user_pin"], b"123456")

    def test_non_bytes_pin_rejected(self):
        token = FakeToken(flags=PRESENT, session=FakeSession())
        session = self._session(token)
        with self.assertRaises(PIVConfigurationError):
            session.login(pin="123456")  # str not allowed

    def test_pin_bytearray_is_zeroed_after_login(self):
        token = FakeToken(flags=PRESENT, session=FakeSession(state=SessionState.RO_USER_FUNCTIONS))
        session = self._session(token)
        pin = bytearray(b"31415926")
        session.login(pin=pin)
        self.assertEqual(bytes(pin), b"\x00" * 8)

    def test_pin_bytearray_zeroed_even_on_auth_failure(self):
        from pkcs11.exceptions import PinIncorrect

        token = FakeToken(flags=PRESENT, open_error=PinIncorrect("bad"))
        session = self._session(token)
        pin = bytearray(b"99887766")
        with self.assertRaises(PIVAuthenticationError):
            session.login(pin=pin)
        self.assertEqual(bytes(pin), b"\x00" * 8)

    def test_wrong_pin_message_is_generic(self):
        from pkcs11.exceptions import PinIncorrect

        token = FakeToken(flags=PRESENT, open_error=PinIncorrect("bad"))
        session = self._session(token)
        with self.assertRaises(PIVAuthenticationError) as ctx:
            session.login(pin=b"sup3rs3cret")
        self.assertEqual(str(ctx.exception), "Authentication failed")

    def test_pin_value_never_in_exception_message(self):
        from pkcs11.exceptions import PinIncorrect

        token = FakeToken(flags=PRESENT, open_error=PinIncorrect("bad"))
        session = self._session(token)
        secret = b"hunter2pin"
        with self.assertRaises(PIVAuthenticationError) as ctx:
            session.login(pin=secret)
        self.assertNotIn("hunter2pin", str(ctx.exception))

    def test_generic_pkcs11_error_becomes_auth_failed(self):
        from pkcs11.exceptions import FunctionFailed

        token = FakeToken(flags=PRESENT, open_error=FunctionFailed("boom"))
        session = self._session(token)
        with self.assertRaises(PIVAuthenticationError):
            session.login(pin=b"123456")

    def test_pin_locked_reports_locked(self):
        from pkcs11.exceptions import PinLocked

        token = FakeToken(flags=PRESENT, open_error=PinLocked("locked"))
        session = self._session(token)
        with self.assertRaises(PIVAuthenticationError) as ctx:
            session.login(pin=b"123456")
        self.assertIn("locked", str(ctx.exception).lower())

    # --- retry counter guard (item 8) ---
    def test_final_try_without_confirmation_refuses(self):
        token = FakeToken(
            flags=PRESENT | TokenFlag.USER_PIN_FINAL_TRY,
            session=FakeSession(state=SessionState.RO_USER_FUNCTIONS),
        )
        session = self._session(token)
        with self.assertRaises(PIVAuthenticationError):
            session.login(pin=b"123456")  # no confirm callback
        self.assertEqual(len(token.open_calls), 0)  # must not attempt the login

    def test_final_try_with_confirmation_proceeds(self):
        token = FakeToken(
            flags=PRESENT | TokenFlag.USER_PIN_FINAL_TRY,
            session=FakeSession(state=SessionState.RO_USER_FUNCTIONS),
        )
        session = self._session(token)
        session.login(pin=b"123456", confirm_final_attempt=lambda: True)
        self.assertEqual(len(token.open_calls), 1)

    def test_final_try_confirmation_declined_refuses(self):
        token = FakeToken(
            flags=PRESENT | TokenFlag.USER_PIN_FINAL_TRY,
            session=FakeSession(),
        )
        session = self._session(token)
        with self.assertRaises(PIVAuthenticationError):
            session.login(pin=b"123456", confirm_final_attempt=lambda: False)
        self.assertEqual(len(token.open_calls), 0)

    def test_locked_flag_refuses_before_open(self):
        token = FakeToken(
            flags=PRESENT | TokenFlag.USER_PIN_LOCKED,
            session=FakeSession(),
        )
        session = self._session(token)
        with self.assertRaises(PIVAuthenticationError):
            session.login(pin=b"123456")
        self.assertEqual(len(token.open_calls), 0)


class TestLoginSessionStateVerification(_TokenSessionTestBase):
    """Item 9: confirm the session is actually in a USER_FUNCTIONS state."""

    def _session(self, token):
        lib = self._library(_piv_mocks.single_slot_lib(token))
        return TokenSession(lib, slot_index=0)

    def test_login_success_returns_session(self):
        sess = FakeSession(state=SessionState.RW_USER_FUNCTIONS)
        token = FakeToken(flags=PRESENT, session=sess)
        ts = self._session(token)
        self.assertIs(ts.login(pin=b"123456"), sess)

    def test_login_not_authenticated_state_raises(self):
        # open() returned a session but state is still public -> not authenticated.
        sess = FakeSession(state=SessionState.RO_PUBLIC_SESSION)
        token = FakeToken(flags=PRESENT, session=sess)
        ts = self._session(token)
        with self.assertRaises(PIVAuthenticationError):
            ts.login(pin=b"123456")

    def test_login_failed_state_closes_session(self):
        sess = FakeSession(state=SessionState.RO_PUBLIC_SESSION)
        token = FakeToken(flags=PRESENT, session=sess)
        ts = self._session(token)
        with self.assertRaises(PIVAuthenticationError):
            ts.login(pin=b"123456")
        self.assertTrue(sess.closed)


if __name__ == "__main__":
    unittest.main()
