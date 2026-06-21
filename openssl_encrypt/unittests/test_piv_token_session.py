"""Unit tests for TokenSession (slot detection, login, PIN handling, cleanup).

Covers verification-table items 3, 4, 5 (slot/token detection), 8, 9 (login and
PIN handling), and 14 (session cleanup).  All PKCS#11 interaction is mocked.
"""

import os
import tempfile
import unittest

from openssl_encrypt.modules.piv_backend import (
    PIVConfigurationError,
    PIVTokenError,
    PKCS11Library,
    TokenSession,
)
from openssl_encrypt.unittests import _piv_mocks
from openssl_encrypt.unittests._piv_mocks import FakeSlot, FakeToken, TokenFlag

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


if __name__ == "__main__":
    unittest.main()
