#!/usr/bin/env python3
"""Security-review follow-ups from gitlab#144 (gitlab#147), 1.5.x port.

1. Strict UTF-8 encodes on secret material leaked a byte through a
   UnicodeEncodeError message printed verbatim by the generic CLI handler. The
   debug_secret chokepoint, the rekey password encode, the recovery
   _passphrase_kek and _read_password encodes now use surrogateescape and refuse
   the residual lone-high-surrogate case value-free.
2. security_logger._value_looks_secret now fails closed instead of raising from
   inside log scrubbing.
3. Secret env vars deleted without register_consumed_secret left redaction
   inert; the deletion sites now register first.
4. -p/--password on the recovery commands now warns about process-list exposure.
"""

import argparse
import io
import os
import unittest
from contextlib import redirect_stderr


def _restore_fingerprint_registry(test):
    from openssl_encrypt.modules import security_logger

    saved = {k: v.copy() for k, v in security_logger._consumed_secret_fingerprints.items()}

    def restore():
        security_logger._consumed_secret_fingerprints.clear()
        security_logger._consumed_secret_fingerprints.update(saved)

    test.addCleanup(restore)


# A lone HIGH surrogate: outside surrogateescape's round-trip range, so it still
# raises UnicodeEncodeError on encode -- the case every item-1/2 wrap must catch.
LONE_SURROGATE = "\ud800"


class TestDebugSecretNeverLeaksAByte(unittest.TestCase):
    """Item 1a: debug_secret must not raise (or echo bytes) on an unencodable str."""

    def test_lone_surrogate_is_redacted_not_raised(self):
        from openssl_encrypt.modules.debug_redaction import debug_secret

        rendered = debug_secret("label", "secret" + LONE_SURROGATE)
        self.assertIn("redacted", rendered)
        self.assertNotIn(LONE_SURROGATE, rendered)

    def test_normal_value_still_fingerprinted(self):
        from openssl_encrypt.modules.debug_redaction import debug_secret

        rendered = debug_secret("", "hello")
        self.assertIn("sha256:", rendered)
        self.assertIn("5 bytes", rendered)


class TestPassphraseKekRefusesCleanly(unittest.TestCase):
    """Item 1c: _passphrase_kek refuses a lone surrogate without echoing bytes."""

    def test_lone_surrogate_raises_value_error_without_the_char(self):
        from openssl_encrypt.modules.recovery_slots import _passphrase_kek

        with self.assertRaises(ValueError) as cm:
            _passphrase_kek(
                "pw" + LONE_SURROGATE, b"\x00" * 16, time_cost=3, memory_cost=65536, parallelism=1
            )
        self.assertNotIn(LONE_SURROGATE, str(cm.exception))
        self.assertNotIsInstance(cm.exception, UnicodeEncodeError)


class TestValueLooksSecretFailsClosed(unittest.TestCase):
    """Item 2: _value_looks_secret returns True (fail closed) instead of raising."""

    def test_lone_surrogate_does_not_propagate(self):
        from openssl_encrypt.modules import security_logger

        _restore_fingerprint_registry(self)
        security_logger.register_consumed_secret("CRYPT_PASSWORD", "some-real-secret")
        self.assertTrue(security_logger._value_looks_secret("x" + LONE_SURROGATE))


class TestRegisteredSecretSurvivesEnvRemoval(unittest.TestCase):
    """Item 3: a registered secret is still redacted after the env var is gone."""

    def test_registered_value_is_matched_without_the_env_var(self):
        from openssl_encrypt.modules import security_logger

        _restore_fingerprint_registry(self)
        secret = "rekey-value-not-in-env-9f3a"
        self.assertFalse(security_logger._value_looks_secret(secret))
        security_logger.register_consumed_secret("OPENSSL_ENCRYPT_REKEY_PASSWORD", secret)
        self.assertTrue(security_logger._value_looks_secret(secret))


class TestRecoveryPasswordWarnsAboutProcessList(unittest.TestCase):
    """Item 4: -p/--password on the recovery commands warns like the others."""

    def setUp(self):
        self._had = "CRYPT_PASSWORD" in os.environ
        self._old = os.environ.get("CRYPT_PASSWORD")
        os.environ.pop("CRYPT_PASSWORD", None)

        def restore():
            if self._had:
                os.environ["CRYPT_PASSWORD"] = self._old
            else:
                os.environ.pop("CRYPT_PASSWORD", None)

        self.addCleanup(restore)

    def test_password_flag_emits_process_list_warning(self):
        from openssl_encrypt.modules.recovery_slots import _read_password

        err = io.StringIO()
        with redirect_stderr(err):
            result = _read_password(argparse.Namespace(password="hunter2"))
        self.assertEqual(result, b"hunter2")
        self.assertIn("visible in process list", err.getvalue())

    def test_no_warning_when_password_comes_from_env(self):
        from openssl_encrypt.modules.recovery_slots import _read_password

        os.environ["CRYPT_PASSWORD"] = "from-env"
        err = io.StringIO()
        with redirect_stderr(err):
            result = _read_password(argparse.Namespace(password=None))
        self.assertEqual(result, b"from-env")
        self.assertNotIn("visible in process list", err.getvalue())

    def test_lone_surrogate_password_refused_without_echoing_the_char(self):
        from openssl_encrypt.modules.recovery_slots import _read_password

        with redirect_stderr(io.StringIO()):
            with self.assertRaises(ValueError) as cm:
                _read_password(argparse.Namespace(password="pw" + LONE_SURROGATE))
        self.assertNotIn(LONE_SURROGATE, str(cm.exception))
        self.assertNotIsInstance(cm.exception, UnicodeEncodeError)


if __name__ == "__main__":
    unittest.main()
