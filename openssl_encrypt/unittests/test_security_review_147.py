#!/usr/bin/env python3
"""Security-review follow-ups from gitlab#144 (gitlab#147).

1. A strict UTF-8 encode on secret material raises UnicodeEncodeError whose
   message embeds a byte of the value; that message is printed verbatim by the
   generic CLI handler, outside debug_secret(). The encode sites now use
   surrogateescape and, for the residual lone-high-surrogate case, refuse
   without echoing bytes.
2. security_logger._value_looks_secret could raise from inside log scrubbing on
   the same input; it now fails closed (treats the value as secret).
3. A secret env var deleted without register_consumed_secret left redaction
   inert from that point on; the deletion sites now register first.
4. -p/--password on the recovery commands now warns about process-list exposure,
   like --recovery-code and --rekey-password.
"""

import argparse
import io
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

        # Must not raise, and must not contain the raw character.
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
        # Populate the ring so the fingerprint branch (the encode) is reached.
        security_logger.register_consumed_secret("CRYPT_PASSWORD", "some-real-secret")
        # An unencodable logged value must not raise out of the scrubber.
        self.assertTrue(security_logger._value_looks_secret("x" + LONE_SURROGATE))


class TestRegisteredSecretSurvivesEnvRemoval(unittest.TestCase):
    """Item 3: a registered secret is still redacted after the env var is gone."""

    def test_registered_value_is_matched_without_the_env_var(self):
        from openssl_encrypt.modules import security_logger

        _restore_fingerprint_registry(self)
        secret = "rekey-value-not-in-env-9f3a"
        # No env var set for it; registration alone must make it match.
        self.assertFalse(security_logger._value_looks_secret(secret))
        security_logger.register_consumed_secret("OPENSSL_ENCRYPT_REKEY_PASSWORD", secret)
        self.assertTrue(security_logger._value_looks_secret(secret))


class TestRecoveryPasswordWarnsAboutProcessList(unittest.TestCase):
    """Item 4: -p/--password on the recovery commands warns like the others."""

    def test_password_flag_emits_process_list_warning(self):
        from openssl_encrypt.modules.recovery_slots import _read_password

        args = argparse.Namespace(password="hunter2")
        err = io.StringIO()
        with redirect_stderr(err):
            result = _read_password(args, env_pw=None)
        self.assertEqual(result, b"hunter2")
        self.assertIn("visible in process list", err.getvalue())

    def test_no_warning_when_password_comes_from_env(self):
        from openssl_encrypt.modules.recovery_slots import _read_password

        args = argparse.Namespace(password=None)
        err = io.StringIO()
        with redirect_stderr(err):
            result = _read_password(args, env_pw="from-env")
        self.assertEqual(result, b"from-env")
        self.assertNotIn("visible in process list", err.getvalue())

    def test_lone_surrogate_password_refused_without_echoing_the_char(self):
        # Defense-in-depth: _read_password's own encode must not leak a byte on
        # an unencodable value either (gitlab#147 review follow-up).
        from openssl_encrypt.modules.recovery_slots import _read_password

        args = argparse.Namespace(password="pw" + LONE_SURROGATE)
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(ValueError) as cm:
                _read_password(args, env_pw=None)
        self.assertNotIn(LONE_SURROGATE, str(cm.exception))
        self.assertNotIsInstance(cm.exception, UnicodeEncodeError)


if __name__ == "__main__":
    unittest.main()
