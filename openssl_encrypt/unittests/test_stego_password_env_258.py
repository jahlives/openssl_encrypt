#!/usr/bin/env python3
"""The steganography password must be accepted via the CRYPT_STEGO_PASSWORD
environment variable, not only on argv (scan findings F21/F22, gitlab#258,
CWE-214).

The desktop GUI passed --stego-password on the child's command line, exposing it
in /proc/<pid>/cmdline. The CLI now consumes CRYPT_STEGO_PASSWORD from the
environment into args.stego_password (mirroring the main password's
CRYPT_PASSWORD channel), so the GUI can pass it out of band.
"""

import argparse
import os
import unittest

from openssl_encrypt.modules.crypt_cli import _resolve_stego_password_env


class TestStegoPasswordEnv(unittest.TestCase):
    def setUp(self):
        os.environ.pop("CRYPT_STEGO_PASSWORD", None)

    def tearDown(self):
        os.environ.pop("CRYPT_STEGO_PASSWORD", None)

    def _args(self, stego_password=None):
        ns = argparse.Namespace()
        ns.stego_password = stego_password
        return ns

    def test_env_populates_when_flag_absent(self):
        os.environ["CRYPT_STEGO_PASSWORD"] = "env-stego"
        args = _resolve_stego_password_env(self._args(stego_password=None))
        self.assertEqual(args.stego_password, "env-stego")
        # Consumed: removed from the environment so a child cannot inherit it.
        self.assertNotIn("CRYPT_STEGO_PASSWORD", os.environ)

    def test_explicit_flag_takes_precedence_but_env_is_still_consumed(self):
        os.environ["CRYPT_STEGO_PASSWORD"] = "env-stego"
        args = _resolve_stego_password_env(self._args(stego_password="flag-stego"))
        self.assertEqual(args.stego_password, "flag-stego")
        self.assertNotIn("CRYPT_STEGO_PASSWORD", os.environ)

    def test_absent_env_leaves_none(self):
        args = _resolve_stego_password_env(self._args(stego_password=None))
        self.assertIsNone(args.stego_password)

    def test_missing_attr_is_tolerated(self):
        os.environ["CRYPT_STEGO_PASSWORD"] = "env-stego"
        ns = argparse.Namespace()  # no stego_password attribute at all
        # Must not raise; the variable is still consumed.
        _resolve_stego_password_env(ns)
        self.assertNotIn("CRYPT_STEGO_PASSWORD", os.environ)

    def test_env_var_is_registered_for_log_redaction(self):
        # The stego password must be redacted in debug/error output while it is
        # live in the environment (before consume_env deletes it), so it belongs
        # in the security logger's secret-env list (review F-1, gitlab#258).
        from openssl_encrypt.modules.security_logger import _SECRET_ENV_VARS

        self.assertIn("CRYPT_STEGO_PASSWORD", _SECRET_ENV_VARS)


if __name__ == "__main__":
    unittest.main()
