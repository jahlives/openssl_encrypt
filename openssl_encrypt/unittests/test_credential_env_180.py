#!/usr/bin/env python3
"""Credential-channel follow-ups from the #154/#159 review (gitlab#180).

1. `$OPENSSL_ENCRYPT_SIGNER_PASSPHRASE` is consumed up front on the
   `encrypt --sign-with` path, before the plugin/HSM/keyserver machinery runs,
   and passed to resolve_credential as explicit= (like `sign` does).
2. `info` can request the second password non-interactively via --hidden-header,
   so a GUI/CI caller can read a keyed hidden file's metadata through the env
   channel instead of only a tty prompt.
3. The fd second-password blank check routes through the canonical
   credential_env.validated rule rather than a bytes-only `.strip()`, so Unicode
   whitespace is treated the same across all channels.
"""

import argparse
import os
import unittest

from openssl_encrypt.modules.credential_env import CredentialError

SIGNER_ENV = "OPENSSL_ENCRYPT_SIGNER_PASSPHRASE"
SECOND_ENV = "OPENSSL_ENCRYPT_SECOND_PASSWORD"


def _restore_env(test, name):
    had, old = name in os.environ, os.environ.get(name)

    def restore():
        if had:
            os.environ[name] = old
        else:
            os.environ.pop(name, None)

    test.addCleanup(restore)


class TestEarlySignerConsume(unittest.TestCase):
    """Item 1: encrypt --sign-with consumes the passphrase before plugins run."""

    def setUp(self):
        _restore_env(self, SIGNER_ENV)
        os.environ.pop(SIGNER_ENV, None)

    def _consume(self, **kw):
        from openssl_encrypt.modules.crypt_cli import _consume_encrypt_signer_passphrase

        base = dict(action="encrypt", sign_with=None)
        base.update(kw)
        return _consume_encrypt_signer_passphrase(argparse.Namespace(**base))

    def test_consumes_and_removes_on_encrypt_sign_with(self):
        os.environ[SIGNER_ENV] = "pw"
        self.assertEqual(self._consume(sign_with="alice"), "pw")
        # Removed here, before any plugin/HSM/keyserver code could inherit it.
        self.assertNotIn(SIGNER_ENV, os.environ)

    def test_no_signing_request_leaves_env_untouched(self):
        os.environ[SIGNER_ENV] = "pw"
        self.assertIsNone(self._consume(sign_with=None))
        self.assertIn(SIGNER_ENV, os.environ)

    def test_non_encrypt_action_leaves_env_untouched(self):
        os.environ[SIGNER_ENV] = "pw"
        self.assertIsNone(self._consume(action="decrypt", sign_with="alice"))
        self.assertIn(SIGNER_ENV, os.environ)

    def test_encrypt_call_site_passes_explicit(self):
        # Lock the wiring: the encrypt --sign-with resolve_credential call must
        # receive explicit= (the early-consumed value), not re-consume the env
        # late inside resolve_credential.
        import ast
        import inspect

        from openssl_encrypt.modules import crypt_cli

        tree = ast.parse(inspect.getsource(crypt_cli.main_with_args))
        wired = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "resolve_credential"
            and {"env_name", "explicit"} <= {kw.arg for kw in node.keywords}
        ]
        self.assertTrue(wired, "encrypt --sign-with must pass explicit= to resolve_credential")


class TestInfoCanUseEnvChannel(unittest.TestCase):
    """Item 2: info reaches the env channel via --hidden-header."""

    def setUp(self):
        _restore_env(self, SECOND_ENV)
        os.environ.pop(SECOND_ENV, None)

    def _resolve(self, **kw):
        from openssl_encrypt.modules.crypt_cli import _resolve_second_password

        base = dict(
            second_password_fd=None,
            second_password=None,
            second_password_prompt=False,
            hidden_header=False,
            legacy_format=False,
            action="info",
        )
        base.update(kw)
        return _resolve_second_password(argparse.Namespace(**base))

    def test_info_with_hidden_header_reads_the_env_value(self):
        os.environ[SECOND_ENV] = "hpw"
        self.assertEqual(self._resolve(hidden_header=True), b"hpw")

    def test_info_without_request_ignores_env_but_consumes_it(self):
        os.environ[SECOND_ENV] = "hpw"
        # No request flag -> not used, but still consumed (removed) so a child
        # process cannot inherit it.
        self.assertIsNone(self._resolve(hidden_header=False))
        self.assertNotIn(SECOND_ENV, os.environ)

    def test_monolithic_parser_accepts_hidden_header_for_info(self):
        # info has no subparser; assert the flag it is told to pass is actually
        # accepted on that route (previously argparse rejected it).
        import subprocess
        import sys

        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "openssl_encrypt.crypt",
                "info",
                "--hidden-header",
                "-i",
                "/nonexistent/definitely-missing.enc",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotIn("unrecognized arguments", proc.stderr)
        self.assertNotIn("--hidden-header", proc.stderr.split("\n")[0] if proc.stderr else "")


class TestFdBlankRuleMatchesOtherChannels(unittest.TestCase):
    """Item 3: the fd channel uses the same blank rule as flag/env."""

    def setUp(self):
        _restore_env(self, SECOND_ENV)
        os.environ.pop(SECOND_ENV, None)

    def _resolve_fd(self, data: bytes, action="encrypt"):
        from openssl_encrypt.modules.crypt_cli import _resolve_second_password

        r, w = os.pipe()
        os.write(w, data)
        os.close(w)
        try:
            return _resolve_second_password(
                argparse.Namespace(
                    second_password_fd=r,
                    second_password=None,
                    second_password_prompt=False,
                    hidden_header=True,
                    legacy_format=False,
                    action=action,
                )
            )
        finally:
            os.close(r)

    def test_unicode_whitespace_only_is_now_refused_when_encrypting(self):
        # U+00A0 (0xC2 0xA0) was rejected via --second-password but accepted via
        # the fd channel's bytes-only strip(). Now both agree.
        with self.assertRaises(CredentialError):
            self._resolve_fd(" ".encode("utf-8"))

    def test_a_real_fd_value_is_returned(self):
        self.assertEqual(self._resolve_fd(b"realpw\n"), b"realpw")

    def test_empty_fd_still_refused_when_encrypting(self):
        with self.assertRaises(CredentialError):
            self._resolve_fd(b"")

    def test_blank_fd_allowed_when_decrypting(self):
        # Decrypt preserves data: a file written with such a value must open.
        self.assertEqual(
            self._resolve_fd(" ".encode("utf-8"), action="decrypt"),
            " ".encode("utf-8"),
        )


class TestEnvChannelNewlineMatchesDirection(unittest.TestCase):
    """Item 3 follow-up: the env channel rejects newlines on encrypt but stays
    data-preserving on read, like the fd/flag channels (gitlab#180)."""

    def setUp(self):
        _restore_env(self, SECOND_ENV)
        os.environ.pop(SECOND_ENV, None)

    def _resolve(self, value, action):
        from openssl_encrypt.modules.crypt_cli import _resolve_second_password

        os.environ[SECOND_ENV] = value
        return _resolve_second_password(
            argparse.Namespace(
                second_password_fd=None,
                second_password=None,
                second_password_prompt=False,
                hidden_header=True,
                legacy_format=False,
                action=action,
            )
        )

    def test_newline_bearing_value_is_refused_when_encrypting(self):
        with self.assertRaises(CredentialError):
            self._resolve("foo\nbar", action="encrypt")

    def test_newline_bearing_value_is_readable_when_decrypting(self):
        # A file written via fd/flag with such a key must open through the env too.
        self.assertEqual(self._resolve("foo\nbar", action="decrypt"), b"foo\nbar")

    def test_blank_env_value_is_refused_on_every_path(self):
        with self.assertRaises(CredentialError):
            self._resolve("   ", action="decrypt")


if __name__ == "__main__":
    unittest.main()
