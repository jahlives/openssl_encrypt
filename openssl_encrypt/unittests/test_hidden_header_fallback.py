#!/usr/bin/env python3
"""
Tests for the interactive second-password fallback on decrypt.

On a bare `decrypt`, the CLI tries keyless first; if the file is hidden but not
keyless-peelable (i.e. keyed, or just random/corrupt), and the session is
interactive, it prompts once for a second password before failing. The prompt
is TTY-gated (never fires in a pipe/script) and suppressible with
--no-second-password-prompt. An explicit --second-password* always wins and
skips the peek/prompt entirely.

All code in English as per project requirements.
"""

import argparse
import contextlib
import os
import tempfile
import unittest
from unittest import mock

from openssl_encrypt.modules.crypt_cli import _resolve_second_password_with_fallback
from openssl_encrypt.modules.crypt_core import encrypt_file

MINIMAL_CONFIG = {
    "sha512": 5,
    "argon2": {
        "enabled": True,
        "time_cost": 1,
        "memory_cost": 512,
        "parallelism": 1,
        "type": "id",
    },
}
PRIMARY = "primary-pw"
SECOND = "the-second-pw"
PLAINTEXT = b"fallback test payload\n" * 8


def _args(input_file, **kw):
    base = dict(
        input=input_file,
        second_password=None,
        second_password_fd=None,
        second_password_prompt=False,
        no_second_password_prompt=False,
        legacy_format=False,
        action="decrypt",
    )
    base.update(kw)
    return argparse.Namespace(**base)


@contextlib.contextmanager
def _interactive(is_tty):
    with mock.patch("openssl_encrypt.modules.crypt_cli.sys.stdin") as stdin:
        stdin.isatty.return_value = is_tty
        yield


class TestSecondPasswordFallback(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.keyless = os.path.join(self.dir, "keyless.enc")
        self.keyed = os.path.join(self.dir, "keyed.enc")
        self.legacy = os.path.join(self.dir, "legacy.enc")
        common = dict(
            hash_config=MINIMAL_CONFIG, quiet=True, encryption_data="aes-gcm", algorithm="aes-gcm"
        )
        encrypt_file(PLAINTEXT, self.keyless, PRIMARY, hidden_header=True, **common)
        encrypt_file(
            PLAINTEXT, self.keyed, PRIMARY, hidden_header=True, second_password=SECOND, **common
        )
        encrypt_file(PLAINTEXT, self.legacy, PRIMARY, hidden_header=False, **common)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.dir, ignore_errors=True)

    def test_explicit_password_wins(self):
        with mock.patch("getpass.getpass") as gp:
            out = _resolve_second_password_with_fallback(_args(self.keyed), b"explicit")
        self.assertEqual(out, b"explicit")
        gp.assert_not_called()

    def test_keyless_no_prompt(self):
        with _interactive(True), mock.patch("getpass.getpass") as gp:
            out = _resolve_second_password_with_fallback(_args(self.keyless), None)
        self.assertIsNone(out)
        gp.assert_not_called()

    def test_legacy_no_prompt(self):
        with _interactive(True), mock.patch("getpass.getpass") as gp:
            out = _resolve_second_password_with_fallback(_args(self.legacy), None)
        self.assertIsNone(out)
        gp.assert_not_called()

    def test_keyed_prompts_and_returns_entry(self):
        with _interactive(True), mock.patch("getpass.getpass", return_value="entered-pw") as gp:
            out = _resolve_second_password_with_fallback(_args(self.keyed), None)
        self.assertEqual(out, b"entered-pw")
        gp.assert_called_once()

    def test_keyed_blank_aborts_to_none(self):
        with _interactive(True), mock.patch("getpass.getpass", return_value=""):
            out = _resolve_second_password_with_fallback(_args(self.keyed), None)
        self.assertIsNone(out)

    def test_keyed_optout_no_prompt(self):
        with _interactive(True), mock.patch("getpass.getpass") as gp:
            out = _resolve_second_password_with_fallback(
                _args(self.keyed, no_second_password_prompt=True), None
            )
        self.assertIsNone(out)
        gp.assert_not_called()

    def test_keyed_non_tty_no_prompt(self):
        with _interactive(False), mock.patch("getpass.getpass") as gp:
            out = _resolve_second_password_with_fallback(_args(self.keyed), None)
        self.assertIsNone(out)
        gp.assert_not_called()


if __name__ == "__main__":
    unittest.main()
