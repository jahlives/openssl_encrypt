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
    # The prompt is gated on whether a controlling terminal is reachable for
    # getpass (which reads /dev/tty), not on whether stdin itself is a tty —
    # so that `armor ... | decrypt -i /dev/stdin` can still prompt.
    with mock.patch("openssl_encrypt.modules.crypt_cli._can_prompt_on_tty", return_value=is_tty):
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

    def test_keyed_prompts_when_stdin_piped_but_terminal_present(self):
        """Regression for `armor ... | decrypt -i /dev/stdin`: stdin carries the
        piped ciphertext (so it is NOT a tty), but a controlling terminal exists
        and getpass can prompt on /dev/tty. The fallback must prompt rather than
        silently give up just because stdin is not a tty."""
        with mock.patch(
            "openssl_encrypt.modules.crypt_cli._can_prompt_on_tty", return_value=True
        ), mock.patch("openssl_encrypt.modules.crypt_cli.sys.stdin") as stdin, mock.patch(
            "getpass.getpass", return_value="entered-pw"
        ) as gp:
            stdin.isatty.return_value = False  # piped ciphertext on stdin
            out = _resolve_second_password_with_fallback(_args(self.keyed), None)
        self.assertEqual(out, b"entered-pw")
        gp.assert_called_once()


class TestArmoredStdinKeyedDecrypt(unittest.TestCase):
    """End-to-end regression for `armor keyed.enc | decrypt -i /dev/stdin`.

    The armored, keyed-hidden ciphertext arrives on stdin (a pipe). The auto
    fallback must materialise stdin, de-armor it, detect the keyed header, and
    prompt (on /dev/tty) for the second password — all without an explicit
    --second-password* flag. Before the fix the prompt was skipped (stdin not a
    tty + /dev/stdin excluded + resolution ran before de-armor), so decryption
    failed with a security-validation error.
    """

    def setUp(self):
        from openssl_encrypt.modules.armor import armor

        self.dir = tempfile.mkdtemp()
        keyed = os.path.join(self.dir, "keyed.enc")
        encrypt_file(
            PLAINTEXT,
            keyed,
            PRIMARY,
            hidden_header=True,
            second_password=SECOND,
            hash_config=MINIMAL_CONFIG,
            quiet=True,
            encryption_data="aes-gcm",
            algorithm="aes-gcm",
        )
        with open(keyed, "rb") as f:
            self.armored = armor(f.read())
        self.out = os.path.join(self.dir, "out.dec")

    def tearDown(self):
        import shutil

        shutil.rmtree(self.dir, ignore_errors=True)

    def _run_decrypt_stdin(self, payload, second_pw):
        import sys as _sys

        from openssl_encrypt.modules.crypt_cli import main as cli_main

        fake_stdin = mock.MagicMock()
        fake_stdin.buffer.read.return_value = payload
        fake_stdin.isatty.return_value = False  # piped

        argv = [
            "crypt.py",
            "--quiet",
            "decrypt",
            "--input",
            "/dev/stdin",
            "--output",
            self.out,
            "--password",
            PRIMARY,
            "--force-password",
        ]
        saved_argv = _sys.argv
        codes = []
        _sys.argv = argv
        devnull = open(os.devnull, "w", encoding="utf-8")
        saved_stdout = _sys.stdout
        _sys.stdout = devnull
        try:
            with mock.patch("openssl_encrypt.modules.crypt_cli.sys.stdin", fake_stdin), mock.patch(
                "openssl_encrypt.modules.crypt_cli._can_prompt_on_tty", return_value=True
            ), mock.patch("getpass.getpass", return_value=second_pw), mock.patch(
                "sys.exit", side_effect=lambda c=0: codes.append(c)
            ):
                cli_main()
        finally:
            _sys.stdout = saved_stdout
            devnull.close()
            _sys.argv = saved_argv
        return codes

    def test_armored_keyed_stdin_decrypts_with_prompted_second_password(self):
        self._run_decrypt_stdin(self.armored, SECOND)
        self.assertTrue(os.path.exists(self.out), "decrypt produced no output file")
        with open(self.out, "rb") as f:
            self.assertEqual(f.read(), PLAINTEXT)


class TestCanPromptOnTty(unittest.TestCase):
    """The terminal-availability gate keys off /dev/tty, not stdin.isatty()."""

    def test_true_when_dev_tty_openable(self):
        from openssl_encrypt.modules.crypt_cli import _can_prompt_on_tty

        with mock.patch("openssl_encrypt.modules.crypt_cli.os.open", return_value=3), mock.patch(
            "openssl_encrypt.modules.crypt_cli.os.close"
        ):
            self.assertTrue(_can_prompt_on_tty())

    def test_false_when_no_tty_anywhere(self):
        from openssl_encrypt.modules.crypt_cli import _can_prompt_on_tty

        with mock.patch(
            "openssl_encrypt.modules.crypt_cli.os.open", side_effect=OSError
        ), mock.patch("openssl_encrypt.modules.crypt_cli.sys.stdin") as si, mock.patch(
            "openssl_encrypt.modules.crypt_cli.sys.stdout"
        ) as so, mock.patch(
            "openssl_encrypt.modules.crypt_cli.sys.stderr"
        ) as se:
            si.isatty.return_value = False
            so.isatty.return_value = False
            se.isatty.return_value = False
            self.assertFalse(_can_prompt_on_tty())


if __name__ == "__main__":
    unittest.main()
