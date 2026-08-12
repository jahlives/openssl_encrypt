#!/usr/bin/env python3
"""
The `--` separator must not defeat redaction or trigger a keyring deletion
(security review of gitlab#177).

gitlab#177 made `--` a supported spelling in the argv layer. Two places that
scan argv did not learn about it, and both have a security consequence.

**The debug argv dump printed the keyserver credential.**
`sanitize_argv_for_debug` redacts the token *immediately after* the
`set-token`/`login` positional. With `--` in between it redacted the
separator and printed the credential verbatim:

    crypt --debug keyserver set-token -- -Xy3SECRET
    -> [..., 'set-token', '<redacted: 2 bytes, ...>', '-Xy3SECRET']

`--` is exactly what a user must type when the token starts with `-`, and
base64url tokens and JWT segments legitimately do. stderr is not a private
channel: it reaches terminal scrollback, is merged by `2>&1`, and the
desktop GUI keeps a persistent debug log.

**`--keyring-remove` deleted a stored password from a command that was not
asking for it.** That scan is a raw membership test over the whole of
`sys.argv`, running before any parsing, with no `--` awareness and no
command-position check:

    crypt shred -- --keyring-remove important-label

deleted the keyring entry and exited 0, having shredded nothing -- when
what the user described was two files with those names.

Neither is a regression against a released version: the positional
redaction rule is itself new in 1.4.9 (1.4.8 did not redact that token at
all, which is the already-recorded gitlab#133-136 item), and `--` was not
usable in this layer before gitlab#177.
"""

import unittest
from unittest import mock

TOKEN = "-Xy3SECRETTOKENVALUE"


class TestTheDebugDumpNeverPrintsTheCredential(unittest.TestCase):
    def _sanitized(self, argv):
        from openssl_encrypt.modules.crypt_cli import sanitize_argv_for_debug

        return sanitize_argv_for_debug(argv)

    def test_a_token_after_the_separator_is_redacted(self):
        result = self._sanitized(["crypt", "--debug", "keyserver", "set-token", "--", TOKEN])
        self.assertNotIn(TOKEN, result, f"the bearer token was printed in cleartext: {result}")

    def test_the_separator_itself_is_not_redacted_instead(self):
        """The bug in one line: `--` consumed the redaction and the token
        walked straight through."""
        result = self._sanitized(["crypt", "--debug", "keyserver", "set-token", "--", TOKEN])
        self.assertIn("--", result, "the separator was redacted instead of the credential")

    def test_a_login_identifier_after_the_separator_is_redacted(self):
        """login's identifier is a credential too (gitlab#171)."""
        result = self._sanitized(["crypt", "--debug", "keyserver", "login", "--", "-user@x.test"])
        self.assertNotIn("-user@x.test", result, str(result))

    def test_the_ordinary_form_still_redacts(self):
        """The negative arm: the fix must not break the case that worked."""
        result = self._sanitized(["crypt", "--debug", "keyserver", "set-token", TOKEN])
        self.assertNotIn(TOKEN, result)

    def test_several_separators_do_not_shift_the_redaction(self):
        result = self._sanitized(["crypt", "keyserver", "set-token", "--", "--", TOKEN])
        self.assertNotIn(TOKEN, result, str(result))

    def test_a_non_secret_argv_is_untouched(self):
        argv = ["crypt", "encrypt", "-i", "a.txt", "--", "-o.txt"]
        self.assertEqual(self._sanitized(list(argv)), argv)


class TestKeyringRemoveOnlyFiresWhenAsked(unittest.TestCase):
    """A destructive credential operation must not be reachable from an
    argv position that means something else."""

    def _run_prescan(self, argv):
        """Drive main() far enough to hit the pre-scan, capturing any
        keyring deletion. Returns the label it tried to delete, or None.

        main(), not main_with_args(): the pre-scan runs in main() before any
        parsing, which is exactly why it sees raw argv.
        """
        from openssl_encrypt.modules import crypt_cli

        deleted = []

        class _FakeKeyring:
            @staticmethod
            def delete_password(service, label):
                deleted.append(label)

        with mock.patch.dict("sys.modules", {"keyring": _FakeKeyring}):
            with mock.patch.object(crypt_cli.sys, "argv", list(argv)):
                try:
                    crypt_cli.main()
                except SystemExit:
                    pass
                except Exception:
                    # Anything past the pre-scan is irrelevant here.
                    pass
        return deleted[0] if deleted else None

    def test_a_label_after_the_separator_is_not_deleted(self):
        self.assertIsNone(
            self._run_prescan(["crypt", "shred", "--", "--keyring-remove", "important-label"]),
            "a keyring entry was deleted by a command that was shredding files "
            "named --keyring-remove and important-label",
        )

    def test_it_still_works_when_actually_requested(self):
        """The load-bearing negative arm: refusing everything would break
        the feature instead of fixing it."""
        self.assertEqual(
            self._run_prescan(["crypt", "--keyring-remove", "my-label"]),
            "my-label",
        )

    def test_the_equals_spelling_works_too(self):
        """`--keyring-remove=LABEL` is one token; the old scan missed it
        entirely, so the option silently did nothing."""
        self.assertEqual(
            self._run_prescan(["crypt", "--keyring-remove=my-label"]),
            "my-label",
        )

    def test_a_label_after_a_command_is_not_deleted(self):
        """The option is top-level. Appearing after a subcommand means it is
        that subcommand's argument, not this one."""
        self.assertIsNone(
            self._run_prescan(["crypt", "encrypt", "-i", "f", "--keyring-remove", "label"])
        )


if __name__ == "__main__":
    unittest.main()
