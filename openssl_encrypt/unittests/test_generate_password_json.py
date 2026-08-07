#!/usr/bin/env python3
"""
Tests for `generate-password --json` (gitlab#187 / github#104).

The desktop GUI has always appended `--json` and parsed stdout as a JSON
object (`GeneratedPassword.fromJson`), but the flag did not exist and the
handler had no JSON path at all -- verified across every branch and release
tag. So GUI password generation never worked.

Two properties matter beyond "the flag parses":

  * The password is the machine-readable PAYLOAD on stdout and must NEVER
    reach stderr in this mode. The human path prints it to stderr behind a
    countdown, which is merged by `2>&1`, lands in scrollback and in the
    GUI's persistent debug log -- the reasoning already applied to
    `encrypt --random` (gitlab#152).
  * stdout carries exactly one JSON document and nothing else, because the
    GUI feeds all of stdout to a parser.
"""

import argparse
import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from openssl_encrypt.modules.crypt_cli_subparser import setup_generate_password_parser


def _parse(*argv):
    parser = argparse.ArgumentParser()
    setup_generate_password_parser(parser)
    return parser.parse_args(list(argv))


class TestParserAcceptsJson(unittest.TestCase):
    def test_json_flag_is_accepted(self):
        self.assertTrue(_parse("16", "--json").json)

    def test_the_gui_invocation_parses(self):
        """The exact argv shape CLIService.generatePassword builds."""
        args = _parse("20", "--use-lowercase", "--use-digits", "--json")
        self.assertTrue(args.json)

    def test_the_gui_diceware_invocation_parses(self):
        args = _parse("--dice", "--dice-count", "6", "--dice-sep", "-", "--json")
        self.assertTrue(args.json)

    def test_default_is_human_output(self):
        self.assertFalse(getattr(_parse("16"), "json", False))


class _HandlerTestCase(unittest.TestCase):
    """Drive the real handler and capture both streams."""

    def _run(self, **overrides):
        if overrides.get("dice"):
            # --dice is mutually exclusive with the character-class flags;
            # the GUI does not send them together either.
            overrides.setdefault("use_lowercase", False)
            overrides.setdefault("use_uppercase", False)
            overrides.setdefault("use_digits", False)
            overrides.setdefault("use_special", False)
        from openssl_encrypt.modules.crypt_cli import main_with_args

        base = dict(
            action="generate-password",
            length=16,
            use_lowercase=True,
            use_uppercase=True,
            use_digits=True,
            use_special=True,
            dice=False,
            dice_count=10,
            dice_sep="",
            dice_list=None,
            force_wordlist=False,
            json=True,
            password_policy="none",
            force_password=False,
            min_password_length=None,
            min_password_entropy=None,
            strict_strength=False,
            disable_common_password_check=False,
            custom_password_list=None,
            quiet=False,
            debug=False,
            verbose=False,
        )
        base.update(overrides)
        args = argparse.Namespace(**base)

        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as exit_ctx:
                main_with_args(args)
        return exit_ctx.exception.code, stdout.getvalue(), stderr.getvalue()


class TestCharacterModeJson(_HandlerTestCase):
    def test_emits_the_document_the_gui_parses(self):
        code, out, _err = self._run(length=20)
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["mode"], "character")
        self.assertEqual(data["length"], 20)
        self.assertEqual(len(data["password"]), 20)
        self.assertIsInstance(data["entropy_bits"], (int, float))
        self.assertIsInstance(data["strength"], str)

    def test_stdout_is_exactly_one_json_document(self):
        """The GUI feeds all of stdout to a parser; a banner would break it."""
        _code, out, _err = self._run()
        json.loads(out)

    def test_the_password_never_reaches_stderr(self):
        """stderr is merged by 2>&1, lands in scrollback and in the GUI's
        persistent debug log. In JSON mode stdout is the delivery channel."""
        _code, out, err = self._run()
        password = json.loads(out)["password"]
        self.assertNotIn(password, err)

    def test_no_countdown_display_in_json_mode(self):
        """The human path holds the password on screen behind a timer; that
        must not run when the caller asked for a document."""
        with mock.patch(
            "openssl_encrypt.modules.crypt_cli.display_password_with_timeout"
        ) as display:
            self._run()
        display.assert_not_called()


class TestDicewareModeJson(_HandlerTestCase):
    def test_emits_the_diceware_document(self):
        code, out, _err = self._run(dice=True, dice_count=5, dice_sep="-")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["mode"], "diceware")
        self.assertEqual(data["word_count"], 5)
        self.assertIsInstance(data["entropy_bits"], (int, float))
        self.assertEqual(data["password"].count("-"), 4)

    def test_the_passphrase_never_reaches_stderr(self):
        _code, out, err = self._run(dice=True, dice_count=5)
        self.assertNotIn(json.loads(out)["password"], err)

    def test_no_countdown_display_in_json_mode(self):
        with mock.patch(
            "openssl_encrypt.modules.crypt_cli.display_password_with_timeout"
        ) as display:
            self._run(dice=True, dice_count=5)
        display.assert_not_called()


class TestHumanModeUnchanged(_HandlerTestCase):
    def test_character_mode_still_uses_the_display_path(self):
        with mock.patch(
            "openssl_encrypt.modules.crypt_cli.display_password_with_timeout"
        ) as display:
            _code, out, _err = self._run(json=False)
        display.assert_called_once()
        self.assertEqual(out, "", "human mode must not write to stdout")

    def test_diceware_mode_still_uses_the_display_path(self):
        with mock.patch(
            "openssl_encrypt.modules.crypt_cli.display_password_with_timeout"
        ) as display:
            _code, out, _err = self._run(json=False, dice=True, dice_count=5)
        display.assert_called_once()
        self.assertEqual(out, "")


class TestCharacterModePolicyVerdict(_HandlerTestCase):
    """The character-mode policy check WARNS, it does not reject.

    Human mode shows that warning beside the password; a machine caller
    reads stderr only on a non-zero exit, so the verdict has to travel in
    the document or it is simply lost. JSON must not be stricter than the
    human path, and must not imply a guarantee the code does not give.
    """

    def test_a_satisfied_policy_is_reported(self):
        _code, out, _err = self._run(password_policy="standard", length=24)
        data = json.loads(out)
        self.assertTrue(data["policy_valid"])
        self.assertEqual(data["policy_warnings"], [])

    def test_a_failed_policy_is_reported_in_the_document(self):
        """Lowercase-only against the standard policy, which wants upper,
        digit and special: the password is still delivered (as in human
        mode) but the document says it does not satisfy the policy."""
        code, out, err = self._run(
            password_policy="standard",
            length=20,
            use_lowercase=True,
            use_uppercase=False,
            use_digits=False,
            use_special=False,
            force_password=True,
        )
        data = json.loads(out)
        self.assertEqual(code, 0, "human mode warns rather than failing; parity")
        self.assertFalse(data["policy_valid"])
        self.assertTrue(data["policy_warnings"], "the reason must be machine-readable")
        self.assertNotIn(data["password"], err)


class TestPolicyFailuresStayOnStderr(_HandlerTestCase):
    def test_a_policy_rejection_emits_no_partial_document(self):
        """A failure must not leave the GUI parsing half a document, and the
        error text belongs on stderr."""
        code, out, err = self._run(dice=True, dice_count=3, min_password_entropy=1000)
        self.assertNotEqual(code, 0)
        self.assertEqual(out.strip(), "")
        self.assertIn("entropy", err.lower())


if __name__ == "__main__":
    unittest.main()
