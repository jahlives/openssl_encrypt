#!/usr/bin/env python3
"""
The `--debug` argv dump must redact every spelling argparse accepts
(gitlab#209).

`sanitize_argv_for_debug` decided what to redact by exact string membership
in `SECRET_VALUE_CLI_OPTIONS`, plus `--opt=value` and a `-p`-prefix rule.
argparse accepts two further spellings and neither was covered. The dump is
only ever reached on an argv argparse *accepted*, so "spellings argparse
accepts" is exactly the set this function has to cover.

Run against the released v1.4.8 sanitizer, lifted from the tag:

    LEAK  ['secret.txt', '-apHunter2']
    LEAK  ['-ap', 'Hunter2']
    safe  ['secret.txt', '-p<redacted: 7 bytes>']

The encrypt subparser declares `-a/--armor`, `-f/--overwrite` and
`-s/--shred` as store_true beside the value-taking `-p/--password`, so
argparse binds `-apHunter2` to `-a` plus `-p=Hunter2`. And no parser sets
`allow_abbrev=False`, so `--manifest-p` is an unambiguous prefix of
`--manifest-password`.

The fail-closed direction here is the OPPOSITE of the command scan's. There,
an unrecognised option is assumed to take a value, so a command is not
mistaken for one. Here, an unresolvable option must be assumed to be secret:
printing a password is worse than redacting a filename.
"""

import unittest

PASSWORD = "Hunter2-Correct-Horse"


class _SanitizerTestCase(unittest.TestCase):
    def sanitized(self, *argv):
        from openssl_encrypt.modules.crypt_cli import sanitize_argv_for_debug

        return sanitize_argv_for_debug(["crypt", *argv])

    def assertNoLeak(self, *argv):
        result = self.sanitized(*argv)
        self.assertNotIn(
            PASSWORD,
            " ".join(result),
            f"the password was printed in cleartext: {result}",
        )
        return result


class TestBundledShortOptions(_SanitizerTestCase):
    """`-ap<value>` is `-a` plus `-p <value>` to argparse."""

    def test_an_attached_value_after_a_bundle_is_redacted(self):
        self.assertNoLeak("--debug", "encrypt", "-i", "f", f"-ap{PASSWORD}")

    def test_a_separated_value_after_a_bundle_is_redacted(self):
        self.assertNoLeak("--debug", "encrypt", "-i", "f", "-ap", PASSWORD)

    def test_a_longer_bundle_is_redacted(self):
        self.assertNoLeak("--debug", "encrypt", "-i", "f", f"-afsp{PASSWORD}")

    def test_the_plain_forms_still_redact(self):
        """The negative arm: the two spellings that already worked."""
        self.assertNoLeak("--debug", "encrypt", "-i", "f", f"-p{PASSWORD}")
        self.assertNoLeak("--debug", "encrypt", "-i", "f", "-p", PASSWORD)

    def test_a_bundle_with_no_secret_letter_is_untouched(self):
        """-afs takes no value; the next token is a real argument."""
        result = self.sanitized("--debug", "encrypt", "-afs", "-i", "plain.txt")
        self.assertIn("plain.txt", result, f"a non-secret argument was redacted: {result}")


class TestAbbreviatedLongOptions(_SanitizerTestCase):
    """argparse accepts unambiguous prefixes unless allow_abbrev=False."""

    def test_an_abbreviated_secret_option_is_redacted(self):
        for form in ("--passw", "--pass", "--pas"):
            with self.subTest(form=form):
                self.assertNoLeak("--debug", "encrypt", "-i", "f", form, PASSWORD)

    def test_an_abbreviated_manifest_password_is_redacted(self):
        self.assertNoLeak(
            "--debug", "create-usb", "--usb-path", "/media/x", "--manifest-p", PASSWORD
        )

    def test_the_equals_form_of_an_abbreviation_is_redacted(self):
        self.assertNoLeak("--debug", "encrypt", "-i", "f", f"--passw={PASSWORD}")

    def test_an_unrelated_abbreviation_is_untouched(self):
        result = self.sanitized("--debug", "encrypt", "--verb", "-i", "plain.txt")
        self.assertIn("plain.txt", result, f"a non-secret argument was redacted: {result}")


class TestAmbiguityFailsClosed(_SanitizerTestCase):
    """Unresolvable must mean "assume secret" here.

    This is the opposite of the command scan's default, on purpose:
    printing a password is worse than redacting a filename.
    """

    def test_an_ambiguous_prefix_of_a_secret_option_is_redacted(self):
        """`--pa` could be --password or --password-policy; redact anyway."""
        self.assertNoLeak("--debug", "encrypt", "-i", "f", "--pa", PASSWORD)


class TestOrdinaryArgvIsUnchanged(_SanitizerTestCase):
    """Over-redacting would make --debug useless for its actual purpose."""

    def test_a_command_line_with_no_secret_is_untouched(self):
        argv = ["crypt", "--debug", "encrypt", "-i", "a.txt", "-o", "b.enc", "--armor"]
        from openssl_encrypt.modules.crypt_cli import sanitize_argv_for_debug

        self.assertEqual(sanitize_argv_for_debug(list(argv)), argv)

    def test_the_input_and_output_paths_survive(self):
        result = self.sanitized("--debug", "encrypt", "-i", "a.txt", "-o", "b.enc", "-p", PASSWORD)
        self.assertIn("a.txt", result)
        self.assertIn("b.enc", result)


if __name__ == "__main__":
    unittest.main()
