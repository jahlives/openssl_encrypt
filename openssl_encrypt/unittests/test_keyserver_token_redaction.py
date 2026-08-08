#!/usr/bin/env python3
"""
`keyserver show-token` must not print the bearer token (gitlab#178).

The handler used to reveal the first 8 and last 4 characters of the stored
API token with a plain `eprint`, bypassing `debug_secret()` — the single
chokepoint every other secret in this codebase goes through.

Twelve characters of a bearer token is key material, and stderr is not a
private channel: it lands in terminal scrollback, it is merged by `2>&1`,
and the desktop GUI keeps a persistent debug log. The token authenticates
uploads and lookups against the keyserver, so it is exactly the kind of
value the chokepoint exists for.

The command still has a job to do — telling you whether a token is set, and
letting you read it back deliberately — so it reports the redacted form by
default and the real value only under the existing `--debug
--unsafe-show-secrets` gate.
"""

import argparse
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock

from openssl_encrypt.modules.debug_redaction import set_show_secrets

TOKEN = "kst_live_A1B2C3D4E5F6G7H8I9J0abcdefghijkl"


class _FakeConfig:
    """Stands in for KeyserverConfig: only the two members show-token uses."""

    def __init__(self, token, path):
        self._token = token
        self.api_token_file = path

    def load_api_token(self):
        return self._token


def _run_show_token(token):
    """Drive the real handler and capture what it writes to stderr."""
    from openssl_encrypt.modules import crypt_cli

    tmp = tempfile.mkdtemp()
    config = _FakeConfig(token, os.path.join(tmp, "api_token"))
    args = argparse.Namespace(keyserver_action="show-token")
    captured = io.StringIO()

    with mock.patch(
        "openssl_encrypt.plugins.keyserver.KeyserverConfig.from_file", return_value=config
    ):
        with redirect_stderr(captured):
            crypt_cli.handle_keyserver_command(args)
    return captured.getvalue()


class TestShowTokenRedaction(unittest.TestCase):
    def setUp(self):
        set_show_secrets(False)
        self.addCleanup(set_show_secrets, False)

    def test_no_part_of_the_token_is_printed(self):
        output = _run_show_token(TOKEN)

        self.assertNotIn(TOKEN, output, "the whole token was printed")
        self.assertNotIn(TOKEN[:8], output, "the first 8 characters were printed")
        self.assertNotIn(TOKEN[-4:], output, "the last 4 characters were printed")

    def test_the_redacted_form_still_says_a_token_is_set(self):
        """The command has to stay useful: it answers "is one configured?"."""
        output = _run_show_token(TOKEN)

        self.assertIn("redacted", output.lower())
        self.assertIn("api_token", output, "the token file path is no longer reported")

    def test_a_short_token_is_not_revealed_either(self):
        """The old masking revealed everything below 13 characters as stars,
        but the length itself leaked and the branch was easy to get wrong.
        """
        short = "abcd"
        output = _run_show_token(short)
        self.assertNotIn(short, output)

    def test_the_unsafe_gate_still_reveals_it(self):
        """Reading your own token back is a legitimate thing to want.

        It goes through the same explicit opt-in as every other secret
        (`--debug --unsafe-show-secrets`), rather than a private rule.
        """
        set_show_secrets(True)
        output = _run_show_token(TOKEN)
        self.assertIn(TOKEN, output)

    def test_no_token_configured_is_reported_plainly(self):
        output = _run_show_token(None)
        self.assertIn("No API token set", output)


if __name__ == "__main__":
    unittest.main()
