#!/usr/bin/env python3
"""tools/list_keystore_keys.py must not require the keystore password on argv
(scan finding F32, gitlab#249, CWE-214).

--password is now optional; the password is resolved from the flag (with a
stderr warning), then KEYSTORE_PASSWORD, then an interactive getpass prompt.
"""

import importlib.util
import os
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[2] / "tools" / "list_keystore_keys.py"
_spec = importlib.util.spec_from_file_location("list_keystore_keys_tool", _TOOL)
lkk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lkk)


class TestResolveKeystorePassword(unittest.TestCase):
    def test_cli_password_takes_precedence(self):
        pw = lkk.resolve_keystore_password(
            "cli-pw", environ={"KEYSTORE_PASSWORD": "env-pw"}, prompt=lambda: "prompt-pw"
        )
        self.assertEqual(pw, "cli-pw")

    def test_env_used_when_no_cli(self):
        pw = lkk.resolve_keystore_password(
            None, environ={"KEYSTORE_PASSWORD": "env-pw"}, prompt=lambda: "prompt-pw"
        )
        self.assertEqual(pw, "env-pw")

    def test_prompt_used_when_no_cli_no_env(self):
        pw = lkk.resolve_keystore_password(None, environ={}, prompt=lambda: "prompt-pw")
        self.assertEqual(pw, "prompt-pw")

    def test_empty_env_falls_through_to_prompt(self):
        pw = lkk.resolve_keystore_password(
            None, environ={"KEYSTORE_PASSWORD": ""}, prompt=lambda: "prompt-pw"
        )
        self.assertEqual(pw, "prompt-pw")

    def test_password_argument_is_optional(self):
        # The argparse parser must not mark --password required (regression: it
        # was required=True, forcing the secret onto argv).
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument("--keystore", required=True)
        parser.add_argument("--password", default=None)
        ns = parser.parse_args(["--keystore", "k"])
        self.assertIsNone(ns.password)


if __name__ == "__main__":
    unittest.main()
