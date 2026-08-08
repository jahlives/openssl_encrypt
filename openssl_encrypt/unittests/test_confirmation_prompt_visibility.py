#!/usr/bin/env python3
"""
A confirmation question must appear where its warning appeared (gitlab#174).

`eprint` writes to stderr; `input("...")` writes its prompt to **stdout**.
Every security confirmation in this tool mixes the two: the warning block
goes to stderr, the question to stdout. Redirect stdout -- `crypt ... >
out.txt`, a pipeline, a GUI that captures stdout as data -- and the user is
left with a frightening warning followed by an apparently hung program, no
visible question, and no idea that typing anything other than `yes` is what
protects them.

The sites that matter are the ones where refusing is the safe answer:

  * the TOFU key-change confirmation on `identity import` and the
    `identity delete` gate,
  * the keyserver "trust and import this key?" prompt,
  * the telemetry opt-out, whose whole point is a deliberate choice,
  * the KDF-cost ceiling override, which exists to stop a crafted file
    exhausting memory,
  * the shared `request_confirmation` helper.

The codebase already had `tty_write` for exactly this: it writes to
/dev/tty so the message survives redirection of both streams, and falls
back to stderr when there is no terminal.

These tests assert on where the PROMPT goes, not on the answer handling,
because that is what was broken -- the yes/no logic was always correct.
"""

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock


class _PromptTestCase(unittest.TestCase):
    def capture(self, call, answer="no"):
        """Run `call` with stdin answered, returning (stdout, stderr, tty)."""
        out, err, tty = io.StringIO(), io.StringIO(), []

        with mock.patch("openssl_encrypt.modules.crypt_utils.tty_write", tty.append):
            with mock.patch("builtins.input", lambda *a: (tty.extend(a), answer)[1]):
                with redirect_stdout(out), redirect_stderr(err):
                    result = call()
        return out.getvalue(), err.getvalue(), "".join(tty), result

    def assertPromptNotOnStdout(self, stdout, marker):
        self.assertNotIn(
            marker,
            stdout,
            "the confirmation question was written to stdout; redirecting "
            "stdout hides the question but not the warning",
        )


class TestTheSharedHelper(_PromptTestCase):
    def test_the_question_does_not_go_to_stdout(self):
        from openssl_encrypt.modules.crypt_utils import request_confirmation

        stdout, _err, tty, _result = self.capture(lambda: request_confirmation("Delete it?"))
        self.assertPromptNotOnStdout(stdout, "Delete it?")
        self.assertIn("Delete it?", tty, "the question reached neither the tty nor stderr")

    def test_yes_still_confirms(self):
        """The answer handling was never the bug and must not change."""
        from openssl_encrypt.modules.crypt_utils import request_confirmation

        for answer in ("y", "yes", "Y", "YES"):
            with self.subTest(answer=answer):
                _o, _e, _t, result = self.capture(
                    lambda: request_confirmation("Proceed?"), answer=answer
                )
                self.assertTrue(result)

    def test_anything_else_refuses(self):
        from openssl_encrypt.modules.crypt_utils import request_confirmation

        for answer in ("n", "no", "", "maybe", "ye"):
            with self.subTest(answer=answer):
                _o, _e, _t, result = self.capture(
                    lambda: request_confirmation("Proceed?"), answer=answer
                )
                self.assertFalse(result)

    def test_end_of_input_refuses(self):
        """A closed stdin must mean "no", not a traceback -- the whole point
        is that the unattended case does not silently proceed."""
        from openssl_encrypt.modules.crypt_utils import request_confirmation

        def raise_eof(*_args):
            raise EOFError

        with mock.patch("builtins.input", raise_eof):
            with mock.patch("openssl_encrypt.modules.crypt_utils.tty_write", lambda *_a: True):
                self.assertFalse(request_confirmation("Proceed?"))


class TestThePromptHelperItself(unittest.TestCase):
    """`prompt_and_read` is what the call sites use."""

    def test_the_prompt_goes_through_tty_write(self):
        from openssl_encrypt.modules import crypt_utils

        seen = []
        with mock.patch.object(crypt_utils, "tty_write", seen.append):
            with mock.patch("builtins.input", lambda *_a: "answer"):
                value = crypt_utils.prompt_and_read("Question? ")

        self.assertEqual(value, "answer")
        self.assertEqual(seen, ["Question? "])

    def test_input_is_called_without_a_prompt_argument(self):
        """If the prompt were still passed to input(), it would go to stdout
        as well as the tty -- which is the bug, half-fixed."""
        from openssl_encrypt.modules import crypt_utils

        calls = []

        def spy(*args):
            calls.append(args)
            return "x"

        with mock.patch.object(crypt_utils, "tty_write", lambda *_a: True):
            with mock.patch("builtins.input", spy):
                crypt_utils.prompt_and_read("Question? ")

        self.assertEqual(calls, [()], f"input() was given a prompt: {calls}")

    def test_end_of_input_is_an_empty_answer(self):
        from openssl_encrypt.modules import crypt_utils

        def raise_eof(*_args):
            raise EOFError

        with mock.patch.object(crypt_utils, "tty_write", lambda *_a: True):
            with mock.patch("builtins.input", raise_eof):
                self.assertEqual(crypt_utils.prompt_and_read("Q? "), "")


class TestNoSecurityGateStillPromptsToStdout(unittest.TestCase):
    """A lint over the call sites, so a new gate cannot reintroduce it.

    Reads the AST rather than the text: `input("...")` with a string
    argument is the shape that writes to stdout, wherever it appears.
    """

    # Wholly interactive flows that own stdout for their entire run -- a
    # menu is not a security gate, and its prompts belong with its output.
    ALLOWED_FILES = {"config_wizard.py", "password_policy.py"}

    def test_no_module_calls_input_with_a_prompt(self):
        import ast
        import os

        modules_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules"
        )
        offenders = []
        for root, _dirs, files in os.walk(modules_dir):
            for name in sorted(files):
                if not name.endswith(".py") or name in self.ALLOWED_FILES:
                    continue
                path = os.path.join(root, name)
                with open(path, encoding="utf-8") as handle:
                    tree = ast.parse(handle.read(), filename=path)
                for node in ast.walk(tree):
                    if (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == "input"
                        and node.args
                    ):
                        offenders.append(f"  {name}:{node.lineno}")

        self.assertFalse(
            offenders,
            "input() called with a prompt, which writes it to stdout while "
            "the warning above it goes to stderr:\n"
            + "\n".join(offenders)
            + "\n\nUse prompt_and_read() instead.",
        )


if __name__ == "__main__":
    unittest.main()
