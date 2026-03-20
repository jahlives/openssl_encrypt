#!/usr/bin/env python3
"""
Tests for stdout/stderr separation.

Verifies that eprint() writes to stderr and never to stdout,
ensuring clean data output on stdout for piping.
"""

import io
import sys
import unittest


class TestEprint(unittest.TestCase):
    """Tests for the eprint() helper function."""

    def test_eprint_writes_to_stderr(self):
        """Verify eprint() output goes to stderr."""
        from openssl_encrypt.modules.crypt_utils import eprint

        captured = io.StringIO()
        old_stderr = sys.stderr
        try:
            sys.stderr = captured
            eprint("test message")
        finally:
            sys.stderr = old_stderr

        self.assertEqual(captured.getvalue(), "test message\n")

    def test_eprint_does_not_write_to_stdout(self):
        """Verify eprint() does not write anything to stdout."""
        from openssl_encrypt.modules.crypt_utils import eprint

        captured_stdout = io.StringIO()
        captured_stderr = io.StringIO()
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        try:
            sys.stdout = captured_stdout
            sys.stderr = captured_stderr
            eprint("test message")
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        self.assertEqual(captured_stdout.getvalue(), "")

    def test_eprint_supports_multiple_args(self):
        """Verify eprint() handles multiple arguments like print()."""
        from openssl_encrypt.modules.crypt_utils import eprint

        captured = io.StringIO()
        old_stderr = sys.stderr
        try:
            sys.stderr = captured
            eprint("hello", "world")
        finally:
            sys.stderr = old_stderr

        self.assertEqual(captured.getvalue(), "hello world\n")

    def test_eprint_supports_end_kwarg(self):
        """Verify eprint() passes through the end= keyword argument."""
        from openssl_encrypt.modules.crypt_utils import eprint

        captured = io.StringIO()
        old_stderr = sys.stderr
        try:
            sys.stderr = captured
            eprint("no newline", end="")
        finally:
            sys.stderr = old_stderr

        self.assertEqual(captured.getvalue(), "no newline")

    def test_eprint_supports_sep_kwarg(self):
        """Verify eprint() passes through the sep= keyword argument."""
        from openssl_encrypt.modules.crypt_utils import eprint

        captured = io.StringIO()
        old_stderr = sys.stderr
        try:
            sys.stderr = captured
            eprint("a", "b", "c", sep="-")
        finally:
            sys.stderr = old_stderr

        self.assertEqual(captured.getvalue(), "a-b-c\n")

    def test_eprint_does_not_override_explicit_file(self):
        """Verify eprint() respects explicit file= argument."""
        from openssl_encrypt.modules.crypt_utils import eprint

        captured = io.StringIO()
        eprint("to custom file", file=captured)

        self.assertEqual(captured.getvalue(), "to custom file\n")

    def test_eprint_flush_kwarg(self):
        """Verify eprint() passes through the flush= keyword argument."""
        from openssl_encrypt.modules.crypt_utils import eprint

        captured = io.StringIO()
        old_stderr = sys.stderr
        try:
            sys.stderr = captured
            eprint("flushed", flush=True)
        finally:
            sys.stderr = old_stderr

        self.assertEqual(captured.getvalue(), "flushed\n")


if __name__ == "__main__":
    unittest.main()
