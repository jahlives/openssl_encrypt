#!/usr/bin/env python3
"""
Unit tests for stdout/stderr separation.

Tests that eprint() correctly writes to stderr and does not write to stdout.
All code in English as per project requirements.
"""

import io
import sys
from unittest import mock

import pytest

from openssl_encrypt.modules.crypt_utils import eprint


class TestEprint:
    """Tests for the eprint() helper function."""

    def test_eprint_writes_to_stderr(self):
        """Test that eprint() output goes to stderr."""
        with mock.patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            eprint("test message")
            assert mock_stderr.getvalue() == "test message\n"

    def test_eprint_does_not_write_to_stdout(self):
        """Test that eprint() does not write anything to stdout."""
        with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            with mock.patch("sys.stderr", new_callable=io.StringIO):
                eprint("test message")
            assert mock_stdout.getvalue() == ""

    def test_eprint_multiple_args(self):
        """Test that eprint() handles multiple arguments like print()."""
        with mock.patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            eprint("hello", "world")
            assert mock_stderr.getvalue() == "hello world\n"

    def test_eprint_custom_sep(self):
        """Test that eprint() respects the sep keyword argument."""
        with mock.patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            eprint("a", "b", "c", sep="-")
            assert mock_stderr.getvalue() == "a-b-c\n"

    def test_eprint_custom_end(self):
        """Test that eprint() respects the end keyword argument."""
        with mock.patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            eprint("no newline", end="")
            assert mock_stderr.getvalue() == "no newline"

    def test_eprint_does_not_override_explicit_file(self):
        """Test that eprint() respects an explicitly passed file argument."""
        buf = io.StringIO()
        eprint("to buffer", file=buf)
        assert buf.getvalue() == "to buffer\n"

    def test_eprint_flush(self):
        """Test that eprint() passes through the flush keyword."""
        with mock.patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            eprint("flushed", flush=True)
            assert mock_stderr.getvalue() == "flushed\n"
