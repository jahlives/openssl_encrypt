#!/usr/bin/env python3
"""
Unit tests for the source-code integrity protection subsystem.

This suite is developed test-first (TDD) alongside the openssl_encrypt.integrity
package. It is organised by implementation step:

- Step 1: allowlist loading and validation (this commit)

Security-relevant cases (adversarial allowlist entries, path traversal, symlinks,
tamper detection, signature failures, fail-closed behaviour) are covered as the
corresponding implementation lands.
"""

import os
import tempfile
import unittest
from pathlib import Path

from openssl_encrypt.integrity.allowlist import (
    AllowlistError,
    default_allowlist_path,
    load_allowlist,
)


class TestAllowlistLoading(unittest.TestCase):
    """Parsing and validation of the protected-files allowlist."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write(self, content: str) -> Path:
        path = Path(self.tmpdir) / "protected_files.txt"
        path.write_text(content, encoding="utf-8")
        return path

    def test_parses_simple_list(self) -> None:
        """Plain entries are returned verbatim."""
        path = self._write("a/b.py\nc/d.py\n")
        self.assertEqual(load_allowlist(path), ["a/b.py", "c/d.py"])

    def test_skips_comments_and_blank_lines(self) -> None:
        """Lines that are blank or start with '#' are ignored."""
        path = self._write("# header comment\n\na/b.py\n   \n# trailing\nc/d.py\n")
        self.assertEqual(load_allowlist(path), ["a/b.py", "c/d.py"])

    def test_strips_surrounding_whitespace(self) -> None:
        """Leading/trailing whitespace on an entry is stripped."""
        path = self._write("  a/b.py  \n\tc/d.py\t\n")
        self.assertEqual(load_allowlist(path), ["a/b.py", "c/d.py"])

    def test_result_is_sorted_and_deduplicated(self) -> None:
        """Output is deterministically sorted with duplicates removed."""
        path = self._write("z/last.py\na/first.py\nz/last.py\nm/mid.py\n")
        self.assertEqual(
            load_allowlist(path),
            ["a/first.py", "m/mid.py", "z/last.py"],
        )

    def test_rejects_absolute_path(self) -> None:
        """Absolute paths are rejected (manifest is repo-relative only)."""
        path = self._write("/etc/passwd\n")
        with self.assertRaises(AllowlistError):
            load_allowlist(path)

    def test_rejects_parent_traversal(self) -> None:
        """Entries containing a '..' component are rejected."""
        path = self._write("a/../../secrets.py\n")
        with self.assertRaises(AllowlistError):
            load_allowlist(path)

    def test_rejects_bare_parent_traversal(self) -> None:
        """A leading '..' is rejected."""
        path = self._write("../outside.py\n")
        with self.assertRaises(AllowlistError):
            load_allowlist(path)

    def test_rejects_backslash_separators(self) -> None:
        """Backslash path separators are rejected (repo uses forward slashes)."""
        path = self._write("a\\b.py\n")
        with self.assertRaises(AllowlistError):
            load_allowlist(path)

    def test_missing_file_raises(self) -> None:
        """A nonexistent allowlist path raises AllowlistError, not bare OSError."""
        with self.assertRaises(AllowlistError):
            load_allowlist(Path(self.tmpdir) / "does-not-exist.txt")

    def test_empty_allowlist_raises(self) -> None:
        """An allowlist with no real entries is an error (fail closed)."""
        path = self._write("# only comments\n\n")
        with self.assertRaises(AllowlistError):
            load_allowlist(path)


class TestShippedAllowlist(unittest.TestCase):
    """The real protected_files.txt shipped in the package."""

    def test_default_allowlist_path_exists(self) -> None:
        """default_allowlist_path() points at a file that exists."""
        self.assertTrue(default_allowlist_path().is_file())

    def test_shipped_allowlist_loads(self) -> None:
        """The shipped allowlist parses and is non-trivial."""
        entries = load_allowlist(default_allowlist_path())
        self.assertGreater(len(entries), 30)

    def test_shipped_entries_all_exist_on_disk(self) -> None:
        """Every protected path resolves to a real file in the repo tree."""
        # Repo root = three levels up from this test file:
        #   <root>/openssl_encrypt/unittests/test_source_integrity.py
        repo_root = Path(__file__).resolve().parents[2]
        entries = load_allowlist(default_allowlist_path())
        missing = [e for e in entries if not (repo_root / e).is_file()]
        self.assertEqual(missing, [], f"Allowlist references missing files: {missing}")

    def test_shipped_allowlist_excludes_generated_version(self) -> None:
        """The auto-generated version.py must never be protected."""
        entries = load_allowlist(default_allowlist_path())
        self.assertNotIn("openssl_encrypt/version.py", entries)


if __name__ == "__main__":
    unittest.main()
