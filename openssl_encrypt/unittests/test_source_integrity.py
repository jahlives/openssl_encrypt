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


class TestHashFile(unittest.TestCase):
    """SHA-512 file hashing."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _file(self, name: str, data: bytes) -> Path:
        path = Path(self.tmpdir) / name
        path.write_bytes(data)
        return path

    def test_empty_file_known_digest(self) -> None:
        """SHA-512 of the empty input matches the published KAT."""
        from openssl_encrypt.integrity.manifest_core import hash_file

        expected = (
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )
        self.assertEqual(hash_file(self._file("empty", b"")), expected)

    def test_abc_known_digest(self) -> None:
        """SHA-512 of b'abc' matches the published KAT."""
        from openssl_encrypt.integrity.manifest_core import hash_file

        expected = (
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
        self.assertEqual(hash_file(self._file("abc", b"abc")), expected)

    def test_handles_large_nonutf8_content(self) -> None:
        """Binary / non-UTF-8 content hashes without error (chunked read)."""
        from openssl_encrypt.integrity.manifest_core import hash_file

        data = bytes(range(256)) * 8192  # 2 MiB, all byte values
        digest = hash_file(self._file("blob", data))
        self.assertEqual(len(digest), 128)  # SHA-512 hex length


class TestBuildManifest(unittest.TestCase):
    """Canonical, reproducible manifest construction."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.root = Path(self.tmpdir)
        (self.root / "pkg").mkdir()
        (self.root / "pkg" / "a.py").write_text("alpha\n", encoding="utf-8")
        (self.root / "pkg" / "b.py").write_text("beta\n", encoding="utf-8")

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_manifest_structure(self) -> None:
        """Manifest carries schema/algorithm/fingerprint and per-file entries."""
        from openssl_encrypt.integrity.manifest_core import (
            HASH_ALGORITHM,
            SCHEMA_VERSION,
            build_manifest,
        )

        m = build_manifest(self.root, ["pkg/a.py", "pkg/b.py"], key_fingerprint="DEADBEEF")
        self.assertEqual(m["schema_version"], SCHEMA_VERSION)
        self.assertEqual(m["hash_algorithm"], HASH_ALGORITHM)
        self.assertEqual(m["key_fingerprint"], "DEADBEEF")
        self.assertEqual(set(m["files"]), {"pkg/a.py", "pkg/b.py"})
        self.assertTrue(m["files"]["pkg/a.py"].startswith("sha512:"))

    def test_no_timestamp_or_commit_fields(self) -> None:
        """Reproducibility (Q5): no volatile provenance fields in the payload."""
        from openssl_encrypt.integrity.manifest_core import build_manifest

        m = build_manifest(self.root, ["pkg/a.py"])
        self.assertNotIn("generated_at_utc", m)
        self.assertNotIn("git_commit", m)

    def test_excludes_self_check_omitted(self) -> None:
        """Missing protected file is a hard error (fail closed)."""
        from openssl_encrypt.integrity.manifest_core import ManifestError, build_manifest

        with self.assertRaises(ManifestError):
            build_manifest(self.root, ["pkg/a.py", "pkg/missing.py"])

    def test_rejects_symlink_entry(self) -> None:
        """A symlinked protected path is rejected (no following links)."""
        from openssl_encrypt.integrity.manifest_core import ManifestError, build_manifest

        link = self.root / "pkg" / "link.py"
        try:
            os.symlink(self.root / "pkg" / "a.py", link)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not supported on this platform")
        with self.assertRaises(ManifestError):
            build_manifest(self.root, ["pkg/link.py"])

    def test_rejects_symlink_escape(self) -> None:
        """A path resolving outside the repo root (via symlinked dir) is rejected."""
        from openssl_encrypt.integrity.manifest_core import ManifestError, build_manifest

        outside = Path(self.tmpdir).parent / "outside_secret.py"
        outside.write_text("secret\n", encoding="utf-8")
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        linkdir = self.root / "escape"
        try:
            os.symlink(Path(self.tmpdir).parent, linkdir)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not supported on this platform")
        with self.assertRaises(ManifestError):
            build_manifest(self.root, ["escape/outside_secret.py"])


class TestSerializeManifest(unittest.TestCase):
    """Deterministic canonical serialization."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.root = Path(self.tmpdir)
        for name in ("z.py", "a.py", "m.py"):
            (self.root / name).write_text(name, encoding="utf-8")

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_deterministic_regardless_of_entry_order(self) -> None:
        """Same tree + same files in any order -> byte-identical manifest."""
        from openssl_encrypt.integrity.manifest_core import build_manifest, serialize_manifest

        m1 = build_manifest(self.root, ["z.py", "a.py", "m.py"], key_fingerprint="K")
        m2 = build_manifest(self.root, ["m.py", "z.py", "a.py"], key_fingerprint="K")
        self.assertEqual(serialize_manifest(m1), serialize_manifest(m2))

    def test_ends_with_newline_and_is_bytes(self) -> None:
        """Serialized form is UTF-8 bytes ending in a single newline."""
        from openssl_encrypt.integrity.manifest_core import build_manifest, serialize_manifest

        blob = serialize_manifest(build_manifest(self.root, ["a.py"]))
        self.assertIsInstance(blob, bytes)
        self.assertTrue(blob.endswith(b"\n"))
        self.assertFalse(blob.endswith(b"\n\n"))

    def test_round_trips_as_json(self) -> None:
        """Serialized manifest parses back to an equal mapping."""
        import json

        from openssl_encrypt.integrity.manifest_core import build_manifest, serialize_manifest

        m = build_manifest(self.root, ["a.py", "m.py"], key_fingerprint="K")
        self.assertEqual(json.loads(serialize_manifest(m).decode("utf-8")), m)


class TestVerifyFiles(unittest.TestCase):
    """Hash comparison against a manifest (tamper detection, no signature)."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.root = Path(self.tmpdir)
        (self.root / "pkg").mkdir()
        (self.root / "pkg" / "a.py").write_text("alpha\n", encoding="utf-8")
        (self.root / "pkg" / "b.py").write_text("beta\n", encoding="utf-8")
        from openssl_encrypt.integrity.manifest_core import build_manifest

        self.entries = ["pkg/a.py", "pkg/b.py"]
        self.manifest = build_manifest(self.root, self.entries, key_fingerprint="K")

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_unmodified_tree_all_ok(self) -> None:
        """An untouched tree verifies clean."""
        from openssl_encrypt.integrity.verify import OK, verify_files

        result = verify_files(self.root, self.manifest)
        self.assertTrue(result.all_ok)
        self.assertTrue(all(s.status == OK for s in result.statuses))
        self.assertEqual(result.problems, [])

    def test_modified_file_detected(self) -> None:
        """A one-byte change flips the file to MODIFIED and fails overall."""
        from openssl_encrypt.integrity.verify import MODIFIED, verify_files

        (self.root / "pkg" / "a.py").write_text("alpha!\n", encoding="utf-8")
        result = verify_files(self.root, self.manifest)
        self.assertFalse(result.all_ok)
        statuses = {s.path: s.status for s in result.statuses}
        self.assertEqual(statuses["pkg/a.py"], MODIFIED)
        self.assertEqual(statuses["pkg/b.py"], "OK")

    def test_missing_file_detected(self) -> None:
        """A deleted protected file is reported MISSING."""
        from openssl_encrypt.integrity.verify import MISSING, verify_files

        (self.root / "pkg" / "a.py").unlink()
        result = verify_files(self.root, self.manifest)
        self.assertFalse(result.all_ok)
        statuses = {s.path: s.status for s in result.statuses}
        self.assertEqual(statuses["pkg/a.py"], MISSING)

    def test_symlink_swap_detected(self) -> None:
        """Replacing a protected file with a symlink is treated as MISSING."""
        from openssl_encrypt.integrity.verify import MISSING, verify_files

        target = self.root / "pkg" / "a.py"
        target.unlink()
        try:
            os.symlink(self.root / "pkg" / "b.py", target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not supported on this platform")
        result = verify_files(self.root, self.manifest)
        statuses = {s.path: s.status for s in result.statuses}
        self.assertEqual(statuses["pkg/a.py"], MISSING)

    def test_unsupported_algorithm_fails_closed(self) -> None:
        """A manifest declaring an unknown hash algorithm is rejected."""
        from openssl_encrypt.integrity.verify import VerifyError, verify_files

        bad = dict(self.manifest)
        bad["hash_algorithm"] = "md5"
        with self.assertRaises(VerifyError):
            verify_files(self.root, bad)


if __name__ == "__main__":
    unittest.main()
