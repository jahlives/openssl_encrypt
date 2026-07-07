"""Tests for the signed per-package plugin manifest logic (H2 [PLUGIN-1]).

Covers the deterministic build, the parser, and the tree-matching check
(unlisted/missing/mismatch detection). The signature layer is exercised
separately once GPG fixtures are available; here we test the byte-exact
manifest logic that the signature protects.
"""

import hashlib
import os
import shutil
import tempfile
import unittest

from openssl_encrypt.modules.plugin_system.plugin_manifest import (
    MANIFEST_HEADER,
    build_manifest,
    check_manifest_matches_tree,
    parse_manifest,
)


class TestManifestLogic(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _write(self, rel, data: bytes):
        path = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def _make_package(self):
        self._write("__init__.py", b"from .helper import x\n")
        self._write("helper.py", b"x = 1\n")
        self._write("_private.py", b"y = 2\n")  # underscore sibling — must be covered
        self._write("sub/__init__.py", b"z = 3\n")  # nested subpackage
        self._write("sub/deep.py", b"w = 4\n")
        self._write("data.txt", b"not python\n")  # non-.py: not covered

    def test_build_is_deterministic_and_sorted(self):
        self._make_package()
        m1 = build_manifest(self.dir)
        m2 = build_manifest(self.dir)
        self.assertEqual(m1, m2)
        lines = m1.decode().splitlines()
        self.assertEqual(lines[0], MANIFEST_HEADER)
        rels = [ln.split("  ", 1)[1] for ln in lines[1:]]
        self.assertEqual(rels, sorted(rels))  # sorted by relpath
        # Every .py (incl. underscore + nested) covered; the .txt is not.
        self.assertIn("_private.py", rels)
        self.assertIn("sub/deep.py", rels)
        self.assertNotIn("data.txt", rels)

    def test_parse_round_trip(self):
        self._make_package()
        parsed = parse_manifest(build_manifest(self.dir))
        # Each entry's digest equals sha256 of the file.
        for rel, digest in parsed.items():
            with open(os.path.join(self.dir, rel), "rb") as f:
                self.assertEqual(digest, hashlib.sha256(f.read()).hexdigest())

    def test_matches_tree_ok(self):
        self._make_package()
        manifest = build_manifest(self.dir)
        ok, reason, paths = check_manifest_matches_tree(self.dir, manifest)
        self.assertTrue(ok, reason)
        # verified_paths includes every covered .py
        self.assertEqual(
            {os.path.basename(p) for p in paths},
            {"__init__.py", "helper.py", "_private.py", "deep.py"},
        )

    def test_extra_unlisted_py_is_refused(self):
        self._make_package()
        manifest = build_manifest(self.dir)
        # Attacker drops a new sibling not in the manifest.
        self._write("evil.py", b"import os\n")
        ok, reason, _ = check_manifest_matches_tree(self.dir, manifest)
        self.assertFalse(ok)
        self.assertIn("unlisted", reason)

    def test_tampered_sibling_is_refused(self):
        self._make_package()
        manifest = build_manifest(self.dir)
        # Modify a sibling after the manifest was built.
        self._write("helper.py", b"x = 999  # tampered\n")
        ok, reason, _ = check_manifest_matches_tree(self.dir, manifest)
        self.assertFalse(ok)
        self.assertIn("hash mismatch", reason)

    def test_missing_listed_file_is_refused(self):
        self._make_package()
        manifest = build_manifest(self.dir)
        os.remove(os.path.join(self.dir, "helper.py"))
        ok, reason, _ = check_manifest_matches_tree(self.dir, manifest)
        self.assertFalse(ok)
        self.assertIn("missing", reason)

    def test_malformed_manifest_rejected(self):
        with self.assertRaises(ValueError):
            parse_manifest(b"not the header\nx\n")
        with self.assertRaises(ValueError):
            parse_manifest((MANIFEST_HEADER + "\nZZZ  bad-digest\n").encode())
        # Whitespace-mangled manifest must not parse to the same thing (the
        # signature covers exact bytes; the parser rejects a broken grammar).
        with self.assertRaises(ValueError):
            parse_manifest((MANIFEST_HEADER + "\n" + "a" * 64 + " onlyonespace\n").encode())

    def test_native_and_bytecode_modules_covered(self):
        """Finding 1: .so/.pyd/.pyc siblings are importable and MUST be covered
        (not just .py) so a swapped native module is caught."""
        self._write("__init__.py", b"x = 1\n")
        self._write("_native.so", b"\x7fELF fake native module\n")
        self._write("cached.pyc", b"fake bytecode\n")
        manifest = build_manifest(self.dir)
        rels = [ln.split("  ", 1)[1] for ln in manifest.decode().splitlines()[1:]]
        self.assertIn("_native.so", rels)
        self.assertIn("cached.pyc", rels)
        # Swapping the native module is a hash mismatch.
        self._write("_native.so", b"\x7fELF MALICIOUS build\n")
        ok, reason, _ = check_manifest_matches_tree(self.dir, manifest)
        self.assertFalse(ok)
        self.assertIn("hash mismatch", reason)

    def test_escaping_symlink_fails_closed(self):
        """Finding 2: a module symlink escaping the package root must fail
        closed (ManifestError), never be silently skipped."""
        from openssl_encrypt.modules.plugin_system.plugin_manifest import (
            ManifestError,
            build_manifest as _bm,
        )

        outside = os.path.join(tempfile.mkdtemp(), "evil.py")
        with open(outside, "wb") as f:
            f.write(b"BAD = 1\n")
        self._write("__init__.py", b"x = 1\n")
        os.symlink(outside, os.path.join(self.dir, "linked.py"))
        with self.assertRaises(ManifestError):
            _bm(self.dir)
        shutil.rmtree(os.path.dirname(outside), ignore_errors=True)

    def test_symlinked_module_rejected(self):
        """A symlinked module file (even in-root) is rejected — a symlink is not
        a vouched-for shipped byte sequence and can be repointed."""
        from openssl_encrypt.modules.plugin_system.plugin_manifest import (
            ManifestError,
            build_manifest as _bm,
        )

        self._write("__init__.py", b"x = 1\n")
        self._write("real.py", b"y = 2\n")
        os.symlink(os.path.join(self.dir, "real.py"), os.path.join(self.dir, "alias.py"))
        with self.assertRaises(ManifestError):
            _bm(self.dir)


if __name__ == "__main__":
    unittest.main()
