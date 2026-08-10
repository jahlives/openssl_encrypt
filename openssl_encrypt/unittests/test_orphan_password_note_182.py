#!/usr/bin/env python3
"""The orphan-password NOTE must fire from the early-exit paths too (gitlab#182 part 2).

The generated `--random-password-out` file is written before the ciphertext, so a
later failure can leave a 0600 orphan a retry then refuses with FileExistsError.
The NOTE that warns about it used to live only in the top-level `except`, so the
paths that `return 1` / `sys.exit(1)` (steganography failure, cascade-diversity
abort, the write-failure handler) skipped it. It is now a helper called from each.
"""

import argparse
import ast
import inspect
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr


class TestOrphanNoteHelper(unittest.TestCase):
    def _run(self, random_password_out, ciphertext_maybe_written=True):
        from openssl_encrypt.modules.crypt_cli import _warn_orphan_random_password

        err = io.StringIO()
        with redirect_stderr(err):
            _warn_orphan_random_password(
                argparse.Namespace(random_password_out=random_password_out),
                ciphertext_maybe_written=ciphertext_maybe_written,
            )
        return err.getvalue()

    def test_note_fires_when_the_file_exists(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "pw.txt")
            with open(path, "w") as f:
                f.write("secret\n")
            out = self._run(path)
        self.assertIn("NOTE:", out)
        self.assertIn(path, out)
        self.assertIn("--random-password-out", out)
        # The password value itself is never echoed.
        self.assertNotIn("secret", out)

    def test_no_note_when_the_file_does_not_exist(self):
        with tempfile.TemporaryDirectory() as d:
            out = self._run(os.path.join(d, "missing.txt"))
        self.assertEqual(out, "")

    def test_no_note_when_not_requested(self):
        self.assertEqual(self._run(None), "")

    def test_pre_ciphertext_variant_does_not_claim_the_file_is_decryptable(self):
        # At a pre-encryption abort / write failure the ciphertext provably does
        # not exist, so the NOTE must not tell the user to check decryptability
        # (gitlab#182 review follow-up).
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "pw.txt")
            with open(path, "w") as f:
                f.write("secret\n")
            out = self._run(path, ciphertext_maybe_written=False)
        self.assertIn("NOTE:", out)
        self.assertIn(path, out)
        self.assertNotIn("decryptable", out)
        self.assertNotIn("secret", out)
        self.assertIn("no usable encrypted file", out)


class TestEarlyExitPathsCallTheHelper(unittest.TestCase):
    """Guard the regression: since gitlab#223 the coverage is structural -- a
    try/finally around the dispatch (which catches every SystemExit/return-1
    site uniformly) plus the pre-dispatch write-failure site. Scattered
    per-site calls are exactly what proved incomplete twice (#182, the #222
    review), so this pins the finally-based shape instead of a site count."""

    def test_the_helper_is_called_from_a_finally_block(self):
        from openssl_encrypt.modules import crypt_cli

        tree = ast.parse(inspect.getsource(crypt_cli.main_with_args))

        def _calls_helper(node):
            return any(
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name)
                and n.func.id == "_warn_orphan_random_password"
                for n in ast.walk(node)
            )

        finally_calls = [
            t
            for t in ast.walk(tree)
            if isinstance(t, ast.Try) and any(_calls_helper(s) for s in t.finalbody)
        ]
        self.assertEqual(len(finally_calls), 1, "the dispatch finally must announce the orphan")
        # The call must be guarded by the completion flag (an unconditional
        # call would fire after every successful encrypt) and must pass the
        # on-disk fact rather than a hardcoded literal (gitlab#223 review
        # f1/f2: hardcoding False told users to delete the only credential
        # of a live ciphertext after a post-processing failure).
        finalbody_src = ast.unparse(ast.Module(body=finally_calls[0].finalbody, type_ignores=[]))
        self.assertIn("if not _encrypt_completed", finalbody_src)
        self.assertIn("ciphertext_maybe_written=_ciphertext_on_disk", finalbody_src)

    def test_only_the_write_failure_site_remains_outside_the_finally(self):
        from openssl_encrypt.modules import crypt_cli

        tree = ast.parse(inspect.getsource(crypt_cli.main_with_args))
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_warn_orphan_random_password"
        ]
        # finally + the pre-dispatch password-write-failure handler + the
        # signal handler (a signal death runs neither the finally nor
        # atexit). More sites means scattered wiring is creeping back in.
        self.assertEqual(len(calls), 3)


if __name__ == "__main__":
    unittest.main()
