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
    """Guard the regression: the early-exit paths must keep calling the helper."""

    def test_main_with_args_calls_the_helper_at_multiple_sites(self):
        from openssl_encrypt.modules import crypt_cli

        tree = ast.parse(inspect.getsource(crypt_cli.main_with_args))
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_warn_orphan_random_password"
        ]
        # top-level except + write-failure + cascade-diversity + two stego sites.
        self.assertGreaterEqual(len(calls), 5)


if __name__ == "__main__":
    unittest.main()
