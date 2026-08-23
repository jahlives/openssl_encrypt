#!/usr/bin/env python3
"""Removed/unavailable ciphers must fail with specific errors (gitlab#297).

The 2026-08-23 fail-closed audit found three generic/masked failures on the
non-streaming decrypt path:

- ``camellia`` and non-streaming ``aes-ocb3`` files (both written by 1.4.x)
  fell through the dispatch to a generic "Unsupported encryption algorithm"
  with no removal cause or migration path;
- a missing ``threefish_native`` module was swallowed by the nonce-retry
  ``except Exception`` and re-raised as "authentication error" — a dependency
  problem masquerading as a wrong password.

Per maintainer decision (2026-08-23) aes-ocb3 STREAMING files remain
decryptable; only the non-streaming path refuses them, and the refusal says
so.
"""

import base64
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

from openssl_encrypt.modules.crypt_core import decrypt_file

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "testfiles", "format_versions")
PASSWORD = b"fixture-corpus-password-2026"


def _rewrite_algorithm(src_path: str, name: str, dest_dir: str) -> str:
    """Copy a fixture with its metadata algorithm renamed.

    Args:
        src_path: Existing fixture file.
        name: Algorithm name to write into the metadata header.
        dest_dir: Directory receiving the rewritten copy.

    Returns:
        Path of the rewritten file.
    """
    raw = open(src_path, "rb").read()
    head, sep, rest = raw.partition(b":")
    meta = json.loads(base64.b64decode(head))
    meta["encryption"]["algorithm"] = name
    out = os.path.join(dest_dir, os.path.basename(src_path) + "." + name)
    with open(out, "wb") as f:
        f.write(base64.b64encode(json.dumps(meta).encode()) + sep + rest)
    return out


class TestRemovedCipherErrors(unittest.TestCase):
    """camellia / non-streaming aes-ocb3 get pointed removal errors."""

    @classmethod
    def setUpClass(cls):
        """Prepare a temp dir shared by the rewritten fixtures."""
        cls.tmp = tempfile.mkdtemp()

    def _decrypt_renamed(self, name):
        path = _rewrite_algorithm(os.path.join(FIXTURE_DIR, "v14_default.enc"), name, self.tmp)
        decrypt_file(path, os.path.join(self.tmp, name + ".out"), PASSWORD, quiet=True)

    def test_camellia_specific_error(self):
        """Camellia files name the removal and the 1.4.x migration path."""
        with self.assertRaises(Exception) as ctx:
            self._decrypt_renamed("camellia")
        msg = str(ctx.exception)
        self.assertIn("camellia", msg.lower())
        self.assertIn("1.4", msg, msg="must point at the 1.4.x line: " + msg)

    def test_aes_ocb3_specific_error_mentions_streaming(self):
        """Non-streaming aes-ocb3 refusal notes the streaming path survives."""
        with self.assertRaises(Exception) as ctx:
            self._decrypt_renamed("aes-ocb3")
        msg = str(ctx.exception)
        self.assertIn("aes-ocb3", msg.lower())
        self.assertIn("1.4", msg)
        self.assertIn("streaming", msg.lower())


class TestThreefishDependencyError(unittest.TestCase):
    """A missing threefish_native must not surface as an auth error."""

    def test_missing_module_gets_dependency_error(self):
        """With threefish_native unimportable, the error names the module.

        PYTEST_CURRENT_TEST is dropped for the call: the nonce-retry loop
        re-raises ORIGINAL errors under pytest, so the pre-fix masking (a
        swallowed ImportError re-raised as "authentication error") only
        exists on the production path this test must pin.
        """
        tmp = tempfile.mkdtemp()
        path = _rewrite_algorithm(
            os.path.join(FIXTURE_DIR, "v14_default.enc"), "threefish-512", tmp
        )
        import contextlib
        import io

        clean_env = {k: v for k, v in os.environ.items() if k != "PYTEST_CURRENT_TEST"}
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, clean_env, clear=True):
            with mock.patch.dict(sys.modules, {"threefish_native": None}):
                with contextlib.redirect_stderr(stderr):
                    with self.assertRaises(Exception) as ctx:
                        decrypt_file(path, os.path.join(tmp, "tf.out"), PASSWORD, quiet=False)
        # Production exception strings are genericized by design (anti-oracle),
        # so the user-facing cause is the stderr guidance — it must name the
        # module, and the failure must not be reported as an auth error.
        self.assertIn(
            "threefish_native",
            stderr.getvalue(),
            msg="missing dependency must be named on stderr, not masked as "
            "an authentication error (gitlab#297): " + stderr.getvalue()[-300:],
        )
        self.assertNotIn("authentication error", str(ctx.exception))
