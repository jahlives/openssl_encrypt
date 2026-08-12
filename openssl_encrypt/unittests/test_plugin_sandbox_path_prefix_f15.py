"""Regression tests for sandbox path-prefix authorization (gitlab#133 / F15).

``PluginSandbox._is_safe_path`` authorized a path with a bare string prefix
match, so a sandboxed plugin could reach a SIBLING directory whose name shares
the prefix — e.g. ``.../plugins/foobar`` matched the allowed ``.../plugins/foo``,
breaking per-plugin isolation. The fix authorizes a path only if it IS the
allowed directory or lives strictly beneath it (``allowed`` or ``allowed`` +
os.sep prefix). These tests pin that a prefix-sharing sibling is refused while
the real directory (and paths beneath it) are still allowed.
"""

import os
import shutil
import tempfile
import unittest

from openssl_encrypt.modules.plugin_system.plugin_base import (
    PluginCapability,
    PluginSecurityContext,
)
from openssl_encrypt.modules.plugin_system.plugin_sandbox import PluginSandbox


class TestSandboxPathPrefixF15(unittest.TestCase):
    def setUp(self):
        self.base = os.path.realpath(tempfile.mkdtemp())
        # "allowed" and a prefix-sharing sibling "allowedX".
        self.allowed = os.path.join(self.base, "allowed")
        self.sibling = os.path.join(self.base, "allowedX")
        os.makedirs(self.allowed)
        os.makedirs(self.sibling)
        self.sandbox = PluginSandbox()

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_temp_dir_within_allowed_but_not_sibling(self):
        self.sandbox.temp_dir = self.allowed
        # A path inside the allowed dir is authorized (write => no exists check).
        self.assertTrue(self.sandbox._is_safe_path(os.path.join(self.allowed, "f"), is_write=True))
        # The allowed dir itself is authorized.
        self.assertTrue(self.sandbox._is_safe_path(self.allowed, is_write=True))
        # A prefix-sharing SIBLING must be refused (the F15 bug).
        self.assertFalse(self.sandbox._is_safe_path(os.path.join(self.sibling, "f"), is_write=True))

    def test_plugin_code_dir_within_allowed_but_not_sibling(self):
        ctx = PluginSecurityContext(
            "p", {PluginCapability.READ_FILES}, plugin_file_directory=self.allowed
        )
        # Create real files so the read-path existence check passes.
        good = os.path.join(self.allowed, "code.py")
        bad = os.path.join(self.sibling, "code.py")
        with open(good, "w") as f:
            f.write("x\n")
        with open(bad, "w") as f:
            f.write("x\n")
        self.assertTrue(self.sandbox._is_safe_path(good, context=ctx, is_write=False))
        # Sibling code dir sharing the prefix must be refused.
        self.assertFalse(self.sandbox._is_safe_path(bad, context=ctx, is_write=False))


if __name__ == "__main__":
    unittest.main()
