"""Regression tests for built-in plugin trust scoping (gitlab#130 follow-up).

The built-in trust shortcut (``_is_builtin_plugin``) skips the signature + AST +
TOCTOU gate. It is scoped to the shipped plugin subtree, but the advertised
third-party drop directories — ``plugins/user``, ``plugins/community``,
``plugins/official`` — live under that root too. If they were treated as
built-in, the ENFORCE-by-default signature policy (gitlab#130) would be
bypassable by simply dropping an unsigned plugin into the directory the tool
advertises for third-party plugins. These tests pin that those three directories
are NOT built-in while genuinely shipped subdirectories still are.
"""

import os
import shutil
import tempfile
import unittest

from openssl_encrypt.modules.plugin_system.plugin_config import PluginConfigManager
from openssl_encrypt.modules.plugin_system.plugin_manager import PluginManager


class TestBuiltinTrustScope(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.mgr = PluginManager(config_manager=PluginConfigManager())
        self.mgr.builtin_plugin_root = os.path.realpath(self.root)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _make(self, *parts):
        path = os.path.join(self.root, *parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("# plugin\n")
        return os.path.realpath(path)

    def test_shipped_subdirs_are_builtin(self):
        for sub in (
            "examples",
            "hsm",
            "keyserver",
            "integrity",
            "pepper",
            "steganography",
            "telemetry",
        ):
            self.assertTrue(
                self.mgr._is_builtin_plugin(self._make(sub, "p.py")),
                f"{sub} should be built-in",
            )

    def test_third_party_dirs_are_not_builtin(self):
        for sub in ("user", "community", "official"):
            self.assertFalse(
                self.mgr._is_builtin_plugin(self._make(sub, "p.py")),
                f"{sub} must NOT be built-in (gitlab#130)",
            )

    def test_third_party_dirs_variant_casing_not_builtin(self):
        # On case-insensitive filesystems "plugins/User" == "plugins/user"; the
        # exclusion must match case-insensitively (gitlab#130) or it fails open.
        for sub in ("User", "OFFICIAL", "Community", "uSeR"):
            self.assertFalse(
                self.mgr._is_builtin_plugin(self._make(sub, "p.py")),
                f"{sub} must NOT be built-in (case-insensitive exclusion)",
            )

    def test_nested_third_party_package_not_builtin(self):
        self.assertFalse(self.mgr._is_builtin_plugin(self._make("user", "pkg", "mod.py")))

    def test_root_level_file_is_not_builtin(self):
        # gitlab#231 (scan F10): a file dropped directly in plugins/ (which the
        # docs used to advertise for third-party plugins) must NOT be built-in;
        # it has to pass the full signature + AST + hash-pin gate.
        self.assertFalse(self.mgr._is_builtin_plugin(self._make("toplevel.py")))

    def test_unknown_subdir_is_not_builtin(self):
        # gitlab#231 (scan F10): only the shipped built-in packages are trusted.
        # Any other subdirectory an attacker creates under the root must go
        # through the full gate, not be trusted by a denylist that only knew the
        # three advertised drop dirs.
        for sub in ("dropped", "evil", "hsm_evil", "notaplugin"):
            self.assertFalse(
                self.mgr._is_builtin_plugin(self._make(sub, "p.py")),
                f"{sub} must NOT be built-in (allowlist, gitlab#231)",
            )

    def test_path_outside_root_not_builtin(self):
        other = tempfile.mkdtemp()
        try:
            p = os.path.join(other, "evil.py")
            with open(p, "w", encoding="utf-8") as f:
                f.write("# x\n")
            self.assertFalse(self.mgr._is_builtin_plugin(os.path.realpath(p)))
        finally:
            shutil.rmtree(other, ignore_errors=True)

    def test_sibling_prefix_dir_not_builtin(self):
        # A sibling dir sharing the root's name prefix must not count as "under".
        sibling = self.root + "_evil"
        os.makedirs(sibling, exist_ok=True)
        try:
            p = os.path.join(sibling, "p.py")
            with open(p, "w", encoding="utf-8") as f:
                f.write("# x\n")
            self.assertFalse(self.mgr._is_builtin_plugin(os.path.realpath(p)))
        finally:
            shutil.rmtree(sibling, ignore_errors=True)

    def test_no_root_configured_is_never_builtin(self):
        self.mgr.builtin_plugin_root = None
        self.assertFalse(self.mgr._is_builtin_plugin(self._make("examples", "p.py")))


if __name__ == "__main__":
    unittest.main()
