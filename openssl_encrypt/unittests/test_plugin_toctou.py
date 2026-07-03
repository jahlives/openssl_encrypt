"""Regression tests for the plugin-load TOCTOU guard (1.5.x port of the 1.4.x fix).

_validate_plugin_file() reads and AST-scans the plugin source, but
exec_module() re-reads the file from disk. Without a hash re-check, an
attacker who can rewrite the file in that window executes code that was
never scanned. The guard hashes the source at validation time and
refuses to exec if the bytes on disk no longer match.

On 1.5.x this guard had been lost in a refactor (only a stray unused
``import hashlib as _hashlib`` remained), silently downgrading a
protection 1.4.x still has.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from openssl_encrypt.modules.plugin_system import PluginManager
from openssl_encrypt.modules.plugin_system.plugin_config import PluginConfigManager

BENIGN_PLUGIN = """
from openssl_encrypt.modules.plugin_system import (
    PluginCapability,
    PluginResult,
    PluginType,
    PreProcessorPlugin,
)


class ToctouTestPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("toctou_test", "TOCTOU Test Plugin", "1.0.0")

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES}

    def get_description(self):
        return "Benign plugin for TOCTOU tests"

    def process_file(self, file_path, context):
        return PluginResult.success_result("ok")
"""

# Passes the AST scan too — the point is that it was never scanned.
SWAPPED_PLUGIN = BENIGN_PLUGIN.replace(
    'PluginResult.success_result("ok")',
    'PluginResult.success_result("swapped-after-validation")',
)


class TestPluginLoadTOCTOU(unittest.TestCase):
    """The source hashed at validation must be the source that executes."""

    def setUp(self):
        self.config_manager = PluginConfigManager()
        self.plugin_manager = PluginManager(
            config_manager=self.config_manager,
            strict_security_mode=True,
        )
        self.temp_dir = tempfile.mkdtemp()
        os.chmod(self.temp_dir, 0o700)  # owner-only, so H8 does not reject
        self.plugin_path = os.path.join(self.temp_dir, "toctou_plugin.py")
        with open(self.plugin_path, "w", encoding="utf-8") as f:
            f.write(BENIGN_PLUGIN)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_swap_after_validation_is_refused(self):
        """A file rewritten between validation and exec must not execute."""
        real_validate = self.plugin_manager._validate_plugin_file

        def validate_then_swap(file_path):
            ok = real_validate(file_path)
            # Attacker rewrites the file in the validation->exec window
            with open(self.plugin_path, "w", encoding="utf-8") as f:
                f.write(SWAPPED_PLUGIN)
            return ok

        with mock.patch.object(
            self.plugin_manager, "_validate_plugin_file", side_effect=validate_then_swap
        ):
            result = self.plugin_manager.load_plugin(self.plugin_path)

        self.assertFalse(result.success)
        self.assertIn("TOCTOU", result.message)

    def test_unmodified_plugin_still_loads(self):
        """The guard must not break legitimate loads."""
        result = self.plugin_manager.load_plugin(self.plugin_path)
        self.assertTrue(result.success, result.message)

    def test_validation_records_source_hash(self):
        """_validate_plugin_file must record the hash it validated."""
        self.assertTrue(self.plugin_manager._validate_plugin_file(self.plugin_path))
        real_path = os.path.realpath(self.plugin_path)
        self.assertIn(real_path, self.plugin_manager._validated_source_hashes)


if __name__ == "__main__":
    unittest.main()
