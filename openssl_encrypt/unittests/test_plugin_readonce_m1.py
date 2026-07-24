"""Regression tests for follow-up finding M1 [PLUGIN-2]: read-once binding.

The plugin loader read each file up to four times from different sources: the
signature was verified over the raw binary bytes, the AST scan + TOCTOU hash
were over a text-mode (universal-newline-translated, utf-8 re-encoded) read,
and exec_module did its own read (and could execute a cached .pyc). Nothing
bound signed == scanned == executed. For a CRLF/BOM file the raw signed bytes
differ from the newline-translated hash bytes, so the signature vouched for
bytes that were neither scanned nor (necessarily) executed.

The fix reads the plugin bytes ONCE (binary, from the realpath) and threads
that exact buffer through signature verification, AST analysis, the hash pin,
and execution (compile+exec of the same bytes). This test pins that the
validation hash is sha256 of the RAW bytes and that a CRLF plugin round-trips.
"""

import hashlib
import os
import shutil
import tempfile
import unittest

from openssl_encrypt.modules.plugin_system import PluginManager
from openssl_encrypt.modules.plugin_system.plugin_config import PluginConfigManager
from openssl_encrypt.modules.plugin_system.plugin_signature import PluginSignaturePolicy

BENIGN_PLUGIN = """
from openssl_encrypt.modules.plugin_system import (
    PluginCapability,
    PluginResult,
    PluginType,
    PreProcessorPlugin,
)


class ReadOnceTestPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("readonce_test", "Read-once Test Plugin", "1.0.0")

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES}

    def get_description(self):
        return "Benign plugin for read-once tests"

    def process_file(self, file_path, context):
        return PluginResult.success_result("ok")
"""


class TestM1ReadOnceBinding(unittest.TestCase):
    def setUp(self):
        self.config_manager = PluginConfigManager()
        # This suite exercises the read-once/hash-pin binding that the signature
        # check performs, so the check must RUN — but on unsigned test plugins.
        # Use WARN (the old default) so the check runs and the plugin still
        # loads; ENFORCE (the new default, gitlab#130) would refuse the unsigned
        # plugin before the binding is exercised.
        self.plugin_manager = PluginManager(
            config_manager=self.config_manager,
            strict_security_mode=True,
            signature_policy=PluginSignaturePolicy.WARN,
        )
        self.temp_dir = tempfile.mkdtemp()
        os.chmod(self.temp_dir, 0o700)  # owner-only, so H8 does not reject
        self.plugin_path = os.path.join(self.temp_dir, "readonce_plugin.py")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _write(self, raw: bytes):
        with open(self.plugin_path, "wb") as f:
            f.write(raw)

    def test_hash_pinned_over_raw_bytes_lf(self):
        raw = BENIGN_PLUGIN.encode("utf-8")
        self._write(raw)
        self.assertTrue(self.plugin_manager._validate_plugin_file(self.plugin_path))
        real = os.path.realpath(self.plugin_path)
        self.assertEqual(
            self.plugin_manager._validated_source_hashes[real],
            hashlib.sha256(raw).hexdigest(),
        )

    def test_hash_pinned_over_raw_bytes_crlf(self):
        """CRLF distinguishes the fix (sha256 of raw) from the old bug (sha256
        of the newline-translated text read)."""
        raw = BENIGN_PLUGIN.replace("\n", "\r\n").encode("utf-8")
        self._write(raw)
        self.assertTrue(self.plugin_manager._validate_plugin_file(self.plugin_path))
        real = os.path.realpath(self.plugin_path)
        self.assertEqual(
            self.plugin_manager._validated_source_hashes[real],
            hashlib.sha256(raw).hexdigest(),
        )

    def test_crlf_plugin_round_trips(self):
        """A CRLF plugin must validate and load (exec from the verified buffer)."""
        raw = BENIGN_PLUGIN.replace("\n", "\r\n").encode("utf-8")
        self._write(raw)
        result = self.plugin_manager.load_plugin(self.plugin_path)
        self.assertTrue(result.success, result.message)

    def test_missing_pin_for_non_builtin_fails_closed(self):
        """If a non-built-in reaches exec with no pinned hash (e.g. a symlink
        target swapped after validation keyed the pin to another realpath), load
        must refuse rather than exec unverified bytes."""
        from unittest import mock

        self._write(BENIGN_PLUGIN.encode("utf-8"))
        # Validation "succeeds" but pins nothing (simulates the pin keyed to a
        # different realpath than the one load_plugin re-reads).
        with mock.patch.object(self.plugin_manager, "_validate_plugin_file", return_value=True):
            self.plugin_manager._validated_source_hashes.clear()
            result = self.plugin_manager.load_plugin(self.plugin_path)
        self.assertFalse(result.success)


if __name__ == "__main__":
    unittest.main()
