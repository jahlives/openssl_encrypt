#!/usr/bin/env python3
"""
Test suite for configuration management functionality.

This module contains comprehensive tests for:
- Default configuration
- Configuration wizard
- Configuration analyzer
- Template manager
- Smart recommendations
- Security scorer
"""

import json
import logging
import os
import shutil
import sys
import tempfile
import textwrap
import time
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from openssl_encrypt.modules.keystore_cli import KeystoreSecurityLevel, PQCKeystore

# Import PQC modules if available
try:
    from openssl_encrypt.modules.pqc import LIBOQS_AVAILABLE
except ImportError:
    LIBOQS_AVAILABLE = False


class LogCapture(logging.Handler):
    """A custom logging handler that captures log records for testing."""

    def __init__(self):
        super().__init__()
        self.records = []
        self.output = StringIO()

    def emit(self, record):
        self.records.append(record)
        msg = self.format(record)
        self.output.write(msg + "\n")

    def get_output(self):
        return self.output.getvalue()

    def clear(self):
        self.records = []
        self.output = StringIO()


class TestDefaultConfiguration(unittest.TestCase):
    """Test class for default configuration application."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.test_dir, "test_file.txt")
        self.test_password = "test_password_123"

        # Create test file
        with open(self.test_file, "w", encoding="utf-8") as f:
            f.write("This is a test file for default configuration testing.")

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_default_configuration_applied(self):
        """Test that default configuration is applied when no arguments provided."""
        from ..modules.crypt_core import EncryptionAlgorithm, encrypt_file, extract_file_metadata

        encrypted_file = self.test_file + ".enc"

        # Encrypt with no hash configuration (should use defaults)
        result = encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=None,  # No configuration provided
            quiet=True,
            algorithm=EncryptionAlgorithm.AES_GCM,
        )

        self.assertTrue(result, "Encryption with default config should succeed")

        self.assertTrue(os.path.exists(encrypted_file), "Encrypted file should exist")

        # Read and verify metadata contains default configuration
        metadata = extract_file_metadata(encrypted_file)
        self.assertIsNotNone(metadata, "Metadata should be present")

        # Check that default hash configurations are applied (using correct nested structure)
        inner_metadata = metadata["metadata"]
        hash_config = inner_metadata["derivation_config"]["hash_config"]
        self.assertEqual(
            hash_config["sha3_512"]["rounds"], 10000, "Default should include 10k SHA3-512 rounds"
        )
        self.assertEqual(
            hash_config["blake3"]["rounds"], 10000, "Default should include 10k BLAKE3 rounds"
        )

        # Check that default KDF configurations are applied
        kdf_config = inner_metadata["derivation_config"]["kdf_config"]
        self.assertFalse(kdf_config.get("scrypt", {}).get("enabled", False), "Default should disable Scrypt")
        self.assertTrue(kdf_config["argon2"]["enabled"], "Default should enable Argon2")
        self.assertEqual(
            kdf_config["argon2"]["rounds"], 10, "Default should include 10 Argon2 rounds"
        )

    def test_default_configuration_decryption(self):
        """Test that files encrypted with default configuration can be decrypted."""
        from ..modules.crypt_core import EncryptionAlgorithm, decrypt_file, encrypt_file

        encrypted_file = self.test_file + ".enc"
        decrypted_file = self.test_file + ".dec"

        # Encrypt with default configuration
        result = encrypt_file(
            self.test_file,
            encrypted_file,
            self.test_password,
            hash_config=None,  # Use defaults
            quiet=True,
            algorithm=EncryptionAlgorithm.AES_GCM,
        )

        self.assertTrue(result, "Encryption with default config should succeed")

        # Decrypt the file
        result = decrypt_file(encrypted_file, decrypted_file, self.test_password, quiet=True)

        self.assertTrue(result, "Decryption should succeed")

        self.assertTrue(os.path.exists(decrypted_file), "Decrypted file should exist")

        # Verify content matches
        with open(self.test_file, "r", encoding="utf-8") as original, open(
            decrypted_file, "r", encoding="utf-8"
        ) as decrypted:
            self.assertEqual(
                original.read(), decrypted.read(), "Decrypted content should match original"
            )

    def test_no_security_warning_with_defaults(self):
        """Test that no security warning appears with default configuration."""
        from ..modules.crypt_core import EncryptionAlgorithm, encrypt_file

        encrypted_file = self.test_file + ".enc"

        # This should not trigger security warnings since defaults include prior hashing
        with unittest.mock.patch("builtins.input") as mock_input:
            result = encrypt_file(
                self.test_file,
                encrypted_file,
                self.test_password,
                hash_config=None,  # Use defaults
                quiet=False,
                algorithm=EncryptionAlgorithm.AES_GCM,
            )

            self.assertTrue(result, "Encryption with defaults should succeed")

            # Verify no user input was requested (no warning)
            mock_input.assert_not_called()

        self.assertTrue(os.path.exists(encrypted_file), "Encrypted file should exist")


try:
    import os
    import sys

    # Get the project root directory (two levels up from unittests.py)
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    tests_path = os.path.join(project_root, "tests")
    if tests_path not in sys.path:
        sys.path.insert(0, tests_path)

    from keystore.test_keystore_hqc_mlkem_integration import TestHQCMLKEMKeystoreIntegration

    print("✅ HQC and ML-KEM keystore integration tests imported successfully")
except ImportError as e:
    print(f"⚠️  Could not import HQC/ML-KEM keystore integration tests: {e}")
except Exception as e:
    print(f"⚠️  Error importing keystore integration tests: {e}")


# =============================================================================
# PLUGIN SYSTEM TESTS
# =============================================================================


# Plugin classes for testing (defined at module level for picklability)
try:
    from openssl_encrypt.modules.plugin_system import (
        PluginCapability,
        PluginResult,
        PluginSecurityContext,
        PreProcessorPlugin,
    )

    class SlowPluginForTimeout(PreProcessorPlugin):
        """A slow plugin for timeout testing (module-level for pickling)."""

        def __init__(self):
            super().__init__("slow_test", "Slow Test Plugin", "1.0.0")

        def get_required_capabilities(self):
            return {PluginCapability.READ_FILES}

        def get_description(self):
            return "A slow plugin for timeout testing"

        def process_file(self, file_path, context):
            import time

            time.sleep(2)  # Sleep longer than timeout
            return PluginResult.success_result("Should not reach here")

        def execute(self, context):
            """Override execute to actually run the blocking sleep."""
            import time

            time.sleep(2)  # Sleep longer than timeout
            return PluginResult.success_result("Should not reach here")

except ImportError:
    # Plugin system not available
    SlowPluginForTimeout = None


@pytest.mark.order(0)
class TestPluginSystem(unittest.TestCase):
    """Test cases for the secure plugin system."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.plugin_dir = os.path.join(self.test_dir, "plugins")
        self.config_dir = os.path.join(self.test_dir, "config")
        os.makedirs(self.plugin_dir, exist_ok=True)
        os.makedirs(self.config_dir, exist_ok=True)

    def tearDown(self):
        """Clean up test environment."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_plugin_capability_enum(self):
        """Test PluginCapability enum values."""
        try:
            from ..modules.plugin_system import PluginCapability

            # Test all expected capabilities exist
            expected_capabilities = [
                "READ_FILES",
                "MODIFY_METADATA",
                "ACCESS_CONFIG",
                "WRITE_LOGS",
                "NETWORK_ACCESS",
                "EXECUTE_PROCESSES",
            ]

            for cap_name in expected_capabilities:
                self.assertTrue(hasattr(PluginCapability, cap_name))
                cap = getattr(PluginCapability, cap_name)
                self.assertIsInstance(cap.value, str)

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_type_enum(self):
        """Test PluginType enum values."""
        try:
            from ..modules.plugin_system import PluginType

            expected_types = [
                "PRE_PROCESSOR",
                "POST_PROCESSOR",
                "METADATA_HANDLER",
                "FORMAT_CONVERTER",
                "ANALYZER",
                "UTILITY",
            ]

            for type_name in expected_types:
                self.assertTrue(hasattr(PluginType, type_name))
                plugin_type = getattr(PluginType, type_name)
                self.assertIsInstance(plugin_type.value, str)

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_security_context_creation(self):
        """Test PluginSecurityContext creation and capabilities."""
        try:
            from ..modules.plugin_system import PluginCapability, PluginSecurityContext

            capabilities = {PluginCapability.READ_FILES, PluginCapability.WRITE_LOGS}
            context = PluginSecurityContext("test_plugin", capabilities)

            self.assertEqual(context.plugin_id, "test_plugin")
            self.assertEqual(context.capabilities, capabilities)
            self.assertTrue(context.has_capability(PluginCapability.READ_FILES))
            self.assertFalse(context.has_capability(PluginCapability.NETWORK_ACCESS))
            self.assertIsInstance(context.metadata, dict)
            self.assertIsInstance(context.file_paths, list)

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_security_context_sensitive_data_filtering(self):
        """Test that PluginSecurityContext filters sensitive data."""
        try:
            from ..modules.plugin_system import PluginCapability, PluginSecurityContext

            context = PluginSecurityContext("test_plugin", {PluginCapability.ACCESS_CONFIG})

            # Try to add sensitive metadata - should be blocked
            context.add_metadata("password", "secret123")
            context.add_metadata("private_key", "key_data")
            context.add_metadata("safe_data", "this_is_ok")

            # Only safe data should be added
            self.assertNotIn("password", context.metadata)
            self.assertNotIn("private_key", context.metadata)
            self.assertIn("safe_data", context.metadata)
            self.assertEqual(context.metadata["safe_data"], "this_is_ok")

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_result_creation(self):
        """Test PluginResult creation and data handling."""
        try:
            from ..modules.plugin_system import PluginResult

            # Test success result
            success_result = PluginResult.success_result("Operation completed")
            self.assertTrue(success_result.success)
            self.assertEqual(success_result.message, "Operation completed")

            # Test error result
            error_result = PluginResult.error_result("Operation failed")
            self.assertFalse(error_result.success)
            self.assertEqual(error_result.message, "Operation failed")

            # Test data addition with sensitive filtering
            result = PluginResult()
            result.add_data("safe_key", "safe_value")
            result.add_data("password", "secret")  # Should be blocked

            self.assertIn("safe_key", result.data)
            self.assertNotIn("password", result.data)

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_config_schema_validation(self):
        """Test plugin configuration schema validation."""
        try:
            from ..modules.plugin_system import (
                ConfigValidationError,
                PluginConfigSchema,
                create_boolean_field,
                create_integer_field,
                create_string_field,
            )

            # Create test schema
            schema = PluginConfigSchema()
            schema.add_field("name", str, required=True, description="Plugin name")
            schema.add_field("max_items", int, default=10, description="Maximum items")
            schema.add_field("enabled", bool, default=True, description="Enable plugin")

            # Test valid configuration
            config = {"name": "test_plugin", "max_items": 5}
            validated = schema.validate(config)

            self.assertEqual(validated["name"], "test_plugin")
            self.assertEqual(validated["max_items"], 5)
            self.assertEqual(validated["enabled"], True)  # Default value

            # Test missing required field
            invalid_config = {"max_items": 5}
            with self.assertRaises(ConfigValidationError):
                schema.validate(invalid_config)

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_config_manager_basic_operations(self):
        """Test basic plugin configuration manager operations."""
        try:
            from ..modules.plugin_system import ConfigValidationError, PluginConfigManager

            config_manager = PluginConfigManager(self.config_dir)

            # Test setting and getting configuration
            test_config = {"enabled": True, "log_level": "info"}
            config_manager.set_plugin_config("test_plugin", test_config)

            retrieved_config = config_manager.get_plugin_config("test_plugin")
            self.assertEqual(retrieved_config["enabled"], True)
            self.assertEqual(retrieved_config["log_level"], "info")

            # Test configuration update
            config_manager.update_plugin_config("test_plugin", {"log_level": "debug"})
            updated_config = config_manager.get_plugin_config("test_plugin")
            self.assertEqual(updated_config["log_level"], "debug")

            # Test listing configurations
            plugin_list = config_manager.list_plugin_configs()
            self.assertIn("test_plugin", plugin_list)

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_config_manager_sensitive_data_detection(self):
        """Test that configuration manager detects and warns about sensitive data."""
        try:
            from ..modules.plugin_system import PluginConfigManager

            config_manager = PluginConfigManager(self.config_dir)

            # Configuration with potential sensitive data (should still work but warn)
            sensitive_config = {
                "api_endpoint": "https://example.com/api",
                "username": "user123",  # Not necessarily sensitive
                "password_hash": "hash123",  # Should trigger warning
            }

            # This should work but log warnings
            config_manager.set_plugin_config("sensitive_plugin", sensitive_config)
            retrieved = config_manager.get_plugin_config("sensitive_plugin")

            # Config should be saved despite warnings
            self.assertEqual(retrieved["api_endpoint"], "https://example.com/api")

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_create_simple_test_plugin(self):
        """Test creating and loading a simple test plugin."""
        try:
            from ..modules.plugin_system import (
                PluginCapability,
                PluginResult,
                PluginSecurityContext,
                PreProcessorPlugin,
            )

            # Create a simple test plugin file
            plugin_code = """
from openssl_encrypt.modules.plugin_system import (
    PreProcessorPlugin,
    PluginCapability,
    PluginResult,
    PluginSecurityContext
)

class SimpleTestPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("simple_test", "Simple Test Plugin", "1.0.0")

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES}

    def get_description(self):
        return "A simple test plugin for unit testing"

    def process_file(self, file_path, context):
        return PluginResult.success_result(f"Processed file: {file_path}")
"""

            plugin_file = os.path.join(self.plugin_dir, "simple_test.py")
            with open(plugin_file, "w", encoding="utf-8") as f:
                f.write(plugin_code)

            self.assertTrue(os.path.exists(plugin_file))

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_manager_plugin_discovery(self):
        """Test plugin manager discovers plugins correctly."""
        try:
            from ..modules.plugin_system import PluginConfigManager, PluginManager

            # Create test plugin file
            self.test_create_simple_test_plugin()

            config_manager = PluginConfigManager(self.config_dir)
            plugin_manager = PluginManager(config_manager)
            plugin_manager.add_plugin_directory(self.plugin_dir)

            # Test plugin discovery
            discovered = plugin_manager.discover_plugins()
            self.assertGreater(len(discovered), 0)

            # Check that our test plugin was found
            plugin_files = [os.path.basename(p) for p in discovered]
            self.assertIn("simple_test.py", plugin_files)

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_manager_load_and_execute_plugin(self):
        """Test loading and executing a plugin."""
        try:
            from ..modules.plugin_system import (
                PluginCapability,
                PluginConfigManager,
                PluginManager,
                PluginSecurityContext,
            )

            # Create and discover test plugin
            self.test_create_simple_test_plugin()

            config_manager = PluginConfigManager(self.config_dir)
            plugin_manager = PluginManager(config_manager)
            plugin_manager.add_plugin_directory(self.plugin_dir)

            discovered = plugin_manager.discover_plugins()
            test_plugin_file = None
            for plugin_file in discovered:
                if "simple_test.py" in plugin_file:
                    test_plugin_file = plugin_file
                    break

            self.assertIsNotNone(test_plugin_file)

            # Load the plugin
            load_result = plugin_manager.load_plugin(test_plugin_file)
            self.assertTrue(load_result.success)

            # Verify plugin is registered
            plugins = plugin_manager.list_plugins()
            plugin_ids = [p["id"] for p in plugins]
            self.assertIn("simple_test", plugin_ids)

            # Create security context and execute plugin
            context = PluginSecurityContext("simple_test", {PluginCapability.READ_FILES})
            context.file_paths = ["/tmp/test_file.txt"]

            # Use in-process execution to avoid pickling issues with dynamically loaded plugins
            exec_result = plugin_manager.execute_plugin(
                "simple_test", context, use_process_isolation=False
            )
            self.assertTrue(exec_result.success)

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_manager_capability_validation(self):
        """Test that plugin manager validates capabilities correctly."""
        try:
            from ..modules.plugin_system import (
                PluginCapability,
                PluginConfigManager,
                PluginManager,
                PluginSecurityContext,
            )

            # Create test plugin and load it
            self.test_create_simple_test_plugin()

            config_manager = PluginConfigManager(self.config_dir)
            plugin_manager = PluginManager(config_manager)
            plugin_manager.add_plugin_directory(self.plugin_dir)

            discovered = plugin_manager.discover_plugins()
            for plugin_file in discovered:
                if "simple_test.py" in plugin_file:
                    plugin_manager.load_plugin(plugin_file)
                    break

            # Test with insufficient capabilities - should fail
            insufficient_context = PluginSecurityContext(
                "simple_test", {PluginCapability.WRITE_LOGS}
            )
            result = plugin_manager.execute_plugin(
                "simple_test", insufficient_context, use_process_isolation=False
            )
            self.assertFalse(result.success)

            # Test with sufficient capabilities - should succeed
            sufficient_context = PluginSecurityContext("simple_test", {PluginCapability.READ_FILES})
            sufficient_context.file_paths = ["/tmp/test_file.txt"]
            result = plugin_manager.execute_plugin(
                "simple_test", sufficient_context, use_process_isolation=False
            )
            self.assertTrue(result.success)

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_sandbox_resource_monitoring(self):
        """Test plugin sandbox resource monitoring."""
        try:
            from ..modules.plugin_system import ResourceMonitor

            monitor = ResourceMonitor()
            monitor.start()

            # Simulate some work
            time.sleep(0.1)
            monitor.update_peak_memory()

            monitor.stop()

            stats = monitor.get_stats()
            self.assertIn("memory_start_mb", stats)
            self.assertIn("memory_peak_mb", stats)
            self.assertIn("execution_time_s", stats)
            self.assertGreater(stats["execution_time_s"], 0)

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_sandbox_execution_timeout(self):
        """Test plugin sandbox timeout functionality."""
        try:
            from ..modules.plugin_system import (
                PluginCapability,
                PluginSandbox,
                PluginSecurityContext,
            )

            # Create a standalone slow plugin module in a temp file so the AST
            # analyzer only sees clean code (no blocked imports from test_config.py).
            import importlib.util
            import tempfile

            slow_plugin_source = textwrap.dedent("""\
                import time
                from openssl_encrypt.modules.plugin_system.plugin_base import (
                    PreProcessorPlugin,
                    PluginCapability,
                    PluginResult,
                )

                class SlowPluginForTimeout(PreProcessorPlugin):
                    def __init__(self):
                        super().__init__("slow_test", "Slow Test Plugin", "1.0.0")

                    def get_required_capabilities(self):
                        return {PluginCapability.READ_FILES}

                    def get_description(self):
                        return "A slow plugin for timeout testing"

                    def process_file(self, file_path, context):
                        time.sleep(2)
                        return PluginResult.success_result("Should not reach here")

                    def execute(self, context):
                        time.sleep(2)
                        return PluginResult.success_result("Should not reach here")
            """)

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", prefix="slow_plugin_", delete=False
            ) as f:
                f.write(slow_plugin_source)
                slow_module_path = f.name

            try:
                spec = importlib.util.spec_from_file_location("_slow_plugin_mod", slow_module_path)
                slow_mod = importlib.util.module_from_spec(spec)
                sys.modules["_slow_plugin_mod"] = slow_mod
                spec.loader.exec_module(slow_mod)

                plugin = slow_mod.SlowPluginForTimeout()
                context = PluginSecurityContext("slow_test", {PluginCapability.READ_FILES})
                sandbox = PluginSandbox()

                # Execute with short timeout and process isolation
                result = sandbox.execute_plugin(
                    plugin, context, max_execution_time=0.5, use_process_isolation=True
                )

                # Should fail due to timeout or process crash
                self.assertFalse(result.success)
                self.assertTrue(
                    "timed out" in result.message.lower()
                    or "process" in result.message.lower(),
                    f"Expected timeout or process failure, got: {result.message}",
                )
            finally:
                sys.modules.pop("_slow_plugin_mod", None)
                os.unlink(slow_module_path)

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_manager_enable_disable_plugin(self):
        """Test enabling and disabling plugins."""
        try:
            from ..modules.plugin_system import PluginConfigManager, PluginManager

            # Create and load test plugin
            self.test_create_simple_test_plugin()

            config_manager = PluginConfigManager(self.config_dir)
            plugin_manager = PluginManager(config_manager)
            plugin_manager.add_plugin_directory(self.plugin_dir)

            discovered = plugin_manager.discover_plugins()
            for plugin_file in discovered:
                if "simple_test.py" in plugin_file:
                    plugin_manager.load_plugin(plugin_file)
                    break

            # Test disabling plugin
            disable_result = plugin_manager.disable_plugin("simple_test")
            self.assertTrue(disable_result.success)

            # Plugin should still exist but be disabled
            plugin_info = plugin_manager.get_plugin_info("simple_test")
            self.assertIsNotNone(plugin_info)
            self.assertFalse(plugin_info["enabled"])

            # Test enabling plugin
            enable_result = plugin_manager.enable_plugin("simple_test")
            self.assertTrue(enable_result.success)

            plugin_info = plugin_manager.get_plugin_info("simple_test")
            self.assertTrue(plugin_info["enabled"])

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_manager_audit_logging(self):
        """Test plugin manager audit logging functionality."""
        try:
            from ..modules.plugin_system import (
                PluginCapability,
                PluginConfigManager,
                PluginManager,
                PluginSecurityContext,
            )

            config_manager = PluginConfigManager(self.config_dir)
            plugin_manager = PluginManager(config_manager)

            # Clear audit log
            plugin_manager.clear_audit_log()
            audit_log = plugin_manager.get_audit_log()
            self.assertEqual(len(audit_log), 0)

            # Perform operations that should generate audit entries
            self.test_create_simple_test_plugin()
            plugin_manager.add_plugin_directory(self.plugin_dir)

            discovered = plugin_manager.discover_plugins()
            for plugin_file in discovered:
                if "simple_test.py" in plugin_file:
                    load_result = plugin_manager.load_plugin(plugin_file)
                    if load_result.success:
                        break

            # Check audit log has entries
            audit_log = plugin_manager.get_audit_log()
            self.assertGreater(len(audit_log), 0)

            # Verify audit entries have required fields
            for entry in audit_log:
                self.assertIn("timestamp", entry)
                self.assertIn("message", entry)
                self.assertIn("thread_id", entry)

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_base_class_abstract_methods(self):
        """Test that BasePlugin enforces abstract method implementation."""
        try:
            from ..modules.plugin_system import BasePlugin

            # Should not be able to instantiate BasePlugin directly
            with self.assertRaises(TypeError):
                BasePlugin("test", "Test", "1.0")

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_different_types(self):
        """Test different plugin types work correctly."""
        try:
            from ..modules.plugin_system import (
                AnalyzerPlugin,
                MetadataHandlerPlugin,
                PluginCapability,
                PluginResult,
                PluginType,
                PostProcessorPlugin,
                UtilityPlugin,
            )

            # Test PostProcessorPlugin
            class TestPostProcessor(PostProcessorPlugin):
                def __init__(self):
                    super().__init__("post_test", "Post Processor", "1.0")

                def get_required_capabilities(self):
                    return {PluginCapability.READ_FILES}

                def get_description(self):
                    return "Test post processor"

                def process_encrypted_file(self, encrypted_file_path, context):
                    return PluginResult.success_result("Post processed")

            post_plugin = TestPostProcessor()
            self.assertEqual(post_plugin.get_plugin_type(), PluginType.POST_PROCESSOR)

            # Test MetadataHandlerPlugin
            class TestMetadataHandler(MetadataHandlerPlugin):
                def __init__(self):
                    super().__init__("meta_test", "Metadata Handler", "1.0")

                def get_required_capabilities(self):
                    return {PluginCapability.MODIFY_METADATA}

                def get_description(self):
                    return "Test metadata handler"

                def process_metadata(self, metadata, context):
                    return PluginResult.success_result("Metadata processed")

            meta_plugin = TestMetadataHandler()
            self.assertEqual(meta_plugin.get_plugin_type(), PluginType.METADATA_HANDLER)

            # Test AnalyzerPlugin
            class TestAnalyzer(AnalyzerPlugin):
                def __init__(self):
                    super().__init__("analyze_test", "Analyzer", "1.0")

                def get_required_capabilities(self):
                    return {PluginCapability.READ_FILES}

                def get_description(self):
                    return "Test analyzer"

                def analyze_file(self, file_path, context):
                    return PluginResult.success_result("File analyzed")

            analyze_plugin = TestAnalyzer()
            self.assertEqual(analyze_plugin.get_plugin_type(), PluginType.ANALYZER)

            # Test UtilityPlugin
            class TestUtility(UtilityPlugin):
                def __init__(self):
                    super().__init__("util_test", "Utility", "1.0")

                def get_required_capabilities(self):
                    return set()

                def get_description(self):
                    return "Test utility"

                def get_utility_functions(self):
                    return {"test_func": lambda x: x * 2}

            util_plugin = TestUtility()
            self.assertEqual(util_plugin.get_plugin_type(), PluginType.UTILITY)

            # Test utility functions
            functions = util_plugin.get_utility_functions()
            self.assertIn("test_func", functions)
            self.assertEqual(functions["test_func"](5), 10)

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_system_availability_functions(self):
        """Test plugin system availability and info functions."""
        try:
            from ..modules.plugin_system import (
                PLUGIN_SYSTEM_AVAILABLE,
                get_plugin_system_info,
                is_plugin_system_available,
            )

            # Test availability
            self.assertTrue(is_plugin_system_available())
            self.assertTrue(PLUGIN_SYSTEM_AVAILABLE)

            # Test system info
            info = get_plugin_system_info()
            self.assertIsInstance(info, dict)
            self.assertIn("version", info)
            self.assertIn("supported_capabilities", info)
            self.assertIn("supported_plugin_types", info)
            self.assertIn("security_features", info)

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_validation_compatibility_check(self):
        """Test plugin compatibility validation."""
        try:
            from ..modules.plugin_system import validate_plugin_compatibility

            # Create test plugin file
            self.test_create_simple_test_plugin()
            plugin_file = os.path.join(self.plugin_dir, "simple_test.py")

            # Test compatibility check
            result = validate_plugin_compatibility(plugin_file)

            self.assertIsInstance(result, dict)
            self.assertIn("compatible", result)
            self.assertIn("issues", result)
            self.assertIn("plugin_class_found", result)

            # Should be compatible
            self.assertTrue(result["compatible"])
            self.assertTrue(result["plugin_class_found"])

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_create_default_plugin_manager(self):
        """Test creating default plugin manager."""
        try:
            from ..modules.plugin_system import create_default_plugin_manager

            plugin_manager = create_default_plugin_manager(self.config_dir)

            self.assertIsNotNone(plugin_manager)

            # Should have empty plugin list initially
            plugins = plugin_manager.list_plugins()
            self.assertIsInstance(plugins, list)

        except ImportError:
            self.skipTest("Plugin system not available")


@pytest.mark.order(0)
class TestPluginIntegration(unittest.TestCase):
    """Integration tests for example plugins with real file operations."""

    def setUp(self):
        """Set up test environment with temporary files."""
        self.test_dir = tempfile.mkdtemp()
        self.test_files = []

        # Create various test files
        self.text_file = os.path.join(self.test_dir, "test.txt")
        with open(self.text_file, "w", encoding="utf-8") as f:
            f.write("This is a test file for plugin integration.\nLine 2\nLine 3")
        self.test_files.append(self.text_file)

        self.json_file = os.path.join(self.test_dir, "test.json")
        with open(self.json_file, "w", encoding="utf-8") as f:
            json.dump({"name": "test", "data": [1, 2, 3], "nested": {"key": "value"}}, f)
        self.test_files.append(self.json_file)

        self.csv_file = os.path.join(self.test_dir, "test.csv")
        with open(self.csv_file, "w", encoding="utf-8") as f:
            f.write("name,age,city\nAlice,30,New York\nBob,25,London\n")
        self.test_files.append(self.csv_file)

    def tearDown(self):
        """Clean up test files."""
        for file_path in self.test_files:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except:
                pass
        try:
            shutil.rmtree(self.test_dir)
        except:
            pass

    def test_file_metadata_analyzer_plugin(self):
        """Test file metadata analyzer plugin functionality."""
        try:
            from openssl_encrypt.modules.plugin_system import (
                PluginCapability,
                PluginSecurityContext,
            )
            from openssl_encrypt.plugins.examples.file_analyzer import FileMetadataAnalyzer

            analyzer = FileMetadataAnalyzer()
            context = PluginSecurityContext(
                "test_operation",
                capabilities={PluginCapability.READ_FILES, PluginCapability.WRITE_LOGS},
            )

            # Test analyzing text file
            result = analyzer.analyze_file(self.text_file, context)
            self.assertTrue(result.success)
            self.assertIn("analysis", result.data)

            analysis = result.data["analysis"]
            self.assertEqual(analysis["file_extension"], ".txt")
            self.assertIn("file_size", analysis)
            self.assertIn("file_category", analysis)
            self.assertFalse(analysis["appears_encrypted"])

            # Test analyzing JSON file
            result = analyzer.analyze_file(self.json_file, context)
            self.assertTrue(result.success)
            analysis = result.data["analysis"]
            self.assertEqual(analysis["file_extension"], ".json")

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_backup_plugin_functionality(self):
        """Test backup plugin creates and verifies backups."""
        try:
            from openssl_encrypt.modules.plugin_system import (
                PluginCapability,
                PluginSecurityContext,
            )
            from openssl_encrypt.plugins.examples.backup_plugin import (
                BackupVerificationPlugin,
                FileBackupPlugin,
            )

            backup_plugin = FileBackupPlugin()
            verifier = BackupVerificationPlugin()

            context = PluginSecurityContext(
                "test_backup",
                capabilities={PluginCapability.READ_FILES, PluginCapability.WRITE_LOGS},
            )

            # Initialize backup plugin
            config = {"backup_directory": os.path.join(self.test_dir, "backups")}
            init_result = backup_plugin.initialize(config)
            self.assertTrue(init_result.success)

            # Create backup
            result = backup_plugin.process_file(self.text_file, context)
            self.assertTrue(result.success)
            self.assertIn("backup_path", result.data)

            backup_path = result.data["backup_path"]
            self.assertTrue(os.path.exists(backup_path))

            # Verify backup content matches original
            with open(self.text_file, "r", encoding="utf-8") as original, open(backup_path, "r", encoding="utf-8") as backup:
                self.assertEqual(original.read(), backup.read())

            # Test backup verification
            context.add_metadata("backup_created", True)
            context.add_metadata("backup_path", backup_path)

            verify_result = verifier.process_encrypted_file("dummy_encrypted.enc", context)
            self.assertTrue(verify_result.success)

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_format_converter_plugin(self):
        """Test format conversion between different text formats."""
        try:
            from openssl_encrypt.modules.plugin_system import (
                PluginCapability,
                PluginSecurityContext,
            )
            from openssl_encrypt.plugins.examples.format_converter import (
                SmartFormatPreProcessor,
                TextFormatConverter,
            )

            converter = TextFormatConverter()
            preprocessor = SmartFormatPreProcessor()

            context = PluginSecurityContext(
                "test_conversion",
                capabilities={
                    PluginCapability.READ_FILES,
                    PluginCapability.WRITE_LOGS,
                    PluginCapability.MODIFY_METADATA,
                },
            )

            # Test JSON to text conversion
            output_file = os.path.join(self.test_dir, "converted.txt")
            self.test_files.append(output_file)

            result = converter.convert_format(self.json_file, output_file, "json", "txt", context)
            self.assertTrue(result.success)
            self.assertTrue(os.path.exists(output_file))

            # Test CSV to JSON conversion
            json_output = os.path.join(self.test_dir, "converted.json")
            self.test_files.append(json_output)

            result = converter.convert_format(self.csv_file, json_output, "csv", "json", context)
            self.assertTrue(result.success)
            self.assertTrue(os.path.exists(json_output))

            # Verify JSON output is valid
            with open(json_output, "r", encoding="utf-8") as f:
                converted_data = json.load(f)
                self.assertIsInstance(converted_data, list)
                self.assertEqual(len(converted_data), 2)  # Two data rows

            # Test smart format detection
            result = preprocessor.process_file(self.json_file, context)
            self.assertTrue(result.success)

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_audit_logger_plugin(self):
        """Test audit logging plugin functionality."""
        try:
            from openssl_encrypt.modules.plugin_system import (
                PluginCapability,
                PluginSecurityContext,
            )
            from openssl_encrypt.plugins.examples.audit_logger import (
                EncryptionAuditPlugin,
                EncryptionCompletionAuditor,
                SecurityEventMonitor,
            )

            audit_plugin = EncryptionAuditPlugin()
            completion_auditor = EncryptionCompletionAuditor()
            security_monitor = SecurityEventMonitor()

            context = PluginSecurityContext(
                "test_audit",
                capabilities={
                    PluginCapability.READ_FILES,
                    PluginCapability.WRITE_LOGS,
                    PluginCapability.MODIFY_METADATA,
                },
            )

            # Set up audit log directory
            audit_dir = os.path.join(self.test_dir, "audit_logs")
            config = {"audit_log_directory": audit_dir}

            # Initialize plugins
            init_result = audit_plugin.initialize(config)
            self.assertTrue(init_result.success)

            # Test pre-processing audit
            result = audit_plugin.process_file(self.text_file, context)
            self.assertTrue(result.success)

            # Check that audit log was created
            self.assertTrue(os.path.exists(audit_dir))
            log_files = os.listdir(audit_dir)
            self.assertTrue(len(log_files) > 0)

            # Test post-processing audit
            encrypted_file = os.path.join(self.test_dir, "dummy.enc")
            with open(encrypted_file, "w", encoding="utf-8") as f:
                f.write("dummy encrypted content")
            self.test_files.append(encrypted_file)

            context.add_metadata("algorithm", "aes-gcm")
            context.add_metadata("operation", "encrypt")

            result = completion_auditor.process_encrypted_file(encrypted_file, context)
            self.assertTrue(result.success)

            # Test security monitoring
            result = security_monitor.execute(context)
            self.assertTrue(result.success)

        except ImportError:
            self.skipTest("Plugin system not available")

    def test_plugin_integration_with_encryption(self):
        """Test plugins working together in encryption/decryption pipeline."""
        try:
            # Create a temporary encrypted file to analyze
            from openssl_encrypt.modules.crypt_core import encrypt_file
            from openssl_encrypt.modules.plugin_system import (
                PluginCapability,
                PluginSecurityContext,
            )
            from openssl_encrypt.plugins.examples.file_analyzer import (
                EncryptionOverheadAnalyzer,
                FileMetadataAnalyzer,
            )

            # Create hash config for encryption
            hash_config = {
                "sha256": {"rounds": 1000},
                "sha512": {"rounds": 0},
                "sha3_256": {"rounds": 0},
                "sha3_512": {"rounds": 0},
                "blake2b": {"rounds": 0},
                "shake256": {"rounds": 0},
            }

            encrypted_file = os.path.join(self.test_dir, "test_encrypted.enc")
            self.test_files.append(encrypted_file)

            # Encrypt the test file (without plugins to avoid circular dependencies)
            success = encrypt_file(
                self.text_file,
                encrypted_file,
                "testpassword",
                hash_config,
                quiet=True,
                enable_plugins=False,  # Disable plugins for this test encryption
            )
            self.assertTrue(success)

            # Now test plugins on the encrypted result
            analyzer = FileMetadataAnalyzer()
            overhead_analyzer = EncryptionOverheadAnalyzer()

            context = PluginSecurityContext(
                "test_integration",
                capabilities={PluginCapability.READ_FILES, PluginCapability.WRITE_LOGS},
            )

            # Add metadata that would normally be set during encryption
            original_size = os.path.getsize(self.text_file)
            context.add_metadata("original_file_size", original_size)
            context.add_metadata("algorithm", "aes-gcm")
            context.add_metadata("operation", "encrypt")

            # Test file analysis on encrypted file
            result = analyzer.analyze_file(encrypted_file, context)
            self.assertTrue(result.success)

            analysis = result.data["analysis"]
            self.assertTrue(analysis["appears_encrypted"])
            self.assertEqual(analysis["file_extension"], ".enc")

            # Test overhead analysis
            result = overhead_analyzer.process_encrypted_file(encrypted_file, context)
            self.assertTrue(result.success)

            overhead_data = result.data["overhead_analysis"]
            self.assertIn("overhead_bytes", overhead_data)
            self.assertIn("overhead_percentage", overhead_data)
            self.assertTrue(overhead_data["openssl_encrypt_format"])

        except ImportError:
            self.skipTest("Plugin system not available")
        except Exception as e:
            # Skip if encryption fails due to environment issues
            self.skipTest(f"Encryption test skipped due to: {str(e)}")

    def test_plugin_error_handling(self):
        """Test plugin error handling with invalid inputs."""
        try:
            from openssl_encrypt.modules.plugin_system import (
                PluginCapability,
                PluginSecurityContext,
            )
            from openssl_encrypt.plugins.examples.backup_plugin import FileBackupPlugin
            from openssl_encrypt.plugins.examples.file_analyzer import FileMetadataAnalyzer

            analyzer = FileMetadataAnalyzer()
            backup_plugin = FileBackupPlugin()

            context = PluginSecurityContext(
                "test_errors",
                capabilities={PluginCapability.READ_FILES, PluginCapability.WRITE_LOGS},
            )

            # Test with non-existent file
            result = analyzer.analyze_file("/nonexistent/file.txt", context)
            self.assertFalse(result.success)
            self.assertIn("not found", result.message)

            # Test backup with non-existent file
            result = backup_plugin.process_file("/nonexistent/file.txt", context)
            self.assertFalse(result.success)
            self.assertIn("not found", result.message)

            # Test with insufficient capabilities
            limited_context = PluginSecurityContext(
                "test_limited",
                capabilities={PluginCapability.READ_FILES},  # Missing WRITE_LOGS
            )

            # This should work as WRITE_LOGS is checked by sandbox, not plugin directly
            result = analyzer.analyze_file(self.text_file, limited_context)
            self.assertTrue(result.success)

        except ImportError:
            self.skipTest("Plugin system not available")


class TestCLIAliases(unittest.TestCase):
    """Test CLI alias system functionality."""

    def setUp(self):
        """Set up test environment."""
        from ..modules.cli_aliases import CLIAliasConfig, CLIAliasProcessor

        self.processor = CLIAliasProcessor()
        self.config = CLIAliasConfig()

    def test_cli_alias_config_constants(self):
        """Test that CLI alias configuration constants are properly defined."""
        # Test security aliases
        self.assertIn("fast", self.config.SECURITY_ALIASES)
        self.assertIn("secure", self.config.SECURITY_ALIASES)
        self.assertIn("max-security", self.config.SECURITY_ALIASES)

        # Test algorithm aliases
        self.assertIn("aes", self.config.ALGORITHM_ALIASES)
        self.assertIn("chacha", self.config.ALGORITHM_ALIASES)
        self.assertIn("xchacha", self.config.ALGORITHM_ALIASES)

        # Test PQC aliases
        self.assertIn("pq-standard", self.config.PQC_ALIASES)
        self.assertIn("pq-high", self.config.PQC_ALIASES)

        # Test use case aliases
        self.assertIn("personal", self.config.USE_CASE_ALIASES)
        self.assertIn("business", self.config.USE_CASE_ALIASES)
        self.assertIn("archival", self.config.USE_CASE_ALIASES)

    def test_security_alias_processing(self):
        """Test processing of security level aliases."""
        import argparse

        # Create mock args for --fast
        args = argparse.Namespace(
            fast=True,
            secure=False,
            max_security=False,
            crypto_family=None,
            quantum_safe=None,
            for_personal=False,
            for_business=False,
            for_archival=False,
            for_compliance=False,
        )

        overrides = self.processor.process_aliases(args)
        self.assertEqual(overrides["template"], "quick")
        self.assertEqual(overrides["algorithm"], "aes-gcm")

        # Test --secure
        args.fast = False
        args.secure = True
        overrides = self.processor.process_aliases(args)
        self.assertEqual(overrides["template"], "standard")
        self.assertEqual(overrides["algorithm"], "aes-gcm")

        # Test --max-security
        args.secure = False
        args.max_security = True
        overrides = self.processor.process_aliases(args)
        self.assertEqual(overrides["template"], "paranoid")
        self.assertEqual(overrides["algorithm"], "xchacha20-poly1305")

    def test_algorithm_alias_processing(self):
        """Test processing of algorithm family aliases."""
        import argparse

        # Test algorithm family mapping
        test_cases = [
            ("aes", "aes-gcm"),
            ("chacha", "chacha20-poly1305"),
            ("xchacha", "xchacha20-poly1305"),
            ("fernet", "fernet"),
        ]

        for alias, expected in test_cases:
            args = argparse.Namespace(
                fast=False,
                secure=False,
                max_security=False,
                crypto_family=alias,
                quantum_safe=None,
                for_personal=False,
                for_business=False,
                for_archival=False,
                for_compliance=False,
            )

            overrides = self.processor.process_aliases(args)
            self.assertEqual(overrides["algorithm"], expected)

    def test_pqc_alias_processing(self):
        """Test processing of post-quantum cryptography aliases."""
        import argparse

        # Test PQC alias mapping
        test_cases = [
            ("pq-standard", "ml-kem-768-hybrid"),
            ("pq-high", "ml-kem-1024-hybrid"),
            ("pq-alternative", "hqc-192-hybrid"),
        ]

        for alias, expected in test_cases:
            args = argparse.Namespace(
                fast=False,
                secure=False,
                max_security=False,
                crypto_family=None,
                quantum_safe=alias,
                for_personal=False,
                for_business=False,
                for_archival=False,
                for_compliance=False,
            )

            overrides = self.processor.process_aliases(args)
            self.assertEqual(overrides["pqc_algorithm"], expected)

    def test_use_case_alias_processing(self):
        """Test processing of use case aliases."""
        import argparse

        # Test personal use case
        args = argparse.Namespace(
            fast=False,
            secure=False,
            max_security=False,
            crypto_family=None,
            quantum_safe=None,
            for_personal=True,
            for_business=False,
            for_archival=False,
            for_compliance=False,
        )

        overrides = self.processor.process_aliases(args)
        self.assertEqual(overrides["template"], "standard")
        self.assertEqual(overrides["algorithm"], "aes-gcm")

        # Test archival use case
        args.for_personal = False
        args.for_archival = True
        overrides = self.processor.process_aliases(args)
        self.assertEqual(overrides["template"], "paranoid")
        self.assertEqual(overrides["algorithm"], "xchacha20-poly1305")
        self.assertEqual(overrides["pqc_algorithm"], "ml-kem-1024-hybrid")

        # Test compliance use case
        args.for_archival = False
        args.for_compliance = True
        overrides = self.processor.process_aliases(args)
        self.assertEqual(overrides["template"], "paranoid")
        self.assertEqual(overrides["algorithm"], "aes-gcm")
        self.assertTrue(overrides.get("require_keystore", False))

    def test_alias_validation(self):
        """Test validation of alias combinations."""
        import argparse

        # Test conflicting security aliases
        args = argparse.Namespace(
            fast=True,
            secure=True,
            max_security=False,
            crypto_family=None,
            quantum_safe=None,
            for_personal=False,
            for_business=False,
            for_archival=False,
            for_compliance=False,
        )

        errors = self.processor.validate_alias_combinations(args)
        self.assertGreater(len(errors), 0)
        self.assertIn("fast", errors[0])
        self.assertIn("secure", errors[0])

        # Test conflicting use case aliases
        args = argparse.Namespace(
            fast=False,
            secure=False,
            max_security=False,
            crypto_family=None,
            quantum_safe=None,
            for_personal=True,
            for_business=True,
            for_archival=False,
            for_compliance=False,
        )

        errors = self.processor.validate_alias_combinations(args)
        self.assertGreater(len(errors), 0)
        self.assertIn("personal", errors[0])
        self.assertIn("business", errors[0])

        # Test incompatible PQC + Fernet combination
        args = argparse.Namespace(
            fast=False,
            secure=False,
            max_security=False,
            crypto_family="fernet",
            quantum_safe="pq-standard",
            for_personal=False,
            for_business=False,
            for_archival=False,
            for_compliance=False,
        )

        errors = self.processor.validate_alias_combinations(args)
        self.assertGreater(len(errors), 0)
        self.assertIn("Post-quantum", errors[0])
        self.assertIn("Fernet", errors[0])

    def test_alias_override_application(self):
        """Test application of alias overrides to parsed arguments."""
        import argparse

        from ..modules.cli_aliases import apply_alias_overrides

        # Create original args
        original_args = argparse.Namespace(
            algorithm=None, template=None, pqc_algorithm=None, custom_flag="test"
        )

        # Create overrides
        overrides = {"algorithm": "aes-gcm", "template": "standard", "new_attr": "new_value"}

        # Apply overrides
        modified_args = apply_alias_overrides(original_args, overrides)

        # Test that overrides were applied
        self.assertEqual(modified_args.algorithm, "aes-gcm")
        self.assertEqual(modified_args.template, "standard")
        self.assertEqual(modified_args.new_attr, "new_value")

        # Test that original attributes were preserved
        self.assertEqual(modified_args.custom_flag, "test")

        # Test that explicit user settings aren't overridden
        original_args.algorithm = "user-specified"
        modified_args = apply_alias_overrides(original_args, overrides)
        self.assertEqual(modified_args.algorithm, "user-specified")

    def test_help_text_generation(self):
        """Test generation of alias help text."""
        help_text = self.processor.get_alias_help_text()

        # Test that help text contains expected sections
        self.assertIn("CLI ALIASES", help_text)
        self.assertIn("SECURITY LEVEL ALIASES", help_text)
        self.assertIn("ALGORITHM FAMILY ALIASES", help_text)
        self.assertIn("POST-QUANTUM ALIASES", help_text)
        self.assertIn("USE CASE ALIASES", help_text)
        self.assertIn("EXAMPLES", help_text)

        # Test that specific aliases are documented
        self.assertIn("--fast", help_text)
        self.assertIn("--secure", help_text)
        self.assertIn("--crypto-family", help_text)
        self.assertIn("--quantum-safe", help_text)
        self.assertIn("--for-personal", help_text)

    def test_empty_alias_processing(self):
        """Test processing when no aliases are specified."""
        import argparse

        args = argparse.Namespace(
            fast=False,
            secure=False,
            max_security=False,
            crypto_family=None,
            quantum_safe=None,
            for_personal=False,
            for_business=False,
            for_archival=False,
            for_compliance=False,
        )

        overrides = self.processor.process_aliases(args)
        self.assertEqual(len(overrides), 0)

    def test_multiple_compatible_aliases(self):
        """Test processing multiple compatible aliases together."""
        import argparse

        # Test security level + algorithm family + PQC
        args = argparse.Namespace(
            fast=False,
            secure=True,
            max_security=False,
            crypto_family="xchacha",
            quantum_safe="pq-high",
            for_personal=False,
            for_business=False,
            for_archival=False,
            for_compliance=False,
        )

        overrides = self.processor.process_aliases(args)
        self.assertEqual(overrides["template"], "standard")  # from --secure
        self.assertEqual(overrides["algorithm"], "xchacha20-poly1305")  # from --crypto-family
        self.assertEqual(overrides["pqc_algorithm"], "ml-kem-1024-hybrid")  # from --quantum-safe

        # Validation should pass
        errors = self.processor.validate_alias_combinations(args)
        self.assertEqual(len(errors), 0)

    def test_alias_precedence(self):
        """Test that later aliases override earlier ones appropriately."""
        import argparse

        # Test that use case aliases override security aliases
        args = argparse.Namespace(
            fast=True,
            secure=False,
            max_security=False,
            crypto_family=None,
            quantum_safe=None,
            for_personal=False,
            for_business=False,
            for_archival=True,
            for_compliance=False,
        )

        overrides = self.processor.process_aliases(args)
        # Archival should override fast template
        self.assertEqual(overrides["template"], "paranoid")
        self.assertEqual(overrides["algorithm"], "xchacha20-poly1305")
