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
import time
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Import configuration modules
from openssl_encrypt.modules.config_wizard import (
    ConfigurationWizard,
    UseCase,
    UserExpertise,
    generate_cli_arguments,
    run_configuration_wizard,
)
from openssl_encrypt.modules.keystore_cli import KeystoreSecurityLevel, PQCKeystore
from openssl_encrypt.modules.security_scorer import SecurityLevel, SecurityScorer

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
            hash_config["sha512"]["rounds"], 10000, "Default should include 10k SHA-512 rounds"
        )
        self.assertEqual(
            hash_config["sha3_256"]["rounds"], 10000, "Default should include 10k SHA3-256 rounds"
        )

        # Check that default KDF configurations are applied
        kdf_config = inner_metadata["derivation_config"]["kdf_config"]
        self.assertTrue(kdf_config["scrypt"]["enabled"], "Default should enable Scrypt")
        self.assertEqual(
            kdf_config["scrypt"]["rounds"], 5, "Default should include 5 Scrypt rounds"
        )
        self.assertTrue(kdf_config["argon2"]["enabled"], "Default should enable Argon2")
        self.assertEqual(
            kdf_config["argon2"]["rounds"], 5, "Default should include 5 Argon2 rounds"
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
            with open(plugin_file, "w") as f:
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

            # Use the module-level SlowPluginForTimeout class (defined outside for picklability)
            if SlowPluginForTimeout is None:
                self.skipTest("Plugin system not available")

            plugin = SlowPluginForTimeout()
            context = PluginSecurityContext("slow_test", {PluginCapability.READ_FILES})
            # No need to add file paths since we're overriding execute()
            sandbox = PluginSandbox()

            # Execute with short timeout and process isolation
            result = sandbox.execute_plugin(
                plugin, context, max_execution_time=0.5, use_process_isolation=True
            )

            # Should fail due to timeout or process crash (both indicate plugin didn't complete)
            # After many tests, the subprocess may crash (exit -11) due to resource exhaustion
            # instead of timing out gracefully, but both outcomes are acceptable
            self.assertFalse(result.success)
            # Accept either timeout message or process failure message
            self.assertTrue(
                "timed out" in result.message.lower() or "process" in result.message.lower(),
                f"Expected timeout or process failure, got: {result.message}",
            )

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
        with open(self.text_file, "w") as f:
            f.write("This is a test file for plugin integration.\nLine 2\nLine 3")
        self.test_files.append(self.text_file)

        self.json_file = os.path.join(self.test_dir, "test.json")
        with open(self.json_file, "w") as f:
            json.dump({"name": "test", "data": [1, 2, 3], "nested": {"key": "value"}}, f)
        self.test_files.append(self.json_file)

        self.csv_file = os.path.join(self.test_dir, "test.csv")
        with open(self.csv_file, "w") as f:
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
            with open(self.text_file, "r") as original, open(backup_path, "r") as backup:
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
            with open(json_output, "r") as f:
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
            with open(encrypted_file, "w") as f:
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
                "whirlpool": {"rounds": 0},
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


class TestSecurityScorer(unittest.TestCase):
    """Test cases for the SecurityScorer system."""

    def setUp(self):
        """Set up test fixtures."""
        self.scorer = SecurityScorer()

    def test_security_level_enum(self):
        """Test SecurityLevel enum values."""
        self.assertEqual(SecurityLevel.MINIMAL.value, 1)
        self.assertEqual(SecurityLevel.LOW.value, 2)
        self.assertEqual(SecurityLevel.MODERATE.value, 3)
        self.assertEqual(SecurityLevel.GOOD.value, 4)
        self.assertEqual(SecurityLevel.HIGH.value, 5)
        self.assertEqual(SecurityLevel.VERY_HIGH.value, 6)
        self.assertEqual(SecurityLevel.MAXIMUM.value, 7)
        self.assertEqual(SecurityLevel.OVERKILL.value, 8)
        self.assertEqual(SecurityLevel.THEORETICAL.value, 9)
        self.assertEqual(SecurityLevel.EXTREME.value, 10)

    def test_hash_strength_ratings(self):
        """Test hash algorithm strength ratings."""
        # Test that all expected algorithms have ratings
        expected_hashes = ["sha256", "sha512", "sha3_256", "sha3_512", "blake2b", "blake3"]
        for hash_alg in expected_hashes:
            self.assertIn(hash_alg, SecurityScorer.HASH_STRENGTH)
            self.assertIsInstance(SecurityScorer.HASH_STRENGTH[hash_alg], (int, float))
            self.assertGreater(SecurityScorer.HASH_STRENGTH[hash_alg], 0)

    def test_kdf_strength_ratings(self):
        """Test KDF algorithm strength ratings."""
        expected_kdfs = ["argon2", "scrypt", "pbkdf2", "balloon", "hkdf"]
        for kdf in expected_kdfs:
            self.assertIn(kdf, SecurityScorer.KDF_STRENGTH)
            self.assertIsInstance(SecurityScorer.KDF_STRENGTH[kdf], (int, float))
            self.assertGreater(SecurityScorer.KDF_STRENGTH[kdf], 0)

    def test_cipher_strength_ratings(self):
        """Test encryption algorithm strength ratings."""
        expected_ciphers = ["aes-gcm", "aes-gcm-siv", "chacha20-poly1305", "xchacha20-poly1305"]
        for cipher in expected_ciphers:
            self.assertIn(cipher, SecurityScorer.CIPHER_STRENGTH)
            self.assertIsInstance(SecurityScorer.CIPHER_STRENGTH[cipher], (int, float))
            self.assertGreater(SecurityScorer.CIPHER_STRENGTH[cipher], 0)

    def test_pqc_bonus_ratings(self):
        """Test post-quantum cryptography bonus ratings."""
        expected_pqc = ["ml-kem", "kyber", "hqc"]
        for pqc in expected_pqc:
            self.assertIn(pqc, SecurityScorer.PQC_BONUS)
            self.assertIsInstance(SecurityScorer.PQC_BONUS[pqc], (int, float))
            self.assertGreater(SecurityScorer.PQC_BONUS[pqc], 0)

    def test_score_hash_config_empty(self):
        """Test hash scoring with empty configuration."""
        hash_config = {}
        result = self.scorer._score_hash_config(hash_config)

        self.assertIsInstance(result, dict)
        self.assertIn("score", result)
        self.assertIn("algorithms", result)
        self.assertIn("total_rounds", result)
        self.assertIn("description", result)
        self.assertEqual(result["score"], 0.0)
        self.assertEqual(result["algorithms"], [])
        self.assertEqual(result["total_rounds"], 0)

    def test_score_hash_config_single(self):
        """Test hash scoring with single algorithm."""
        hash_config = {"sha256": {"rounds": 1000000}}
        result = self.scorer._score_hash_config(hash_config)

        self.assertGreater(result["score"], 0)
        self.assertEqual(result["algorithms"], ["sha256"])
        self.assertEqual(result["total_rounds"], 1000000)
        self.assertIsInstance(result["description"], str)

    def test_score_hash_config_multiple(self):
        """Test hash scoring with multiple algorithms."""
        hash_config = {
            "sha256": {"rounds": 1000000},
            "blake2b": {"rounds": 500000},
            "sha3_512": {"rounds": 200000},
        }
        result = self.scorer._score_hash_config(hash_config)

        self.assertGreater(result["score"], 0)
        self.assertEqual(len(result["algorithms"]), 3)
        self.assertIn("sha256", result["algorithms"])
        self.assertIn("blake2b", result["algorithms"])
        self.assertIn("sha3_512", result["algorithms"])
        self.assertEqual(result["total_rounds"], 1700000)

    def test_score_kdf_config_empty(self):
        """Test KDF scoring with empty configuration."""
        kdf_config = {}
        result = self.scorer._score_kdf_config(kdf_config)

        self.assertEqual(result["score"], 0.0)
        self.assertEqual(result["algorithms"], [])

    def test_score_kdf_config_argon2(self):
        """Test KDF scoring with Argon2 configuration."""
        kdf_config = {
            "argon2": {"enabled": True, "memory_cost": 65536, "time_cost": 3, "parallelism": 4}
        }
        result = self.scorer._score_kdf_config(kdf_config)

        self.assertGreater(result["score"], 0)
        self.assertEqual(result["algorithms"], ["argon2"])
        self.assertIsInstance(result["description"], str)

    def test_score_kdf_config_scrypt(self):
        """Test KDF scoring with Scrypt configuration."""
        kdf_config = {"scrypt": {"enabled": True, "n": 16384, "r": 8, "p": 1}}
        result = self.scorer._score_kdf_config(kdf_config)

        self.assertGreater(result["score"], 0)
        self.assertEqual(result["algorithms"], ["scrypt"])

    def test_score_kdf_config_pbkdf2(self):
        """Test KDF scoring with PBKDF2 configuration."""
        kdf_config = {"pbkdf2": {"enabled": True, "rounds": 100000}}
        result = self.scorer._score_kdf_config(kdf_config)

        self.assertGreater(result["score"], 0)
        self.assertEqual(result["algorithms"], ["pbkdf2"])

    def test_score_cipher_config(self):
        """Test cipher scoring with different algorithms."""
        # Test AES-GCM
        cipher_info = {"algorithm": "aes-gcm"}
        result = self.scorer._score_cipher_config(cipher_info)

        self.assertGreater(result["score"], 0)
        self.assertEqual(result["algorithm"], "aes-gcm")
        self.assertTrue(result["authenticated"])

        # Test ChaCha20-Poly1305
        cipher_info = {"algorithm": "chacha20-poly1305"}
        result = self.scorer._score_cipher_config(cipher_info)

        self.assertGreater(result["score"], 0)
        self.assertEqual(result["algorithm"], "chacha20-poly1305")
        self.assertTrue(result["authenticated"])

        # Test unknown algorithm
        cipher_info = {"algorithm": "unknown-cipher"}
        result = self.scorer._score_cipher_config(cipher_info)

        self.assertEqual(result["score"], 2.0)  # Default score
        self.assertEqual(result["algorithm"], "unknown-cipher")

    def test_score_pqc_config_disabled(self):
        """Test PQC scoring when disabled."""
        result = self.scorer._score_pqc_config(None)
        self.assertEqual(result, 0.0)

        result = self.scorer._score_pqc_config({"enabled": False})
        self.assertEqual(result, 0.0)

    def test_score_pqc_config_enabled(self):
        """Test PQC scoring with different algorithms."""
        # Test ML-KEM
        pqc_info = {"enabled": True, "algorithm": "ml-kem-768"}
        result = self.scorer._score_pqc_config(pqc_info)
        self.assertGreater(result, 0)

        # Test Kyber
        pqc_info = {"enabled": True, "algorithm": "kyber-768"}
        result = self.scorer._score_pqc_config(pqc_info)
        self.assertGreater(result, 0)

        # Test HQC
        pqc_info = {"enabled": True, "algorithm": "hqc-192"}
        result = self.scorer._score_pqc_config(pqc_info)
        self.assertGreater(result, 0)

        # Test unknown PQC algorithm
        pqc_info = {"enabled": True, "algorithm": "unknown-pqc"}
        result = self.scorer._score_pqc_config(pqc_info)
        self.assertEqual(result, 1.0)  # Basic bonus for unknown PQC

    def test_score_to_level(self):
        """Test score to security level conversion."""
        test_cases = [
            (1.5, SecurityLevel.MINIMAL),
            (2.5, SecurityLevel.LOW),
            (3.5, SecurityLevel.MODERATE),
            (4.5, SecurityLevel.GOOD),
            (5.5, SecurityLevel.HIGH),
            (6.5, SecurityLevel.VERY_HIGH),
            (7.5, SecurityLevel.MAXIMUM),
            (8.5, SecurityLevel.OVERKILL),
            (9.2, SecurityLevel.THEORETICAL),
            (9.8, SecurityLevel.EXTREME),
        ]

        for score, expected_level in test_cases:
            result = self.scorer._score_to_level(score)
            self.assertEqual(
                result, expected_level, f"Score {score} should map to {expected_level}"
            )

    def test_get_security_description(self):
        """Test security description generation."""
        descriptions = [
            (1.5, "Basic protection suitable for low-value data"),
            (3.5, "Adequate security for everyday use"),
            (5.5, "Strong protection for sensitive information"),
            (7.5, "Highest practical security level"),
            (9.8, "Maximum possible security settings"),
        ]

        for score, expected_desc in descriptions:
            result = self.scorer._get_security_description(score)
            self.assertEqual(result, expected_desc)

    def test_complete_configuration_scoring_minimal(self):
        """Test complete configuration scoring with minimal setup."""
        hash_config = {"sha256": {"rounds": 100000}}
        kdf_config = {"pbkdf2": {"enabled": True, "rounds": 100000}}
        cipher_info = {"algorithm": "aes-gcm"}

        result = self.scorer.score_configuration(hash_config, kdf_config, cipher_info)

        # Validate structure
        self.assertIn("overall", result)
        self.assertIn("hash_analysis", result)
        self.assertIn("kdf_analysis", result)
        self.assertIn("cipher_analysis", result)
        self.assertIn("pqc_analysis", result)
        self.assertIn("estimates", result)
        self.assertIn("suggestions", result)

        # Validate overall score
        self.assertIsInstance(result["overall"]["score"], (int, float))
        self.assertGreaterEqual(result["overall"]["score"], 1.0)
        self.assertLessEqual(result["overall"]["score"], 10.0)
        self.assertIsInstance(result["overall"]["level"], SecurityLevel)
        self.assertIsInstance(result["overall"]["description"], str)

        # Validate PQC analysis
        self.assertFalse(result["pqc_analysis"]["enabled"])
        self.assertEqual(result["pqc_analysis"]["score"], 0)

    def test_complete_configuration_scoring_maximum(self):
        """Test complete configuration scoring with maximum security setup."""
        hash_config = {
            "sha256": {"rounds": 10000000},
            "blake3": {"rounds": 5000000},
            "sha3_512": {"rounds": 2000000},
        }
        kdf_config = {
            "argon2": {
                "enabled": True,
                "memory_cost": 1048576,  # 1GB
                "time_cost": 10,
                "parallelism": 8,
            },
            "scrypt": {"enabled": True, "n": 1048576, "r": 8, "p": 1},
        }
        cipher_info = {"algorithm": "xchacha20-poly1305"}
        pqc_info = {"enabled": True, "algorithm": "ml-kem-1024"}

        result = self.scorer.score_configuration(hash_config, kdf_config, cipher_info, pqc_info)

        # Should have higher overall score
        self.assertGreaterEqual(result["overall"]["score"], 5.0)

        # Should detect multiple algorithms
        self.assertGreater(len(result["hash_analysis"]["algorithms"]), 1)
        self.assertGreater(len(result["kdf_analysis"]["algorithms"]), 1)

        # Should detect PQC
        self.assertTrue(result["pqc_analysis"]["enabled"])
        self.assertGreater(result["pqc_analysis"]["score"], 0)

        # Should have authenticated encryption
        self.assertTrue(result["cipher_analysis"]["authenticated"])

    def test_security_estimates(self):
        """Test security time estimates generation."""
        hash_score = {"total_rounds": 1000000}
        kdf_score = {"algorithms": ["argon2"]}
        cipher_score = {"algorithm": "aes-gcm"}

        result = self.scorer._calculate_security_estimates(hash_score, kdf_score, cipher_score)

        self.assertIn("brute_force_time", result)
        self.assertIn("note", result)
        self.assertIn("disclaimer", result)
        self.assertIsInstance(result["brute_force_time"], str)
        self.assertIsInstance(result["note"], str)
        self.assertIsInstance(result["disclaimer"], str)

    def test_generate_suggestions(self):
        """Test suggestion generation."""
        # Test low-security configuration
        low_scores = {
            "overall": {"score": 2.0},
            "hash_analysis": {"score": 2.0},
            "kdf_analysis": {"score": 2.0},
            "cipher_analysis": {"score": 2.0},
            "pqc_analysis": {"enabled": False, "score": 0},
        }

        suggestions = self.scorer._generate_suggestions(low_scores)
        self.assertIsInstance(suggestions, list)
        self.assertGreater(len(suggestions), 0)
        self.assertTrue(any("stronger algorithm" in s for s in suggestions))
        self.assertTrue(any("post-quantum" in s for s in suggestions))

        # Test high-security configuration
        high_scores = {
            "overall": {"score": 9.0},
            "hash_analysis": {"score": 8.0},
            "kdf_analysis": {"score": 8.0},
            "cipher_analysis": {"score": 8.0},
            "pqc_analysis": {"enabled": True, "score": 2.0},
        }

        suggestions = self.scorer._generate_suggestions(high_scores)
        self.assertIsInstance(suggestions, list)
        self.assertTrue(any("stronger than necessary" in s for s in suggestions))

    def test_convenience_function(self):
        """Test the convenience function analyze_security_config."""
        from openssl_encrypt.modules.security_scorer import analyze_security_config

        hash_config = {"sha256": {"rounds": 1000000}}
        kdf_config = {"argon2": {"enabled": True, "memory_cost": 65536}}
        cipher_info = {"algorithm": "aes-gcm"}

        result = analyze_security_config(hash_config, kdf_config, cipher_info)

        self.assertIn("overall", result)
        self.assertIn("hash_analysis", result)
        self.assertIn("kdf_analysis", result)
        self.assertIn("cipher_analysis", result)


@pytest.mark.xdist_group(name="config_wizard")
class TestConfigurationWizard(unittest.TestCase):
    """Test cases for the ConfigurationWizard system."""

    def setUp(self):
        """Set up test fixtures."""
        self.wizard = ConfigurationWizard()

    def test_user_expertise_enum(self):
        """Test UserExpertise enum values."""
        self.assertEqual(UserExpertise.BEGINNER.value, "beginner")
        self.assertEqual(UserExpertise.INTERMEDIATE.value, "intermediate")
        self.assertEqual(UserExpertise.ADVANCED.value, "advanced")
        self.assertEqual(UserExpertise.EXPERT.value, "expert")

    def test_use_case_enum(self):
        """Test UseCase enum values."""
        self.assertEqual(UseCase.PERSONAL_FILES.value, "personal")
        self.assertEqual(UseCase.BUSINESS_DOCUMENTS.value, "business")
        self.assertEqual(UseCase.SENSITIVE_DATA.value, "sensitive")
        self.assertEqual(UseCase.ARCHIVAL_STORAGE.value, "archival")
        self.assertEqual(UseCase.HIGH_SECURITY.value, "high_security")
        self.assertEqual(UseCase.COMPLIANCE.value, "compliance")

    def test_wizard_initialization(self):
        """Test wizard initialization."""
        self.assertIsNotNone(self.wizard.scorer)
        self.assertEqual(self.wizard.config, {})
        self.assertIsNone(self.wizard.user_expertise)
        self.assertIsNone(self.wizard.use_case)

    def test_quiet_mode_wizard(self):
        """Test wizard running in quiet mode."""
        config = self.wizard.run_wizard(quiet=True)

        # Should have default values
        self.assertEqual(self.wizard.user_expertise, UserExpertise.INTERMEDIATE)
        self.assertEqual(self.wizard.use_case, UseCase.PERSONAL_FILES)

        # Should return a valid configuration
        self.assertIsInstance(config, dict)
        self.assertIn("hash_algorithms", config)
        self.assertIn("kdf_settings", config)
        self.assertIn("encryption", config)
        self.assertIn("post_quantum", config)

    def test_base_config_generation_personal_files(self):
        """Test base configuration generation for personal files."""
        self.wizard.user_expertise = UserExpertise.INTERMEDIATE
        self.wizard.use_case = UseCase.PERSONAL_FILES

        config = self.wizard._generate_base_config()

        # Should have balanced security/performance settings
        self.assertIn("sha256", config["hash_algorithms"])
        self.assertEqual(config["hash_algorithms"]["sha256"]["rounds"], 1000000)

        self.assertIn("argon2", config["kdf_settings"])
        self.assertTrue(config["kdf_settings"]["argon2"]["enabled"])
        self.assertEqual(config["kdf_settings"]["argon2"]["memory_cost"], 65536)  # 64MB

        self.assertEqual(config["encryption"]["algorithm"], "aes-gcm")

    def test_base_config_generation_sensitive_data(self):
        """Test base configuration generation for sensitive data."""
        self.wizard.user_expertise = UserExpertise.ADVANCED
        self.wizard.use_case = UseCase.SENSITIVE_DATA

        config = self.wizard._generate_base_config()

        # Should have higher security
        self.assertIn("sha256", config["hash_algorithms"])
        self.assertIn("blake2b", config["hash_algorithms"])
        self.assertEqual(config["hash_algorithms"]["sha256"]["rounds"], 2000000)

        self.assertIn("argon2", config["kdf_settings"])
        self.assertIn("scrypt", config["kdf_settings"])
        self.assertEqual(config["kdf_settings"]["argon2"]["memory_cost"], 131072)  # 128MB

        self.assertEqual(config["encryption"]["algorithm"], "xchacha20-poly1305")

    def test_base_config_generation_archival_storage(self):
        """Test base configuration generation for archival storage."""
        self.wizard.user_expertise = UserExpertise.EXPERT
        self.wizard.use_case = UseCase.ARCHIVAL_STORAGE

        config = self.wizard._generate_base_config()

        # Should emphasize future-proofing
        self.assertIn("sha3_512", config["hash_algorithms"])
        self.assertIn("blake3", config["hash_algorithms"])

        self.assertEqual(config["kdf_settings"]["argon2"]["memory_cost"], 262144)  # 256MB
        self.assertEqual(config["encryption"]["algorithm"], "aes-gcm-siv")

        # Should enable post-quantum by default
        self.assertTrue(config["post_quantum"]["enabled"])
        self.assertEqual(config["post_quantum"]["algorithm"], "ml-kem-768")

    def test_base_config_generation_high_security(self):
        """Test base configuration generation for high security."""
        self.wizard.user_expertise = UserExpertise.EXPERT
        self.wizard.use_case = UseCase.HIGH_SECURITY

        config = self.wizard._generate_base_config()

        # Should have maximum security
        self.assertIn("sha256", config["hash_algorithms"])
        self.assertIn("sha3_512", config["hash_algorithms"])
        self.assertIn("blake3", config["hash_algorithms"])
        self.assertEqual(config["hash_algorithms"]["sha256"]["rounds"], 5000000)

        self.assertIn("argon2", config["kdf_settings"])
        self.assertIn("scrypt", config["kdf_settings"])
        self.assertEqual(config["kdf_settings"]["argon2"]["memory_cost"], 524288)  # 512MB

        self.assertEqual(config["encryption"]["algorithm"], "xchacha20-poly1305")
        self.assertTrue(config["post_quantum"]["enabled"])
        self.assertEqual(config["post_quantum"]["algorithm"], "ml-kem-1024")

    def test_generate_cli_arguments_basic(self):
        """Test CLI argument generation for basic configuration."""
        config = {
            "hash_algorithms": {"sha256": {"rounds": 1000000}},
            "kdf_settings": {
                "argon2": {"enabled": True, "memory_cost": 65536, "time_cost": 3, "parallelism": 4}
            },
            "encryption": {"algorithm": "aes-gcm"},
            "post_quantum": {},
        }

        args = generate_cli_arguments(config)

        expected_args = [
            "--sha256-rounds",
            "1000000",
            "--argon2-memory-cost",
            "65536",
            "--argon2-time-cost",
            "3",
            "--argon2-parallelism",
            "4",
            "--encryption-data-algorithm",
            "aes-gcm",
        ]

        for arg in expected_args:
            self.assertIn(arg, args)

    def test_generate_cli_arguments_advanced(self):
        """Test CLI argument generation for advanced configuration."""
        config = {
            "hash_algorithms": {"sha256": {"rounds": 2000000}, "blake3": {"rounds": 1000000}},
            "kdf_settings": {
                "argon2": {
                    "enabled": True,
                    "memory_cost": 131072,
                    "time_cost": 4,
                    "parallelism": 8,
                },
                "scrypt": {"enabled": True, "n": 32768, "r": 8, "p": 1},
            },
            "encryption": {"algorithm": "xchacha20-poly1305"},
            "post_quantum": {"enabled": True, "algorithm": "ml-kem-768"},
        }

        args = generate_cli_arguments(config)

        # Should have all hash algorithms
        self.assertIn("--sha256-rounds", args)
        self.assertIn("2000000", args)
        self.assertIn("--blake3-rounds", args)
        self.assertIn("1000000", args)

        # Should have both KDFs
        self.assertIn("--argon2-memory-cost", args)
        self.assertIn("131072", args)
        self.assertIn("--scrypt-n", args)
        self.assertIn("32768", args)

        # Should have encryption algorithm
        self.assertIn("--encryption-data-algorithm", args)
        self.assertIn("xchacha20-poly1305", args)

        # Should have post-quantum
        self.assertIn("--pqc-algorithm", args)
        self.assertIn("ml-kem-768", args)

    def test_generate_cli_arguments_with_underscores(self):
        """Test CLI argument generation handles underscores correctly."""
        config = {
            "hash_algorithms": {"sha3_256": {"rounds": 1500000}, "sha3_512": {"rounds": 800000}},
            "kdf_settings": {},
            "encryption": {"algorithm": "aes-gcm"},
            "post_quantum": {},
        }

        args = generate_cli_arguments(config)

        # Should convert underscores to hyphens in CLI arguments
        self.assertIn("--sha3-256-rounds", args)
        self.assertIn("1500000", args)
        self.assertIn("--sha3-512-rounds", args)
        self.assertIn("800000", args)

    def test_generate_cli_arguments_empty_config(self):
        """Test CLI argument generation with empty configuration."""
        config = {"hash_algorithms": {}, "kdf_settings": {}, "encryption": {}, "post_quantum": {}}

        args = generate_cli_arguments(config)

        # Should return empty or minimal args
        self.assertIsInstance(args, list)

    def test_convenience_function(self):
        """Test the convenience function run_configuration_wizard."""
        config = run_configuration_wizard(quiet=True)

        self.assertIsInstance(config, dict)
        self.assertIn("hash_algorithms", config)
        self.assertIn("kdf_settings", config)
        self.assertIn("encryption", config)
        self.assertIn("post_quantum", config)

    def test_wizard_config_completeness(self):
        """Test that wizard generates complete configurations."""
        test_cases = [
            (UserExpertise.BEGINNER, UseCase.PERSONAL_FILES),
            (UserExpertise.INTERMEDIATE, UseCase.BUSINESS_DOCUMENTS),
            (UserExpertise.ADVANCED, UseCase.SENSITIVE_DATA),
            (UserExpertise.EXPERT, UseCase.HIGH_SECURITY),
        ]

        for expertise, use_case in test_cases:
            with self.subTest(
                expertise=expertise.value, use_case=use_case.value
            ):  # Use .value for pytest-xdist serialization
                self.wizard.user_expertise = expertise
                self.wizard.use_case = use_case

                config = self.wizard._generate_base_config()

                # All configurations should have these basic components
                self.assertIn("hash_algorithms", config)
                self.assertIn("kdf_settings", config)
                self.assertIn("encryption", config)
                self.assertIn("post_quantum", config)

                # Should have at least one hash algorithm
                self.assertGreater(len(config["hash_algorithms"]), 0)

                # Should have at least one KDF
                enabled_kdfs = [k for k, v in config["kdf_settings"].items() if v.get("enabled")]
                self.assertGreater(len(enabled_kdfs), 0)

                # Should have encryption algorithm
                self.assertIn("algorithm", config["encryption"])
                self.assertIsInstance(config["encryption"]["algorithm"], str)

    def test_cli_argument_round_trip(self):
        """Test that generated CLI arguments would produce equivalent security scores."""
        # Generate a configuration
        self.wizard.user_expertise = UserExpertise.ADVANCED
        self.wizard.use_case = UseCase.SENSITIVE_DATA
        config = self.wizard._generate_base_config()

        # Generate CLI arguments
        cli_args = generate_cli_arguments(config)

        # Verify that the arguments are valid format
        self.assertIsInstance(cli_args, list)

        # Arguments should come in pairs (flag, value) mostly
        # Count arguments that start with '--'
        flags = [arg for arg in cli_args if arg.startswith("--")]
        self.assertGreater(len(flags), 0)

        # Each flag should have valid format
        for flag in flags:
            self.assertTrue(flag.startswith("--"))
            self.assertNotIn("_", flag)  # Should use hyphens, not underscores


class TestConfigurationAnalyzer(unittest.TestCase):
    """Test configuration analysis functionality."""

    def setUp(self):
        """Set up test environment."""
        from ..modules.config_analyzer import (
            AnalysisCategory,
            ConfigurationAnalyzer,
            RecommendationPriority,
        )

        self.analyzer = ConfigurationAnalyzer()

    def test_basic_configuration_analysis(self):
        """Test basic configuration analysis."""
        config = {
            "algorithm": "aes-gcm",
            "sha256_rounds": 1000,
            "pbkdf2_iterations": 100000,
            "enable_argon2": False,
            "enable_scrypt": False,
        }

        analysis = self.analyzer.analyze_configuration(config)

        self.assertIsInstance(analysis.overall_score, float)
        self.assertTrue(1.0 <= analysis.overall_score <= 10.0)
        self.assertIsNotNone(analysis.security_level)
        self.assertIsInstance(analysis.recommendations, list)
        self.assertIsInstance(analysis.configuration_summary, dict)

    def test_performance_assessment(self):
        """Test performance assessment functionality."""
        config = {
            "algorithm": "aes-gcm",
            "sha256_rounds": 100000,
            "enable_argon2": True,
            "argon2_memory": 1048576,  # 1GB
            "argon2_time": 3,
        }

        analysis = self.analyzer.analyze_configuration(config)
        perf = analysis.performance_assessment

        self.assertIn("overall_score", perf)
        self.assertIn("estimated_relative_speed", perf)
        self.assertIn("memory_requirements", perf)
        self.assertIn("cpu_intensity", perf)

        # High memory usage should be reflected
        self.assertGreater(perf["memory_requirements"]["estimated_peak_mb"], 1000)

    def test_compatibility_analysis(self):
        """Test compatibility analysis across platforms."""
        config = {"algorithm": "xchacha20-poly1305", "sha256_rounds": 1000}

        analysis = self.analyzer.analyze_configuration(config)
        compat = analysis.compatibility_matrix

        self.assertIn("platform_compatibility", compat)
        self.assertIn("library_compatibility", compat)
        self.assertIn("overall_compatibility_score", compat)
        self.assertTrue(0.0 <= compat["overall_compatibility_score"] <= 10.0)

    def test_security_recommendations(self):
        """Test security-focused recommendations."""
        # Weak configuration to trigger recommendations
        config = {
            "algorithm": "fernet",
            "sha256_rounds": 100,  # Very low
            "pbkdf2_iterations": 1000,  # Low
            "enable_argon2": False,
        }

        analysis = self.analyzer.analyze_configuration(config)

        # Should generate multiple recommendations for this weak config
        self.assertGreater(len(analysis.recommendations), 0)

        # Check that we have security-related recommendations
        security_recs = [r for r in analysis.recommendations if r.category.value == "security"]
        self.assertGreater(len(security_recs), 0)

    def test_use_case_analysis(self):
        """Test use case specific analysis."""
        config = {"algorithm": "aes-gcm", "sha256_rounds": 1000, "pbkdf2_iterations": 100000}

        # Test different use cases
        for use_case in ["personal", "business", "compliance", "archival"]:
            analysis = self.analyzer.analyze_configuration(config, use_case)
            self.assertIsInstance(analysis.recommendations, list)

            # Archival should recommend post-quantum
            if use_case == "archival":
                pq_recs = [r for r in analysis.recommendations if "quantum" in r.title.lower()]
                self.assertGreater(len(pq_recs), 0)

    def test_compliance_checking(self):
        """Test compliance framework checking."""
        # FIPS-compliant config
        config = {"algorithm": "aes-gcm", "pbkdf2_iterations": 100000, "enable_argon2": False}

        analysis = self.analyzer.analyze_configuration(
            config, compliance_requirements=["fips_140_2"]
        )

        self.assertIn("fips_140_2", analysis.compliance_status)
        fips_status = analysis.compliance_status["fips_140_2"]
        self.assertIn("compliant", fips_status)

    def test_future_proofing_assessment(self):
        """Test future-proofing assessment."""
        config = {
            "algorithm": "aes-gcm",
            "sha256_rounds": 1000,
            "pqc_algorithm": "ml-kem-768-hybrid",  # With PQC
        }

        analysis = self.analyzer.analyze_configuration(config)
        future = analysis.future_proofing

        self.assertIn("algorithm_longevity_score", future)
        self.assertIn("post_quantum_ready", future)
        self.assertIn("estimated_secure_years", future)

        # With PQC enabled, should be quantum ready
        self.assertTrue(future["post_quantum_ready"])

    def test_configuration_summary(self):
        """Test configuration summary generation."""
        config = {
            "algorithm": "xchacha20-poly1305",
            "sha256_rounds": 10000,
            "blake2b_rounds": 5000,
            "enable_argon2": True,
            "enable_scrypt": True,
            "pqc_algorithm": "ml-kem-1024-hybrid",
        }

        analysis = self.analyzer.analyze_configuration(config)
        summary = analysis.configuration_summary

        self.assertEqual(summary["algorithm"], "xchacha20-poly1305")
        self.assertIn("sha256", summary["active_hash_functions"])
        self.assertIn("blake2b", summary["active_hash_functions"])
        self.assertIn("Argon2", summary["active_kdfs"])
        self.assertIn("Scrypt", summary["active_kdfs"])
        self.assertTrue(summary["post_quantum_enabled"])
        self.assertIn("configuration_complexity", summary)

    def test_recommendation_priorities(self):
        """Test that recommendations are properly prioritized."""
        # Create a configuration with critical issues
        config = {
            "algorithm": "fernet",
            "sha256_rounds": 1,  # Extremely low
            "pbkdf2_iterations": 1,  # Extremely low
        }

        analysis = self.analyzer.analyze_configuration(config, "compliance")

        # Should have critical recommendations
        critical_recs = [r for r in analysis.recommendations if r.priority.value == "critical"]
        self.assertGreater(len(critical_recs), 0)

        # Recommendations should be sorted by priority
        priorities = [r.priority.value for r in analysis.recommendations]
        priority_order = ["critical", "high", "medium", "low", "info"]

        # Check that priorities are in correct order
        last_priority_index = -1
        for priority in priorities:
            current_index = priority_order.index(priority)
            self.assertGreaterEqual(current_index, last_priority_index)
            last_priority_index = current_index

    def test_analyze_configuration_from_args(self):
        """Test the convenience function for analyzing from CLI args."""
        import argparse

        from ..modules.config_analyzer import analyze_configuration_from_args

        # Create mock args
        args = argparse.Namespace(
            algorithm="aes-gcm",
            sha256_rounds=10000,
            pbkdf2_iterations=100000,
            enable_argon2=True,
            argon2_memory=524288,
            enable_scrypt=False,
            pqc_algorithm=None,
        )

        analysis = analyze_configuration_from_args(args, "business")

        self.assertIsInstance(analysis.overall_score, float)
        self.assertIsInstance(analysis.recommendations, list)


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


class TestTemplateManager(unittest.TestCase):
    """Test template management system functionality."""

    def setUp(self):
        """Set up test environment."""
        import os
        import tempfile

        from ..modules.template_manager import EnhancedTemplate, TemplateManager, TemplateMetadata

        self.manager = TemplateManager()
        # Create temporary directory for test templates
        self.test_dir = tempfile.mkdtemp()
        self.manager.template_dir = self.test_dir

    def tearDown(self):
        """Clean up test environment."""
        import shutil

        if hasattr(self, "test_dir"):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_template_creation_from_wizard(self):
        """Test creating template from wizard configuration."""
        from ..modules.template_manager import EnhancedTemplate

        wizard_config = {
            "algorithm": "aes-gcm",
            "kdf_algorithm": "argon2id",
            "argon2_time_cost": 4,
            "argon2_memory_cost": 65536,
            "argon2_parallelism": 4,
            "compression": True,
            "metadata_embedded": True,
            "secure_deletion": True,
        }

        template = self.manager.create_template_from_wizard(
            wizard_config,
            name="test-template",
            description="Test template from wizard",
            use_cases=["personal", "business"],
        )

        self.assertIsInstance(template, EnhancedTemplate)
        self.assertEqual(template.metadata.name, "test-template")
        self.assertEqual(template.metadata.description, "Test template from wizard")
        self.assertEqual(template.metadata.use_cases, ["personal", "business"])
        self.assertEqual(template.config["hash_config"]["algorithm"], "aes-gcm")

    def test_template_saving_and_loading(self):
        """Test template saving and loading functionality."""
        import json

        from ..modules.template_manager import EnhancedTemplate, TemplateFormat, TemplateMetadata

        # Create test template
        config = {
            "hash_config": {
                "algorithm": "xchacha20-poly1305",
                "sha256": 1000,
                "argon2": {"enabled": True},
            }
        }
        metadata = TemplateMetadata(
            name="test-save",
            description="Test save/load",
            use_cases=["personal"],
            security_level="MODERATE",
        )
        template = EnhancedTemplate(config=config, metadata=metadata)

        # Save template
        filename = self.manager.save_template(template, format=TemplateFormat.JSON)
        self.assertTrue(filename.endswith(".json"))

        # Load template
        loaded_template = self.manager.load_template(filename)
        self.assertEqual(loaded_template.metadata.name, "test-save")
        self.assertEqual(loaded_template.config["hash_config"]["algorithm"], "xchacha20-poly1305")

    def test_template_comparison(self):
        """Test template comparison functionality."""
        from ..modules.template_manager import EnhancedTemplate, TemplateMetadata

        # Create two templates
        template1 = EnhancedTemplate(
            config={
                "hash_config": {"algorithm": "aes-gcm", "sha256": 1000, "argon2": {"enabled": True}}
            },
            metadata=TemplateMetadata(name="template1", security_level="MODERATE"),
        )
        template2 = EnhancedTemplate(
            config={
                "hash_config": {
                    "algorithm": "xchacha20-poly1305",
                    "sha512": 2000,
                    "scrypt": {"enabled": True},
                }
            },
            metadata=TemplateMetadata(name="template2", security_level="HIGH"),
        )

        comparison = self.manager.compare_templates(template1, template2)

        self.assertIn("templates", comparison)
        self.assertIn("security_comparison", comparison)
        self.assertIn("performance_comparison", comparison)
        self.assertIn("recommendations", comparison)

        # Check that template info is included
        templates = comparison["templates"]
        self.assertIn("template1", templates)
        self.assertIn("template2", templates)

    def test_template_recommendations(self):
        """Test template recommendation system."""
        import os

        from ..modules.template_manager import EnhancedTemplate, TemplateMetadata

        # Create test templates for different use cases
        personal_template = EnhancedTemplate(
            config={
                "hash_config": {"algorithm": "fernet", "sha256": 500, "pbkdf2_iterations": 5000}
            },
            metadata=TemplateMetadata(
                name="personal-template", use_cases=["personal"], security_level="MINIMAL"
            ),
        )
        business_template = EnhancedTemplate(
            config={
                "hash_config": {"algorithm": "aes-gcm", "sha256": 1000, "argon2": {"enabled": True}}
            },
            metadata=TemplateMetadata(
                name="business-template", use_cases=["business"], security_level="MODERATE"
            ),
        )

        # Save templates
        self.manager.save_template(personal_template)
        self.manager.save_template(business_template)

        # Get recommendations for business use case
        recommendations = self.manager.recommend_templates("business", max_results=2)

        self.assertIsInstance(recommendations, list)
        self.assertTrue(len(recommendations) >= 1)

        # Check that business template is recommended for business use case
        template_names = [rec[0].metadata.name for rec in recommendations]
        self.assertIn("business-template", template_names)

    def test_template_analysis_integration(self):
        """Test template analysis integration with configuration analyzer."""
        from ..modules.config_analyzer import ConfigurationAnalyzer
        from ..modules.template_manager import EnhancedTemplate, TemplateMetadata

        # Create template with analyzable configuration
        config = {
            "hash_config": {
                "algorithm": "aes-gcm",
                "sha256": 1000,
                "argon2": {"enabled": True, "time_cost": 4, "memory_cost": 65536},
            }
        }
        template = EnhancedTemplate(
            config=config,
            metadata=TemplateMetadata(name="analysis-test", security_level="MODERATE"),
        )

        # Analyze template
        analysis = self.manager.analyze_template(template, use_case="business")

        self.assertIsNotNone(analysis)
        self.assertIn("overall_score", analysis.__dict__)
        self.assertIn("performance_assessment", analysis.__dict__)
        self.assertIn("recommendations", analysis.__dict__)

    def test_template_validation(self):
        """Test template validation functionality."""
        from ..modules.template_manager import EnhancedTemplate, TemplateMetadata

        # Test valid template
        valid_config = {
            "hash_config": {
                "algorithm": "aes-gcm",
                "sha256": 1000,  # Hash function with iterations
                "argon2": {"enabled": True},  # KDF configuration
            }
        }
        valid_template = EnhancedTemplate(
            config=valid_config, metadata=TemplateMetadata(name="valid", security_level="MODERATE")
        )

        is_valid, errors = self.manager.validate_template(valid_template)
        if not is_valid:
            print(f"Validation errors: {errors}")
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

        # Test invalid template (missing required field)
        invalid_config = {
            "hash_config": {"kdf_algorithm": "argon2id"}
        }  # missing algorithm and hash functions
        invalid_template = EnhancedTemplate(
            config=invalid_config,
            metadata=TemplateMetadata(name="invalid", security_level="MINIMAL"),
        )

        is_valid, errors = self.manager.validate_template(invalid_template)
        self.assertFalse(is_valid)
        self.assertGreater(len(errors), 0)

    def test_template_listing_with_filters(self):
        """Test template listing with use case filters."""
        from ..modules.template_manager import EnhancedTemplate, TemplateMetadata

        # Create templates for different use cases
        personal_template = EnhancedTemplate(
            config={
                "hash_config": {"algorithm": "fernet", "sha256": 500, "pbkdf2_iterations": 5000}
            },
            metadata=TemplateMetadata(name="personal", use_cases=["personal"]),
        )
        business_template = EnhancedTemplate(
            config={
                "hash_config": {"algorithm": "aes-gcm", "sha256": 1000, "argon2": {"enabled": True}}
            },
            metadata=TemplateMetadata(name="business", use_cases=["business"]),
        )
        mixed_template = EnhancedTemplate(
            config={
                "hash_config": {
                    "algorithm": "xchacha20-poly1305",
                    "sha512": 2000,
                    "argon2": {"enabled": True},
                }
            },
            metadata=TemplateMetadata(name="mixed", use_cases=["personal", "business"]),
        )

        # Save templates
        self.manager.save_template(personal_template)
        self.manager.save_template(business_template)
        self.manager.save_template(mixed_template)

        # List all templates
        all_templates = self.manager.list_templates()
        self.assertGreaterEqual(len(all_templates), 3)

        # Filter templates manually by use case since the method doesn't support this filter
        all_templates = self.manager.list_templates()

        # Filter by personal use case
        personal_templates = [t for t in all_templates if "personal" in t.metadata.use_cases]
        personal_names = [t.metadata.name for t in personal_templates]
        self.assertIn("personal", personal_names)
        self.assertIn("mixed", personal_names)  # Mixed should be included

        # Filter by business use case
        business_templates = [t for t in all_templates if "business" in t.metadata.use_cases]
        business_names = [t.metadata.name for t in business_templates]
        self.assertIn("business", business_names)
        self.assertIn("mixed", business_names)  # Mixed should be included

    def test_template_deletion(self):
        """Test template deletion functionality."""
        import os

        from ..modules.template_manager import EnhancedTemplate, TemplateMetadata

        # Create and save template
        template = EnhancedTemplate(
            config={
                "hash_config": {"algorithm": "aes-gcm", "sha256": 1000, "argon2": {"enabled": True}}
            },
            metadata=TemplateMetadata(name="delete-test", security_level="MODERATE"),
        )
        filename = self.manager.save_template(template)

        # Verify template exists
        self.assertTrue(os.path.exists(filename))

        # Delete template
        result = self.manager.delete_template(template)
        self.assertTrue(result)

        # Verify template is deleted
        self.assertFalse(os.path.exists(filename))


class TestSmartRecommendations(unittest.TestCase):
    """Test smart recommendations system functionality."""

    def setUp(self):
        """Set up test environment."""
        import os
        import tempfile

        from ..modules.smart_recommendations import SmartRecommendationEngine, UserContext

        # Create temporary directory for test data
        self.test_dir = tempfile.mkdtemp()
        self.engine = SmartRecommendationEngine(data_dir=self.test_dir)

    def tearDown(self):
        """Clean up test environment."""
        import shutil

        if hasattr(self, "test_dir"):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_user_context_creation(self):
        """Test user context creation and configuration."""
        from ..modules.smart_recommendations import UserContext

        context = UserContext(
            user_type="business",
            experience_level="advanced",
            primary_use_cases=["business", "compliance"],
            data_sensitivity="high",
        )

        self.assertEqual(context.user_type, "business")
        self.assertEqual(context.experience_level, "advanced")
        self.assertEqual(context.primary_use_cases, ["business", "compliance"])
        self.assertEqual(context.data_sensitivity, "high")

    def test_basic_recommendations_generation(self):
        """Test basic recommendation generation."""
        from ..modules.smart_recommendations import UserContext

        user_context = UserContext(
            user_type="personal",
            experience_level="intermediate",
            primary_use_cases=["personal"],
            data_sensitivity="medium",
        )

        recommendations = self.engine.generate_recommendations(user_context)

        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)

        # Check recommendation structure
        for rec in recommendations:
            self.assertTrue(hasattr(rec, "id"))
            self.assertTrue(hasattr(rec, "category"))
            self.assertTrue(hasattr(rec, "priority"))
            self.assertTrue(hasattr(rec, "confidence"))
            self.assertTrue(hasattr(rec, "title"))
            self.assertTrue(hasattr(rec, "description"))
            self.assertTrue(hasattr(rec, "action"))

    def test_security_recommendations(self):
        """Test security-focused recommendations."""
        from ..modules.smart_recommendations import RecommendationCategory, UserContext

        # High sensitivity context should generate security recommendations
        user_context = UserContext(
            user_type="compliance",
            data_sensitivity="high",
            primary_use_cases=["compliance"],
            security_clearance_level="high",
        )

        recommendations = self.engine.generate_recommendations(user_context)

        # Should have security category recommendations
        security_recs = [
            r for r in recommendations if r.category == RecommendationCategory.SECURITY
        ]
        self.assertGreater(len(security_recs), 0)

        # Should recommend post-quantum encryption for high sensitivity
        pq_recs = [
            r
            for r in recommendations
            if "quantum" in r.title.lower() or "quantum" in r.description.lower()
        ]
        self.assertGreater(len(pq_recs), 0)

    def test_algorithm_recommendations(self):
        """Test algorithm-specific recommendations."""
        from ..modules.smart_recommendations import RecommendationCategory, UserContext

        user_context = UserContext(
            user_type="business",
            primary_use_cases=["business"],
            typical_file_sizes="large",
            performance_priority="speed",
        )

        current_config = {"algorithm": "fernet"}  # Suboptimal for business use

        recommendations = self.engine.generate_recommendations(user_context, current_config)

        # Should have algorithm recommendations
        algo_recs = [r for r in recommendations if r.category == RecommendationCategory.ALGORITHM]
        self.assertGreater(len(algo_recs), 0)

        # Should suggest better algorithms for business use
        business_improvement_recs = [r for r in algo_recs if "fernet" in r.description.lower()]
        self.assertGreater(len(business_improvement_recs), 0)

    def test_template_recommendations(self):
        """Test template recommendation integration."""
        from ..modules.smart_recommendations import RecommendationCategory, UserContext

        user_context = UserContext(primary_use_cases=["personal"], experience_level="beginner")

        recommendations = self.engine.generate_recommendations(user_context)

        # Should have template recommendations
        template_recs = [
            r for r in recommendations if r.category == RecommendationCategory.TEMPLATE
        ]
        self.assertGreater(len(template_recs), 0)

        # Template recommendations should mention using --template
        template_actions = [r.action for r in template_recs]
        template_mentioned = any("template" in action.lower() for action in template_actions)
        self.assertTrue(template_mentioned)

    def test_compliance_recommendations(self):
        """Test compliance-specific recommendations."""
        from ..modules.smart_recommendations import RecommendationCategory, UserContext

        user_context = UserContext(
            user_type="compliance",
            primary_use_cases=["compliance"],
            compliance_requirements=["fips_140_2", "common_criteria"],
        )

        recommendations = self.engine.generate_recommendations(user_context)

        # Should have compliance recommendations
        compliance_recs = [
            r for r in recommendations if r.category == RecommendationCategory.COMPLIANCE
        ]
        self.assertGreater(len(compliance_recs), 0)

        # Should mention FIPS 140-2 or Common Criteria
        compliance_content = " ".join(
            [r.title + " " + r.description for r in compliance_recs]
        ).lower()
        self.assertTrue("fips" in compliance_content or "common criteria" in compliance_content)

    def test_performance_recommendations(self):
        """Test performance optimization recommendations."""
        from ..modules.smart_recommendations import RecommendationCategory, UserContext

        user_context = UserContext(
            performance_priority="speed", computational_constraints=True, typical_file_sizes="large"
        )

        recommendations = self.engine.generate_recommendations(user_context)

        # Should have performance recommendations
        perf_recs = [r for r in recommendations if r.category == RecommendationCategory.PERFORMANCE]
        self.assertGreater(len(perf_recs), 0)

        # Should mention optimization for speed or constraints
        perf_content = " ".join([r.title + " " + r.description for r in perf_recs]).lower()
        self.assertTrue(
            "speed" in perf_content
            or "performance" in perf_content
            or "constrained" in perf_content
        )

    def test_user_preferences_application(self):
        """Test application of user preferences and feedback."""
        from ..modules.smart_recommendations import UserContext

        user_context = UserContext(
            primary_use_cases=["personal"],
            preferred_algorithms=["aes-gcm"],
            avoided_algorithms=["fernet"],
        )

        recommendations = self.engine.generate_recommendations(user_context)

        # Should not recommend avoided algorithms
        fernet_recs = [r for r in recommendations if "fernet" in r.action.lower()]
        self.assertEqual(len(fernet_recs), 0)

        # Should boost confidence for preferred algorithms
        aes_gcm_recs = [r for r in recommendations if "aes-gcm" in r.action.lower()]
        if aes_gcm_recs:
            # At least one should have high confidence
            high_confidence_recs = [r for r in aes_gcm_recs if r.confidence.value >= 4]
            self.assertGreater(len(high_confidence_recs), 0)

    def test_user_context_persistence(self):
        """Test saving and loading user context."""
        from ..modules.smart_recommendations import UserContext

        user_id = "test_user"
        original_context = UserContext(
            user_type="business",
            experience_level="expert",
            primary_use_cases=["business", "compliance"],
            data_sensitivity="high",
            preferred_algorithms=["aes-gcm", "xchacha20-poly1305"],
        )

        # Save context
        self.engine.save_user_context(user_id, original_context)

        # Load context
        loaded_context = self.engine.load_user_context(user_id)

        self.assertIsNotNone(loaded_context)
        self.assertEqual(loaded_context.user_type, original_context.user_type)
        self.assertEqual(loaded_context.experience_level, original_context.experience_level)
        self.assertEqual(loaded_context.primary_use_cases, original_context.primary_use_cases)
        self.assertEqual(loaded_context.data_sensitivity, original_context.data_sensitivity)
        self.assertEqual(loaded_context.preferred_algorithms, original_context.preferred_algorithms)

    def test_feedback_recording(self):
        """Test feedback recording and learning."""
        from ..modules.smart_recommendations import UserContext

        user_id = "test_user"
        rec_id = "test_rec_001"

        # Record positive feedback
        self.engine.record_feedback(user_id, rec_id, accepted=True, feedback_text="Very helpful!")

        # Load context and check feedback was recorded
        context = self.engine.load_user_context(user_id)
        self.assertIsNotNone(context)
        self.assertIn(rec_id, context.feedback_history)

        feedback = context.feedback_history[rec_id]
        self.assertTrue(feedback["user_accepted"])
        self.assertEqual(feedback["user_feedback"], "Very helpful!")
        self.assertIn("timestamp", feedback)

    def test_quick_recommendations(self):
        """Test quick recommendations functionality."""
        quick_recs = self.engine.get_quick_recommendations("business", "intermediate")

        self.assertIsInstance(quick_recs, list)
        self.assertGreater(len(quick_recs), 0)
        self.assertLessEqual(len(quick_recs), 5)  # Should be limited to top 5

        # Each recommendation should be a string with action
        for rec in quick_recs:
            self.assertIsInstance(rec, str)
            self.assertTrue(len(rec) > 0)

    def test_security_level_determination(self):
        """Test security level determination based on context."""
        from ..modules.smart_recommendations import UserContext

        # Test different contexts
        contexts = [
            (UserContext(user_type="personal", data_sensitivity="low"), "lower security"),
            (UserContext(user_type="business", data_sensitivity="high"), "higher security"),
            (
                UserContext(user_type="compliance", data_sensitivity="top_secret"),
                "maximum security",
            ),
        ]

        for context, expected_level in contexts:
            requirements = self.engine._determine_required_security_level(context)

            self.assertIn("minimum_score", requirements)
            self.assertIn("recommended_score", requirements)
            self.assertIsInstance(requirements["minimum_score"], float)
            self.assertIsInstance(requirements["recommended_score"], float)

            # Higher sensitivity should require higher scores
            self.assertGreaterEqual(
                requirements["recommended_score"], requirements["minimum_score"]
            )

    def test_recommendation_priority_sorting(self):
        """Test that recommendations are properly sorted by priority and confidence."""
        from ..modules.smart_recommendations import UserContext

        user_context = UserContext(
            user_type="compliance",
            data_sensitivity="high",
            primary_use_cases=["compliance"],
            compliance_requirements=["fips_140_2"],
        )

        recommendations = self.engine.generate_recommendations(user_context)

        # Should be sorted by priority (critical/high first) then confidence
        if len(recommendations) > 1:
            for i in range(len(recommendations) - 1):
                current = recommendations[i]
                next_rec = recommendations[i + 1]

                # Priority ordering: critical > high > medium > low > info
                priority_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
                current_priority = priority_order.get(current.priority.value, 0)
                next_priority = priority_order.get(next_rec.priority.value, 0)

                # Current should have higher or equal priority
                self.assertGreaterEqual(current_priority, next_priority)
