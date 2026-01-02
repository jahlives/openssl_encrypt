#!/usr/bin/env python3
"""
Plugin Security Unit Tests

Tests malicious plugin behavior to ensure security boundaries remain intact.
These tests verify that the plugin system successfully blocks:
- Sensitive data access attempts
- Unauthorized file operations
- Network operations without permission
- Subprocess execution without permission
- Dangerous code patterns (eval, exec, etc.)
- Resource exhaustion attacks

These tests serve as regression tests to ensure security features
are not accidentally broken in future updates.
"""

import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from openssl_encrypt.modules.plugin_system import (
    BasePlugin,
    PluginCapability,
    PluginManager,
    PluginResult,
    PluginSecurityContext,
    PluginType,
    PreProcessorPlugin,
)
from openssl_encrypt.modules.plugin_system.plugin_config import PluginConfigManager
from openssl_encrypt.modules.plugin_system.plugin_sandbox import (
    PluginSandbox,
    SandboxViolationError,
)


class TestSensitiveDataProtection(unittest.TestCase):
    """Test that plugins cannot access sensitive data"""

    def test_password_not_in_context(self):
        """Verify passwords are never added to plugin context"""
        context = PluginSecurityContext(
            "test_plugin", {PluginCapability.READ_FILES}
        )

        # Attempt to add password
        context.add_metadata("password", "super_secret_password")

        # Password should not be in metadata
        self.assertNotIn("password", context.metadata)
        self.assertIsNone(context.metadata.get("password"))

    def test_salt_not_in_context(self):
        """Verify salts are never added to plugin context"""
        context = PluginSecurityContext(
            "test_plugin", {PluginCapability.READ_FILES}
        )

        # Attempt to add salt
        context.add_metadata("salt", b"random_salt_bytes")

        # Salt should not be in metadata
        self.assertNotIn("salt", context.metadata)
        self.assertIsNone(context.metadata.get("salt"))

    def test_secret_key_not_in_context(self):
        """Verify secret keys are never added to plugin context"""
        context = PluginSecurityContext(
            "test_plugin", {PluginCapability.READ_FILES}
        )

        # Attempt to add secret key
        context.add_metadata("secret_key", "deadbeef" * 8)

        # Secret key should not be in metadata
        self.assertNotIn("secret_key", context.metadata)
        self.assertIsNone(context.metadata.get("secret_key"))

    def test_auth_token_not_in_context(self):
        """Verify auth tokens are never added to plugin context"""
        context = PluginSecurityContext(
            "test_plugin", {PluginCapability.READ_FILES}
        )

        # Attempt to add auth token
        context.add_metadata("auth_token", "Bearer abc123xyz")

        # Auth token should not be in metadata
        self.assertNotIn("auth_token", context.metadata)
        self.assertIsNone(context.metadata.get("auth_token"))

    def test_only_safe_metadata_in_context(self):
        """Verify only safe metadata is accessible to plugins"""
        context = PluginSecurityContext(
            "test_plugin", {PluginCapability.READ_FILES}
        )

        # Add safe metadata
        context.add_metadata("operation", "encrypt")
        context.add_metadata("algorithm", "AES-256-GCM")

        # Add sensitive metadata (should be blocked)
        context.add_metadata("password", "secret123")
        context.add_metadata("private_key", "key_data")

        # Only safe metadata should be present
        self.assertEqual(context.metadata["operation"], "encrypt")
        self.assertEqual(context.metadata["algorithm"], "AES-256-GCM")
        self.assertNotIn("password", context.metadata)
        self.assertNotIn("private_key", context.metadata)

    def test_sensitive_key_patterns(self):
        """Test comprehensive sensitive key pattern detection"""
        context = PluginSecurityContext(
            "test_plugin", {PluginCapability.READ_FILES}
        )

        sensitive_keys = [
            "password",
            "passphrase",
            "secret",
            "secret_key",
            "api_key",
            "private_key",
            "access_key",
            "auth_token",
            "credential",
            "salt",
            "iv",
            "nonce",
            "seed",
        ]

        for key in sensitive_keys:
            context.add_metadata(key, "sensitive_value")
            self.assertNotIn(key, context.metadata, f"Sensitive key '{key}' was not blocked")


class TestStaticCodeAnalysis(unittest.TestCase):
    """Test that dangerous code patterns are detected at load time"""

    def setUp(self):
        self.config_manager = PluginConfigManager()
        self.plugin_manager = PluginManager(
            config_manager=self.config_manager,
            strict_security_mode=True  # Strict mode - block dangerous patterns
        )
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _create_malicious_plugin(self, dangerous_code: str) -> str:
        """Create a plugin file with dangerous code"""
        plugin_content = f"""
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginCapability, PluginResult, PluginType

class MaliciousPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("malicious", "Malicious Plugin", "1.0.0")

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return {{PluginCapability.READ_FILES}}

    def get_description(self):
        return "Malicious plugin"

    def process_file(self, file_path, context):
        {dangerous_code}
        return PluginResult.success_result("Done")
"""
        plugin_path = os.path.join(self.temp_dir, "malicious_plugin.py")
        with open(plugin_path, 'w') as f:
            f.write(plugin_content)
        return plugin_path

    def test_eval_pattern_blocked(self):
        """Verify eval() usage is detected and blocked"""
        plugin_path = self._create_malicious_plugin("eval('1+1')")
        result = self.plugin_manager.load_plugin(plugin_path)
        self.assertFalse(result.success)
        self.assertIn("security validation", result.message.lower())

    def test_exec_pattern_blocked(self):
        """Verify exec() usage is detected and blocked"""
        plugin_path = self._create_malicious_plugin("exec('print(1)')")
        result = self.plugin_manager.load_plugin(plugin_path)
        self.assertFalse(result.success)
        self.assertIn("security validation", result.message.lower())

    def test_subprocess_pattern_blocked(self):
        """Verify subprocess usage is detected and blocked"""
        plugin_path = self._create_malicious_plugin("import subprocess; subprocess.call(['ls'])")
        result = self.plugin_manager.load_plugin(plugin_path)
        self.assertFalse(result.success)
        self.assertIn("security validation", result.message.lower())

    def test_compile_pattern_blocked(self):
        """Verify compile() usage is detected and blocked"""
        plugin_path = self._create_malicious_plugin("compile('1+1', '<string>', 'eval')")
        result = self.plugin_manager.load_plugin(plugin_path)
        self.assertFalse(result.success)
        self.assertIn("security validation", result.message.lower())

    def test_file_size_limit(self):
        """Verify file size limit is enforced"""
        plugin_path = os.path.join(self.temp_dir, "huge_plugin.py")

        # Create a plugin larger than 1MB
        with open(plugin_path, 'w') as f:
            f.write("# " + "A" * (1024 * 1024 + 1000))  # > 1MB

        result = self.plugin_manager.load_plugin(plugin_path)
        self.assertFalse(result.success)


class TestNetworkAccessControl(unittest.TestCase):
    """Test that network operations require NETWORK_ACCESS capability"""

    def setUp(self):
        self.config_manager = PluginConfigManager()
        self.plugin_manager = PluginManager(
            config_manager=self.config_manager,
            strict_security_mode=False  # Allow loading for runtime testing
        )
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _create_network_plugin(self, has_capability: bool) -> str:
        """Create a plugin that attempts network access"""
        caps = "PluginCapability.NETWORK_ACCESS, PluginCapability.READ_FILES" if has_capability else "PluginCapability.READ_FILES"

        plugin_content = f"""
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginCapability, PluginResult, PluginType

class NetworkPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("network_test", "Network Test", "1.0.0")

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return {{{caps}}}

    def get_description(self):
        return "Network test plugin"

    def process_file(self, file_path, context):
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.close()
            return PluginResult.success_result("Socket created")
        except Exception as e:
            return PluginResult.error_result(str(e))
"""
        plugin_path = os.path.join(self.temp_dir, "network_plugin.py")
        with open(plugin_path, 'w') as f:
            f.write(plugin_content)
        return plugin_path

    def test_network_blocked_without_capability(self):
        """Verify network access blocked without NETWORK_ACCESS capability"""
        plugin_path = self._create_network_plugin(has_capability=False)
        load_result = self.plugin_manager.load_plugin(plugin_path)

        if not load_result.success:
            self.skipTest("Plugin failed to load (static analysis blocked socket)")
            return

        # Create test file
        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        test_file.write("test")
        test_file.close()

        try:
            context = PluginSecurityContext(
                "network_test",
                capabilities={PluginCapability.READ_FILES}  # NO NETWORK_ACCESS
            )
            context.file_paths = [test_file.name]

            # Execute should block network access
            result = self.plugin_manager.execute_plugin(
                "network_test",
                context,
                use_process_isolation=False  # Use threading for error visibility
            )

            # Should fail due to SandboxViolationError
            self.assertFalse(result.success)
            self.assertIn("network access denied", result.message.lower())

        finally:
            os.unlink(test_file.name)


class TestSubprocessControl(unittest.TestCase):
    """Test that subprocess operations require EXECUTE_PROCESSES capability"""

    def setUp(self):
        self.config_manager = PluginConfigManager()
        self.plugin_manager = PluginManager(
            config_manager=self.config_manager,
            strict_security_mode=False  # Allow loading for runtime testing
        )
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _create_subprocess_plugin(self, has_capability: bool) -> str:
        """Create a plugin that attempts subprocess execution"""
        caps = "PluginCapability.EXECUTE_PROCESSES, PluginCapability.READ_FILES" if has_capability else "PluginCapability.READ_FILES"

        plugin_content = f"""
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginCapability, PluginResult, PluginType

class SubprocessPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("subprocess_test", "Subprocess Test", "1.0.0")

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return {{{caps}}}

    def get_description(self):
        return "Subprocess test plugin"

    def process_file(self, file_path, context):
        import subprocess
        try:
            result = subprocess.Popen(['echo', 'test'], stdout=subprocess.PIPE)
            output = result.stdout.read()
            return PluginResult.success_result("Subprocess executed")
        except Exception as e:
            return PluginResult.error_result(str(e))
"""
        plugin_path = os.path.join(self.temp_dir, "subprocess_plugin.py")
        with open(plugin_path, 'w') as f:
            f.write(plugin_content)
        return plugin_path

    def test_subprocess_blocked_without_capability(self):
        """Verify subprocess blocked without EXECUTE_PROCESSES capability"""
        plugin_path = self._create_subprocess_plugin(has_capability=False)
        load_result = self.plugin_manager.load_plugin(plugin_path)

        if not load_result.success:
            self.skipTest("Plugin failed to load (static analysis blocked subprocess)")
            return

        # Create test file
        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        test_file.write("test")
        test_file.close()

        try:
            context = PluginSecurityContext(
                "subprocess_test",
                capabilities={PluginCapability.READ_FILES}  # NO EXECUTE_PROCESSES
            )
            context.file_paths = [test_file.name]

            # Execute should block subprocess
            result = self.plugin_manager.execute_plugin(
                "subprocess_test",
                context,
                use_process_isolation=False  # Use threading for error visibility
            )

            # Should fail due to SandboxViolationError
            self.assertFalse(result.success)
            self.assertIn("process execution denied", result.message.lower())

        finally:
            os.unlink(test_file.name)


class TestResourceLimits(unittest.TestCase):
    """Test that resource limits are enforced"""

    def setUp(self):
        self.config_manager = PluginConfigManager()
        self.plugin_manager = PluginManager(
            config_manager=self.config_manager,
            strict_security_mode=False
        )
        self.plugin_manager.max_execution_time = 2.0  # 2 second timeout for testing
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _create_timeout_plugin(self) -> str:
        """Create a plugin that runs too long"""
        plugin_content = """
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginCapability, PluginResult, PluginType
import time

class TimeoutPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("timeout_test", "Timeout Test", "1.0.0")

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES}

    def get_description(self):
        return "Timeout test plugin"

    def process_file(self, file_path, context):
        time.sleep(10)  # Sleep longer than timeout
        return PluginResult.success_result("Should not reach here")
"""
        plugin_path = os.path.join(self.temp_dir, "timeout_plugin.py")
        with open(plugin_path, 'w') as f:
            f.write(plugin_content)
        return plugin_path

    def test_execution_timeout_enforced(self):
        """Verify execution timeout is enforced"""
        plugin_path = self._create_timeout_plugin()
        load_result = self.plugin_manager.load_plugin(plugin_path)
        self.assertTrue(load_result.success, "Plugin should load successfully")

        # Create test file
        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        test_file.write("test")
        test_file.close()

        try:
            context = PluginSecurityContext(
                "timeout_test",
                capabilities={PluginCapability.READ_FILES}
            )
            context.file_paths = [test_file.name]

            # Execute with timeout
            start_time = time.time()
            result = self.plugin_manager.execute_plugin(
                "timeout_test",
                context,
                use_process_isolation=True  # Process isolation for reliable timeout
            )
            elapsed = time.time() - start_time

            # Should fail due to timeout
            self.assertFalse(result.success)
            self.assertIn("timeout", result.message.lower())

            # Should terminate around the timeout limit (with some tolerance)
            self.assertLess(elapsed, 5.0, "Plugin should be terminated by timeout")

        finally:
            os.unlink(test_file.name)


class TestCapabilityValidation(unittest.TestCase):
    """Test that capability validation works correctly"""

    def test_missing_capability_denied(self):
        """Verify execution fails if required capability is missing"""

        class TestPlugin(PreProcessorPlugin):
            def __init__(self):
                super().__init__("test", "Test", "1.0.0")

            def get_plugin_type(self):
                return PluginType.PRE_PROCESSOR

            def get_required_capabilities(self):
                return {PluginCapability.READ_FILES, PluginCapability.NETWORK_ACCESS}

            def get_description(self):
                return "Test plugin"

            def process_file(self, file_path, context):
                return PluginResult.success_result("OK")

        plugin = TestPlugin()

        # Create context WITHOUT NETWORK_ACCESS capability
        context = PluginSecurityContext(
            "test",
            capabilities={PluginCapability.READ_FILES}  # Missing NETWORK_ACCESS
        )

        # Validation should fail
        self.assertFalse(plugin.validate_security_context(context))

    def test_all_capabilities_granted(self):
        """Verify execution succeeds if all capabilities are granted"""

        class TestPlugin(PreProcessorPlugin):
            def __init__(self):
                super().__init__("test", "Test", "1.0.0")

            def get_plugin_type(self):
                return PluginType.PRE_PROCESSOR

            def get_required_capabilities(self):
                return {PluginCapability.READ_FILES, PluginCapability.WRITE_LOGS}

            def get_description(self):
                return "Test plugin"

            def process_file(self, file_path, context):
                return PluginResult.success_result("OK")

        plugin = TestPlugin()

        # Create context with ALL required capabilities
        context = PluginSecurityContext(
            "test",
            capabilities={PluginCapability.READ_FILES, PluginCapability.WRITE_LOGS}
        )

        # Validation should succeed
        self.assertTrue(plugin.validate_security_context(context))


class TestResultValidation(unittest.TestCase):
    """Test that plugin results are validated for sensitive data"""

    def test_sensitive_data_blocked_in_results(self):
        """Verify sensitive data cannot be added to plugin results"""
        result = PluginResult.success_result("Test")

        # Attempt to add sensitive data
        result.add_data("password", "secret123")
        result.add_data("api_key", "key_abc")
        result.add_data("auth_token", "token_xyz")

        # Sensitive data should not be in result
        self.assertNotIn("password", result.data)
        self.assertNotIn("api_key", result.data)
        self.assertNotIn("auth_token", result.data)

    def test_safe_data_allowed_in_results(self):
        """Verify safe data can be added to plugin results"""
        result = PluginResult.success_result("Test")

        # Add safe data
        result.add_data("file_count", 5)
        result.add_data("total_size", 1024)
        result.add_data("operation_time", 1.5)

        # Safe data should be in result
        self.assertEqual(result.data["file_count"], 5)
        self.assertEqual(result.data["total_size"], 1024)
        self.assertEqual(result.data["operation_time"], 1.5)


class TestSecurityModes(unittest.TestCase):
    """Test strict vs permissive security modes"""

    def setUp(self):
        self.config_manager = PluginConfigManager()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _create_eval_plugin(self) -> str:
        """Create a plugin with eval()"""
        plugin_content = """
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginCapability, PluginResult, PluginType

class EvalPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("eval_test", "Eval Test", "1.0.0")

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES}

    def get_description(self):
        return "Eval test"

    def process_file(self, file_path, context):
        result = eval('1+1')
        return PluginResult.success_result(str(result))
"""
        plugin_path = os.path.join(self.temp_dir, "eval_plugin.py")
        with open(plugin_path, 'w') as f:
            f.write(plugin_content)
        return plugin_path

    def test_strict_mode_blocks_dangerous_patterns(self):
        """Verify strict mode blocks dangerous patterns"""
        plugin_manager = PluginManager(
            config_manager=self.config_manager,
            strict_security_mode=True  # STRICT
        )

        plugin_path = self._create_eval_plugin()
        result = plugin_manager.load_plugin(plugin_path)

        # Should be blocked in strict mode
        self.assertFalse(result.success)
        self.assertIn("security validation", result.message.lower())

    def test_permissive_mode_allows_with_warning(self):
        """Verify permissive mode allows dangerous patterns with warning"""
        plugin_manager = PluginManager(
            config_manager=self.config_manager,
            strict_security_mode=False  # PERMISSIVE
        )

        plugin_path = self._create_eval_plugin()
        result = plugin_manager.load_plugin(plugin_path)

        # Should be allowed in permissive mode
        self.assertTrue(result.success)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
