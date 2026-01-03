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

            # Should fail due to import blocking or usage blocking (defense-in-depth)
            # Import hooks block at 'import socket' (new security layer)
            # Sandbox blocks at 'socket.socket()' usage (original security layer)
            self.assertFalse(result.success)
            # Accept either error message (import blocking is preferred/earlier)
            self.assertTrue(
                "network access denied" in result.message.lower() or
                "import of 'socket' blocked" in result.message.lower(),
                f"Expected network blocking error, got: {result.message}"
            )

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

            # Should fail due to import blocking or usage blocking (defense-in-depth)
            # Import hooks block at 'import subprocess' (new security layer)
            # Sandbox blocks at 'subprocess.Popen()' usage (original security layer)
            self.assertFalse(result.success)
            # Accept either error message (import blocking is preferred/earlier)
            self.assertTrue(
                "process execution denied" in result.message.lower() or
                "import of 'subprocess' blocked" in result.message.lower(),
                f"Expected subprocess blocking error, got: {result.message}"
            )

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


class TestConfigDirectoryPermissions(unittest.TestCase):
    """Tests for plugin config directory permission enforcement."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dirs = []

    def tearDown(self):
        """Clean up test directories."""
        import shutil
        for test_dir in self.test_dirs:
            if test_dir.exists():
                try:
                    shutil.rmtree(test_dir)
                except Exception:
                    pass

    def test_ensure_plugin_data_dir_creates_with_0o700(self):
        """Verify directories are created with 0o700 permissions."""
        from openssl_encrypt.modules.plugin_system.plugin_config import ensure_plugin_data_dir
        import stat

        test_dir = ensure_plugin_data_dir("test_security_plugin", "")
        self.assertIsNotNone(test_dir, "Directory creation should succeed")
        self.test_dirs.append(test_dir)

        # Check permissions (Unix only)
        if hasattr(os, "chmod"):
            perms = stat.S_IMODE(os.stat(test_dir).st_mode)
            self.assertEqual(perms, 0o700, f"Expected 0o700, got {oct(perms)}")

    def test_ensure_plugin_data_dir_with_subdir(self):
        """Verify subdirectories are created with 0o700 permissions."""
        from openssl_encrypt.modules.plugin_system.plugin_config import ensure_plugin_data_dir
        import stat

        test_dir = ensure_plugin_data_dir("test_security_plugin", "subdir")
        self.assertIsNotNone(test_dir, "Subdirectory creation should succeed")
        self.test_dirs.append(test_dir.parent)

        # Check subdirectory permissions (Unix only)
        if hasattr(os, "chmod"):
            perms = stat.S_IMODE(os.stat(test_dir).st_mode)
            self.assertEqual(perms, 0o700, f"Expected 0o700, got {oct(perms)}")

            # Check parent directory permissions too
            parent_perms = stat.S_IMODE(os.stat(test_dir.parent).st_mode)
            self.assertEqual(parent_perms, 0o700, f"Parent expected 0o700, got {oct(parent_perms)}")

    def test_ensure_plugin_data_dir_fixes_existing_permissions(self):
        """Verify existing directories have permissions corrected."""
        from openssl_encrypt.modules.plugin_system.plugin_config import ensure_plugin_data_dir
        import stat

        # First create with correct permissions
        test_dir = ensure_plugin_data_dir("test_security_plugin2", "")
        self.assertIsNotNone(test_dir)
        self.test_dirs.append(test_dir)

        if hasattr(os, "chmod"):
            # Change to insecure permissions
            os.chmod(test_dir, 0o755)
            initial_perms = stat.S_IMODE(os.stat(test_dir).st_mode)
            self.assertEqual(initial_perms, 0o755)

            # Call again - should fix permissions
            test_dir2 = ensure_plugin_data_dir("test_security_plugin2", "")
            self.assertIsNotNone(test_dir2)

            # Check permissions were fixed
            fixed_perms = stat.S_IMODE(os.stat(test_dir).st_mode)
            self.assertEqual(fixed_perms, 0o700, "Permissions should be corrected to 0o700")

    def test_plugin_load_fails_on_insecure_config_dir(self):
        """Verify plugins don't load if config dir permissions cannot be secured."""
        from unittest.mock import patch
        from openssl_encrypt.modules.plugin_system.plugin_config import PluginConfigManager

        # Create temporary directories for both plugin and config
        with tempfile.TemporaryDirectory() as temp_dir:
            with tempfile.TemporaryDirectory() as config_dir:
                plugin_file = Path(temp_dir) / "test_plugin.py"
                plugin_file.write_text("""
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginResult, PluginCapability

class TestPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("test_plugin", "Test", "1.0")

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES}

    def get_description(self):
        return "Test plugin"

    def process_file(self, file_path, context):
        return PluginResult.success_result("OK")
""")

                # Use temp config directory to avoid loading existing configs
                config_manager = PluginConfigManager(config_dir)
                plugin_manager = PluginManager(config_manager)
                plugin_manager.add_plugin_directory(temp_dir)

                # Mock ensure_plugin_data_dir to return None (permission failure)
                with patch('openssl_encrypt.modules.plugin_system.plugin_manager.ensure_plugin_data_dir') as mock:
                    mock.return_value = None

                    result = plugin_manager.load_plugin(str(plugin_file))

                    # Should fail to load
                    if hasattr(os, "chmod"):  # Only on Unix systems
                        self.assertFalse(result.success, "Plugin load should fail with insecure permissions")
                        self.assertIn("insecure permissions", result.message.lower())


class TestPackagePluginDiscovery(unittest.TestCase):
    """Tests for package-based plugin discovery."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.config_dir = Path(tempfile.mkdtemp())
        self.config_manager = PluginConfigManager(str(self.config_dir))
        self.plugin_manager = PluginManager(self.config_manager)
        self.plugin_manager.add_plugin_directory(str(self.test_dir))

    def tearDown(self):
        """Clean up test directories."""
        import shutil
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)
        if self.config_dir.exists():
            shutil.rmtree(self.config_dir)

    def test_discovers_package_plugins(self):
        """Verify plugins in packages (with __init__.py) are discovered."""
        # Create a package plugin
        pkg_dir = self.test_dir / "test_package_plugin"
        pkg_dir.mkdir()
        init_file = pkg_dir / "__init__.py"
        init_file.write_text("""
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginResult, PluginCapability

class PackagePlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("package_plugin", "Package Plugin", "1.0")

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES}

    def get_description(self):
        return "Package-based plugin"

    def process_file(self, file_path, context):
        return PluginResult.success_result("OK")
""")

        # Discover plugins
        discovered = self.plugin_manager.discover_plugins()

        # Should find the package plugin
        self.assertTrue(
            any("test_package_plugin" in p for p in discovered),
            f"Package plugin not discovered in: {discovered}"
        )

    def test_discovers_both_file_and_package_plugins(self):
        """Verify both flat files and packages are discovered."""
        # Create a flat file plugin
        flat_file = self.test_dir / "flat_plugin.py"
        flat_file.write_text("""
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginResult, PluginCapability

class FlatPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("flat_plugin", "Flat Plugin", "1.0")

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES}

    def get_description(self):
        return "Flat file plugin"

    def process_file(self, file_path, context):
        return PluginResult.success_result("OK")
""")

        # Create a package plugin
        pkg_dir = self.test_dir / "package_plugin"
        pkg_dir.mkdir()
        init_file = pkg_dir / "__init__.py"
        init_file.write_text("""
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginResult, PluginCapability

class PackagePlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("package_plugin", "Package Plugin", "1.0")

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES}

    def get_description(self):
        return "Package plugin"

    def process_file(self, file_path, context):
        return PluginResult.success_result("OK")
""")

        # Discover plugins
        discovered = self.plugin_manager.discover_plugins()

        # Should find both
        self.assertTrue(any("flat_plugin.py" in p for p in discovered), "Flat plugin not found")
        self.assertTrue(any("package_plugin" in p for p in discovered), "Package plugin not found")

    def test_package_plugin_file_directory_correct(self):
        """Verify PluginRegistration.file_directory points to package dir, not __init__.py."""
        # Create a package plugin
        pkg_dir = self.test_dir / "dir_test_plugin"
        pkg_dir.mkdir()
        init_file = pkg_dir / "__init__.py"
        init_file.write_text("""
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginResult, PluginCapability

class DirTestPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("dir_test_plugin", "Dir Test", "1.0")

    def get_required_capabilities(self):
        return {PluginCapability.READ_FILES}

    def get_description(self):
        return "Test plugin directory"

    def process_file(self, file_path, context):
        return PluginResult.success_result("OK")
""")

        # Load the plugin
        result = self.plugin_manager.load_plugin(str(init_file))
        self.assertTrue(result.success, f"Plugin load failed: {result.message}")

        # Check file_directory
        registration = self.plugin_manager.plugins.get("dir_test_plugin")
        self.assertIsNotNone(registration, "Plugin not registered")

        # file_directory should be the package directory, not __init__.py
        self.assertEqual(
            registration.file_directory,
            str(pkg_dir),
            "file_directory should point to package directory"
        )


class TestUnifiedConfigPaths(unittest.TestCase):
    """Tests for unified config directory structure."""

    def setUp(self):
        """Set up test fixtures."""
        self.config_manager = PluginConfigManager()
        self.test_dirs = []

    def tearDown(self):
        """Clean up test directories."""
        import shutil
        for test_dir in self.test_dirs:
            if test_dir.exists():
                try:
                    shutil.rmtree(test_dir)
                except Exception:
                    pass

    def test_config_file_path_under_plugin_dir(self):
        """Verify config files are at plugins/<plugin_id>/config.json."""
        config_path = self.config_manager._get_config_file_path("test_plugin")

        expected = Path.home() / ".openssl_encrypt" / "plugins" / "test_plugin" / "config.json"
        self.assertEqual(
            config_path,
            expected,
            f"Config path should be {expected}, got {config_path}"
        )

        # Clean up
        if config_path.parent.exists():
            self.test_dirs.append(config_path.parent)

    def test_plugin_data_dir_under_plugins(self):
        """Verify ensure_plugin_data_dir creates under plugins/<plugin_id>/."""
        from openssl_encrypt.modules.plugin_system.plugin_config import ensure_plugin_data_dir

        test_dir = ensure_plugin_data_dir("unified_test_plugin", "data")
        self.assertIsNotNone(test_dir)
        self.test_dirs.append(test_dir.parent)

        expected_base = Path.home() / ".openssl_encrypt" / "plugins" / "unified_test_plugin"
        expected_full = expected_base / "data"

        self.assertEqual(
            test_dir,
            expected_full,
            f"Data dir should be {expected_full}, got {test_dir}"
        )

        # Verify parent is also under plugins/
        self.assertTrue(
            str(test_dir.parent).startswith(str(Path.home() / ".openssl_encrypt" / "plugins")),
            "Plugin data should be under ~/.openssl_encrypt/plugins/"
        )


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
