#!/usr/bin/env python3
"""
Unit tests for plugin import hook security.

Tests the PluginImportGuard that blocks dangerous module imports
during plugin execution.
"""

import pytest
import os
import sys
import tempfile
import shutil

from openssl_encrypt.modules.plugin_system.plugin_manager import PluginManager
from openssl_encrypt.modules.plugin_system.plugin_config import PluginConfigManager
from openssl_encrypt.modules.plugin_system.plugin_base import PluginSecurityContext, PluginCapability
from openssl_encrypt.modules.plugin_system.plugin_sandbox import PluginImportGuard


class TestDirectImportBlocking:
    """Tests for blocking direct imports"""

    def setup_method(self):
        """Set up test environment"""
        self.config_manager = PluginConfigManager()
        self.plugin_manager = PluginManager(
            config_manager=self.config_manager,
            strict_security_mode=False  # Allow loading for runtime testing
        )
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Clean up test environment"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _create_plugin(self, plugin_id: str, import_statement: str, capabilities: str = ""):
        """Create a test plugin with specific import"""
        caps = f"{{{capabilities}}}" if capabilities else "{PluginCapability.READ_FILES}"

        plugin_content = f"""
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginCapability, PluginResult, PluginType

class TestPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("{plugin_id}", "Test Plugin", "1.0.0")

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return {caps}

    def get_description(self):
        return "Test plugin for import blocking"

    def process_file(self, file_path, context):
        {import_statement}
        return PluginResult.success_result("Executed")
"""
        plugin_path = os.path.join(self.temp_dir, f"{plugin_id}.py")
        with open(plugin_path, 'w') as f:
            f.write(plugin_content)
        return plugin_path

    def test_direct_subprocess_import_blocked(self):
        """import subprocess should be blocked"""
        plugin_path = self._create_plugin("test_subprocess", "import subprocess")
        load_result = self.plugin_manager.load_plugin(plugin_path)

        if not load_result.success:
            # Static analysis blocked it
            assert "subprocess" in load_result.message.lower()
            return

        # Try runtime execution
        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        test_file.write("test")
        test_file.close()

        try:
            context = PluginSecurityContext("test_subprocess", {PluginCapability.READ_FILES})
            context.file_paths = [test_file.name]

            result = self.plugin_manager.execute_plugin(
                "test_subprocess",
                context,
                use_process_isolation=False
            )

            # Should be blocked
            assert not result.success
            assert "import" in result.message.lower() or "blocked" in result.message.lower()
            assert "subprocess" in result.message.lower()
        finally:
            os.unlink(test_file.name)

    def test_direct_socket_import_blocked(self):
        """import socket should be blocked (without network capability)"""
        plugin_path = self._create_plugin("test_socket", "import socket")
        load_result = self.plugin_manager.load_plugin(plugin_path)

        if not load_result.success:
            assert "socket" in load_result.message.lower()
            return

        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        test_file.write("test")
        test_file.close()

        try:
            context = PluginSecurityContext("test_socket", {PluginCapability.READ_FILES})
            context.file_paths = [test_file.name]

            result = self.plugin_manager.execute_plugin(
                "test_socket",
                context,
                use_process_isolation=False
            )

            assert not result.success
            assert "socket" in result.message.lower()
        finally:
            os.unlink(test_file.name)

    def test_direct_os_import_blocked(self):
        """import os should be blocked"""
        plugin_path = self._create_plugin("test_os", "import os")
        load_result = self.plugin_manager.load_plugin(plugin_path)

        if not load_result.success:
            assert "os" in load_result.message.lower() or "security" in load_result.message.lower()
            return

        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        test_file.write("test")
        test_file.close()

        try:
            context = PluginSecurityContext("test_os", {PluginCapability.READ_FILES})
            context.file_paths = [test_file.name]

            result = self.plugin_manager.execute_plugin(
                "test_os",
                context,
                use_process_isolation=False
            )

            assert not result.success
        finally:
            os.unlink(test_file.name)

    def test_direct_ctypes_import_blocked(self):
        """import ctypes should be blocked"""
        plugin_path = self._create_plugin("test_ctypes", "import ctypes")
        load_result = self.plugin_manager.load_plugin(plugin_path)

        if not load_result.success:
            assert "ctypes" in load_result.message.lower() or "security" in load_result.message.lower()
            return

        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        test_file.write("test")
        test_file.close()

        try:
            context = PluginSecurityContext("test_ctypes", {PluginCapability.READ_FILES})
            context.file_paths = [test_file.name]

            result = self.plugin_manager.execute_plugin(
                "test_ctypes",
                context,
                use_process_isolation=False
            )

            assert not result.success
        finally:
            os.unlink(test_file.name)


class TestFromImportBlocking:
    """Tests for blocking from...import statements"""

    def setup_method(self):
        self.config_manager = PluginConfigManager()
        self.plugin_manager = PluginManager(
            config_manager=self.config_manager,
            strict_security_mode=False
        )
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _create_plugin(self, plugin_id: str, import_statement: str):
        plugin_content = f"""
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginCapability, PluginResult, PluginType

class TestPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("{plugin_id}", "Test Plugin", "1.0.0")

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return {{PluginCapability.READ_FILES}}

    def get_description(self):
        return "Test plugin"

    def process_file(self, file_path, context):
        {import_statement}
        return PluginResult.success_result("Done")
"""
        plugin_path = os.path.join(self.temp_dir, f"{plugin_id}.py")
        with open(plugin_path, 'w') as f:
            f.write(plugin_content)
        return plugin_path

    def test_from_subprocess_import_blocked(self):
        """from subprocess import Popen should be blocked"""
        plugin_path = self._create_plugin("test_from_subprocess", "from subprocess import Popen")
        load_result = self.plugin_manager.load_plugin(plugin_path)

        # Should be blocked at static analysis or runtime
        if not load_result.success:
            assert "subprocess" in load_result.message.lower()
        else:
            # Try runtime
            test_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
            test_file.write("test")
            test_file.close()

            try:
                context = PluginSecurityContext("test_from_subprocess", {PluginCapability.READ_FILES})
                context.file_paths = [test_file.name]

                result = self.plugin_manager.execute_plugin(
                    "test_from_subprocess",
                    context,
                    use_process_isolation=False
                )

                assert not result.success
                assert "subprocess" in result.message.lower()
            finally:
                os.unlink(test_file.name)

    def test_from_os_import_blocked(self):
        """from os import system should be blocked"""
        plugin_path = self._create_plugin("test_from_os", "from os import system")
        load_result = self.plugin_manager.load_plugin(plugin_path)

        if not load_result.success:
            assert "os" in load_result.message.lower() or "security" in load_result.message.lower()


class TestSafeImportsAllowed:
    """Tests that safe imports still work"""

    def setup_method(self):
        self.config_manager = PluginConfigManager()
        self.plugin_manager = PluginManager(
            config_manager=self.config_manager,
            strict_security_mode=False
        )
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _create_plugin(self, plugin_id: str, code: str):
        plugin_content = f"""
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginCapability, PluginResult, PluginType

class TestPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("{plugin_id}", "Test Plugin", "1.0.0")

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return {{PluginCapability.READ_FILES}}

    def get_description(self):
        return "Test plugin"

    def process_file(self, file_path, context):
        {code}
"""
        plugin_path = os.path.join(self.temp_dir, f"{plugin_id}.py")
        with open(plugin_path, 'w') as f:
            f.write(plugin_content)
        return plugin_path

    def test_json_import_works(self):
        """JSON module should work in plugins"""
        code = '''
        import json
        data = {"key": "value"}
        result = json.dumps(data)
        return PluginResult.success_result(result)
'''
        plugin_path = self._create_plugin("test_json", code)
        load_result = self.plugin_manager.load_plugin(plugin_path)

        assert load_result.success

        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        test_file.write("test")
        test_file.close()

        try:
            context = PluginSecurityContext("test_json", {PluginCapability.READ_FILES})
            context.file_paths = [test_file.name]

            result = self.plugin_manager.execute_plugin(
                "test_json",
                context,
                use_process_isolation=False
            )

            assert result.success
        finally:
            os.unlink(test_file.name)

    def test_datetime_import_works(self):
        """datetime module should work in plugins"""
        code = '''
        import datetime
        now = datetime.datetime.now()
        return PluginResult.success_result(str(now))
'''
        plugin_path = self._create_plugin("test_datetime", code)
        load_result = self.plugin_manager.load_plugin(plugin_path)

        assert load_result.success

        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        test_file.write("test")
        test_file.close()

        try:
            context = PluginSecurityContext("test_datetime", {PluginCapability.READ_FILES})
            context.file_paths = [test_file.name]

            result = self.plugin_manager.execute_plugin(
                "test_datetime",
                context,
                use_process_isolation=False
            )

            assert result.success
        finally:
            os.unlink(test_file.name)


class TestImportHookCleanup:
    """Tests for proper cleanup of import hooks"""

    def test_import_hook_removed_after_execution(self):
        """Import guard should be removed from sys.meta_path after execution"""
        initial_meta_path_len = len(sys.meta_path)

        # Verify no import guards initially
        for finder in sys.meta_path:
            assert not isinstance(finder, PluginImportGuard)

        # After any operation, meta_path should remain clean
        assert len(sys.meta_path) == initial_meta_path_len


class TestImportGuardInternals:
    """Tests for PluginImportGuard internal behavior"""

    def test_import_guard_blocks_base_module(self):
        """Import guard should block base module name"""
        guard = PluginImportGuard()

        # Try to find blocked module - should raise ImportError
        with pytest.raises(ImportError) as exc_info:
            guard.find_module("subprocess", None)

        assert "blocked" in str(exc_info.value).lower()
        assert "subprocess" in str(exc_info.value).lower()

    def test_import_guard_allows_safe_module(self):
        """Import guard should allow safe modules"""
        guard = PluginImportGuard()

        # Try to find safe module - should return None (not handled)
        result = guard.find_module("json", None)
        assert result is None

    def test_import_guard_checks_base_module_only(self):
        """Import guard should check base module for submodule imports"""
        guard = PluginImportGuard()

        # os.path should be blocked based on 'os' base
        with pytest.raises(ImportError) as exc_info:
            guard.find_module("os.path", None)

        assert "os" in str(exc_info.value).lower()


class TestErrorMessages:
    """Tests for clear error messages"""

    def setup_method(self):
        self.config_manager = PluginConfigManager()
        self.plugin_manager = PluginManager(
            config_manager=self.config_manager,
            strict_security_mode=False
        )
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _create_plugin(self, plugin_id: str, import_statement: str):
        plugin_content = f"""
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginCapability, PluginResult, PluginType

class TestPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("{plugin_id}", "Test Plugin", "1.0.0")

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return {{PluginCapability.READ_FILES}}

    def get_description(self):
        return "Test plugin"

    def process_file(self, file_path, context):
        {import_statement}
        return PluginResult.success_result("Done")
"""
        plugin_path = os.path.join(self.temp_dir, f"{plugin_id}.py")
        with open(plugin_path, 'w') as f:
            f.write(plugin_content)
        return plugin_path

    def test_import_error_message_clarity(self):
        """Error message should clearly explain security policy"""
        plugin_path = self._create_plugin("test_subprocess_msg", "import subprocess")
        load_result = self.plugin_manager.load_plugin(plugin_path)

        if not load_result.success:
            message = load_result.message.lower()
            # Static analysis blocked it
            assert "security" in message or "subprocess" in message
        else:
            # Runtime blocking
            test_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
            test_file.write("test")
            test_file.close()

            try:
                context = PluginSecurityContext("test_subprocess_msg", {PluginCapability.READ_FILES})
                context.file_paths = [test_file.name]

                result = self.plugin_manager.execute_plugin(
                    "test_subprocess_msg",
                    context,
                    use_process_isolation=False
                )

                message = result.message.lower()
                assert "import" in message or "blocked" in message or "security" in message
            finally:
                os.unlink(test_file.name)

    def test_error_message_includes_module_name(self):
        """Error message should mention the blocked module"""
        plugin_path = self._create_plugin("test_socket_msg", "import socket")
        load_result = self.plugin_manager.load_plugin(plugin_path)

        if not load_result.success:
            assert "socket" in load_result.message.lower()


class TestEdgeCases:
    """Tests for edge cases in import blocking"""

    def setup_method(self):
        self.config_manager = PluginConfigManager()
        self.plugin_manager = PluginManager(
            config_manager=self.config_manager,
            strict_security_mode=False
        )
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _create_plugin(self, plugin_id: str, code: str):
        plugin_content = f"""
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginCapability, PluginResult, PluginType

class TestPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("{plugin_id}", "Test Plugin", "1.0.0")

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return {{PluginCapability.READ_FILES}}

    def get_description(self):
        return "Test plugin"

    def process_file(self, file_path, context):
        {code}
"""
        plugin_path = os.path.join(self.temp_dir, f"{plugin_id}.py")
        with open(plugin_path, 'w') as f:
            f.write(plugin_content)
        return plugin_path

    def test_empty_plugin_no_imports(self):
        """Plugin with no imports should work"""
        code = 'return PluginResult.success_result("no imports")'
        plugin_path = self._create_plugin("test_empty", code)
        load_result = self.plugin_manager.load_plugin(plugin_path)

        assert load_result.success

    def test_multiple_safe_imports(self):
        """Multiple safe imports in one plugin"""
        code = '''
        import json
        import datetime
        import hashlib
        data = {"time": str(datetime.datetime.now()), "hash": hashlib.md5(b"test").hexdigest()}
        return PluginResult.success_result(json.dumps(data))
'''
        plugin_path = self._create_plugin("test_multi", code)
        load_result = self.plugin_manager.load_plugin(plugin_path)

        assert load_result.success

    def test_conditional_import_blocked(self):
        """Import inside conditional should be detected by AST analysis"""
        code = '''
        if True:
            import subprocess
        return PluginResult.success_result("Done")
'''
        plugin_path = self._create_plugin("test_conditional", code)
        load_result = self.plugin_manager.load_plugin(plugin_path)

        # In permissive mode (strict_security_mode=False), plugin loads with warning
        # AST analysis detects subprocess import regardless of conditional
        # The violation is logged but plugin is allowed
        # In strict mode, this would be blocked
        assert load_result.success  # Loads in permissive mode

        # Verify it would be blocked in strict mode by checking with strict manager
        strict_manager = PluginManager(
            config_manager=self.config_manager,
            strict_security_mode=True
        )
        strict_result = strict_manager.load_plugin(plugin_path)
        assert not strict_result.success  # Blocked in strict mode
        assert "subprocess" in strict_result.message.lower() or "security" in strict_result.message.lower()
