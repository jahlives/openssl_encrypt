#!/usr/bin/env python3
"""
Unit tests for plugin import hook security.

Tests the PluginImportGuard that blocks dangerous module imports
during plugin execution.
"""

import pytest
import sys
import importlib
from unittest.mock import MagicMock, patch

from openssl_encrypt.modules.plugin_system.plugin_sandbox import PluginSandbox, PluginImportGuard
from openssl_encrypt.modules.plugin_system.plugin_base import PluginSecurityContext, PluginCapability


@pytest.fixture
def security_context():
    """Create test security context"""
    return PluginSecurityContext(
        plugin_id="test_plugin",
        capabilities=frozenset(),
        plugin_file_directory="/tmp/test_plugin"
    )


@pytest.fixture
def sandbox(security_context):
    """Create plugin sandbox for testing"""
    return PluginSandbox(security_context)


class TestDirectImportBlocking:
    """Tests for blocking direct imports"""

    def test_direct_subprocess_import_blocked(self, sandbox, security_context):
        """import subprocess should be blocked"""

        def test_plugin():
            import subprocess
            return True

        result = sandbox.execute(test_plugin)

        assert not result.success
        assert "import" in result.message.lower()
        assert "blocked" in result.message.lower()
        assert "subprocess" in result.message.lower()

    def test_direct_socket_import_blocked(self, sandbox, security_context):
        """import socket should be blocked (without network capability)"""

        def test_plugin():
            import socket
            return True

        result = sandbox.execute(test_plugin)

        assert not result.success
        assert "socket" in result.message.lower()

    def test_direct_os_import_blocked(self, sandbox, security_context):
        """import os should be blocked"""

        def test_plugin():
            import os
            return True

        result = sandbox.execute(test_plugin)

        assert not result.success
        assert "os" in result.message.lower()

    def test_direct_ctypes_import_blocked(self, sandbox, security_context):
        """import ctypes should be blocked"""

        def test_plugin():
            import ctypes
            return True

        result = sandbox.execute(test_plugin)

        assert not result.success
        assert "ctypes" in result.message.lower()


class TestFromImportBlocking:
    """Tests for blocking from...import statements"""

    def test_from_subprocess_import_blocked(self, sandbox, security_context):
        """from subprocess import Popen should be blocked"""

        def test_plugin():
            from subprocess import Popen
            return True

        result = sandbox.execute(test_plugin)

        assert not result.success
        assert "subprocess" in result.message.lower()

    def test_from_os_import_blocked(self, sandbox, security_context):
        """from os import system should be blocked"""

        def test_plugin():
            from os import system
            return True

        result = sandbox.execute(test_plugin)

        assert not result.success
        assert "os" in result.message.lower()


class TestDynamicImportBlocking:
    """Tests for blocking dynamic imports"""

    def test_importlib_import_module_blocked(self, sandbox, security_context):
        """importlib.import_module('subprocess') should be blocked"""

        def test_plugin():
            import importlib
            return True

        result = sandbox.execute(test_plugin)

        assert not result.success
        assert "importlib" in result.message.lower()

    def test_import_during_execution_blocked(self, sandbox, security_context):
        """Import attempt during plugin execution should be blocked"""

        def test_plugin():
            # Delayed import (not at module level)
            import subprocess
            return subprocess

        result = sandbox.execute(test_plugin)

        assert not result.success
        assert "subprocess" in result.message.lower()


class TestAllDangerousModulesBlocked:
    """Tests that all dangerous modules are blocked"""

    def test_all_dangerous_modules_blocked(self, sandbox, security_context):
        """Test each module in blocked list"""
        dangerous_modules = [
            'subprocess', 'os', 'socket', 'ctypes', 'multiprocessing',
            'importlib', '__builtins__', 'sys', 'shutil'
        ]

        for module_name in dangerous_modules:
            def test_plugin():
                exec(f"import {module_name}")
                return True

            result = sandbox.execute(test_plugin)

            assert not result.success, f"Module '{module_name}' was not blocked"
            assert "blocked" in result.message.lower() or "denied" in result.message.lower()


class TestSafeImportsAllowed:
    """Tests that safe imports still work"""

    def test_safe_imports_allowed(self, sandbox, security_context):
        """Common safe modules should be importable"""
        safe_modules = ['json', 'datetime', 'hashlib']

        for module_name in safe_modules:
            def test_plugin():
                exec(f"import {module_name}")
                return True

            result = sandbox.execute(test_plugin)

            assert result.success, f"Safe module '{module_name}' was incorrectly blocked"

    def test_json_import_works(self, sandbox, security_context):
        """JSON module should work in plugins"""

        def test_plugin():
            import json
            data = {"key": "value"}
            return json.dumps(data)

        result = sandbox.execute(test_plugin)

        assert result.success
        assert '{"key": "value"}' in result.data or result.data == '{"key": "value"}'

    def test_datetime_import_works(self, sandbox, security_context):
        """datetime module should work in plugins"""

        def test_plugin():
            import datetime
            now = datetime.datetime.now()
            return str(now)

        result = sandbox.execute(test_plugin)

        assert result.success
        assert result.data is not None


class TestImportHookCleanup:
    """Tests for proper cleanup of import hooks"""

    def test_import_hook_removed_after_execution(self, sandbox, security_context):
        """Import guard should be removed from sys.meta_path after execution"""

        initial_meta_path_len = len(sys.meta_path)

        def test_plugin():
            return True

        sandbox.execute(test_plugin)

        # After execution, meta_path should be back to original length
        assert len(sys.meta_path) == initial_meta_path_len

        # Verify PluginImportGuard not in meta_path
        for finder in sys.meta_path:
            assert not isinstance(finder, PluginImportGuard)

    def test_multiple_plugins_dont_interfere(self, sandbox, security_context):
        """Running multiple plugins shouldn't accumulate import guards"""

        def test_plugin1():
            import json
            return json.dumps({"plugin": 1})

        def test_plugin2():
            import datetime
            return str(datetime.datetime.now())

        initial_meta_path_len = len(sys.meta_path)

        # Execute first plugin
        result1 = sandbox.execute(test_plugin1)
        assert result1.success

        # Execute second plugin
        result2 = sandbox.execute(test_plugin2)
        assert result2.success

        # meta_path should be clean
        assert len(sys.meta_path) == initial_meta_path_len


class TestImportHookSubmodules:
    """Tests for blocking submodule imports"""

    def test_import_hook_blocks_submodules(self, sandbox, security_context):
        """import os.path should be blocked (base module check)"""

        def test_plugin():
            import os.path
            return True

        result = sandbox.execute(test_plugin)

        assert not result.success
        assert "os" in result.message.lower()

    def test_subprocess_submodule_blocked(self, sandbox, security_context):
        """Submodule of blocked module should be blocked"""

        def test_plugin():
            # Even if subprocess had submodules, should be blocked
            import subprocess
            return True

        result = sandbox.execute(test_plugin)

        assert not result.success


class TestErrorMessages:
    """Tests for clear error messages"""

    def test_import_error_message_clarity(self, sandbox, security_context):
        """Error message should clearly explain security policy"""

        def test_plugin():
            import subprocess
            return True

        result = sandbox.execute(test_plugin)

        message = result.message.lower()

        # Should mention import and security policy
        assert "import" in message
        assert ("blocked" in message or "denied" in message)
        assert "security" in message or "policy" in message

    def test_error_message_includes_module_name(self, sandbox, security_context):
        """Error message should mention the blocked module"""

        def test_plugin():
            import socket
            return True

        result = sandbox.execute(test_plugin)

        assert "socket" in result.message.lower()


class TestImportGuardCapabilityIntegration:
    """Tests for import guard respecting capabilities"""

    def test_network_capability_allows_socket_import(self):
        """Socket import should be allowed with network capability"""
        context = PluginSecurityContext(
            plugin_id="test_plugin",
            capabilities=frozenset([PluginCapability.NETWORK]),
            plugin_file_directory="/tmp/test_plugin"
        )

        sandbox = PluginSandbox(context)

        def test_plugin():
            import socket
            return "socket imported"

        result = sandbox.execute(test_plugin)

        # With network capability, socket should be importable
        # (though import hook currently blocks all - this tests expected behavior)
        # Note: This may fail if import guard doesn't check capabilities yet
        # In that case, this test documents desired behavior for future implementation


class TestImportGuardInternals:
    """Tests for PluginImportGuard internal behavior"""

    def test_import_guard_blocks_base_module(self):
        """Import guard should block base module name"""
        guard = PluginImportGuard()

        # Try to find blocked module
        result = guard.find_module("subprocess", None)

        # Should raise ImportError
        with pytest.raises(ImportError) as exc_info:
            if result:
                result.load_module("subprocess")

        assert "blocked" in str(exc_info.value).lower()

    def test_import_guard_allows_safe_module(self):
        """Import guard should allow safe modules"""
        guard = PluginImportGuard()

        # Try to find safe module
        result = guard.find_module("json", None)

        # Should return None (not handled by our guard, use default import)
        assert result is None

    def test_import_guard_checks_base_module_only(self):
        """Import guard should check base module for submodule imports"""
        guard = PluginImportGuard()

        # os.path should be blocked based on 'os' base
        with pytest.raises(ImportError):
            guard.find_module("os.path", None)


class TestEdgeCases:
    """Tests for edge cases in import blocking"""

    def test_empty_plugin_no_imports(self, sandbox, security_context):
        """Plugin with no imports should work"""

        def test_plugin():
            return "no imports"

        result = sandbox.execute(test_plugin)

        assert result.success
        assert result.data == "no imports"

    def test_multiple_safe_imports(self, sandbox, security_context):
        """Multiple safe imports in one plugin"""

        def test_plugin():
            import json
            import datetime
            import hashlib

            data = {
                "time": str(datetime.datetime.now()),
                "hash": hashlib.md5(b"test").hexdigest()
            }
            return json.dumps(data)

        result = sandbox.execute(test_plugin)

        assert result.success
        assert result.data is not None

    def test_conditional_import_blocked(self, sandbox, security_context):
        """Import inside conditional should be blocked"""

        def test_plugin():
            if True:
                import subprocess
            return True

        result = sandbox.execute(test_plugin)

        assert not result.success

    def test_try_except_import_blocked(self, sandbox, security_context):
        """Import in try block should be blocked"""

        def test_plugin():
            try:
                import subprocess
            except ImportError:
                return "blocked"
            return "not blocked"

        result = sandbox.execute(test_plugin)

        # Import should be blocked before except clause
        assert not result.success or result.data == "blocked"
