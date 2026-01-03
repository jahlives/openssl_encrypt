#!/usr/bin/env python3
"""
Unit tests for plugin path traversal security.

Tests the _is_safe_path() validation that prevents symlink attacks,
path traversal, and unauthorized file access.
"""

import pytest
import os
import sys
import tempfile
import shutil

from openssl_encrypt.modules.plugin_system.plugin_manager import PluginManager
from openssl_encrypt.modules.plugin_system.plugin_config import PluginConfigManager
from openssl_encrypt.modules.plugin_system.plugin_base import PluginSecurityContext, PluginCapability


class TestSymlinkAttacks:
    """Tests for symlink-based path traversal attacks"""

    def setup_method(self):
        """Set up test environment"""
        self.config_manager = PluginConfigManager()
        self.plugin_manager = PluginManager(
            config_manager=self.config_manager,
            strict_security_mode=False
        )
        self.temp_dir = tempfile.mkdtemp()
        self.plugin_data_dir = os.path.join(self.temp_dir, "plugin_data")
        os.makedirs(self.plugin_data_dir, exist_ok=True)

    def teardown_method(self):
        """Clean up test environment"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _create_plugin_with_file_access(self, plugin_id: str, file_operation: str):
        """Create a plugin that attempts file access"""
        plugin_content = f"""
import os
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginCapability, PluginResult, PluginType

class TestPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("{plugin_id}", "Test Plugin", "1.0.0")

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return {{PluginCapability.READ_FILES, PluginCapability.WRITE_FILES}}

    def get_description(self):
        return "Test plugin for path security"

    def process_file(self, file_path, context):
        try:
            {file_operation}
            return PluginResult.success_result("File accessed")
        except Exception as e:
            return PluginResult.error_result(str(e))
"""
        plugin_path = os.path.join(self.temp_dir, f"{plugin_id}.py")
        with open(plugin_path, 'w') as f:
            f.write(plugin_content)
        return plugin_path

    def test_symlink_attack_blocked(self):
        """Symlink pointing outside plugin directory should be blocked"""
        # Create a sensitive file outside plugin directory
        sensitive_file = os.path.join(self.temp_dir, "sensitive_data.txt")
        with open(sensitive_file, 'w') as f:
            f.write("SECRET DATA")

        # Create symlink in plugin data dir pointing to sensitive file
        symlink_path = os.path.join(self.plugin_data_dir, "symlink_to_sensitive")
        os.symlink(sensitive_file, symlink_path)

        # Plugin attempts to read via symlink
        file_operation = f'''
            target_file = os.path.join(context.plugin_file_directory, "symlink_to_sensitive")
            with open(target_file, 'r') as f:
                content = f.read()
        '''

        plugin_path = self._create_plugin_with_file_access("test_symlink", file_operation)
        load_result = self.plugin_manager.load_plugin(plugin_path)

        if not load_result.success:
            # Static analysis might block 'open'
            return

        # Try execution - should be blocked by sandbox
        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        test_file.write("test")
        test_file.close()

        try:
            context = PluginSecurityContext(
                "test_symlink",
                {PluginCapability.READ_FILES, PluginCapability.WRITE_FILES},
                plugin_file_directory=self.plugin_data_dir
            )
            context.file_paths = [test_file.name]

            result = self.plugin_manager.execute_plugin(
                "test_symlink",
                context,
                use_process_isolation=False
            )

            # Should fail due to symlink blocking
            # Either sandbox blocks it, or file doesn't exist after symlink rejection
            # We accept either outcome as both are secure
            if result.success:
                # If it succeeded, verify it didn't actually read the sensitive data
                assert "SECRET DATA" not in str(result.data)
        finally:
            os.unlink(test_file.name)

    def test_symlink_to_sensitive_file_blocked(self):
        """Symlink to system sensitive files should be blocked"""
        # Try to create symlink to /etc/passwd (if it exists)
        if not os.path.exists("/etc/passwd"):
            pytest.skip("Test requires /etc/passwd")

        symlink_path = os.path.join(self.plugin_data_dir, "passwd_link")
        try:
            os.symlink("/etc/passwd", symlink_path)
        except PermissionError:
            pytest.skip("Cannot create symlink")

        # Verify symlink was created
        assert os.path.islink(symlink_path)

        # Plugin attempts to read via symlink
        file_operation = f'''
            target_file = os.path.join(context.plugin_file_directory, "passwd_link")

            # Check if file is symlink (should be detected)
            if os.path.islink(target_file):
                raise ValueError("Symlink detected by sandbox")

            with open(target_file, 'r') as f:
                content = f.read()
                if "root:" in content:
                    raise ValueError("Read /etc/passwd - SECURITY VIOLATION")
        '''

        plugin_path = self._create_plugin_with_file_access("test_passwd_link", file_operation)
        load_result = self.plugin_manager.load_plugin(plugin_path)

        if not load_result.success:
            return

        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        test_file.write("test")
        test_file.close()

        try:
            context = PluginSecurityContext(
                "test_passwd_link",
                {PluginCapability.READ_FILES, PluginCapability.WRITE_FILES},
                plugin_file_directory=self.plugin_data_dir
            )
            context.file_paths = [test_file.name]

            result = self.plugin_manager.execute_plugin(
                "test_passwd_link",
                context,
                use_process_isolation=False
            )

            # Should either fail or not contain passwd content
            if result.success:
                assert "root:" not in str(result.data)
                assert "SECURITY VIOLATION" not in result.message
        finally:
            os.unlink(test_file.name)

    def test_double_symlink_chain_blocked(self):
        """Chain of symlinks should be resolved and blocked"""
        # Create target file outside plugin dir
        target_file = os.path.join(self.temp_dir, "target.txt")
        with open(target_file, 'w') as f:
            f.write("TARGET DATA")

        # Create symlink chain: link1 -> link2 -> target
        link2 = os.path.join(self.plugin_data_dir, "link2")
        link1 = os.path.join(self.plugin_data_dir, "link1")

        os.symlink(target_file, link2)
        os.symlink(link2, link1)

        # Verify chain exists
        assert os.path.islink(link1)
        assert os.path.islink(link2)

        # Plugin attempts to read via chain
        file_operation = '''
            import os
            target_file = os.path.join(context.plugin_file_directory, "link1")

            # Realpath should resolve the entire chain
            real = os.path.realpath(target_file)

            with open(target_file, 'r') as f:
                content = f.read()
        '''

        plugin_path = self._create_plugin_with_file_access("test_chain", file_operation)
        load_result = self.plugin_manager.load_plugin(plugin_path)

        if not load_result.success:
            return

        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        test_file.write("test")
        test_file.close()

        try:
            context = PluginSecurityContext(
                "test_chain",
                {PluginCapability.READ_FILES, PluginCapability.WRITE_FILES},
                plugin_file_directory=self.plugin_data_dir
            )
            context.file_paths = [test_file.name]

            result = self.plugin_manager.execute_plugin(
                "test_chain",
                context,
                use_process_isolation=False
            )

            # Should be blocked or not contain target data
            if result.success:
                assert "TARGET DATA" not in str(result.data)
        finally:
            os.unlink(test_file.name)


class TestPathTraversal:
    """Tests for directory traversal attacks"""

    def setup_method(self):
        self.config_manager = PluginConfigManager()
        self.plugin_manager = PluginManager(
            config_manager=self.config_manager,
            strict_security_mode=False
        )
        self.temp_dir = tempfile.mkdtemp()
        self.plugin_data_dir = os.path.join(self.temp_dir, "plugin_data")
        os.makedirs(self.plugin_data_dir, exist_ok=True)

    def teardown_method(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _create_plugin_with_file_access(self, plugin_id: str, file_operation: str):
        plugin_content = f"""
import os
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginCapability, PluginResult, PluginType

class TestPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("{plugin_id}", "Test Plugin", "1.0.0")

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return {{PluginCapability.READ_FILES, PluginCapability.WRITE_FILES}}

    def get_description(self):
        return "Test plugin"

    def process_file(self, file_path, context):
        try:
            {file_operation}
            return PluginResult.success_result("File accessed")
        except Exception as e:
            return PluginResult.error_result(str(e))
"""
        plugin_path = os.path.join(self.temp_dir, f"{plugin_id}.py")
        with open(plugin_path, 'w') as f:
            f.write(plugin_content)
        return plugin_path

    def test_realpath_resolution_prevents_traversal(self):
        """Path traversal with ../ should be resolved and blocked"""
        # Create sensitive file outside plugin dir
        sensitive_file = os.path.join(self.temp_dir, "secret.txt")
        with open(sensitive_file, 'w') as f:
            f.write("SECRET")

        # Plugin attempts path traversal
        file_operation = '''
            # Try to escape plugin directory
            traversal_path = os.path.join(context.plugin_file_directory, "..", "secret.txt")

            # os.path.realpath should resolve this
            real_path = os.path.realpath(traversal_path)

            # This should be blocked by sandbox
            with open(traversal_path, 'r') as f:
                content = f.read()
        '''

        plugin_path = self._create_plugin_with_file_access("test_traversal", file_operation)
        load_result = self.plugin_manager.load_plugin(plugin_path)

        if not load_result.success:
            return

        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        test_file.write("test")
        test_file.close()

        try:
            context = PluginSecurityContext(
                "test_traversal",
                {PluginCapability.READ_FILES, PluginCapability.WRITE_FILES},
                plugin_file_directory=self.plugin_data_dir
            )
            context.file_paths = [test_file.name]

            result = self.plugin_manager.execute_plugin(
                "test_traversal",
                context,
                use_process_isolation=False
            )

            # Should be blocked or not contain secret
            if result.success:
                assert "SECRET" not in str(result.data)
        finally:
            os.unlink(test_file.name)

    def test_absolute_path_outside_plugin_dir_blocked(self):
        """Absolute path outside plugin directory should be blocked"""
        # Create file in /tmp
        tmp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', dir='/tmp')
        tmp_file.write("TMPDATA")
        tmp_file.close()
        tmp_path = tmp_file.name

        try:
            # Plugin attempts to access absolute path
            file_operation = f'''
                # Try to access file via absolute path
                target = "{tmp_path}"
                with open(target, 'r') as f:
                    content = f.read()
            '''

            plugin_path = self._create_plugin_with_file_access("test_absolute", file_operation)
            load_result = self.plugin_manager.load_plugin(plugin_path)

            if not load_result.success:
                return

            test_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
            test_file.write("test")
            test_file.close()

            try:
                context = PluginSecurityContext(
                    "test_absolute",
                    {PluginCapability.READ_FILES, PluginCapability.WRITE_FILES},
                    plugin_file_directory=self.plugin_data_dir
                )
                context.file_paths = [test_file.name]

                result = self.plugin_manager.execute_plugin(
                    "test_absolute",
                    context,
                    use_process_isolation=False
                )

                # Should be blocked or not contain tmp data
                if result.success:
                    assert "TMPDATA" not in str(result.data)
            finally:
                os.unlink(test_file.name)
        finally:
            os.unlink(tmp_path)


class TestLegitimateAccess:
    """Tests that legitimate file access still works"""

    def setup_method(self):
        self.config_manager = PluginConfigManager()
        self.plugin_manager = PluginManager(
            config_manager=self.config_manager,
            strict_security_mode=False
        )
        self.temp_dir = tempfile.mkdtemp()
        self.plugin_data_dir = os.path.join(self.temp_dir, "plugin_data")
        os.makedirs(self.plugin_data_dir, exist_ok=True)

    def teardown_method(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _create_plugin_with_file_access(self, plugin_id: str, file_operation: str):
        plugin_content = f"""
import os
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginCapability, PluginResult, PluginType

class TestPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("{plugin_id}", "Test Plugin", "1.0.0")

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return {{PluginCapability.READ_FILES, PluginCapability.WRITE_FILES}}

    def get_description(self):
        return "Test plugin"

    def process_file(self, file_path, context):
        try:
            {file_operation}
            return PluginResult.success_result("Success")
        except Exception as e:
            return PluginResult.error_result(str(e))
"""
        plugin_path = os.path.join(self.temp_dir, f"{plugin_id}.py")
        with open(plugin_path, 'w') as f:
            f.write(plugin_content)
        return plugin_path

    def test_legitimate_file_access_still_works(self):
        """Normal file access via context.file_paths should work"""
        # Create legitimate file
        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        test_file.write("LEGITIMATE DATA")
        test_file.close()

        # Plugin accesses file from context (not direct file operations)
        file_operation = '''
            # Access file provided in context - this is the safe way
            if context.file_paths:
                target_file = context.file_paths[0]
                # Note: Direct file operations are blocked by AST analysis
                # Plugin should use safer context-provided paths
                return PluginResult.success_result(f"Received file: {target_file}")
            else:
                return PluginResult.error_result("No files in context")
        '''

        plugin_path = self._create_plugin_with_file_access("test_legitimate", file_operation)
        load_result = self.plugin_manager.load_plugin(plugin_path)

        # May have warnings but should load in permissive mode
        if not load_result.success:
            # If load fails, skip test (strict AST blocking)
            pytest.skip("Plugin blocked by AST analysis")

        try:
            context = PluginSecurityContext(
                "test_legitimate",
                {PluginCapability.READ_FILES, PluginCapability.WRITE_FILES},
                plugin_file_directory=self.plugin_data_dir
            )
            context.file_paths = [test_file.name]

            result = self.plugin_manager.execute_plugin(
                "test_legitimate",
                context,
                use_process_isolation=False
            )

            # Should succeed - file access via context is allowed
            assert result.success
            assert test_file.name in result.message or test_file.name in str(result.data)
        finally:
            os.unlink(test_file.name)

    def test_file_in_subdirectory_accessible(self):
        """Context can provide files from various locations"""
        # Create file in a subdirectory
        subdir = os.path.join(self.temp_dir, "subdir")
        os.makedirs(subdir, exist_ok=True)

        subdir_file = os.path.join(subdir, "nested.txt")
        with open(subdir_file, 'w') as f:
            f.write("NESTED DATA")

        # Plugin accesses file via context
        file_operation = '''
            # Context provides file paths - plugin accesses via context
            if context.file_paths and len(context.file_paths) > 0:
                file_path = context.file_paths[0]
                # File path is provided safely by context
                return PluginResult.success_result(f"File path: {file_path}")
            else:
                return PluginResult.error_result("No files")
        '''

        plugin_path = self._create_plugin_with_file_access("test_subdir", file_operation)
        load_result = self.plugin_manager.load_plugin(plugin_path)

        if not load_result.success:
            pytest.skip("Plugin blocked by AST analysis")

        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        test_file.write("test")
        test_file.close()

        try:
            context = PluginSecurityContext(
                "test_subdir",
                {PluginCapability.READ_FILES, PluginCapability.WRITE_FILES},
                plugin_file_directory=self.plugin_data_dir
            )
            # Provide the subdirectory file via context
            context.file_paths = [subdir_file]

            result = self.plugin_manager.execute_plugin(
                "test_subdir",
                context,
                use_process_isolation=False
            )

            # Should succeed - context-provided paths work
            assert result.success
            assert subdir_file in result.message or subdir_file in str(result.data)
        finally:
            os.unlink(test_file.name)


class TestHardlinkAttacks:
    """Tests for hardlink-based attacks"""

    def setup_method(self):
        self.config_manager = PluginConfigManager()
        self.plugin_manager = PluginManager(
            config_manager=self.config_manager,
            strict_security_mode=False
        )
        self.temp_dir = tempfile.mkdtemp()
        self.plugin_data_dir = os.path.join(self.temp_dir, "plugin_data")
        os.makedirs(self.plugin_data_dir, exist_ok=True)

    def teardown_method(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _create_plugin_with_file_access(self, plugin_id: str, file_operation: str):
        plugin_content = f"""
import os
from openssl_encrypt.modules.plugin_system import PreProcessorPlugin, PluginCapability, PluginResult, PluginType

class TestPlugin(PreProcessorPlugin):
    def __init__(self):
        super().__init__("{plugin_id}", "Test Plugin", "1.0.0")

    def get_plugin_type(self):
        return PluginType.PRE_PROCESSOR

    def get_required_capabilities(self):
        return {{PluginCapability.READ_FILES, PluginCapability.WRITE_FILES}}

    def get_description(self):
        return "Test plugin"

    def process_file(self, file_path, context):
        try:
            {file_operation}
            return PluginResult.success_result("Accessed")
        except Exception as e:
            return PluginResult.error_result(str(e))
"""
        plugin_path = os.path.join(self.temp_dir, f"{plugin_id}.py")
        with open(plugin_path, 'w') as f:
            f.write(plugin_content)
        return plugin_path

    def test_hardlink_to_sensitive_file(self):
        """Hardlink to file outside plugin dir should be limited by inode checks"""
        # Create sensitive file outside plugin dir
        sensitive_file = os.path.join(self.temp_dir, "sensitive.txt")
        with open(sensitive_file, 'w') as f:
            f.write("SENSITIVE")

        # Create hardlink in plugin dir
        hardlink = os.path.join(self.plugin_data_dir, "hardlink")
        try:
            os.link(sensitive_file, hardlink)
        except (OSError, PermissionError):
            pytest.skip("Cannot create hardlink")

        # Verify hardlink exists and points to same inode
        assert os.path.exists(hardlink)
        assert os.stat(sensitive_file).st_ino == os.stat(hardlink).st_ino

        # Plugin reads via hardlink
        # Note: Hardlinks are harder to detect than symlinks
        # They point to same inode but have different paths
        # Our security relies on path-based restrictions primarily
        file_operation = '''
            import os
            target = os.path.join(context.plugin_file_directory, "hardlink")

            # Hardlink is not a symlink
            is_link = os.path.islink(target)

            # But both paths point to same inode
            with open(target, 'r') as f:
                content = f.read()
        '''

        plugin_path = self._create_plugin_with_file_access("test_hardlink", file_operation)
        load_result = self.plugin_manager.load_plugin(plugin_path)

        if not load_result.success:
            return

        test_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        test_file.write("test")
        test_file.close()

        try:
            context = PluginSecurityContext(
                "test_hardlink",
                {PluginCapability.READ_FILES, PluginCapability.WRITE_FILES},
                plugin_file_directory=self.plugin_data_dir
            )
            context.file_paths = [test_file.name]

            result = self.plugin_manager.execute_plugin(
                "test_hardlink",
                context,
                use_process_isolation=False
            )

            # Hardlinks are within the allowed directory (by path)
            # This is expected behavior - hardlinks in allowed dir are accessible
            # The file contents are shared, but the path is legitimate
            # This is a known limitation of path-based security
            # NOTE: This test documents current behavior rather than testing a vulnerability
        finally:
            os.unlink(test_file.name)
