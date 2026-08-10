#!/usr/bin/env python3
"""
Unit tests for permission security (TOCTOU fixes).

Tests that files and directories are created with secure permissions
atomically to prevent time-of-check-to-time-of-use vulnerabilities.
"""

import os
import stat
import sys
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from openssl_encrypt.modules.file_permissions import (
    PermissionLevel,
    check_permissions,
)
from openssl_encrypt.modules.plugin_system.plugin_config import (
    ensure_plugin_data_dir,
    PluginConfigManager,
)


class TestEnsurePluginDataDir:
    """Tests for ensure_plugin_data_dir TOCTOU fixes"""

    def test_directory_created_with_0700_permissions(self):
        """Directory should be created with 0o700 permissions"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Mock home directory
            with patch("pathlib.Path.home", return_value=Path(tmpdir)):
                result = ensure_plugin_data_dir("test_plugin")

                assert result is not None
                assert result.exists()

                # Check permissions
                assert check_permissions(
                    result, PermissionLevel.OWNER_FULL
                ), "Expected OWNER_FULL permissions"

    def test_subdirectory_created_with_0700_permissions(self):
        """Subdirectory should also have 0o700 permissions"""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pathlib.Path.home", return_value=Path(tmpdir)):
                result = ensure_plugin_data_dir("test_plugin", "cache")

                assert result is not None
                assert result.exists()

                # Check subdirectory permissions
                assert check_permissions(
                    result, PermissionLevel.OWNER_FULL
                ), "Expected OWNER_FULL permissions"

    def test_parent_directory_secured(self):
        """Parent directory should also be secured when creating subdirectory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pathlib.Path.home", return_value=Path(tmpdir)):
                result = ensure_plugin_data_dir("test_plugin", "cache")

                # Check parent directory permissions
                parent = result.parent
                assert check_permissions(
                    parent, PermissionLevel.OWNER_FULL
                ), "Parent expected OWNER_FULL permissions"

    def test_existing_directory_permissions_verified(self):
        """Existing directory permissions should be verified"""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pathlib.Path.home", return_value=Path(tmpdir)):
                # Create first time
                result1 = ensure_plugin_data_dir("test_plugin")
                assert result1 is not None

                # Create again (exists)
                result2 = ensure_plugin_data_dir("test_plugin")
                assert result2 is not None

                # Permissions should still be correct
                assert check_permissions(result2, PermissionLevel.OWNER_FULL)

    @pytest.mark.skipif(sys.platform == "win32", reason="umask not available on Windows")
    def test_umask_restored_after_creation(self):
        """umask should be restored even if error occurs"""
        original_umask = os.umask(0o022)
        os.umask(original_umask)  # Restore it

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pathlib.Path.home", return_value=Path(tmpdir)):
                ensure_plugin_data_dir("test_plugin")

                # Check umask is restored
                current_umask = os.umask(0o022)
                os.umask(current_umask)  # Restore again
                assert current_umask == original_umask

    def test_permission_failure_returns_none(self):
        """Should return None if permissions cannot be set correctly"""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pathlib.Path.home", return_value=Path(tmpdir)):
                # Mock check_permissions to always return False
                with patch(
                    "openssl_encrypt.modules.plugin_system.plugin_config.check_permissions",
                    return_value=False,
                ):
                    result = ensure_plugin_data_dir("test_plugin")
                    assert result is None


class TestPluginConfigFileSecurity:
    """Tests for plugin config file TOCTOU fixes"""

    def test_config_file_created_with_0600_permissions(self):
        """Config file should be created with 0o600 permissions"""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginConfigManager(config_dir=tmpdir)

            # Save a config
            config = {"enabled": True, "setting": "value"}
            manager.set_plugin_config("test_plugin", config)

            # Check file permissions
            config_file = Path(tmpdir) / "test_plugin" / "config.json"
            assert config_file.exists()

            assert check_permissions(
                config_file, PermissionLevel.OWNER_ONLY
            ), "Expected OWNER_ONLY permissions"

    def test_config_directory_created_with_0700_permissions(self):
        """Config plugin directory should have 0o700 permissions"""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginConfigManager(config_dir=tmpdir)

            # Save a config
            config = {"enabled": True}
            manager.set_plugin_config("test_plugin", config)

            # Check plugin directory permissions
            plugin_dir = Path(tmpdir) / "test_plugin"
            assert check_permissions(
                plugin_dir, PermissionLevel.OWNER_FULL
            ), "Expected OWNER_FULL permissions"

    def test_config_root_directory_secured(self):
        """Root config directory should be secured"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "config"
            manager = PluginConfigManager(config_dir=str(config_dir))

            # Check root directory permissions
            assert config_dir.exists()
            assert check_permissions(
                config_dir, PermissionLevel.OWNER_FULL
            ), "Expected OWNER_FULL permissions"

    def test_file_update_preserves_permissions(self):
        """Updating config file should preserve secure permissions"""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginConfigManager(config_dir=tmpdir)

            # Save initial config
            config1 = {"enabled": True, "value": 1}
            manager.set_plugin_config("test_plugin", config1)

            config_file = Path(tmpdir) / "test_plugin" / "config.json"
            assert check_permissions(config_file, PermissionLevel.OWNER_ONLY)

            # Update config
            config2 = {"enabled": True, "value": 2}
            manager.set_plugin_config("test_plugin", config2)

            # Permissions should still be secure
            assert check_permissions(config_file, PermissionLevel.OWNER_ONLY)

    @pytest.mark.skipif(sys.platform == "win32", reason="umask not available on Windows")
    def test_umask_restored_on_file_creation_error(self):
        """umask should be restored even if file creation fails"""
        original_umask = os.umask(0o022)
        os.umask(original_umask)

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginConfigManager(config_dir=tmpdir)

            # Try to save config with invalid data that will cause error
            with pytest.raises(Exception):
                with patch("os.open", side_effect=OSError("Mocked error")):
                    manager.set_plugin_config("test_plugin", {"test": "data"})

            # umask should be restored
            current_umask = os.umask(0o022)
            os.umask(current_umask)
            assert current_umask == original_umask


class TestAtomicPermissionSetting:
    """Tests that permissions are set atomically during creation"""

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX atomicity test")
    def test_no_race_condition_window_for_directory(self):
        """Directory permissions should be set at creation time"""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pathlib.Path.home", return_value=Path(tmpdir)):
                # Track mkdir calls
                original_mkdir = Path.mkdir

                def tracked_mkdir(self, *args, **kwargs):
                    # Call original mkdir
                    original_mkdir(self, *args, **kwargs)

                    # Immediately check permissions (no window for attack)
                    perms = stat.S_IMODE(os.stat(self).st_mode)
                    # Should already be 0o700
                    assert perms == 0o700, "Permissions not set atomically!"

                with patch.object(Path, "mkdir", tracked_mkdir):
                    result = ensure_plugin_data_dir("test_plugin")
                    assert result is not None

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX atomicity test")
    def test_no_race_condition_window_for_file(self):
        """File permissions should be set at creation time"""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginConfigManager(config_dir=tmpdir)

            # Track os.open calls
            original_open = os.open
            file_created_with_correct_perms = False

            def tracked_open(path, flags, mode=0o777):
                nonlocal file_created_with_correct_perms
                fd = original_open(path, flags, mode)

                # Check permissions immediately after creation
                perms = stat.S_IMODE(os.fstat(fd).st_mode)
                if perms == 0o600:
                    file_created_with_correct_perms = True

                return fd

            with patch("os.open", tracked_open):
                manager.set_plugin_config("test_plugin", {"test": "value"})

            assert file_created_with_correct_perms, "File permissions not set atomically!"

    @pytest.mark.skipif(sys.platform == "win32", reason="umask not available on Windows")
    def test_no_global_umask_used(self):
        """Secure creation must NOT touch the process-global umask (#74).

        Previously create_secure_directory set os.umask(0o077) for the duration
        of the create and restored it, which races any other thread creating
        files concurrently. The hardened path creates each component with
        mkdir(mode=...) + chmod instead, so os.umask is never called while the
        resulting permissions remain correct.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            umask_values = []
            real_umask = os.umask  # Save reference to real umask

            def tracked_umask(mask):
                umask_values.append(mask)
                return real_umask(mask)

            with patch("os.umask", side_effect=tracked_umask):
                with patch("pathlib.Path.home", return_value=Path(tmpdir)):
                    result = ensure_plugin_data_dir("test_plugin")

            assert umask_values == [], f"os.umask must not be called, got {umask_values}"
            assert result is not None
            assert check_permissions(
                result, PermissionLevel.OWNER_FULL
            ), "Directory permissions must still be correct without umask"
