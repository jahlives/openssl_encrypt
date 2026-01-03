#!/usr/bin/env python3
"""
Unit tests for permission security (TOCTOU fixes).

Tests that files and directories are created with secure permissions
atomically to prevent time-of-check-to-time-of-use vulnerabilities.
"""

import os
import stat
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

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
            with patch('pathlib.Path.home', return_value=Path(tmpdir)):
                result = ensure_plugin_data_dir("test_plugin")

                assert result is not None
                assert result.exists()

                # Check permissions
                perms = stat.S_IMODE(os.stat(result).st_mode)
                assert perms == 0o700, f"Expected 0o700, got {oct(perms)}"

    def test_subdirectory_created_with_0700_permissions(self):
        """Subdirectory should also have 0o700 permissions"""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('pathlib.Path.home', return_value=Path(tmpdir)):
                result = ensure_plugin_data_dir("test_plugin", "cache")

                assert result is not None
                assert result.exists()

                # Check subdirectory permissions
                perms = stat.S_IMODE(os.stat(result).st_mode)
                assert perms == 0o700, f"Expected 0o700, got {oct(perms)}"

    def test_parent_directory_secured(self):
        """Parent directory should also be secured when creating subdirectory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('pathlib.Path.home', return_value=Path(tmpdir)):
                result = ensure_plugin_data_dir("test_plugin", "cache")

                # Check parent directory permissions
                parent = result.parent
                parent_perms = stat.S_IMODE(os.stat(parent).st_mode)
                assert parent_perms == 0o700, f"Parent expected 0o700, got {oct(parent_perms)}"

    def test_existing_directory_permissions_verified(self):
        """Existing directory permissions should be verified"""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('pathlib.Path.home', return_value=Path(tmpdir)):
                # Create first time
                result1 = ensure_plugin_data_dir("test_plugin")
                assert result1 is not None

                # Create again (exists)
                result2 = ensure_plugin_data_dir("test_plugin")
                assert result2 is not None

                # Permissions should still be correct
                perms = stat.S_IMODE(os.stat(result2).st_mode)
                assert perms == 0o700

    def test_umask_restored_after_creation(self):
        """umask should be restored even if error occurs"""
        original_umask = os.umask(0o022)
        os.umask(original_umask)  # Restore it

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('pathlib.Path.home', return_value=Path(tmpdir)):
                ensure_plugin_data_dir("test_plugin")

                # Check umask is restored
                current_umask = os.umask(0o022)
                os.umask(current_umask)  # Restore again
                assert current_umask == original_umask

    def test_permission_failure_returns_none(self):
        """Should return None if permissions cannot be set correctly"""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('pathlib.Path.home', return_value=Path(tmpdir)):
                # Mock os.stat to return wrong permissions
                with patch('os.stat') as mock_stat:
                    stat_result = MagicMock()
                    stat_result.st_mode = 0o100755  # Wrong permissions
                    mock_stat.return_value = stat_result

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

            perms = stat.S_IMODE(os.stat(config_file).st_mode)
            assert perms == 0o600, f"Expected 0o600, got {oct(perms)}"

    def test_config_directory_created_with_0700_permissions(self):
        """Config plugin directory should have 0o700 permissions"""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginConfigManager(config_dir=tmpdir)

            # Save a config
            config = {"enabled": True}
            manager.set_plugin_config("test_plugin", config)

            # Check plugin directory permissions
            plugin_dir = Path(tmpdir) / "test_plugin"
            perms = stat.S_IMODE(os.stat(plugin_dir).st_mode)
            assert perms == 0o700, f"Expected 0o700, got {oct(perms)}"

    def test_config_root_directory_secured(self):
        """Root config directory should be secured"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "config"
            manager = PluginConfigManager(config_dir=str(config_dir))

            # Check root directory permissions
            assert config_dir.exists()
            perms = stat.S_IMODE(os.stat(config_dir).st_mode)
            assert perms == 0o700, f"Expected 0o700, got {oct(perms)}"

    def test_file_update_preserves_permissions(self):
        """Updating config file should preserve secure permissions"""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginConfigManager(config_dir=tmpdir)

            # Save initial config
            config1 = {"enabled": True, "value": 1}
            manager.set_plugin_config("test_plugin", config1)

            config_file = Path(tmpdir) / "test_plugin" / "config.json"
            initial_perms = stat.S_IMODE(os.stat(config_file).st_mode)

            # Update config
            config2 = {"enabled": True, "value": 2}
            manager.set_plugin_config("test_plugin", config2)

            # Permissions should still be secure
            updated_perms = stat.S_IMODE(os.stat(config_file).st_mode)
            assert updated_perms == 0o600
            assert updated_perms == initial_perms

    def test_umask_restored_on_file_creation_error(self):
        """umask should be restored even if file creation fails"""
        original_umask = os.umask(0o022)
        os.umask(original_umask)

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginConfigManager(config_dir=tmpdir)

            # Try to save config with invalid data that will cause error
            with pytest.raises(Exception):
                with patch('os.open', side_effect=OSError("Mocked error")):
                    manager.set_plugin_config("test_plugin", {"test": "data"})

            # umask should be restored
            current_umask = os.umask(0o022)
            os.umask(current_umask)
            assert current_umask == original_umask


class TestAtomicPermissionSetting:
    """Tests that permissions are set atomically during creation"""

    def test_no_race_condition_window_for_directory(self):
        """Directory permissions should be set at creation time"""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('pathlib.Path.home', return_value=Path(tmpdir)):
                # Track mkdir calls
                original_mkdir = Path.mkdir

                def tracked_mkdir(self, *args, **kwargs):
                    # Call original mkdir
                    original_mkdir(self, *args, **kwargs)

                    # Immediately check permissions (no window for attack)
                    perms = stat.S_IMODE(os.stat(self).st_mode)
                    # Should already be 0o700
                    assert perms == 0o700, "Permissions not set atomically!"

                with patch.object(Path, 'mkdir', tracked_mkdir):
                    result = ensure_plugin_data_dir("test_plugin")
                    assert result is not None

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

            with patch('os.open', tracked_open):
                manager.set_plugin_config("test_plugin", {"test": "value"})

            assert file_created_with_correct_perms, "File permissions not set atomically!"

    def test_umask_mechanism_used(self):
        """Should use umask mechanism for atomic permission setting"""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_umask = os.umask(0o022)
            os.umask(original_umask)

            # Track umask calls
            umask_values = []
            real_umask = os.umask  # Save reference to real umask

            def tracked_umask(mask):
                umask_values.append(mask)
                # Call real umask to actually set it
                return real_umask(mask)

            with patch('os.umask', side_effect=tracked_umask):
                with patch('pathlib.Path.home', return_value=Path(tmpdir)):
                    ensure_plugin_data_dir("test_plugin")

            # Should have called umask(0o077) and then restored
            assert 0o077 in umask_values, "Should set umask to 0o077"
            # Should restore original umask
            assert original_umask in umask_values, f"Should restore original umask {oct(original_umask)}"
