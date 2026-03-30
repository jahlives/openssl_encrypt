#!/usr/bin/env python3
"""
Unit tests for permission security (TOCTOU fixes).

Tests that files and directories are created with secure permissions
atomically to prevent time-of-check-to-time-of-use vulnerabilities.

Uses file_permissions helper for cross-platform permission checks.
"""

import os
import stat
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from openssl_encrypt.modules.file_permissions import PermissionLevel, check_permissions
from openssl_encrypt.modules.plugin_system.plugin_config import (
    PluginConfigManager,
    ensure_plugin_data_dir,
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

                # Check permissions using cross-platform helper
                assert check_permissions(
                    result, PermissionLevel.OWNER_FULL
                ), "Directory should have OWNER_FULL (0o700) permissions"

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
                ), "Subdirectory should have OWNER_FULL (0o700) permissions"

    def test_parent_directory_secured(self):
        """Parent directory should also be secured when creating subdirectory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pathlib.Path.home", return_value=Path(tmpdir)):
                result = ensure_plugin_data_dir("test_plugin", "cache")

                # Check parent directory permissions
                parent = result.parent
                assert check_permissions(
                    parent, PermissionLevel.OWNER_FULL
                ), "Parent directory should have OWNER_FULL (0o700) permissions"

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

    @pytest.mark.skipif(sys.platform == "win32", reason="umask is a POSIX concept")
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
                # Mock check_permissions to return False (permission failure)
                with patch(
                    "openssl_encrypt.modules.file_permissions.check_permissions",
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
            ), "Config file should have OWNER_ONLY (0o600) permissions"

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
            ), "Config directory should have OWNER_FULL (0o700) permissions"

    def test_config_root_directory_secured(self):
        """Root config directory should be secured"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "config"
            manager = PluginConfigManager(config_dir=str(config_dir))

            # Check root directory permissions
            assert config_dir.exists()
            assert check_permissions(
                config_dir, PermissionLevel.OWNER_FULL
            ), "Root config directory should have OWNER_FULL (0o700) permissions"

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
            assert check_permissions(
                config_file, PermissionLevel.OWNER_ONLY
            ), "Permissions should be preserved after update"

    @pytest.mark.skipif(sys.platform == "win32", reason="umask is a POSIX concept")
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
    """Tests that permissions are set correctly during creation"""

    def test_directory_has_correct_permissions_after_creation(self):
        """Directory should have correct permissions after creation"""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pathlib.Path.home", return_value=Path(tmpdir)):
                result = ensure_plugin_data_dir("test_plugin")
                assert result is not None

                # Verify permissions are correct
                assert check_permissions(
                    result, PermissionLevel.OWNER_FULL
                ), "Directory permissions should be correct after creation"

    def test_file_has_correct_permissions_after_creation(self):
        """File should have correct permissions after creation"""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginConfigManager(config_dir=tmpdir)
            manager.set_plugin_config("test_plugin", {"test": "value"})

            config_file = Path(tmpdir) / "test_plugin" / "config.json"
            assert check_permissions(
                config_file, PermissionLevel.OWNER_ONLY
            ), "File permissions should be correct after creation"

    @pytest.mark.skipif(sys.platform == "win32", reason="umask is a POSIX concept")
    def test_umask_mechanism_used(self):
        """Should use umask mechanism for atomic permission setting on POSIX"""
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

            with patch("os.umask", side_effect=tracked_umask):
                with patch("pathlib.Path.home", return_value=Path(tmpdir)):
                    ensure_plugin_data_dir("test_plugin")

            # Should have called umask(0o077) and then restored
            assert 0o077 in umask_values, "Should set umask to 0o077"
            # Should restore original umask
            assert (
                original_umask in umask_values
            ), f"Should restore original umask {oct(original_umask)}"
