#!/usr/bin/env python3
"""
Unit tests for password-based authentication in keyserver plugin.

Tests the client-side changes to support the server's new password requirement:
- Login sends {client_id, password}
- Handles 403 "password_required" for legacy accounts
- Password stored securely alongside tokens
"""

from unittest.mock import MagicMock

import pytest

from openssl_encrypt.plugins.keyserver.config import KeyserverConfig
from openssl_encrypt.plugins.keyserver.keyserver_plugin import (
    AuthenticationError,
    KeyserverPlugin,
)


# ---------------------------------------------------------------------------
# Password Storage Tests
# ---------------------------------------------------------------------------


class TestPasswordStorage:
    """Tests for password persistence in config."""

    def test_config_has_password_file_attribute(self, tmp_path):
        """KeyserverConfig must have a password_file path."""
        config = KeyserverConfig(
            enabled=True,
            servers=["https://keyserver.example.com"],
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
            refresh_token_file=tmp_path / "refresh_token",
        )
        assert hasattr(config, "password_file")

    def test_save_and_load_password(self, tmp_path):
        """Saved password can be loaded back."""
        config = KeyserverConfig(
            enabled=True,
            servers=["https://keyserver.example.com"],
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
            refresh_token_file=tmp_path / "refresh_token",
            password_file=tmp_path / "password",
        )
        config.save_password("my_secure_password")
        assert config.load_password() == "my_secure_password"

    def test_load_password_returns_none_when_missing(self, tmp_path):
        """load_password returns None if no password file exists."""
        config = KeyserverConfig(
            enabled=True,
            servers=["https://keyserver.example.com"],
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
            refresh_token_file=tmp_path / "refresh_token",
            password_file=tmp_path / "password",
        )
        assert config.load_password() is None

    def test_clear_password(self, tmp_path):
        """clear_password removes the stored password."""
        config = KeyserverConfig(
            enabled=True,
            servers=["https://keyserver.example.com"],
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
            refresh_token_file=tmp_path / "refresh_token",
            password_file=tmp_path / "password",
        )
        config.save_password("my_secure_password")
        assert config.clear_password() is True
        assert config.load_password() is None

    def test_password_file_has_secure_permissions(self, tmp_path):
        """Password file must be created with 0600 permissions."""
        import os
        import platform

        config = KeyserverConfig(
            enabled=True,
            servers=["https://keyserver.example.com"],
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
            refresh_token_file=tmp_path / "refresh_token",
            password_file=tmp_path / "password",
        )
        config.save_password("my_secure_password")

        if platform.system() != "Windows":
            mode = oct(os.stat(tmp_path / "password").st_mode & 0o777)
            assert mode == "0o600", f"Password file has insecure permissions: {mode}"


# ---------------------------------------------------------------------------
# Login with Password Tests
# ---------------------------------------------------------------------------


class TestLoginWithPassword:
    """Tests for login with client_id + password."""

    def _make_plugin(self, tmp_path):
        config = KeyserverConfig(
            enabled=True,
            servers=["https://keyserver.example.com"],
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
            refresh_token_file=tmp_path / "refresh_token",
            password_file=tmp_path / "password",
        )
        plugin = KeyserverPlugin(config)
        plugin.session = MagicMock()
        return plugin, config

    def test_login_sends_password(self, tmp_path):
        """Login sends {client_id, password} when password is provided."""
        plugin, config = self._make_plugin(tmp_path)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "client_id": "abc",
            "access_token": "tok",
            "refresh_token": "ref",
            "expires_at": "2026-03-26T12:00:00Z",
            "token_type": "Bearer",
        }
        plugin.session.post.return_value = mock_response

        plugin.login("abc", password="securepassword12")

        call_args = plugin.session.post.call_args
        assert call_args[1]["json"] == {"client_id": "abc", "password": "securepassword12"}

    def test_login_sends_stored_password(self, tmp_path):
        """Login uses stored password from config when no password arg given."""
        plugin, config = self._make_plugin(tmp_path)
        config.save_password("stored_password")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "client_id": "abc",
            "access_token": "tok",
            "token_type": "Bearer",
        }
        plugin.session.post.return_value = mock_response

        plugin.login("abc")

        call_args = plugin.session.post.call_args
        assert call_args[1]["json"] == {"client_id": "abc", "password": "stored_password"}

    def test_login_without_password_sends_client_id_only(self, tmp_path):
        """Login without stored or provided password sends client_id only."""
        plugin, config = self._make_plugin(tmp_path)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "client_id": "abc",
            "access_token": "tok",
            "token_type": "Bearer",
        }
        plugin.session.post.return_value = mock_response

        plugin.login("abc")

        call_args = plugin.session.post.call_args
        assert call_args[1]["json"] == {"client_id": "abc"}

    def test_login_saves_password_on_success(self, tmp_path):
        """Login saves the password after successful authentication."""
        plugin, config = self._make_plugin(tmp_path)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "client_id": "abc",
            "access_token": "tok",
            "token_type": "Bearer",
        }
        plugin.session.post.return_value = mock_response

        plugin.login("abc", password="new_password_12")

        assert config.load_password() == "new_password_12"


# ---------------------------------------------------------------------------
# Legacy Client (403 password_required) Tests
# ---------------------------------------------------------------------------


class TestPasswordRequiredHandling:
    """Tests for handling 403 password_required from server."""

    def _make_plugin(self, tmp_path):
        config = KeyserverConfig(
            enabled=True,
            servers=["https://keyserver.example.com"],
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
            refresh_token_file=tmp_path / "refresh_token",
            password_file=tmp_path / "password",
        )
        plugin = KeyserverPlugin(config)
        plugin.session = MagicMock()
        return plugin, config

    def test_login_raises_password_required_on_403(self, tmp_path):
        """Login raises PasswordRequiredError on 403 password_required."""
        from openssl_encrypt.plugins.keyserver.keyserver_plugin import PasswordRequiredError

        plugin, config = self._make_plugin(tmp_path)

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.json.return_value = {
            "status": "password_required",
            "message": "Password setup required.",
        }
        plugin.session.post.return_value = mock_response

        with pytest.raises(PasswordRequiredError):
            plugin.login("legacy_client_id")

    def test_password_required_error_is_authentication_error(self):
        """PasswordRequiredError must be a subclass of AuthenticationError."""
        from openssl_encrypt.plugins.keyserver.keyserver_plugin import PasswordRequiredError

        assert issubclass(PasswordRequiredError, AuthenticationError)
