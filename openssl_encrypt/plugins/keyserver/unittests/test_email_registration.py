#!/usr/bin/env python3
"""
Unit tests for email-confirmed keyserver registration (client-side).

Tests the polling-based flow:
1. Plugin POSTs email → gets registration_id
2. Plugin polls status endpoint → pending/confirmed
3. On confirmed → saves tokens automatically
"""

import time
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
import requests

from openssl_encrypt.plugins.keyserver.keyserver_plugin import (
    KeyserverPlugin,
    NetworkError,
)
from openssl_encrypt.plugins.keyserver.config import KeyserverConfig


@pytest.fixture
def config(tmp_path):
    """Create a minimal keyserver config."""
    from pathlib import Path

    return KeyserverConfig(
        enabled=True,
        servers=["https://keys.example.com"],
        cache_path=Path(tmp_path / "cache.db"),
        api_token_file=Path(tmp_path / "token"),
    )


@pytest.fixture
def plugin(config):
    """Create a KeyserverPlugin with mocked session."""
    p = KeyserverPlugin(config)
    p.session = MagicMock()
    return p


class TestRegisterWithEmailRequest:
    """Tests for the initial email registration POST."""

    def test_posts_to_register_email_endpoint(self, plugin):
        """Plugin POSTs to /api/v1/keys/register/email."""
        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_response.json.return_value = {
            "registration_id": "reg_abc123",
            "message": "Check your email",
        }
        plugin.session.post.return_value = mock_response

        # Mock the polling to return confirmed immediately
        mock_status_response = MagicMock()
        mock_status_response.status_code = 200
        mock_status_response.json.return_value = {
            "status": "confirmed",
            "client_id": "client_123",
            "access_token": "tok_access",
            "refresh_token": "tok_refresh",
            "expires_at": "2026-03-26T13:00:00Z",
            "refresh_expires_at": "2026-04-02T12:00:00Z",
            "token_type": "Bearer",
        }
        plugin.session.get.return_value = mock_status_response

        with patch.object(plugin.config, "save_api_token"):
            plugin.register_with_email("user@example.com")

        plugin.session.post.assert_called_once()
        call_args = plugin.session.post.call_args
        assert "/api/v1/keys/register/email" in call_args[0][0]
        assert call_args[1]["json"] == {"email": "user@example.com"}

    def test_uses_custom_server_url(self, plugin):
        """Plugin uses custom server URL when provided."""
        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_response.json.return_value = {
            "registration_id": "reg_abc",
            "message": "Check email",
        }
        plugin.session.post.return_value = mock_response

        mock_status = MagicMock()
        mock_status.status_code = 200
        mock_status.json.return_value = {
            "status": "confirmed",
            "client_id": "c1",
            "access_token": "t",
            "refresh_token": "r",
            "expires_at": "x",
            "refresh_expires_at": "x",
            "token_type": "Bearer",
        }
        plugin.session.get.return_value = mock_status

        with patch.object(plugin.config, "save_api_token"):
            plugin.register_with_email("user@example.com", server_url="https://custom.example.com")

        url = plugin.session.post.call_args[0][0]
        assert url.startswith("https://custom.example.com")

    def test_raises_on_non_202_response(self, plugin):
        """Plugin raises NetworkError if registration POST fails."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal server error"
        plugin.session.post.return_value = mock_response

        with pytest.raises(NetworkError):
            plugin.register_with_email("user@example.com")

    def test_raises_on_409_duplicate(self, plugin):
        """Plugin raises NetworkError with detail on 409 (duplicate email)."""
        mock_response = MagicMock()
        mock_response.status_code = 409
        mock_response.text = "An account with this email already exists"
        plugin.session.post.return_value = mock_response

        with pytest.raises(NetworkError, match="409"):
            plugin.register_with_email("user@example.com")


class TestPollingFlow:
    """Tests for the status polling loop."""

    def test_polls_until_confirmed(self, plugin):
        """Plugin polls status endpoint until confirmed."""
        mock_post = MagicMock()
        mock_post.status_code = 202
        mock_post.json.return_value = {
            "registration_id": "reg_abc",
            "message": "Check email",
        }
        plugin.session.post.return_value = mock_post

        # First poll: pending, second poll: confirmed
        pending_response = MagicMock()
        pending_response.status_code = 200
        pending_response.json.return_value = {"status": "pending"}

        confirmed_response = MagicMock()
        confirmed_response.status_code = 200
        confirmed_response.json.return_value = {
            "status": "confirmed",
            "client_id": "client_abc",
            "access_token": "tok_a",
            "refresh_token": "tok_r",
            "expires_at": "2026-03-26T13:00:00Z",
            "refresh_expires_at": "2026-04-02T12:00:00Z",
            "token_type": "Bearer",
        }
        plugin.session.get.side_effect = [pending_response, confirmed_response]

        with patch.object(plugin.config, "save_api_token") as mock_save:
            with patch("time.sleep"):  # Don't actually sleep in tests
                result = plugin.register_with_email("user@example.com")

        assert result["status"] == "confirmed"
        assert result["client_id"] == "client_abc"
        assert plugin.session.get.call_count == 2

    def test_saves_token_on_confirmation(self, plugin):
        """Plugin saves the access token when confirmed."""
        mock_post = MagicMock()
        mock_post.status_code = 202
        mock_post.json.return_value = {
            "registration_id": "reg_abc",
            "message": "ok",
        }
        plugin.session.post.return_value = mock_post

        mock_status = MagicMock()
        mock_status.status_code = 200
        mock_status.json.return_value = {
            "status": "confirmed",
            "client_id": "client_abc",
            "access_token": "the_token",
            "refresh_token": "ref_tok",
            "expires_at": "x",
            "refresh_expires_at": "x",
            "token_type": "Bearer",
        }
        plugin.session.get.return_value = mock_status

        with patch.object(plugin.config, "save_api_token") as mock_save:
            plugin.register_with_email("user@example.com")

        mock_save.assert_called_once_with("the_token")

    def test_returns_full_result(self, plugin):
        """Plugin returns the full confirmed response."""
        mock_post = MagicMock()
        mock_post.status_code = 202
        mock_post.json.return_value = {
            "registration_id": "reg_abc",
            "message": "ok",
        }
        plugin.session.post.return_value = mock_post

        expected = {
            "status": "confirmed",
            "client_id": "client_xyz",
            "access_token": "tok_a",
            "refresh_token": "tok_r",
            "expires_at": "2026-03-26T13:00:00Z",
            "refresh_expires_at": "2026-04-02T12:00:00Z",
            "token_type": "Bearer",
        }
        mock_status = MagicMock()
        mock_status.status_code = 200
        mock_status.json.return_value = expected
        plugin.session.get.return_value = mock_status

        with patch.object(plugin.config, "save_api_token"):
            result = plugin.register_with_email("user@example.com")

        assert result["client_id"] == "client_xyz"
        assert result["access_token"] == "tok_a"
        assert result["refresh_token"] == "tok_r"

    def test_polls_correct_url(self, plugin):
        """Plugin polls the correct status URL with registration_id."""
        mock_post = MagicMock()
        mock_post.status_code = 202
        mock_post.json.return_value = {
            "registration_id": "my_reg_id_123",
            "message": "ok",
        }
        plugin.session.post.return_value = mock_post

        mock_status = MagicMock()
        mock_status.status_code = 200
        mock_status.json.return_value = {
            "status": "confirmed",
            "client_id": "c1",
            "access_token": "t",
            "refresh_token": "r",
            "expires_at": "x",
            "refresh_expires_at": "x",
            "token_type": "Bearer",
        }
        plugin.session.get.return_value = mock_status

        with patch.object(plugin.config, "save_api_token"):
            plugin.register_with_email("user@example.com")

        poll_url = plugin.session.get.call_args[0][0]
        assert "/api/v1/keys/register/status/my_reg_id_123" in poll_url


class TestTimeoutHandling:
    """Tests for polling timeout."""

    def test_raises_on_timeout(self, plugin):
        """Plugin raises NetworkError after polling timeout."""
        mock_post = MagicMock()
        mock_post.status_code = 202
        mock_post.json.return_value = {
            "registration_id": "reg_abc",
            "message": "ok",
        }
        plugin.session.post.return_value = mock_post

        # Always return pending
        mock_status = MagicMock()
        mock_status.status_code = 200
        mock_status.json.return_value = {"status": "pending"}
        plugin.session.get.return_value = mock_status

        with patch("time.sleep"):
            with patch("time.monotonic", side_effect=[0, 0, 1801]):  # Exceed 30 min
                with pytest.raises(NetworkError, match="timed out"):
                    plugin.register_with_email("user@example.com")

    def test_raises_on_410_expired(self, plugin):
        """Plugin raises NetworkError when status returns 410 (expired)."""
        mock_post = MagicMock()
        mock_post.status_code = 202
        mock_post.json.return_value = {
            "registration_id": "reg_abc",
            "message": "ok",
        }
        plugin.session.post.return_value = mock_post

        mock_status = MagicMock()
        mock_status.status_code = 410
        mock_status.text = "Registration expired"
        plugin.session.get.return_value = mock_status

        with patch("time.sleep"):
            with pytest.raises(NetworkError, match="expired"):
                plugin.register_with_email("user@example.com")


class TestConnectionErrors:
    """Tests for network error handling during registration."""

    def test_raises_on_connection_error(self, plugin):
        """Plugin raises NetworkError on connection failure."""
        plugin.session.post.side_effect = requests.exceptions.ConnectionError("refused")

        with pytest.raises(NetworkError, match="Connection failed"):
            plugin.register_with_email("user@example.com")

    def test_raises_on_request_timeout(self, plugin):
        """Plugin raises NetworkError on request timeout."""
        plugin.session.post.side_effect = requests.exceptions.Timeout()

        with pytest.raises(NetworkError, match="timeout"):
            plugin.register_with_email("user@example.com")
