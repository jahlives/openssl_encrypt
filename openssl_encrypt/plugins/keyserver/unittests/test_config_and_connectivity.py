#!/usr/bin/env python3
"""
Unit tests for keyserver plugin configuration and server connectivity.

Tests:
1. Config loading and validation (from file, defaults, invalid values)
2. Server connectivity (health endpoint, search endpoint)
3. API token loading from secure file

These tests use mocked HTTP responses by default. Tests marked with
@pytest.mark.live require a running keyserver and are skipped by default.
Run with: pytest -m live --live-server=https://keyserver.rm-rf.ch
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from openssl_encrypt.plugins.keyserver.config import (
    ConfigError,
    KeyserverConfig,
)
from openssl_encrypt.plugins.keyserver.keyserver_plugin import (
    AuthenticationError,
    KeyserverPlugin,
    NetworkError,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_config_dir(tmp_path):
    """Create a temporary config directory structure."""
    config_dir = tmp_path / "plugins" / "keyserver"
    config_dir.mkdir(parents=True)
    return config_dir


@pytest.fixture
def sample_config_data():
    """Return a valid config dictionary."""
    return {
        "enabled": True,
        "servers": ["https://keyserver.example.com"],
        "cache_ttl_seconds": 3600,
        "cache_max_entries": 500,
        "connect_timeout_seconds": 5,
        "read_timeout_seconds": 15,
        "upload_enabled": True,
    }


@pytest.fixture
def config_file(tmp_config_dir, sample_config_data):
    """Write a config file and return its path."""
    config_path = tmp_config_dir / "config.json"
    config_path.write_text(json.dumps(sample_config_data))
    return config_path


@pytest.fixture
def token_file(tmp_config_dir):
    """Write a token file and return its path."""
    token_path = tmp_config_dir / "token"
    token_path.write_text("test_client_id_abc123")
    token_path.chmod(0o600)
    return token_path


@pytest.fixture
def plugin_with_mock_session(tmp_path):
    """Create a KeyserverPlugin with mocked HTTP session."""
    config = KeyserverConfig(
        enabled=True,
        servers=["https://keyserver.example.com"],
        cache_path=tmp_path / "cache.db",
        api_token_file=tmp_path / "token",
    )
    plugin = KeyserverPlugin(config)
    plugin.session = MagicMock()
    return plugin


# ===========================================================================
# Config Loading Tests
# ===========================================================================

class TestConfigFromFile:
    """Test configuration loading from JSON file."""

    def test_loads_valid_config(self, config_file, sample_config_data):
        """Config loads all fields from a valid JSON file."""
        config = KeyserverConfig.from_file(config_file)
        assert config.enabled is True
        assert config.servers == ["https://keyserver.example.com"]
        assert config.cache_ttl_seconds == 3600
        assert config.cache_max_entries == 500
        assert config.connect_timeout_seconds == 5
        assert config.read_timeout_seconds == 15
        assert config.upload_enabled is True

    def test_returns_defaults_when_file_missing(self, tmp_path):
        """Returns default config when file does not exist."""
        config = KeyserverConfig.from_file(tmp_path / "nonexistent.json")
        assert config.enabled is False
        assert config.cache_ttl_seconds == 86400
        assert config.cache_max_entries == 1000

    def test_raises_on_invalid_json(self, tmp_config_dir):
        """Raises ConfigError for malformed JSON."""
        bad_file = tmp_config_dir / "config.json"
        bad_file.write_text("{invalid json")
        with pytest.raises(ConfigError):
            KeyserverConfig.from_file(bad_file)

    def test_raises_on_unknown_fields(self, tmp_config_dir):
        """Raises ConfigError for unknown config keys."""
        bad_file = tmp_config_dir / "config.json"
        bad_file.write_text(json.dumps({"enabled": True, "servers": ["https://x.com"], "bogus_field": 42}))
        with pytest.raises((ConfigError, TypeError)):
            KeyserverConfig.from_file(bad_file)


class TestConfigValidation:
    """Test configuration validation rules."""

    def test_rejects_http_server_url(self):
        """Server URLs must be HTTPS."""
        with pytest.raises(ConfigError, match="HTTPS"):
            KeyserverConfig(servers=["http://insecure.example.com"])

    def test_rejects_zero_connect_timeout(self):
        """Connect timeout must be positive."""
        with pytest.raises(ConfigError, match="connect_timeout"):
            KeyserverConfig(
                servers=["https://example.com"],
                connect_timeout_seconds=0,
            )

    def test_rejects_zero_read_timeout(self):
        """Read timeout must be positive."""
        with pytest.raises(ConfigError, match="read_timeout"):
            KeyserverConfig(
                servers=["https://example.com"],
                read_timeout_seconds=0,
            )

    def test_rejects_zero_cache_ttl(self):
        """Cache TTL must be positive."""
        with pytest.raises(ConfigError, match="cache_ttl"):
            KeyserverConfig(
                servers=["https://example.com"],
                cache_ttl_seconds=0,
            )

    def test_rejects_zero_cache_max_entries(self):
        """Cache max entries must be positive."""
        with pytest.raises(ConfigError, match="cache_max_entries"):
            KeyserverConfig(
                servers=["https://example.com"],
                cache_max_entries=0,
            )

    def test_accepts_valid_config(self, tmp_path):
        """Valid config passes all validation."""
        config = KeyserverConfig(
            enabled=True,
            servers=["https://keyserver.example.com"],
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
        )
        assert config.enabled is True
        assert len(config.servers) == 1


# ===========================================================================
# API Token Tests
# ===========================================================================

class TestApiToken:
    """Test API token loading and saving."""

    def test_loads_token_from_file(self, tmp_path):
        """Token is read from the token file."""
        token_file = tmp_path / "token"
        token_file.write_text("my_secret_token")
        token_file.chmod(0o600)
        config = KeyserverConfig(
            servers=["https://example.com"],
            api_token_file=token_file,
            cache_path=tmp_path / "cache.db",
        )
        assert config.load_api_token() == "my_secret_token"

    def test_returns_none_when_no_token_file(self, tmp_path):
        """Returns None when token file does not exist."""
        config = KeyserverConfig(
            servers=["https://example.com"],
            api_token_file=tmp_path / "nonexistent",
            cache_path=tmp_path / "cache.db",
        )
        assert config.load_api_token() is None

    def test_returns_none_for_empty_token_file(self, tmp_path):
        """Returns None when token file is empty."""
        token_file = tmp_path / "token"
        token_file.write_text("")
        token_file.chmod(0o600)
        config = KeyserverConfig(
            servers=["https://example.com"],
            api_token_file=token_file,
            cache_path=tmp_path / "cache.db",
        )
        assert config.load_api_token() is None

    def test_save_and_load_roundtrip(self, tmp_path):
        """Saved token can be loaded back."""
        token_file = tmp_path / "token"
        config = KeyserverConfig(
            servers=["https://example.com"],
            api_token_file=token_file,
            cache_path=tmp_path / "cache.db",
        )
        config.save_api_token("roundtrip_token_123")
        assert config.load_api_token() == "roundtrip_token_123"

    def test_save_sets_restrictive_permissions(self, tmp_path):
        """Token file is created with 0600 permissions."""
        token_file = tmp_path / "token"
        config = KeyserverConfig(
            servers=["https://example.com"],
            api_token_file=token_file,
            cache_path=tmp_path / "cache.db",
        )
        config.save_api_token("secure_token")
        mode = token_file.stat().st_mode & 0o777
        assert mode == 0o600


# ===========================================================================
# Refresh Token Tests
# ===========================================================================

class TestRefreshToken:
    """Test refresh token loading and saving."""

    def test_loads_refresh_token_from_file(self, tmp_path):
        """Refresh token is read from the refresh token file."""
        refresh_file = tmp_path / "refresh_token"
        refresh_file.write_text("my_refresh_token")
        refresh_file.chmod(0o600)
        config = KeyserverConfig(
            servers=["https://example.com"],
            refresh_token_file=refresh_file,
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
        )
        assert config.load_refresh_token() == "my_refresh_token"

    def test_returns_none_when_no_refresh_token_file(self, tmp_path):
        """Returns None when refresh token file does not exist."""
        config = KeyserverConfig(
            servers=["https://example.com"],
            refresh_token_file=tmp_path / "nonexistent",
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
        )
        assert config.load_refresh_token() is None

    def test_save_and_load_roundtrip(self, tmp_path):
        """Saved refresh token can be loaded back."""
        refresh_file = tmp_path / "refresh_token"
        config = KeyserverConfig(
            servers=["https://example.com"],
            refresh_token_file=refresh_file,
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
        )
        config.save_refresh_token("refresh_roundtrip_123")
        assert config.load_refresh_token() == "refresh_roundtrip_123"

    def test_save_sets_restrictive_permissions(self, tmp_path):
        """Refresh token file is created with 0600 permissions."""
        refresh_file = tmp_path / "refresh_token"
        config = KeyserverConfig(
            servers=["https://example.com"],
            refresh_token_file=refresh_file,
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
        )
        config.save_refresh_token("secure_refresh")
        mode = refresh_file.stat().st_mode & 0o777
        assert mode == 0o600

    def test_clear_refresh_token(self, tmp_path):
        """Clear deletes the refresh token file."""
        refresh_file = tmp_path / "refresh_token"
        config = KeyserverConfig(
            servers=["https://example.com"],
            refresh_token_file=refresh_file,
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
        )
        config.save_refresh_token("to_be_deleted")
        assert config.clear_refresh_token() is True
        assert config.load_refresh_token() is None

    def test_clear_nonexistent_returns_false(self, tmp_path):
        """Clear returns False when no refresh token file exists."""
        config = KeyserverConfig(
            servers=["https://example.com"],
            refresh_token_file=tmp_path / "nonexistent",
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
        )
        assert config.clear_refresh_token() is False


# ===========================================================================
# Config Save/Load Roundtrip
# ===========================================================================

class TestConfigSaveLoad:
    """Test config serialization roundtrip."""

    def test_save_and_load_roundtrip(self, tmp_path):
        """Config saved to file can be loaded back with same values."""
        config_path = tmp_path / "config.json"
        original = KeyserverConfig(
            enabled=True,
            servers=["https://my-keyserver.example.com"],
            cache_ttl_seconds=7200,
            cache_max_entries=200,
            connect_timeout_seconds=8,
            read_timeout_seconds= 20,
            upload_enabled=False,
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
        )
        original.to_file(config_path)
        loaded = KeyserverConfig.from_file(config_path)

        assert loaded.enabled == original.enabled
        assert loaded.servers == original.servers
        assert loaded.cache_ttl_seconds == original.cache_ttl_seconds
        assert loaded.cache_max_entries == original.cache_max_entries
        assert loaded.connect_timeout_seconds == original.connect_timeout_seconds
        assert loaded.read_timeout_seconds == original.read_timeout_seconds
        assert loaded.upload_enabled == original.upload_enabled

    def test_save_excludes_api_token(self, tmp_path):
        """API token is not written to the config JSON file."""
        config_path = tmp_path / "config.json"
        config = KeyserverConfig(
            servers=["https://example.com"],
            api_token="secret_should_not_be_saved",
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
        )
        config.to_file(config_path)
        data = json.loads(config_path.read_text())
        assert "api_token" not in data


# ===========================================================================
# Mocked Connectivity Tests
# ===========================================================================

class TestServerConnectivity:
    """Test plugin connectivity with mocked HTTP."""

    def test_search_returns_none_when_disabled(self, tmp_path):
        """Plugin returns None for fetch when disabled."""
        config = KeyserverConfig(
            enabled=False,
            servers=["https://keyserver.example.com"],
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
        )
        plugin = KeyserverPlugin(config)
        result = plugin.fetch_key("test@example.com")
        assert result is None

    def test_search_handles_404(self, plugin_with_mock_session):
        """Plugin handles 404 (key not found) gracefully."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        plugin_with_mock_session.session.get.return_value = mock_response

        result = plugin_with_mock_session.fetch_key("nonexistent@example.com")
        assert result is None

    def test_search_handles_connection_error(self, plugin_with_mock_session):
        """Plugin handles connection failures gracefully."""
        plugin_with_mock_session.session.get.side_effect = (
            requests.exceptions.ConnectionError("Connection refused")
        )
        result = plugin_with_mock_session.fetch_key("test@example.com")
        assert result is None

    def test_search_handles_timeout(self, plugin_with_mock_session):
        """Plugin handles request timeouts gracefully."""
        plugin_with_mock_session.session.get.side_effect = (
            requests.exceptions.Timeout("Request timed out")
        )
        result = plugin_with_mock_session.fetch_key("test@example.com")
        assert result is None

    def test_search_calls_correct_url(self, plugin_with_mock_session):
        """Plugin sends search request to correct endpoint."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        plugin_with_mock_session.session.get.return_value = mock_response

        plugin_with_mock_session.fetch_key("alice@example.com")

        plugin_with_mock_session.session.get.assert_called_once()
        call_args = plugin_with_mock_session.session.get.call_args
        assert call_args[0][0] == "https://keyserver.example.com/api/v1/keys/search"
        assert call_args[1]["params"] == {"q": "alice@example.com"}


# ===========================================================================
# Token Refresh Tests (mocked)
# ===========================================================================

class TestTokenRefresh:
    """Test automatic token refresh on 401."""

    @pytest.fixture
    def plugin_with_tokens(self, tmp_path):
        """Plugin with access and refresh tokens saved."""
        token_file = tmp_path / "token"
        token_file.write_text("expired_access_token")
        token_file.chmod(0o600)
        refresh_file = tmp_path / "refresh_token"
        refresh_file.write_text("valid_refresh_token")
        refresh_file.chmod(0o600)
        config = KeyserverConfig(
            enabled=True,
            servers=["https://keyserver.example.com"],
            cache_path=tmp_path / "cache.db",
            api_token_file=token_file,
            refresh_token_file=refresh_file,
        )
        plugin = KeyserverPlugin(config)
        plugin.session = MagicMock()
        return plugin

    def test_auto_refresh_on_401(self, plugin_with_tokens):
        """On 401, plugin refreshes token and retries the request."""
        # First call returns 401, refresh succeeds, retry returns 200
        response_401 = MagicMock()
        response_401.status_code = 401
        response_200 = MagicMock()
        response_200.status_code = 200

        # POST calls: 1) upload → 401, 2) refresh → 200, 3) upload retry → 200
        refresh_response = MagicMock()
        refresh_response.status_code = 200
        refresh_response.json.return_value = {
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
        }

        plugin_with_tokens.session.post.side_effect = [
            response_401,      # initial authenticated request
            refresh_response,  # refresh call
            response_200,      # retry after refresh
        ]

        response = plugin_with_tokens._authenticated_request(
            "post", "https://keyserver.example.com/api/v1/keys", json={}
        )
        assert response.status_code == 200

        # Verify new tokens were saved
        assert plugin_with_tokens.config.load_api_token() == "new_access_token"
        assert plugin_with_tokens.config.load_refresh_token() == "new_refresh_token"

    def test_raises_auth_error_when_refresh_fails(self, plugin_with_tokens):
        """Raises AuthenticationError when refresh also fails."""
        response_401 = MagicMock()
        response_401.status_code = 401

        refresh_fail = MagicMock()
        refresh_fail.status_code = 401

        plugin_with_tokens.session.post.side_effect = [
            response_401,   # initial request
            refresh_fail,   # refresh fails
        ]

        with pytest.raises(AuthenticationError):
            plugin_with_tokens._authenticated_request(
                "post", "https://keyserver.example.com/api/v1/keys", json={}
            )

    def test_raises_auth_error_when_no_refresh_token(self, tmp_path):
        """Raises AuthenticationError when no refresh token available."""
        token_file = tmp_path / "token"
        token_file.write_text("expired_token")
        token_file.chmod(0o600)
        config = KeyserverConfig(
            enabled=True,
            servers=["https://keyserver.example.com"],
            cache_path=tmp_path / "cache.db",
            api_token_file=token_file,
            refresh_token_file=tmp_path / "no_refresh",
        )
        plugin = KeyserverPlugin(config)
        plugin.session = MagicMock()

        response_401 = MagicMock()
        response_401.status_code = 401
        plugin.session.post.return_value = response_401

        with pytest.raises(AuthenticationError):
            plugin._authenticated_request(
                "post", "https://keyserver.example.com/api/v1/keys", json={}
            )

    def test_no_refresh_when_request_succeeds(self, plugin_with_tokens):
        """No refresh attempt when initial request succeeds."""
        response_200 = MagicMock()
        response_200.status_code = 200
        plugin_with_tokens.session.post.return_value = response_200

        response = plugin_with_tokens._authenticated_request(
            "post", "https://keyserver.example.com/api/v1/keys", json={}
        )
        assert response.status_code == 200
        # Only one call — no refresh
        assert plugin_with_tokens.session.post.call_count == 1

    def test_raises_auth_error_when_no_token(self, tmp_path):
        """Raises AuthenticationError when no access token at all."""
        config = KeyserverConfig(
            enabled=True,
            servers=["https://keyserver.example.com"],
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "no_token",
            refresh_token_file=tmp_path / "no_refresh",
        )
        plugin = KeyserverPlugin(config)

        with pytest.raises(AuthenticationError):
            plugin._authenticated_request(
                "post", "https://keyserver.example.com/api/v1/keys", json={}
            )


# ===========================================================================
# Login Tests (mocked)
# ===========================================================================

class TestLogin:
    """Test login with client_id."""

    def test_login_saves_tokens(self, tmp_path):
        """Successful login saves access and refresh tokens."""
        config = KeyserverConfig(
            enabled=True,
            servers=["https://keyserver.example.com"],
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
            refresh_token_file=tmp_path / "refresh_token",
        )
        plugin = KeyserverPlugin(config)
        plugin.session = MagicMock()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "client_id": "test_client_123",
            "access_token": "jwt_access_token",
            "refresh_token": "jwt_refresh_token",
            "expires_at": "2026-03-26T12:00:00Z",
            "token_type": "Bearer",
        }
        plugin.session.post.return_value = mock_response

        result = plugin.login("test_client_123")

        assert result["client_id"] == "test_client_123"
        assert config.load_api_token() == "jwt_access_token"
        assert config.load_refresh_token() == "jwt_refresh_token"

    def test_login_calls_correct_url(self, tmp_path):
        """Login POSTs to /api/v1/keys/login."""
        config = KeyserverConfig(
            enabled=True,
            servers=["https://keyserver.example.com"],
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
            refresh_token_file=tmp_path / "refresh_token",
        )
        plugin = KeyserverPlugin(config)
        plugin.session = MagicMock()

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
        assert call_args[0][0] == "https://keyserver.example.com/api/v1/keys/login"
        assert call_args[1]["json"] == {"client_id": "abc"}

    def test_login_raises_on_invalid_client_id(self, tmp_path):
        """Login raises AuthenticationError on 401."""
        config = KeyserverConfig(
            enabled=True,
            servers=["https://keyserver.example.com"],
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
            refresh_token_file=tmp_path / "refresh_token",
        )
        plugin = KeyserverPlugin(config)
        plugin.session = MagicMock()

        mock_response = MagicMock()
        mock_response.status_code = 401
        plugin.session.post.return_value = mock_response

        with pytest.raises(AuthenticationError):
            plugin.login("invalid_client_id")

    def test_login_raises_when_disabled(self, tmp_path):
        """Login raises ValueError when plugin is disabled."""
        config = KeyserverConfig(
            enabled=False,
            servers=["https://keyserver.example.com"],
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
            refresh_token_file=tmp_path / "refresh_token",
        )
        plugin = KeyserverPlugin(config)

        with pytest.raises(ValueError):
            plugin.login("some_client_id")


# ===========================================================================
# Live Connectivity Tests (require --live-server)
# ===========================================================================

@pytest.mark.live
class TestLiveConnectivity:
    """Live tests against a running keyserver. Run with --live-server=URL."""

    def test_health_endpoint(self, live_server):
        """Server health endpoint returns healthy status."""
        response = requests.get(f"{live_server}/health", timeout=10)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_info_endpoint(self, live_server):
        """Server info endpoint lists keyserver module."""
        response = requests.get(f"{live_server}/info", timeout=10)
        assert response.status_code == 200
        data = response.json()
        assert "modules" in data
        assert "keyserver" in data["modules"]
        assert data["modules"]["keyserver"]["enabled"] is True

    def test_search_nonexistent_key(self, live_server):
        """Search for a non-existent key returns 404."""
        response = requests.get(
            f"{live_server}/api/v1/keys/search",
            params={"q": "nonexistent_test_key_12345"},
            timeout=10,
        )
        assert response.status_code == 404

    def test_plugin_fetch_nonexistent_key(self, live_server, tmp_path):
        """Plugin gracefully returns None for non-existent key."""
        config = KeyserverConfig(
            enabled=True,
            servers=[live_server],
            cache_path=tmp_path / "cache.db",
            api_token_file=tmp_path / "token",
        )
        plugin = KeyserverPlugin(config)
        result = plugin.fetch_key("nonexistent_test_key_12345")
        assert result is None

    def test_auth_with_valid_token(self, live_server):
        """Valid JWT token is accepted by an authenticated endpoint."""
        config = KeyserverConfig.from_file()
        token = config.load_api_token()
        if not token:
            pytest.skip("No API token configured")

        # POST to upload endpoint with valid token but empty body.
        # Expected: 422 (validation error) — NOT 401/403, proving auth passed.
        response = requests.post(
            f"{live_server}/api/v1/keys",
            headers={"Authorization": f"Bearer {token}"},
            json={},
            timeout=10,
        )
        assert response.status_code != 401, "Valid token was rejected"
        assert response.status_code != 403, "Valid token was forbidden"

    def test_auth_with_invalid_token(self, live_server):
        """Invalid token is rejected by an authenticated endpoint."""
        response = requests.post(
            f"{live_server}/api/v1/keys",
            headers={"Authorization": "Bearer invalid_token_12345"},
            json={},
            timeout=10,
        )
        assert response.status_code in (401, 403)

    def test_plugin_config_from_default_location(self):
        """Plugin loads config from default location if it exists."""
        config = KeyserverConfig.from_file()
        assert isinstance(config.enabled, bool)
        assert isinstance(config.servers, list)
        assert all(s.startswith("https://") for s in config.servers)
