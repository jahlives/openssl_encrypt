#!/usr/bin/env python3
"""
Unit tests for CORS configuration.

Tests secure CORS settings with explicit origin control.
"""

import pytest
from unittest.mock import patch
import logging


class TestCORSConfiguration:
    """Tests for CORS configuration parsing and validation"""

    def test_empty_cors_origins_returns_empty_list(self):
        """Empty CORS_ORIGINS should return empty list (disabled)"""
        from openssl_encrypt_server.config import Settings

        settings = Settings(cors_origins="")
        origins = settings.get_cors_origins_list()

        assert origins == []

    def test_single_origin_parsing(self):
        """Should parse single origin correctly"""
        from openssl_encrypt_server.config import Settings

        settings = Settings(cors_origins="https://app.example.com")
        origins = settings.get_cors_origins_list()

        assert origins == ["https://app.example.com"]

    def test_multiple_origins_parsing(self):
        """Should parse comma-separated origins"""
        from openssl_encrypt_server.config import Settings

        settings = Settings(
            cors_origins="https://app.example.com,https://admin.example.com,http://localhost:3000"
        )
        origins = settings.get_cors_origins_list()

        assert len(origins) == 3
        assert "https://app.example.com" in origins
        assert "https://admin.example.com" in origins
        assert "http://localhost:3000" in origins

    def test_origins_are_trimmed(self):
        """Should trim whitespace from origins"""
        from openssl_encrypt_server.config import Settings

        settings = Settings(
            cors_origins=" https://app.example.com , https://admin.example.com "
        )
        origins = settings.get_cors_origins_list()

        assert origins == ["https://app.example.com", "https://admin.example.com"]

    def test_wildcard_origin_logs_warning(self):
        """Wildcard '*' origin should log security warning"""
        from openssl_encrypt_server.config import Settings

        settings = Settings(cors_origins="*")

        with patch('logging.getLogger') as mock_logger:
            logger_instance = mock_logger.return_value
            origins = settings.get_cors_origins_list()

            assert origins == ["*"]
            # Should have logged warning
            assert logger_instance.warning.called
            warning_msg = logger_instance.warning.call_args[0][0]
            assert "SECURITY WARNING" in warning_msg
            assert "wildcard" in warning_msg.lower()

    def test_wildcard_with_other_origins_logs_warning(self):
        """Wildcard with other origins should still log warning"""
        from openssl_encrypt_server.config import Settings

        settings = Settings(cors_origins="https://app.example.com,*")

        with patch('logging.getLogger') as mock_logger:
            logger_instance = mock_logger.return_value
            origins = settings.get_cors_origins_list()

            assert len(origins) == 2
            assert "*" in origins
            assert logger_instance.warning.called

    def test_cors_methods_parsing(self):
        """Should parse CORS methods correctly"""
        from openssl_encrypt_server.config import Settings

        settings = Settings(cors_allow_methods="GET,POST,PUT,DELETE,PATCH")
        methods = settings.get_cors_methods_list()

        assert len(methods) == 5
        assert "GET" in methods
        assert "POST" in methods
        assert "PUT" in methods
        assert "DELETE" in methods
        assert "PATCH" in methods

    def test_cors_headers_parsing(self):
        """Should parse CORS headers correctly"""
        from openssl_encrypt_server.config import Settings

        settings = Settings(
            cors_allow_headers="Authorization,Content-Type,X-Custom-Header"
        )
        headers = settings.get_cors_headers_list()

        assert len(headers) == 3
        assert "Authorization" in headers
        assert "Content-Type" in headers
        assert "X-Custom-Header" in headers

    def test_cors_default_credentials_false(self):
        """CORS credentials should default to false"""
        from openssl_encrypt_server.config import Settings

        settings = Settings()
        assert settings.cors_allow_credentials == False

    def test_cors_credentials_can_be_enabled(self):
        """CORS credentials can be explicitly enabled"""
        from openssl_encrypt_server.config import Settings

        settings = Settings(cors_allow_credentials=True)
        assert settings.cors_allow_credentials == True

    def test_cors_max_age_default(self):
        """CORS max age should default to 600 seconds"""
        from openssl_encrypt_server.config import Settings

        settings = Settings()
        assert settings.cors_max_age == 600

    def test_cors_max_age_configurable(self):
        """CORS max age can be configured"""
        from openssl_encrypt_server.config import Settings

        settings = Settings(cors_max_age=3600)
        assert settings.cors_max_age == 3600


class TestCORSMiddleware:
    """Tests for CORS middleware integration"""

    def test_cors_disabled_when_no_origins(self):
        """CORS middleware should not be added when no origins configured"""
        # This would require testing the actual server setup
        # We can at least verify the logic
        from openssl_encrypt_server.config import Settings

        settings = Settings(cors_origins="")
        origins = settings.get_cors_origins_list()

        # Empty list means CORS should be disabled
        assert origins == []
        assert len(origins) == 0

    def test_cors_enabled_when_origins_configured(self):
        """CORS middleware should be added when origins configured"""
        from openssl_encrypt_server.config import Settings

        settings = Settings(cors_origins="https://app.example.com")
        origins = settings.get_cors_origins_list()

        # Non-empty list means CORS should be enabled
        assert len(origins) > 0

    def test_cors_configuration_complete(self):
        """All CORS settings should be configurable"""
        from openssl_encrypt_server.config import Settings

        settings = Settings(
            cors_origins="https://app.example.com,https://admin.example.com",
            cors_allow_credentials=True,
            cors_allow_methods="GET,POST,DELETE",
            cors_allow_headers="Authorization,X-Custom",
            cors_max_age=1800
        )

        assert len(settings.get_cors_origins_list()) == 2
        assert settings.cors_allow_credentials == True
        assert len(settings.get_cors_methods_list()) == 3
        assert len(settings.get_cors_headers_list()) == 2
        assert settings.cors_max_age == 1800


class TestCORSSecureDefaults:
    """Tests for secure CORS defaults"""

    def test_default_cors_origins_empty(self):
        """Default CORS origins should be empty (disabled)"""
        from openssl_encrypt_server.config import Settings

        settings = Settings()
        assert settings.cors_origins == ""

    def test_default_credentials_disabled(self):
        """Default credentials should be disabled"""
        from openssl_encrypt_server.config import Settings

        settings = Settings()
        assert settings.cors_allow_credentials == False

    def test_default_methods_restrictive(self):
        """Default methods should be restrictive"""
        from openssl_encrypt_server.config import Settings

        settings = Settings()
        methods = settings.get_cors_methods_list()

        # Should not include dangerous methods like TRACE, CONNECT
        assert "TRACE" not in methods
        assert "CONNECT" not in methods

        # Should include standard CRUD methods
        assert "GET" in methods
        assert "POST" in methods
        assert "PUT" in methods
        assert "DELETE" in methods

    def test_default_headers_minimal(self):
        """Default headers should be minimal"""
        from openssl_encrypt_server.config import Settings

        settings = Settings()
        headers = settings.get_cors_headers_list()

        # Should include essential headers
        assert "Authorization" in headers
        assert "Content-Type" in headers

        # Should not include wildcards
        assert "*" not in headers

    def test_no_wildcard_by_default(self):
        """Should not use wildcard origins by default"""
        from openssl_encrypt_server.config import Settings

        settings = Settings()
        origins = settings.get_cors_origins_list()

        assert "*" not in origins
        assert origins == []  # Completely disabled by default
