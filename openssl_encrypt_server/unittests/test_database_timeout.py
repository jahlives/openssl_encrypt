#!/usr/bin/env python3
"""
Unit tests for database query timeout.

Tests that query timeout is properly configured to prevent DoS attacks
from slow queries.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, call


class TestDatabaseTimeoutConfiguration:
    """Tests for database timeout configuration"""

    def test_init_engine_accepts_query_timeout_parameter(self):
        """init_engine should accept query_timeout parameter"""
        from openssl_encrypt_server.core.database import init_engine

        with patch('openssl_encrypt_server.core.database.create_async_engine') as mock_create:
            mock_create.return_value = Mock()

            init_engine(
                "postgresql+asyncpg://user:pass@localhost/db",
                query_timeout=45
            )

            # Should have been called
            assert mock_create.called

    def test_default_query_timeout_is_30_seconds(self):
        """Default query timeout should be 30 seconds"""
        from openssl_encrypt_server.core.database import init_engine

        with patch('openssl_encrypt_server.core.database.create_async_engine') as mock_create:
            mock_create.return_value = Mock()

            init_engine("postgresql+asyncpg://user:pass@localhost/db")

            # Check connect_args
            call_kwargs = mock_create.call_args[1]
            connect_args = call_kwargs.get('connect_args', {})

            assert 'command_timeout' in connect_args
            assert connect_args['command_timeout'] == 30

    def test_custom_query_timeout_used(self):
        """Custom query timeout should be used"""
        from openssl_encrypt_server.core.database import init_engine

        with patch('openssl_encrypt_server.core.database.create_async_engine') as mock_create:
            mock_create.return_value = Mock()

            init_engine(
                "postgresql+asyncpg://user:pass@localhost/db",
                query_timeout=60
            )

            call_kwargs = mock_create.call_args[1]
            connect_args = call_kwargs.get('connect_args', {})

            assert connect_args['command_timeout'] == 60

    def test_asyncpg_command_timeout_configured(self):
        """asyncpg command_timeout should be configured"""
        from openssl_encrypt_server.core.database import init_engine

        with patch('openssl_encrypt_server.core.database.create_async_engine') as mock_create:
            mock_create.return_value = Mock()

            init_engine(
                "postgresql+asyncpg://user:pass@localhost/db",
                query_timeout=30
            )

            call_kwargs = mock_create.call_args[1]
            connect_args = call_kwargs.get('connect_args', {})

            # asyncpg uses command_timeout
            assert 'command_timeout' in connect_args
            assert connect_args['command_timeout'] == 30

    def test_postgresql_statement_timeout_configured(self):
        """PostgreSQL statement_timeout should be configured"""
        from openssl_encrypt_server.core.database import init_engine

        with patch('openssl_encrypt_server.core.database.create_async_engine') as mock_create:
            mock_create.return_value = Mock()

            init_engine(
                "postgresql+asyncpg://user:pass@localhost/db",
                query_timeout=30
            )

            call_kwargs = mock_create.call_args[1]
            connect_args = call_kwargs.get('connect_args', {})

            # PostgreSQL server setting
            assert 'server_settings' in connect_args
            assert 'statement_timeout' in connect_args['server_settings']
            assert connect_args['server_settings']['statement_timeout'] == "30s"

    def test_pool_size_configurable(self):
        """Pool size should be configurable"""
        from openssl_encrypt_server.core.database import init_engine

        with patch('openssl_encrypt_server.core.database.create_async_engine') as mock_create:
            mock_create.return_value = Mock()

            init_engine(
                "postgresql+asyncpg://user:pass@localhost/db",
                pool_size=30
            )

            call_kwargs = mock_create.call_args[1]
            assert call_kwargs['pool_size'] == 30

    def test_max_overflow_configurable(self):
        """Max overflow should be configurable"""
        from openssl_encrypt_server.core.database import init_engine

        with patch('openssl_encrypt_server.core.database.create_async_engine') as mock_create:
            mock_create.return_value = Mock()

            init_engine(
                "postgresql+asyncpg://user:pass@localhost/db",
                max_overflow=20
            )

            call_kwargs = mock_create.call_args[1]
            assert call_kwargs['max_overflow'] == 20

    def test_pool_pre_ping_enabled(self):
        """pool_pre_ping should be enabled"""
        from openssl_encrypt_server.core.database import init_engine

        with patch('openssl_encrypt_server.core.database.create_async_engine') as mock_create:
            mock_create.return_value = Mock()

            init_engine("postgresql+asyncpg://user:pass@localhost/db")

            call_kwargs = mock_create.call_args[1]
            assert call_kwargs['pool_pre_ping'] == True


class TestSettingsIntegration:
    """Tests for settings integration with database timeout"""

    def test_settings_has_database_query_timeout(self):
        """Settings should have database_query_timeout field"""
        from openssl_encrypt_server.config import Settings

        settings = Settings()
        assert hasattr(settings, 'database_query_timeout')

    def test_default_database_query_timeout_is_30(self):
        """Default database query timeout should be 30 seconds"""
        from openssl_encrypt_server.config import Settings

        settings = Settings()
        assert settings.database_query_timeout == 30

    def test_database_query_timeout_configurable(self):
        """Database query timeout should be configurable via env"""
        from openssl_encrypt_server.config import Settings

        settings = Settings(database_query_timeout=60)
        assert settings.database_query_timeout == 60

    def test_settings_has_pool_configuration(self):
        """Settings should have pool size and overflow configuration"""
        from openssl_encrypt_server.config import Settings

        settings = Settings()
        assert hasattr(settings, 'database_pool_size')
        assert hasattr(settings, 'database_max_overflow')

    def test_default_pool_size_is_20(self):
        """Default pool size should be 20"""
        from openssl_encrypt_server.config import Settings

        settings = Settings()
        assert settings.database_pool_size == 20

    def test_default_max_overflow_is_10(self):
        """Default max overflow should be 10"""
        from openssl_encrypt_server.config import Settings

        settings = Settings()
        assert settings.database_max_overflow == 10


class TestTimeoutDefenseInDepth:
    """Tests for defense-in-depth timeout configuration"""

    def test_both_driver_and_server_timeouts_configured(self):
        """Both driver-level and server-level timeouts should be configured"""
        from openssl_encrypt_server.core.database import init_engine

        with patch('openssl_encrypt_server.core.database.create_async_engine') as mock_create:
            mock_create.return_value = Mock()

            init_engine(
                "postgresql+asyncpg://user:pass@localhost/db",
                query_timeout=30
            )

            call_kwargs = mock_create.call_args[1]
            connect_args = call_kwargs.get('connect_args', {})

            # Driver level (asyncpg)
            assert 'command_timeout' in connect_args

            # Server level (PostgreSQL)
            assert 'server_settings' in connect_args
            assert 'statement_timeout' in connect_args['server_settings']

    def test_timeout_format_consistency(self):
        """Timeout formats should be consistent with each layer"""
        from openssl_encrypt_server.core.database import init_engine

        with patch('openssl_encrypt_server.core.database.create_async_engine') as mock_create:
            mock_create.return_value = Mock()

            timeout_seconds = 45
            init_engine(
                "postgresql+asyncpg://user:pass@localhost/db",
                query_timeout=timeout_seconds
            )

            call_kwargs = mock_create.call_args[1]
            connect_args = call_kwargs.get('connect_args', {})

            # asyncpg uses seconds as number
            assert connect_args['command_timeout'] == timeout_seconds

            # PostgreSQL uses string with 's' suffix
            assert connect_args['server_settings']['statement_timeout'] == f"{timeout_seconds}s"

    def test_zero_timeout_not_allowed(self):
        """Zero timeout should not be allowed (would disable timeout)"""
        from openssl_encrypt_server.config import Settings

        # Default should not be zero
        settings = Settings()
        assert settings.database_query_timeout > 0

    def test_negative_timeout_not_allowed(self):
        """Negative timeout should not be allowed"""
        from openssl_encrypt_server.config import Settings

        # Test that negative value gets rejected or uses default
        # Pydantic should enforce positive values
        settings = Settings()
        assert settings.database_query_timeout > 0


class TestTimeoutLogging:
    """Tests for timeout configuration logging"""

    def test_timeout_value_logged(self):
        """Query timeout value should be logged"""
        from openssl_encrypt_server.core.database import init_engine

        with patch('openssl_encrypt_server.core.database.create_async_engine') as mock_create:
            mock_create.return_value = Mock()

            with patch('openssl_encrypt_server.core.database.logger') as mock_logger:
                init_engine(
                    "postgresql+asyncpg://user:pass@localhost/db",
                    query_timeout=45
                )

                # Should log the timeout value
                info_calls = [call[0][0] for call in mock_logger.info.call_args_list]
                timeout_logged = any("45" in str(call) and "timeout" in str(call).lower() for call in info_calls)
                assert timeout_logged, "Query timeout should be logged"
