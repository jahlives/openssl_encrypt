#!/usr/bin/env python3
"""
Unit tests for JWT Refresh Token implementation.

Tests the new refresh token functionality with sliding expiration,
token type validation, and security boundaries.
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock
import jwt

from openssl_encrypt_server.core.auth.token import TokenAuth, TokenConfig
from openssl_encrypt_server.modules.keyserver.models import KSClient
from fastapi import HTTPException


@pytest.fixture
def token_config():
    """Create test token configuration"""
    return TokenConfig(
        secret="test_secret_key_for_testing_only",
        algorithm="HS256",
        access_token_expire_minutes=60,  # 1 hour
        refresh_token_expire_days=7,     # 7 days
        issuer="test-keyserver",
        enable_sliding_expiration=True
    )


@pytest.fixture
def token_auth(token_config):
    """Create TokenAuth instance for testing"""
    return TokenAuth(token_config, KSClient)


class TestAccessTokenExpiry:
    """Tests for access token expiration"""

    def test_access_token_expires_after_1_hour(self, token_auth):
        """Access token should expire after 1 hour"""
        client_id = "test_client_123"

        # Create token
        access_token, expiry = token_auth.create_token(client_id, "access")

        # Verify expiry is approximately 1 hour from now
        now = datetime.now(timezone.utc)
        expected_expiry = now + timedelta(hours=1)

        # Allow 5 second tolerance for test execution time
        assert abs((expiry - expected_expiry).total_seconds()) < 5

        # Decode and verify expiry claim
        payload = jwt.decode(
            access_token,
            token_auth.secret,
            algorithms=[token_auth.algorithm],
            issuer=token_auth.issuer
        )

        exp_time = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
        assert abs((exp_time - expected_expiry).total_seconds()) < 5

    def test_expired_access_token_rejected(self, token_auth):
        """Expired access token should be rejected"""
        client_id = "test_client_123"

        # Create token with past expiry
        with patch('openssl_encrypt_server.core.auth.token.datetime') as mock_datetime:
            past_time = datetime.now(timezone.utc) - timedelta(hours=2)
            mock_datetime.now.return_value = past_time

            access_token, _ = token_auth.create_token(client_id, "access")

        # Try to verify expired token
        with pytest.raises(HTTPException) as exc_info:
            token_auth.verify_token(access_token)

        assert exc_info.value.status_code == 401
        assert "Token expired" in exc_info.value.detail


class TestRefreshTokenExpiry:
    """Tests for refresh token expiration"""

    def test_refresh_token_expires_after_7_days(self, token_auth):
        """Refresh token should expire after 7 days"""
        client_id = "test_client_123"

        # Create refresh token
        refresh_token, expiry = token_auth.create_token(client_id, "refresh")

        # Verify expiry is approximately 7 days from now
        now = datetime.now(timezone.utc)
        expected_expiry = now + timedelta(days=7)

        assert abs((expiry - expected_expiry).total_seconds()) < 5

    def test_expired_refresh_token_rejected(self, token_auth):
        """Expired refresh token should be rejected"""
        client_id = "test_client_123"

        # Create token with past expiry (8 days ago)
        with patch('openssl_encrypt_server.core.auth.token.datetime') as mock_datetime:
            past_time = datetime.now(timezone.utc) - timedelta(days=8)
            mock_datetime.now.return_value = past_time

            refresh_token, _ = token_auth.create_token(client_id, "refresh")

        # Try to use expired refresh token
        with pytest.raises(HTTPException) as exc_info:
            token_auth.refresh_access_token(refresh_token)

        assert exc_info.value.status_code == 401
        assert "Token expired" in exc_info.value.detail


class TestRefreshEndpoint:
    """Tests for token refresh functionality"""

    def test_refresh_endpoint_returns_new_token_pair(self, token_auth):
        """Refresh should return both new access and refresh tokens"""
        client_id = "test_client_123"

        # Create initial token pair
        tokens = token_auth.create_token_pair(client_id)
        refresh_token = tokens['refresh_token']

        # Refresh tokens
        result = token_auth.refresh_access_token(refresh_token)

        # Verify response structure
        assert 'client_id' in result
        assert 'access_token' in result
        assert 'refresh_token' in result
        assert 'access_token_expires_at' in result
        assert 'refresh_token_expires_at' in result
        assert 'token_type' in result

        assert result['client_id'] == client_id
        assert result['token_type'] == 'Bearer'

    def test_refresh_token_creates_new_access_token(self, token_auth):
        """New access token from refresh should be valid"""
        client_id = "test_client_123"

        # Create and use refresh token
        tokens = token_auth.create_token_pair(client_id)
        result = token_auth.refresh_access_token(tokens['refresh_token'])

        new_access_token = result['access_token']

        # Verify new access token works
        payload = token_auth.verify_token(new_access_token)
        assert payload.sub == client_id
        assert payload.iss == token_auth.issuer

    def test_old_access_token_still_valid_after_refresh(self, token_auth):
        """Old access token remains valid until its own expiry"""
        client_id = "test_client_123"

        # Create initial tokens
        tokens = token_auth.create_token_pair(client_id)
        old_access_token = tokens['access_token']

        # Refresh to get new tokens
        token_auth.refresh_access_token(tokens['refresh_token'])

        # Old access token should still be valid (not revoked)
        payload = token_auth.verify_token(old_access_token)
        assert payload.sub == client_id


class TestSlidingExpiration:
    """Tests for sliding expiration mechanism"""

    def test_sliding_expiration_extends_tokens(self, token_auth):
        """Refreshing should extend expiry times (sliding window)"""
        client_id = "test_client_123"

        # Create initial tokens
        initial_tokens = token_auth.create_token_pair(client_id)
        initial_refresh_expiry = initial_tokens['refresh_token_expires_at']

        # Simulate waiting 6 days
        with patch('openssl_encrypt_server.core.auth.token.datetime') as mock_datetime:
            future_time = datetime.now(timezone.utc) + timedelta(days=6)
            mock_datetime.now.return_value = future_time
            mock_datetime.side_effect = lambda *args, **kwargs: datetime.now(timezone.utc) if not args else datetime(*args, **kwargs)

            # Refresh tokens
            new_tokens = token_auth.refresh_access_token(initial_tokens['refresh_token'])

        # New refresh token should expire 7 days from refresh time (not original time)
        # This means the expiry was extended by ~6 days
        new_refresh_expiry = datetime.fromisoformat(new_tokens['refresh_token_expires_at'])
        initial_expiry = datetime.fromisoformat(initial_refresh_expiry)

        # New expiry should be significantly later than initial
        time_extension = (new_refresh_expiry - initial_expiry).total_seconds()

        # Should be extended by approximately 6 days (allowing for test execution time)
        expected_extension = 6 * 24 * 3600  # 6 days in seconds
        assert abs(time_extension - expected_extension) < 10

    def test_multiple_refreshes_chain_correctly(self, token_auth):
        """Multiple refreshes should continue sliding the window"""
        client_id = "test_client_123"

        # Initial tokens
        tokens = token_auth.create_token_pair(client_id)

        # Refresh 3 times
        for i in range(3):
            result = token_auth.refresh_access_token(tokens['refresh_token'])
            tokens = result

            # Verify each new access token works
            payload = token_auth.verify_token(tokens['access_token'])
            assert payload.sub == client_id


class TestTokenTypeValidation:
    """Tests for token type enforcement"""

    def test_access_token_cannot_be_used_to_refresh(self, token_auth):
        """Access token should not work for refresh endpoint"""
        client_id = "test_client_123"

        # Create token pair
        tokens = token_auth.create_token_pair(client_id)
        access_token = tokens['access_token']

        # Try to refresh with access token
        with pytest.raises(HTTPException) as exc_info:
            token_auth.refresh_access_token(access_token)

        assert exc_info.value.status_code == 401
        assert "Invalid token type" in exc_info.value.detail or "Refresh token required" in exc_info.value.detail

    def test_token_type_field_in_jwt(self, token_auth):
        """JWT payload should include type field"""
        client_id = "test_client_123"

        # Create both token types
        access_token, _ = token_auth.create_token(client_id, "access")
        refresh_token, _ = token_auth.create_token(client_id, "refresh")

        # Decode and check type field
        access_payload = jwt.decode(
            access_token,
            token_auth.secret,
            algorithms=[token_auth.algorithm],
            issuer=token_auth.issuer
        )
        refresh_payload = jwt.decode(
            refresh_token,
            token_auth.secret,
            algorithms=[token_auth.algorithm],
            issuer=token_auth.issuer
        )

        assert access_payload['type'] == 'access'
        assert refresh_payload['type'] == 'refresh'


class TestTokenPairCreation:
    """Tests for create_token_pair method"""

    def test_register_response_includes_both_tokens(self, token_auth):
        """Token pair should include access and refresh tokens"""
        client_id = "test_client_123"

        tokens = token_auth.create_token_pair(client_id)

        assert 'access_token' in tokens
        assert 'refresh_token' in tokens
        assert 'access_token_expires_at' in tokens
        assert 'refresh_token_expires_at' in tokens
        assert 'token_type' in tokens

        assert tokens['token_type'] == 'Bearer'
        assert tokens['access_token'] != tokens['refresh_token']

    def test_refresh_response_includes_expiry_times(self, token_auth):
        """Refresh response should include both expiry timestamps"""
        client_id = "test_client_123"

        tokens = token_auth.create_token_pair(client_id)
        result = token_auth.refresh_access_token(tokens['refresh_token'])

        # Check ISO 8601 format timestamps
        assert 'access_token_expires_at' in result
        assert 'refresh_token_expires_at' in result

        # Verify they parse as valid ISO timestamps
        access_expiry = datetime.fromisoformat(result['access_token_expires_at'])
        refresh_expiry = datetime.fromisoformat(result['refresh_token_expires_at'])

        # Refresh token should expire after access token
        assert refresh_expiry > access_expiry


class TestInvalidTokens:
    """Tests for invalid token handling"""

    def test_invalid_refresh_token_rejected(self, token_auth):
        """Random string should be rejected as refresh token"""
        fake_token = "not.a.valid.jwt.token.at.all"

        with pytest.raises(HTTPException) as exc_info:
            token_auth.refresh_access_token(fake_token)

        assert exc_info.value.status_code == 401

    def test_tampered_token_rejected(self, token_auth):
        """Modified token should fail verification"""
        client_id = "test_client_123"

        # Create valid token
        tokens = token_auth.create_token_pair(client_id)
        valid_token = tokens['refresh_token']

        # Tamper with token (change one character)
        tampered_token = valid_token[:-10] + "X" + valid_token[-9:]

        with pytest.raises(HTTPException) as exc_info:
            token_auth.refresh_access_token(tampered_token)

        assert exc_info.value.status_code == 401

    def test_wrong_issuer_token_rejected(self, token_auth):
        """Token from different issuer should be rejected"""
        client_id = "test_client_123"

        # Create token with wrong issuer
        wrong_issuer_config = TokenConfig(
            secret="test_secret_key_for_testing_only",
            algorithm="HS256",
            access_token_expire_minutes=60,
            refresh_token_expire_days=7,
            issuer="wrong-issuer",
            enable_sliding_expiration=True
        )
        wrong_auth = TokenAuth(wrong_issuer_config, KSClient)

        tokens = wrong_auth.create_token_pair(client_id)

        # Try to use with original token_auth
        with pytest.raises(HTTPException) as exc_info:
            token_auth.refresh_access_token(tokens['refresh_token'])

        assert exc_info.value.status_code == 401
        assert "not valid for this service" in exc_info.value.detail.lower() or "invalid issuer" in exc_info.value.detail.lower()


class TestTokenStructure:
    """Tests for JWT token structure"""

    def test_token_contains_required_claims(self, token_auth):
        """JWT should contain all required claims"""
        client_id = "test_client_123"

        access_token, _ = token_auth.create_token(client_id, "access")

        payload = jwt.decode(
            access_token,
            token_auth.secret,
            algorithms=[token_auth.algorithm],
            issuer=token_auth.issuer
        )

        # Check required claims
        assert 'sub' in payload  # Subject (client_id)
        assert 'iss' in payload  # Issuer
        assert 'exp' in payload  # Expiration
        assert 'iat' in payload  # Issued at
        assert 'jti' in payload  # JWT ID (unique token ID)
        assert 'type' in payload  # Token type

        assert payload['sub'] == client_id
        assert payload['iss'] == token_auth.issuer

    def test_each_token_has_unique_jti(self, token_auth):
        """Each token should have unique JWT ID"""
        client_id = "test_client_123"

        # Create multiple tokens
        token1, _ = token_auth.create_token(client_id, "access")
        token2, _ = token_auth.create_token(client_id, "access")

        payload1 = jwt.decode(token1, token_auth.secret, algorithms=[token_auth.algorithm], issuer=token_auth.issuer)
        payload2 = jwt.decode(token2, token_auth.secret, algorithms=[token_auth.algorithm], issuer=token_auth.issuer)

        # JTI should be different
        assert payload1['jti'] != payload2['jti']
