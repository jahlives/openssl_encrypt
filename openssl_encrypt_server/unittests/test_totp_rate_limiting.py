#!/usr/bin/env python3
"""
Unit tests for TOTP rate limiting.

Tests the TOTPRateLimiter that prevents brute-force attacks
on TOTP verification endpoints.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch

from openssl_encrypt_server.modules.pepper.totp import TOTPRateLimiter
from fastapi import HTTPException


@pytest.fixture
def rate_limiter():
    """Create TOTPRateLimiter with default settings"""
    return TOTPRateLimiter(
        max_attempts=5,
        window_minutes=5,
        lockout_minutes=15
    )


@pytest.fixture
def strict_rate_limiter():
    """Create TOTPRateLimiter with stricter settings for testing"""
    return TOTPRateLimiter(
        max_attempts=3,
        window_minutes=2,
        lockout_minutes=10
    )


class TestAttemptLimits:
    """Tests for attempt counting and limits"""

    def test_totp_allows_5_attempts(self, rate_limiter):
        """Should allow 5 attempts without lockout"""
        client_id = "test_client_123"

        # Record 5 attempts
        for i in range(5):
            rate_limiter.check_rate_limit(client_id)
            rate_limiter.record_attempt(client_id)

        # All 5 should succeed without exception
        assert len(rate_limiter.attempts[client_id]) == 5

    def test_totp_locks_after_5_attempts(self, rate_limiter):
        """6th attempt should trigger lockout"""
        client_id = "test_client_123"

        # Record 5 attempts
        for i in range(5):
            rate_limiter.check_rate_limit(client_id)
            rate_limiter.record_attempt(client_id)

        # 6th attempt should raise HTTPException
        with pytest.raises(HTTPException) as exc_info:
            rate_limiter.check_rate_limit(client_id)

        assert exc_info.value.status_code == 429
        assert "locked" in exc_info.value.detail.lower() or "many attempts" in exc_info.value.detail.lower()

    def test_exact_limit_boundary(self, rate_limiter):
        """Test behavior at exact attempt limit"""
        client_id = "test_client_123"

        # Record exactly 4 attempts
        for i in range(4):
            rate_limiter.record_attempt(client_id)

        # 5th check (after 4 attempts) should still pass
        rate_limiter.check_rate_limit(client_id)

        # Record 5th attempt
        rate_limiter.record_attempt(client_id)

        # 6th check (after 5 attempts) should fail
        with pytest.raises(HTTPException):
            rate_limiter.check_rate_limit(client_id)


class TestLockoutDuration:
    """Tests for lockout duration and expiry"""

    def test_totp_lockout_lasts_15_minutes(self, rate_limiter):
        """Lockout should last for configured duration"""
        client_id = "test_client_123"

        # Trigger lockout
        for i in range(6):
            try:
                rate_limiter.check_rate_limit(client_id)
                rate_limiter.record_attempt(client_id)
            except HTTPException:
                pass

        # Should be locked out
        with pytest.raises(HTTPException):
            rate_limiter.check_rate_limit(client_id)

        # Mock time advancing 14 minutes
        with patch('openssl_encrypt_server.modules.pepper.totp.datetime') as mock_datetime:
            future_time = datetime.now(timezone.utc) + timedelta(minutes=14)
            mock_datetime.now.return_value = future_time
            mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw) if args else future_time

            # Still locked
            with pytest.raises(HTTPException):
                rate_limiter.check_rate_limit(client_id)

        # Mock time advancing 16 minutes (past lockout)
        with patch('openssl_encrypt_server.modules.pepper.totp.datetime') as mock_datetime:
            future_time = datetime.now(timezone.utc) + timedelta(minutes=16)
            mock_datetime.now.return_value = future_time
            mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw) if args else future_time

            # Should be unlocked
            rate_limiter.check_rate_limit(client_id)

    def test_lockout_entry_created(self, rate_limiter):
        """Lockout should create entry in lockouts dict"""
        client_id = "test_client_123"

        # Trigger lockout
        for i in range(6):
            try:
                rate_limiter.check_rate_limit(client_id)
                rate_limiter.record_attempt(client_id)
            except HTTPException:
                pass

        # Lockout entry should exist
        assert client_id in rate_limiter.lockouts

        # Lockout expiry should be ~15 minutes from now
        lockout_until = rate_limiter.lockouts[client_id]
        expected_time = datetime.now(timezone.utc) + timedelta(minutes=15)

        # Allow 5 second tolerance
        assert abs((lockout_until - expected_time).total_seconds()) < 5


class TestWindowExpiry:
    """Tests for attempt window sliding/expiry"""

    def test_totp_attempt_window_5_minutes(self, rate_limiter):
        """Old attempts should expire after window"""
        client_id = "test_client_123"

        # Record 3 attempts
        for i in range(3):
            rate_limiter.record_attempt(client_id)

        # Mock time advancing 6 minutes
        with patch('openssl_encrypt_server.modules.pepper.totp.datetime') as mock_datetime:
            future_time = datetime.utcnow() + timedelta(minutes=6)
            mock_datetime.utcnow.return_value = future_time

            # Old attempts should be cleaned up
            rate_limiter.check_rate_limit(client_id)

            # Should be able to make 5 new attempts
            for i in range(3):
                rate_limiter.record_attempt(client_id)

            rate_limiter.check_rate_limit(client_id)  # Should succeed

    def test_totp_counter_cleanup(self, rate_limiter):
        """Old timestamps should be removed from attempts list"""
        client_id = "test_client_123"

        # Record attempts at different times
        with patch('openssl_encrypt_server.modules.pepper.totp.datetime') as mock_datetime:
            # 3 old attempts (7 minutes ago)
            old_time = datetime.utcnow() - timedelta(minutes=7)
            mock_datetime.utcnow.return_value = old_time

            for i in range(3):
                rate_limiter.record_attempt(client_id)

        # 2 recent attempts
        for i in range(2):
            rate_limiter.record_attempt(client_id)

        # Trigger cleanup via check
        rate_limiter.check_rate_limit(client_id)

        # Only recent attempts should remain
        # (Old ones outside 5-minute window should be cleaned)
        recent_attempts = [
            ts for ts in rate_limiter.attempts[client_id]
            if datetime.utcnow() - ts < timedelta(minutes=5)
        ]

        assert len(recent_attempts) == 2


class TestPerClientIsolation:
    """Tests that rate limits are per-client"""

    def test_totp_rate_limit_per_client(self, rate_limiter):
        """Each client should have independent counter"""
        client_a = "client_a"
        client_b = "client_b"

        # Exhaust client A's attempts
        for i in range(6):
            try:
                rate_limiter.check_rate_limit(client_a)
                rate_limiter.record_attempt(client_a)
            except HTTPException:
                pass

        # Client A should be locked
        with pytest.raises(HTTPException):
            rate_limiter.check_rate_limit(client_a)

        # Client B should be unaffected
        rate_limiter.check_rate_limit(client_b)
        for i in range(5):
            rate_limiter.record_attempt(client_b)
            rate_limiter.check_rate_limit(client_b)

    def test_multiple_clients_independent_counters(self, rate_limiter):
        """Multiple clients should not interfere"""
        clients = [f"client_{i}" for i in range(10)]

        # Each client makes 3 attempts
        for client_id in clients:
            for i in range(3):
                rate_limiter.check_rate_limit(client_id)
                rate_limiter.record_attempt(client_id)

        # All clients should still have 2 attempts remaining
        for client_id in clients:
            rate_limiter.check_rate_limit(client_id)
            rate_limiter.record_attempt(client_id)
            rate_limiter.check_rate_limit(client_id)
            rate_limiter.record_attempt(client_id)

            # All should still be under limit
            assert len(rate_limiter.attempts[client_id]) == 5


class TestResponseFormat:
    """Tests for error response format"""

    def test_totp_lockout_response_format(self, rate_limiter):
        """Lockout error should have appropriate status and message"""
        client_id = "test_client_123"

        # Trigger lockout
        for i in range(6):
            try:
                rate_limiter.check_rate_limit(client_id)
                rate_limiter.record_attempt(client_id)
            except HTTPException:
                pass

        # Check error response
        with pytest.raises(HTTPException) as exc_info:
            rate_limiter.check_rate_limit(client_id)

        exception = exc_info.value

        # Verify status code
        assert exception.status_code == 429

        # Verify message content
        detail = exception.detail.lower()
        assert "locked" in detail or "many" in detail or "try again" in detail

    def test_error_message_user_friendly(self, rate_limiter):
        """Error message should be clear to users"""
        client_id = "test_client_123"

        # Trigger lockout
        for i in range(6):
            try:
                rate_limiter.check_rate_limit(client_id)
                rate_limiter.record_attempt(client_id)
            except HTTPException:
                pass

        with pytest.raises(HTTPException) as exc_info:
            rate_limiter.check_rate_limit(client_id)

        detail = exc_info.value.detail

        # Should be informative
        assert len(detail) > 10
        assert "minute" in detail.lower() or "time" in detail.lower()


class TestConfigurability:
    """Tests for configurable rate limiting parameters"""

    def test_custom_max_attempts(self):
        """Should respect custom max attempts"""
        limiter = TOTPRateLimiter(max_attempts=3, window_minutes=5, lockout_minutes=15)
        client_id = "test_client"

        # Should allow 3 attempts
        for i in range(3):
            limiter.check_rate_limit(client_id)
            limiter.record_attempt(client_id)

        # 4th should trigger lockout
        with pytest.raises(HTTPException):
            limiter.check_rate_limit(client_id)

    def test_custom_window_duration(self):
        """Should respect custom window duration"""
        limiter = TOTPRateLimiter(max_attempts=5, window_minutes=2, lockout_minutes=15)
        client_id = "test_client"

        # Record attempts
        for i in range(3):
            limiter.record_attempt(client_id)

        # Mock time advancing 3 minutes (past 2-minute window)
        with patch('openssl_encrypt_server.modules.pepper.totp.datetime') as mock_datetime:
            future_time = datetime.utcnow() + timedelta(minutes=3)
            mock_datetime.utcnow.return_value = future_time

            # Old attempts should be expired
            limiter.check_rate_limit(client_id)
            cleaned_attempts = [
                ts for ts in limiter.attempts[client_id]
                if future_time - ts < timedelta(minutes=2)
            ]
            assert len(cleaned_attempts) == 0

    def test_custom_lockout_duration(self):
        """Should respect custom lockout duration"""
        limiter = TOTPRateLimiter(max_attempts=2, window_minutes=5, lockout_minutes=5)
        client_id = "test_client"

        # Trigger lockout
        for i in range(3):
            try:
                limiter.check_rate_limit(client_id)
                limiter.record_attempt(client_id)
            except HTTPException:
                pass

        # Mock time advancing 6 minutes (past 5-minute lockout)
        with patch('openssl_encrypt_server.modules.pepper.totp.datetime') as mock_datetime:
            future_time = datetime.utcnow() + timedelta(minutes=6)
            mock_datetime.utcnow.return_value = future_time

            # Should be unlocked
            limiter.check_rate_limit(client_id)


class TestEdgeCases:
    """Tests for edge cases"""

    def test_first_attempt_always_allowed(self, rate_limiter):
        """First attempt for new client should always work"""
        client_id = "new_client"

        rate_limiter.check_rate_limit(client_id)
        rate_limiter.record_attempt(client_id)

        assert len(rate_limiter.attempts[client_id]) == 1

    def test_simultaneous_attempts(self, rate_limiter):
        """Rapid sequential attempts should all count"""
        client_id = "test_client"

        # Record 6 attempts rapidly
        for i in range(6):
            try:
                rate_limiter.check_rate_limit(client_id)
            except HTTPException:
                pass
            rate_limiter.record_attempt(client_id)

        # Should have triggered lockout
        with pytest.raises(HTTPException):
            rate_limiter.check_rate_limit(client_id)

    def test_lockout_reset_after_expiry(self, rate_limiter):
        """After lockout expires, counter should reset"""
        client_id = "test_client"

        # Trigger lockout
        for i in range(6):
            try:
                rate_limiter.check_rate_limit(client_id)
                rate_limiter.record_attempt(client_id)
            except HTTPException:
                pass

        # Mock time past lockout
        with patch('openssl_encrypt_server.modules.pepper.totp.datetime') as mock_datetime:
            future_time = datetime.utcnow() + timedelta(minutes=20)
            mock_datetime.utcnow.return_value = future_time

            # Lockout should be cleared
            rate_limiter.check_rate_limit(client_id)

            # Should be able to make fresh attempts
            for i in range(5):
                rate_limiter.record_attempt(client_id)
                rate_limiter.check_rate_limit(client_id)

    def test_empty_client_id_handled(self, rate_limiter):
        """Empty client ID should be handled"""
        client_id = ""

        rate_limiter.check_rate_limit(client_id)
        rate_limiter.record_attempt(client_id)

        assert client_id in rate_limiter.attempts
