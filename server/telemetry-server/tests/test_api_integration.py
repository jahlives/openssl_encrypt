#!/usr/bin/env python3
"""
Integration tests for FastAPI telemetry server.

Tests all API endpoints with real database interactions.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest
from app.database import Base, get_db
from app.main import app
from app.models import APIKey, TelemetryRaw
from app.services import KeyService
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Test database URL (SQLite in-memory)
TEST_DATABASE_URL = "sqlite:///:memory:"

# Create test engine
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Override database dependency for testing."""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


# Override dependency
app.dependency_overrides[get_db] = override_get_db

# Create test client
client = TestClient(app)


@pytest.fixture(scope="function")
def test_db():
    """Create test database for each test."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


class TestHealthEndpoint:
    """Test health check endpoint."""

    def test_health_check(self):
        """Test health endpoint returns healthy status."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data


class TestRegistrationEndpoint:
    """Test client registration endpoint."""

    def test_successful_registration(self, test_db):
        """Test successful client registration."""
        request_data = {
            "client_id": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
            "platform": "linux",
            "client_version": "1.4.0",
        }

        response = client.post("/api/v1/register", json=request_data)

        assert response.status_code == 200
        data = response.json()
        assert "api_key" in data
        assert data["api_key"].startswith("sk_")
        assert "expires" in data

        # Verify key is valid for ~365 days
        expires = datetime.fromisoformat(data["expires"].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        days_until_expiry = (expires - now).days
        assert 360 <= days_until_expiry <= 370

    def test_registration_invalid_platform(self, test_db):
        """Test registration with invalid platform."""
        request_data = {
            "client_id": "test_client_123",
            "platform": "invalid_platform",
            "client_version": "1.4.0",
        }

        response = client.post("/api/v1/register", json=request_data)
        assert response.status_code == 400
        assert "Invalid platform" in response.json()["detail"]

    def test_registration_duplicate_client_id(self, test_db):
        """Test registration with duplicate client ID."""
        request_data = {
            "client_id": "duplicate_client_id",
            "platform": "linux",
            "client_version": "1.4.0",
        }

        # First registration
        response1 = client.post("/api/v1/register", json=request_data)
        assert response1.status_code == 200

        # Second registration with same client_id
        response2 = client.post("/api/v1/register", json=request_data)
        assert response2.status_code == 409
        assert "already registered" in response2.json()["detail"]

    def test_registration_missing_fields(self, test_db):
        """Test registration with missing required fields."""
        request_data = {
            "client_id": "test_client",
            # Missing platform and client_version
        }

        response = client.post("/api/v1/register", json=request_data)
        assert response.status_code == 422  # Validation error


class TestTelemetryUploadEndpoint:
    """Test telemetry upload endpoint."""

    def test_successful_batch_upload(self, test_db):
        """Test successful batch telemetry upload."""
        # Register client first
        reg_response = client.post(
            "/api/v1/register",
            json={
                "client_id": "test_client_upload",
                "platform": "linux",
                "client_version": "1.4.0",
            },
        )
        api_key = reg_response.json()["api_key"]

        # Prepare telemetry events
        events = [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operation": "encrypt",
                "mode": "symmetric",
                "format_version": 8,
                "hash_algorithms": ["sha512", "blake2b"],
                "kdf_algorithms": ["argon2"],
                "kdf_parameters": {"argon2": {"time_cost": 3, "memory_cost": 65536}},
                "encryption_algorithm": "aes-256-gcm",
                "cascade_enabled": False,
                "success": True,
            },
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operation": "decrypt",
                "mode": "symmetric",
                "format_version": 8,
                "hash_algorithms": ["sha3_256"],
                "kdf_algorithms": ["scrypt"],
                "encryption_algorithm": "chacha20-poly1305",
                "success": True,
            },
        ]

        # Upload
        response = client.post(
            "/api/v1/telemetry",
            json={"events": events},
            headers={"Authorization": f"Bearer {api_key}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["received"] == 2
        assert data["processed"] == 2

    def test_upload_without_authentication(self, test_db):
        """Test upload without API key."""
        events = [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operation": "encrypt",
                "mode": "symmetric",
                "format_version": 8,
                "hash_algorithms": ["sha512"],
                "kdf_algorithms": ["argon2"],
                "encryption_algorithm": "aes-256-gcm",
                "success": True,
            }
        ]

        response = client.post("/api/v1/telemetry", json={"events": events})
        assert response.status_code == 403  # No auth header

    def test_upload_with_invalid_api_key(self, test_db):
        """Test upload with invalid API key."""
        events = [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operation": "encrypt",
                "mode": "symmetric",
                "format_version": 8,
                "hash_algorithms": ["sha512"],
                "kdf_algorithms": ["argon2"],
                "encryption_algorithm": "aes-256-gcm",
                "success": True,
            }
        ]

        response = client.post(
            "/api/v1/telemetry",
            json={"events": events},
            headers={"Authorization": "Bearer invalid_key_12345"},
        )
        assert response.status_code == 401

    def test_upload_cascade_encryption(self, test_db):
        """Test uploading cascade encryption event."""
        # Register client
        reg_response = client.post(
            "/api/v1/register",
            json={
                "client_id": "test_cascade_client",
                "platform": "macos",
                "client_version": "1.4.0",
            },
        )
        api_key = reg_response.json()["api_key"]

        # Cascade event
        events = [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operation": "encrypt",
                "mode": "symmetric",
                "format_version": 8,
                "hash_algorithms": ["sha512"],
                "kdf_algorithms": ["argon2"],
                "encryption_algorithm": "cascade",
                "cascade_enabled": True,
                "cascade_cipher_count": 3,
                "success": True,
            }
        ]

        response = client.post(
            "/api/v1/telemetry",
            json={"events": events},
            headers={"Authorization": f"Bearer {api_key}"},
        )

        assert response.status_code == 200
        assert response.json()["processed"] == 1

    def test_upload_pqc_event(self, test_db):
        """Test uploading post-quantum cryptography event."""
        # Register client
        reg_response = client.post(
            "/api/v1/register",
            json={
                "client_id": "test_pqc_client",
                "platform": "windows",
                "client_version": "1.4.0",
            },
        )
        api_key = reg_response.json()["api_key"]

        # PQC event
        events = [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operation": "encrypt",
                "mode": "asymmetric",
                "format_version": 8,
                "hash_algorithms": ["sha512"],
                "kdf_algorithms": ["argon2"],
                "encryption_algorithm": "aes-256-gcm",
                "pqc_kem_algorithm": "ML-KEM-768",
                "pqc_signing_algorithm": "ML-DSA-65",
                "success": True,
            }
        ]

        response = client.post(
            "/api/v1/telemetry",
            json={"events": events},
            headers={"Authorization": f"Bearer {api_key}"},
        )

        assert response.status_code == 200
        assert response.json()["processed"] == 1


class TestStatisticsEndpoint:
    """Test public statistics endpoint."""

    def test_stats_endpoint_no_auth_required(self, test_db):
        """Test statistics endpoint is public (no auth)."""
        response = client.get("/api/v1/stats")
        assert response.status_code == 200

    def test_stats_with_no_data(self, test_db):
        """Test statistics with no telemetry data."""
        response = client.get("/api/v1/stats")
        data = response.json()

        assert data["total_operations"] == 0
        assert data["total_clients"] == 0
        assert data["success_rate"] == 1.0  # Default when no data

    def test_stats_with_data(self, test_db):
        """Test statistics with telemetry data."""
        # Register client and upload events
        reg_response = client.post(
            "/api/v1/register",
            json={
                "client_id": "stats_test_client",
                "platform": "linux",
                "client_version": "1.4.0",
            },
        )
        api_key = reg_response.json()["api_key"]

        # Upload various events
        events = [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operation": "encrypt",
                "mode": "symmetric",
                "format_version": 8,
                "hash_algorithms": ["sha512", "blake2b"],
                "kdf_algorithms": ["argon2"],
                "encryption_algorithm": "aes-256-gcm",
                "success": True,
            },
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operation": "decrypt",
                "mode": "symmetric",
                "format_version": 8,
                "hash_algorithms": ["sha3_256"],
                "kdf_algorithms": ["scrypt"],
                "encryption_algorithm": "chacha20-poly1305",
                "success": True,
            },
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operation": "encrypt",
                "mode": "asymmetric",
                "format_version": 8,
                "hash_algorithms": ["sha512"],
                "kdf_algorithms": ["argon2"],
                "encryption_algorithm": "aes-256-gcm",
                "pqc_kem_algorithm": "ML-KEM-768",
                "success": False,
                "error_category": "key_error",
            },
        ]

        client.post(
            "/api/v1/telemetry",
            json={"events": events},
            headers={"Authorization": f"Bearer {api_key}"},
        )

        # Get statistics
        response = client.get("/api/v1/stats")
        data = response.json()

        # Verify statistics
        assert data["total_operations"] == 3
        assert data["total_clients"] == 1
        assert data["success_rate"] < 1.0  # One failed operation

        # Verify algorithm distributions
        assert len(data["modes"]) > 0
        assert len(data["encryption_algorithms"]) > 0
        assert len(data["hash_algorithms"]) > 0
        assert len(data["kdf_algorithms"]) > 0


class TestKeyRefreshEndpoint:
    """Test API key refresh endpoint."""

    def test_successful_key_refresh(self, test_db):
        """Test successful API key refresh."""
        # Register client
        reg_response = client.post(
            "/api/v1/register",
            json={
                "client_id": "refresh_test_client",
                "platform": "linux",
                "client_version": "1.4.0",
            },
        )
        old_api_key = reg_response.json()["api_key"]

        # Refresh key
        response = client.post(
            "/api/v1/key/refresh", headers={"Authorization": f"Bearer {old_api_key}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "api_key" in data
        assert data["api_key"] != old_api_key  # New key
        assert "expires" in data

    def test_refresh_with_invalid_key(self, test_db):
        """Test refresh with invalid key."""
        response = client.post(
            "/api/v1/key/refresh", headers={"Authorization": "Bearer invalid_key"}
        )
        assert response.status_code == 401


class TestRateLimiting:
    """Test rate limiting functionality."""

    def test_rate_limit_enforcement(self, test_db):
        """Test rate limiting prevents excessive requests."""
        # Register client
        reg_response = client.post(
            "/api/v1/register",
            json={
                "client_id": "rate_limit_test_client",
                "platform": "linux",
                "client_version": "1.4.0",
            },
        )
        api_key = reg_response.json()["api_key"]

        # Get database session to manipulate rate limit
        db = next(override_get_db())

        # Find API key in database
        db_key = (
            db.query(APIKey).filter(APIKey.api_key_hash == KeyService.hash_api_key(api_key)).first()
        )

        # Set requests to maximum
        from app.config import settings

        db_key.requests_today = settings.rate_limit_events_per_day
        db.commit()

        # Try to upload
        events = [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operation": "encrypt",
                "mode": "symmetric",
                "format_version": 8,
                "hash_algorithms": ["sha512"],
                "kdf_algorithms": ["argon2"],
                "encryption_algorithm": "aes-256-gcm",
                "success": True,
            }
        ]

        response = client.post(
            "/api/v1/telemetry",
            json={"events": events},
            headers={"Authorization": f"Bearer {api_key}"},
        )

        assert response.status_code == 429  # Too many requests
        assert "Rate limit exceeded" in response.json()["detail"]


class TestDatabaseIntegration:
    """Test database operations."""

    def test_telemetry_raw_storage(self, test_db):
        """Test telemetry events are stored correctly in database."""
        # Register and upload
        reg_response = client.post(
            "/api/v1/register",
            json={
                "client_id": "db_test_client",
                "platform": "linux",
                "client_version": "1.4.0",
            },
        )
        api_key = reg_response.json()["api_key"]

        events = [
            {
                "timestamp": "2025-12-30T12:00:00Z",
                "operation": "encrypt",
                "mode": "symmetric",
                "format_version": 8,
                "hash_algorithms": ["sha512", "blake2b"],
                "kdf_algorithms": ["argon2", "scrypt"],
                "encryption_algorithm": "aes-256-gcm",
                "success": True,
            }
        ]

        client.post(
            "/api/v1/telemetry",
            json={"events": events},
            headers={"Authorization": f"Bearer {api_key}"},
        )

        # Query database directly
        db = next(override_get_db())
        stored_events = db.query(TelemetryRaw).all()

        assert len(stored_events) == 1
        event = stored_events[0]
        assert event.operation == "encrypt"
        assert event.encryption_algorithm == "aes-256-gcm"
        assert json.loads(event.hash_algorithms) == ["sha512", "blake2b"]
        assert json.loads(event.kdf_algorithms) == ["argon2", "scrypt"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
