#!/usr/bin/env python3
"""
Integration tests for telemetry plugin components.

Tests the interaction between:
- TelemetryDataFilter
- LocalBuffer
- APIKeyManager
- TelemetryUploader
- OpenSSLEncryptTelemetryPlugin
"""

import json
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

# Import telemetry components
from openssl_encrypt.modules.telemetry_filter import TelemetryDataFilter, TelemetryEvent
from openssl_encrypt.plugins.telemetry.api_key_manager import APIKeyManager
from openssl_encrypt.plugins.telemetry.local_buffer import LocalBuffer
from openssl_encrypt.plugins.telemetry.telemetry_plugin import (
    OpenSSLEncryptTelemetryPlugin,
    TelemetryPluginConfig,
)
from openssl_encrypt.plugins.telemetry.uploader import TelemetryUploader


class TestLocalBufferIntegration:
    """Test LocalBuffer with real SQLite database."""

    def test_buffer_stores_and_retrieves_events(self, tmp_path):
        """Test storing and retrieving events from buffer."""
        # Create buffer
        buffer_path = tmp_path / "test_buffer.db"
        buffer = LocalBuffer(buffer_path, max_buffer_size=100)

        # Create test event
        event = TelemetryEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            operation="encrypt",
            mode="symmetric",
            format_version=8,
            hash_algorithms=("sha512", "blake2b"),
            kdf_algorithms=("argon2",),
            encryption_algorithm="aes-256-gcm",
        )

        # Add event
        buffer.add(event)

        # Verify count
        assert buffer.get_pending_count() == 1

        # Retrieve events
        batch = buffer.get_batch(batch_size=10)
        assert len(batch) == 1

        event_id, event_dict = batch[0]
        assert event_dict["operation"] == "encrypt"
        assert event_dict["encryption_algorithm"] == "aes-256-gcm"
        assert "sha512" in event_dict["hash_algorithms"]

    def test_buffer_fifo_cleanup(self, tmp_path):
        """Test FIFO cleanup when buffer is full."""
        buffer_path = tmp_path / "test_buffer.db"
        buffer = LocalBuffer(buffer_path, max_buffer_size=10)

        # Add 15 events (more than max)
        for i in range(15):
            event = TelemetryEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation="encrypt",
                mode="symmetric",
                format_version=8,
                hash_algorithms=("sha512",),
                kdf_algorithms=("argon2",),
                encryption_algorithm=f"test-algo-{i}",
            )
            buffer.add(event)

        # Should have removed oldest events
        count = buffer.get_pending_count()
        assert count <= 10

    def test_buffer_mark_uploaded(self, tmp_path):
        """Test marking events as uploaded."""
        buffer_path = tmp_path / "test_buffer.db"
        buffer = LocalBuffer(buffer_path)

        # Add events
        for i in range(5):
            event = TelemetryEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation="encrypt",
                mode="symmetric",
                format_version=8,
                hash_algorithms=("sha512",),
                kdf_algorithms=("argon2",),
                encryption_algorithm="aes-256-gcm",
            )
            buffer.add(event)

        # Get batch
        batch = buffer.get_batch(batch_size=3)
        event_ids = [event_id for event_id, _ in batch]

        # Mark as uploaded
        buffer.mark_uploaded(event_ids)

        # Remaining should be 2
        assert buffer.get_pending_count() == 2

    def test_buffer_export_pending(self, tmp_path):
        """Test exporting pending events for user inspection."""
        buffer_path = tmp_path / "test_buffer.db"
        buffer = LocalBuffer(buffer_path)

        # Add event with cascade
        event = TelemetryEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            operation="encrypt",
            mode="symmetric",
            format_version=8,
            hash_algorithms=("sha512", "blake2b"),
            kdf_algorithms=("argon2", "scrypt"),
            encryption_algorithm="cascade",
            cascade_enabled=True,
            cascade_cipher_count=3,
        )
        buffer.add(event)

        # Export
        exported = buffer.export_pending(limit=10)
        assert len(exported) == 1
        assert exported[0]["cascade_enabled"] is True
        assert exported[0]["cascade_cipher_count"] == 3


class TestAPIKeyManagerIntegration:
    """Test APIKeyManager with real file I/O."""

    def test_key_manager_generates_random_client_id(self, tmp_path):
        """Test that client IDs are truly random."""
        config = Mock()
        config.server_url = "https://test.example.com"
        config.buffer_path = tmp_path / "buffer.db"

        manager = APIKeyManager(config)

        # Generate multiple client IDs
        ids = [manager._generate_client_id() for _ in range(100)]

        # All should be unique
        assert len(set(ids)) == 100

        # All should be 32 characters (16 bytes hex)
        assert all(len(id) == 32 for id in ids)

    def test_key_manager_saves_and_loads_key(self, tmp_path):
        """Test saving and loading API key data."""
        config = Mock()
        config.server_url = "https://test.example.com"
        config.buffer_path = tmp_path / "buffer.db"

        manager = APIKeyManager(config)

        # Save key data
        test_data = {
            "client_id": "test_client_123",
            "api_key": "sk_test_key",
            "expires": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        }

        manager._save_key_data(test_data)

        # Load key data
        loaded = manager._load_key_data()
        assert loaded["client_id"] == "test_client_123"
        assert loaded["api_key"] == "sk_test_key"

    def test_key_manager_file_permissions(self, tmp_path):
        """Test that key file has secure permissions (0600)."""
        config = Mock()
        config.server_url = "https://test.example.com"
        config.buffer_path = tmp_path / "buffer.db"

        manager = APIKeyManager(config)

        # Save key data
        test_data = {
            "client_id": "test_client",
            "api_key": "sk_test",
            "expires": datetime.now(timezone.utc).isoformat(),
        }

        manager._save_key_data(test_data)

        # Check permissions (should be 0600 = owner read/write only)
        import stat

        file_stat = os.stat(manager.key_file)
        permissions = stat.S_IMODE(file_stat.st_mode)
        assert permissions == 0o600

    def test_key_manager_expiry_check(self, tmp_path):
        """Test key expiration detection."""
        config = Mock()
        config.server_url = "https://test.example.com"
        config.buffer_path = tmp_path / "buffer.db"

        manager = APIKeyManager(config)

        # Test expired key
        expired_date = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        assert manager._is_key_expired(expired_date) is True

        # Test valid key
        valid_date = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        assert manager._is_key_expired(valid_date) is False


class TestTelemetryUploaderIntegration:
    """Test TelemetryUploader with mocked HTTP requests."""

    @patch("openssl_encrypt.plugins.telemetry.uploader.requests.post")
    def test_uploader_successful_batch_upload(self, mock_post, tmp_path):
        """Test successful batch upload."""
        # Setup
        config = Mock()
        config.server_url = "https://test.example.com"
        config.batch_size = 100
        config.buffer_path = tmp_path / "buffer.db"

        key_manager = Mock()
        key_manager.get_api_key.return_value = "sk_test_key"

        uploader = TelemetryUploader(config, key_manager)

        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"received": 2, "processed": 2}
        mock_post.return_value = mock_response

        # Upload events
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
            },
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operation": "decrypt",
                "mode": "symmetric",
                "format_version": 8,
                "hash_algorithms": ["blake2b"],
                "kdf_algorithms": ["scrypt"],
                "encryption_algorithm": "chacha20-poly1305",
                "success": True,
            },
        ]

        result = uploader.upload_batch(events)

        # Verify
        assert result is not None
        assert result["received"] == 2
        assert result["processed"] == 2

        # Verify request was made with correct headers
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"] == "Bearer sk_test_key"
        assert call_kwargs["verify"] is True  # TLS verification

    @patch("openssl_encrypt.plugins.telemetry.uploader.requests.post")
    def test_uploader_rate_limit_handling(self, mock_post, tmp_path):
        """Test rate limit response handling."""
        config = Mock()
        config.server_url = "https://test.example.com"
        config.batch_size = 100
        config.buffer_path = tmp_path / "buffer.db"

        key_manager = Mock()
        key_manager.get_api_key.return_value = "sk_test_key"

        uploader = TelemetryUploader(config, key_manager)

        # Mock rate limit response (429)
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "60"}
        mock_post.return_value = mock_response

        # Upload should return None (failed)
        result = uploader.upload_batch([{"test": "event"}])
        assert result is None

    @patch("openssl_encrypt.plugins.telemetry.uploader.requests.post")
    def test_uploader_retry_on_server_error(self, mock_post, tmp_path):
        """Test retry logic on server error."""
        config = Mock()
        config.server_url = "https://test.example.com"
        config.batch_size = 100
        config.buffer_path = tmp_path / "buffer.db"

        key_manager = Mock()
        key_manager.get_api_key.return_value = "sk_test_key"

        uploader = TelemetryUploader(config, key_manager)

        # Mock server error (500) followed by success
        error_response = Mock()
        error_response.status_code = 500

        success_response = Mock()
        success_response.status_code = 200
        success_response.json.return_value = {"received": 1, "processed": 1}

        mock_post.side_effect = [error_response, success_response]

        # Upload should retry and succeed
        result = uploader.upload_batch([{"test": "event"}])
        assert result is not None
        assert result["received"] == 1


class TestTelemetryPluginIntegration:
    """Test complete telemetry plugin integration."""

    def test_plugin_initialization(self, tmp_path):
        """Test plugin initializes all components correctly."""
        config = TelemetryPluginConfig(
            server_url="https://test.example.com",
            buffer_path=tmp_path / "buffer.db",
            max_buffer_size=100,
            batch_size=50,
            upload_interval=3600,
        )

        plugin = OpenSSLEncryptTelemetryPlugin(config)

        # Verify components initialized
        assert plugin.key_manager is not None
        assert plugin.buffer is not None
        assert plugin.uploader is not None
        assert plugin._upload_thread is not None
        assert plugin._upload_thread.is_alive()

        # Cleanup
        plugin.stop()

    def test_plugin_receives_and_buffers_event(self, tmp_path):
        """Test plugin receives event and buffers it."""
        config = TelemetryPluginConfig(
            server_url="https://test.example.com",
            buffer_path=tmp_path / "buffer.db",
            max_buffer_size=100,
            batch_size=50,
            upload_interval=3600,
        )

        plugin = OpenSSLEncryptTelemetryPlugin(config)

        # Create event
        event = TelemetryEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            operation="encrypt",
            mode="symmetric",
            format_version=8,
            hash_algorithms=("sha512",),
            kdf_algorithms=("argon2",),
            encryption_algorithm="aes-256-gcm",
        )

        # Send event to plugin
        plugin.on_telemetry_event(event)

        # Verify buffered
        status = plugin.get_status()
        assert status["pending_events"] == 1

        # Cleanup
        plugin.stop()

    def test_plugin_get_pending_events_transparency(self, tmp_path):
        """Test user can inspect pending events."""
        config = TelemetryPluginConfig(
            server_url="https://test.example.com",
            buffer_path=tmp_path / "buffer.db",
            max_buffer_size=100,
            batch_size=50,
            upload_interval=3600,
        )

        plugin = OpenSSLEncryptTelemetryPlugin(config)

        # Add events
        for i in range(3):
            event = TelemetryEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation="encrypt",
                mode="symmetric",
                format_version=8,
                hash_algorithms=("sha512",),
                kdf_algorithms=("argon2",),
                encryption_algorithm=f"test-algo-{i}",
            )
            plugin.on_telemetry_event(event)

        # Get pending events
        pending = plugin.get_pending_events(limit=10)
        assert len(pending) == 3

        # Verify event structure
        for event_dict in pending:
            assert "timestamp" in event_dict
            assert "operation" in event_dict
            assert "encryption_algorithm" in event_dict
            assert "hash_algorithms" in event_dict

        # Cleanup
        plugin.stop()

    def test_plugin_opt_out_deletes_all_data(self, tmp_path):
        """Test opt-out completely removes all data."""
        config = TelemetryPluginConfig(
            server_url="https://test.example.com",
            buffer_path=tmp_path / "buffer.db",
            max_buffer_size=100,
            batch_size=50,
            upload_interval=3600,
        )

        plugin = OpenSSLEncryptTelemetryPlugin(config)

        # Add events
        for i in range(5):
            event = TelemetryEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                operation="encrypt",
                mode="symmetric",
                format_version=8,
                hash_algorithms=("sha512",),
                kdf_algorithms=("argon2",),
                encryption_algorithm="aes-256-gcm",
            )
            plugin.on_telemetry_event(event)

        # Verify events exist
        assert plugin.buffer.get_pending_count() == 5

        # Opt out
        result = plugin.opt_out()
        assert result.success is True

        # Verify all data deleted
        assert plugin.buffer.get_pending_count() == 0

        # Verify background thread stopped
        assert not plugin._upload_thread.is_alive()


class TestEndToEndTelemetryFlow:
    """Test complete telemetry flow from event creation to buffering."""

    def test_complete_flow_with_filter_and_plugin(self, tmp_path):
        """Test complete flow: metadata -> filter -> plugin -> buffer."""
        # Setup plugin
        config = TelemetryPluginConfig(
            server_url="https://test.example.com",
            buffer_path=tmp_path / "buffer.db",
            max_buffer_size=100,
            batch_size=50,
            upload_interval=3600,
        )

        plugin = OpenSSLEncryptTelemetryPlugin(config)

        # Create metadata (simulating encryption operation)
        metadata = {
            "format_version": 8,
            "mode": "symmetric",
            "derivation_config": {
                "salt": "dGVzdHNhbHQ=",  # Base64 encoded
                "hash_config": {
                    "sha512": {"rounds": 10000},
                    "blake2b": {"rounds": 5000},
                },
                "kdf_config": {
                    "argon2": {
                        "time_cost": 3,
                        "memory_cost": 65536,
                        "parallelism": 4,
                    }
                },
            },
            "encryption": {
                "algorithm": "aes-256-gcm",
                "cascade": False,
            },
            "hashes": {
                "original_hash": "hash1",
                "encrypted_hash": "hash2",
            },
        }

        # Filter metadata (simulating core emission)
        filtered_event = TelemetryDataFilter.filter_metadata(
            metadata=metadata, operation="encrypt", success=True
        )

        # Verify filtering worked
        assert filtered_event.operation == "encrypt"
        assert filtered_event.encryption_algorithm == "aes-256-gcm"
        assert "sha512" in filtered_event.hash_algorithms
        assert "argon2" in filtered_event.kdf_algorithms

        # Verify sensitive data NOT in event
        event_dict = TelemetryDataFilter.to_dict(filtered_event)
        event_str = json.dumps(event_dict)
        assert "dGVzdHNhbHQ=" not in event_str  # Salt not exposed
        assert "hash1" not in event_str  # Hashes not exposed
        assert "hash2" not in event_str

        # Send to plugin
        plugin.on_telemetry_event(filtered_event)

        # Verify buffered
        assert plugin.buffer.get_pending_count() == 1

        # Retrieve and verify
        pending = plugin.get_pending_events(limit=1)
        assert len(pending) == 1
        assert pending[0]["encryption_algorithm"] == "aes-256-gcm"
        assert "sha512" in pending[0]["hash_algorithms"]

        # Cleanup
        plugin.stop()

    def test_cascade_encryption_flow(self, tmp_path):
        """Test telemetry for cascade encryption (format v8)."""
        config = TelemetryPluginConfig(
            server_url="https://test.example.com",
            buffer_path=tmp_path / "buffer.db",
        )

        plugin = OpenSSLEncryptTelemetryPlugin(config)

        # Cascade metadata
        metadata = {
            "format_version": 8,
            "mode": "symmetric",
            "derivation_config": {
                "salt": "dGVzdA==",
                "hash_config": {"sha512": {"rounds": 10000}},
                "kdf_config": {"argon2": {"time_cost": 3, "memory_cost": 65536}},
            },
            "encryption": {
                "cascade": True,
                "cipher_chain": ["aes-256-gcm", "chacha20-poly1305", "xchacha20-poly1305"],
                "hkdf_hash": "sha256",
            },
            "hashes": {},
        }

        # Filter
        filtered_event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")

        # Verify cascade handling
        assert filtered_event.cascade_enabled is True
        assert filtered_event.cascade_cipher_count == 3
        assert filtered_event.encryption_algorithm == "cascade"  # Generic

        # Verify exact cipher sequence NOT exposed
        event_dict = TelemetryDataFilter.to_dict(filtered_event)
        event_str = json.dumps(event_dict)
        assert "cipher_chain" not in event_str
        assert "aes-256-gcm" not in event_str  # Exact ciphers hidden

        # Send to plugin
        plugin.on_telemetry_event(filtered_event)

        # Verify
        pending = plugin.get_pending_events(limit=1)
        assert pending[0]["cascade_enabled"] is True
        assert pending[0]["cascade_cipher_count"] == 3

        plugin.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
