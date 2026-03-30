#!/usr/bin/env python3
"""
End-to-end integration tests for complete telemetry system.

Tests the full flow from client plugin to server and back.
"""

import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import requests_mock

from openssl_encrypt.modules.telemetry_filter import TelemetryDataFilter
from openssl_encrypt.plugins.telemetry.telemetry_plugin import (
    OpenSSLEncryptTelemetryPlugin, TelemetryPluginConfig)


class TestEndToEndFlow:
    """Test complete client-to-server telemetry flow."""

    def test_registration_and_upload_flow(self, tmp_path):
        """Test complete flow: registration -> event generation -> upload."""
        # Setup plugin
        config = TelemetryPluginConfig(
            server_url="https://test-telemetry.example.com",
            buffer_path=tmp_path / "buffer.db",
            upload_interval=3600,
        )

        with requests_mock.Mocker() as m:
            # Mock registration endpoint
            m.post(
                "https://test-telemetry.example.com/api/v1/register",
                json={
                    "api_key": "sk_test_registration_key_12345",
                    "expires": "2026-12-30T00:00:00Z",
                },
                status_code=200,
            )

            # Mock telemetry upload endpoint
            m.post(
                "https://test-telemetry.example.com/api/v1/telemetry",
                json={"received": 3, "processed": 3},
                status_code=200,
            )

            plugin = OpenSSLEncryptTelemetryPlugin(config)

            # Simulate encryption operations generating telemetry
            for i in range(3):
                metadata = {
                    "format_version": 8,
                    "mode": "symmetric",
                    "derivation_config": {
                        "salt": "dGVzdA==",
                        "hash_config": {"sha512": {"rounds": 10000}},
                        "kdf_config": {
                            "argon2": {"time_cost": 3, "memory_cost": 65536}
                        },
                    },
                    "encryption": {"algorithm": "aes-256-gcm"},
                    "hashes": {},
                }

                # Filter metadata (as core would)
                event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")

                # Send to plugin
                plugin.on_telemetry_event(event)

            # Verify buffered
            assert plugin.buffer.get_pending_count() == 3

            # Trigger upload
            result = plugin.flush()

            # Verify upload succeeded
            assert result.success is True
            assert "3 events" in result.message

            # Verify no pending events left
            assert plugin.buffer.get_pending_count() == 0

            plugin.stop()

    def test_retry_on_server_error(self, tmp_path):
        """Test retry logic when server returns error."""
        config = TelemetryPluginConfig(
            server_url="https://test-telemetry.example.com",
            buffer_path=tmp_path / "buffer.db",
        )

        with requests_mock.Mocker() as m:
            # Mock registration
            m.post(
                "https://test-telemetry.example.com/api/v1/register",
                json={"api_key": "sk_test_key", "expires": "2026-12-30T00:00:00Z"},
            )

            # Mock server error then success
            m.post(
                "https://test-telemetry.example.com/api/v1/telemetry",
                [
                    {"status_code": 500},  # First attempt fails
                    {
                        "json": {"received": 1, "processed": 1},
                        "status_code": 200,
                    },  # Second succeeds
                ],
            )

            plugin = OpenSSLEncryptTelemetryPlugin(config)

            # Add event
            metadata = {
                "format_version": 8,
                "mode": "symmetric",
                "derivation_config": {
                    "salt": "test",
                    "hash_config": {"sha512": {"rounds": 10000}},
                    "kdf_config": {"argon2": {"time_cost": 3, "memory_cost": 65536}},
                },
                "encryption": {"algorithm": "aes-256-gcm"},
                "hashes": {},
            }

            event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
            plugin.on_telemetry_event(event)

            # Flush (should retry and succeed)
            result = plugin.flush()
            assert result.success is True

            plugin.stop()

    def test_rate_limit_response_handling(self, tmp_path):
        """Test handling of rate limit response."""
        config = TelemetryPluginConfig(
            server_url="https://test-telemetry.example.com",
            buffer_path=tmp_path / "buffer.db",
        )

        with requests_mock.Mocker() as m:
            # Mock registration
            m.post(
                "https://test-telemetry.example.com/api/v1/register",
                json={"api_key": "sk_test_key", "expires": "2026-12-30T00:00:00Z"},
            )

            # Mock rate limit response
            m.post(
                "https://test-telemetry.example.com/api/v1/telemetry",
                status_code=429,
                headers={"Retry-After": "3600"},
            )

            plugin = OpenSSLEncryptTelemetryPlugin(config)

            # Add event
            metadata = {
                "format_version": 8,
                "mode": "symmetric",
                "derivation_config": {
                    "salt": "test",
                    "hash_config": {"sha512": {"rounds": 10000}},
                    "kdf_config": {"argon2": {"time_cost": 3, "memory_cost": 65536}},
                },
                "encryption": {"algorithm": "aes-256-gcm"},
                "hashes": {},
            }

            event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
            plugin.on_telemetry_event(event)

            # Flush (should fail due to rate limit)
            result = plugin.flush()
            assert result.success is False

            # Event should still be in buffer for retry
            assert plugin.buffer.get_pending_count() == 1

            plugin.stop()

    def test_offline_operation(self, tmp_path):
        """Test telemetry works offline (buffers locally)."""
        config = TelemetryPluginConfig(
            server_url="https://unreachable-server.example.com",
            buffer_path=tmp_path / "buffer.db",
        )

        with requests_mock.Mocker() as m:
            # Mock all requests to fail (simulating offline)
            m.post(requests_mock.ANY, exc=requests_mock.exceptions.ConnectTimeout)

            plugin = OpenSSLEncryptTelemetryPlugin(config)

            # Add events (should succeed even when offline)
            for i in range(5):
                metadata = {
                    "format_version": 8,
                    "mode": "symmetric",
                    "derivation_config": {
                        "salt": "test",
                        "hash_config": {"sha512": {"rounds": 10000}},
                        "kdf_config": {
                            "argon2": {"time_cost": 3, "memory_cost": 65536}
                        },
                    },
                    "encryption": {"algorithm": f"test-algo-{i}"},
                    "hashes": {},
                }

                event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
                plugin.on_telemetry_event(event)

            # Events should be buffered
            assert plugin.buffer.get_pending_count() == 5

            # Flush will fail but shouldn't crash
            result = plugin.flush()
            assert result.success is False

            # Events should still be in buffer
            assert plugin.buffer.get_pending_count() == 5

            plugin.stop()

    def test_key_refresh_flow(self, tmp_path):
        """Test API key refresh when expired."""
        config = TelemetryPluginConfig(
            server_url="https://test-telemetry.example.com",
            buffer_path=tmp_path / "buffer.db",
        )

        with requests_mock.Mocker() as m:
            # Initial registration
            m.post(
                "https://test-telemetry.example.com/api/v1/register",
                json={"api_key": "sk_old_key", "expires": "2026-01-01T00:00:00Z"},
            )

            # First upload attempt fails with 401 (expired key)
            # Then refresh succeeds
            # Then second upload succeeds
            m.post(
                "https://test-telemetry.example.com/api/v1/telemetry",
                [
                    {"status_code": 401},  # Expired key
                    {
                        "json": {"received": 1, "processed": 1},
                        "status_code": 200,
                    },  # After refresh
                ],
            )

            m.post(
                "https://test-telemetry.example.com/api/v1/key/refresh",
                json={"api_key": "sk_new_key", "expires": "2027-01-01T00:00:00Z"},
            )

            plugin = OpenSSLEncryptTelemetryPlugin(config)

            # Add event
            metadata = {
                "format_version": 8,
                "mode": "symmetric",
                "derivation_config": {
                    "salt": "test",
                    "hash_config": {"sha512": {"rounds": 10000}},
                    "kdf_config": {"argon2": {"time_cost": 3, "memory_cost": 65536}},
                },
                "encryption": {"algorithm": "aes-256-gcm"},
                "hashes": {},
            }

            event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
            plugin.on_telemetry_event(event)

            # Flush (should refresh key and retry)
            result = plugin.flush()
            assert result.success is True

            plugin.stop()


class TestMultiFormatSupport:
    """Test telemetry works with all format versions."""

    @pytest.mark.parametrize("format_version", [4, 5, 6, 7, 8])
    def test_all_format_versions(self, format_version, tmp_path):
        """Test telemetry supports all format versions."""
        config = TelemetryPluginConfig(
            server_url="https://test-telemetry.example.com",
            buffer_path=tmp_path / "buffer.db",
        )

        plugin = OpenSSLEncryptTelemetryPlugin(config)

        # Create metadata for specific format version
        metadata = {
            "format_version": format_version,
            "mode": "symmetric",
            "derivation_config": {
                "salt": "test",
                "hash_config": {"sha512": {"rounds": 10000}},
                "kdf_config": {"argon2": {"time_cost": 3, "memory_cost": 65536}},
            },
            "encryption": {"algorithm": "aes-256-gcm"},
            "hashes": {},
        }

        # Filter and send
        event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
        plugin.on_telemetry_event(event)

        # Verify buffered
        assert plugin.buffer.get_pending_count() == 1

        # Verify event has correct format version
        pending = plugin.get_pending_events(limit=1)
        assert pending[0]["format_version"] == format_version

        plugin.stop()


class TestPrivacyGuarantees:
    """Test privacy guarantees in end-to-end flow."""

    def test_no_sensitive_data_in_upload(self, tmp_path):
        """Test no sensitive data reaches upload endpoint."""
        config = TelemetryPluginConfig(
            server_url="https://test-telemetry.example.com",
            buffer_path=tmp_path / "buffer.db",
        )

        # Track actual upload payload
        uploaded_payload = None

        def capture_request(request, context):
            nonlocal uploaded_payload
            uploaded_payload = request.json()
            return {"received": 1, "processed": 1}

        with requests_mock.Mocker() as m:
            m.post(
                "https://test-telemetry.example.com/api/v1/register",
                json={"api_key": "sk_test_key", "expires": "2026-12-30T00:00:00Z"},
            )

            m.post(
                "https://test-telemetry.example.com/api/v1/telemetry",
                json=capture_request,
            )

            plugin = OpenSSLEncryptTelemetryPlugin(config)

            # Create metadata with sensitive data
            metadata = {
                "format_version": 8,
                "mode": "symmetric",
                "derivation_config": {
                    "salt": "SENSITIVE_SALT_BASE64",  # SENSITIVE
                    "hash_config": {"sha512": {"rounds": 10000}},
                    "kdf_config": {"argon2": {"time_cost": 3, "memory_cost": 65536}},
                },
                "encryption": {
                    "algorithm": "aes-256-gcm",
                    "pqc_public_key": "SENSITIVE_PUBLIC_KEY",  # SENSITIVE
                    "pqc_private_key": "SENSITIVE_PRIVATE_KEY",  # SENSITIVE
                },
                "hashes": {
                    "original_hash": "SENSITIVE_HASH_1",  # SENSITIVE
                    "encrypted_hash": "SENSITIVE_HASH_2",  # SENSITIVE
                },
            }

            # Filter and send
            event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
            plugin.on_telemetry_event(event)

            # Flush
            plugin.flush()

            # Verify sensitive data NOT in payload
            import json

            payload_str = json.dumps(uploaded_payload)

            assert "SENSITIVE_SALT_BASE64" not in payload_str
            assert "SENSITIVE_PUBLIC_KEY" not in payload_str
            assert "SENSITIVE_PRIVATE_KEY" not in payload_str
            assert "SENSITIVE_HASH_1" not in payload_str
            assert "SENSITIVE_HASH_2" not in payload_str

            # Verify safe data IS in payload
            assert "sha512" in payload_str
            assert "argon2" in payload_str
            assert "aes-256-gcm" in payload_str

            plugin.stop()

    def test_cascade_cipher_sequence_hidden(self, tmp_path):
        """Test exact cascade cipher sequence is hidden in upload."""
        config = TelemetryPluginConfig(
            server_url="https://test-telemetry.example.com",
            buffer_path=tmp_path / "buffer.db",
        )

        uploaded_payload = None

        def capture_request(request, context):
            nonlocal uploaded_payload
            uploaded_payload = request.json()
            return {"received": 1, "processed": 1}

        with requests_mock.Mocker() as m:
            m.post(
                "https://test-telemetry.example.com/api/v1/register",
                json={"api_key": "sk_test_key", "expires": "2026-12-30T00:00:00Z"},
            )

            m.post(
                "https://test-telemetry.example.com/api/v1/telemetry",
                json=capture_request,
            )

            plugin = OpenSSLEncryptTelemetryPlugin(config)

            # Cascade metadata
            metadata = {
                "format_version": 8,
                "mode": "symmetric",
                "derivation_config": {
                    "salt": "test",
                    "hash_config": {"sha512": {"rounds": 10000}},
                    "kdf_config": {"argon2": {"time_cost": 3, "memory_cost": 65536}},
                },
                "encryption": {
                    "cascade": True,
                    "cipher_chain": [
                        "aes-256-gcm",
                        "chacha20-poly1305",
                        "xchacha20-poly1305",
                    ],  # SENSITIVE
                },
                "hashes": {},
            }

            event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
            plugin.on_telemetry_event(event)

            plugin.flush()

            # Verify cipher sequence NOT exposed
            import json

            payload_str = json.dumps(uploaded_payload)

            assert "cipher_chain" not in payload_str
            assert "chacha20-poly1305" not in payload_str  # Exact ciphers hidden

            # Verify generic cascade info IS present
            events = uploaded_payload["events"]
            assert events[0]["cascade_enabled"] is True
            assert events[0]["cascade_cipher_count"] == 3
            assert events[0]["encryption_algorithm"] == "cascade"

            plugin.stop()


class TestCLIIntegration:
    """Test CLI commands with real plugin."""

    def test_cli_status_command(self, tmp_path):
        """Test telemetry status CLI command."""
        config = TelemetryPluginConfig(
            server_url="https://test-telemetry.example.com",
            buffer_path=tmp_path / "buffer.db",
        )

        plugin = OpenSSLEncryptTelemetryPlugin(config)

        # Get status
        status = plugin.get_status()

        assert status["enabled"] is True
        assert status["pending_events"] == 0
        assert status["server_url"] == "https://test-telemetry.example.com"
        assert isinstance(status["upload_interval"], int)

        plugin.stop()

    def test_cli_show_pending_command(self, tmp_path):
        """Test show pending events CLI command."""
        config = TelemetryPluginConfig(
            server_url="https://test-telemetry.example.com",
            buffer_path=tmp_path / "buffer.db",
        )

        plugin = OpenSSLEncryptTelemetryPlugin(config)

        # Add events
        for i in range(3):
            metadata = {
                "format_version": 8,
                "mode": "symmetric",
                "derivation_config": {
                    "salt": "test",
                    "hash_config": {"sha512": {"rounds": 10000}},
                    "kdf_config": {"argon2": {"time_cost": 3, "memory_cost": 65536}},
                },
                "encryption": {"algorithm": f"test-algo-{i}"},
                "hashes": {},
            }

            event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
            plugin.on_telemetry_event(event)

        # Get pending
        pending = plugin.get_pending_events(limit=10)

        assert len(pending) == 3
        for event_dict in pending:
            assert "timestamp" in event_dict
            assert "encryption_algorithm" in event_dict

        plugin.stop()

    def test_cli_opt_out_command(self, tmp_path):
        """Test opt-out CLI command."""
        config = TelemetryPluginConfig(
            server_url="https://test-telemetry.example.com",
            buffer_path=tmp_path / "buffer.db",
        )

        plugin = OpenSSLEncryptTelemetryPlugin(config)

        # Add events
        for i in range(5):
            metadata = {
                "format_version": 8,
                "mode": "symmetric",
                "derivation_config": {
                    "salt": "test",
                    "hash_config": {"sha512": {"rounds": 10000}},
                    "kdf_config": {"argon2": {"time_cost": 3, "memory_cost": 65536}},
                },
                "encryption": {"algorithm": "aes-256-gcm"},
                "hashes": {},
            }

            event = TelemetryDataFilter.filter_metadata(metadata, "encrypt")
            plugin.on_telemetry_event(event)

        assert plugin.buffer.get_pending_count() == 5

        # Opt out
        result = plugin.opt_out()

        assert result.success is True
        assert plugin.buffer.get_pending_count() == 0
        assert not plugin._upload_thread.is_alive()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
