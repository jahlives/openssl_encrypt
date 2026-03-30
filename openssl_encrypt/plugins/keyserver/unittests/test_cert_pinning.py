#!/usr/bin/env python3
"""
Unit tests for certificate pinning in keyserver plugin.

Tests the CertPinningAdapter to ensure certificate validation works correctly.
"""

import hashlib
import ssl
from unittest.mock import MagicMock, Mock, patch

import pytest

from openssl_encrypt.plugins.keyserver.keyserver_plugin import \
    CertPinningAdapter


class TestCertPinningAdapter:
    """Tests for certificate pinning adapter"""

    def test_adapter_initialization_with_fingerprints(self):
        """Adapter should store normalized fingerprints"""
        fingerprints = [
            "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
            "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00",
        ]

        adapter = CertPinningAdapter(fingerprints)

        # Should normalize (lowercase, remove colons)
        assert len(adapter.expected_fingerprints) == 2
        assert (
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
            in adapter.expected_fingerprints
        )
        assert (
            "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
            in adapter.expected_fingerprints
        )

    def test_adapter_initialization_empty_list(self):
        """Adapter should handle empty fingerprint list"""
        adapter = CertPinningAdapter([])
        assert adapter.expected_fingerprints == []

    def test_init_poolmanager_sets_ssl_verification(self):
        """Pool manager should enforce SSL verification"""
        adapter = CertPinningAdapter(["aabbccdd"])

        # Mock the parent init_poolmanager and capture kwargs
        captured_kwargs = {}

        def capture_init(*args, **kwargs):
            captured_kwargs.update(kwargs)
            return None

        with patch.object(
            adapter.__class__.__bases__[0], "init_poolmanager", side_effect=capture_init
        ):
            adapter.init_poolmanager(connections=10)

            # Should set SSL verification parameters
            assert captured_kwargs.get("assert_hostname") == True
            assert captured_kwargs.get("cert_reqs") == ssl.CERT_REQUIRED

    def test_cert_verify_no_fingerprints_configured(self):
        """Should skip pinning if no fingerprints configured"""
        adapter = CertPinningAdapter([])

        # Mock connection
        conn = Mock()
        conn.sock = None

        # Should not raise (no fingerprints = no pinning)
        with patch.object(adapter.__class__.__bases__[0], "cert_verify"):
            adapter.cert_verify(conn, "https://example.com", True, None)

    def test_cert_verify_valid_fingerprint(self):
        """Should pass if certificate fingerprint matches"""
        # Create a mock certificate
        cert_der = b"mock_certificate_data"
        expected_fingerprint = hashlib.sha256(cert_der).hexdigest()

        adapter = CertPinningAdapter([expected_fingerprint])

        # Mock connection with certificate
        conn = Mock()
        sock = Mock()
        sock.getpeercert.return_value = cert_der
        conn.sock = sock

        # Mock parent cert_verify
        with patch.object(adapter.__class__.__bases__[0], "cert_verify"):
            # Should not raise
            adapter.cert_verify(conn, "https://example.com", True, None)

    def test_cert_verify_invalid_fingerprint(self):
        """Should raise SSLError if fingerprint doesn't match"""
        # Create a mock certificate
        cert_der = b"mock_certificate_data"
        actual_fingerprint = hashlib.sha256(cert_der).hexdigest()

        # Use a different fingerprint
        wrong_fingerprint = "00" * 32
        adapter = CertPinningAdapter([wrong_fingerprint])

        # Mock connection with certificate
        conn = Mock()
        sock = Mock()
        sock.getpeercert.return_value = cert_der
        conn.sock = sock

        # Mock parent cert_verify
        with patch.object(adapter.__class__.__bases__[0], "cert_verify"):
            with pytest.raises(ssl.SSLError) as exc_info:
                adapter.cert_verify(conn, "https://example.com", True, None)

            assert "Certificate pinning failed" in str(exc_info.value)
            assert actual_fingerprint in str(exc_info.value)

    def test_cert_verify_no_socket_connection(self):
        """Should raise SSLError if no socket available"""
        adapter = CertPinningAdapter(["aabbccdd"])

        # Mock connection without socket
        conn = Mock()
        conn.sock = None

        with patch.object(adapter.__class__.__bases__[0], "cert_verify"):
            with pytest.raises(ssl.SSLError) as exc_info:
                adapter.cert_verify(conn, "https://example.com", True, None)

            assert "No socket connection" in str(exc_info.value)

    def test_cert_verify_no_peer_certificate(self):
        """Should raise SSLError if no peer certificate available"""
        adapter = CertPinningAdapter(["aabbccdd"])

        # Mock connection with socket but no certificate
        conn = Mock()
        sock = Mock()
        sock.getpeercert.return_value = None
        conn.sock = sock

        with patch.object(adapter.__class__.__bases__[0], "cert_verify"):
            with pytest.raises(ssl.SSLError) as exc_info:
                adapter.cert_verify(conn, "https://example.com", True, None)

            assert "Could not retrieve peer certificate" in str(exc_info.value)

    def test_cert_verify_multiple_valid_fingerprints(self):
        """Should pass if certificate matches any configured fingerprint"""
        cert_der = b"mock_certificate_data"
        actual_fingerprint = hashlib.sha256(cert_der).hexdigest()

        # Configure multiple fingerprints, one matches
        fingerprints = [
            "00" * 32,
            actual_fingerprint,
            "ff" * 32,
        ]  # Wrong  # Correct  # Wrong
        adapter = CertPinningAdapter(fingerprints)

        # Mock connection with certificate
        conn = Mock()
        sock = Mock()
        sock.getpeercert.return_value = cert_der
        conn.sock = sock

        # Mock parent cert_verify
        with patch.object(adapter.__class__.__bases__[0], "cert_verify"):
            # Should not raise
            adapter.cert_verify(conn, "https://example.com", True, None)

    def test_cert_verify_exception_during_validation(self):
        """Should convert exceptions to SSLError"""
        adapter = CertPinningAdapter(["aabbccdd"])

        # Mock connection that raises exception
        conn = Mock()
        sock = Mock()
        sock.getpeercert.side_effect = RuntimeError("Connection error")
        conn.sock = sock

        with patch.object(adapter.__class__.__bases__[0], "cert_verify"):
            with pytest.raises(ssl.SSLError) as exc_info:
                adapter.cert_verify(conn, "https://example.com", True, None)

            assert "Certificate pinning validation failed" in str(exc_info.value)


class TestKeyserverPluginWithPinning:
    """Integration tests for keyserver plugin with cert pinning enabled"""

    def test_plugin_creates_session_with_pinning_enabled(self):
        """Plugin should mount pinning adapter when enabled"""
        from openssl_encrypt.plugins.keyserver.config import KeyserverConfig
        from openssl_encrypt.plugins.keyserver.keyserver_plugin import \
            KeyserverPlugin

        config = KeyserverConfig(
            enabled=True,
            enable_cert_pinning=True,
            cert_fingerprints=["aa" * 32, "bb" * 32],
        )

        plugin = KeyserverPlugin(config)

        # Should have session created
        assert plugin.session is not None

        # Session should have HTTPS adapter mounted
        assert "https://" in plugin.session.adapters

    def test_plugin_creates_session_without_pinning(self):
        """Plugin should create normal session when pinning disabled"""
        from openssl_encrypt.plugins.keyserver.config import KeyserverConfig
        from openssl_encrypt.plugins.keyserver.keyserver_plugin import \
            KeyserverPlugin

        config = KeyserverConfig(
            enabled=True, enable_cert_pinning=False, cert_fingerprints=None
        )

        plugin = KeyserverPlugin(config)

        # Should have session created
        assert plugin.session is not None

    def test_plugin_uses_session_for_requests(self):
        """Plugin should use session for all HTTP requests"""
        from openssl_encrypt.plugins.keyserver.config import KeyserverConfig
        from openssl_encrypt.plugins.keyserver.keyserver_plugin import \
            KeyserverPlugin

        config = KeyserverConfig(enabled=True, servers=["https://test.example.com"])

        plugin = KeyserverPlugin(config)

        # Mock the session
        plugin.session = Mock()
        plugin.session.get = Mock(return_value=Mock(status_code=404))

        # Try to fetch a key
        result = plugin.fetch_key("test@example.com")

        # Should have used session
        assert plugin.session.get.called
        assert result is None  # 404 = not found
