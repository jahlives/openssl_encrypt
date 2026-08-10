#!/usr/bin/env python3
"""
Unit tests for KeyserverPlugin.search_keys() and updated fetch_key() (TDD red phase).

Tests:
1. search_keys() method — returns list of PublicKeyBundle, queries /search endpoint
2. fetch_key() — uses /{fingerprint} endpoint for fingerprint identifiers,
   uses /search for name/email identifiers

Fingerprint pattern: ^[0-9a-f]{2}(:[0-9a-f]{2})+$ (lowercase hex pairs joined by colons)
"""

import re
from unittest.mock import MagicMock, call, patch

import pytest
import requests

from openssl_encrypt.plugins.keyserver.keyserver_plugin import (
    KeyserverPlugin,
    NetworkError,
)
from openssl_encrypt.plugins.keyserver.config import KeyserverConfig

# ---------------------------------------------------------------------------
# Shared fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def plugin(tmp_path):
    """KeyserverPlugin with mocked session."""
    config = KeyserverConfig(
        enabled=True,
        servers=["https://keyserver.example.com"],
        cache_path=tmp_path / "cache.db",
    )
    p = KeyserverPlugin(config)
    p.session = MagicMock()
    return p


@pytest.fixture
def disabled_plugin(tmp_path):
    """KeyserverPlugin that is disabled."""
    config = KeyserverConfig(
        enabled=False,
        servers=["https://keyserver.example.com"],
        cache_path=tmp_path / "cache.db",
    )
    p = KeyserverPlugin(config)
    p.session = MagicMock()
    return p


@pytest.fixture
def two_server_plugin(tmp_path):
    """KeyserverPlugin with two configured servers."""
    config = KeyserverConfig(
        enabled=True,
        servers=[
            "https://server1.example.com",
            "https://server2.example.com",
        ],
        cache_path=tmp_path / "cache.db",
    )
    p = KeyserverPlugin(config)
    p.session = MagicMock()
    return p


def _make_response(status_code, json_data=None):
    """Build a mock requests.Response."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = str(json_data)
    return resp


def _make_bundle_dict(fingerprint="aa:bb:cc:dd", name="Alice", email=None):
    """Build a minimal key bundle dict matching the server response format."""
    return {
        "name": name,
        "email": email,
        "fingerprint": fingerprint,
        "created_at": "2026-01-01T00:00:00+00:00",
        "encryption_public_key": "dGVzdA==",
        "signing_public_key": "dGVzdA==",
        "encryption_algorithm": "ML-KEM-768",
        "signing_algorithm": "ML-DSA-65",
        "self_signature": "dGVzdA==",
    }


def _make_verified_bundle(fingerprint="aa:bb:cc:dd", name="Alice"):
    """Build a MagicMock PublicKeyBundle that passes verify_signature."""
    bundle = MagicMock()
    bundle.fingerprint = fingerprint
    bundle.name = name
    bundle.verify_signature.return_value = True
    return bundle


# ---------------------------------------------------------------------------
# TestSearchKeysMethod
# ---------------------------------------------------------------------------


class TestSearchKeysMethod:
    """Tests for KeyserverPlugin.search_keys(query)."""

    def test_method_exists(self):
        """search_keys method exists on KeyserverPlugin."""
        assert hasattr(KeyserverPlugin, "search_keys")

    def test_method_is_callable(self):
        """search_keys is callable."""
        assert callable(KeyserverPlugin.search_keys)

    def test_calls_get_search_endpoint(self, plugin):
        """search_keys calls GET /api/v1/keys/search?q=<query>."""
        bundle_dict = _make_bundle_dict()
        plugin.session.get.return_value = _make_response(
            200,
            {
                "keys": [bundle_dict],
                "count": 1,
            },
        )

        with patch(
            "openssl_encrypt.plugins.keyserver.keyserver_plugin.PublicKeyBundle"
        ) as MockBundle:
            mock_b = _make_verified_bundle()
            MockBundle.from_dict.return_value = mock_b
            plugin.search_keys("Alice")

        plugin.session.get.assert_called_once()
        call_args = plugin.session.get.call_args
        url = call_args[0][0]
        assert "/api/v1/keys/search" in url

    def test_sends_query_as_q_param(self, plugin):
        """search_keys sends the query string as the `q` query parameter."""
        plugin.session.get.return_value = _make_response(200, {"keys": [], "count": 0})

        plugin.search_keys("alice@example.com")

        call_args = plugin.session.get.call_args
        params = call_args[1].get("params") or (call_args[0][1] if len(call_args[0]) > 1 else {})
        assert params.get("q") == "alice@example.com"

    def test_returns_list_of_public_key_bundles(self, plugin):
        """search_keys returns a list of PublicKeyBundle objects."""
        bundle_dict = _make_bundle_dict()
        plugin.session.get.return_value = _make_response(
            200,
            {
                "keys": [bundle_dict],
                "count": 1,
            },
        )

        from openssl_encrypt.modules.key_bundle import PublicKeyBundle

        with patch.object(PublicKeyBundle, "from_dict") as mock_from_dict:
            mock_bundle = _make_verified_bundle()
            mock_from_dict.return_value = mock_bundle
            result = plugin.search_keys("Alice")

        assert isinstance(result, list)
        assert len(result) == 1

    def test_returns_empty_list_if_plugin_disabled(self, disabled_plugin):
        """search_keys returns [] immediately when plugin is disabled."""
        result = disabled_plugin.search_keys("Alice")

        assert result == []
        disabled_plugin.session.get.assert_not_called()

    def test_returns_empty_list_on_404(self, plugin):
        """search_keys returns [] when server responds with 404."""
        plugin.session.get.return_value = _make_response(404, {"detail": "Key not found"})

        result = plugin.search_keys("nobody@example.com")

        assert result == []

    def test_returns_empty_list_on_network_error(self, plugin):
        """search_keys returns [] when a network error occurs."""
        plugin.session.get.side_effect = requests.exceptions.ConnectionError("refused")

        result = plugin.search_keys("Alice")

        assert result == []

    def test_returns_empty_list_on_timeout(self, plugin):
        """search_keys returns [] when request times out."""
        plugin.session.get.side_effect = requests.exceptions.Timeout("timed out")

        result = plugin.search_keys("Alice")

        assert result == []

    def test_verifies_each_bundle_before_returning(self, plugin):
        """search_keys calls verify_signature() on each bundle."""
        bundle_dict = _make_bundle_dict()
        plugin.session.get.return_value = _make_response(
            200,
            {
                "keys": [bundle_dict],
                "count": 1,
            },
        )

        from openssl_encrypt.modules.key_bundle import PublicKeyBundle

        mock_bundle = _make_verified_bundle()
        with patch.object(PublicKeyBundle, "from_dict", return_value=mock_bundle):
            plugin.search_keys("Alice")

        mock_bundle.verify_signature.assert_called_once()

    def test_excludes_unverified_bundles(self, plugin):
        """Bundles that fail verify_signature() are not included in the result."""
        bundle_dict1 = _make_bundle_dict(fingerprint="aa:bb:cc", name="Alice")
        bundle_dict2 = _make_bundle_dict(fingerprint="dd:ee:ff", name="Bob")
        plugin.session.get.return_value = _make_response(
            200,
            {
                "keys": [bundle_dict1, bundle_dict2],
                "count": 2,
            },
        )

        from openssl_encrypt.modules.key_bundle import PublicKeyBundle

        good_bundle = MagicMock()
        good_bundle.fingerprint = "aa:bb:cc"
        good_bundle.verify_signature.return_value = True

        bad_bundle = MagicMock()
        bad_bundle.fingerprint = "dd:ee:ff"
        bad_bundle.verify_signature.return_value = False

        with patch.object(PublicKeyBundle, "from_dict", side_effect=[good_bundle, bad_bundle]):
            result = plugin.search_keys("Alice")

        assert len(result) == 1
        assert result[0] is good_bundle

    def test_queries_multiple_servers_and_merges_results(self, two_server_plugin):
        """search_keys queries all configured servers and merges results."""
        bundle1 = _make_bundle_dict(fingerprint="aa:bb:cc", name="Alice")
        bundle2 = _make_bundle_dict(fingerprint="dd:ee:ff", name="Alice B")

        server1_response = _make_response(200, {"keys": [bundle1], "count": 1})
        server2_response = _make_response(200, {"keys": [bundle2], "count": 1})
        two_server_plugin.session.get.side_effect = [server1_response, server2_response]

        from openssl_encrypt.modules.key_bundle import PublicKeyBundle

        mock_b1 = _make_verified_bundle("aa:bb:cc", "Alice")
        mock_b2 = _make_verified_bundle("dd:ee:ff", "Alice B")

        with patch.object(PublicKeyBundle, "from_dict", side_effect=[mock_b1, mock_b2]):
            result = two_server_plugin.search_keys("Alice")

        assert two_server_plugin.session.get.call_count == 2
        assert len(result) == 2

    def test_deduplicates_by_fingerprint_across_servers(self, two_server_plugin):
        """If the same fingerprint appears on multiple servers, it is included only once."""
        same_bundle = _make_bundle_dict(fingerprint="aa:bb:cc", name="Alice")

        server1_response = _make_response(200, {"keys": [same_bundle], "count": 1})
        server2_response = _make_response(200, {"keys": [same_bundle], "count": 1})
        two_server_plugin.session.get.side_effect = [server1_response, server2_response]

        from openssl_encrypt.modules.key_bundle import PublicKeyBundle

        mock_b1 = _make_verified_bundle("aa:bb:cc", "Alice")
        mock_b2 = _make_verified_bundle("aa:bb:cc", "Alice")

        with patch.object(PublicKeyBundle, "from_dict", side_effect=[mock_b1, mock_b2]):
            result = two_server_plugin.search_keys("Alice")

        # Same fingerprint from two servers → only one entry
        fingerprints = [b.fingerprint for b in result]
        assert fingerprints.count("aa:bb:cc") == 1

    def test_does_not_cache_results(self, plugin):
        """search_keys does NOT cache results (caching is for single-bundle fetch_key only)."""
        bundle_dict = _make_bundle_dict()
        plugin.session.get.return_value = _make_response(
            200,
            {
                "keys": [bundle_dict],
                "count": 1,
            },
        )

        from openssl_encrypt.modules.key_bundle import PublicKeyBundle

        mock_bundle = _make_verified_bundle()
        with patch.object(PublicKeyBundle, "from_dict", return_value=mock_bundle):
            plugin.search_keys("Alice")

        # Cache.put should not have been called
        with patch.object(plugin.cache, "put") as mock_put:
            plugin.search_keys("Alice")

        # Calling again should still hit the network (not cache)
        assert plugin.session.get.call_count >= 2

    def test_second_call_still_hits_network(self, plugin):
        """A second search_keys() call goes to the network, not a cache."""
        bundle_dict = _make_bundle_dict()
        resp = _make_response(200, {"keys": [bundle_dict], "count": 1})
        plugin.session.get.return_value = resp

        from openssl_encrypt.modules.key_bundle import PublicKeyBundle

        mock_bundle = _make_verified_bundle()
        with patch.object(PublicKeyBundle, "from_dict", return_value=mock_bundle):
            plugin.search_keys("Alice")
            plugin.search_keys("Alice")

        assert plugin.session.get.call_count == 2

    def test_returns_empty_list_when_keys_field_missing(self, plugin):
        """Returns [] gracefully when server response is missing `keys` field."""
        plugin.session.get.return_value = _make_response(200, {"message": "ok"})

        result = plugin.search_keys("Alice")

        assert result == []

    def test_returns_empty_list_when_count_is_zero(self, plugin):
        """Returns [] when server returns count=0 with empty keys list."""
        plugin.session.get.return_value = _make_response(200, {"keys": [], "count": 0})

        result = plugin.search_keys("Alice")

        assert result == []


# ---------------------------------------------------------------------------
# TestFetchKeyUsesFingerprint
# ---------------------------------------------------------------------------


class TestFetchKeyUsesFingerprint:
    """fetch_key() uses /{fingerprint} endpoint when query matches fingerprint pattern."""

    # Fingerprint pattern: lowercase hex pairs separated by colons, at least two pairs.
    # e.g. "3a:4b" matches, "3a:4b:5c:6d:7e:8f" matches
    # "alice@example.com" does NOT match, "Alice" does NOT match

    VALID_FINGERPRINTS = [
        "aa:bb",
        "3a:4b:5c",
        "3a:4b:5c:6d:7e:8f:90:ab",
        "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff",
    ]

    NON_FINGERPRINT_IDENTIFIERS = [
        "alice@example.com",
        "Alice",
        "Bob Smith",
        "AA:BB:CC",  # uppercase — not fingerprint pattern
        "aabb",  # no colons
        "aa:bb:cc:",  # trailing colon
        ":aa:bb",  # leading colon
        "aa:bbb:cc",  # non-pair (3 hex chars in middle)
    ]

    def test_fetch_key_uses_fingerprint_endpoint_for_fingerprint_query(self, plugin):
        """fetch_key() calls GET /api/v1/keys/{fingerprint} for fingerprint identifiers."""
        fp = "3a:4b:5c:6d"
        bundle_dict = _make_bundle_dict(fingerprint=fp)
        plugin.session.get.return_value = _make_response(200, {"key": bundle_dict})

        from openssl_encrypt.modules.key_bundle import PublicKeyBundle

        mock_bundle = _make_verified_bundle(fingerprint=fp)
        with patch.object(PublicKeyBundle, "from_dict", return_value=mock_bundle):
            plugin.fetch_key(fp)

        call_url = plugin.session.get.call_args[0][0]
        expected_path = f"/api/v1/keys/{fp}"
        assert (
            expected_path in call_url
        ), f"Expected URL containing '{expected_path}', got '{call_url}'"

    def test_fetch_key_does_not_use_search_for_fingerprint(self, plugin):
        """fetch_key() does NOT call /search when the identifier is a fingerprint."""
        fp = "aa:bb:cc:dd"
        bundle_dict = _make_bundle_dict(fingerprint=fp)
        plugin.session.get.return_value = _make_response(200, {"key": bundle_dict})

        from openssl_encrypt.modules.key_bundle import PublicKeyBundle

        mock_bundle = _make_verified_bundle(fingerprint=fp)
        with patch.object(PublicKeyBundle, "from_dict", return_value=mock_bundle):
            plugin.fetch_key(fp)

        call_url = plugin.session.get.call_args[0][0]
        assert "/search" not in call_url

    def test_fetch_key_uses_search_for_email(self, plugin):
        """fetch_key() calls GET /api/v1/keys/search for an email identifier."""
        email = "alice@example.com"
        bundle_dict = _make_bundle_dict()
        # Old-style single response or new list response — search_key returns either
        plugin.session.get.return_value = _make_response(200, {"key": bundle_dict})

        from openssl_encrypt.modules.key_bundle import PublicKeyBundle

        mock_bundle = _make_verified_bundle()
        with patch.object(PublicKeyBundle, "from_dict", return_value=mock_bundle):
            plugin.fetch_key(email)

        call_url = plugin.session.get.call_args[0][0]
        assert "/search" in call_url or "search" in call_url

    def test_fetch_key_uses_search_for_name(self, plugin):
        """fetch_key() calls GET /api/v1/keys/search for a plain name identifier."""
        bundle_dict = _make_bundle_dict()
        plugin.session.get.return_value = _make_response(200, {"key": bundle_dict})

        from openssl_encrypt.modules.key_bundle import PublicKeyBundle

        mock_bundle = _make_verified_bundle()
        with patch.object(PublicKeyBundle, "from_dict", return_value=mock_bundle):
            plugin.fetch_key("Alice")

        call_url = plugin.session.get.call_args[0][0]
        assert "/search" in call_url

    @pytest.mark.parametrize("fp", VALID_FINGERPRINTS)
    def test_fingerprint_pattern_matches_valid_fingerprints(self, fp):
        """The fingerprint regex matches all valid fingerprint strings."""
        pattern = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2})+$")
        assert pattern.match(fp), f"Expected '{fp}' to match fingerprint pattern"

    @pytest.mark.parametrize("identifier", NON_FINGERPRINT_IDENTIFIERS)
    def test_fingerprint_pattern_does_not_match_non_fingerprints(self, identifier):
        """The fingerprint regex does NOT match non-fingerprint identifiers."""
        pattern = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2})+$")
        assert not pattern.match(
            identifier
        ), f"Expected '{identifier}' to NOT match fingerprint pattern"

    def test_fetch_key_returns_bundle_for_fingerprint(self, plugin):
        """fetch_key() returns a PublicKeyBundle when fingerprint lookup succeeds."""
        fp = "aa:bb:cc:dd"
        bundle_dict = _make_bundle_dict(fingerprint=fp)
        plugin.session.get.return_value = _make_response(200, {"key": bundle_dict})

        from openssl_encrypt.modules.key_bundle import PublicKeyBundle

        mock_bundle = _make_verified_bundle(fingerprint=fp)
        with patch.object(PublicKeyBundle, "from_dict", return_value=mock_bundle):
            result = plugin.fetch_key(fp)

        assert result is mock_bundle

    def test_fetch_key_returns_none_on_fingerprint_404(self, plugin):
        """fetch_key() returns None when fingerprint endpoint returns 404."""
        fp = "aa:bb:cc:dd"
        plugin.session.get.return_value = _make_response(404, {"detail": "Key not found"})

        result = plugin.fetch_key(fp)

        assert result is None

    def test_fetch_key_caches_result_from_fingerprint_endpoint(self, plugin):
        """fetch_key() still caches the result when using the fingerprint endpoint."""
        fp = "aa:bb:cc:dd"
        bundle_dict = _make_bundle_dict(fingerprint=fp)
        plugin.session.get.return_value = _make_response(200, {"key": bundle_dict})

        from openssl_encrypt.modules.key_bundle import PublicKeyBundle

        mock_bundle = _make_verified_bundle(fingerprint=fp)
        with patch.object(PublicKeyBundle, "from_dict", return_value=mock_bundle):
            with patch.object(plugin.cache, "put") as mock_put:
                plugin.fetch_key(fp)

        mock_put.assert_called_once_with(mock_bundle)

    def test_fetch_key_checks_cache_before_fingerprint_endpoint(self, plugin):
        """fetch_key() checks the cache first, even for fingerprint identifiers."""
        fp = "aa:bb:cc:dd"
        cached_bundle = _make_verified_bundle(fingerprint=fp)

        with patch.object(plugin.cache, "get", return_value=cached_bundle):
            result = plugin.fetch_key(fp)

        # Network should not be called
        plugin.session.get.assert_not_called()
        assert result is cached_bundle

    def test_fetch_key_uses_search_for_uppercase_fingerprint_like_string(self, plugin):
        """fetch_key() uses /search (not /{fingerprint}) for uppercase hex pairs."""
        # "AA:BB:CC" is not a valid fingerprint pattern (requires lowercase)
        bundle_dict = _make_bundle_dict()
        plugin.session.get.return_value = _make_response(200, {"key": bundle_dict})

        from openssl_encrypt.modules.key_bundle import PublicKeyBundle

        mock_bundle = _make_verified_bundle()
        with patch.object(PublicKeyBundle, "from_dict", return_value=mock_bundle):
            plugin.fetch_key("AA:BB:CC")

        call_url = plugin.session.get.call_args[0][0]
        assert "/search" in call_url
        assert "/api/v1/keys/AA:BB:CC" not in call_url
