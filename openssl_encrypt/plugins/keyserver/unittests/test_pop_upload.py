#!/usr/bin/env python3
"""
Unit tests for Proof of Possession (PoP) client-side upload flow.

Tests:
1. create_pop_signature() helper in key_bundle.py
2. KeyserverPlugin._request_challenge() — fetches nonce from server
3. KeyserverPlugin.upload_key() — per-server challenge+sign+upload flow

Upload flow with PoP (per server):
  For each configured server:
    1. POST /api/v1/keys/challenge  → {challenge_id, nonce}
    2. sign b"POP:" + nonce_hex.encode("ascii") + b":" + fingerprint.encode("utf-8")
    3. POST /api/v1/keys  body = bundle.to_dict() | {challenge_id, pop_signature (base64)}
"""

import base64
import inspect
from unittest.mock import MagicMock, patch

import pytest
import requests

from openssl_encrypt.plugins.keyserver.config import KeyserverConfig
from openssl_encrypt.plugins.keyserver.keyserver_plugin import (
    KeyserverPlugin,
    NetworkError,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def plugin(tmp_path):
    """KeyserverPlugin with mocked session and a saved API token."""
    config = KeyserverConfig(
        enabled=True,
        servers=["https://keyserver.example.com"],
        upload_enabled=True,
        cache_path=tmp_path / "cache.db",
        api_token_file=tmp_path / "token",
    )
    (tmp_path / "token").write_text("test_access_token")
    (tmp_path / "token").chmod(0o600)

    plugin = KeyserverPlugin(config)
    plugin.session = MagicMock()
    return plugin


@pytest.fixture
def mock_bundle():
    """Minimal PublicKeyBundle mock."""
    bundle = MagicMock()
    bundle.fingerprint = "3a:4b:5c:6d:7e:8f:90:ab"
    bundle.signing_algorithm = "ML-DSA-65"
    bundle.verify_signature.return_value = True
    bundle.to_dict.return_value = {
        "name": "Alice",
        "fingerprint": "3a:4b:5c:6d:7e:8f:90:ab",
        "signing_algorithm": "ML-DSA-65",
        "self_signature": "dGVzdA==",
    }
    return bundle


def _make_response(status_code, json_data=None):
    """Build a mock requests.Response."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = str(json_data)
    return resp


# ---------------------------------------------------------------------------
# create_pop_signature tests
# ---------------------------------------------------------------------------


class TestCreatePopSignature:
    """Tests for create_pop_signature() in key_bundle.py."""

    def test_function_is_importable(self):
        """create_pop_signature is importable from key_bundle."""
        from openssl_encrypt.modules.key_bundle import create_pop_signature

        assert callable(create_pop_signature)

    def test_canonical_message_is_pop_prefix_plus_hex_nonce_plus_fingerprint(self):
        """
        Canonical message is b"POP:" + nonce_hex.encode("ascii") + b":" + fingerprint.encode("utf-8").

        PROTOCOL CONTRACT: the nonce is encoded as its hex string representation,
        NOT as raw bytes. This must match the server exactly.
        """
        from openssl_encrypt.modules.key_bundle import create_pop_signature
        from openssl_encrypt.modules.pqc_signing import PQCSigner

        nonce_hex = "a" * 64
        fingerprint = "3a:4b:5c"
        expected_message = b"POP:" + nonce_hex.encode("ascii") + b":" + fingerprint.encode("utf-8")

        captured_messages = []

        with patch.object(
            PQCSigner,
            "sign",
            side_effect=lambda msg, key: captured_messages.append(msg) or b"sig",
        ):
            create_pop_signature(
                nonce_hex=nonce_hex,
                fingerprint=fingerprint,
                signing_algorithm="ML-DSA-65",
                private_key_bytes=b"fake_private_key",
            )

        assert len(captured_messages) == 1
        assert captured_messages[0] == expected_message

    def test_nonce_is_hex_string_not_raw_bytes(self):
        """
        The nonce in the canonical message is the hex string, not bytes.fromhex(nonce).

        Both values exist; we verify the hex-string path is taken.
        """
        from openssl_encrypt.modules.key_bundle import create_pop_signature
        from openssl_encrypt.modules.pqc_signing import PQCSigner

        nonce_hex = "deadbeef" * 8  # 64 chars
        fingerprint = "fp"

        hex_string_message = (
            b"POP:" + nonce_hex.encode("ascii") + b":" + fingerprint.encode("utf-8")
        )
        raw_bytes_message = b"POP:" + bytes.fromhex(nonce_hex) + b":" + fingerprint.encode("utf-8")

        captured_messages = []
        with patch.object(
            PQCSigner,
            "sign",
            side_effect=lambda msg, key: captured_messages.append(msg) or b"sig",
        ):
            create_pop_signature(
                nonce_hex=nonce_hex,
                fingerprint=fingerprint,
                signing_algorithm="ML-DSA-65",
                private_key_bytes=b"key",
            )

        assert captured_messages[0] == hex_string_message
        assert captured_messages[0] != raw_bytes_message

    def test_returns_signature_bytes(self):
        """Returns the bytes returned by PQCSigner.sign()."""
        from openssl_encrypt.modules.key_bundle import create_pop_signature
        from openssl_encrypt.modules.pqc_signing import PQCSigner

        fake_sig = b"\xde\xad\xbe\xef" * 8

        with patch.object(PQCSigner, "sign", return_value=fake_sig):
            result = create_pop_signature(
                nonce_hex="a" * 64,
                fingerprint="fp",
                signing_algorithm="ML-DSA-65",
                private_key_bytes=b"key",
            )

        assert result == fake_sig

    def test_uses_correct_signing_algorithm(self):
        """PQCSigner is instantiated with the provided signing_algorithm."""
        from openssl_encrypt.modules.key_bundle import create_pop_signature

        with patch("openssl_encrypt.modules.key_bundle.PQCSigner") as MockSigner:
            MockSigner.return_value.sign.return_value = b"sig"
            create_pop_signature(
                nonce_hex="a" * 64,
                fingerprint="fp",
                signing_algorithm="ML-DSA-44",
                private_key_bytes=b"key",
            )

        MockSigner.assert_called_once_with("ML-DSA-44", quiet=True)

    def test_works_for_all_three_ml_dsa_variants(self):
        """create_pop_signature works for ML-DSA-44, ML-DSA-65, and ML-DSA-87."""
        from openssl_encrypt.modules.key_bundle import create_pop_signature
        from openssl_encrypt.modules.pqc_signing import PQCSigner

        for algo in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
            with patch.object(PQCSigner, "sign", return_value=b"sig"):
                result = create_pop_signature(
                    nonce_hex="a" * 64,
                    fingerprint="fp",
                    signing_algorithm=algo,
                    private_key_bytes=b"key",
                )
            assert result == b"sig"


# ---------------------------------------------------------------------------
# _request_challenge tests
# ---------------------------------------------------------------------------


class TestRequestChallenge:
    """Tests for KeyserverPlugin._request_challenge()."""

    def test_method_exists(self):
        """_request_challenge method exists on KeyserverPlugin."""
        assert hasattr(KeyserverPlugin, "_request_challenge")

    def test_posts_to_challenge_endpoint(self, plugin):
        """POSTs to /api/v1/keys/challenge on the given server."""
        challenge_data = {
            "challenge_id": "abc-123",
            "nonce": "a" * 64,
            "expires_at": "2026-03-26T10:00:00+00:00",
        }
        plugin.session.post.return_value = _make_response(200, challenge_data)

        # Simulate _authenticated_request by having it call session.post
        with patch.object(
            plugin,
            "_authenticated_request",
            wraps=lambda method, url, **kw: plugin.session.post(url, **kw),
        ):
            _result = plugin._request_challenge("https://keyserver.example.com", "3a:4b")

        called_url = plugin.session.post.call_args[0][0]
        assert called_url == "https://keyserver.example.com/api/v1/keys/challenge"

    def test_sends_fingerprint_hint_in_body(self, plugin):
        """Sends fingerprint as JSON body when provided."""
        plugin.session.post.return_value = _make_response(
            200, {"challenge_id": "x", "nonce": "a" * 64, "expires_at": "2026-01-01"}
        )

        with patch.object(plugin, "_authenticated_request") as mock_req:
            mock_req.return_value = _make_response(
                200,
                {"challenge_id": "x", "nonce": "a" * 64, "expires_at": "2026-01-01"},
            )
            plugin._request_challenge("https://keyserver.example.com", "fp:hint")

        mock_req.assert_called_once()
        kwargs = mock_req.call_args[1]
        assert kwargs.get("json", {}).get("fingerprint") == "fp:hint"

    def test_returns_challenge_dict_on_200(self, plugin):
        """Returns the full response dict on HTTP 200."""
        data = {"challenge_id": "abc", "nonce": "b" * 64, "expires_at": "2026-01-01"}

        with patch.object(plugin, "_authenticated_request", return_value=_make_response(200, data)):
            result = plugin._request_challenge("https://keyserver.example.com")

        assert result["challenge_id"] == "abc"
        assert result["nonce"] == "b" * 64

    def test_raises_network_error_on_non_200(self, plugin):
        """Raises NetworkError for unexpected HTTP status codes."""
        with patch.object(
            plugin,
            "_authenticated_request",
            return_value=_make_response(500, {"detail": "error"}),
        ):
            with pytest.raises(NetworkError):
                plugin._request_challenge("https://keyserver.example.com")

    def test_fingerprint_hint_is_optional(self, plugin):
        """_request_challenge works without a fingerprint hint."""
        data = {"challenge_id": "abc", "nonce": "c" * 64, "expires_at": "2026-01-01"}

        with patch.object(plugin, "_authenticated_request", return_value=_make_response(200, data)):
            result = plugin._request_challenge("https://keyserver.example.com")

        assert "challenge_id" in result


# ---------------------------------------------------------------------------
# upload_key (PoP flow) tests
# ---------------------------------------------------------------------------


class TestUploadKeyWithPoP:
    """Tests for the updated KeyserverPlugin.upload_key() with per-server PoP."""

    def test_upload_key_accepts_signing_private_key_bytes(self):
        """upload_key signature now accepts signing_private_key_bytes parameter."""
        sig = inspect.signature(KeyserverPlugin.upload_key)
        assert "signing_private_key_bytes" in sig.parameters

    def test_upload_key_requests_challenge_before_upload(self, plugin, mock_bundle):
        """A challenge is requested from the server before the key upload POST."""
        challenge = {
            "challenge_id": "chal-1",
            "nonce": "a" * 64,
            "expires_at": "2026-01-01",
        }

        with patch.object(plugin, "_request_challenge", return_value=challenge) as mock_challenge:
            with patch(
                "openssl_encrypt.plugins.keyserver.keyserver_plugin.create_pop_signature",
                return_value=b"pop_sig",
            ):
                with patch.object(
                    plugin,
                    "_authenticated_request",
                    return_value=_make_response(200, {"success": True, "fingerprint": "fp"}),
                ):
                    plugin.upload_key(mock_bundle, signing_private_key_bytes=b"priv_key")

        mock_challenge.assert_called_once()

    def test_upload_key_uses_challenge_fingerprint_hint(self, plugin, mock_bundle):
        """Challenge is requested with the bundle fingerprint as hint."""
        challenge = {
            "challenge_id": "chal-1",
            "nonce": "a" * 64,
            "expires_at": "2026-01-01",
        }

        with patch.object(plugin, "_request_challenge", return_value=challenge) as mock_challenge:
            with patch(
                "openssl_encrypt.plugins.keyserver.keyserver_plugin.create_pop_signature",
                return_value=b"pop_sig",
            ):
                with patch.object(
                    plugin,
                    "_authenticated_request",
                    return_value=_make_response(200, {}),
                ):
                    plugin.upload_key(mock_bundle, signing_private_key_bytes=b"priv_key")

        # Hint should be the bundle's fingerprint
        call_args = mock_challenge.call_args
        assert mock_bundle.fingerprint in call_args[0] or mock_bundle.fingerprint in str(call_args)

    def test_upload_key_signs_with_bundle_algorithm_and_private_key(self, plugin, mock_bundle):
        """create_pop_signature is called with bundle's algorithm and the provided private key."""
        challenge = {
            "challenge_id": "chal-1",
            "nonce": "ff" * 32,
            "expires_at": "2026-01-01",
        }

        with patch.object(plugin, "_request_challenge", return_value=challenge):
            with patch(
                "openssl_encrypt.plugins.keyserver.keyserver_plugin.create_pop_signature",
                return_value=b"pop_sig",
            ) as mock_sign:
                with patch.object(
                    plugin,
                    "_authenticated_request",
                    return_value=_make_response(200, {}),
                ):
                    plugin.upload_key(mock_bundle, signing_private_key_bytes=b"my_priv_key")

        mock_sign.assert_called_once()
        call_kwargs = mock_sign.call_args[1] if mock_sign.call_args[1] else {}
        call_args = mock_sign.call_args[0] if mock_sign.call_args[0] else ()
        all_args = list(call_args) + list(call_kwargs.values())

        assert b"my_priv_key" in all_args or "my_priv_key" in str(mock_sign.call_args)
        assert "ff" * 32 in str(mock_sign.call_args)  # nonce passed through
        assert "ML-DSA-65" in str(mock_sign.call_args)  # algorithm from bundle

    def test_upload_body_includes_challenge_id_and_pop_signature(self, plugin, mock_bundle):
        """The upload POST body contains challenge_id and base64-encoded pop_signature."""
        challenge = {
            "challenge_id": "chal-uuid-123",
            "nonce": "a" * 64,
            "expires_at": "2026-01-01",
        }
        pop_sig_bytes = b"\xde\xad\xbe\xef"

        with patch.object(plugin, "_request_challenge", return_value=challenge):
            with patch(
                "openssl_encrypt.plugins.keyserver.keyserver_plugin.create_pop_signature",
                return_value=pop_sig_bytes,
            ):
                with patch.object(
                    plugin,
                    "_authenticated_request",
                    return_value=_make_response(200, {}),
                ) as mock_req:
                    plugin.upload_key(mock_bundle, signing_private_key_bytes=b"key")

        upload_call = mock_req.call_args
        body = upload_call[1].get("json") or (upload_call[0][2] if len(upload_call[0]) > 2 else {})

        assert body.get("challenge_id") == "chal-uuid-123"
        assert body.get("pop_signature") == base64.b64encode(pop_sig_bytes).decode("ascii")

    def test_pop_signature_is_base64_encoded_in_body(self, plugin, mock_bundle):
        """pop_signature in request body is base64-encoded string, not raw bytes."""
        challenge = {
            "challenge_id": "chal-1",
            "nonce": "a" * 64,
            "expires_at": "2026-01-01",
        }
        raw_sig = b"\x00\xff\xde\xad"

        with patch.object(plugin, "_request_challenge", return_value=challenge):
            with patch(
                "openssl_encrypt.plugins.keyserver.keyserver_plugin.create_pop_signature",
                return_value=raw_sig,
            ):
                with patch.object(
                    plugin,
                    "_authenticated_request",
                    return_value=_make_response(200, {}),
                ) as mock_req:
                    plugin.upload_key(mock_bundle, signing_private_key_bytes=b"key")

        body = mock_req.call_args[1]["json"]
        assert isinstance(body["pop_signature"], str)
        assert base64.b64decode(body["pop_signature"]) == raw_sig

    def test_upload_key_returns_true_on_success(self, plugin, mock_bundle):
        """Returns True when server responds 200."""
        challenge = {
            "challenge_id": "c1",
            "nonce": "a" * 64,
            "expires_at": "2026-01-01",
        }

        with patch.object(plugin, "_request_challenge", return_value=challenge):
            with patch(
                "openssl_encrypt.plugins.keyserver.keyserver_plugin.create_pop_signature",
                return_value=b"sig",
            ):
                with patch.object(
                    plugin,
                    "_authenticated_request",
                    return_value=_make_response(200, {}),
                ):
                    result = plugin.upload_key(mock_bundle, signing_private_key_bytes=b"key")

        assert result is True

    def test_upload_key_returns_false_when_challenge_fails(self, plugin, mock_bundle):
        """Returns False (does not raise) when challenge request fails on all servers."""
        with patch.object(plugin, "_request_challenge", side_effect=NetworkError("timeout")):
            result = plugin.upload_key(mock_bundle, signing_private_key_bytes=b"key")

        assert result is False

    def test_upload_key_returns_false_on_upload_400(self, plugin, mock_bundle):
        """Returns False on 400 from server (bad PoP, bad bundle, etc.)."""
        challenge = {
            "challenge_id": "c1",
            "nonce": "a" * 64,
            "expires_at": "2026-01-01",
        }

        with patch.object(plugin, "_request_challenge", return_value=challenge):
            with patch(
                "openssl_encrypt.plugins.keyserver.keyserver_plugin.create_pop_signature",
                return_value=b"sig",
            ):
                with patch.object(
                    plugin,
                    "_authenticated_request",
                    return_value=_make_response(400, {"detail": "PoP failed"}),
                ):
                    result = plugin.upload_key(mock_bundle, signing_private_key_bytes=b"key")

        assert result is False

    def test_upload_key_handles_409_key_already_exists(self, plugin, mock_bundle):
        """409 (key already exists) is treated as non-fatal — returns False with warning."""
        challenge = {
            "challenge_id": "c1",
            "nonce": "a" * 64,
            "expires_at": "2026-01-01",
        }

        with patch.object(plugin, "_request_challenge", return_value=challenge):
            with patch(
                "openssl_encrypt.plugins.keyserver.keyserver_plugin.create_pop_signature",
                return_value=b"sig",
            ):
                with patch.object(
                    plugin,
                    "_authenticated_request",
                    return_value=_make_response(409, {}),
                ):
                    result = plugin.upload_key(mock_bundle, signing_private_key_bytes=b"key")

        # 409 is a valid pre-existing state, not a crash
        assert result is False

    def test_upload_key_per_server_fresh_challenge(self, plugin, mock_bundle):
        """A fresh challenge is requested for each server (nonces are per-server)."""
        plugin.config.servers = [
            "https://server1.example.com",
            "https://server2.example.com",
        ]

        challenge = {
            "challenge_id": "c1",
            "nonce": "a" * 64,
            "expires_at": "2026-01-01",
        }

        with patch.object(plugin, "_request_challenge", return_value=challenge) as mock_challenge:
            with patch(
                "openssl_encrypt.plugins.keyserver.keyserver_plugin.create_pop_signature",
                return_value=b"sig",
            ):
                with patch.object(
                    plugin,
                    "_authenticated_request",
                    return_value=_make_response(200, {}),
                ):
                    plugin.upload_key(mock_bundle, signing_private_key_bytes=b"key")

        # Called once per server
        assert mock_challenge.call_count == 2

    def test_upload_key_verifies_bundle_signature_before_upload(self, plugin, mock_bundle):
        """Bundle signature is verified locally before attempting upload."""
        mock_bundle.verify_signature.return_value = False

        result = plugin.upload_key(mock_bundle, signing_private_key_bytes=b"key")

        assert result is False
        mock_bundle.verify_signature.assert_called_once()

    def test_upload_key_disabled_returns_false(self, tmp_path):
        """Returns False immediately when plugin is disabled."""
        config = KeyserverConfig(
            enabled=False,
            servers=["https://keyserver.example.com"],
            cache_path=tmp_path / "cache.db",
        )
        plugin = KeyserverPlugin(config)

        bundle = MagicMock()
        result = plugin.upload_key(bundle, signing_private_key_bytes=b"key")

        assert result is False

    def test_upload_disabled_in_config_returns_false(self, tmp_path):
        """Returns False when upload_enabled=False in config."""
        config = KeyserverConfig(
            enabled=True,
            upload_enabled=False,
            servers=["https://keyserver.example.com"],
            cache_path=tmp_path / "cache.db",
        )
        plugin = KeyserverPlugin(config)

        bundle = MagicMock()
        result = plugin.upload_key(bundle, signing_private_key_bytes=b"key")

        assert result is False
