#!/usr/bin/env python3
"""
Tests for HSM Plugin System

These tests validate the HSM plugin infrastructure and mock Yubikey operations.
Actual Yubikey testing requires physical hardware.
"""

import hashlib
import hmac
import os
import secrets
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

try:
    from openssl_encrypt.modules.plugin_system import (
        HSMPlugin,
        PluginCapability,
        PluginResult,
        PluginSecurityContext,
        PluginType,
    )
except ImportError:
    pytest.skip("Plugin system not available", allow_module_level=True)


class MockYubikeyHSMPlugin(HSMPlugin):
    """Mock Yubikey plugin for testing without hardware."""

    def __init__(self):
        super().__init__(plugin_id="mock_yubikey", name="Mock Yubikey HSM", version="1.0.0")

    def get_required_capabilities(self):
        return {PluginCapability.ACCESS_CONFIG}

    def get_description(self):
        return "Mock Yubikey for testing"

    def get_hsm_pepper(self, salt, context):
        """Simulate Yubikey Challenge-Response with HMAC."""
        # Use a fixed key for testing
        test_key = b"test_yubikey_secret_key_0123456789"
        pepper = hmac.new(test_key, salt, hashlib.sha1).digest()

        return PluginResult.success_result(
            "Mock Challenge-Response successful", data={"hsm_pepper": pepper, "slot": 1}
        )


class TestHSMPluginBase:
    """Test HSM plugin base class."""

    def test_hsm_plugin_type(self):
        """Test that HSM plugin reports correct type."""
        plugin = MockYubikeyHSMPlugin()
        assert plugin.get_plugin_type() == PluginType.HSM

    def test_hsm_pepper_derivation(self):
        """Test basic HSM pepper derivation."""
        plugin = MockYubikeyHSMPlugin()
        salt = secrets.token_bytes(16)

        context = PluginSecurityContext(
            plugin_id=plugin.plugin_id, capabilities={PluginCapability.ACCESS_CONFIG}
        )
        context.metadata["salt"] = salt

        result = plugin.get_hsm_pepper(salt, context)

        assert result.success
        assert "hsm_pepper" in result.data
        assert len(result.data["hsm_pepper"]) == 20  # HMAC-SHA1 = 20 bytes

    def test_hsm_pepper_deterministic(self):
        """Test that same salt produces same pepper."""
        plugin = MockYubikeyHSMPlugin()
        salt = secrets.token_bytes(16)

        context = PluginSecurityContext(
            plugin_id=plugin.plugin_id, capabilities={PluginCapability.ACCESS_CONFIG}
        )

        # Derive pepper twice with same salt
        result1 = plugin.get_hsm_pepper(salt, context)
        result2 = plugin.get_hsm_pepper(salt, context)

        assert result1.success and result2.success
        assert result1.data["hsm_pepper"] == result2.data["hsm_pepper"]

    def test_hsm_pepper_different_salts(self):
        """Test that different salts produce different peppers."""
        plugin = MockYubikeyHSMPlugin()
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)

        context = PluginSecurityContext(
            plugin_id=plugin.plugin_id, capabilities={PluginCapability.ACCESS_CONFIG}
        )

        result1 = plugin.get_hsm_pepper(salt1, context)
        result2 = plugin.get_hsm_pepper(salt2, context)

        assert result1.success and result2.success
        assert result1.data["hsm_pepper"] != result2.data["hsm_pepper"]

    def test_execute_method(self):
        """Test the execute() method that wraps get_hsm_pepper()."""
        plugin = MockYubikeyHSMPlugin()
        salt = secrets.token_bytes(16)

        context = PluginSecurityContext(
            plugin_id=plugin.plugin_id, capabilities={PluginCapability.ACCESS_CONFIG}
        )
        context.metadata["salt"] = salt

        result = plugin.execute(context)

        assert result.success
        assert "hsm_pepper" in result.data

    def test_execute_without_salt(self):
        """Test that execute() fails gracefully without salt."""
        plugin = MockYubikeyHSMPlugin()

        context = PluginSecurityContext(
            plugin_id=plugin.plugin_id, capabilities={PluginCapability.ACCESS_CONFIG}
        )
        # No salt in metadata

        result = plugin.execute(context)

        assert not result.success
        assert "No salt provided" in result.message


class TestHSMEncryptionIntegration:
    """Test HSM integration with encryption/decryption."""

    def test_hsm_pepper_length(self):
        """Test HSM pepper has reasonable length."""
        plugin = MockYubikeyHSMPlugin()
        salt = secrets.token_bytes(16)

        context = PluginSecurityContext(
            plugin_id=plugin.plugin_id, capabilities={PluginCapability.ACCESS_CONFIG}
        )

        result = plugin.get_hsm_pepper(salt, context)

        assert result.success
        pepper = result.data["hsm_pepper"]
        # HMAC-SHA1 produces 20 bytes
        assert len(pepper) == 20
        # Pepper should be bytes
        assert isinstance(pepper, bytes)

    def test_plugin_metadata(self):
        """Test plugin metadata is correct."""
        plugin = MockYubikeyHSMPlugin()

        assert plugin.plugin_id == "mock_yubikey"
        assert plugin.name == "Mock Yubikey HSM"
        assert plugin.version == "1.0.0"
        assert PluginCapability.ACCESS_CONFIG in plugin.get_required_capabilities()


class TestPluginManager:
    """Test plugin manager HSM methods."""

    def test_plugin_manager_hsm_methods_exist(self):
        """Test that plugin manager has HSM-specific methods."""
        try:
            from openssl_encrypt.modules.plugin_system import PluginManager

            manager = PluginManager()

            # Check methods exist
            assert hasattr(manager, "get_hsm_plugin")
            assert hasattr(manager, "execute_hsm_plugin")

        except ImportError:
            pytest.skip("PluginManager not available")


# Integration test requiring actual Yubikey (skip by default)
@pytest.mark.skip(reason="Requires physical Yubikey hardware")
class TestRealYubikey:
    """Integration tests with real Yubikey hardware."""

    def test_yubikey_challenge_response_auto_detect(self):
        """Test actual Yubikey Challenge-Response with auto-detection."""
        try:
            from openssl_encrypt.plugins.hsm.yubikey_challenge_response import YubikeyHSMPlugin
        except ImportError:
            pytest.skip("Yubikey plugin not available")

        plugin = YubikeyHSMPlugin()
        salt = secrets.token_bytes(16)

        context = PluginSecurityContext(
            plugin_id=plugin.plugin_id, capabilities={PluginCapability.ACCESS_CONFIG}
        )

        result = plugin.get_hsm_pepper(salt, context)

        # This will fail if no Yubikey is connected or no Challenge-Response configured
        assert result.success, f"Auto-detect failed: {result.message}"
        assert "hsm_pepper" in result.data
        print(f"\n✅ Auto-detect successful, used slot {result.data.get('slot')}")

    def test_yubikey_challenge_response_slot2(self):
        """Test actual Yubikey Challenge-Response with explicit slot 2."""
        try:
            from openssl_encrypt.plugins.hsm.yubikey_challenge_response import YubikeyHSMPlugin
        except ImportError:
            pytest.skip("Yubikey plugin not available")

        plugin = YubikeyHSMPlugin()
        salt = secrets.token_bytes(16)

        context = PluginSecurityContext(
            plugin_id=plugin.plugin_id, capabilities={PluginCapability.ACCESS_CONFIG}
        )
        context.config["slot"] = 2  # Explicitly use slot 2

        result = plugin.get_hsm_pepper(salt, context)

        assert result.success
        assert "hsm_pepper" in result.data
        assert result.data.get("slot") == 2
        assert len(result.data["hsm_pepper"]) == 20  # HMAC-SHA1 = 20 bytes
        print(f"\n✅ Slot 2 test successful, pepper length: {len(result.data['hsm_pepper'])} bytes")

    def test_yubikey_deterministic_pepper(self):
        """Test that same salt produces same pepper on real Yubikey."""
        try:
            from openssl_encrypt.plugins.hsm.yubikey_challenge_response import YubikeyHSMPlugin
        except ImportError:
            pytest.skip("Yubikey plugin not available")

        plugin = YubikeyHSMPlugin()
        salt = secrets.token_bytes(16)

        context = PluginSecurityContext(
            plugin_id=plugin.plugin_id, capabilities={PluginCapability.ACCESS_CONFIG}
        )
        context.config["slot"] = 2

        # Get pepper twice with same salt
        result1 = plugin.get_hsm_pepper(salt, context)
        result2 = plugin.get_hsm_pepper(salt, context)

        assert result1.success and result2.success
        assert result1.data["hsm_pepper"] == result2.data["hsm_pepper"]
        print(f"\n✅ Deterministic test passed: same salt → same pepper")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
