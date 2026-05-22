"""
Cross-backend determinism test for HMAC-SHA1 Challenge-Response.

The whole point of the OnlyKey plugin is that an OnlyKey loaded with the
same 20-byte HMAC-SHA1 secret as a YubiKey produces *identical* responses
for identical challenges — letting a user encrypt with one device in their
fleet and decrypt with another.

This test set proves that property holds when both plugins are loaded with
the same secret. We use RFC 2202 known-good HMAC-SHA1 test vectors so a
failure here would either be:
  - a real determinism bug in either plugin's response handling, or
  - a sign that one of the plugins is mangling bytes on the way to / from
    the underlying HMAC engine.

Per the approved plan (Q5), we use RFC 2202 vectors instead of
hypothesis-based property testing — no new heavy dev dependencies, and
the same invariant is exercised with concrete debuggable cases.

References:
- RFC 2202: Test Cases for HMAC-MD5 and HMAC-SHA-1
  https://datatracker.ietf.org/doc/html/rfc2202#section-3
"""

import hmac
import sys
import unittest
from unittest.mock import MagicMock, patch

# Stub hardware libs at import time so both plugins are importable in any env.
sys.modules.setdefault("ykman", MagicMock())
sys.modules.setdefault("ykman.device", MagicMock())
sys.modules.setdefault("ykman.hid", MagicMock())
sys.modules.setdefault("ykman.hid.base", MagicMock())
sys.modules.setdefault("ykman.hid.linux", MagicMock())
sys.modules.setdefault("hid", MagicMock())
sys.modules.setdefault("yubikit", MagicMock())
sys.modules.setdefault("yubikit.core", MagicMock())
sys.modules.setdefault("yubikit.core.otp", MagicMock())
sys.modules.setdefault("yubikit.yubiotp", MagicMock())

from openssl_encrypt.plugins.hsm.onlykey_challenge_response import (  # noqa: E402
    OnlykeyHSMPlugin,
)
from openssl_encrypt.plugins.hsm.yubikey_challenge_response import (  # noqa: E402
    YubikeyHSMPlugin,
)


# RFC 2202 Section 3 — HMAC-SHA-1 test vectors that fit the YubiKey/OnlyKey
# challenge-response constraints (20-byte secret, challenge ≤ 64 bytes).
# A YubiKey/OnlyKey CR secret is always 20 bytes, so we skip RFC 2202 test 7
# (which uses an 80-byte key) — it isn't representative of this device's API.
RFC_2202_VECTORS = [
    # (description, key, challenge, expected_hmac_sha1_hex)
    (
        "RFC 2202 test 1 — 20-byte 0x0b key, 'Hi There'",
        b"\x0b" * 20,
        b"Hi There",
        "b617318655057264e28bc0b6fb378c8ef146be00",
    ),
    (
        "RFC 2202 test 2 — 4-byte ASCII key 'Jefe' — note YubiKey CR is 20-byte",
        # Pad to 20 bytes — HMAC-SHA1 internally zero-pads anyway, but we
        # exercise the device-loaded shape.
        b"Jefe" + b"\x00" * 16,
        b"what do ya want for nothing?",
        # Recompute because the key changed (added zero padding)
        hmac.new(b"Jefe" + b"\x00" * 16, b"what do ya want for nothing?", "sha1").hexdigest(),
    ),
    (
        "RFC 2202 test 3 — 20-byte 0xaa key, 50 bytes of 0xdd",
        b"\xaa" * 20,
        b"\xdd" * 50,
        "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    ),
    (
        "RFC 2202 test 4 — 25-byte numeric key — pad to 20 by truncation",
        bytes(range(1, 21)),  # 0x01..0x14 (20 bytes — closest fit to RFC's 25)
        b"\xcd" * 50,
        hmac.new(bytes(range(1, 21)), b"\xcd" * 50, "sha1").hexdigest(),
    ),
    (
        "RFC 2202 test 5 — 20-byte 0x0c key, 'Test With Truncation'",
        b"\x0c" * 20,
        b"Test With Truncation",
        "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
    ),
    # Edge cases the plan called for explicitly
    (
        "Edge: empty challenge",
        b"\x42" * 20,
        b"",
        hmac.new(b"\x42" * 20, b"", "sha1").hexdigest(),
    ),
    (
        "Edge: challenge with embedded null bytes",
        b"\x99" * 20,
        b"\x00\x01\x00\x02\x00\x03",
        hmac.new(b"\x99" * 20, b"\x00\x01\x00\x02\x00\x03", "sha1").hexdigest(),
    ),
    (
        "Edge: full 64-byte challenge (HMAC-SHA1 block size)",
        b"\x77" * 20,
        bytes(range(64)),
        hmac.new(b"\x77" * 20, bytes(range(64)), "sha1").hexdigest(),
    ),
]


def _make_device_with_loaded_secret(secret: bytes):
    """
    Build a mock device + session pair that emulates an HMAC-SHA1
    challenge-response token loaded with `secret`.

    Both plugins call session.calculate_hmac_sha1(slot, challenge). This
    fixture makes that call return the real HMAC-SHA1(secret, challenge),
    just like a correctly-implemented YubiKey/OnlyKey would.
    """
    device = MagicMock()
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=MagicMock())
    ctx.__exit__ = MagicMock(return_value=False)
    device.open_connection.return_value = ctx

    session = MagicMock()

    def fake_calculate(slot, challenge):
        return hmac.new(secret, challenge, "sha1").digest()

    session.calculate_hmac_sha1.side_effect = fake_calculate
    return device, session


class TestCrossBackendHmacSha1Determinism(unittest.TestCase):
    """
    Both backends, loaded with the same 20-byte secret, must produce the
    same HMAC-SHA1 response for any given challenge. This is the
    invariant that justifies the existence of the OnlyKey plugin.
    """

    def _yubikey_response(self, secret: bytes, challenge: bytes, slot: int = 1) -> bytes:
        plugin = YubikeyHSMPlugin()
        device, session = _make_device_with_loaded_secret(secret)
        with patch("ykman.device.list_all_devices", return_value=[device]), patch(
            "yubikit.core.otp.OtpConnection"
        ), patch("yubikit.yubiotp.YubiOtpSession", return_value=session):
            return plugin._calculate_challenge_response(challenge, slot)

    def _onlykey_response(self, secret: bytes, challenge: bytes, slot: int = 1) -> bytes:
        plugin = OnlykeyHSMPlugin()
        device, session = _make_device_with_loaded_secret(secret)
        with patch.object(
            plugin, "_list_onlykey_devices", return_value=[device]
        ), patch("yubikit.yubiotp.YubiOtpSession", return_value=session):
            return plugin._calculate_challenge_response(challenge, slot)

    def test_rfc_2202_vectors_match_canonical_expected(self):
        """Sanity check: our mock framework produces RFC 2202 expected values."""
        for description, key, challenge, expected_hex in RFC_2202_VECTORS:
            with self.subTest(description):
                actual = self._yubikey_response(key, challenge).hex()
                self.assertEqual(
                    actual,
                    expected_hex,
                    f"YubiKey mock failed RFC 2202 vector: {description}",
                )

    def test_yubikey_and_onlykey_responses_identical(self):
        """The cross-backend determinism guarantee."""
        for description, key, challenge, _expected in RFC_2202_VECTORS:
            with self.subTest(description):
                yk = self._yubikey_response(key, challenge)
                ok = self._onlykey_response(key, challenge)
                self.assertEqual(
                    yk,
                    ok,
                    f"Cross-backend mismatch on vector: {description}\n"
                    f"  YubiKey: {yk.hex()}\n"
                    f"  OnlyKey: {ok.hex()}",
                )

    def test_responses_are_always_20_bytes(self):
        """HMAC-SHA1 always yields 20 bytes — pepper consumers depend on this."""
        for description, key, challenge, _expected in RFC_2202_VECTORS:
            with self.subTest(description):
                self.assertEqual(
                    len(self._yubikey_response(key, challenge)),
                    20,
                    f"YubiKey response wrong length for: {description}",
                )
                self.assertEqual(
                    len(self._onlykey_response(key, challenge)),
                    20,
                    f"OnlyKey response wrong length for: {description}",
                )

    def test_different_secrets_yield_different_responses(self):
        """Sanity: two devices with different secrets must NOT match."""
        challenge = b"same challenge for both"
        secret_a = b"\xaa" * 20
        secret_b = b"\xbb" * 20
        self.assertNotEqual(
            self._yubikey_response(secret_a, challenge),
            self._onlykey_response(secret_b, challenge),
        )

    def test_different_challenges_yield_different_responses_same_secret(self):
        """Sanity: same device, different challenges → different responses."""
        secret = b"\xcc" * 20
        r1 = self._onlykey_response(secret, b"challenge one")
        r2 = self._onlykey_response(secret, b"challenge two")
        self.assertNotEqual(r1, r2)


if __name__ == "__main__":
    unittest.main()
