#!/usr/bin/env python3
"""
Regression tests for the recipient password-wrap key derivation.

Background: the per-recipient AES-256-GCM wrap key was originally derived as a
bare SHA-256 of the KEM shared secret (``password_wrap.v1``). It was migrated to
HKDF-SHA256 (``password_wrap.v2``) on the 1.4.x line (commit c994fc7f) but the
fix was not forward-ported to 1.5.x, which left 1.5.x unable to decrypt 1.4.x
asymmetric recipient files. This module pins the forward-ported behavior:

- new wraps use HKDF/v2 (NOT bare SHA-256),
- existing v1 (bare SHA-256) blobs still decrypt via the legacy fallback,
- a v2 blob as written by 1.4.x decrypts here (cross-version interop).

The wrap/unwrap methods take the shared secret directly, so these tests use a
fixed 32-byte secret and do not require liboqs key generation.
"""

import hashlib
import os
import unittest

from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from openssl_encrypt.modules.asymmetric_core import PasswordWrapper

# Fixed inputs for deterministic derivation (the nonce is still random per wrap).
SHARED_SECRET = bytes(range(32))  # stand-in for a 32-byte ML-KEM shared secret
PASSWORD = b"recipient-bulk-password-32-byte!"  # 31 chars + ! = 32 bytes

_WRAP_V1_LABEL = b"openssl_encrypt.password_wrap.v1"
_WRAP_V2_INFO = b"openssl_encrypt.password_wrap.v2"


def _wrap_key_v1(shared_secret: bytes) -> bytes:
    """Legacy bare-SHA256 wrap key (pre-c994fc7f / pre-forward-port)."""
    return hashlib.sha256(_WRAP_V1_LABEL + shared_secret).digest()


def _wrap_key_v2(shared_secret: bytes) -> bytes:
    """Current HKDF-SHA256 wrap key (as 1.4.x writes)."""
    hkdf = HKDF(
        algorithm=crypto_hashes.SHA256(),
        length=32,
        salt=None,
        info=_WRAP_V2_INFO,
    )
    return hkdf.derive(shared_secret)


def _make_blob(wrap_key: bytes, password: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(wrap_key).encrypt(nonce, password, None)


class TestPasswordWrapHkdfForwardPort(unittest.TestCase):
    def setUp(self):
        try:
            self.wrapper = PasswordWrapper("ML-KEM-768", quiet=True)
        except Exception as exc:  # pragma: no cover - env without liboqs
            self.skipTest(f"PasswordWrapper unavailable (liboqs?): {exc}")

    def test_wrap_uses_hkdf_v2_not_bare_sha256(self):
        """New wraps MUST use HKDF/v2; the bare-SHA256/v1 key must NOT decrypt them."""
        blob = self.wrapper.wrap_password(PASSWORD, SHARED_SECRET)
        nonce, ciphertext = blob[:12], blob[12:]

        # Decrypts under the HKDF/v2 key ...
        self.assertEqual(
            AESGCM(_wrap_key_v2(SHARED_SECRET)).decrypt(nonce, ciphertext, None),
            PASSWORD,
        )
        # ... and NOT under the legacy bare-SHA256/v1 key (proves we left v1).
        with self.assertRaises(Exception):
            AESGCM(_wrap_key_v1(SHARED_SECRET)).decrypt(nonce, ciphertext, None)

    def test_roundtrip_v2(self):
        """wrap_password -> unwrap_password round-trips under the new derivation."""
        blob = self.wrapper.wrap_password(PASSWORD, SHARED_SECRET)
        self.assertEqual(self.wrapper.unwrap_password(blob, SHARED_SECRET), PASSWORD)

    def test_unwrap_legacy_v1_fallback(self):
        """Regression: existing v1 (bare SHA-256) blobs still decrypt via fallback."""
        blob = _make_blob(_wrap_key_v1(SHARED_SECRET), PASSWORD)
        self.assertEqual(self.wrapper.unwrap_password(blob, SHARED_SECRET), PASSWORD)

    def test_unwrap_cross_version_v2_from_1_4_x(self):
        """The fixed bug: a v2 (HKDF) blob as written by 1.4.x decrypts on 1.5.x."""
        blob = _make_blob(_wrap_key_v2(SHARED_SECRET), PASSWORD)
        self.assertEqual(self.wrapper.unwrap_password(blob, SHARED_SECRET), PASSWORD)


if __name__ == "__main__":
    unittest.main()
