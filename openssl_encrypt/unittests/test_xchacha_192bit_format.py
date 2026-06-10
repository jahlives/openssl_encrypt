#!/usr/bin/env python3
"""
End-to-end tests for the real 192-bit XChaCha20-Poly1305 file format.

New-format files carry ``encryption.xchacha_nonce_format: 2`` in their
metadata and use the full 24-byte nonce via HChaCha20 subkey derivation.
Legacy files (no flag) keep decrypting through the historical
first-12-bytes code path; the committed corpus in testfiles/v12 is the
backward-compatibility regression suite.
"""

import base64
import json
import unittest
from pathlib import Path
from unittest import mock

from openssl_encrypt.modules import xchacha
from openssl_encrypt.modules.crypt_core import decrypt_file, encrypt_file
from openssl_encrypt.modules.crypt_errors import (
    AuthenticationError,
    DecryptionError,
    ValidationError,
)

TESTFILES_DIR = Path(__file__).parent / "testfiles"
LEGACY_PASSWORD = b"1234"
LEGACY_XCHACHA_FILE = TESTFILES_DIR / "v12" / "test_v12_xchacha20-poly1305_blake2b=2_argon2=2.txt"

# Fixtures generated with the pre-192-bit code (commit a644e280's parent);
# they cannot be regenerated and prove the legacy decryption paths forever.
LEGACY_DIR = TESTFILES_DIR / "xchacha_legacy"
LEGACY_PLAINTEXT = b"Legacy XChaCha fixture: pre-1.5 nonce format\n"
LEGACY_STREAMING_PLAINTEXT = LEGACY_PLAINTEXT * 4000

PASSWORD = b"xchacha_format_test_pw"
PLAINTEXT = b"The quick brown fox jumps over the lazy dog, 192 bits at a time."


def _encrypt_bytes(**kwargs) -> bytes:
    """Encrypt PLAINTEXT in-memory with XChaCha20-Poly1305 and return the file bytes."""
    params = dict(
        input_file=PLAINTEXT,
        output_file=None,
        password=PASSWORD,
        algorithm="xchacha20-poly1305",
        quiet=True,
    )
    params.update(kwargs)
    return encrypt_file(**params)


def _parse_metadata(file_bytes: bytes) -> dict:
    return json.loads(base64.b64decode(file_bytes.split(b":", 1)[0]))


def _decrypt_bytes(file_bytes: bytes, password: bytes = PASSWORD) -> bytes:
    """decrypt_file() only takes paths; stage the bytes in a temp file."""
    import os
    import tempfile

    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(file_bytes)
        return decrypt_file(input_file=path, output_file=None, password=password, quiet=True)
    finally:
        os.unlink(path)


class TestNewFormatEncryption(unittest.TestCase):
    """Freshly encrypted XChaCha files must use the real 192-bit format."""

    def test_metadata_carries_nonce_format_flag(self):
        meta = _parse_metadata(_encrypt_bytes())
        self.assertEqual(meta.get("encryption", {}).get("xchacha_nonce_format"), 2)

    def test_round_trip(self):
        encrypted = _encrypt_bytes()
        self.assertEqual(_decrypt_bytes(encrypted), PLAINTEXT)

    def test_real_xchacha_used_on_encrypt(self):
        """The spec-compliant primitive must be invoked with a full 24-byte
        nonce during file encryption (proves the real path end-to-end,
        including under pytest where a 12-byte test-mode nonce was
        historically substituted)."""
        calls = []
        original = xchacha.xchacha20poly1305_encrypt

        def spy(key, nonce, plaintext, associated_data=None):
            calls.append(len(nonce))
            return original(key, nonce, plaintext, associated_data)

        with mock.patch.object(xchacha, "xchacha20poly1305_encrypt", side_effect=spy):
            _encrypt_bytes()
        self.assertIn(24, calls, "real XChaCha primitive was not used for encryption")

    def test_real_xchacha_used_on_decrypt(self):
        encrypted = _encrypt_bytes()
        calls = []
        original = xchacha.xchacha20poly1305_decrypt

        def spy(key, nonce, ciphertext, associated_data=None):
            calls.append(len(nonce))
            return original(key, nonce, ciphertext, associated_data)

        with mock.patch.object(xchacha, "xchacha20poly1305_decrypt", side_effect=spy):
            decrypted = _decrypt_bytes(encrypted)
        self.assertEqual(decrypted, PLAINTEXT)
        self.assertIn(24, calls, "real XChaCha primitive was not used for decryption")


class TestDowngradeResistance(unittest.TestCase):
    """Stripping or altering the nonce-format flag must never silently
    decrypt a new-format file through the legacy path."""

    def _rebuild(self, encrypted: bytes, mutate) -> bytes:
        meta_b64, payload = encrypted.split(b":", 1)
        meta = json.loads(base64.b64decode(meta_b64))
        mutate(meta)
        new_meta = base64.b64encode(json.dumps(meta, separators=(",", ":")).encode("utf-8"))
        return new_meta + b":" + payload

    def test_stripped_flag_fails_authentication(self):
        encrypted = _encrypt_bytes()
        tampered = self._rebuild(encrypted, lambda m: m["encryption"].pop("xchacha_nonce_format"))
        with self.assertRaises((AuthenticationError, DecryptionError, ValidationError, ValueError)):
            _decrypt_bytes(tampered)

    def test_downgraded_flag_fails_authentication(self):
        encrypted = _encrypt_bytes()

        def downgrade(m):
            m["encryption"]["xchacha_nonce_format"] = 1

        tampered = self._rebuild(encrypted, downgrade)
        with self.assertRaises((AuthenticationError, DecryptionError, ValidationError, ValueError)):
            _decrypt_bytes(tampered)


class TestLegacyCompatibility(unittest.TestCase):
    """Pre-1.5 files must keep decrypting byte-for-byte."""

    def test_legacy_v12_fixture_decrypts(self):
        self.assertTrue(LEGACY_XCHACHA_FILE.exists(), f"fixture missing: {LEGACY_XCHACHA_FILE}")
        decrypted = decrypt_file(
            input_file=str(LEGACY_XCHACHA_FILE),
            output_file=None,
            password=LEGACY_PASSWORD,
            quiet=True,
        )
        self.assertTrue(decrypted)

    def test_legacy_fixture_has_no_flag(self):
        raw = LEGACY_XCHACHA_FILE.read_bytes()
        meta = _parse_metadata(raw)
        self.assertNotIn("xchacha_nonce_format", meta.get("encryption", {}))

    def test_legacy_oneshot_fixture_exact_plaintext(self):
        decrypted = decrypt_file(
            input_file=str(LEGACY_DIR / "oneshot_xchacha_legacy.bin"),
            output_file=None,
            password=LEGACY_PASSWORD,
            quiet=True,
        )
        self.assertEqual(decrypted, LEGACY_PLAINTEXT)

    def test_legacy_cascade_fixture_exact_plaintext(self):
        decrypted = decrypt_file(
            input_file=str(LEGACY_DIR / "cascade_xchacha_legacy.bin"),
            output_file=None,
            password=LEGACY_PASSWORD,
            quiet=True,
        )
        self.assertEqual(decrypted, LEGACY_PLAINTEXT)

    def test_legacy_streaming_fixture_exact_plaintext(self):
        decrypted = decrypt_file(
            input_file=str(LEGACY_DIR / "streaming_xchacha_legacy.bin"),
            output_file=None,
            password=LEGACY_PASSWORD,
            quiet=True,
        )
        self.assertEqual(decrypted, LEGACY_STREAMING_PLAINTEXT)


class TestNewFormatStreaming(unittest.TestCase):
    """Streaming XChaCha files must use 24-byte chunk nonces and the real
    construction, signaled by the same metadata flag."""

    # format_version=11 sidesteps a pre-existing streaming bug: metadata is
    # always written as v12 but the key is derived with the *passed* version,
    # and only v11 derivation coincides with v12 (see test_streaming.py).
    ENCRYPT_KWARGS = dict(
        password=PASSWORD,
        algorithm="xchacha20-poly1305",
        quiet=True,
        format_version=11,
        chunk_size=16384,
        streaming_threshold=1024,
    )

    def _encrypt_streaming(self, tmpdir: str) -> str:
        plain_path = f"{tmpdir}/plain.bin"
        enc_path = f"{tmpdir}/enc.bin"
        Path(plain_path).write_bytes(PLAINTEXT * 3000)
        self.assertTrue(
            encrypt_file(input_file=plain_path, output_file=enc_path, **self.ENCRYPT_KWARGS)
        )
        return enc_path

    def test_streaming_round_trip_and_flag(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            enc_path = self._encrypt_streaming(tmpdir)
            raw = Path(enc_path).read_bytes()
            meta = _parse_metadata(raw)
            self.assertTrue(meta.get("streaming", {}).get("enabled"))
            self.assertEqual(meta.get("encryption", {}).get("xchacha_nonce_format"), 2)
            decrypted = decrypt_file(
                input_file=enc_path, output_file=None, password=PASSWORD, quiet=True
            )
            self.assertEqual(decrypted, PLAINTEXT * 3000)

    def test_streaming_uses_real_xchacha_per_chunk(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            calls = []
            original = xchacha.xchacha20poly1305_encrypt

            def spy(key, nonce, plaintext, associated_data=None):
                calls.append(len(nonce))
                return original(key, nonce, plaintext, associated_data)

            with mock.patch.object(xchacha, "xchacha20poly1305_encrypt", side_effect=spy):
                self._encrypt_streaming(tmpdir)
            self.assertGreater(len(calls), 1, "expected multiple chunks")
            self.assertTrue(
                all(n == 24 for n in calls),
                f"non-24-byte chunk nonces observed: {set(calls)}",
            )


class TestNewFormatCascade(unittest.TestCase):
    """Cascade chains containing XChaCha must use the real construction for
    that layer in new files, while legacy cascade files keep the historical
    HKDF nonce derivation."""

    def _encrypt_cascade(self) -> bytes:
        return encrypt_file(
            input_file=PLAINTEXT,
            output_file=None,
            password=PASSWORD,
            algorithm="cascade",
            cascade=True,
            cipher_names=["aes-gcm", "xchacha20-poly1305"],
            quiet=True,
        )

    def test_cascade_round_trip_and_flag(self):
        encrypted = self._encrypt_cascade()
        meta = _parse_metadata(encrypted)
        self.assertEqual(meta.get("encryption", {}).get("xchacha_nonce_format"), 2)
        self.assertEqual(_decrypt_bytes(encrypted), PLAINTEXT)

    def test_cascade_uses_real_xchacha(self):
        calls = []
        original = xchacha.xchacha20poly1305_encrypt

        def spy(key, nonce, plaintext, associated_data=None):
            calls.append(len(nonce))
            return original(key, nonce, plaintext, associated_data)

        with mock.patch.object(xchacha, "xchacha20poly1305_encrypt", side_effect=spy):
            self._encrypt_cascade()
        self.assertIn(24, calls, "real XChaCha primitive not used in cascade layer")


class TestRegistryCipherModes(unittest.TestCase):
    """The registry XChaCha cipher must support both nonce derivations."""

    def test_real_mode_matches_primitives(self):
        import secrets

        from openssl_encrypt.modules.registry.cipher_registry import (
            XChaCha20Poly1305 as RegistryXChaCha,
        )

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(24)
        cipher = RegistryXChaCha()
        cipher.nonce_format = 2
        sealed = cipher.encrypt(key, b"registry real mode", nonce=nonce)
        self.assertEqual(sealed[:24], nonce)
        self.assertEqual(
            bytes(sealed[24:]),
            xchacha.xchacha20poly1305_encrypt(key, nonce, b"registry real mode", None),
        )
        self.assertEqual(bytes(cipher.decrypt(key, sealed)), b"registry real mode")

    def test_legacy_mode_unchanged(self):
        """Default mode must keep the historical HKDF derivation so old
        cascade files decrypt."""
        import secrets

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        from openssl_encrypt.modules.registry.cipher_registry import (
            XChaCha20Poly1305 as RegistryXChaCha,
        )

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(24)
        sealed = RegistryXChaCha().encrypt(key, b"registry legacy mode", nonce=nonce)
        derived = HKDF(
            algorithm=hashes.SHA256(), length=12, salt=nonce[:16], info=nonce[16:]
        ).derive(key)
        expected = ChaCha20Poly1305(key).encrypt(derived, b"registry legacy mode", None)
        self.assertEqual(bytes(sealed[24:]), expected)


if __name__ == "__main__":
    unittest.main()
