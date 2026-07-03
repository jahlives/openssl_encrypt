#!/usr/bin/env python3
"""
End-to-end tests for the real 192-bit XChaCha20-Poly1305 file format.

New-format files carry ``encryption.xchacha_nonce_format: 2`` in their
metadata and use the full 24-byte nonce via HChaCha20 subkey derivation.
Legacy files (no flag) keep decrypting through the historical HKDF
nonce funnel (24 bytes reduced to a 96-bit effective nonce); the
committed corpus in testfiles/v12 is the backward-compatibility
regression suite.
"""

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from openssl_encrypt.modules import xchacha
from openssl_encrypt.modules.crypt_core import decrypt_file, encrypt_file, rekey_file
from openssl_encrypt.modules.crypt_errors import (
    AuthenticationError,
    DecryptionError,
    ValidationError,
)

TESTFILES_DIR = Path(__file__).parent / "testfiles"
LEGACY_PASSWORD = b"1234"

# Fixtures generated with the pre-192-bit code (commit a644e280's parent);
# they cannot be regenerated and prove the legacy decryption paths forever.
LEGACY_DIR = TESTFILES_DIR / "xchacha_legacy"
LEGACY_PLAINTEXT = b"Legacy XChaCha fixture: pre-1.5 nonce format\n"
LEGACY_STREAMING_PLAINTEXT = LEGACY_PLAINTEXT * 4000

# Fixtures generated with the 1.5 real-192-bit code; pin the new format
# so later changes cannot silently alter it.
V2_DIR = TESTFILES_DIR / "xchacha_v2"
V2_PLAINTEXT = b"Real 192-bit XChaCha fixture: 1.5 nonce format\n"
V2_STREAMING_PLAINTEXT = V2_PLAINTEXT * 4000

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


class TestV2FixtureCompatibility(unittest.TestCase):
    """Committed real-192-bit fixtures pin the new format across releases."""

    def _check(self, name: str, expected: bytes):
        path = V2_DIR / name
        self.assertTrue(path.exists(), f"fixture missing: {path}")
        meta = _parse_metadata(path.read_bytes())
        self.assertEqual(meta.get("encryption", {}).get("xchacha_nonce_format"), 2)
        decrypted = decrypt_file(
            input_file=str(path), output_file=None, password=LEGACY_PASSWORD, quiet=True
        )
        self.assertEqual(decrypted, expected)

    def test_oneshot_v2_fixture(self):
        self._check("oneshot_xchacha_v2.bin", V2_PLAINTEXT)

    def test_cascade_v2_fixture(self):
        self._check("cascade_xchacha_v2.bin", V2_PLAINTEXT)

    def test_streaming_v2_fixture(self):
        self._check("streaming_xchacha_v2.bin", V2_STREAMING_PLAINTEXT)


class TestNewFormatStreaming(unittest.TestCase):
    """Streaming XChaCha files must use 24-byte chunk nonces and the real
    construction, signaled by the same metadata flag."""

    # No format_version pin needed: the streaming encrypt path forces v12
    # internally (see test_streaming_format_version.py), so the default
    # caller version round-trips.
    ENCRYPT_KWARGS = dict(
        password=PASSWORD,
        algorithm="xchacha20-poly1305",
        quiet=True,
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

    def test_streaming_cascade_round_trip(self):
        """Streaming + cascade + XChaCha must round-trip with the real
        construction.

        No format_version pin needed: the streaming encrypt path forces v12
        internally, keeping cascade per-layer salts and AAD scope in sync
        with the v12 metadata (see test_streaming_format_version.py)."""
        import tempfile

        data = PLAINTEXT * 3000
        with tempfile.TemporaryDirectory() as tmpdir:
            plain_path = f"{tmpdir}/plain.bin"
            enc_path = f"{tmpdir}/enc.bin"
            Path(plain_path).write_bytes(data)
            self.assertTrue(
                encrypt_file(
                    input_file=plain_path,
                    output_file=enc_path,
                    password=PASSWORD,
                    algorithm="cascade",
                    cascade=True,
                    cipher_names=["aes-gcm", "xchacha20-poly1305"],
                    quiet=True,
                    chunk_size=16384,
                    streaming_threshold=1024,
                )
            )
            meta = _parse_metadata(Path(enc_path).read_bytes())
            self.assertTrue(meta.get("streaming", {}).get("enabled"))
            self.assertEqual(meta.get("encryption", {}).get("xchacha_nonce_format"), 2)
            decrypted = decrypt_file(
                input_file=enc_path, output_file=None, password=PASSWORD, quiet=True
            )
            self.assertEqual(decrypted, data)


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


class TestEnvelopeCascadeXChaCha(unittest.TestCase):
    """Envelope (DEK/KEK) + cascade + XChaCha: the wrapped DEK must use the same
    real 192-bit construction as the bulk for new files, while genuine
    pre-backport 1.4.x envelope files (no flag, legacy DEK wrap) keep
    decrypting. Closes the envelope cross-version-interop gap."""

    _V14_DIR = TESTFILES_DIR / "envelope_xchacha_v14"
    V14_VECTOR = _V14_DIR / "envelope_cascade_xchacha_v14.enc"
    V14_PLAINTEXT = _V14_DIR / "plaintext.bin"
    V14_PASSWORD = b"envelope-xchacha-cross-version-1.4.x"

    def _encrypt_envelope_cascade(self) -> bytes:
        return encrypt_file(
            input_file=PLAINTEXT,
            output_file=None,
            password=PASSWORD,
            algorithm="cascade",
            cascade=True,
            cipher_names=["aes-gcm", "xchacha20-poly1305"],
            envelope=True,
            quiet=True,
        )

    def test_dek_wrap_uses_real_xchacha(self):
        """Both the bulk and the wrapped DEK must use the real 24-byte
        construction (>=2 real-XChaCha invocations), and the file round-trips."""
        calls = []
        original = xchacha.xchacha20poly1305_encrypt

        def spy(key, nonce, plaintext, associated_data=None):
            calls.append(len(nonce))
            return original(key, nonce, plaintext, associated_data)

        with mock.patch.object(xchacha, "xchacha20poly1305_encrypt", side_effect=spy):
            encrypted = self._encrypt_envelope_cascade()

        meta = _parse_metadata(encrypted)
        self.assertIn("wrapped_dek", meta["encryption"], "envelope layer missing")
        self.assertEqual(meta["encryption"].get("xchacha_nonce_format"), 2)
        # Bulk xchacha layer + DEK-wrap xchacha layer => >= 2 real 24-byte calls.
        self.assertGreaterEqual(
            calls.count(24),
            2,
            f"DEK wrap did not use the real XChaCha construction: nonce sizes {calls}",
        )
        self.assertEqual(_decrypt_bytes(encrypted), PLAINTEXT)

    def test_legacy_v14_envelope_fixture_decrypts(self):
        """A genuine pre-backport 1.4.x envelope+cascade+xchacha file (no flag,
        legacy DEK wrap) must still decrypt byte-for-byte."""
        meta = _parse_metadata(self.V14_VECTOR.read_bytes())
        self.assertNotIn(
            "xchacha_nonce_format", meta["encryption"], "fixture is not a legacy file"
        )
        expected = self.V14_PLAINTEXT.read_bytes()
        decrypted = decrypt_file(
            input_file=str(self.V14_VECTOR),
            output_file=None,
            password=self.V14_PASSWORD,
            quiet=True,
        )
        self.assertEqual(decrypted, expected)

    def test_envelope_xchacha_rekey_preserves_format_and_roundtrips(self):
        """Rekeying an envelope cascade+xchacha file must rewrap the DEK in the
        same (real) nonce format and stay decryptable under the new password."""
        with tempfile.TemporaryDirectory() as tmp:
            enc_path = os.path.join(tmp, "enc.bin")
            rekeyed = os.path.join(tmp, "rekeyed.bin")
            with open(enc_path, "wb") as f:
                f.write(self._encrypt_envelope_cascade())

            self.assertTrue(
                rekey_file(
                    input_file=enc_path,
                    output_file=rekeyed,
                    old_password=PASSWORD,
                    new_password=b"new-" + PASSWORD,
                    quiet=True,
                )
            )
            meta = _parse_metadata(Path(rekeyed).read_bytes())
            self.assertEqual(meta["encryption"].get("xchacha_nonce_format"), 2)
            self.assertEqual(
                _decrypt_bytes(Path(rekeyed).read_bytes(), password=b"new-" + PASSWORD),
                PLAINTEXT,
            )


if __name__ == "__main__":
    unittest.main()


class TestFormat1DocsAccuracy(unittest.TestCase):
    """Regression tests for GitLab #93 [CORE-9]: format-1 nonce docs must be honest.

    Legacy ``nonce_format=1`` HKDF-funnels the 24-byte nonce down to a
    12-byte ChaCha20-Poly1305 nonce — 96-bit effective, not 192-bit, and
    not the HChaCha20 construction from the XChaCha20 spec (that is what
    ``nonce_format=2`` provides). The comments must say so instead of
    claiming spec compliance.
    """

    def test_process_nonce_docs_are_honest(self) -> None:
        import inspect

        from openssl_encrypt.modules.crypt_core import XChaCha20Poly1305

        src = inspect.getsource(XChaCha20Poly1305._process_nonce)
        self.assertNotIn("following the XChaCha20 specification", src)
        self.assertNotIn("mimicking HChaCha20", src)
        self.assertIn("96-bit", src)

    def test_init_comment_describes_hkdf_funnel(self) -> None:
        import inspect

        from openssl_encrypt.modules.crypt_core import XChaCha20Poly1305

        src = inspect.getsource(XChaCha20Poly1305.__init__)
        self.assertNotIn("use the first 12 directly", src)
        self.assertIn("96-bit", src)
