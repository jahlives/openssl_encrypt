#!/usr/bin/env python3
"""
KEM-ciphertext transcript binding for the recipient password wrap
(post-v14 review LOW-3, gitlab#112).

``PasswordWrapper`` derived the AES-256-GCM wrap key from the KEM shared
secret with static HKDF info (``password_wrap.v2``) — the finding-#83
transcript-binding hardening was applied only to the main PQC data path.
Wrap version 3 binds the KEM encapsulation ciphertext and the KEM algorithm
identity into the wrap-key derivation:

    info = b"openssl_encrypt.password_wrap.v3|" + kem_algorithm
           + b"|ct=" + sha256(encapsulated_key)

Asymmetric files are pinned to format_version 7, so the binding is versioned
per recipient entry via a ``wrap_version: 3`` marker (covered by the metadata
signature through the canonicalizer). Entries WITHOUT the marker take the
existing v2->v1 fallback chain byte-for-byte — every existing file keeps
decrypting, pinned here by a pre-fix fixture. Stripping the marker fails
closed: the v2 attempt derives a different key and the GCM tag rejects.

The wrap/unwrap unit tests use a fixed shared secret and ciphertext stand-in
(no liboqs keygen needed), mirroring test_password_wrap_hkdf.py.
"""

import hashlib
import os
import pathlib
import shutil
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from openssl_encrypt.modules.asymmetric_core import PasswordWrapper, PasswordWrapperError

SHARED_SECRET = bytes(range(32))
PASSWORD = b"recipient-bulk-password-32-byte!"
# Stand-in for an ML-KEM-768 encapsulation ciphertext (real ones are 1088 bytes;
# the binding hashes it, so any length works for derivation tests).
ENCAPSULATED_KEY = bytes(range(256)) * 4

_WRAP_V1_LABEL = b"openssl_encrypt.password_wrap.v1"
_WRAP_V2_INFO = b"openssl_encrypt.password_wrap.v2"


def _hkdf(info: bytes, shared_secret: bytes) -> bytes:
    return HKDF(algorithm=crypto_hashes.SHA256(), length=32, salt=None, info=info).derive(
        shared_secret
    )


def _wrap_key_v2(shared_secret: bytes) -> bytes:
    return _hkdf(_WRAP_V2_INFO, shared_secret)


def _wrap_key_v3(shared_secret: bytes, encapsulated_key: bytes, kem_algorithm: str) -> bytes:
    """Independent reimplementation of the v3 binding (spec cross-check).

    PINNED for cross-line (1.4.x/1.5.x) interop — do not change the label,
    separators, field order, or the SHA-256 ciphertext digest.
    """
    info = (
        b"openssl_encrypt.password_wrap.v3|"
        + kem_algorithm.encode("ascii")
        + b"|ct="
        + hashlib.sha256(encapsulated_key).digest()
    )
    return _hkdf(info, shared_secret)


def _make_blob(wrap_key: bytes, password: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(wrap_key).encrypt(nonce, password, None)


class TestWrapV3Binding(unittest.TestCase):
    def setUp(self):
        try:
            self.wrapper = PasswordWrapper("ML-KEM-768", quiet=True)
        except Exception as exc:  # pragma: no cover - env without liboqs
            self.skipTest(f"PasswordWrapper unavailable (liboqs?): {exc}")

    def _wrap_v3(self, **kw):
        return self.wrapper.wrap_password(
            PASSWORD, SHARED_SECRET, encapsulated_key=ENCAPSULATED_KEY, **kw
        )

    def test_roundtrip_v3(self):
        blob = self._wrap_v3()
        self.assertEqual(
            self.wrapper.unwrap_password(
                blob, SHARED_SECRET, encapsulated_key=ENCAPSULATED_KEY, wrap_version=3
            ),
            PASSWORD,
        )

    def test_v3_derivation_matches_pinned_spec(self):
        blob = self._wrap_v3()
        nonce, ct = blob[:12], blob[12:]
        self.assertEqual(
            AESGCM(_wrap_key_v3(SHARED_SECRET, ENCAPSULATED_KEY, "ML-KEM-768")).decrypt(
                nonce, ct, None
            ),
            PASSWORD,
        )

    def test_no_encapsulated_key_still_writes_v2(self):
        # kwarg default None -> byte-identical v2 behavior (protects
        # recovery_slots and external callers).
        blob = self.wrapper.wrap_password(PASSWORD, SHARED_SECRET)
        nonce, ct = blob[:12], blob[12:]
        self.assertEqual(AESGCM(_wrap_key_v2(SHARED_SECRET)).decrypt(nonce, ct, None), PASSWORD)

    def test_ciphertext_substitution_fails(self):
        # THE security property: same shared secret, different encapsulation
        # ciphertext -> different wrap key -> GCM tag failure.
        blob = self._wrap_v3()
        other_ct = b"\xff" + ENCAPSULATED_KEY[1:]
        with self.assertRaises(PasswordWrapperError):
            self.wrapper.unwrap_password(
                blob, SHARED_SECRET, encapsulated_key=other_ct, wrap_version=3
            )

    def test_kem_algorithm_binding(self):
        # The algorithm identity is bound: unwrapping under a wrapper for a
        # different KEM algorithm fails even with identical secret+ciphertext.
        blob = self._wrap_v3()
        other = PasswordWrapper("ML-KEM-1024", quiet=True)
        with self.assertRaises(PasswordWrapperError):
            other.unwrap_password(
                blob, SHARED_SECRET, encapsulated_key=ENCAPSULATED_KEY, wrap_version=3
            )

    def test_marker_strip_downgrade_fails_closed(self):
        # A v3 blob pushed through the no-marker (v2->v1 fallback) path must
        # fail, never silently succeed under a weaker derivation.
        blob = self._wrap_v3()
        with self.assertRaises(PasswordWrapperError):
            self.wrapper.unwrap_password(blob, SHARED_SECRET)

    def test_v3_requires_encapsulated_key(self):
        blob = self._wrap_v3()
        with self.assertRaises(PasswordWrapperError):
            self.wrapper.unwrap_password(blob, SHARED_SECRET, wrap_version=3)

    def test_unknown_wrap_versions_fail_closed(self):
        # Fail closed on anything but 3 or None - including bool True
        # (isinstance int) and numeric strings. No fallback attempts.
        blob = self._wrap_v3()
        for wv in ("3", True, 2, 4, 0, [], {}):
            with self.subTest(wrap_version=wv):
                with self.assertRaises(PasswordWrapperError):
                    self.wrapper.unwrap_password(
                        blob,
                        SHARED_SECRET,
                        encapsulated_key=ENCAPSULATED_KEY,
                        wrap_version=wv,
                    )

    def test_legacy_chain_unchanged_without_marker(self):
        # No marker -> v2 first, then v1. Byte-for-byte the pre-fix behavior.
        v2_blob = _make_blob(_wrap_key_v2(SHARED_SECRET), PASSWORD)
        self.assertEqual(self.wrapper.unwrap_password(v2_blob, SHARED_SECRET), PASSWORD)
        v1_key = hashlib.sha256(_WRAP_V1_LABEL + SHARED_SECRET).digest()
        v1_blob = _make_blob(v1_key, PASSWORD)
        self.assertEqual(self.wrapper.unwrap_password(v1_blob, SHARED_SECRET), PASSWORD)


FIXTURE_DIR = pathlib.Path(__file__).parent / "testfiles" / "asymmetric_wrap"


def _load_fixture_identities():
    from openssl_encrypt.modules.identity import Identity

    recipient = Identity.load(
        FIXTURE_DIR / "recipient_identity", passphrase="fixture-recipient-pass"
    )
    sender = Identity.load(FIXTURE_DIR / "sender_identity", passphrase="fixture-sender-pass")
    return sender, recipient


class TestAsymmetricEndToEnd(unittest.TestCase):
    def setUp(self):
        try:
            from openssl_encrypt.modules.pqc_signing import LIBOQS_AVAILABLE
        except Exception:  # pragma: no cover
            LIBOQS_AVAILABLE = False
        if not LIBOQS_AVAILABLE:
            self.skipTest("liboqs not available")
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_prefix_fixture_still_decrypts(self):
        # THE backward-compat pin (non-negotiable): a file written BEFORE the
        # LOW-3 fix (password_wrap.v2, no wrap_version marker) must decrypt.
        from openssl_encrypt.modules.crypt_core import decrypt_file_asymmetric

        sender, recipient = _load_fixture_identities()
        out = os.path.join(self.dir, "fixture.out")
        decrypt_file_asymmetric(
            input_file=str(FIXTURE_DIR / "v7_wrap_v2_prefix.enc"),
            output_file=out,
            recipient=recipient,
            sender_public_key=sender.signing_public_key,
            quiet=True,
        )
        with open(out, "rb") as f:
            self.assertEqual(f.read(), (FIXTURE_DIR / "plaintext.bin").read_bytes())

    def test_new_files_carry_wrap_version_3_and_roundtrip(self):
        import base64 as b64
        import json

        from openssl_encrypt.modules.crypt_core import (
            decrypt_file_asymmetric,
            encrypt_file_asymmetric,
        )

        sender, recipient = _load_fixture_identities()
        src = os.path.join(self.dir, "msg.txt")
        content = b"wrap_version 3 end-to-end payload"
        with open(src, "wb") as f:
            f.write(content)
        enc = os.path.join(self.dir, "msg.enc")
        encrypt_file_asymmetric(
            input_file=src,
            output_file=enc,
            recipients=[recipient],
            sender=sender,
            quiet=True,
        )

        with open(enc, "rb") as f:
            raw = f.read()
        meta = json.loads(b64.b64decode(raw[: raw.find(b":")]))
        for entry in meta["asymmetric"]["recipients"]:
            self.assertEqual(entry.get("wrap_version"), 3)

        out = os.path.join(self.dir, "msg.out")
        decrypt_file_asymmetric(
            input_file=enc,
            output_file=out,
            recipient=recipient,
            sender_public_key=sender.signing_public_key,
            quiet=True,
        )
        with open(out, "rb") as f:
            self.assertEqual(f.read(), content)

    def test_marker_strip_fails_even_without_signature_check(self):
        # Stripping wrap_version from a new file breaks the signature; even
        # bypassing verification, the v2/v1 fallback derives the wrong key
        # and the unwrap fails closed - never a silent weaker success.
        import base64 as b64
        import json

        from openssl_encrypt.modules.crypt_core import (
            decrypt_file_asymmetric,
            encrypt_file_asymmetric,
        )

        sender, recipient = _load_fixture_identities()
        src = os.path.join(self.dir, "msg.txt")
        with open(src, "wb") as f:
            f.write(b"strip test")
        enc = os.path.join(self.dir, "msg.enc")
        encrypt_file_asymmetric(
            input_file=src,
            output_file=enc,
            recipients=[recipient],
            sender=sender,
            quiet=True,
        )

        with open(enc, "rb") as f:
            raw = f.read()
        colon = raw.find(b":")
        meta = json.loads(b64.b64decode(raw[:colon]))
        for entry in meta["asymmetric"]["recipients"]:
            entry.pop("wrap_version", None)
        stripped = b64.b64encode(json.dumps(meta).encode("utf-8")) + raw[colon:]
        tampered = os.path.join(self.dir, "tampered.enc")
        with open(tampered, "wb") as f:
            f.write(stripped)

        out = os.path.join(self.dir, "tampered.out")
        with self.assertRaises(Exception):
            decrypt_file_asymmetric(
                input_file=tampered,
                output_file=out,
                recipient=recipient,
                sender_public_key=sender.signing_public_key,
                skip_verification=True,
                quiet=True,
            )
        self.assertFalse(os.path.exists(out) and os.path.getsize(out) > 0)


if __name__ == "__main__":
    unittest.main()
