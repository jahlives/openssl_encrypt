#!/usr/bin/env python3
"""Tests for password-based envelope (DEK/KEK) wrapping.

Feature #2 (see docs/PLAN_streaming-cascade-nonce_and_envelope.md). Bulk data
is encrypted under a random DEK; the DEK is wrapped by a password-derived KEK so
that rekey only rewraps the DEK instead of re-encrypting the bulk data.

Cycle 1 covers the standalone wrap/unwrap primitive in modules/envelope.py.
"""

import base64
import json
import os
import secrets
import tempfile
import unittest

from openssl_encrypt.modules.crypt_core import decrypt_file, encrypt_file
from openssl_encrypt.modules.envelope import (
    DEK_SIZE,
    envelope_aad,
    generate_dek,
    unwrap_dek,
    wrap_dek,
)

_FAST_HASH = {"sha256": 1, "pbkdf2_iterations": 0}


def _tmp(data: bytes = b"") -> str:
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def _read_metadata(path: str) -> dict:
    with open(path, "rb") as f:
        raw = f.read()
    return json.loads(base64.b64decode(raw.split(b":", 1)[0]))


class TestEnvelopeWrapUnwrap(unittest.TestCase):
    """wrap_dek() / unwrap_dek() round-trip and failure modes."""

    def setUp(self):
        self.kek = secrets.token_bytes(32)
        self.dek = bytes(generate_dek())

    def test_generate_dek_size(self):
        """generate_dek() returns DEK_SIZE bytes of mutable buffer."""
        dek = generate_dek()
        self.assertEqual(len(dek), DEK_SIZE)
        self.assertEqual(DEK_SIZE, 32)
        self.assertIsInstance(dek, bytearray)  # mutable so callers can zero it

    def test_roundtrip(self):
        """unwrap_dek(wrap_dek(dek, kek), kek) == dek."""
        wrapped = wrap_dek(self.dek, self.kek)
        recovered = unwrap_dek(wrapped, self.kek)
        self.assertEqual(bytes(recovered), self.dek)

    def test_wrapped_is_not_plaintext_dek(self):
        """The wrapped blob must not expose the raw DEK."""
        wrapped = wrap_dek(self.dek, self.kek)
        self.assertNotIn(self.dek, wrapped)

    def test_output_size(self):
        """Wrapped format is nonce(12) + ciphertext(32) + tag(16) = 60 bytes."""
        wrapped = wrap_dek(self.dek, self.kek)
        self.assertEqual(len(wrapped), 12 + DEK_SIZE + 16)

    def test_unique_nonce_per_wrap(self):
        """Each wrap uses a fresh nonce, so identical inputs differ."""
        w1 = wrap_dek(self.dek, self.kek)
        w2 = wrap_dek(self.dek, self.kek)
        self.assertNotEqual(w1, w2)

    def test_wrong_kek_fails(self):
        """Unwrapping with the wrong KEK raises (authenticated)."""
        wrapped = wrap_dek(self.dek, self.kek)
        wrong_kek = secrets.token_bytes(32)
        with self.assertRaises(Exception):
            unwrap_dek(wrapped, wrong_kek)

    def test_tamper_fails(self):
        """Flipping any ciphertext/tag byte makes unwrap fail."""
        wrapped = bytearray(wrap_dek(self.dek, self.kek))
        wrapped[-1] ^= 0x01  # corrupt the tag
        with self.assertRaises(Exception):
            unwrap_dek(bytes(wrapped), self.kek)

    def test_truncated_blob_fails(self):
        """A too-short blob is rejected, not silently processed."""
        with self.assertRaises(Exception):
            unwrap_dek(b"too-short", self.kek)

    def test_short_kek_rejected(self):
        """A KEK shorter than 32 bytes is rejected."""
        with self.assertRaises(Exception):
            wrap_dek(self.dek, b"short")


class TestEnvelopeIntegration(unittest.TestCase):
    """End-to-end envelope mode through encrypt_file / decrypt_file (opt-in)."""

    PASSWORD = b"envelope-integration-pw"

    def _roundtrip(self, algorithm=None, cascade=False, cipher_names=None, size=4096):
        data = secrets.token_bytes(size)
        ip = _tmp(data)
        op = _tmp()
        try:
            kwargs = dict(
                input_file=ip,
                output_file=op,
                password=self.PASSWORD,
                hash_config=dict(_FAST_HASH),
                quiet=True,
                envelope=True,
            )
            if cascade:
                kwargs.update(algorithm="cascade", cascade=True, cipher_names=cipher_names)
            else:
                kwargs.update(algorithm=algorithm)
            self.assertTrue(encrypt_file(**kwargs))

            meta = _read_metadata(op)
            decrypted = decrypt_file(
                input_file=op, output_file=None, password=self.PASSWORD, quiet=True
            )
            self.assertEqual(decrypted, data)
            return meta
        finally:
            for p in (ip, op):
                if os.path.exists(p):
                    os.unlink(p)

    def test_envelope_roundtrip_aes_gcm(self):
        """Envelope encrypt/decrypt round-trips for aes-gcm."""
        meta = self._roundtrip(algorithm="aes-gcm")
        self.assertIn("wrapped_dek", meta["encryption"])

    def test_envelope_roundtrip_chacha(self):
        """Envelope encrypt/decrypt round-trips for chacha20-poly1305."""
        self._roundtrip(algorithm="chacha20-poly1305")

    def test_envelope_roundtrip_cascade(self):
        """Envelope encrypt/decrypt round-trips for a cascade chain."""
        self._roundtrip(cascade=True, cipher_names=["aes-256-gcm", "chacha20-poly1305"])

    def test_wrapped_dek_is_base64(self):
        """The stored wrapped_dek is base64 and decodes to the expected size."""
        meta = self._roundtrip(algorithm="aes-gcm")
        wrapped = base64.b64decode(meta["encryption"]["wrapped_dek"])
        self.assertEqual(len(wrapped), 12 + DEK_SIZE + 16)

    def test_non_envelope_has_no_wrapped_dek(self):
        """Without --envelope, no wrapped_dek is written (unchanged behavior)."""
        data = secrets.token_bytes(4096)
        ip = _tmp(data)
        op = _tmp()
        try:
            self.assertTrue(
                encrypt_file(
                    input_file=ip,
                    output_file=op,
                    password=self.PASSWORD,
                    hash_config=dict(_FAST_HASH),
                    quiet=True,
                    algorithm="aes-gcm",
                )
            )
            meta = _read_metadata(op)
            self.assertNotIn("wrapped_dek", meta.get("encryption", {}))
            decrypted = decrypt_file(
                input_file=op, output_file=None, password=self.PASSWORD, quiet=True
            )
            self.assertEqual(decrypted, data)
        finally:
            for p in (ip, op):
                if os.path.exists(p):
                    os.unlink(p)

    def test_envelope_streaming_roundtrip(self):
        """Envelope mode works with the streaming path (key=DEK flows through)."""
        data = secrets.token_bytes(8 * 1024)
        ip = _tmp(data)
        op = _tmp()
        try:
            self.assertTrue(
                encrypt_file(
                    input_file=ip,
                    output_file=op,
                    password=self.PASSWORD,
                    hash_config=dict(_FAST_HASH),
                    quiet=True,
                    algorithm="aes-gcm",
                    envelope=True,
                    chunk_size=1024,
                    streaming_threshold=1024,
                )
            )
            meta = _read_metadata(op)
            self.assertTrue(meta.get("streaming", {}).get("enabled"))
            self.assertIn("wrapped_dek", meta["encryption"])
            decrypted = decrypt_file(
                input_file=op, output_file=None, password=self.PASSWORD, quiet=True
            )
            self.assertEqual(decrypted, data)
        finally:
            for p in (ip, op):
                if os.path.exists(p):
                    os.unlink(p)

    def test_envelope_wrong_password_fails(self):
        """A wrong password must not decrypt an envelope file."""
        data = secrets.token_bytes(4096)
        ip = _tmp(data)
        op = _tmp()
        try:
            encrypt_file(
                input_file=ip,
                output_file=op,
                password=self.PASSWORD,
                hash_config=dict(_FAST_HASH),
                quiet=True,
                algorithm="aes-gcm",
                envelope=True,
            )
            with self.assertRaises(Exception):
                decrypt_file(
                    input_file=op, output_file=None, password=b"wrong-password", quiet=True
                )
        finally:
            for p in (ip, op):
                if os.path.exists(p):
                    os.unlink(p)


class TestEnvelopeAAD(unittest.TestCase):
    """envelope_aad() — the stable-subset canonical AAD for Option A.

    Excludes ONLY the KEK-gating fields that a rekey changes
    (derivation_config subtree + encryption.wrapped_dek); authenticates every
    other field (bulk interpretation). Deterministic on both encrypt and
    decrypt. See docs/PLAN_streaming-cascade-nonce_and_envelope.md (#2, gate).
    """

    def _meta(self):
        # Representative envelope metadata (mirrors a real cascade file).
        return {
            "format_version": 12,
            "mode": "symmetric",
            "encrypted_at": "2026-06-24T10:00:00Z",
            "derivation_config": {
                "salt": "QUFBQUFBQUFBQUFBQUFBQQ==",
                "hash_config": {"sha256": {"rounds": 1}},
                "kdf_config": {},
            },
            "encryption": {
                "cascade": True,
                "cascade_salt": "Q0NDQ0NDQ0NDQ0NDQ0NDQw==",
                "cipher_chain": ["aes-gcm", "chacha20-poly1305"],
                "wrapped_dek": "V1dXV1dXV1dXV1dXV1dXVw==",
            },
            "streaming": {
                "enabled": True,
                "chunk_size": 1024,
                "chunk_count": 3,
                "nonce_prefix": "Tk5OTk5OTk4=",
                "cascade_nonce_scheme": 2,
            },
            "hashes": {"original_hash": "deadbeef" * 8},
        }

    def test_returns_bytes(self):
        self.assertIsInstance(envelope_aad(self._meta()), bytes)

    def test_rejects_non_dict(self):
        with self.assertRaises(Exception):
            envelope_aad("not-a-dict")

    def test_deterministic_regardless_of_key_order(self):
        """Same content, different insertion order ⇒ identical AAD."""
        m1 = self._meta()
        m2 = json.loads(json.dumps(m1))  # round-trip (re-orders nothing but proves stability)
        # Rebuild encryption block in a different key order:
        enc = m2["encryption"]
        m2["encryption"] = {k: enc[k] for k in reversed(list(enc.keys()))}
        self.assertEqual(envelope_aad(m1), envelope_aad(m2))

    def test_excludes_derivation_config(self):
        """Changing ANY derivation_config field (salt/hash/kdf) ⇒ AAD unchanged."""
        base = self._meta()
        ref = envelope_aad(base)
        for mutate in (
            lambda m: m["derivation_config"].__setitem__("salt", "ZZZZZZZZZZZZZZZZZZZZZZ=="),
            lambda m: m["derivation_config"].__setitem__("hash_config", {"argon2": {"rounds": 9}}),
            lambda m: m["derivation_config"].__setitem__("kdf_config", {"scrypt": {"n": 2}}),
        ):
            m = self._meta()
            mutate(m)
            self.assertEqual(envelope_aad(m), ref)

    def test_excludes_wrapped_dek(self):
        """Changing encryption.wrapped_dek ⇒ AAD unchanged (it is rekey-mutable)."""
        base = self._meta()
        ref = envelope_aad(base)
        m = self._meta()
        m["encryption"]["wrapped_dek"] = "ZG lmZmVyZW50d3JhcA=="
        self.assertEqual(envelope_aad(m), ref)

    def test_includes_bulk_interpretation_fields(self):
        """Changing any bulk-interpretation field ⇒ AAD changes (authenticated)."""
        ref = envelope_aad(self._meta())
        mutations = [
            ("format_version", lambda m: m.__setitem__("format_version", 11)),
            ("mode", lambda m: m.__setitem__("mode", "asymmetric")),
            (
                "cascade_salt",
                lambda m: m["encryption"].__setitem__("cascade_salt", "eHh4eHh4eHh4eHh4eHh4eA=="),
            ),
            ("cipher_chain", lambda m: m["encryption"].__setitem__("cipher_chain", ["aes-gcm"])),
            ("cascade_flag", lambda m: m["encryption"].__setitem__("cascade", False)),
            ("nonce_prefix", lambda m: m["streaming"].__setitem__("nonce_prefix", "eHh4eHh4eHg=")),
            ("chunk_count", lambda m: m["streaming"].__setitem__("chunk_count", 99)),
            (
                "cascade_nonce_scheme",
                lambda m: m["streaming"].__setitem__("cascade_nonce_scheme", 1),
            ),
            ("original_hash", lambda m: m["hashes"].__setitem__("original_hash", "00" * 32)),
            ("encrypted_at", lambda m: m.__setitem__("encrypted_at", "2030-01-01T00:00:00Z")),
        ]
        for name, mutate in mutations:
            m = self._meta()
            mutate(m)
            self.assertNotEqual(envelope_aad(m), ref, f"{name} must be authenticated (in AAD)")

    def test_rekey_invariant(self):
        """A rekey changes ONLY derivation_config + wrapped_dek ⇒ AAD invariant.

        This is the property that lets the fast-path retain the bulk ciphertext.
        """
        before = self._meta()
        after = self._meta()
        after["derivation_config"] = {
            "salt": "bmV3c2FsdG5ld3NhbHRuZXc=",
            "hash_config": {"argon2": {"rounds": 3}},
            "kdf_config": {"argon2": {"memory": 65536}},
        }
        after["encryption"]["wrapped_dek"] = "cmV3cmFwcGVkbmV3a2Vrd3JhcA=="
        self.assertEqual(envelope_aad(before), envelope_aad(after))

    def test_non_envelope_metadata_has_stable_aad(self):
        """envelope_aad works on metadata lacking wrapped_dek (still excludes derivation_config)."""
        m = self._meta()
        del m["encryption"]["wrapped_dek"]
        ref = envelope_aad(m)
        m["derivation_config"]["salt"] = "b3RoZXJzYWx0b3RoZXJzYWx0"
        self.assertEqual(envelope_aad(m), ref)


class TestEnvelopeBulkAADWiring(unittest.TestCase):
    """White-box: the streaming bulk_aad override actually binds chunks to the
    given AAD (the stable subset), while the file header still stores the full
    metadata. This is the mechanism (cycle 5b) that lets an envelope file
    survive a rekey -- proven here with a known key, independent of the KDF.
    """

    def _encrypt(self, key, data, metadata_b64, bulk_aad, chunk_size=16):
        from openssl_encrypt.modules.streaming import StreamingEncryptor

        ip = _tmp(data)
        op = _tmp()
        enc = StreamingEncryptor(
            key=key, algorithm="aes-gcm", chunk_size=chunk_size, format_version=12
        )
        chunk_count = enc.get_chunk_count(len(data))
        try:
            enc.encrypt_file(
                input_file=ip,
                output_file=op,
                metadata_b64=metadata_b64,
                chunk_count=chunk_count,
                quiet=True,
                bulk_aad=bulk_aad,
            )
        finally:
            os.unlink(ip)
        return op, enc.nonce_prefix, chunk_count

    def _decrypt(self, key, op, nonce_prefix, chunk_count, metadata_b64, bulk_aad, chunk_size=16):
        from openssl_encrypt.modules.streaming import StreamingDecryptor

        dec = StreamingDecryptor(
            key=key,
            algorithm="aes-gcm",
            nonce_prefix=nonce_prefix,
            chunk_size=chunk_size,
            format_version=12,
        )
        return dec.decrypt_file(
            input_file=op,
            output_file=None,
            metadata_b64=metadata_b64,
            expected_chunk_count=chunk_count,
            quiet=True,
            bulk_aad=bulk_aad,
        )

    def test_roundtrip_with_matching_override(self):
        """Encrypt and decrypt with the same bulk_aad round-trips."""
        key = secrets.token_bytes(32)
        data = secrets.token_bytes(70)  # 5 chunks @ 16
        full_meta = base64.b64encode(b'{"derivation_config":{"salt":"AAAA"}}')
        bulk = b"STABLE-SUBSET-AAD"
        op, npfx, cc = self._encrypt(key, data, full_meta, bulk)
        try:
            out = self._decrypt(key, op, npfx, cc, full_meta, bulk)
            self.assertEqual(out, data)
        finally:
            os.unlink(op)

    def test_override_is_what_was_bound_not_metadata(self):
        """Chunks are bound to bulk_aad, NOT the metadata header.

        Encrypt with bulk_aad=X; decrypting with the DEFAULT (bulk_aad=None,
        i.e. the full metadata_b64) must FAIL -- proving the override was used.
        """
        key = secrets.token_bytes(32)
        data = secrets.token_bytes(70)
        full_meta = base64.b64encode(b'{"derivation_config":{"salt":"AAAA"},"x":1}')
        bulk = b"STABLE-SUBSET-AAD"
        op, npfx, cc = self._encrypt(key, data, full_meta, bulk)
        try:
            # Same bulk_aad → works.
            self.assertEqual(self._decrypt(key, op, npfx, cc, full_meta, bulk), data)
            # Default (binds full metadata) → fails: chunks were bound to `bulk`.
            with self.assertRaises(Exception):
                self._decrypt(key, op, npfx, cc, full_meta, None)
        finally:
            os.unlink(op)

    def test_decrypt_independent_of_metadata_when_override_matches(self):
        """A DIFFERENT metadata header but the SAME bulk_aad still decrypts.

        Models a rekey: the KEK-gating metadata changed, but the stable subset
        (bulk_aad) did not, so the retained ciphertext still authenticates.
        """
        key = secrets.token_bytes(32)
        data = secrets.token_bytes(70)
        meta_before = base64.b64encode(b'{"derivation_config":{"salt":"OLDSALT"}}')
        meta_after = base64.b64encode(b'{"derivation_config":{"salt":"NEWSALT-DIFFERENT"}}')
        bulk = b"STABLE-SUBSET-AAD"
        op, npfx, cc = self._encrypt(key, data, meta_before, bulk)
        try:
            out = self._decrypt(key, op, npfx, cc, meta_after, bulk)
            self.assertEqual(out, data)
        finally:
            os.unlink(op)

    def test_header_stores_full_metadata(self):
        """The file header is the full metadata_b64, regardless of bulk_aad."""
        key = secrets.token_bytes(32)
        data = secrets.token_bytes(40)
        full_meta = base64.b64encode(b'{"derivation_config":{"salt":"AAAA"}}')
        op, _, _ = self._encrypt(key, data, full_meta, b"different-aad")
        try:
            with open(op, "rb") as f:
                raw = f.read()
            self.assertTrue(raw.startswith(full_meta + b":"))
        finally:
            os.unlink(op)


if __name__ == "__main__":
    unittest.main()
