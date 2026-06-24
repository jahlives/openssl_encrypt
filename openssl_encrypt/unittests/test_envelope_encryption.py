#!/usr/bin/env python3
"""Tests for password-based envelope (DEK/KEK) wrapping.

Feature #2 (see docs/PLAN_streaming-cascade-nonce_and_envelope.md). Bulk data
is encrypted under a random DEK; the DEK is wrapped by a password-derived KEK so
that rekey only rewraps the DEK instead of re-encrypting the bulk data.

Cycle 1 covers the standalone wrap/unwrap primitive in modules/envelope.py.
"""

import base64
import contextlib
import io
import json
import logging
import os
import secrets
import tempfile
import unittest
from unittest import mock

import openssl_encrypt.modules.envelope as envelope_mod
from openssl_encrypt.modules.crypt_core import decrypt_file, encrypt_file, rekey_file
from openssl_encrypt.modules.envelope import (
    DEK_SIZE,
    envelope_aad,
    generate_dek,
    unwrap_dek,
    unwrap_dek_cascade,
    wrap_dek,
    wrap_dek_cascade,
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

    def test_envelope_roundtrip_cascade_xchacha(self):
        """Regression: envelope + cascade containing xchacha20-poly1305 round-trips.

        Pins the three-feature combination (envelope DEK/KEK + cascade chain +
        XChaCha 192-bit nonces). The DEK is wrapped under the same cascade chain
        via wrap_dek_cascade(), so the wrapped_dek is present and the cascade
        layer must use real 24-byte nonces (xchacha_nonce_format == 2), never the
        legacy 12-byte format. Guards against either feature silently degrading
        when combined.
        """
        meta = self._roundtrip(cascade=True, cipher_names=["aes-256-gcm", "xchacha20-poly1305"])
        enc = meta["encryption"]
        self.assertIn("wrapped_dek", enc, "envelope layer missing for cascade+xchacha")
        self.assertEqual(
            enc.get("xchacha_nonce_format"),
            2,
            "cascade xchacha layer must use real 192-bit nonces, not legacy format",
        )

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


class TestEnvelopeRekeyFastPath(unittest.TestCase):
    """Cycle 5c: the O(header) envelope rekey fast-path.

    A pure credential rotation must rewrap the DEK and retain the bulk
    ciphertext VERBATIM: same payload bytes, new password decrypts, old
    password fails. This simultaneously proves the 5b AAD wiring (the retained
    ciphertext only authenticates because envelope_aad excluded the rolled
    fields) and the KEK derivation in both directions.
    """

    PW_OLD = b"old-rekey-password"
    PW_NEW = b"new-rekey-password-different"

    def _payload(self, path):
        with open(path, "rb") as f:
            return f.read().partition(b":")[2]

    def _encrypt(self, data, **kw):
        ip = _tmp(data)
        op = _tmp()
        base = dict(
            input_file=ip,
            output_file=op,
            password=self.PW_OLD,
            hash_config=dict(_FAST_HASH),
            quiet=True,
            envelope=True,
        )
        base.update(kw)
        try:
            self.assertTrue(encrypt_file(**base))
        finally:
            os.unlink(ip)
        return op

    def _assert_fast_rekey(self, data, **enc_kw):
        op = self._encrypt(data, **enc_kw)
        rp = _tmp()
        try:
            payload_before = self._payload(op)
            self.assertTrue(
                rekey_file(
                    input_file=op,
                    output_file=rp,
                    old_password=self.PW_OLD,
                    new_password=self.PW_NEW,
                    quiet=True,
                )
            )
            # Bulk ciphertext retained verbatim (the whole point of the fast-path).
            self.assertEqual(self._payload(rp), payload_before)
            # New password decrypts to the original plaintext.
            self.assertEqual(
                decrypt_file(input_file=rp, output_file=None, password=self.PW_NEW, quiet=True),
                data,
            )
            # Old password no longer unwraps.
            with self.assertRaises(Exception):
                decrypt_file(input_file=rp, output_file=None, password=self.PW_OLD, quiet=True)
        finally:
            for p in (op, rp):
                if os.path.exists(p):
                    os.unlink(p)

    def test_rekey_oneshot_aes_gcm(self):
        """One-shot v10 envelope file: fast-path retains ciphertext."""
        self._assert_fast_rekey(secrets.token_bytes(4096), algorithm="aes-gcm")

    def test_rekey_streaming_v12(self):
        """Streaming v12 envelope file (independent-XOR KEK): fast-path works."""
        self._assert_fast_rekey(
            secrets.token_bytes(8 * 1024),
            algorithm="aes-gcm",
            chunk_size=1024,
            streaming_threshold=1024,
        )

    def test_rekey_cascade(self):
        """Cascade envelope file: fast-path retains the cascade ciphertext."""
        self._assert_fast_rekey(
            secrets.token_bytes(4096),
            algorithm="cascade",
            cascade=True,
            cipher_names=["aes-256-gcm", "chacha20-poly1305"],
        )

    def test_rekey_in_place(self):
        """In-place fast rekey (output_file=None) rewrites the same file."""
        data = secrets.token_bytes(2048)
        op = self._encrypt(data, algorithm="aes-gcm")
        try:
            payload_before = self._payload(op)
            self.assertTrue(
                rekey_file(
                    input_file=op,
                    output_file=None,
                    old_password=self.PW_OLD,
                    new_password=self.PW_NEW,
                    quiet=True,
                )
            )
            self.assertEqual(self._payload(op), payload_before)
            self.assertEqual(
                decrypt_file(input_file=op, output_file=None, password=self.PW_NEW, quiet=True),
                data,
            )
        finally:
            if os.path.exists(op):
                os.unlink(op)

    def test_wrong_old_password_raises(self):
        """A wrong old password must raise, not silently fall back/corrupt."""
        op = self._encrypt(secrets.token_bytes(2048), algorithm="aes-gcm")
        rp = _tmp()
        try:
            with self.assertRaises(Exception):
                rekey_file(
                    input_file=op,
                    output_file=rp,
                    old_password=b"wrong-password",
                    new_password=self.PW_NEW,
                    quiet=True,
                )
        finally:
            for p in (op, rp):
                if os.path.exists(p):
                    os.unlink(p)

    def test_nonenvelope_rekey_full_reencrypt(self):
        """Non-envelope files fall back to full re-encrypt (payload changes)."""
        data = secrets.token_bytes(4096)
        ip = _tmp(data)
        op = _tmp()
        self.assertTrue(
            encrypt_file(
                input_file=ip,
                output_file=op,
                password=self.PW_OLD,
                hash_config=dict(_FAST_HASH),
                quiet=True,
                algorithm="aes-gcm",
            )  # NO envelope
        )
        os.unlink(ip)
        rp = _tmp()
        try:
            payload_before = self._payload(op)
            self.assertTrue(
                rekey_file(
                    input_file=op,
                    output_file=rp,
                    old_password=self.PW_OLD,
                    new_password=self.PW_NEW,
                    quiet=True,
                )
            )
            # Full re-encrypt → fresh DEK/nonce → payload differs.
            self.assertNotEqual(self._payload(rp), payload_before)
            self.assertEqual(
                decrypt_file(input_file=rp, output_file=None, password=self.PW_NEW, quiet=True),
                data,
            )
        finally:
            for p in (op, rp):
                if os.path.exists(p):
                    os.unlink(p)


def _rewrite_metadata(path, mutate):
    """Parse a file's metadata header, apply ``mutate(meta)``, rewrite the file
    with the SAME payload. Models an attacker editing the (unencrypted) header.
    """
    with open(path, "rb") as f:
        raw = f.read()
    mb64, sep, payload = raw.partition(b":")
    meta = json.loads(base64.b64decode(mb64))
    mutate(meta)
    with open(path, "wb") as f:
        f.write(base64.b64encode(json.dumps(meta).encode("utf-8")) + b":" + payload)


class TestEnvelopeAdversarial(unittest.TestCase):
    """Cycle 5d: adversarial matrix for envelope mode (Option A).

    Confirms the security properties are fail-closed: mode-confusion (add/remove
    wrapped_dek), cross-file wrapped_dek swap, and tampering an authenticated
    (included) metadata field. The 'tamper encrypted_at' case is the clean
    end-to-end proof that envelope_aad is actually enforced -- encrypted_at
    affects neither the key nor the content hash, so only the AEAD binding can
    reject it.
    """

    PW = b"adversarial-envelope-pw"

    def _enc_envelope(self, data=None, **kw):
        data = secrets.token_bytes(4096) if data is None else data
        ip = _tmp(data)
        op = _tmp()
        base = dict(
            input_file=ip,
            output_file=op,
            password=self.PW,
            hash_config=dict(_FAST_HASH),
            quiet=True,
            envelope=True,
            algorithm="aes-gcm",
        )
        base.update(kw)
        try:
            self.assertTrue(encrypt_file(**base))
        finally:
            os.unlink(ip)
        return op, data

    def _enc_plain(self, data=None):
        data = secrets.token_bytes(4096) if data is None else data
        ip = _tmp(data)
        op = _tmp()
        try:
            self.assertTrue(
                encrypt_file(
                    input_file=ip,
                    output_file=op,
                    password=self.PW,
                    hash_config=dict(_FAST_HASH),
                    quiet=True,
                    algorithm="aes-gcm",
                )
            )
        finally:
            os.unlink(ip)
        return op, data

    def _decrypts_ok(self, path, data):
        self.assertEqual(
            decrypt_file(input_file=path, output_file=None, password=self.PW, quiet=True), data
        )

    def test_strip_wrapped_dek_fails_closed(self):
        """Removing wrapped_dek (force non-envelope interpretation) must fail."""
        op, data = self._enc_envelope()
        try:
            self._decrypts_ok(op, data)  # sanity: baseline works
            _rewrite_metadata(op, lambda m: m["encryption"].pop("wrapped_dek", None))
            with self.assertRaises(Exception):
                decrypt_file(input_file=op, output_file=None, password=self.PW, quiet=True)
        finally:
            os.unlink(op)

    def test_inject_wrapped_dek_into_plain_file_fails_closed(self):
        """Adding a wrapped_dek to a non-envelope file must fail (wrong key)."""
        env_op, _ = self._enc_envelope()
        plain_op, _ = self._enc_plain()
        try:
            with open(env_op, "rb") as f:
                env_meta = json.loads(base64.b64decode(f.read().partition(b":")[0]))
            stolen = env_meta["encryption"]["wrapped_dek"]
            _rewrite_metadata(
                plain_op,
                lambda m: m.setdefault("encryption", {}).__setitem__("wrapped_dek", stolen),
            )
            with self.assertRaises(Exception):
                decrypt_file(input_file=plain_op, output_file=None, password=self.PW, quiet=True)
        finally:
            for p in (env_op, plain_op):
                os.path.exists(p) and os.unlink(p)

    def test_cross_file_wrapped_dek_swap_fails_closed(self):
        """Swapping wrapped_dek between two same-password envelope files fails."""
        op_a, _ = self._enc_envelope(data=secrets.token_bytes(4096))
        op_b, data_b = self._enc_envelope(data=secrets.token_bytes(4096))
        try:
            with open(op_a, "rb") as f:
                dek_a = json.loads(base64.b64decode(f.read().partition(b":")[0]))["encryption"][
                    "wrapped_dek"
                ]
            # Put A's wrapped DEK into B: unwraps to DEK_A, but B's bulk is DEK_B.
            _rewrite_metadata(op_b, lambda m: m["encryption"].__setitem__("wrapped_dek", dek_a))
            with self.assertRaises(Exception):
                decrypt_file(input_file=op_b, output_file=None, password=self.PW, quiet=True)
        finally:
            for p in (op_a, op_b):
                os.path.exists(p) and os.unlink(p)

    def test_tamper_authenticated_field_fails_closed(self):
        """Tampering an included field (encrypted_at) is rejected by envelope_aad.

        encrypted_at affects neither the KEK/DEK nor the content hash, so the
        ONLY thing that can reject this change is the bulk AEAD binding.
        """
        op, data = self._enc_envelope()
        try:
            self._decrypts_ok(op, data)
            _rewrite_metadata(op, lambda m: m.__setitem__("encrypted_at", "1999-01-01T00:00:00Z"))
            with self.assertRaises(Exception):
                decrypt_file(input_file=op, output_file=None, password=self.PW, quiet=True)
        finally:
            os.unlink(op)

    def test_tamper_excluded_field_does_not_break_aad(self):
        """Editing an EXCLUDED field (wrapped_dek) is not an AAD violation.

        It fails at the DEK-unwrap step instead (the key path), proving the
        field is genuinely outside the bulk AAD -- the complement of the test
        above. (Either way it fails closed; here we assert it still fails.)
        """
        op, data = self._enc_envelope()
        try:
            # Corrupt one base64 char of wrapped_dek -> unwrap (AES-GCM) fails.
            def corrupt(m):
                w = m["encryption"]["wrapped_dek"]
                m["encryption"]["wrapped_dek"] = ("A" if w[0] != "A" else "B") + w[1:]

            _rewrite_metadata(op, corrupt)
            with self.assertRaises(Exception):
                decrypt_file(input_file=op, output_file=None, password=self.PW, quiet=True)
        finally:
            os.unlink(op)


class TestEnvelopeCascadeWrap(unittest.TestCase):
    """Cycle 5d-2: cascade-match DEK wrap.

    When the bulk is a cascade chain, the DEK is wrapped under the SAME chain so
    the envelope is never the weak link (breaking the wrap requires breaking
    every layer, matching the bulk's guarantee) -- not reduced to single AES-GCM.
    """

    CHAIN = ["aes-256-gcm", "chacha20-poly1305"]

    def test_cascade_wrap_roundtrip(self):
        kek = secrets.token_bytes(32)
        dek = bytes(generate_dek())
        wrapped = wrap_dek_cascade(dek, kek, self.CHAIN)
        self.assertEqual(bytes(unwrap_dek_cascade(wrapped, kek, self.CHAIN)), dek)

    def test_cascade_wrap_is_not_single_gcm(self):
        """Cascade wrap differs from (and is larger than) the 60-byte AES-GCM wrap."""
        kek = secrets.token_bytes(32)
        dek = bytes(generate_dek())
        casc = wrap_dek_cascade(dek, kek, self.CHAIN)
        gcm = wrap_dek(dek, kek)
        self.assertNotEqual(casc, gcm)
        self.assertGreater(len(casc), len(gcm))  # multi-layer overhead
        self.assertNotIn(dek, casc)

    def test_cascade_wrap_wrong_kek_fails(self):
        kek = secrets.token_bytes(32)
        dek = bytes(generate_dek())
        wrapped = wrap_dek_cascade(dek, kek, self.CHAIN)
        with self.assertRaises(Exception):
            unwrap_dek_cascade(wrapped, secrets.token_bytes(32), self.CHAIN)

    def test_cascade_wrap_wrong_chain_fails(self):
        """Unwrapping with a different chain must fail (chain is authenticated)."""
        kek = secrets.token_bytes(32)
        dek = bytes(generate_dek())
        wrapped = wrap_dek_cascade(dek, kek, self.CHAIN)
        with self.assertRaises(Exception):
            unwrap_dek_cascade(wrapped, kek, ["chacha20-poly1305", "aes-256-gcm"])

    def test_cascade_envelope_file_uses_cascade_wrap(self):
        """An end-to-end cascade envelope file stores a cascade-wrapped DEK
        (longer than the 60-byte AES-GCM wrap), proving the wrap is matched."""
        data = secrets.token_bytes(4096)
        ip = _tmp(data)
        op = _tmp()
        try:
            self.assertTrue(
                encrypt_file(
                    input_file=ip,
                    output_file=op,
                    password=b"cascade-wrap-pw",
                    hash_config=dict(_FAST_HASH),
                    quiet=True,
                    envelope=True,
                    algorithm="cascade",
                    cascade=True,
                    cipher_names=self.CHAIN,
                )
            )
            meta = _read_metadata(op)
            wrapped = base64.b64decode(meta["encryption"]["wrapped_dek"])
            self.assertGreater(len(wrapped), 12 + DEK_SIZE + 16)  # not single AES-GCM
            self.assertEqual(
                decrypt_file(
                    input_file=op, output_file=None, password=b"cascade-wrap-pw", quiet=True
                ),
                data,
            )
        finally:
            for p in (ip, op):
                if os.path.exists(p):
                    os.unlink(p)


class _RecordingHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        try:
            self.records.append(self.format(record))
        except Exception:
            self.records.append(str(record.msg))


class TestEnvelopeKeyHygiene(unittest.TestCase):
    """Cycle 7: key-material hygiene for envelope mode.

    The DEK is zeroed in place on every path; key material never reaches normal
    logs/output or exception messages. (The secure_memzero calls already exist
    in the code; these tests prove the resulting properties.)
    """

    PW = b"hygiene-envelope-pw"
    # Distinctive sentinel DEK so any leak is unmistakable.
    SENTINEL = bytes.fromhex("deadbeef" * 8)

    def _sentinel_dek_factory(self, captured):
        def factory():
            buf = bytearray(self.SENTINEL)
            captured.append(buf)  # keep a reference to inspect after wiping
            return buf

        return factory

    def _leak_forms(self):
        return [self.SENTINEL.hex(), base64.b64encode(self.SENTINEL).decode(), str(self.SENTINEL)]

    def test_dek_zeroized_in_place_after_encrypt(self):
        """The DEK bytearray is securely zeroed after encryption."""
        captured = []
        ip = _tmp(secrets.token_bytes(2048))
        op = _tmp()
        try:
            with mock.patch.object(
                envelope_mod, "generate_dek", self._sentinel_dek_factory(captured)
            ):
                self.assertTrue(
                    encrypt_file(
                        input_file=ip,
                        output_file=op,
                        password=self.PW,
                        hash_config=dict(_FAST_HASH),
                        quiet=True,
                        envelope=True,
                        algorithm="aes-gcm",
                    )
                )
            self.assertEqual(len(captured), 1)
            self.assertEqual(bytes(captured[0]), b"\x00" * DEK_SIZE)  # wiped
        finally:
            for p in (ip, op):
                os.path.exists(p) and os.unlink(p)

    def test_dek_zeroized_in_place_after_decrypt(self):
        """The unwrapped DEK bytearray is zeroed after decryption."""
        ip = _tmp(secrets.token_bytes(2048))
        op = _tmp()
        captured = []
        real_unwrap = envelope_mod.unwrap_dek

        def spy(wrapped, kek):
            r = real_unwrap(wrapped, kek)
            captured.append(r)
            return r

        try:
            self.assertTrue(
                encrypt_file(
                    input_file=ip,
                    output_file=op,
                    password=self.PW,
                    hash_config=dict(_FAST_HASH),
                    quiet=True,
                    envelope=True,
                    algorithm="aes-gcm",
                )
            )
            with mock.patch.object(envelope_mod, "unwrap_dek", spy):
                decrypt_file(input_file=op, output_file=None, password=self.PW, quiet=True)
            self.assertEqual(len(captured), 1)
            self.assertEqual(bytes(captured[0]), b"\x00" * DEK_SIZE)  # wiped
        finally:
            for p in (ip, op):
                os.path.exists(p) and os.unlink(p)

    def test_dek_zeroized_after_rekey_fast_path(self):
        """Both the unwrapped DEK is zeroed after the rekey fast-path."""
        ip = _tmp(secrets.token_bytes(2048))
        op = _tmp()
        rp = _tmp()
        captured = []
        real_unwrap = envelope_mod.unwrap_dek

        def spy(wrapped, kek):
            r = real_unwrap(wrapped, kek)
            captured.append(r)
            return r

        try:
            encrypt_file(
                input_file=ip,
                output_file=op,
                password=self.PW,
                hash_config=dict(_FAST_HASH),
                quiet=True,
                envelope=True,
                algorithm="aes-gcm",
            )
            with mock.patch.object(envelope_mod, "unwrap_dek", spy):
                self.assertTrue(
                    rekey_file(
                        input_file=op,
                        output_file=rp,
                        old_password=self.PW,
                        new_password=b"new-hygiene-pw",
                        quiet=True,
                    )
                )
            self.assertTrue(captured)
            for buf in captured:
                self.assertEqual(bytes(buf), b"\x00" * DEK_SIZE)
        finally:
            for p in (ip, op, rp):
                os.path.exists(p) and os.unlink(p)

    def test_no_key_material_in_normal_logs_or_output(self):
        """Normal (non-debug) envelope encrypt+decrypt must not emit the DEK."""
        captured = []
        handler = _RecordingHandler()
        root = logging.getLogger()
        root.addHandler(handler)
        old_level = root.level
        root.setLevel(logging.DEBUG)
        ip = _tmp(secrets.token_bytes(2048))
        op = _tmp()
        out, err = io.StringIO(), io.StringIO()
        try:
            with mock.patch.object(
                envelope_mod, "generate_dek", self._sentinel_dek_factory(captured)
            ), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                encrypt_file(
                    input_file=ip,
                    output_file=op,
                    password=self.PW,
                    hash_config=dict(_FAST_HASH),
                    quiet=False,
                    envelope=True,
                    algorithm="aes-gcm",
                )  # NOTE: debug=False — debug mode intentionally dumps crypto internals
                decrypt_file(input_file=op, output_file=None, password=self.PW, quiet=False)
            blob = "\n".join(handler.records) + out.getvalue() + err.getvalue()
            for form in self._leak_forms():
                self.assertNotIn(form, blob, "key material leaked to logs/output")
        finally:
            root.removeHandler(handler)
            root.setLevel(old_level)
            for p in (ip, op):
                os.path.exists(p) and os.unlink(p)

    def test_no_key_material_in_unwrap_exception(self):
        """A failed unwrap (wrong KEK) must not leak key material in its message."""
        kek = secrets.token_bytes(32)
        dek = bytes(generate_dek())
        wrapped = wrap_dek(dek, kek)
        try:
            unwrap_dek(wrapped, secrets.token_bytes(32))
            self.fail("expected unwrap to raise")
        except Exception as e:
            msg = f"{e} {getattr(e, 'args', '')}"
            self.assertNotIn(dek.hex(), msg)
            self.assertNotIn(kek.hex(), msg)


class TestEnvelopeCrossVersionXChaCha(unittest.TestCase):
    """Forward-compat: 1.5.x must decrypt 1.4.x envelope+cascade+xchacha files.

    1.4.x writes xchacha with a 12-byte legacy nonce and NO
    ``xchacha_nonce_format`` flag, and wraps the DEK under the same cascade chain
    in that legacy format. The bulk decrypt path already defaults an absent flag
    to legacy (1); the envelope DEK-unwrap must do the same instead of assuming
    the new 192-bit format (2), or the DEK can never be recovered and the file is
    permanently undecryptable after upgrading 1.4.x -> 1.5.x.

    The fixture is a genuine file produced by the feature/v1.4.x-development
    code, committed verbatim so the guarantee cannot silently drift.
    """

    _FIX_DIR = os.path.join(os.path.dirname(__file__), "testfiles", "envelope_xchacha_v14")
    VECTOR = os.path.join(_FIX_DIR, "envelope_cascade_xchacha_v14.enc")
    PLAINTEXT = os.path.join(_FIX_DIR, "plaintext.bin")
    PASSWORD = b"envelope-xchacha-cross-version-1.4.x"

    def test_vector_has_legacy_shape(self):
        """Guard the fixture itself: no nonce-format flag, but envelope+cascade."""
        meta = _read_metadata(self.VECTOR)
        enc = meta["encryption"]
        self.assertNotIn("xchacha_nonce_format", enc, "fixture is not a legacy (1.4.x) file")
        self.assertIn("wrapped_dek", enc)
        self.assertTrue(enc.get("cascade"))
        self.assertIn("xchacha20-poly1305", enc.get("cipher_chain", []))

    def test_1_4_x_envelope_xchacha_decrypts(self):
        """Regression: the 1.4.x golden vector decrypts on the current code."""
        with open(self.PLAINTEXT, "rb") as f:
            expected = f.read()
        decrypted = decrypt_file(
            input_file=self.VECTOR, output_file=None, password=self.PASSWORD, quiet=True
        )
        self.assertEqual(decrypted, expected)


if __name__ == "__main__":
    unittest.main()
