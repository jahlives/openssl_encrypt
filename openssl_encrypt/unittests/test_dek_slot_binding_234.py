#!/usr/bin/env python3
"""
Recovery-slot presence must be authenticated so an attacker cannot silently
strip recovery slots from an envelope header (F17/F18, gitlab#234, CWE-354/347).

Root cause: ``encryption.dek_slots`` / ``dek_slots_mac`` are excluded from the
bulk AEAD AAD (so slots can be managed without re-encrypting the bulk), and the
slot-set MAC is only checked when slots are *present* -- so deleting both fields
wholesale needs no key and the password decrypt path proceeds as if the file
never had recovery slots.

Fix (Option B -- wrapped_dek AAD binding): the DEK wrap is bound to an
``encryption.dek_slot_count`` commitment via its AEAD associated data. Because
the wrapped_dek ciphertext cannot be recomputed without the password KEK, and
decrypt deterministically uses ``wrapped_dek_aad(count)`` when the field is
present (and ``None`` when absent, with no fallback), an attacker cannot strip
the slots, zero the count, or downgrade the file without the password unwrap
failing closed. dek_slot_count is EXCLUDED from the bulk AAD, so legitimate slot
add/remove stays an O(header) header rewrite. Trade-off (accepted): slot
management now requires the primary password (re-wrapping wrapped_dek needs the
KEK), not merely a recovery credential.
"""

import base64
import json
import os
import tempfile
import unittest

from openssl_encrypt.modules import envelope as _env
from openssl_encrypt.modules.crypt_core import (
    add_recovery_slots,
    decrypt_file,
    encrypt_file,
    list_recovery_slots,
    remove_recovery_slot,
)
from openssl_encrypt.modules.crypt_errors import (
    AuthenticationError,
    DecryptionError,
    ValidationError,
)
from openssl_encrypt.modules.recovery_slots import generate_recovery_code

PASSWORD = b"primary-password-correct-horse-9"
PLAINTEXT = b"dek-slot-binding round-trip payload, several blocks long.\n" * 8

_FAIL = (DecryptionError, AuthenticationError, ValidationError)


def _encrypt(**kwargs) -> bytes:
    params = dict(
        input_file=PLAINTEXT,
        output_file=None,
        password=PASSWORD,
        algorithm="aes-gcm",
        quiet=True,
    )
    params.update(kwargs)
    return encrypt_file(**params)


def _parse_meta(file_bytes: bytes) -> dict:
    return json.loads(base64.b64decode(file_bytes.split(b":", 1)[0]))


def _rewrite_meta(file_bytes: bytes, meta: dict) -> bytes:
    payload = file_bytes.split(b":", 1)[1]
    return base64.b64encode(json.dumps(meta).encode("utf-8")) + b":" + payload


def _to_path(file_bytes: bytes) -> str:
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "wb") as f:
        f.write(file_bytes)
    return path


def _decrypt(file_bytes: bytes, **kwargs):
    path = _to_path(file_bytes)
    try:
        params = dict(input_file=path, output_file=None, quiet=True)
        params.update(kwargs)
        return decrypt_file(**params)
    finally:
        os.unlink(path)


# --------------------------------------------------------------------------- #
# 1. envelope.py primitive: the AAD binding
# --------------------------------------------------------------------------- #
class TestWrappedDekAadPrimitive(unittest.TestCase):
    def setUp(self):
        self.dek = os.urandom(32)
        self.kek = os.urandom(32)

    def test_none_count_yields_none_aad(self):
        self.assertIsNone(_env.wrapped_dek_aad(None))

    def test_roundtrip_with_matching_aad(self):
        aad = _env.wrapped_dek_aad(2)
        self.assertIsNotNone(aad)
        wrapped = _env.wrap_dek(self.dek, self.kek, aad=aad)
        self.assertEqual(bytes(_env.unwrap_dek(wrapped, self.kek, aad=aad)), self.dek)

    def test_unwrap_with_wrong_count_aad_fails(self):
        wrapped = _env.wrap_dek(self.dek, self.kek, aad=_env.wrapped_dek_aad(2))
        with self.assertRaises(_FAIL):
            _env.unwrap_dek(wrapped, self.kek, aad=_env.wrapped_dek_aad(3))

    def test_bound_wrap_does_not_unwrap_as_legacy(self):
        # A file wrapped WITH a count binding must not unwrap under aad=None:
        # that is exactly the downgrade attack.
        wrapped = _env.wrap_dek(self.dek, self.kek, aad=_env.wrapped_dek_aad(1))
        with self.assertRaises(_FAIL):
            _env.unwrap_dek(wrapped, self.kek, aad=None)

    def test_legacy_none_aad_roundtrip_preserved(self):
        # Backward-compat: the pre-fix call shape (no aad) still round-trips.
        wrapped = _env.wrap_dek(self.dek, self.kek)
        self.assertEqual(bytes(_env.unwrap_dek(wrapped, self.kek)), self.dek)


# --------------------------------------------------------------------------- #
# 2. The vulnerability: stripping / downgrading / tampering fails closed
# --------------------------------------------------------------------------- #
class TestStrippingFailsClosed(unittest.TestCase):
    def _encrypted_with_one_slot(self):
        code = generate_recovery_code()
        enc = _encrypt(
            envelope=True,
            recovery_credentials=[{"type": "recovery_code", "code": code}],
        )
        # sanity: it decrypts both ways before tampering
        self.assertEqual(_decrypt(enc, password=PASSWORD), PLAINTEXT)
        self.assertEqual(_decrypt(enc, recovery_code=code), PLAINTEXT)
        return enc

    def test_strip_slots_keeping_count_fails_password_decrypt(self):
        enc = self._encrypted_with_one_slot()
        meta = _parse_meta(enc)
        del meta["encryption"]["dek_slots"]
        del meta["encryption"]["dek_slots_mac"]
        # dek_slot_count left at 1 -> presence check must fail closed
        tampered = _rewrite_meta(enc, meta)
        with self.assertRaises(_FAIL):
            _decrypt(tampered, password=PASSWORD)

    def test_full_downgrade_removing_count_fails_password_decrypt(self):
        enc = self._encrypted_with_one_slot()
        meta = _parse_meta(enc)
        del meta["encryption"]["dek_slots"]
        del meta["encryption"]["dek_slots_mac"]
        del meta["encryption"]["dek_slot_count"]
        tampered = _rewrite_meta(enc, meta)
        with self.assertRaises(_FAIL):
            _decrypt(tampered, password=PASSWORD)

    def test_tampering_count_value_fails_password_decrypt(self):
        enc = self._encrypted_with_one_slot()
        meta = _parse_meta(enc)
        meta["encryption"]["dek_slot_count"] = 7
        tampered = _rewrite_meta(enc, meta)
        with self.assertRaises(_FAIL):
            _decrypt(tampered, password=PASSWORD)


# --------------------------------------------------------------------------- #
# 3. Correctness: the count is present and files still decrypt
# --------------------------------------------------------------------------- #
class TestMetadataAndRoundTrip(unittest.TestCase):
    def test_plain_envelope_has_zero_count_and_decrypts(self):
        enc = _encrypt(envelope=True)
        meta = _parse_meta(enc)
        self.assertEqual(meta["encryption"].get("dek_slot_count"), 0)
        self.assertEqual(_decrypt(enc, password=PASSWORD), PLAINTEXT)

    def test_inline_recovery_count_matches_slots(self):
        code = generate_recovery_code()
        enc = _encrypt(
            envelope=True,
            recovery_credentials=[{"type": "recovery_code", "code": code}],
        )
        meta = _parse_meta(enc)
        self.assertEqual(meta["encryption"].get("dek_slot_count"), 1)
        self.assertEqual(len(meta["encryption"]["dek_slots"]), 1)
        self.assertEqual(_decrypt(enc, password=PASSWORD), PLAINTEXT)
        self.assertEqual(_decrypt(enc, recovery_code=code), PLAINTEXT)

    def test_count_excluded_from_bulk_aad(self):
        # Changing dek_slot_count must NOT change the bulk AAD (slot ops stay
        # O(header)); the wrapped_dek binding is what authenticates it.
        m = {"encryption": {"algorithm": "aes-gcm", "dek_slot_count": 3, "wrapped_dek": "x"}}
        m2 = {"encryption": {"algorithm": "aes-gcm", "dek_slot_count": 9, "wrapped_dek": "x"}}
        self.assertEqual(_env.envelope_aad(m), _env.envelope_aad(m2))


# --------------------------------------------------------------------------- #
# 4. Slot management: password required, re-tag correct
# --------------------------------------------------------------------------- #
class TestSlotManagement(unittest.TestCase):
    def _write(self, file_bytes):
        return _to_path(file_bytes)

    def test_add_then_decrypt_by_password_and_code(self):
        path = self._write(_encrypt(envelope=True))
        try:
            code = generate_recovery_code()
            add_recovery_slots(
                path, path, [{"type": "recovery_code", "code": code}], password=PASSWORD
            )
            with open(path, "rb") as f:
                enc = f.read()
            self.assertEqual(_parse_meta(enc)["encryption"]["dek_slot_count"], 1)
            self.assertEqual(_decrypt(enc, password=PASSWORD), PLAINTEXT)
            self.assertEqual(_decrypt(enc, recovery_code=code), PLAINTEXT)
        finally:
            os.unlink(path)

    def test_remove_updates_count_and_still_decrypts(self):
        c1, c2 = generate_recovery_code(), generate_recovery_code()
        path = self._write(
            _encrypt(
                envelope=True,
                recovery_credentials=[
                    {"type": "recovery_code", "code": c1},
                    {"type": "recovery_code", "code": c2},
                ],
            )
        )
        try:
            slots = list_recovery_slots(path)
            remove_recovery_slot(path, path, slots[0]["id"], password=PASSWORD)
            with open(path, "rb") as f:
                enc = f.read()
            self.assertEqual(_parse_meta(enc)["encryption"]["dek_slot_count"], 1)
            self.assertEqual(_decrypt(enc, password=PASSWORD), PLAINTEXT)
        finally:
            os.unlink(path)

    def test_remove_last_slot_yields_zero_count_and_decrypts(self):
        code = generate_recovery_code()
        path = self._write(
            _encrypt(
                envelope=True,
                recovery_credentials=[{"type": "recovery_code", "code": code}],
            )
        )
        try:
            slots = list_recovery_slots(path)
            remove_recovery_slot(path, path, slots[0]["id"], password=PASSWORD)
            with open(path, "rb") as f:
                enc = f.read()
            meta = _parse_meta(enc)
            self.assertEqual(meta["encryption"].get("dek_slot_count"), 0)
            self.assertNotIn("dek_slots", meta["encryption"])
            self.assertEqual(_decrypt(enc, password=PASSWORD), PLAINTEXT)
        finally:
            os.unlink(path)

    def test_add_requires_password_not_recovery_credential(self):
        code = generate_recovery_code()
        path = self._write(
            _encrypt(
                envelope=True,
                recovery_credentials=[{"type": "recovery_code", "code": code}],
            )
        )
        try:
            with self.assertRaises(_FAIL):
                add_recovery_slots(
                    path,
                    path,
                    [{"type": "recovery_code", "code": generate_recovery_code()}],
                    recovery_code=code,  # no password -> must be refused
                )
        finally:
            os.unlink(path)

    def test_remove_requires_password_not_recovery_credential(self):
        code = generate_recovery_code()
        path = self._write(
            _encrypt(
                envelope=True,
                recovery_credentials=[{"type": "recovery_code", "code": code}],
            )
        )
        try:
            slots = list_recovery_slots(path)
            with self.assertRaises(_FAIL):
                remove_recovery_slot(path, path, slots[0]["id"], recovery_code=code)
        finally:
            os.unlink(path)

    def test_add_refuses_tampered_incoming_slot_set(self):
        # review F1: a slot change must authenticate the EXISTING set first, not
        # launder a tampered incoming set into a freshly MAC'd, count-bound header.
        code = generate_recovery_code()
        raw = _encrypt(
            envelope=True, recovery_credentials=[{"type": "recovery_code", "code": code}]
        )
        meta = _parse_meta(raw)
        meta["encryption"]["dek_slots_mac"] = base64.b64encode(b"\x00" * 32).decode("ascii")
        path = self._write(_rewrite_meta(raw, meta))
        try:
            with self.assertRaises(_FAIL):
                add_recovery_slots(
                    path,
                    path,
                    [{"type": "recovery_code", "code": generate_recovery_code()}],
                    password=PASSWORD,
                )
        finally:
            os.unlink(path)


# --------------------------------------------------------------------------- #
# 5. Cascade + rekey + backward compat
# --------------------------------------------------------------------------- #
class TestCascadeRekeyLegacy(unittest.TestCase):
    def test_cascade_envelope_binding_and_strip_fails(self):
        code = generate_recovery_code()
        enc = _encrypt(
            algorithm="cascade",
            cascade=True,
            cipher_names=["aes-gcm", "xchacha20-poly1305"],
            envelope=True,
            recovery_credentials=[{"type": "recovery_code", "code": code}],
        )
        self.assertEqual(_decrypt(enc, password=PASSWORD), PLAINTEXT)
        self.assertEqual(_decrypt(enc, recovery_code=code), PLAINTEXT)
        meta = _parse_meta(enc)
        del meta["encryption"]["dek_slots"]
        del meta["encryption"]["dek_slots_mac"]
        with self.assertRaises(_FAIL):
            _decrypt(_rewrite_meta(enc, meta), password=PASSWORD)

    def test_rekey_preserves_slot_binding(self):
        from openssl_encrypt.modules.crypt_core import rekey_file

        code = generate_recovery_code()
        path = _to_path(
            _encrypt(
                envelope=True,
                recovery_credentials=[{"type": "recovery_code", "code": code}],
            )
        )
        new_pw = b"rotated-password-battery-staple-2"
        try:
            rekey_file(path, path, old_password=PASSWORD, new_password=new_pw, quiet=True)
            with open(path, "rb") as f:
                enc = f.read()
            self.assertEqual(_parse_meta(enc)["encryption"].get("dek_slot_count"), 1)
            self.assertEqual(_decrypt(enc, password=new_pw), PLAINTEXT)
            self.assertEqual(_decrypt(enc, recovery_code=code), PLAINTEXT)
        finally:
            os.unlink(path)

    def test_legacy_file_without_count_decrypts(self):
        # Construct a pre-fix legacy envelope: wrapped_dek bound with aad=None and
        # no dek_slot_count field. It must still decrypt (tolerant fallback).
        from openssl_encrypt.modules.crypt_core import _derive_envelope_kek

        enc = _encrypt(envelope=True)
        meta = _parse_meta(enc)
        e = meta["encryption"]
        kek = _derive_envelope_kek(
            PASSWORD,
            meta["derivation_config"],
            e.get("algorithm"),
            meta["format_version"],
            meta.get("xor_mode", "sequential"),
        )
        dek = _env.unwrap_dek(
            base64.b64decode(e["wrapped_dek"]),
            kek,
            aad=_env.wrapped_dek_aad(e.get("dek_slot_count")),
        )
        e["wrapped_dek"] = base64.b64encode(_env.wrap_dek(bytes(dek), kek, aad=None)).decode(
            "ascii"
        )
        e.pop("dek_slot_count", None)
        legacy = _rewrite_meta(enc, meta)
        self.assertEqual(_decrypt(legacy, password=PASSWORD), PLAINTEXT)


if __name__ == "__main__":
    unittest.main()
