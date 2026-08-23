#!/usr/bin/env python3
"""remove-recovery ambiguity and long-id revocation (gitlab#256, F5+F6).

F5: the removal filter dropped ALL slots sharing an id, so a crafted file
with N slots under one id silently revoked N slots after a dialog promising
one. It now refuses ambiguous matches with ValidationError, BEFORE the
password is consumed.

F6: the credential-free listing truncates ids to 256 chars while removal
matched the full stored id exactly, so a planted >256-char id was
unrevocable through any documented interface. The listing now marks the
truncation (``id_truncated: true`` under SLOT_DOC_KEYS), and removal accepts
the 256-char truncated form when it unambiguously identifies one slot.
"""

import unittest
from unittest import mock

import openssl_encrypt.modules.crypt_core as cc
from openssl_encrypt.modules.crypt_errors import ValidationError
from openssl_encrypt.modules.recovery_slots import SLOT_DOC_KEYS, _slot_doc


def _meta(slots):
    """Envelope-shaped metadata carrying the given dek_slots list."""
    return {"encryption": {"dek_slots": slots, "dek_slot_count": len(slots)}}


def _fake_unwrap(meta, password, allow_high_kdf_cost):
    return bytearray(32), (lambda n: "AAAA"), (lambda: None)


class TestDuplicateIdRefused(unittest.TestCase):
    """F5: >1 matching slot refuses instead of revoking all matches."""

    def test_duplicate_id_raises_before_password_use(self):
        """Ambiguity is refused, and before any credential is consumed."""
        meta = _meta(
            [
                {"id": "dup", "type": "recovery_code"},
                {"id": "dup", "type": "passphrase"},
                {"id": "other", "type": "recovery_code"},
            ]
        )
        with (
            mock.patch.object(cc, "_read_envelope_file", return_value=(meta, b"")),
            mock.patch.object(
                cc,
                "_password_unwrap_and_rewrapper",
                side_effect=AssertionError("password consumed on ambiguous input"),
            ),
        ):
            with self.assertRaises(ValidationError) as ctx:
                cc.remove_recovery_slot("in.enc", None, "dup", password=b"pw")
        self.assertIn("2", str(ctx.exception))

    def test_unique_id_still_removes(self):
        """The normal one-match removal keeps working end to end."""
        meta = _meta(
            [
                {"id": "keep", "type": "recovery_code"},
                {"id": "gone", "type": "recovery_code"},
            ]
        )
        written = {}

        def _capture(m, payload, infile, outfile):
            written["slots"] = m["encryption"]["dek_slots"]

        with (
            mock.patch.object(cc, "_read_envelope_file", return_value=(meta, b"")),
            mock.patch.object(cc, "_password_unwrap_and_rewrapper", side_effect=_fake_unwrap),
            mock.patch.object(cc, "_write_envelope_header", side_effect=_capture),
            mock.patch("openssl_encrypt.modules.envelope.envelope_aad", return_value=b"same"),
        ):
            self.assertTrue(cc.remove_recovery_slot("in.enc", None, "gone", password=b"pw"))
        self.assertEqual([s["id"] for s in written["slots"]], ["keep"])


class TestLongIdRevocation(unittest.TestCase):
    """F6: >256-char ids are revocable via their truncated listing form."""

    LONG_A = "A" * 300
    LONG_B = "A" * 256 + "B" * 44  # same 256-char prefix as LONG_A

    def test_listing_marks_truncated_id(self):
        """The --json slot doc flags the truncation in-band."""
        doc = _slot_doc({"id": self.LONG_A, "type": "recovery_code"})
        self.assertEqual(doc["id"], "A" * 256)
        self.assertTrue(doc.get("id_truncated"))
        self.assertIn("id_truncated", SLOT_DOC_KEYS)

    def test_short_id_has_no_truncation_flag(self):
        """Normal ids must not grow a misleading flag."""
        doc = _slot_doc({"id": "normal", "type": "recovery_code"})
        self.assertNotIn("id_truncated", doc)

    def test_truncated_form_removes_the_long_id_slot(self):
        """Removal accepts the 256-char listed form for a >256-char id."""
        meta = _meta(
            [
                {"id": self.LONG_A, "type": "recovery_code"},
                {"id": "keep", "type": "recovery_code"},
            ]
        )
        written = {}

        def _capture(m, payload, infile, outfile):
            written["slots"] = m["encryption"]["dek_slots"]

        with (
            mock.patch.object(cc, "_read_envelope_file", return_value=(meta, b"")),
            mock.patch.object(cc, "_password_unwrap_and_rewrapper", side_effect=_fake_unwrap),
            mock.patch.object(cc, "_write_envelope_header", side_effect=_capture),
            mock.patch("openssl_encrypt.modules.envelope.envelope_aad", return_value=b"same"),
        ):
            self.assertTrue(cc.remove_recovery_slot("in.enc", None, "A" * 256, password=b"pw"))
        self.assertEqual([s["id"] for s in written["slots"]], ["keep"])

    def test_colliding_truncated_prefixes_are_ambiguous(self):
        """Two long ids sharing the 256-char prefix refuse, never revoke both."""
        meta = _meta(
            [
                {"id": self.LONG_A, "type": "recovery_code"},
                {"id": self.LONG_B, "type": "recovery_code"},
            ]
        )
        with (
            mock.patch.object(cc, "_read_envelope_file", return_value=(meta, b"")),
            mock.patch.object(
                cc,
                "_password_unwrap_and_rewrapper",
                side_effect=AssertionError("password consumed on ambiguous input"),
            ),
        ):
            with self.assertRaises(ValidationError):
                cc.remove_recovery_slot("in.enc", None, "A" * 256, password=b"pw")

    def test_exact_long_id_still_matches(self):
        """Passing the FULL >256-char id keeps working (exact match wins)."""
        meta = _meta(
            [
                {"id": self.LONG_A, "type": "recovery_code"},
                {"id": "keep", "type": "recovery_code"},
            ]
        )
        written = {}

        def _capture(m, payload, infile, outfile):
            written["slots"] = m["encryption"]["dek_slots"]

        with (
            mock.patch.object(cc, "_read_envelope_file", return_value=(meta, b"")),
            mock.patch.object(cc, "_password_unwrap_and_rewrapper", side_effect=_fake_unwrap),
            mock.patch.object(cc, "_write_envelope_header", side_effect=_capture),
            mock.patch("openssl_encrypt.modules.envelope.envelope_aad", return_value=b"same"),
        ):
            self.assertTrue(cc.remove_recovery_slot("in.enc", None, self.LONG_A, password=b"pw"))
        self.assertEqual([s["id"] for s in written["slots"]], ["keep"])
