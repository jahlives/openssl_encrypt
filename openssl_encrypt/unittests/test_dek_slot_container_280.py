#!/usr/bin/env python3
"""Crafted dek_slots container shapes fail uniformly as ValidationError (gitlab#280).

list_recovery_slots grew container-shape validation in gitlab#278, but the
two sibling readers of the same untrusted header structure —
add_recovery_slots and remove_recovery_slot — still hit raw internal
AttributeErrors on the same crafted files (a string `encryption` section, a
string `dek_slots` whose list() yields characters, a non-dict slot entry).
Those paths are password-gated and the CLI sanitizes the message, so the
impact was internal-shape disclosure in an error string and an inconsistent
failure mode for the same crafted file. All three readers now share
_validated_slot_container, so the failure is a uniform ValidationError.
"""

import unittest
from unittest import mock

import openssl_encrypt.modules.crypt_core as cc
from openssl_encrypt.modules.crypt_errors import ValidationError

# The same shapes test_list_recovery_shamir_278.py pins for the listing.
MALFORMED = (
    {"encryption": "x"},
    {"encryption": ["x"]},
    {"encryption": {"dek_slots": "abc"}},
    {"encryption": {"dek_slots": {"a": 1}}},
    {"encryption": {"dek_slots": [1]}},
    {"encryption": {"dek_slots": [{"id": "a", "type": "recovery_code"}, None]}},
)


def _fake_unwrap(meta, password, allow_high_kdf_cost):
    return bytearray(32), (lambda n: "AAAA"), (lambda: None)


class TestRemovePathContainerShapes(unittest.TestCase):
    def test_malformed_containers_raise_validation_error(self):
        for meta in MALFORMED:
            with mock.patch.object(cc, "_read_envelope_file", return_value=(meta, b"")):
                with self.assertRaises(ValidationError, msg=meta):
                    cc.remove_recovery_slot("in.enc", None, "slot-1", password=b"pw")

    def test_missing_slot_id_still_reports_cleanly(self):
        """The refactor must keep the no-such-slot error on valid shapes."""
        meta = {"encryption": {"dek_slots": [{"id": "a", "type": "recovery_code"}]}}
        with mock.patch.object(cc, "_read_envelope_file", return_value=(meta, b"")):
            with self.assertRaises(ValidationError):
                cc.remove_recovery_slot("in.enc", None, "no-such-slot", password=b"pw")


class TestAddPathContainerShapes(unittest.TestCase):
    def test_malformed_containers_raise_validation_error(self):
        for meta in MALFORMED:
            with (
                mock.patch.object(cc, "_read_envelope_file", return_value=(meta, b"")),
                mock.patch.object(cc, "_password_unwrap_and_rewrapper", side_effect=_fake_unwrap),
            ):
                with self.assertRaises(ValidationError, msg=meta):
                    cc.add_recovery_slots("in.enc", None, [], password=b"pw")

    def test_malformed_containers_fail_before_password_consumption(self):
        """A crafted container must be refused before the password is used.

        Mirrors the gitlab#277 principle: validation failures on
        attacker-authored input come before any credential is consumed, so
        a scripted caller keeps its password sources intact.
        """
        for meta in MALFORMED:
            with (
                mock.patch.object(cc, "_read_envelope_file", return_value=(meta, b"")),
                mock.patch.object(
                    cc, "_password_unwrap_and_rewrapper", side_effect=AssertionError
                ) as unwrap,
            ):
                with self.assertRaises(ValidationError, msg=meta):
                    cc.add_recovery_slots("in.enc", None, [], password=b"pw")
                unwrap.assert_not_called()


if __name__ == "__main__":
    unittest.main()
