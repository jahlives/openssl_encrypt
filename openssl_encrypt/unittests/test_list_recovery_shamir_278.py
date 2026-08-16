#!/usr/bin/env python3
"""list-recovery exposes shamir K-of-N parameters (gitlab#278) — 1.4.x port.

The threshold/num_shares of a shamir slot live in the plaintext envelope
header (encryption.dek_slots[].params.shamir) but were not surfaced by
list-recovery, so a GUI could not show "needs 2 of 3 shares" without parsing
raw metadata itself. On this line shamir slots cannot be *created* (the
secret-sharing module is 1.5.x-only) but 1.5.x-authored files are listable,
so the listing surface and its hardening are ported. The fields are
untrusted header input: they are only passed through when they validate as
ints with 2 <= K <= N <= 255 (the 1.5.x creation invariant), and are
omitted otherwise.
"""

import argparse
import base64
import copy
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from openssl_encrypt.modules.crypt_core import encrypt_file, list_recovery_slots
from openssl_encrypt.modules.recovery_slots import generate_recovery_code, list_recovery_cli

PASSWORD = b"primary-shamir-list-password"
PLAINTEXT = b"shamir listing payload\n" * 4

# A shamir slot as the 1.5.x builder stores it (wrap/salt values are dummies:
# the listing never unwraps).
SHAMIR_SLOT = {
    "id": "shamir-0",
    "type": "shamir",
    "wrap": "AAAA",
    "params": {"salt": "AAAA", "shamir": {"threshold": 2, "num_shares": 3, "key_id": "set-A"}},
}


def _ns(**kw):
    base = dict(input=None, json=False, quiet=True)
    base.update(kw)
    return argparse.Namespace(**base)


class ShamirListingBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.enc = os.path.join(self.tmp, "file.enc")

    def tearDown(self):
        for root, dirs, files in os.walk(self.tmp, topdown=False):
            for f in files:
                os.unlink(os.path.join(root, f))
            for d in dirs:
                os.rmdir(os.path.join(root, d))
        os.rmdir(self.tmp)

    def _write_envelope_with_code_slot(self):
        data = encrypt_file(
            input_file=PLAINTEXT,
            output_file=None,
            password=PASSWORD,
            algorithm="aes-gcm",
            quiet=True,
            envelope=True,
            recovery_credentials=[{"type": "recovery_code", "code": generate_recovery_code()}],
        )
        with open(self.enc, "wb") as f:
            f.write(data)

    def _inject_shamir_slot(self, slot=None):
        """Append a shamir slot to the real file's header, as a 1.5.x-authored
        (or tampered) file would carry it. Listing never verifies the slot-set
        MAC, so the injected slot is visible without a credential."""
        with open(self.enc, "rb") as f:
            meta_b64, payload = f.read().split(b":", 1)
        meta = json.loads(base64.b64decode(meta_b64))
        meta["encryption"].setdefault("dek_slots", []).append(slot or copy.deepcopy(SHAMIR_SLOT))
        with open(self.enc, "wb") as f:
            f.write(base64.b64encode(json.dumps(meta).encode("utf-8")) + b":" + payload)

    def _list_json(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            list_recovery_cli(_ns(input=self.enc, json=True))
        return json.loads(buf.getvalue())


class TestShamirKofNExposed(ShamirListingBase):
    def test_shamir_slot_reports_threshold_and_num_shares(self):
        self._write_envelope_with_code_slot()
        self._inject_shamir_slot()
        slots = [s for s in self._list_json()["slots"] if s["type"] == "shamir"]
        self.assertEqual(len(slots), 1)
        self.assertEqual(slots[0]["threshold"], 2)
        self.assertEqual(slots[0]["num_shares"], 3)
        self.assertEqual(slots[0]["key_id"], "set-A")

    def test_core_listing_carries_the_fields(self):
        self._write_envelope_with_code_slot()
        self._inject_shamir_slot()
        shamir = [s for s in list_recovery_slots(self.enc) if s["type"] == "shamir"][0]
        self.assertEqual(shamir["threshold"], 2)
        self.assertEqual(shamir["num_shares"], 3)

    def test_non_shamir_slots_carry_no_threshold_fields(self):
        self._write_envelope_with_code_slot()
        for slot in self._list_json()["slots"]:
            self.assertNotIn("threshold", slot)
            self.assertNotIn("num_shares", slot)

    def test_human_view_renders_k_of_n(self):
        self._write_envelope_with_code_slot()
        self._inject_shamir_slot()
        err = io.StringIO()
        with redirect_stderr(err):
            list_recovery_cli(_ns(input=self.enc))
        # Values are json.dumps-quoted so header strings cannot forge the
        # structured suffix; the K-of-N suffix sits outside the quotes.
        self.assertIn('type="shamir" (2 of 3)', err.getvalue())
        # The header is unauthenticated at listing time; the human view must
        # say so.
        self.assertIn("unauthenticated", err.getvalue())

    def test_slot_documents_carry_only_allowlisted_keys(self):
        """Pins that wrap/salt/params can never leak into --json."""
        self._write_envelope_with_code_slot()
        self._inject_shamir_slot()
        for slot in self._list_json()["slots"]:
            self.assertLessEqual(
                set(slot), {"id", "type", "key_id", "threshold", "num_shares"}, slot
            )


class TestMalformedShamirParams(unittest.TestCase):
    """threshold/num_shares come from the untrusted header: validate or omit."""

    def _crafted_meta(self, shamir_params):
        return {
            "encryption": {
                "dek_slots": [
                    {
                        "id": "shamir-1",
                        "type": "shamir",
                        "wrap": "AAAA",
                        "params": {"salt": "AAAA", "shamir": shamir_params},
                    }
                ]
            }
        }

    def _slots_for(self, shamir_params):
        import openssl_encrypt.modules.crypt_core as cc

        with mock.patch.object(
            cc, "_read_envelope_file", return_value=(self._crafted_meta(shamir_params), b"")
        ):
            return cc.list_recovery_slots("ignored.enc")

    def test_string_threshold_is_omitted(self):
        slot = self._slots_for({"threshold": "2", "num_shares": 3})[0]
        self.assertNotIn("threshold", slot)
        self.assertNotIn("num_shares", slot)

    def test_out_of_range_values_are_omitted(self):
        for params in (
            {"threshold": 0, "num_shares": 3},
            {"threshold": 1, "num_shares": 3},
            {"threshold": 2, "num_shares": 4000000000},
            # First value past the format bound (K = N = 255 is the maximum).
            {"threshold": 2, "num_shares": 256},
            {"threshold": 256, "num_shares": 256},
            {"threshold": True, "num_shares": 3},
            # bool is an int subclass on BOTH operands.
            {"threshold": 2, "num_shares": True},
            # Floats fail isinstance(..., int) even when integral.
            {"threshold": 2.0, "num_shares": 3.0},
            # One field alone must not surface the other.
            {"threshold": 2},
            {"num_shares": 3},
            # Impossible policy: no legitimately created file carries K > N
            # (the 1.5.x split_secret/_parse_k_of_n both reject it), so a
            # crafted header must not render "5 of 2".
            {"threshold": 5, "num_shares": 2},
        ):
            slot = self._slots_for(params)[0]
            self.assertNotIn("threshold", slot, params)
            self.assertNotIn("num_shares", slot, params)

    def test_boundary_values_are_accepted(self):
        slot = self._slots_for({"threshold": 255, "num_shares": 255})[0]
        self.assertEqual(slot["threshold"], 255)
        self.assertEqual(slot["num_shares"], 255)
        slot = self._slots_for({"threshold": 2, "num_shares": 2})[0]
        self.assertEqual(slot["threshold"], 2)
        self.assertEqual(slot["num_shares"], 2)

    def test_missing_shamir_params_do_not_crash(self):
        # None, and non-dict shapes: the isinstance(shamir, dict) guard.
        for shamir_params in (None, "2-of-3", ["threshold", 2], 7):
            slot = self._slots_for(shamir_params)[0]
            self.assertEqual(slot["type"], "shamir", shamir_params)
            self.assertNotIn("threshold", slot, shamir_params)

    def test_non_dict_params_container_does_not_crash(self):
        import openssl_encrypt.modules.crypt_core as cc

        meta = self._crafted_meta({"threshold": 2, "num_shares": 3})
        meta["encryption"]["dek_slots"][0]["params"] = "not-a-dict"
        with mock.patch.object(cc, "_read_envelope_file", return_value=(meta, b"")):
            slot = cc.list_recovery_slots("ignored.enc")[0]
        self.assertEqual(slot["type"], "shamir")
        self.assertNotIn("threshold", slot)

    def test_shamir_key_id_is_surfaced(self):
        slot = self._slots_for({"threshold": 2, "num_shares": 3, "key_id": "set-A"})[0]
        self.assertEqual(slot["key_id"], "set-A")

    def test_non_string_shamir_key_id_is_omitted(self):
        for bad in ({"a": 1}, 7, ["set-A"], True):
            slot = self._slots_for({"threshold": 2, "num_shares": 3, "key_id": bad})[0]
            self.assertNotIn("key_id", slot, bad)

    def test_non_string_top_level_key_id_is_omitted(self):
        """params.key_id (the pqc-style location) is untrusted too."""
        import openssl_encrypt.modules.crypt_core as cc

        meta = self._crafted_meta({"threshold": 2, "num_shares": 3})
        for bad in ({"a": 1}, 7, ["set-A"], True):
            meta["encryption"]["dek_slots"][0]["params"]["key_id"] = bad
            with mock.patch.object(cc, "_read_envelope_file", return_value=(meta, b"")):
                slot = cc.list_recovery_slots("ignored.enc")[0]
            self.assertNotIn("key_id", slot, bad)

    def test_rejected_top_level_key_id_does_not_block_the_nested_one(self):
        import openssl_encrypt.modules.crypt_core as cc

        meta = self._crafted_meta({"threshold": 2, "num_shares": 3, "key_id": "set-A"})
        meta["encryption"]["dek_slots"][0]["params"]["key_id"] = 7
        with mock.patch.object(cc, "_read_envelope_file", return_value=(meta, b"")):
            slot = cc.list_recovery_slots("ignored.enc")[0]
        self.assertEqual(slot["key_id"], "set-A")

    def test_cli_paths_omit_malformed_values_end_to_end(self):
        """The rendering paths must not re-read raw header values."""
        import openssl_encrypt.modules.crypt_core as cc

        crafted = self._crafted_meta({"threshold": "2\x1b[31m", "num_shares": 3})
        with mock.patch.object(cc, "_read_envelope_file", return_value=(crafted, b"")):
            out = io.StringIO()
            with redirect_stdout(out):
                list_recovery_cli(_ns(input="ignored.enc", json=True))
            slot = json.loads(out.getvalue())["slots"][0]
            self.assertNotIn("threshold", slot)
            self.assertNotIn("num_shares", slot)

            err = io.StringIO()
            with redirect_stderr(err):
                list_recovery_cli(_ns(input="ignored.enc"))
            self.assertNotIn(" of ", err.getvalue())
            self.assertNotIn("\x1b", err.getvalue())

    def test_crafted_id_cannot_forge_the_k_of_n_suffix(self):
        """_display_safe keeps spaces, so ids must be quoted when rendered."""
        import openssl_encrypt.modules.crypt_core as cc

        meta = {
            "encryption": {
                "dek_slots": [
                    {
                        "id": 'x  type="shamir" (2 of 3)',
                        "type": "recovery_code",
                        "wrap": "AAAA",
                        "params": {"salt": "AAAA"},
                    }
                ]
            }
        }
        with mock.patch.object(cc, "_read_envelope_file", return_value=(meta, b"")):
            err = io.StringIO()
            with redirect_stderr(err):
                list_recovery_cli(_ns(input="ignored.enc"))
        # json.dumps escapes the embedded quotes, so the exact structured
        # token a genuine shamir slot produces cannot appear via the id.
        self.assertNotIn('type="shamir" (2 of 3)', err.getvalue())


class TestMalformedHeaderShapes(unittest.TestCase):
    """Container-shape attacks must fail as ValidationError, not internals."""

    def _meta_slots(self, meta):
        import openssl_encrypt.modules.crypt_core as cc

        with mock.patch.object(cc, "_read_envelope_file", return_value=(meta, b"")):
            return cc.list_recovery_slots("ignored.enc")

    def test_malformed_containers_raise_validation_error(self):
        from openssl_encrypt.modules.crypt_errors import ValidationError

        for meta in (
            {"encryption": "x"},
            {"encryption": ["x"]},
            {"encryption": {"dek_slots": "abc"}},
            {"encryption": {"dek_slots": {"a": 1}}},
            {"encryption": {"dek_slots": [1]}},
            {"encryption": {"dek_slots": ["x"]}},
            {"encryption": {"dek_slots": [{"type": "shamir"}, None]}},
        ):
            with self.assertRaises(ValidationError, msg=meta):
                self._meta_slots(meta)

    def test_null_containers_mean_no_slots(self):
        self.assertEqual(self._meta_slots({"encryption": None}), [])
        self.assertEqual(self._meta_slots({"encryption": {"dek_slots": None}}), [])
        self.assertEqual(self._meta_slots({}), [])

    def test_huge_numeric_literal_in_raw_header_is_handled(self):
        """A >4300-digit int trips CPython's int_max_str_digits inside
        json.loads (3.11+); it must surface as ValidationError, and on
        older interpreters the parsed value must fail the range check."""
        from openssl_encrypt.modules.crypt_errors import ValidationError

        raw_meta = (
            b'{"encryption": {"dek_slots": [{"id": "s", "type": "shamir", '
            b'"params": {"shamir": {"threshold": 2, "num_shares": ' + b"9" * 5000 + b"}}}]}}"
        )
        path = os.path.join(tempfile.mkdtemp(), "crafted.enc")
        with open(path, "wb") as f:
            f.write(base64.b64encode(raw_meta) + b":payload")
        try:
            try:
                slots = list_recovery_slots(path)
            except ValidationError:
                pass  # 3.11+: json.loads refuses the literal
            else:
                self.assertNotIn("threshold", slots[0])
        finally:
            os.unlink(path)
            os.rmdir(os.path.dirname(path))


if __name__ == "__main__":
    unittest.main()
