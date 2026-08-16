#!/usr/bin/env python3
"""list-recovery caps output and header reads on crafted files (gitlab#279).

The credential-free listing path had three flood surfaces: _read_envelope_file
slurped the whole attacker-supplied file before touching the header (docstring
claimed an oversized-metadata guard that did not exist), list_recovery_slots
materialized one dict per claimed slot before any cap (a multi-MB header of
empty slots amplifies ~30x in memory), and list_recovery_cli printed every
claimed slot even though the unlock paths refuse >MAX_DEK_SLOTS. Deeply
nested JSON could also surface a raw RecursionError through the normalized
parse-error path.
"""

import argparse
import base64
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import openssl_encrypt.modules.crypt_core as cc
from openssl_encrypt.modules.crypt_errors import ValidationError
from openssl_encrypt.modules.recovery_slots import MAX_DEK_SLOTS, list_recovery_cli


def _write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def _envelope_bytes(meta):
    return base64.b64encode(json.dumps(meta).encode("utf-8")) + b":payload"


def _meta_with_slots(n):
    return {
        "encryption": {"dek_slots": [{"id": f"s-{i}", "type": "recovery_code"} for i in range(n)]}
    }


class TestHeaderReadBounds(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "crafted.enc")

    def tearDown(self):
        for f in os.listdir(self.tmp):
            os.unlink(os.path.join(self.tmp, f))
        os.rmdir(self.tmp)

    def test_oversized_header_is_refused(self):
        """A header past the metadata cap fails as ValidationError, before
        the base64/JSON stages can touch it."""
        _write(self.path, b"A" * (3 * 1024 * 1024) + b":payload")
        with self.assertRaises(ValidationError):
            cc.list_recovery_slots(self.path)

    def test_separatorless_flood_is_refused(self):
        """No separator at all must hit the cap, not read the whole file."""
        _write(self.path, b"A" * (3 * 1024 * 1024))
        with self.assertRaises(ValidationError):
            cc.list_recovery_slots(self.path)

    def test_large_payload_after_small_header_lists_fine(self):
        """The bound applies to the header, not the (legitimate) payload."""
        meta = _meta_with_slots(2)
        _write(
            self.path,
            base64.b64encode(json.dumps(meta).encode()) + b":" + b"P" * (4 * 1024 * 1024),
        )
        slots = cc.list_recovery_slots(self.path)
        self.assertEqual(len(slots), 2)

    def test_deeply_nested_json_is_normalized(self):
        """RecursionError from a nesting bomb surfaces as ValidationError."""
        _write(self.path, base64.b64encode(b"[" * 200000) + b":payload")
        with self.assertRaises(ValidationError):
            cc.list_recovery_slots(self.path)


class TestCoreMaterializationCap(unittest.TestCase):
    def test_core_caps_slot_materialization(self):
        meta = _meta_with_slots(500)
        with mock.patch.object(cc, "_read_envelope_file", return_value=(meta, b"")):
            slots = cc.list_recovery_slots("ignored.enc")
        self.assertEqual(len(slots), MAX_DEK_SLOTS + 1)

    def test_at_cap_is_untouched(self):
        meta = _meta_with_slots(MAX_DEK_SLOTS)
        with mock.patch.object(cc, "_read_envelope_file", return_value=(meta, b"")):
            self.assertEqual(len(cc.list_recovery_slots("ignored.enc")), MAX_DEK_SLOTS)


class TestCliCaps(unittest.TestCase):
    def _mocked_slots(self, n):
        return [{"id": f"s-{i}", "type": "recovery_code"} for i in range(n)]

    def _json_doc(self, slots):
        args = argparse.Namespace(input="ignored", json=True, quiet=True)
        out = io.StringIO()
        with mock.patch.object(cc, "list_recovery_slots", return_value=slots):
            with redirect_stdout(out):
                list_recovery_cli(args)
        # 1.5.x emits through the total-json envelope (gitlab#268).
        envelope = json.loads(out.getvalue())
        self.assertEqual(envelope["status"], "ok")
        return envelope["data"]

    def test_json_is_capped_with_explicit_truncated_marker(self):
        doc = self._json_doc(self._mocked_slots(MAX_DEK_SLOTS + 1))
        self.assertEqual(len(doc["slots"]), MAX_DEK_SLOTS)
        self.assertIs(doc["truncated"], True)

    def test_json_within_cap_has_no_truncated_key(self):
        """No silent-truncation ambiguity: the key appears only when true."""
        doc = self._json_doc(self._mocked_slots(MAX_DEK_SLOTS))
        self.assertEqual(len(doc["slots"]), MAX_DEK_SLOTS)
        self.assertNotIn("truncated", doc)

    def test_human_view_is_capped_with_notice(self):
        args = argparse.Namespace(input="ignored", json=False, quiet=True)
        err = io.StringIO()
        with mock.patch.object(
            cc, "list_recovery_slots", return_value=self._mocked_slots(MAX_DEK_SLOTS + 1)
        ):
            with redirect_stderr(err):
                list_recovery_cli(args)
        out = err.getvalue()
        self.assertIn(f"showing the first {MAX_DEK_SLOTS}", out)
        self.assertEqual(out.count("  id="), MAX_DEK_SLOTS)

    def test_human_view_never_states_a_wrong_count(self):
        """Core caps at MAX+1, so on a truncated listing the exact claimed
        count is unknown — the header line must not present the capped
        length (e.g. "33") as the file's slot count (review F1)."""
        args = argparse.Namespace(input="ignored", json=False, quiet=True)
        err = io.StringIO()
        with mock.patch.object(
            cc, "list_recovery_slots", return_value=self._mocked_slots(MAX_DEK_SLOTS + 1)
        ):
            with redirect_stderr(err):
                list_recovery_cli(args)
        out = err.getvalue()
        self.assertNotIn(f"{MAX_DEK_SLOTS + 1} recovery slot(s)", out)
        self.assertIn(f"more than {MAX_DEK_SLOTS} recovery slot(s)", out)

    def test_human_view_exact_count_when_not_truncated(self):
        args = argparse.Namespace(input="ignored", json=False, quiet=True)
        err = io.StringIO()
        with mock.patch.object(cc, "list_recovery_slots", return_value=self._mocked_slots(3)):
            with redirect_stderr(err):
                list_recovery_cli(args)
        self.assertIn("3 recovery slot(s):", err.getvalue())


if __name__ == "__main__":
    unittest.main()
