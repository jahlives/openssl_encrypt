#!/usr/bin/env python3
"""Decrypt auto-detection of an untrusted asymmetric header must be bounded and
must not print raw control characters (gitlab#237, scan F3, CWE-117).

`detect_encryption_type` parsed the file header with a bare `json.loads` and
returned each `asymmetric.recipients[].key_id`; the caller printed them
unescaped, letting a crafted key_id repaint a forged Fingerprint line, and an
unbounded recipient list could be materialized/printed. The parse is now bounded
(JSON security scan before json.loads), the recipient list is capped, and the
printed value is routed through sanitize_for_display.
"""

import base64
import json
import os
import pathlib
import tempfile
import unittest

from openssl_encrypt.modules.crypt_cli import (
    _MAX_RECIPIENTS_SHOWN,
    _detect_metadata_loads,
    detect_encryption_type,
)

_FIXTURE = pathlib.Path(__file__).parent / "testfiles" / "asymmetric_wrap" / "v7_wrap_v2_prefix.enc"


def _write(path, meta):
    with open(path, "wb") as f:
        f.write(base64.b64encode(json.dumps(meta).encode("utf-8")) + b":" + b"payload")


class TestRecipientListBounded(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "asym.enc")

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_huge_recipient_list_is_capped(self):
        meta = {
            "format_version": 7,
            "mode": "asymmetric",
            "asymmetric": {
                "recipients": [{"key_id": f"fp{i}"} for i in range(5000)],
                "sender": {"key_id": "s"},
            },
        }
        _write(self.path, meta)
        info = detect_encryption_type(self.path)
        self.assertEqual(info["type"], "asymmetric")
        self.assertLessEqual(len(info["recipient_fingerprints"]), _MAX_RECIPIENTS_SHOWN)

    def test_non_dict_recipient_entries_do_not_crash(self):
        meta = {
            "format_version": 7,
            "mode": "asymmetric",
            "asymmetric": {"recipients": ["not-a-dict", {"key_id": "ok"}], "sender": "nope"},
        }
        _write(self.path, meta)
        info = detect_encryption_type(self.path)
        self.assertEqual(info["type"], "asymmetric")
        self.assertIn("ok", info["recipient_fingerprints"])
        self.assertEqual(info["sender_fingerprint"], "")


class TestBoundedParse(unittest.TestCase):
    def test_oversized_header_is_rejected(self):
        # > 1 MiB JSON must be refused by the security scan, not parsed.
        big = '{"x":"' + "a" * (1024 * 1024 + 10) + '"}'
        with self.assertRaises(ValueError):
            _detect_metadata_loads(big)

    def test_literal_control_char_header_is_rejected(self):
        # A literal control byte in the JSON source is rejected by the scan.
        with self.assertRaises(ValueError):
            _detect_metadata_loads('{"a":"b\x01c"}')

    def test_clean_header_parses(self):
        self.assertEqual(_detect_metadata_loads('{"a": 1}'), {"a": 1})


@unittest.skipUnless(_FIXTURE.exists(), "asymmetric fixture missing")
class TestRealFixtureStillDetects(unittest.TestCase):
    def test_v7_fixture_detected_as_asymmetric(self):
        info = detect_encryption_type(str(_FIXTURE))
        self.assertEqual(info["type"], "asymmetric")
        self.assertTrue(info["recipient_fingerprints"])


if __name__ == "__main__":
    unittest.main()
